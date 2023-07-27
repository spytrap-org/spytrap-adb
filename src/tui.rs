use crate::errors::*;
use crate::ioc::{Repository, Suspicion, SuspicionLevel};
use crate::scan;
use crate::utils;
use crossterm::event::EventStream;
use crossterm::event::{KeyEvent, KeyModifiers};
use crossterm::{
    event::{Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use forensic_adb::{AndroidStorageInput, DeviceInfo, Host};
use indexmap::IndexMap;
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io;
use std::io::Stdout;
use std::iter::Chain;
use std::slice::Iter;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time;
use tokio_stream::StreamExt;

const DARK_GREY: Color = Color::Rgb(0x3b, 0x3b, 0x3b);
/// Number of items to navigate with page up/down keys
const PAGE_MODIFIER: usize = 10;
/// The number of lines used by the spytrap-adb UI around the scroll view
const SCROLL_CHROME_HEIGHT: usize = 6;

const DEVICE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const ACTIVITY_TICK_INTERVAL: Duration = Duration::from_millis(100);
const ACTIVITY: &[&str] = &[".", "o", "O", "°", " ", " ", "°", "O", "o", ".", " ", " "];

#[derive(Debug)]
pub enum Message {
    Suspicion(Suspicion),
    App { name: String, sus: Suspicion },
    StartDownload,
    ScanTick,
    ScanEnded,
    DownloadTick,
    DownloadEnded(Option<Repository>),
    DeviceRefreshTick,
}

#[derive(Debug)]
pub enum TimerCmd {
    Start(Duration),
    Stop,
}

impl TimerCmd {
    pub async fn recv(rx: &mut mpsc::Receiver<TimerCmd>) -> Result<TimerCmd> {
        let cmd = rx.recv().await.context("Channel has closed")?;
        Ok(cmd)
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct SavedCursor {
    offset: usize,
    cursor: usize,
    interval: Option<Duration>,
}

pub struct App {
    adb_host: Host,
    repository: Repository,
    events_tx: mpsc::Sender<Message>,
    events_rx: mpsc::Receiver<Message>,
    timer_tx: mpsc::Sender<TimerCmd>,
    timer_rx: Option<mpsc::Receiver<TimerCmd>>,
    current_timer: Option<Duration>,
    devices: Vec<DeviceInfo>,
    offset: usize,
    cursor: usize,
    /// the previous cursor positions before switching into a different scroll-view
    cursor_backtrace: Vec<SavedCursor>,
    scan: Option<Scan>,
    download: Option<Download>,
}

impl App {
    pub fn new(adb_host: Host, repository: Repository) -> Self {
        let (events_tx, events_rx) = mpsc::channel(5);
        let (timer_tx, timer_rx) = mpsc::channel(5);
        Self {
            adb_host,
            repository,
            events_tx,
            events_rx,
            timer_tx,
            timer_rx: Some(timer_rx),
            current_timer: None,
            devices: Vec::new(),
            offset: 0,
            cursor: 0,
            cursor_backtrace: vec![],
            scan: None,
            download: None,
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        let devices = self
            .adb_host
            .devices::<Vec<_>>()
            .await
            .map_err(|e| anyhow!("Failed to list devices from adb: {}", e))?;
        self.devices = devices;
        self.start_timer(DEVICE_REFRESH_INTERVAL).await?;

        if self.repository.content.is_none() {
            self.events_tx.send(Message::StartDownload).await.ok();
        }

        Ok(())
    }

    async fn start_timer(&mut self, interval: Duration) -> Result<()> {
        self.timer_tx.send(TimerCmd::Start(interval)).await?;
        self.current_timer = Some(interval);
        Ok(())
    }

    async fn stop_timer(&mut self) -> Result<()> {
        self.timer_tx.send(TimerCmd::Stop).await?;
        self.current_timer = None;
        Ok(())
    }

    /// The number of visible lines in the current active view
    pub fn view_length(&self) -> usize {
        if let Some(scan) = &self.scan {
            scan.findings.len()
                + scan.apps.len()
                + scan
                    .apps
                    .iter()
                    .map(|(name, values)| {
                        if scan.expanded.contains(name) {
                            values.len()
                        } else {
                            0
                        }
                    })
                    .sum::<usize>()
        } else {
            self.devices.len()
        }
    }

    pub async fn save_cursor(&mut self) -> Result<()> {
        self.cursor_backtrace.push(SavedCursor {
            offset: self.offset,
            cursor: self.cursor,
            interval: self.current_timer,
        });
        self.offset = 0;
        self.cursor = 0;
        self.stop_timer().await?;
        Ok(())
    }

    pub fn key_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
        if self.cursor < self.offset {
            self.offset = self.cursor;
        }
    }

    pub fn key_down<B: Backend>(&mut self, terminal: &Terminal<B>) -> Result<()> {
        let max = self.view_length().saturating_sub(1);

        if self.cursor < max {
            self.cursor += 1;
            self.recalculate_scroll_offset(terminal)?;
        }

        Ok(())
    }

    pub fn recalculate_scroll_offset<B: Backend>(&mut self, terminal: &Terminal<B>) -> Result<()> {
        let scroll_height = terminal.size()?.height as usize - SCROLL_CHROME_HEIGHT;
        if self.cursor - self.offset > scroll_height {
            self.offset = self.cursor - scroll_height;
        }
        Ok(())
    }

    pub async fn refresh_devices(&mut self) -> Result<()> {
        let devices = self
            .adb_host
            .devices::<Vec<_>>()
            .await
            .map_err(|e| anyhow!("Failed to list devices from adb: {}", e))?;
        self.devices = devices;
        if self.devices.get(self.cursor).is_none() {
            self.cursor = match self.devices.len() {
                0 => 0,
                n => n - 1,
            };
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Spinner {
    idx: usize,
}

impl Spinner {
    pub fn activity_tick(&mut self) {
        self.idx += 1;
        self.idx %= ACTIVITY.len();
    }

    pub fn render(&self) -> Span {
        Span::styled(
            ACTIVITY[self.idx],
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )
    }
}

#[derive(Debug, Default)]
pub struct Download {
    spinner: Spinner,
    cancel: Option<mpsc::Sender<Infallible>>,
}

#[derive(Debug, Default)]
pub struct Scan {
    findings: Vec<Suspicion>,
    apps: IndexMap<String, AppInfos>,
    expanded: BTreeSet<String>,
    spinner: Spinner,
    cancel: Option<mpsc::Sender<Infallible>>,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct AppInfos {
    high: Vec<Suspicion>,
    medium: Vec<Suspicion>,
    low: Vec<Suspicion>,
}

impl AppInfos {
    pub fn push(&mut self, item: Suspicion) {
        match item.level {
            SuspicionLevel::High => self.high.push(item),
            SuspicionLevel::Medium => self.medium.push(item),
            SuspicionLevel::Low => self.low.push(item),
            SuspicionLevel::Good => (),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.high.is_empty() && self.medium.is_empty() && self.low.is_empty()
    }

    pub fn len(&self) -> usize {
        self.high.len() + self.medium.len() + self.low.len()
    }

    pub fn iter(
        &self,
    ) -> Chain<Chain<Iter<'_, Suspicion>, Iter<'_, Suspicion>>, Iter<'_, Suspicion>> {
        self.high
            .iter()
            .chain(self.medium.iter())
            .chain(self.low.iter())
    }
}

impl Ord for AppInfos {
    fn cmp(&self, other: &Self) -> Ordering {
        Ordering::Equal
            .then(self.high.len().cmp(&other.high.len()))
            .then(self.medium.len().cmp(&other.medium.len()))
            .then(self.low.len().cmp(&other.low.len()))
    }
}

impl PartialOrd for AppInfos {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub enum Action {
    Shutdown,
    Clear,
}

pub async fn run_scan(
    adb_host: Host,
    repo: Repository,
    device: DeviceInfo,
    events_tx: mpsc::Sender<Message>,
) -> Result<()> {
    let device = adb_host
        .clone()
        .device_or_default(Some(&device.serial), AndroidStorageInput::Auto)
        .await
        .with_context(|| anyhow!("Failed to access device: {:?}", device.serial))?;

    let rules = repo.parse_rules().context("Failed to load rules")?;
    scan::run(
        &device,
        &rules,
        &scan::Settings { skip_apps: false },
        &mut scan::ScanNotifier::Channel(events_tx),
    )
    .await?;

    Ok(())
}

pub async fn run_download(mut repo: Repository) -> Result<Repository> {
    repo.download_ioc_db()
        .await
        .context("Failed to download stalkerware-indicators yaml files")?;
    Ok(repo)
}

pub async fn handle_key<B: Backend>(
    terminal: &Terminal<B>,
    app: &mut App,
    event: Event,
) -> Result<Option<Action>> {
    match event {
        Event::Key(KeyEvent {
            code: KeyCode::Esc,
            modifiers: KeyModifiers::NONE,
            ..
        })
        | Event::Key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            ..
        })
        | Event::Key(KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            if let Some(tx) = app.download.take() {
                drop(tx);
            } else if let Some(tx) = app.scan.as_mut().and_then(|s| s.cancel.take()) {
                drop(tx);
            } else if app.scan.take().is_none() {
                println!("Exiting...");
                return Ok(Some(Action::Shutdown));
            } else {
                let saved = app.cursor_backtrace.pop().unwrap_or_default();
                app.offset = saved.offset;
                app.cursor = saved.cursor;
                if let Some(interval) = saved.interval {
                    app.start_timer(interval).await?;
                } else {
                    app.stop_timer().await?;
                }
            }
        }
        Event::Key(KeyEvent {
            code: KeyCode::Char('Q'),
            modifiers: KeyModifiers::SHIFT,
            ..
        }) => {
            println!("Exiting...");
            return Ok(Some(Action::Shutdown));
        }
        Event::Key(KeyEvent {
            code: KeyCode::Enter,
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            if let Some(scan) = &mut app.scan {
                if let Some(mut idx) = app.cursor.checked_sub(scan.findings.len()) {
                    let mut offset = 0;
                    for (i, (name, appinfos)) in scan.apps.iter().enumerate() {
                        let height = if scan.expanded.contains(name) {
                            appinfos.len() + 1
                        } else {
                            1
                        };

                        if offset + height > idx {
                            idx = i;
                            app.cursor = offset + scan.findings.len();
                            break;
                        } else {
                            offset += height;
                        }
                    }

                    let (name, _appinfos) = scan.apps.get_index(idx).unwrap();
                    // toggle the app from the `expanded` list
                    if scan.expanded.contains(name) {
                        scan.expanded.remove(name);
                    } else {
                        scan.expanded.insert(name.clone());
                    }
                }
            } else if let Some(device) = app.devices.get(app.cursor) {
                let adb_host = app.adb_host.clone();
                let repo = app.repository.clone();
                let device = device.clone();
                let events_tx = app.events_tx.clone();

                let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
                tokio::spawn(async move {
                    let mut interval = time::interval(ACTIVITY_TICK_INTERVAL);
                    let scan = run_scan(adb_host, repo, device, events_tx.clone());
                    tokio::pin!(scan);

                    loop {
                        tokio::select! {
                            _ = cancel_rx.recv() => {
                                debug!("Scan has been canceled");
                                events_tx.send(Message::ScanEnded).await.ok();
                                break;
                            }
                            ret = &mut scan => {
                                debug!("Scan has completed: {:?}", ret); // TODO print errors in UI
                                events_tx.send(Message::ScanEnded).await.ok();
                                break;
                            }
                            _ = interval.tick() => {
                                events_tx.send(Message::ScanTick).await.ok();
                            }
                        }
                    }
                });
                app.scan = Some(Scan {
                    cancel: Some(cancel_tx),
                    ..Default::default()
                });
                app.save_cursor().await?;
            }
        }
        Event::Key(KeyEvent {
            code: KeyCode::Up,
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            app.key_up();
        }
        Event::Key(KeyEvent {
            code: KeyCode::Down,
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            app.key_down(terminal)?;
        }
        Event::Key(KeyEvent {
            code: KeyCode::PageUp,
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            for _ in 0..PAGE_MODIFIER {
                app.key_up();
            }
        }
        Event::Key(KeyEvent {
            code: KeyCode::PageDown,
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            for _ in 0..PAGE_MODIFIER {
                app.key_down(terminal)?;
            }
        }
        Event::Key(KeyEvent {
            code: KeyCode::Char('r'),
            modifiers: KeyModifiers::CONTROL,
            ..
        }) => {
            app.events_tx.send(Message::StartDownload).await.ok();
        }
        Event::Key(KeyEvent {
            code: KeyCode::Char('l'),
            modifiers: KeyModifiers::CONTROL,
            ..
        }) => {
            return Ok(Some(Action::Clear));
        }
        Event::Resize(_columns, _rows) => {
            app.recalculate_scroll_offset(terminal)?;
        }
        _ => (),
    }
    Ok(None)
}

async fn run_timer(mut rx: mpsc::Receiver<TimerCmd>, tx: mpsc::Sender<Message>) -> Result<()> {
    let mut next_interval = None;
    loop {
        let interval = if let Some(interval) = next_interval.take() {
            interval
        } else {
            match TimerCmd::recv(&mut rx).await? {
                TimerCmd::Start(time) => time,
                TimerCmd::Stop => continue,
            }
        };
        let mut timer = time::interval(interval);
        loop {
            tokio::select! {
                cmd = TimerCmd::recv(&mut rx) => {
                    match cmd? {
                        TimerCmd::Start(time) => {
                            next_interval = Some(time);
                            break;
                        }
                        TimerCmd::Stop => break,
                    }
                }
                _ = timer.tick() => {
                    tx.send(Message::DeviceRefreshTick).await?;
                }
            }
        }
    }
}

pub async fn run<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    let mut stream = EventStream::new();

    let mut tasks = JoinSet::new();

    let timer_rx = app.timer_rx.take().context("Timer already started")?;
    tasks.spawn(run_timer(timer_rx, app.events_tx.clone()));

    loop {
        terminal.draw(|f| ui(f, app))?;

        tokio::select! {
            event = stream.next() => {
                let Some(event) = event else { break };
                let event = event.context("Failed to read terminal input")?;
                match handle_key(terminal, app, event).await? {
                    Some(Action::Shutdown) => break,
                    Some(Action::Clear) => {
                        terminal.clear()?;
                    },
                    None => (),
                }
            }
            event = app.events_rx.recv() => {
                let Some(event) = event else { break };
                debug!("Received message from channel: event={event:?}");
                match event {
                    Message::Suspicion(sus) => {
                        if let Some(scan) = &mut app.scan {
                            scan.findings.push(sus);
                            scan.findings.sort_by(|a, b| {
                                a.level.cmp(&b.level)
                                    .reverse()
                                    .then(a.description.cmp(&b.description))
                            });
                        }
                    }
                    Message::App { name, sus } => {
                        if let Some(scan) = &mut app.scan {
                            scan.apps.entry(name).or_default().push(sus);
                            scan.apps.sort_by(|k1, v1, k2, v2| {
                                v1.cmp(v2)
                                    .reverse()
                                    .then(k1.cmp(k2))
                            });
                        }
                    }
                    Message::StartDownload => {
                        let events_tx = app.events_tx.clone();
                        let repo = app.repository.clone();

                        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
                        tokio::spawn(async move {
                            let mut interval = time::interval(ACTIVITY_TICK_INTERVAL);
                            let download = run_download(repo);
                            tokio::pin!(download);

                            loop {
                                tokio::select! {
                                    _ = cancel_rx.recv() => {
                                        debug!("Download has been canceled");
                                        events_tx.send(Message::DownloadEnded(None)).await.ok();
                                        break;
                                    }
                                    ret = &mut download => {
                                        let repo = match ret {
                                            Ok(repo) => {
                                                debug!("Download has completed");
                                                Some(repo)
                                            }
                                            Err(err) => {
                                                error!("Download has failed: {err:?}"); // TODO print errors in UI
                                                None
                                            }
                                        };
                                        events_tx.send(Message::DownloadEnded(repo)).await.ok();
                                        break;
                                    }
                                    _ = interval.tick() => {
                                        events_tx.send(Message::DownloadTick).await.ok();
                                    }
                                }
                            }
                        });
                        app.download = Some(Download {
                            cancel: Some(cancel_tx),
                            ..Default::default()
                        });
                    }
                    Message::ScanTick => {
                        if let Some(scan) = &mut app.scan {
                            scan.spinner.activity_tick();
                        }
                    }
                    Message::ScanEnded => {
                        if let Some(scan) = &mut app.scan {
                            scan.cancel.take();
                        }
                    }
                    Message::DownloadTick => {
                        if let Some(download) = &mut app.download {
                            download.spinner.activity_tick();
                        }
                    }
                    Message::DownloadEnded(repo) => {
                        app.download.take();
                        if let Some(repo) = repo {
                            app.repository = repo;
                        }
                    }
                    Message::DeviceRefreshTick => {
                        app.refresh_devices().await?;
                    }
                }
            }
            res = tasks.join_next() => {
                bail!("Task has crashed: {res:?}");
            }
        }
    }

    Ok(())
}

fn cursor<'a, T: IntoIterator<Item = Span<'a>>>(msg: T, selected: bool) -> (Line<'a>, Style) {
    let mut style = Style::default();
    if selected {
        style = style.bg(DARK_GREY);
    }

    let mut row = vec![Span::styled(
        if selected { " > " } else { "   " },
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )];
    row.extend(msg);

    (Line::from(row), style)
}

pub fn ui<B: Backend>(f: &mut Frame<'_, B>, app: &App) {
    let white = Style::default().fg(Color::White).bg(Color::Black);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ]
            .as_ref(),
        )
        .split(f.size());

    f.render_widget(render_help_widget(app), chunks[0]);
    f.render_widget(Block::default().style(white), chunks[1]);
    f.render_widget(render_app_widget(app), chunks[2]);
    f.render_widget(render_statusline_widget(app), chunks[3]);
}

fn render_help_widget(app: &App) -> Paragraph {
    let white = Style::default().fg(Color::White).bg(Color::Black);
    let mut text = Vec::new();

    if let Some(scan) = &app.scan {
        if scan.cancel.is_some() {
            text.push(scan.spinner.render());
            text.push(Span::raw(" scanning - "));
        }
    }

    if let Some(download) = &app.download {
        if download.cancel.is_some() {
            text.push(download.spinner.render());
            text.push(Span::raw(" downloading - "));
        }
    }

    if text.is_empty() {
        text.push(Span::raw("idle - "));
    }

    text.extend([
        Span::raw("Press "),
        Span::styled("ESC", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" to exit - "),
        Span::raw(concat!(
            env!("CARGO_PKG_NAME"),
            " v",
            env!("CARGO_PKG_VERSION")
        )),
    ]);
    let text = Text::from(Line::from(text));
    Paragraph::new(text)
        .style(white)
        .alignment(Alignment::Right)
}

fn render_app_widget(app: &App) -> List {
    let white = Style::default().fg(Color::White).bg(Color::Black);

    if let Some(scan) = &app.scan {
        let mut list = Vec::new();
        let mut i = 0;

        for sus in &scan.findings {
            let selected = i == app.cursor;
            let row = sus.to_terminal();
            let (content, style) = cursor(row, selected);
            list.push(ListItem::new(content).style(style));
            i += 1;
        }

        for (name, findings) in &scan.apps {
            let selected = i == app.cursor;
            let is_expanded = scan.expanded.contains(name);

            let mut row = Vec::new();
            row.push(Span::styled(
                if is_expanded { "[-]" } else { "[+]" },
                Style::default().add_modifier(Modifier::BOLD),
            ));
            row.push(Span::raw(format!(" App {name:?} (")));

            let mut details = Vec::new();
            if !findings.high.is_empty() {
                details.push(Span::styled(
                    format!("{} high", findings.high.len()),
                    SuspicionLevel::High.terminal_color(),
                ));
            }

            if !findings.medium.is_empty() {
                details.push(Span::styled(
                    format!("{} medium", findings.medium.len()),
                    SuspicionLevel::Medium.terminal_color(),
                ));
            }

            if !findings.low.is_empty() {
                details.push(Span::styled(
                    format!("{} low", findings.low.len()),
                    SuspicionLevel::Low.terminal_color(),
                ));
            }

            for (i, value) in details.into_iter().enumerate() {
                if i > 0 {
                    row.push(Span::raw(", "));
                }
                row.push(value);
            }

            row.push(Span::raw(")"));

            let (content, style) = cursor(row, selected);
            list.push(ListItem::new(content).style(style));

            i += 1;

            // show app details if expanded
            if is_expanded {
                for sus in findings.iter() {
                    let selected = i == app.cursor;
                    let mut row = vec![Span::raw("    ")];
                    row.extend(sus.to_terminal());
                    let (content, style) = cursor(row, selected);
                    list.push(ListItem::new(content).style(style));
                    i += 1;
                }
            }
        }

        // scrolling
        let list = &list[app.offset..];

        let title = Span::styled("Findings", white.add_modifier(Modifier::BOLD));
        List::new(list).block(
            Block::default()
                .borders(Borders::ALL)
                .style(white)
                .border_style(Style::default().fg(Color::Green))
                .title(title),
        )
    } else {
        let devices: Vec<ListItem> = app
            .devices
            .iter()
            .enumerate()
            .map(|(i, device)| {
                let selected = i == app.cursor;

                let msg = format!(
                    "{:30} device={:?}, model={:?}, product={:?}",
                    device.serial,
                    utils::human_option_str(device.info.get("device")),
                    utils::human_option_str(device.info.get("model")),
                    utils::human_option_str(device.info.get("product")),
                );

                let (content, style) = cursor([Span::raw(msg)], selected);
                ListItem::new(content).style(style)
            })
            .collect();

        let title = Span::styled("Connected devices", white.add_modifier(Modifier::BOLD));
        List::new(devices).block(
            Block::default()
                .borders(Borders::ALL)
                .style(white)
                .border_style(Style::default().fg(Color::Green))
                .title(title),
        )
    }
}

fn render_statusline_widget(app: &App) -> Paragraph {
    let white = Style::default().fg(Color::White).bg(Color::Black);
    let green = Style::default().fg(Color::Green).bg(Color::Black);
    let mut text = Vec::new();

    if let Some(content) = &app.repository.content {
        text.push(Span::raw("ioc-git:"));
        text.push(Span::styled(&content.git_commit, green));
        text.push(Span::raw(" released:"));
        text.push(Span::styled(
            utils::format_datetime(content.released),
            green,
        ));
    }

    let text = Text::from(Line::from(text));
    Paragraph::new(text)
        .style(white)
        .alignment(Alignment::Right)
}

pub fn setup() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn cleanup(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen,)?;
    terminal.show_cursor()?;
    Ok(())
}
