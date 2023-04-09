use crate::errors::*;
use crate::iocs;
use crate::rules;
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
    text::{Span, Spans, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io;
use std::io::Stdout;
use std::iter::Chain;
use std::slice::Iter;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

const DARK_GREY: Color = Color::Rgb(0x3b, 0x3b, 0x3b);
/// Number of items to navigate with page up/down keys
const PAGE_MODIFIER: usize = 10;
/// The number of lines used by the spytrap-adb UI around the scroll view
const SCROLL_CHROME_HEIGHT: usize = 5;

#[derive(Debug)]
pub enum Message {
    ScanEnded,
    Suspicion(iocs::Suspicion),
    App { name: String, sus: iocs::Suspicion },
}

#[derive(Debug, PartialEq, Default)]
pub struct SavedCursor {
    offset: usize,
    cursor: usize,
}

pub struct App {
    adb_host: Host,
    events_tx: mpsc::Sender<Message>,
    events_rx: mpsc::Receiver<Message>,
    devices: Vec<DeviceInfo>,
    offset: usize,
    cursor: usize,
    /// the previous cursor positions before switching into a different scroll-view
    cursor_backtrace: Vec<SavedCursor>,
    scan: Option<Scan>,
    cancel_scan: Option<mpsc::Sender<()>>,
}

impl App {
    pub fn new(adb_host: Host) -> Self {
        let (events_tx, events_rx) = mpsc::channel(5);
        Self {
            adb_host,
            events_tx,
            events_rx,
            devices: Vec::new(),
            offset: 0,
            cursor: 0,
            cursor_backtrace: vec![],
            scan: None,
            cancel_scan: None,
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        let devices = self
            .adb_host
            .devices::<Vec<_>>()
            .await
            .map_err(|e| anyhow!("Failed to list devices from adb: {}", e))?;
        self.devices = devices;

        Ok(())
    }

    /// The number of visible lines in the current active view
    pub fn view_length(&self) -> usize {
        if let Some(scan) = &self.scan {
            scan.findings.len() + scan.apps.len()
        } else {
            self.devices.len()
        }
    }

    pub fn save_cursor(&mut self) {
        self.cursor_backtrace.push(SavedCursor {
            offset: self.offset,
            cursor: self.cursor,
        });
        self.offset = 0;
        self.cursor = 0;
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
pub struct Scan {
    findings: Vec<iocs::Suspicion>,
    apps: IndexMap<String, AppInfos>,
    expanded: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct AppInfos {
    high: Vec<iocs::Suspicion>,
    medium: Vec<iocs::Suspicion>,
    low: Vec<iocs::Suspicion>,
}

impl AppInfos {
    pub fn push(&mut self, item: iocs::Suspicion) {
        match item.level {
            iocs::SuspicionLevel::High => self.high.push(item),
            iocs::SuspicionLevel::Medium => self.medium.push(item),
            iocs::SuspicionLevel::Low => self.low.push(item),
        }
    }

    pub fn iter(
        &self,
    ) -> Chain<Chain<Iter<'_, iocs::Suspicion>, Iter<'_, iocs::Suspicion>>, Iter<'_, iocs::Suspicion>>
    {
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
    device: DeviceInfo,
    events_tx: mpsc::Sender<Message>,
) -> Result<()> {
    let device = adb_host
        .clone()
        .device_or_default(Some(&device.serial), AndroidStorageInput::Auto)
        .await
        .with_context(|| anyhow!("Failed to access device: {:?}", device.serial))?;

    let repo = iocs::Repository::ioc_file_path()?;
    let (rules, _sha256) = rules::load_map_from_file(repo).context("Failed to load rules")?;
    scan::run(
        &device,
        &rules,
        &scan::Settings { skip_apps: false },
        &mut scan::ScanNotifier::Channel(events_tx),
    )
    .await?;

    Ok(())
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
            if let Some(tx) = app.cancel_scan.take() {
                tx.send(()).await.ok();
            } else if app.scan.take().is_none() {
                println!("Exiting...");
                return Ok(Some(Action::Shutdown));
            } else {
                let saved = app.cursor_backtrace.pop().unwrap_or_default();
                app.offset = saved.offset;
                app.cursor = saved.cursor;
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
                if let Some(idx) = app.cursor.checked_sub(scan.findings.len()) {
                    let (name, _appinfos) = scan.apps.get_index(idx).unwrap();
                    // toggle the app from the `expanded` list
                    if scan.expanded.contains(name) {
                        scan.expanded.remove(name);
                    } else {
                        scan.expanded.insert(name.clone());
                    }
                }
            } else {
                let adb_host = app.adb_host.clone();
                let device = app.devices[app.cursor].clone();
                let events_tx = app.events_tx.clone();

                let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
                tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel_rx.recv() => {
                            debug!("Scan has been canceled");
                            events_tx.send(Message::ScanEnded).await.ok();
                        }
                        ret = run_scan(adb_host, device, events_tx.clone()) => {
                            debug!("Scan has completed: {:?}", ret); // TODO print errors in UI
                            events_tx.send(Message::ScanEnded).await.ok();
                        }
                    }
                });
                app.scan = Some(Scan::default());
                app.cancel_scan = Some(cancel_tx);
                app.save_cursor();
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
            // TODO: check if we're in device list or report view
            app.refresh_devices().await?;
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

pub async fn run<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    let mut stream = EventStream::new();

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
                    Message::ScanEnded => {
                        app.cancel_scan.take();
                    }
                    Message::Suspicion(sus) => {
                        if let Some(scan) = &mut app.scan {
                            scan.findings.push(sus);
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
                }
            }
        }
    }

    Ok(())
}

fn cursor<'a, T: IntoIterator<Item = Span<'a>>>(msg: T, selected: bool) -> (Spans<'a>, Style) {
    let mut style = Style::default();
    if selected {
        style = style.bg(DARK_GREY);
    }

    let mut row = vec![Span::styled(
        if selected { " > " } else { "   " },
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )];
    row.extend(msg);

    (Spans::from(row), style)
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
            ]
            .as_ref(),
        )
        .split(f.size());

    let text = Text::from(Spans::from(vec![
        Span::raw(if app.cancel_scan.is_some() {
            "scanning - "
        } else {
            "idle - "
        }),
        Span::raw("Press "),
        Span::styled("ESC", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" to exit - "),
        Span::raw(concat!(
            env!("CARGO_PKG_NAME"),
            " v",
            env!("CARGO_PKG_VERSION")
        )),
    ]));
    let help_message = Paragraph::new(text)
        .style(white)
        .alignment(Alignment::Right);
    f.render_widget(help_message, chunks[0]);

    f.render_widget(Block::default().style(white), chunks[1]);

    let widget = if let Some(scan) = &app.scan {
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
                    iocs::SuspicionLevel::High.terminal_color(),
                ));
            }

            if !findings.medium.is_empty() {
                details.push(Span::styled(
                    format!("{} medium", findings.medium.len()),
                    iocs::SuspicionLevel::Medium.terminal_color(),
                ));
            }

            if !findings.low.is_empty() {
                details.push(Span::styled(
                    format!("{} low", findings.low.len()),
                    iocs::SuspicionLevel::Low.terminal_color(),
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
    };
    f.render_widget(widget, chunks[2]);
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
