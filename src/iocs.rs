use crate::errors::*;
use crate::utils;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;

// query the latest commit to detect if we need to update
const IOC_GIT_REFS_URL: &str =
    "https://api.github.com/repos/AssoEchap/stalkerware-indicators/branches";
const IOC_GIT_BRANCH: &str = "master";
const IOC_REFRESH_INTERVAL: i64 = 3 * 60; // Assume the cache is ok for 3h
const IOC_DOWNLOAD_URL: &str =
    "https://github.com/AssoEchap/stalkerware-indicators/raw/{{commit}}/ioc.yaml";

#[derive(Debug, PartialEq, Eq)]
pub struct Suspicion {
    pub level: SuspicionLevel,
    pub description: String,
}

impl Suspicion {
    pub fn to_terminal(&self) -> Vec<Span> {
        vec![
            Span::styled(
                match self.level {
                    SuspicionLevel::High => "high",
                    SuspicionLevel::Medium => "medium",
                    SuspicionLevel::Low => "low",
                },
                self.level.terminal_color(),
            ),
            Span::raw(": "),
            Span::raw(&self.description),
        ]
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd)]
pub enum SuspicionLevel {
    Low,
    Medium,
    High,
}

impl SuspicionLevel {
    pub fn terminal_color(&self) -> Style {
        match self {
            SuspicionLevel::High => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            SuspicionLevel::Medium => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            SuspicionLevel::Low => Style::default().add_modifier(Modifier::BOLD),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateState {
    pub last_update_check: i64,
    pub last_updated: i64,
    pub git_commit: String,
    pub sha256: String,
}

pub struct Repository {
    pub update_state: Option<UpdateState>,
    client: reqwest::Client,
}

impl Repository {
    pub fn data_path() -> Result<PathBuf> {
        let dir = dirs::data_local_dir().context("Failed to find local data dir")?;
        let dir = dir.join("spytrap-adb");
        Ok(dir)
    }

    pub fn ioc_file_path() -> Result<PathBuf> {
        Ok(Self::data_path()?.join("ioc.yaml"))
    }

    pub fn update_file_path() -> Result<PathBuf> {
        Ok(Self::data_path()?.join("update.json"))
    }

    pub async fn init() -> Result<Self> {
        let dir = Self::data_path()?;
        Self::init_at(&dir).await
    }

    pub async fn init_at(path: &Path) -> Result<Self> {
        debug!("Opening repository at {path:?}...");
        fs::create_dir_all(path)
            .await
            .with_context(|| anyhow!("Failed to create directory at {path:?}"))?;

        let update_file_path = Self::update_file_path()?;
        let update_state = match fs::read(&update_file_path).await {
            Ok(buf) => serde_json::from_slice::<UpdateState>(&buf).ok(),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err)
                    .with_context(|| anyhow!("Failed to read update file at {update_file_path:?}"))
            }
        };

        static APP_USER_AGENT: &str =
            concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

        let client = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()
            .context("Failed to setup http client")?;
        Ok(Self {
            update_state,
            client,
        })
    }

    fn ioc_download_url(commit: &GithubCommit) -> String {
        IOC_DOWNLOAD_URL.replace("{{commit}}", &commit.sha)
    }

    pub fn is_update_check_due(&self) -> bool {
        if let Some(update_state) = &self.update_state {
            let age = utils::now() - update_state.last_update_check;
            age >= IOC_REFRESH_INTERVAL
        } else {
            true
        }
    }

    pub async fn sync_ioc_file(&mut self) -> Result<()> {
        debug!("Starting update check");
        let commit = self
            .current_github_commit(IOC_GIT_REFS_URL)
            .await
            .context("Failed to determine latest git commit for stalkerware-indicators")?;

        if let Some(update_state) = &mut self.update_state {
            if update_state.git_commit == commit.sha {
                let path = Self::ioc_file_path()?;
                let buf = fs::read(&path)
                    .await
                    .with_context(|| anyhow!("Failed to open ioc file at {path:?}"))?;

                if update_state.sha256 == utils::sha256(&buf) {
                    info!(
                        "We're still on most recent git commit, marking as fresh... (commit={:?})",
                        commit.sha
                    );
                    update_state.last_update_check = utils::now();
                    self.write_state_file()
                        .await
                        .context("Failed to write update state file")?;
                    return Ok(());
                }
            }
        }

        let ioc_download_url = Self::ioc_download_url(&commit);
        let sha256 = self.download_ioc_database(&ioc_download_url).await?;

        let now = utils::now();
        self.update_state = Some(UpdateState {
            last_update_check: now,
            last_updated: now,
            git_commit: commit.sha,
            sha256,
        });

        self.write_state_file()
            .await
            .context("Failed to write update state file")?;

        debug!("Update check complete");

        Ok(())
    }

    async fn http_get(&self, url: &str) -> Result<reqwest::Response> {
        let req = self
            .client
            .get(url)
            .send()
            .await
            .context("Failed to send HTTP request")?;

        let status = req.status();
        let headers = req.headers();
        trace!("Received response from server: status={status:?}, headers={headers:?}");

        let req = req.error_for_status()?;
        Ok(req)
    }

    pub async fn download_ioc_database(&mut self, url: &str) -> Result<String> {
        info!("Downloading IOC file from {url:?}...");
        let body = self
            .http_get(url)
            .await?
            .bytes()
            .await
            .context("Failed to download HTTP response")?;

        let ioc_file_path = Self::ioc_file_path()?;
        debug!(
            "Writing IOC file to {ioc_file_path:?}... ({} bytes)",
            body.len()
        );
        fs::write(&ioc_file_path, &body)
            .await
            .with_context(|| anyhow!("Failed to write IOC file to {ioc_file_path:?}"))?;

        let sha256 = utils::sha256(&body);

        Ok(sha256)
    }

    async fn write_state_file(&self) -> Result<()> {
        let update_file_path = Self::update_file_path()?;
        let mut buf = serde_json::to_vec(&self.update_state)?;
        buf.push(b'\n');
        debug!("Writing update state file to {update_file_path:?}...");
        fs::write(&update_file_path, &buf).await.with_context(|| {
            anyhow!("Failed to write update state file at {update_file_path:?}")
        })?;
        Ok(())
    }

    async fn current_github_commit(&self, url: &str) -> Result<GithubCommit> {
        info!("Fetching git repository meta data: {url:?}...");
        let branches = self
            .http_get(url)
            .await?
            .json::<Vec<GithubBranch>>()
            .await
            .context("Failed to receive http response")?;

        for branch in branches {
            if branch.name == IOC_GIT_BRANCH {
                let commit = branch.commit;
                debug!("Found github commit for branch {IOC_GIT_BRANCH}: {commit:?}");
                return Ok(commit);
            }
        }

        bail!("Failed to find branch: {IOC_GIT_BRANCH:?}")
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubBranch {
    name: String,
    commit: GithubCommit,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubCommit {
    sha: String,
}
