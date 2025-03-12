use crate::errors::*;
use crate::http;
use crate::rules;
use crate::utils;
use indexmap::IndexMap;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;

// query the latest commit to detect if we need to update
pub const IOC_GIT_BRANCHES_URL: &str =
    "https://api.github.com/repos/AssoEchap/stalkerware-indicators/branches";
pub const IOC_GIT_BRANCH: &str = "master";
const IOC_DOWNLOAD_URL: &str =
    "https://github.com/AssoEchap/stalkerware-indicators/raw/{{commit}}/{{filename}}";
const IOC_DB_FILES: &[&str] = &["ioc.yaml", "watchware.yaml"];

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
                    SuspicionLevel::Good => "good",
                },
                self.level.terminal_color(),
            ),
            Span::raw(": "),
            Span::raw(&self.description),
        ]
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum SuspicionLevel {
    Good,
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
            SuspicionLevel::Good => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryContent {
    pub last_update_check: i64,
    #[serde(default)]
    pub update_available: bool,
    pub released: i64,
    pub git_commit: String,
    pub files: IndexMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Repository {
    pub path: PathBuf,
    pub content: Option<RepositoryContent>,
    pub client: http::Client,
}

impl Repository {
    pub fn data_path() -> Result<PathBuf> {
        let dir = dirs::data_local_dir().context("Failed to find local data dir")?;
        let dir = dir.join("spytrap-adb");
        Ok(dir)
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

        let db_path = path.join("update.json");
        let content = match fs::read(&db_path).await {
            Ok(buf) => serde_json::from_slice::<RepositoryContent>(&buf).ok(),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err)
                    .with_context(|| anyhow!("Failed to read database file at {db_path:?}"));
            }
        };

        let client = http::Client::new()?;
        Ok(Self {
            path: db_path,
            content,
            client,
        })
    }

    pub async fn query_latest_branch(&self) -> Result<http::GithubRef> {
        let branch = self
            .client
            .github_branch_metadata(IOC_GIT_BRANCHES_URL, IOC_GIT_BRANCH)
            .await?;
        Ok(branch)
    }

    pub async fn download_ioc_db(&mut self) -> Result<()> {
        let branch = self.query_latest_branch().await?;

        if let Some(content) = &mut self.content {
            if content.git_commit == branch.sha {
                info!(
                    "We're still on most recent git commit, marking as fresh... (commit={:?})",
                    branch.sha
                );
                content.update_available = false;
                content.last_update_check = utils::now();
                self.write_database_file()
                    .await
                    .context("Failed to write database file")?;
                return Ok(());
            }
        }

        let now = utils::now();
        let released = branch.commit.release_timestamp()?;

        let mut files = IndexMap::new();
        for filename in IOC_DB_FILES {
            let data = self
                .client
                .github_download_file(IOC_DOWNLOAD_URL, &branch, filename)
                .await?;
            files.insert(filename.to_string(), data);
        }

        self.content = Some(RepositoryContent {
            last_update_check: now,
            update_available: false,
            released,
            git_commit: branch.sha,
            files,
        });
        self.write_database_file()
            .await
            .context("Failed to write database file")?;
        Ok(())
    }

    pub async fn write_database_file(&self) -> Result<()> {
        let path = &self.path;
        let mut buf = serde_json::to_vec(&self.content)?;
        buf.push(b'\n');
        debug!("Writing database file to {path:?}...");
        fs::write(&path, &buf)
            .await
            .with_context(|| anyhow!("Failed to write database file at {path:?}"))?;
        Ok(())
    }

    pub fn parse_rules(&self) -> Result<rules::Rules> {
        let content = self
            .content
            .as_ref()
            .context("Local IOC repository does not have any content downloaded yet")?;
        let mut rules = rules::Rules::default();
        for (name, data) in &content.files {
            rules.load_yaml(name, data.as_bytes())?;
        }
        Ok(rules)
    }
}
