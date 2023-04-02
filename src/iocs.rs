use crate::errors::*;
use std::path::{Path, PathBuf};

const GIT_REPO_URL: &str = "https://github.com/AssoEchap/stalkerware-indicators.git";
const GIT_REPO_REMOTE: &str = "origin";
const GIT_REPO_BRANCH: &str = "master";

#[derive(Debug, PartialEq)]
pub struct Suspicion {
    pub level: SuspicionLevel,
    pub description: String,
}

#[derive(Debug, PartialEq)]
pub enum SuspicionLevel {
    High,
    Medium,
    Low,
}

pub struct Repository {
    repo: git2::Repository,
}

impl Repository {
    pub fn new(repo: git2::Repository) -> Self {
        Self { repo }
    }

    pub fn data_path() -> Result<PathBuf> {
        let dir = dirs::data_local_dir().context("Failed to find local data dir")?;
        let dir = dir.join("spytrap-adb");
        Ok(dir)
    }

    pub fn repo_path() -> Result<PathBuf> {
        Ok(Self::data_path()?.join("iocs"))
    }

    pub fn ioc_file_path() -> Result<PathBuf> {
        Ok(Self::repo_path()?.join("ioc.yaml"))
    }

    pub async fn init() -> Result<Self> {
        let dir = Self::repo_path()?;
        Self::init_at(&dir).await
    }

    pub async fn init_at(path: &Path) -> Result<Self> {
        debug!("Opening repository at {path:?}...");
        let repo = git2::Repository::init(path)
            .with_context(|| anyhow!("Failed to open git repository at {path:?}"))?;
        Ok(Self { repo })
    }

    pub fn ensure_remote(&self) -> Result<()> {
        if !self
            .repo
            .remotes()?
            .iter()
            .any(|r| r == Some(GIT_REPO_REMOTE))
        {
            debug!("Adding `{GIT_REPO_REMOTE}` remote at {GIT_REPO_URL:?} to git repo...");
            self.repo.remote(GIT_REPO_REMOTE, GIT_REPO_URL)
                .with_context(|| anyhow!("Failed to add `{GIT_REPO_REMOTE}` remote for stalkerware-indicators repo at {GIT_REPO_URL:?}"))?;
        }
        Ok(())
    }

    pub fn fetch(&self) -> Result<()> {
        // TODO: this should do a shallow clone with depth=1
        info!("Fetching updates from git remote...");
        let mut remote = self.repo.find_remote(GIT_REPO_REMOTE)?;
        remote.fetch(&[GIT_REPO_BRANCH], None, None)?;
        Ok(())
    }

    pub fn checkout(&self) -> Result<()> {
        info!("Checking out latest IOC list from git...");
        let remote_branch = format!("{GIT_REPO_REMOTE}/{GIT_REPO_BRANCH}");
        let object = self
            .repo
            .revparse_single(&remote_branch)
            .with_context(|| anyhow!("Failed to resolve `{remote_branch}` branch"))?;
        self.repo
            .reset(&object, git2::ResetType::Hard, None)
            .context("Failed to reset repository to latest upstream commit")?;
        Ok(())
    }
}
