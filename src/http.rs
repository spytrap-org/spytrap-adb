use crate::errors::*;
use chrono::{offset::Utc, DateTime};
use serde::{Deserialize, Serialize};

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
}

impl Client {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()
            .context("Failed to setup http client")?;
        Ok(Self { http })
    }

    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let req = self
            .http
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

    pub async fn github_branch_metadata(&self, base_url: &str, branch: &str) -> Result<GithubRef> {
        let url = format!("{}/{}", base_url, branch);

        info!("Fetching git repository meta data: {url:?}...");
        let metadata = self
            .get(&url)
            .await?
            .json::<GithubBranch>()
            .await
            .context("Failed to receive http response")?;

        let commit = metadata.commit;
        debug!("Found github commit for branch {branch:?}: {commit:?}");
        Ok(commit)
    }

    pub async fn github_download_file(
        &self,
        base_url: &str,
        commit: &GithubRef,
        filename: &str,
    ) -> Result<String> {
        let url = base_url
            .replace("{{commit}}", &commit.sha)
            .replace("{{filename}}", filename);
        info!("Downloading IOC file from {url:?}...");
        let body = self
            .get(&url)
            .await?
            .text()
            .await
            .context("Failed to download HTTP response")?;
        Ok(body)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubBranch {
    pub name: String,
    pub commit: GithubRef,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubRef {
    pub sha: String,
    pub commit: GithubCommit,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubCommit {
    pub committer: GithubGitAuthor,
}

impl GithubCommit {
    pub fn release_timestamp(&self) -> Result<i64> {
        let date = &self.committer.date;
        let dt = DateTime::parse_from_rfc3339(date)
            .with_context(|| anyhow!("Failed to parse datetime from github: {date:?}"))?;
        let dt = DateTime::<Utc>::from(dt);
        Ok(dt.timestamp())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubGitAuthor {
    pub name: String,
    pub email: String,
    pub date: String,
}
