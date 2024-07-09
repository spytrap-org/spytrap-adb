use crate::errors::*;
use chrono::{offset::Utc, DateTime};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
}

impl Client {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
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
        let datetime = &self.committer.date;
        let timestamp = parse_datetime(datetime)
            .with_context(|| anyhow!("Failed to parse datetime from github: {datetime:?}"))?;
        Ok(timestamp)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GithubGitAuthor {
    pub name: String,
    pub email: String,
    pub date: String,
}

fn parse_datetime(datetime: &str) -> Result<i64> {
    let dt = DateTime::parse_from_rfc3339(datetime)?;
    let dt = DateTime::<Utc>::from(dt);
    Ok(dt.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_datetime() {
        let timestamp = parse_datetime("2024-07-02T23:34:14Z").unwrap();
        assert_eq!(timestamp, 1719963254);
    }
}
