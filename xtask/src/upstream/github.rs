//! The GitHub REST calls of the publisher, with the workflow's `GITHUB_TOKEN`: issues by
//! their `upstream-key`, labels, comments and the `repository_dispatch` event. The token
//! never appears in an error or in the output.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::report::{Issue, Label, key_of};

/// Largest response read.
const RESPONSE_MAX: u64 = 16 << 20;
/// Longest wait for a rate limit.
const WAIT_MAX: u64 = 60;

/// The client.
pub struct Client {
    base: String,
    repo: String,
    token: Zeroizing<String>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

/// An issue found by its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueState {
    /// Its number.
    pub number: u64,
    /// Open.
    pub open: bool,
    /// Its body.
    pub body: String,
}

impl Client {
    /// A client of `repo` (`owner/name`) at `base`.
    pub fn new(base: &str, repo: &str, token: &str) -> Client {
        Client {
            base: base.trim_end_matches('/').to_owned(),
            repo: repo.to_owned(),
            token: Zeroizing::new(token.to_owned()),
        }
    }

    /// `GITHUB_API_URL` (default `https://api.github.com`), `GITHUB_REPOSITORY`,
    /// `GITHUB_TOKEN`.
    ///
    /// # Errors
    ///
    /// A variable is missing.
    pub fn from_env() -> anyhow::Result<Client> {
        let base =
            std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_owned());
        let repo = std::env::var("GITHUB_REPOSITORY").context("GITHUB_REPOSITORY is not set")?;
        let token =
            Zeroizing::new(std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN is not set")?);
        Ok(Client::new(&base, &repo, &token))
    }

    /// `owner/name`.
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// A request; 403/429 with a rate-limit header are retried once after at most a minute.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<(u16, Value)> {
        for attempt in 0..2 {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(60)))
                .user_agent("OpenNCALayer-upstream-watch")
                .build()
                .into();
            let url = format!("{}{path}", self.base);
            let auth = format!("Bearer {}", self.token.as_str());
            let response = match (method, body) {
                ("GET", _) => agent
                    .get(&url)
                    .header("Authorization", &auth)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .call(),
                (_, body) => {
                    let request = match method {
                        "PATCH" => agent.patch(&url),
                        _ => agent.post(&url),
                    }
                    .header("Authorization", &auth)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("Content-Type", "application/json");
                    let bytes = serde_json::to_vec(&body.cloned().unwrap_or(Value::Null))?;
                    request.send(&bytes[..])
                }
            };
            let mut response = response.map_err(|e| {
                anyhow::anyhow!("{method} {path}: {}", redact(&e.to_string(), &self.token))
            })?;
            let status = response.status().as_u16();
            if (status == 403 || status == 429) && attempt == 0 {
                let header = |name: &str| {
                    response
                        .headers()
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                };
                let wait = header("retry-after").or_else(|| {
                    header("x-ratelimit-reset").map(|reset| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs());
                        reset.saturating_sub(now)
                    })
                });
                if let Some(wait) = wait {
                    if wait > WAIT_MAX {
                        bail!("{method} {path}: rate limited for {wait} s");
                    }
                    std::thread::sleep(Duration::from_secs(wait));
                    continue;
                }
            }
            let bytes = response
                .body_mut()
                .with_config()
                .limit(RESPONSE_MAX)
                .read_to_vec()
                .map_err(|e| {
                    anyhow::anyhow!("{method} {path}: {}", redact(&e.to_string(), &self.token))
                })?;
            let value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap_or(Value::Null)
            };
            return Ok((status, value));
        }
        bail!("{method} {path}: rate limited")
    }

    fn expect(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        ok: &[u16],
    ) -> anyhow::Result<Value> {
        let (status, value) = self.call(method, path, body)?;
        if !ok.contains(&status) {
            bail!("{method} {path}: status {status}");
        }
        Ok(value)
    }

    /// The issues with the watcher's labels by their key (pull requests skipped).
    ///
    /// # Errors
    ///
    /// API errors.
    pub fn issues_by_key(&self) -> anyhow::Result<BTreeMap<String, IssueState>> {
        let mut out = BTreeMap::new();
        for label in Label::ALL {
            for page in 1.. {
                let path = format!(
                    "/repos/{}/issues?labels={}&state=all&per_page=100&page={page}",
                    self.repo,
                    label.name()
                );
                let value = self.expect("GET", &path, None, &[200])?;
                let items = value.as_array().cloned().unwrap_or_default();
                for item in &items {
                    if item.get("pull_request").is_some() {
                        continue;
                    }
                    let body = item["body"].as_str().unwrap_or_default();
                    let (Some(key), Some(number)) = (key_of(body), item["number"].as_u64()) else {
                        continue;
                    };
                    out.entry(key).or_insert(IssueState {
                        number,
                        open: item["state"].as_str() == Some("open"),
                        body: body.to_owned(),
                    });
                }
                if items.len() < 100 {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Creates the missing labels.
    ///
    /// # Errors
    ///
    /// API errors.
    pub fn ensure_labels(&self) -> anyhow::Result<()> {
        for label in Label::ALL {
            let path = format!("/repos/{}/labels/{}", self.repo, label.name());
            let (status, _) = self.call("GET", &path, None)?;
            match status {
                200 => {}
                404 => {
                    self.expect(
                        "POST",
                        &format!("/repos/{}/labels", self.repo),
                        Some(&json!({
                            "name": label.name(),
                            "color": label.color(),
                            "description": "Наблюдатель за оригиналом NCALayer",
                        })),
                        &[201],
                    )?;
                }
                s => bail!("GET {path}: status {s}"),
            }
        }
        Ok(())
    }

    /// Creates `issue`; returns its number.
    ///
    /// # Errors
    ///
    /// API errors.
    pub fn create_issue(&self, issue: &Issue) -> anyhow::Result<u64> {
        let value = self.expect(
            "POST",
            &format!("/repos/{}/issues", self.repo),
            Some(&json!({
                "title": issue.title,
                "body": issue.body,
                "labels": [issue.label.name()],
            })),
            &[201],
        )?;
        value["number"]
            .as_u64()
            .context("no number in the created issue")
    }

    /// Replaces the body of issue `number`.
    ///
    /// # Errors
    ///
    /// API errors.
    pub fn update_body(&self, number: u64, body: &str) -> anyhow::Result<()> {
        self.expect(
            "PATCH",
            &format!("/repos/{}/issues/{number}", self.repo),
            Some(&json!({ "body": body })),
            &[200],
        )
        .map(drop)
    }

    /// Comments on issue `number`.
    ///
    /// # Errors
    ///
    /// API errors.
    pub fn comment(&self, number: u64, text: &str) -> anyhow::Result<()> {
        self.expect(
            "POST",
            &format!("/repos/{}/issues/{number}/comments", self.repo),
            Some(&json!({ "body": text })),
            &[201],
        )
        .map(drop)
    }

    /// Sends the `repository_dispatch` event `event_type`.
    ///
    /// # Errors
    ///
    /// API errors.
    pub fn dispatch(&self, event_type: &str) -> anyhow::Result<()> {
        self.expect(
            "POST",
            &format!("/repos/{}/dispatches", self.repo),
            Some(&json!({ "event_type": event_type })),
            &[204, 200],
        )
        .map(drop)
    }
}

fn redact(text: &str, token: &str) -> String {
    if token.is_empty() {
        text.to_owned()
    } else {
        text.replace(token, "***")
    }
}
