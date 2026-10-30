//! `state.json` of the `upstream` branch: what the last poll saw of each source and its run
//! of failures. No time of a run is kept, so an unchanged world gives the same bytes.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The schema version of `state.json`.
pub const STATE_SCHEMA: u32 = 1;

/// `state.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// [`STATE_SCHEMA`].
    pub schema: u32,
    /// By source id.
    pub sources: BTreeMap<String, SourceState>,
}

impl Default for State {
    fn default() -> Self {
        State {
            schema: STATE_SCHEMA,
            sources: BTreeMap::new(),
        }
    }
}

/// What the last poll saw of a source.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceState {
    /// The URL (a page link without its key).
    pub url: String,
    /// `Content-Length`.
    pub size: Option<u64>,
    /// `ETag`.
    pub etag: Option<String>,
    /// `Last-Modified`.
    pub last_modified: Option<String>,
    /// SHA-256 of the content last downloaded.
    pub sha256: Option<String>,
    /// The SHA-1 published on the download page.
    pub published_sha1: Option<String>,
    /// The `hash` the manifest gives.
    pub manifest_hash: Option<String>,
    /// Failed polls in a row.
    pub failures: u32,
    /// The outcome.
    pub status: SourceStatus,
}

/// The outcome of the last poll of a source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// Seen.
    #[default]
    Ok,
    /// Failed fewer than [`super::FAILURES_TO_REMOVE`] times in a row.
    Failing,
    /// Failed that many times: removed.
    Gone,
    /// Its address is not public: never requested.
    Refused,
}

impl State {
    /// `state.json` of `dir`; none = empty.
    ///
    /// # Errors
    ///
    /// An unreadable or invalid file.
    pub fn load(dir: &Path) -> anyhow::Result<State> {
        let path = dir.join(super::branch_layout::STATE);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let state: State = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse {}", path.display()))?;
                anyhow::ensure!(
                    state.schema == STATE_SCHEMA,
                    "{}: schema {} is not {STATE_SCHEMA}",
                    path.display(),
                    state.schema
                );
                Ok(state)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Pretty JSON with a final newline; keys sorted.
    pub fn to_json(&self) -> Vec<u8> {
        super::pretty_json(self)
    }
}
