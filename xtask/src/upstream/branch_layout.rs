//! The layout of the `upstream` branch — the interface for its readers (the registry site and
//! the private laboratory): `state.json`, `latest/facts.json`, `index.json` and
//! `history/<id>/{facts,diff,changes}.json`, all JSON. `run.json` goes with an emit directory
//! only, never into the branch.

use serde::{Deserialize, Serialize};

use super::diff::{EntryKind, Summary};
use super::poll::Alert;

/// The poll state.
pub const STATE: &str = "state.json";
/// The latest facts.
pub const LATEST: &str = "latest/facts.json";
/// The index of the history.
pub const INDEX: &str = "index.json";
/// What a run did (emit directory only).
pub const RUN: &str = "run.json";
/// The files of a history entry.
pub const HISTORY_FILES: [&str; 3] = ["facts.json", "diff.json", "changes.json"];

/// The schema version of `index.json` and `run.json`.
pub const INDEX_SCHEMA: u32 = 1;

/// `history/<id>/`.
pub fn history_dir(id: &str) -> String {
    format!("history/{id}/")
}

/// `<date>-<version>-<key8>`, the version's characters outside `[A-Za-z0-9._-]` as `_`.
pub fn entry_id(date: &str, version: &str, key8: &str) -> String {
    let version: String = version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let version = if version.is_empty() {
        "_".to_owned()
    } else {
        version
    };
    format!("{date}-{version}-{key8}")
}

/// Whether `id` matches `^[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Za-z0-9._-]+$` and is no path trick.
pub fn is_entry_id(id: &str) -> bool {
    let b = id.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|s| s.iter().all(u8::is_ascii_digit));
    b.len() > 11
        && b.len() <= 128
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'-'
        && b[11..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && !id.contains("..")
}

/// `index.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    /// [`INDEX_SCHEMA`].
    pub schema: u32,
    /// Entries by `observed`, oldest first.
    pub entries: Vec<IndexEntry>,
}

impl Default for Index {
    fn default() -> Self {
        Index {
            schema: INDEX_SCHEMA,
            entries: Vec::new(),
        }
    }
}

/// An entry of the history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    /// [`entry_id`].
    pub id: String,
    /// `YYYY-MM-DD`.
    pub date: String,
    /// When it was observed, RFC 3339 UTC.
    pub observed: String,
    /// The manifest's version.
    pub version: String,
    /// The first 8 hex digits of the SHA-256 of its `facts.json`.
    pub key8: String,
    /// [`history_dir`].
    pub path: String,
    /// What it is.
    pub kind: EntryKind,
    /// Plain-text summary.
    pub summary: Summary,
    /// Its issues.
    pub issues: Vec<IssueRef>,
}

/// An issue of an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRef {
    /// The `upstream-key`.
    pub key: String,
    /// The issue number.
    pub number: u64,
    /// Its label.
    pub label: String,
}

/// `run.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunJson {
    /// [`INDEX_SCHEMA`].
    pub schema: u32,
    /// Whether branch files were emitted.
    pub changed: bool,
    /// The new history entry.
    pub entry: Option<String>,
    /// Alerts.
    pub alerts: Vec<Alert>,
    /// The external tools' versions.
    pub tools: ToolVersions,
}

/// The versions of the external tools.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolVersions {
    /// innounp.
    pub innounp: Option<String>,
    /// 7-Zip.
    pub sevenzip: Option<String>,
}
