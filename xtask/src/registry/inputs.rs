//! What the site reads besides the ports: the channels' update indexes (data of the
//! repository: an error stops the build), the list of the project's releases and the facts
//! of the `upstream` branch (external inputs: the caller turns an error into a warning).
//! Every file is read with the limit [`MAX_INPUT`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, bail};
use oncl_update::{Channel, Index, Version};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::index::{check_asset_urls, index_path};
use crate::plugin::read_limited;

/// The largest input file read.
pub const MAX_INPUT: u64 = 8 * 1024 * 1024;

/// What a channel's index offers.
#[derive(Debug, Clone)]
pub struct ChannelView {
    /// The index's `seq`.
    pub seq: u64,
    /// When it was made.
    pub generated: OffsetDateTime,
    /// When it stops being valid.
    pub expires: OffsetDateTime,
    /// The newest core version not revoked.
    pub core: Option<Version>,
    /// The newest version not revoked of each plugin, by id.
    pub plugins: BTreeMap<String, PluginView>,
}

/// A plugin's version in a channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginView {
    /// The port's version.
    pub version: Version,
    /// The oldest core it runs on.
    pub min_core: Version,
    /// The percentage of installations it is offered to.
    pub rollout: u8,
    /// The package.
    pub url: String,
    /// Its sha256, lowercase hex.
    pub sha256: String,
    /// Its size in bytes.
    pub size: u64,
}

/// The channels whose index is in `dir` (`updates/v1`): a missing directory or file is a
/// channel without an index.
///
/// # Errors
///
/// An index that cannot be read, is invalid, is of another channel or fails
/// [`check_asset_urls`].
pub fn read_channels(dir: &Path) -> anyhow::Result<BTreeMap<Channel, ChannelView>> {
    let mut channels = BTreeMap::new();
    for channel in Channel::ALL {
        let path = index_path(dir, channel);
        if !path.is_file() {
            continue;
        }
        let bytes = read_limited(&path, MAX_INPUT)?;
        let index =
            Index::from_json(&bytes).with_context(|| format!("reading {}", path.display()))?;
        if index.channel != channel {
            bail!("{}: the channel is {}", path.display(), index.channel);
        }
        check_asset_urls(&index).with_context(|| path.display().to_string())?;
        channels.insert(channel, view(&index));
    }
    Ok(channels)
}

fn view(index: &Index) -> ChannelView {
    let core = index
        .core
        .iter()
        .filter(|r| !r.revoked)
        .map(|r| &r.version)
        .max()
        .cloned();
    let mut plugins: BTreeMap<String, PluginView> = BTreeMap::new();
    for plugin in index.plugins.iter().filter(|p| !p.revoked) {
        let newer = plugins
            .get(&plugin.id)
            .is_none_or(|known| plugin.version > known.version);
        if newer {
            plugins.insert(
                plugin.id.clone(),
                PluginView {
                    version: plugin.version.clone(),
                    min_core: plugin.min_core.clone(),
                    rollout: plugin.rollout,
                    url: plugin.package.url.clone(),
                    sha256: plugin.package.sha256.to_string(),
                    size: plugin.package.size,
                },
            );
        }
    }
    ChannelView {
        seq: index.seq,
        generated: index.generated,
        expires: index.expires,
        core,
        plugins,
    }
}

/// A published release of the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Its version, the tag without `v`.
    pub version: Version,
    /// Whether GitHub marks it a pre-release.
    pub prerelease: bool,
    /// The day it was published, `YYYY-MM-DD`, or empty.
    pub published: String,
    /// The names of its assets.
    pub assets: BTreeSet<String>,
}

/// One line of the releases file, as `gh api …/releases` gives it.
#[derive(Deserialize)]
struct ReleaseLine {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<AssetLine>,
}

#[derive(Deserialize)]
struct AssetLine {
    name: String,
}

/// The releases of the JSON Lines file `path`: drafts and tags other than `v<semver>`
/// (`plugins-*`) are left out.
///
/// # Errors
///
/// The file is missing, too large, or a line is not a release.
pub fn read_releases(path: &Path) -> anyhow::Result<Vec<Release>> {
    let bytes = read_limited(path, MAX_INPUT)?;
    let text = std::str::from_utf8(&bytes).with_context(|| path.display().to_string())?;
    let mut releases = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line: ReleaseLine =
            serde_json::from_str(line).with_context(|| format!("{}:{}", path.display(), n + 1))?;
        if line.draft {
            continue;
        }
        let Some(version) = line
            .tag_name
            .strip_prefix('v')
            .and_then(|v| Version::parse(v).ok())
        else {
            continue;
        };
        let published = line
            .published_at
            .as_deref()
            .and_then(|at| at.get(..10))
            .filter(|day| is_date(day))
            .unwrap_or_default()
            .to_owned();
        releases.push(Release {
            version,
            prerelease: line.prerelease,
            published,
            assets: line.assets.into_iter().map(|a| a.name).collect(),
        });
    }
    Ok(releases)
}

/// The newest release, and the newest pre-release if it is newer than that release.
pub fn latest(releases: &[Release]) -> (Option<&Release>, Option<&Release>) {
    let release = releases
        .iter()
        .filter(|r| !r.prerelease)
        .max_by(|a, b| a.version.cmp(&b.version));
    let prerelease = releases
        .iter()
        .filter(|r| r.prerelease)
        .max_by(|a, b| a.version.cmp(&b.version))
        .filter(|pre| release.is_none_or(|r| pre.version > r.version));
    (release, prerelease)
}

/// `YYYY-MM-DD`.
pub(crate) fn is_date(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// What the `upstream` branch says about the original.
#[derive(Debug, Clone, Default)]
pub struct Upstream {
    /// `latest/facts.json`.
    pub facts: Option<Facts>,
    /// `index.json`, as the branch orders it (by `observed`).
    pub history: Vec<HistoryEntry>,
    /// The entries left out, and why.
    pub warnings: Vec<String>,
}

/// The original's current manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The manifest's version.
    pub version: String,
    /// Its bundles, by symbolic name.
    pub bundles: BTreeMap<String, FactBundle>,
}

/// A bundle of the original's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FactBundle {
    /// Its version.
    pub version: String,
    /// Whether the original installs it always (a core bundle).
    #[serde(default)]
    pub required: bool,
}

/// What kind of change an entry of the history is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryKind {
    /// The first observation.
    Baseline,
    /// The manifest or a bundle changed.
    Change,
    /// Only the packing changed.
    Repack,
}

/// How a bundle changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// It appeared.
    Added,
    /// It is gone.
    Removed,
    /// Its version changed.
    Changed,
}

/// A bundle's change in an entry of the history.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PluginChange {
    /// Its symbolic name.
    pub symname: String,
    /// The version before.
    pub from: Option<String>,
    /// The version after.
    pub to: Option<String>,
    /// What changed.
    pub change: ChangeKind,
}

/// An entry of the history of the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// `<YYYY-MM-DD>-<version>-<key8>`.
    pub id: String,
    /// The day, `YYYY-MM-DD`.
    pub date: String,
    /// When it was observed, as the branch writes it (the order of the history).
    pub observed: String,
    /// The original's version.
    pub version: String,
    /// What kind of change.
    pub kind: HistoryKind,
    /// `history/<id>/`, kept only if it is exactly that.
    pub path: Option<String>,
    /// The core bundles that changed.
    pub core: Vec<String>,
    /// The other bundles that changed.
    pub plugins: Vec<PluginChange>,
    /// Notes.
    pub notes: Vec<String>,
    /// The numbers of the issues opened for it.
    pub issues: Vec<u64>,
}

#[derive(Deserialize)]
struct IndexFile {
    schema: u32,
    #[serde(default)]
    entries: Vec<EntryFile>,
}

#[derive(Deserialize)]
struct EntryFile {
    id: String,
    date: String,
    #[serde(default)]
    observed: String,
    version: String,
    kind: HistoryKind,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    summary: SummaryFile,
    #[serde(default)]
    issues: Vec<IssueFile>,
}

#[derive(Default, Deserialize)]
struct SummaryFile {
    #[serde(default)]
    core: Vec<String>,
    #[serde(default)]
    plugins: Vec<PluginChange>,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Deserialize)]
struct IssueFile {
    number: u64,
}

#[derive(Deserialize)]
struct FactsFile {
    manifest: ManifestFile,
    #[serde(default)]
    bundles: BTreeMap<String, FactBundle>,
}

#[derive(Deserialize)]
struct ManifestFile {
    version: String,
}

/// The facts of the `upstream` branch in `dir`: `index.json` and `latest/facts.json`, each
/// absent if its file is.
///
/// # Errors
///
/// A file that is too large or not of the schema, or `index.json` of a schema other than 1.
pub fn read_upstream(dir: &Path) -> anyhow::Result<Upstream> {
    let mut upstream = Upstream::default();
    let facts = dir.join("latest/facts.json");
    if facts.is_file() {
        let file: FactsFile = serde_json::from_slice(&read_limited(&facts, MAX_INPUT)?)
            .with_context(|| facts.display().to_string())?;
        upstream.facts = Some(Facts {
            version: file.manifest.version,
            bundles: file.bundles,
        });
    }
    let index = dir.join("index.json");
    if index.is_file() {
        let file: IndexFile = serde_json::from_slice(&read_limited(&index, MAX_INPUT)?)
            .with_context(|| index.display().to_string())?;
        if file.schema != 1 {
            bail!("{}: schema {} is not 1", index.display(), file.schema);
        }
        for entry in file.entries {
            if !is_date(&entry.date) {
                upstream.warnings.push(format!(
                    "{}: the entry {:?} has no YYYY-MM-DD date; left out",
                    index.display(),
                    entry.id
                ));
                continue;
            }
            let path = entry.path.filter(|path| {
                is_history_id(&entry.id) && *path == format!("history/{}/", entry.id)
            });
            upstream.history.push(HistoryEntry {
                id: entry.id,
                date: entry.date,
                observed: entry.observed,
                version: entry.version,
                kind: entry.kind,
                path,
                core: entry.summary.core,
                plugins: entry.summary.plugins,
                notes: entry.summary.notes,
                issues: entry.issues.into_iter().map(|i| i.number).collect(),
            });
        }
    }
    Ok(upstream)
}

/// `^[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Za-z0-9._-]{1,96}$`.
fn is_history_id(id: &str) -> bool {
    let Some((date, rest)) = id.split_at_checked(10) else {
        return false;
    };
    let Some(tail) = rest.strip_prefix('-') else {
        return false;
    };
    is_date(date)
        && (1..=96).contains(&tail.len())
        && tail
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    fn fixtures() -> PathBuf {
        oncl_testkit::workspace_root().join("fixtures/registry")
    }

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn alpha() -> &'static str {
        "io.github.arynyklas.openncalayer.port.alpha"
    }

    #[test]
    fn channels_absent_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_channels(&dir.path().join("none")).unwrap().is_empty());
        assert!(read_channels(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn channels_read_fixture() {
        let channels = read_channels(&fixtures().join("updates/v1")).unwrap();
        let stable = &channels[&Channel::Stable];
        assert_eq!(stable.core, Some(v("0.2.0")));
        assert_eq!(stable.seq, 3);
        assert_eq!(stable.plugins[alpha()].version, v("1.0.0"));
        let beta = &channels[&Channel::Beta];
        assert_eq!(beta.core, Some(v("0.3.0-beta.1")));
        let plugin = &beta.plugins[alpha()];
        assert_eq!(plugin.version, v("1.1.0-beta.1"));
        assert_eq!(plugin.rollout, 25);
        assert_eq!(plugin.sha256, "22".repeat(32));
    }

    fn write_index(dir: &Path, name: &str, value: &serde_json::Value) {
        fs::write(dir.join(name), serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn fixture_index(channel: &str) -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(fixtures().join(format!("updates/v1/{channel}.json"))).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn revoked_versions_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = fixture_index("stable");
        index["core"][1]["revoked"] = json!(true);
        index["plugins"][0]["revoked"] = json!(true);
        write_index(dir.path(), "stable.json", &index);
        let channels = read_channels(dir.path()).unwrap();
        let stable = &channels[&Channel::Stable];
        assert_eq!(stable.core, Some(v("0.1.0")));
        assert!(stable.plugins.is_empty());
    }

    #[test]
    fn channel_name_must_match_file() {
        let dir = tempfile::tempdir().unwrap();
        write_index(dir.path(), "beta.json", &fixture_index("stable"));
        let err = read_channels(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("beta.json"), "{err:#}");
    }

    #[test]
    fn foreign_plugin_url_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = fixture_index("stable");
        index["plugins"][0]["url"] = json!("https://example.com/plugins-20261101/x.onclp");
        write_index(dir.path(), "stable.json", &index);
        let err = read_channels(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("not an asset"), "{err:#}");
    }

    #[test]
    fn releases_skip_drafts_and_plugin_tags() {
        let releases = read_releases(&fixtures().join("releases.jsonl")).unwrap();
        let versions: Vec<String> = releases.iter().map(|r| r.version.to_string()).collect();
        assert_eq!(versions, ["0.3.0-beta.1", "0.2.0"]);
        assert_eq!(releases[1].published, "2026-10-20");
        assert!(releases[0].prerelease);
        assert!(releases[1].assets.contains("SHA256SUMS"));
    }

    fn release(version: &str, prerelease: bool) -> Release {
        Release {
            version: v(version),
            prerelease,
            published: String::new(),
            assets: BTreeSet::new(),
        }
    }

    #[test]
    fn latest_prerelease_only_if_newer() {
        let releases = [release("0.2.0", false), release("0.2.0-rc.1", true)];
        let (r, pre) = latest(&releases);
        assert_eq!(r.unwrap().version, v("0.2.0"));
        assert!(pre.is_none());
        let releases = [
            release("0.1.0", false),
            release("0.2.0", false),
            release("0.3.0-beta.1", true),
            release("0.3.0-beta.2", true),
        ];
        let (r, pre) = latest(&releases);
        assert_eq!(r.unwrap().version, v("0.2.0"));
        assert_eq!(pre.unwrap().version, v("0.3.0-beta.2"));
        let releases = [release("0.1.0-alpha.1", true)];
        assert_eq!(latest(&releases).1.unwrap().version, v("0.1.0-alpha.1"));
    }

    #[test]
    fn releases_reject_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("releases.jsonl");
        fs::write(&path, vec![b'\n'; MAX_INPUT as usize + 1]).unwrap();
        let err = read_releases(&path).unwrap_err();
        assert!(format!("{err:#}").contains("exceeds"), "{err:#}");
    }

    #[test]
    fn upstream_absent_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = read_upstream(&dir.path().join("none")).unwrap();
        assert!(upstream.facts.is_none());
        assert!(upstream.history.is_empty());
    }

    #[test]
    fn upstream_reads_fixture() {
        let upstream = read_upstream(&fixtures().join("upstream")).unwrap();
        let facts = upstream.facts.unwrap();
        assert_eq!(facts.version, "1.4");
        assert_eq!(facts.bundles["kz.example.gamma"].version, "1.1");
        assert!(facts.bundles["kz.gov.pki.kalkan.xmldsig"].required);
        assert_eq!(upstream.history.len(), 2);
        let baseline = &upstream.history[0];
        assert_eq!(baseline.kind, HistoryKind::Baseline);
        assert_eq!(
            baseline.path.as_deref(),
            Some("history/2026-10-01-1.3-0a1b2c3d/")
        );
        let change = &upstream.history[1];
        assert_eq!(change.kind, HistoryKind::Change);
        assert_eq!(change.path, None);
        assert_eq!(change.issues, [17]);
        assert_eq!(change.plugins[0].change, ChangeKind::Changed);
    }

    fn upstream_with_path(id: &str, path: &str) -> Option<String> {
        let dir = tempfile::tempdir().unwrap();
        let index = json!({"schema": 1, "entries": [{
            "id": id, "date": "2026-10-01", "observed": "2026-10-01T00:00:00Z",
            "version": "1.4", "kind": "change", "path": path
        }]});
        fs::write(dir.path().join("index.json"), index.to_string()).unwrap();
        read_upstream(dir.path()).unwrap().history[0].path.clone()
    }

    #[test]
    fn upstream_bad_path_is_dropped() {
        let id = "2026-10-01-1.4-0a1b2c3d";
        assert_eq!(
            upstream_with_path(id, &format!("history/{id}/")).as_deref(),
            Some("history/2026-10-01-1.4-0a1b2c3d/")
        );
        for path in [
            "../x",
            "history/x/../../",
            &format!("history/{id}"),
            &format!("history/{id}/../"),
        ] {
            assert_eq!(upstream_with_path(id, path), None, "{path}");
        }
        assert_eq!(upstream_with_path("../x", "history/../x/"), None);
    }

    #[test]
    fn upstream_bad_date_is_left_out_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let index = json!({"schema": 1, "entries": [{
            "id": "x", "date": "yesterday", "version": "1", "kind": "change"
        }]});
        fs::write(dir.path().join("index.json"), index.to_string()).unwrap();
        let upstream = read_upstream(dir.path()).unwrap();
        assert!(upstream.history.is_empty());
        assert_eq!(upstream.warnings.len(), 1);
    }

    #[test]
    fn upstream_other_schema_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("index.json"),
            json!({"schema": 2, "entries": []}).to_string(),
        )
        .unwrap();
        let err = read_upstream(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("schema 2"), "{err:#}");
    }
}
