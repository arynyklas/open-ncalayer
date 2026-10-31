//! `data/site.json` of the site's build copy: everything the templates show, read once by
//! `base.html`. The texts in it are untrusted: the templates print them escaped. The URLs
//! in it are made here, by fixed rules, never taken from an input.

use std::collections::BTreeMap;

use oncl_basics::capabilities::capability_text;
use oncl_plugin::is_symbolic_name;
use oncl_update::Channel;
use serde::Serialize;
use time::OffsetDateTime;

use super::LANGS;
use super::inputs::{
    ChannelView, Facts, HistoryKind, PluginChange, PluginView, Release, Upstream, latest,
};
use super::ports::{Conformance, Port, PortStatus};
use crate::index::{chromium_name, firefox_name, release_asset_url, release_notes_url};
use crate::package::{linux, macos, windows};

/// The repository: issues, the `upstream` branch and releases are its pages.
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Everything the site shows.
#[derive(Debug, Clone, Serialize)]
pub struct SiteData {
    /// The format: 1.
    pub schema: u32,
    /// The ports, by short name.
    pub plugins: BTreeMap<String, PluginData>,
    /// The short names of the ports in each language's order.
    pub order: BTreeMap<String, Vec<String>>,
    /// The channels that have an index: `stable`, `beta`.
    pub channels: BTreeMap<String, ChannelData>,
    /// The latest release and pre-release.
    pub releases: ReleasesData,
    /// The facts of the `upstream` branch.
    pub upstream: UpstreamData,
}

/// A port.
#[derive(Debug, Clone, Serialize)]
pub struct PluginData {
    /// Its plugin id.
    pub id: String,
    /// Its version in the repository.
    pub version: String,
    /// The oldest core it runs on.
    pub min_core: String,
    /// The modules it serves.
    pub modules: Vec<String>,
    /// Its name, by language.
    pub name: BTreeMap<String, String>,
    /// Its description, by language.
    pub description: Option<BTreeMap<String, String>>,
    /// The original bundle it replaces.
    pub symname: String,
    /// The version of that bundle it was ported from.
    pub original_version: String,
    /// The original's publisher.
    pub vendor: String,
    /// How far the port is.
    pub status: PortStatus,
    /// How it was compared with the original.
    pub conformance: Conformance,
    /// What it may do, a line each, by language.
    pub capabilities: BTreeMap<String, Vec<String>>,
    /// How it differs from the original, in Russian.
    pub differences: Vec<String>,
    /// Its version in each channel that offers it.
    pub channels: BTreeMap<String, PluginView>,
    /// Whether the original changed since the port.
    pub original: OriginalChange,
}

/// Whether the original bundle changed after the port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum OriginalChange {
    /// The original still has the ported version.
    Same,
    /// The original has another version.
    Changed {
        /// The original's version now.
        current: String,
    },
    /// The original no longer has the bundle.
    Removed,
    /// No facts about the original.
    Unknown,
}

/// Whether the bundle `symname`, ported from its version `ported`, changed in `facts`.
pub fn original_change(symname: &str, ported: &str, facts: Option<&Facts>) -> OriginalChange {
    let Some(facts) = facts else {
        return OriginalChange::Unknown;
    };
    match facts.bundles.get(symname) {
        None => OriginalChange::Removed,
        Some(bundle) if bundle.version == ported => OriginalChange::Same,
        Some(bundle) => OriginalChange::Changed {
            current: bundle.version.clone(),
        },
    }
}

/// A channel's index.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelData {
    /// Its `seq`.
    pub seq: u64,
    /// When it was made, `YYYY-MM-DD`.
    pub generated: String,
    /// When it stops being valid, `YYYY-MM-DD`.
    pub expires: String,
    /// The core version it offers.
    pub core: Option<String>,
}

/// The releases.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReleasesData {
    /// Whether the list of releases was read.
    pub available: bool,
    /// The latest release.
    pub release: Option<ReleaseData>,
    /// The latest pre-release, if newer than the release.
    pub prerelease: Option<ReleaseData>,
}

/// A release.
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseData {
    /// Its version.
    pub version: String,
    /// The day it was published, or empty.
    pub published: String,
    /// Its page.
    pub notes_url: String,
    /// The files to download, in a fixed order.
    pub assets: Vec<AssetData>,
}

/// A file of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetData {
    /// What it is: `win-x64`, …, `sha256sums`; the template's caption key.
    pub kind: &'static str,
    /// The file name.
    pub name: String,
    /// Where to download it.
    pub url: String,
}

/// The files of `release` that the site offers, those it has, in a fixed order.
pub fn release_assets(release: &Release) -> Vec<AssetData> {
    let v = &release.version;
    let mut candidates: Vec<(&'static str, String)> = windows::FLAVORS
        .iter()
        .map(|flavor| (flavor.name, windows::setup_name(v, flavor)))
        .collect();
    candidates.extend([
        ("osx-pkg", macos::pkg_name(v)),
        ("osx-zip", macos::zip_name(v)),
        ("linux-appimage", linux::appimage_name(v)),
        ("chromium", chromium_name(v)),
        ("firefox", firefox_name(v)),
        ("sha256sums", "SHA256SUMS".to_owned()),
    ]);
    candidates
        .into_iter()
        .filter(|(_, name)| release.assets.contains(name))
        .map(|(kind, name)| AssetData {
            kind,
            url: release_asset_url(v, &name),
            name,
        })
        .collect()
}

fn release_data(release: &Release) -> ReleaseData {
    ReleaseData {
        version: release.version.to_string(),
        published: release.published.clone(),
        notes_url: release_notes_url(&release.version),
        assets: release_assets(release),
    }
}

/// What the site says about the original.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamData {
    /// Whether the `upstream` branch's facts were read.
    pub available: bool,
    /// The original's manifest version.
    pub version: Option<String>,
    /// The original's bundles, by symbolic name.
    pub bundles: Vec<BundleRow>,
    /// The history, newest first.
    pub history: Vec<HistoryRow>,
}

/// A bundle of the original.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleRow {
    /// Its symbolic name.
    pub symname: String,
    /// Whether it may be an `id` of the page.
    pub anchor: bool,
    /// The original's version.
    pub version: String,
    /// Whether it is a core bundle of the original.
    pub required: bool,
    /// The short name of its port.
    pub port: Option<String>,
    /// The version OpenNCALayer has: the port's original version or what `getBundles` says.
    pub ours: Option<String>,
    /// Whether the original's version differs from ours.
    pub changed: bool,
}

/// An entry of the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryRow {
    /// Its id.
    pub id: String,
    /// The day.
    pub date: String,
    /// The original's version.
    pub version: String,
    /// What kind of change.
    pub kind: HistoryKind,
    /// The core bundles that changed.
    pub core: Vec<String>,
    /// The other bundles that changed.
    pub plugins: Vec<PluginChange>,
    /// Notes.
    pub notes: Vec<String>,
    /// The entry's facts on the `upstream` branch.
    pub url: Option<String>,
    /// Its issues.
    pub issues: Vec<IssueLink>,
}

/// An issue of the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueLink {
    /// Its number.
    pub number: u64,
    /// Its page.
    pub url: String,
}

/// The site's data from the ports, the channels, and the external inputs if read.
pub fn site_data(
    ports: &[Port],
    channels: &BTreeMap<Channel, ChannelView>,
    releases: Option<&[Release]>,
    upstream: Option<&Upstream>,
) -> SiteData {
    let facts = upstream.and_then(|u| u.facts.as_ref());
    let plugins: BTreeMap<String, PluginData> = ports
        .iter()
        .map(|port| (port.short.clone(), plugin_data(port, channels, facts)))
        .collect();
    let order = LANGS
        .iter()
        .map(|(lang, _)| {
            let mut shorts: Vec<&String> = plugins.keys().collect();
            shorts.sort_by_cached_key(|short| (plugins[*short].name[*lang].to_lowercase(), *short));
            (
                (*lang).to_owned(),
                shorts.into_iter().cloned().collect::<Vec<_>>(),
            )
        })
        .collect();
    let channels = channels
        .iter()
        .map(|(channel, view)| {
            (
                channel.as_str().to_owned(),
                ChannelData {
                    seq: view.seq,
                    generated: day(view.generated),
                    expires: day(view.expires),
                    core: view.core.as_ref().map(ToString::to_string),
                },
            )
        })
        .collect();
    let releases = releases.map_or_else(ReleasesData::default, |releases| {
        let (release, prerelease) = latest(releases);
        ReleasesData {
            available: true,
            release: release.map(release_data),
            prerelease: prerelease.map(release_data),
        }
    });
    SiteData {
        schema: 1,
        plugins,
        order,
        channels,
        releases,
        upstream: upstream.map_or_else(UpstreamData::default, |u| upstream_data(u, ports)),
    }
}

fn plugin_data(
    port: &Port,
    channels: &BTreeMap<Channel, ChannelView>,
    facts: Option<&Facts>,
) -> PluginData {
    let manifest = &port.manifest;
    let original = &port.registry.original;
    let by_lang = |text: &oncl_plugin::Localized| -> BTreeMap<String, String> {
        LANGS
            .iter()
            .map(|(lang, l)| ((*lang).to_owned(), text.get(*l).to_owned()))
            .collect()
    };
    let lines = manifest.capabilities.lines();
    PluginData {
        id: manifest.id.clone(),
        version: manifest.version.to_string(),
        min_core: manifest.min_core.to_string(),
        modules: manifest.modules.clone(),
        name: by_lang(&manifest.name),
        description: manifest.description.as_ref().map(by_lang),
        symname: original.symname.clone(),
        original_version: original.version.clone(),
        vendor: original.vendor.clone(),
        status: port.registry.port.status,
        conformance: port.registry.port.conformance,
        capabilities: LANGS
            .iter()
            .map(|(lang, l)| {
                (
                    (*lang).to_owned(),
                    lines.iter().map(|line| capability_text(line, *l)).collect(),
                )
            })
            .collect(),
        differences: port
            .registry
            .differences
            .iter()
            .map(|d| d.ru.clone())
            .collect(),
        channels: channels
            .iter()
            .filter_map(|(channel, view)| {
                view.plugins
                    .get(&manifest.id)
                    .map(|p| (channel.as_str().to_owned(), p.clone()))
            })
            .collect(),
        original: original_change(&original.symname, &original.version, facts),
    }
}

fn upstream_data(upstream: &Upstream, ports: &[Port]) -> UpstreamData {
    let core = oncl_builtin_accessory::bundles();
    let bundles = upstream
        .facts
        .iter()
        .flat_map(|facts| &facts.bundles)
        .map(|(symname, bundle)| {
            let port = ports
                .iter()
                .find(|p| p.registry.original.symname == *symname);
            let ours = port
                .map(|p| p.registry.original.version.clone())
                .or_else(|| {
                    core.iter()
                        .find(|(name, _)| name == symname)
                        .map(|(_, version)| (*version).to_owned())
                });
            BundleRow {
                symname: symname.clone(),
                anchor: is_symbolic_name(symname),
                version: bundle.version.clone(),
                required: bundle.required,
                port: port.map(|p| p.short.clone()),
                changed: ours.as_ref().is_some_and(|ours| *ours != bundle.version),
                ours,
            }
        })
        .collect();
    let mut entries: Vec<_> = upstream.history.iter().collect();
    entries.sort_by(|a, b| b.observed.cmp(&a.observed));
    let history = entries
        .into_iter()
        .map(|entry| HistoryRow {
            id: entry.id.clone(),
            date: entry.date.clone(),
            version: entry.version.clone(),
            kind: entry.kind,
            core: entry.core.clone(),
            plugins: entry.plugins.clone(),
            notes: entry.notes.clone(),
            url: entry
                .path
                .as_ref()
                .map(|path| format!("{REPOSITORY}/tree/upstream/{path}")),
            issues: entry
                .issues
                .iter()
                .map(|&number| IssueLink {
                    number,
                    url: format!("{REPOSITORY}/issues/{number}"),
                })
                .collect(),
        })
        .collect();
    UpstreamData {
        available: upstream.facts.is_some() || !upstream.history.is_empty(),
        version: upstream.facts.as_ref().map(|f| f.version.clone()),
        bundles,
        history,
    }
}

/// `YYYY-MM-DD` of `at`, in UTC.
fn day(at: OffsetDateTime) -> String {
    let date = at.to_offset(time::UtcOffset::UTC).date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use oncl_update::Version;

    use super::super::inputs::{FactBundle, read_releases, read_upstream};
    use super::super::ports::load;
    use super::*;

    fn fixtures() -> PathBuf {
        oncl_testkit::workspace_root().join("fixtures/registry")
    }

    fn facts(bundles: &[(&str, &str, bool)]) -> Facts {
        Facts {
            version: "1.4".to_owned(),
            bundles: bundles
                .iter()
                .map(|(s, v, r)| {
                    (
                        (*s).to_owned(),
                        FactBundle {
                            version: (*v).to_owned(),
                            required: *r,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn original_change_states() {
        let f = facts(&[("kz.a", "1.0", false)]);
        assert_eq!(
            original_change("kz.a", "1.0", None),
            OriginalChange::Unknown
        );
        assert_eq!(
            original_change("kz.a", "1.0", Some(&f)),
            OriginalChange::Same
        );
        assert_eq!(
            original_change("kz.a", "0.9", Some(&f)),
            OriginalChange::Changed {
                current: "1.0".to_owned()
            }
        );
        assert_eq!(
            original_change("kz.b", "1.0", Some(&f)),
            OriginalChange::Removed
        );
        assert_eq!(
            serde_json::to_value(OriginalChange::Changed {
                current: "2".to_owned()
            })
            .unwrap(),
            serde_json::json!({"state": "changed", "current": "2"})
        );
    }

    #[test]
    fn core_bundle_compared_with_get_bundles() {
        let (symname, version) = oncl_builtin_accessory::bundles()[0];
        let upstream = Upstream {
            facts: Some(facts(&[(symname, "999.0", true), ("x y", "1", false)])),
            ..Upstream::default()
        };
        let data = upstream_data(&upstream, &[]);
        let row = data.bundles.iter().find(|b| b.symname == symname).unwrap();
        assert_eq!(row.ours.as_deref(), Some(version));
        assert!(row.changed);
        assert!(row.required);
        let odd = data.bundles.iter().find(|b| b.symname == "x y").unwrap();
        assert!(!odd.anchor);
        assert_eq!(odd.ours, None);
        assert!(!odd.changed);
    }

    #[test]
    fn release_assets_only_present_ones() {
        let releases = read_releases(&fixtures().join("releases.jsonl")).unwrap();
        let pre = &releases[0];
        assert_eq!(pre.version, Version::parse("0.3.0-beta.1").unwrap());
        let assets = release_assets(pre);
        let kinds: Vec<&str> = assets.iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            [
                "win-x64",
                "win-x86",
                "win7-x64",
                "win7-x86",
                "linux-appimage",
                "chromium",
                "firefox",
                "sha256sums"
            ]
        );
        assert_eq!(
            assets[0].url,
            "https://github.com/arynyklas/open-ncalayer/releases/download/v0.3.0-beta.1/\
             openncalayer-0.3.0-beta.1-win-x64-setup.exe"
        );
        let full = release_assets(&releases[1]);
        assert_eq!(full.len(), 10);
        let none = Release {
            assets: BTreeSet::from(["other.bin".to_owned()]),
            ..releases[1].clone()
        };
        assert!(release_assets(&none).is_empty());
    }

    #[test]
    fn capabilities_rendered_per_language() {
        let ports = load(&fixtures().join("plugins")).unwrap();
        let data = site_data(&ports, &BTreeMap::new(), None, None);
        let alpha = &data.plugins["alpha"];
        for (lang, l) in LANGS {
            let lines = &alpha.capabilities[lang];
            assert_eq!(lines.len(), 2, "{lang}");
            assert_eq!(
                lines[0],
                capability_text(&oncl_basics::capabilities::CapabilityLine::Keys, l)
            );
            assert!(lines[1].contains("https://*.example.kz/"), "{}", lines[1]);
        }
        assert_ne!(alpha.capabilities["ru"], alpha.capabilities["en"]);
    }

    #[test]
    fn order_by_localized_name() {
        let ports = load(&fixtures().join("plugins")).unwrap();
        let data = site_data(&ports, &BTreeMap::new(), None, None);
        // "<script…" sorts before letters; Cyrillic after Latin.
        assert_eq!(data.order["ru"], ["hostile", "alpha", "gamma"]);
        assert_eq!(data.order["en"], ["hostile", "alpha", "gamma"]);
        let mut ports = ports;
        ports[0].manifest.name.en = "zeta".to_owned();
        ports[1].manifest.name.en = "Beta".to_owned();
        let data = site_data(&ports, &BTreeMap::new(), None, None);
        assert_eq!(data.order["en"], ["hostile", "gamma", "alpha"]);
    }

    #[test]
    fn history_newest_first_with_links() {
        let upstream = read_upstream(&fixtures().join("upstream")).unwrap();
        let data = upstream_data(&upstream, &[]);
        assert!(data.available);
        assert_eq!(data.version.as_deref(), Some("1.4"));
        let ids: Vec<&str> = data.history.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["2026-10-20-1.4-4e5f6a7b", "2026-10-01-1.3-0a1b2c3d"]);
        assert_eq!(data.history[0].url, None);
        assert_eq!(
            data.history[1].url.as_deref(),
            Some(
                "https://github.com/arynyklas/open-ncalayer/tree/upstream/\
                 history/2026-10-01-1.3-0a1b2c3d/"
            )
        );
        assert_eq!(
            data.history[0].issues[0].url,
            "https://github.com/arynyklas/open-ncalayer/issues/17"
        );
    }
}
