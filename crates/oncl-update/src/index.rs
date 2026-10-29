//! The update index of a channel, `updates/v1/<channel>.json`: core versions by flavor with
//! their staged rollout and revocation, the browser extension, plugins (left opaque until
//! their format exists). [`Index::from_json`] reads one and checks the rules of the format
//! that JSON alone does not express.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use time::OffsetDateTime;

use crate::UpdateError;

/// The only `schema` this version reads.
pub const SCHEMA: u32 = 1;

/// An update channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Releases, after beta.
    Stable,
    /// Pre-releases; everything goes here first.
    Beta,
}

impl Channel {
    /// Every channel.
    pub const ALL: [Channel; 2] = [Channel::Stable, Channel::Beta];

    /// The name in the index and its file name: `stable` or `beta`.
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Beta => "beta",
        }
    }

    /// The channel an installation of `version` follows when its settings name none: beta
    /// for a pre-release (a semver pre-release part, `-alpha.1`, `-rc.1`), stable for a
    /// release, `0.x` releases included. Pre-releases are indexed into beta only, so a
    /// pre-release on stable would never be offered the next one.
    pub fn default_for(version: &Version) -> Channel {
        if version.pre.is_empty() {
            Channel::Stable
        } else {
            Channel::Beta
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A build of the core: the key of [`CoreRelease::flavors`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flavor {
    /// Windows 10 and later, x86-64.
    WinX64,
    /// Windows 10 and later, x86.
    WinX86,
    /// Windows 7 SP1 and later, x86-64.
    Win7X64,
    /// Windows 7 SP1 and later, x86.
    Win7X86,
    /// macOS, universal (x86-64 and arm64).
    Osx,
    /// Linux, x86-64.
    LinuxX64,
}

impl Flavor {
    /// Every flavor.
    pub const ALL: [Flavor; 6] = [
        Flavor::WinX64,
        Flavor::WinX86,
        Flavor::Win7X64,
        Flavor::Win7X86,
        Flavor::Osx,
        Flavor::LinuxX64,
    ];

    /// The key in the index: `win-x64`, `win-x86`, `win7-x64`, `win7-x86`, `osx` or
    /// `linux-x64`.
    pub fn as_str(self) -> &'static str {
        match self {
            Flavor::WinX64 => "win-x64",
            Flavor::WinX86 => "win-x86",
            Flavor::Win7X64 => "win7-x64",
            Flavor::Win7X86 => "win7-x86",
            Flavor::Osx => "osx",
            Flavor::LinuxX64 => "linux-x64",
        }
    }

    /// The flavor of this build, from its target; `None` for a target no flavor is built
    /// for.
    pub fn current() -> Option<Flavor> {
        if cfg!(all(windows, target_vendor = "win7", target_arch = "x86_64")) {
            Some(Flavor::Win7X64)
        } else if cfg!(all(windows, target_vendor = "win7", target_arch = "x86")) {
            Some(Flavor::Win7X86)
        } else if cfg!(all(windows, target_arch = "x86_64")) {
            Some(Flavor::WinX64)
        } else if cfg!(all(windows, target_arch = "x86")) {
            Some(Flavor::WinX86)
        } else if cfg!(target_os = "macos") {
            Some(Flavor::Osx)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Flavor::LinuxX64)
        } else {
            None
        }
    }
}

impl fmt::Display for Flavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A sha256 sum, lowercase hex in the index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256(#[serde(with = "crate::hex::array")] pub [u8; 32]);

impl Sha256 {
    /// The sum of `data`.
    pub fn of(data: &[u8]) -> Sha256 {
        Sha256(sha2::Sha256::digest(data).into())
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({self})")
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hex::encode(&self.0))
    }
}

/// The index of a channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// The format version: [`SCHEMA`].
    pub schema: u32,
    /// The channel; also in the signature's trusted comment.
    pub channel: Channel,
    /// Grows with every published index of the channel; also in the signature's trusted
    /// comment.
    pub seq: u64,
    /// When the index was made.
    #[serde(with = "time::serde::rfc3339")]
    pub generated: OffsetDateTime,
    /// After this the index is refused: a newly signed one is due.
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
    /// Versions of the core.
    pub core: Vec<CoreRelease>,
    /// The browser extension, if one is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<Extension>,
    /// Independently versioned plugins available in this channel.
    #[serde(default)]
    pub plugins: Vec<crate::plugins::PluginRelease>,
}

/// A version of the core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreRelease {
    /// The version (tag `v<version>`).
    pub version: Version,
    /// Packages by flavor ([`Flavor::as_str`]). Keys this version does not know are kept,
    /// not refused: a later index may add flavors.
    pub flavors: BTreeMap<String, FlavorPackage>,
    /// Percentage of installations offered this version, `0..=100` ([`crate::rollout_bucket`]).
    pub rollout: u8,
    /// A revoked version is no longer offered; installations on it move to the newest
    /// version not revoked, even if older.
    #[serde(default)]
    pub revoked: bool,
    /// The release notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_url: Option<String>,
}

impl CoreRelease {
    /// The package for `flavor`.
    pub fn package(&self, flavor: Flavor) -> Option<&FlavorPackage> {
        self.flavors.get(flavor.as_str())
    }
}

/// The packages of a version for one flavor: the full one and deltas from older versions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlavorPackage {
    /// The full package (`url`, `sha256` and `size` beside `delta_from` in the JSON).
    #[serde(flatten)]
    pub full: Package,
    /// [`crate::contents_sha256()`] of the full package: what a full package rebuilt from
    /// a delta must hold. A rebuilt package is another zip archive of the same files
    /// (another order and compression), so its own sha256 differs from [`Package::sha256`].
    /// Required with `delta_from`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents_sha256: Option<Sha256>,
    /// Delta packages by the version they apply to.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delta_from: BTreeMap<Version, Package>,
}

/// A downloadable package of the core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// `https://` URL (a GitHub Releases asset).
    pub url: String,
    /// The sum of the file.
    pub sha256: Sha256,
    /// The size of the file in bytes.
    pub size: u64,
}

impl Package {
    /// Checks the downloaded file at `path` against [`Package::size`] and [`Package::sha256`];
    /// a package that fails is not to be applied.
    ///
    /// # Errors
    ///
    /// [`UpdateError::PackageSize`], [`UpdateError::PackageHash`], or
    /// [`UpdateError::Io`] if the file cannot be read.
    pub fn check_file(&self, path: &Path) -> Result<(), UpdateError> {
        let mut file = File::open(path)?;
        let actual = file.metadata()?.len();
        if actual != self.size {
            return Err(UpdateError::PackageSize {
                expected: self.size,
                actual,
            });
        }
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut read = 0u64;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            read += n as u64;
        }
        // The file may have changed after its size was read.
        if read != self.size {
            return Err(UpdateError::PackageSize {
                expected: self.size,
                actual: read,
            });
        }
        if Sha256(hasher.finalize().into()) != self.sha256 {
            return Err(UpdateError::PackageHash);
        }
        Ok(())
    }
}

/// The browser extension; its version is the core's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    /// The version.
    pub version: Version,
    /// The Chromium package (`.zip`).
    pub chromium_zip: Asset,
    /// The Firefox package (`.xpi`).
    pub firefox_xpi: Asset,
}

/// A downloadable file other than a core package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// `https://` URL (a GitHub Releases asset).
    pub url: String,
    /// The sum of the file.
    pub sha256: Sha256,
}

impl Index {
    /// Reads an index from its JSON and checks the format's rules: [`SCHEMA`], `https://`
    /// URLs only, `rollout` up to 100, each core version once, `contents_sha256` beside any
    /// `delta_from`. Unknown members are
    /// ignored, so later versions of schema 1 may add some. The signature is not checked
    /// here: see [`crate::verify()`].
    ///
    /// # Errors
    ///
    /// [`UpdateError::UnsupportedSchema`] for another schema, [`UpdateError::Malformed`]
    /// otherwise.
    pub fn from_json(bytes: &[u8]) -> Result<Index, UpdateError> {
        #[derive(Deserialize)]
        struct Probe {
            schema: u32,
        }
        let malformed = |e: serde_json::Error| UpdateError::Malformed(e.to_string());
        let probe: Probe = serde_json::from_slice(bytes).map_err(malformed)?;
        if probe.schema != SCHEMA {
            return Err(UpdateError::UnsupportedSchema(probe.schema));
        }
        let index: Index = serde_json::from_slice(bytes).map_err(malformed)?;
        index.check()?;
        Ok(index)
    }

    /// The release of `version`, if the index lists it.
    pub fn release(&self, version: &Version) -> Option<&CoreRelease> {
        self.core.iter().find(|r| r.version == *version)
    }

    fn check(&self) -> Result<(), UpdateError> {
        let mut versions = BTreeSet::new();
        for release in &self.core {
            let v = &release.version;
            if !versions.insert(v) {
                return Err(malformed(format!("core version {v} is listed twice")));
            }
            if release.rollout > 100 {
                return Err(malformed(format!(
                    "core version {v}: rollout {} is over 100",
                    release.rollout
                )));
            }
            if let Some(url) = &release.notes_url {
                https(url, || format!("core version {v}: notes_url"))?;
            }
            for (flavor, package) in &release.flavors {
                https(&package.full.url, || format!("core version {v} {flavor}"))?;
                if !package.delta_from.is_empty() && package.contents_sha256.is_none() {
                    return Err(malformed(format!(
                        "core version {v} {flavor}: delta_from without contents_sha256"
                    )));
                }
                for (from, delta) in &package.delta_from {
                    https(&delta.url, || {
                        format!("core version {v} {flavor}: delta from {from}")
                    })?;
                }
            }
        }
        if let Some(ext) = &self.extension {
            https(&ext.chromium_zip.url, || {
                "extension chromium_zip".to_owned()
            })?;
            https(&ext.firefox_xpi.url, || "extension firefox_xpi".to_owned())?;
        }
        let mut plugin_versions = BTreeSet::new();
        for release in &self.plugins {
            release.check()?;
            if !plugin_versions.insert((&release.id, &release.version)) {
                return Err(malformed(format!(
                    "plugin {} {} is listed twice",
                    release.id, release.version
                )));
            }
            https(&release.package.url, || {
                format!("plugin {} {}", release.id, release.version)
            })?;
        }
        Ok(())
    }
}

fn malformed(message: String) -> UpdateError {
    UpdateError::Malformed(message)
}

/// Refuses a URL that is not `https://` with a host.
fn https(url: &str, what: impl FnOnce() -> String) -> Result<(), UpdateError> {
    match url.strip_prefix("https://") {
        Some(rest) if !rest.is_empty() && !rest.starts_with('/') => Ok(()),
        _ => Err(malformed(format!(
            "{}: {url:?} is not an https URL",
            what()
        ))),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn sum(n: u8) -> String {
        crate::hex::encode(&[n; 32])
    }

    /// A valid index of `channel` and `seq`, generated 2026-10-01, expiring 2026-10-31.
    pub(crate) fn index_json(channel: &str, seq: u64) -> serde_json::Value {
        json!({
            "schema": 1,
            "channel": channel,
            "seq": seq,
            "generated": "2026-10-01T00:00:00Z",
            "expires": "2026-10-31T00:00:00Z",
            "core": [{
                "version": "0.1.0-alpha.2",
                "flavors": {
                    "win-x64": {
                        "url": "https://github.com/o/r/releases/download/v0.1.0-alpha.2/full.nupkg",
                        "sha256": sum(1),
                        "size": 123,
                        "contents_sha256": sum(6),
                        "delta_from": {
                            "0.1.0-alpha.1": {
                                "url": "https://github.com/o/r/releases/download/v0.1.0-alpha.2/delta.nupkg",
                                "sha256": sum(2),
                                "size": 45
                            }
                        }
                    },
                    "riscv-future": {
                        "url": "https://github.com/o/r/releases/download/v0.1.0-alpha.2/rv.nupkg",
                        "sha256": sum(3),
                        "size": 1
                    }
                },
                "rollout": 100,
                "revoked": false,
                "notes_url": "https://github.com/o/r/releases/tag/v0.1.0-alpha.2"
            }],
            "extension": {
                "version": "0.1.0-alpha.2",
                "chromium_zip": {"url": "https://github.com/o/r/e.zip", "sha256": sum(4)},
                "firefox_xpi": {"url": "https://github.com/o/r/e.xpi", "sha256": sum(5)}
            },
            "plugins": [],
            "future_member": {"ignored": true}
        })
    }

    fn parse(value: &serde_json::Value) -> Result<Index, UpdateError> {
        Index::from_json(&serde_json::to_vec(value).unwrap())
    }

    fn malformed_message(value: &serde_json::Value) -> String {
        match parse(value) {
            Err(UpdateError::Malformed(m)) => m,
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn reads_the_documented_shape() {
        let index = parse(&index_json("beta", 42)).unwrap();
        assert_eq!(index.channel, Channel::Beta);
        assert_eq!(index.seq, 42);
        assert_eq!(
            index.generated,
            time::macros::datetime!(2026-10-01 0:00 UTC)
        );
        let release = index
            .release(&Version::parse("0.1.0-alpha.2").unwrap())
            .unwrap();
        let package = release.package(Flavor::WinX64).unwrap();
        assert_eq!(package.full.size, 123);
        assert_eq!(package.full.sha256, Sha256([1; 32]));
        let from = Version::parse("0.1.0-alpha.1").unwrap();
        assert_eq!(package.delta_from[&from].size, 45);
        assert_eq!(package.contents_sha256, Some(Sha256([6; 32])));
        assert!(release.package(Flavor::LinuxX64).is_none());
        assert!(
            release.flavors.contains_key("riscv-future"),
            "unknown flavors kept"
        );
        assert_eq!(index.extension.unwrap().firefox_xpi.sha256, Sha256([5; 32]));
    }

    #[test]
    fn serializes_back_to_the_same_index() {
        let index = parse(&index_json("stable", 7)).unwrap();
        let again = Index::from_json(&serde_json::to_vec(&index).unwrap()).unwrap();
        assert_eq!(again, index);
        let value = serde_json::to_value(&index).unwrap();
        assert_eq!(value["generated"], "2026-10-01T00:00:00Z");
        assert_eq!(value["core"][0]["flavors"]["win-x64"]["sha256"], sum(1));
    }

    #[test]
    fn other_schemas_are_unsupported() {
        let mut v = index_json("beta", 1);
        v["schema"] = json!(2);
        assert!(matches!(parse(&v), Err(UpdateError::UnsupportedSchema(2))));
        // A later schema may change everything but `schema`.
        let v = json!({"schema": 2, "core": "not a list"});
        assert!(matches!(parse(&v), Err(UpdateError::UnsupportedSchema(2))));
    }

    #[test]
    fn format_rules_are_enforced() {
        let mut v = index_json("beta", 1);
        v["core"][0]["rollout"] = json!(101);
        assert!(malformed_message(&v).contains("rollout 101"));

        let mut v = index_json("beta", 1);
        let twice = v["core"][0].clone();
        v["core"].as_array_mut().unwrap().push(twice);
        assert!(malformed_message(&v).contains("listed twice"));

        let mut v = index_json("beta", 1);
        v["core"][0]["flavors"]["win-x64"]
            .as_object_mut()
            .unwrap()
            .remove("contents_sha256");
        assert!(malformed_message(&v).contains("delta_from without contents_sha256"));

        for (pointer, url) in [
            ("/core/0/flavors/win-x64/url", "http://github.com/x.nupkg"),
            (
                "/core/0/flavors/win-x64/delta_from/0.1.0-alpha.1/url",
                "file:///x",
            ),
            ("/core/0/notes_url", "https:///x"),
            ("/extension/chromium_zip/url", "github.com/x.zip"),
            ("/extension/firefox_xpi/url", "https://"),
        ] {
            let mut v = index_json("beta", 1);
            *v.pointer_mut(pointer).unwrap() = json!(url);
            assert!(
                malformed_message(&v).contains("not an https URL"),
                "{pointer}"
            );
        }

        for (pointer, bad) in [
            (
                "/core/0/flavors/win-x64/sha256",
                json!(sum(0xab).to_uppercase()),
            ),
            ("/core/0/flavors/win-x64/sha256", json!("00")),
            ("/core/0/version", json!("1.0")),
            ("/channel", json!("nightly")),
            ("/generated", json!("2026-10-01")),
            ("/seq", json!(-1)),
            ("/core/0/flavors/win-x64/size", json!("123")),
        ] {
            let mut v = index_json("beta", 1);
            *v.pointer_mut(pointer).unwrap() = bad;
            malformed_message(&v);
        }
        assert!(matches!(
            Index::from_json(b"not json"),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn optional_members_may_be_missing() {
        let mut v = index_json("beta", 1);
        let object = v.as_object_mut().unwrap();
        object.remove("extension");
        object.remove("plugins");
        let release = v["core"][0].as_object_mut().unwrap();
        release.remove("revoked");
        release.remove("notes_url");
        let index = parse(&v).unwrap();
        assert!(index.extension.is_none());
        assert!(!index.core[0].revoked);
    }

    #[test]
    fn flavor_and_channel_names() {
        let names: Vec<_> = Flavor::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(
            names,
            [
                "win-x64",
                "win-x86",
                "win7-x64",
                "win7-x86",
                "osx",
                "linux-x64"
            ]
        );
        assert_eq!(Channel::Beta.to_string(), "beta");
        assert_eq!(serde_json::to_value(Channel::Stable).unwrap(), "stable");
        #[cfg(all(windows, target_arch = "x86_64", not(target_vendor = "win7")))]
        assert_eq!(Flavor::current(), Some(Flavor::WinX64));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(Flavor::current(), Some(Flavor::LinuxX64));
    }

    #[test]
    fn package_files_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.nupkg");
        std::fs::write(&path, b"package bytes").unwrap();
        let good = Package {
            url: "https://example.org/p".to_owned(),
            sha256: Sha256::of(b"package bytes"),
            size: 13,
        };
        good.check_file(&path).unwrap();

        let other_hash = Package {
            sha256: Sha256::of(b"package bytez"),
            ..good.clone()
        };
        assert!(matches!(
            other_hash.check_file(&path),
            Err(UpdateError::PackageHash)
        ));
        let other_size = Package {
            size: 14,
            ..good.clone()
        };
        assert!(matches!(
            other_size.check_file(&path),
            Err(UpdateError::PackageSize {
                expected: 14,
                actual: 13
            })
        ));
        assert!(matches!(
            good.check_file(&dir.path().join("missing")),
            Err(UpdateError::Io(_))
        ));
    }

    #[test]
    fn sha256_of_known_input() {
        assert_eq!(
            Sha256::of(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
