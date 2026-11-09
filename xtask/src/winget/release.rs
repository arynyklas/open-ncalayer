//! The GitHub release a WinGet manifest may be made of, and the reasons it may not.
//!
//! The input is the release object of the GitHub REST API (`GET /repos/{owner}/{repo}/releases/tags/{tag}`).
//! Only a published stable release passes: not a draft, not a pre-release (the flag **and** the
//! version: `v0.1.0-alpha.7` is refused even if someone clears the flag), a tag that is exactly
//! `v<major>.<minor>.<patch>`, and both WinGet installer assets present once, uploaded, at their
//! version-specific download URL. Nothing here renames or promotes a pre-release.

use std::fmt;

use anyhow::Context;
use oncl_update::Version;
use regex::Regex;
use serde::Deserialize;

use super::Arch;

/// The GitHub repository the assets are published in.
pub const REPOSITORY: &str = "arynyklas/OpenNCALayer";

/// A release as the GitHub API reports it (only the fields the manifests depend on).
#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    /// The tag.
    pub tag_name: String,
    /// A draft is not published.
    pub draft: bool,
    /// The pre-release flag.
    pub prerelease: bool,
    /// When it was published (UTC, `YYYY-MM-DDTHH:MM:SSZ`); null for a draft.
    pub published_at: Option<String>,
    /// Its assets.
    pub assets: Vec<Asset>,
}

/// An asset of a release.
#[derive(Clone, Debug, Deserialize)]
pub struct Asset {
    /// The file name.
    pub name: String,
    /// `uploaded` once the upload finished.
    pub state: String,
    /// Size in bytes.
    pub size: u64,
    /// `sha256:<hex>`; GitHub computes it for assets uploaded since 2025.
    #[serde(default)]
    pub digest: Option<String>,
    /// The download URL.
    pub browser_download_url: String,
}

/// Why a release gives no stable manifest. Every variant names what to fix; none is a warning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// A draft is not public.
    Draft,
    /// The pre-release flag is set.
    Prerelease,
    /// The tag is not `v<major>.<minor>.<patch>` (an alpha, a beta, a build or a branch name).
    TagNotStable(String),
    /// The release has no (valid) publication time.
    NotPublished,
    /// A required asset is absent.
    AssetMissing(String),
    /// The same asset name appears twice.
    AssetDuplicated(String),
    /// A WinGet installer of another version or flavor is attached to this release.
    ForeignAsset(String),
    /// The upload of an asset is not finished.
    AssetNotUploaded {
        /// The asset.
        name: String,
        /// Its state.
        state: String,
    },
    /// An asset's size is zero.
    AssetEmpty(String),
    /// The download URL is not the immutable, version-specific URL of the asset.
    UrlNotVersionSpecific {
        /// The asset.
        name: String,
        /// What the release says.
        url: String,
    },
    /// The API digest of an asset is not `sha256:<64 hex>`.
    DigestMalformed(String),
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::Draft => f.write_str("the release is a draft"),
            ReleaseError::Prerelease => f.write_str("the release is marked as a pre-release"),
            ReleaseError::TagNotStable(tag) => write!(
                f,
                "the tag {tag:?} is not a stable version (v<major>.<minor>.<patch>): alpha, beta and other pre-release or build versions never get a WinGet manifest"
            ),
            ReleaseError::NotPublished => f.write_str("the release has no valid publication time"),
            ReleaseError::AssetMissing(name) => write!(f, "the release has no asset {name}"),
            ReleaseError::AssetDuplicated(name) => {
                write!(f, "the release has the asset {name} twice")
            }
            ReleaseError::ForeignAsset(name) => write!(
                f,
                "{name} is a WinGet installer that is not one of this version's two (x64, x86): a wrong asset is attached to the release"
            ),
            ReleaseError::AssetNotUploaded { name, state } => {
                write!(f, "the asset {name} is {state:?}, not uploaded")
            }
            ReleaseError::AssetEmpty(name) => write!(f, "the asset {name} is empty"),
            ReleaseError::UrlNotVersionSpecific { name, url } => write!(
                f,
                "the URL of {name} is {url:?}, not the version-specific release download URL"
            ),
            ReleaseError::DigestMalformed(name) => {
                write!(f, "the API digest of {name} is not sha256:<64 hex digits>")
            }
        }
    }
}

impl std::error::Error for ReleaseError {}

/// One installer asset of a stable release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallerAsset {
    /// The architecture of the flavor.
    pub arch: Arch,
    /// `openncalayer-<version>-win-<arch>-winget-setup.exe`.
    pub name: String,
    /// `https://github.com/<repository>/releases/download/v<version>/<name>`.
    pub url: String,
    /// The size the API reports.
    pub size: u64,
    /// The digest the API reports, lowercase hex, if it reports one.
    pub api_sha256: Option<String>,
}

/// A release that passed every check of [`Release::stable`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableRelease {
    /// The version.
    pub version: Version,
    /// The tag (`v<version>`).
    pub tag: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub published_at: String,
    /// The two installers, x64 first.
    pub installers: [InstallerAsset; 2],
}

impl StableRelease {
    /// The release page, `ReleaseNotesUrl`.
    pub fn page(&self) -> String {
        format!("https://github.com/{REPOSITORY}/releases/tag/{}", self.tag)
    }

    /// The installer of `arch`.
    pub fn installer(&self, arch: Arch) -> &InstallerAsset {
        self.installers
            .iter()
            .find(|asset| asset.arch == arch)
            .expect("both architectures are present")
    }

    /// `YYYY-MM-DD` of the publication.
    pub fn release_date(&self) -> &str {
        &self.published_at[..10]
    }
}

/// The asset name of the installer for `version` and `arch`.
pub fn asset_name(version: &Version, arch: Arch) -> String {
    format!("openncalayer-{version}-win-{arch}-winget-setup.exe")
}

/// The URL a published asset of the tag is downloaded from; it does not change when a newer
/// release appears, unlike `releases/latest/download/…`.
pub fn asset_url(tag: &str, name: &str) -> String {
    format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{name}")
}

/// A UTC time in the one form the checks compare as text: `YYYY-MM-DDTHH:MM:SSZ`, a real
/// calendar date and clock time.
pub fn is_utc_time(text: &str) -> bool {
    static SHAPE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$").expect("a time pattern")
    });
    let Some(parts) = SHAPE.captures(text) else {
        return false;
    };
    let number = |i: usize| parts[i].parse::<u32>().unwrap_or(u32::MAX);
    let date = u8::try_from(number(2))
        .ok()
        .and_then(|month| time::Month::try_from(month).ok())
        .zip(u8::try_from(number(3)).ok())
        .and_then(|(month, day)| time::Date::from_calendar_date(number(1) as i32, month, day).ok());
    let clock = u8::try_from(number(4))
        .ok()
        .zip(u8::try_from(number(5)).ok())
        .zip(u8::try_from(number(6)).ok());
    date.is_some()
        && clock.is_some_and(|((hour, minute), second)| {
            time::Time::from_hms(hour, minute, second).is_ok()
        })
}

/// Reads the JSON of a release.
///
/// # Errors
///
/// The text is not a release object.
pub fn parse(json: &str) -> anyhow::Result<Release> {
    serde_json::from_str(json).context("the release JSON is not a GitHub release object")
}

impl Release {
    /// The release as a stable, published one with both installers.
    ///
    /// # Errors
    ///
    /// The first [`ReleaseError`].
    pub fn stable(&self) -> Result<StableRelease, ReleaseError> {
        if self.draft {
            return Err(ReleaseError::Draft);
        }
        if self.prerelease {
            return Err(ReleaseError::Prerelease);
        }
        let version = self
            .tag_name
            .strip_prefix('v')
            .and_then(|text| Version::parse(text).ok())
            .filter(|v| v.pre.is_empty() && v.build.is_empty())
            .filter(|v| format!("v{v}") == self.tag_name)
            .ok_or_else(|| ReleaseError::TagNotStable(self.tag_name.clone()))?;
        let published_at = self
            .published_at
            .as_deref()
            .filter(|time| is_utc_time(time))
            .ok_or(ReleaseError::NotPublished)?
            .to_owned();

        let expected = [Arch::X64, Arch::X86].map(|arch| (arch, asset_name(&version, arch)));
        for asset in &self.assets {
            if asset.name.ends_with("-winget-setup.exe")
                && !expected.iter().any(|(_, name)| *name == asset.name)
            {
                return Err(ReleaseError::ForeignAsset(asset.name.clone()));
            }
        }
        let mut found = Vec::new();
        for (arch, name) in &expected {
            let mut matching = self.assets.iter().filter(|asset| asset.name == *name);
            let asset = matching
                .next()
                .ok_or_else(|| ReleaseError::AssetMissing(name.clone()))?;
            if matching.next().is_some() {
                return Err(ReleaseError::AssetDuplicated(name.clone()));
            }
            if asset.state != "uploaded" {
                return Err(ReleaseError::AssetNotUploaded {
                    name: name.clone(),
                    state: asset.state.clone(),
                });
            }
            if asset.size == 0 {
                return Err(ReleaseError::AssetEmpty(name.clone()));
            }
            let url = asset_url(&self.tag_name, name);
            if asset.browser_download_url != url {
                return Err(ReleaseError::UrlNotVersionSpecific {
                    name: name.clone(),
                    url: asset.browser_download_url.clone(),
                });
            }
            let api_sha256 = match &asset.digest {
                None => None,
                Some(digest) => Some(
                    digest
                        .strip_prefix("sha256:")
                        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                        .map(str::to_ascii_lowercase)
                        .ok_or_else(|| ReleaseError::DigestMalformed(name.clone()))?,
                ),
            };
            found.push(InstallerAsset {
                arch: *arch,
                name: name.clone(),
                url,
                size: asset.size,
                api_sha256,
            });
        }
        let [x64, x86]: [InstallerAsset; 2] = found.try_into().expect("two installers");
        Ok(StableRelease {
            version,
            tag: self.tag_name.clone(),
            published_at,
            installers: [x64, x86],
        })
    }
}
