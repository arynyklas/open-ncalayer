//! `cargo xtask index`: the update indexes of the channels, `updates/v1/<channel>.json`
//! (`docs/design/update-index.md`).
//!
//! - [`add`] appends a released version to an index, from the downloaded assets of its
//!   GitHub release, with the next `seq` and a new validity. The result is unsigned: sign it
//!   with `cargo xtask sign`.
//! - [`check`] is the gate before publishing: the format, the signature by a trusted key,
//!   `seq` growth against the base branch and, with a [`Remote`], that every asset answers
//!   `HEAD` with 200 and, behind a flag, that new versions passed `vm-smoke`.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{Context, bail};
use oncl_update::{
    Asset, Channel, CoreRelease, Extension, Flavor, FlavorPackage, Index, Package, PublicKey,
    Sha256, Version,
};
use serde_json::Value;
use sha2::Digest;
use time::OffsetDateTime;
use ureq::Agent;

use crate::sign::signature_path;

/// Where the indexes live, from the workspace root; published under `/updates/v1/`.
pub const INDEX_DIR: &str = "updates/v1";

/// The repository whose releases hold the assets.
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The `vm-smoke` commit status context (set on release tags by the lab agent).
pub const VM_SMOKE: &str = "vm-smoke";

/// The index of `channel` in `dir`.
pub fn index_path(dir: &Path, channel: Channel) -> PathBuf {
    dir.join(format!("{channel}.json"))
}

/// What [`add`] did.
#[derive(Debug)]
pub struct Added {
    /// The index written.
    pub path: PathBuf,
    /// Its new `seq`.
    pub seq: u64,
    /// The flavors of the new version.
    pub flavors: Vec<Flavor>,
    /// Whether the new version brought the browser extension.
    pub extension: bool,
    /// A signature of the previous index, removed: it does not match the new one.
    pub removed_signature: Option<PathBuf>,
}

/// Appends the version of `tag` (`v<semver>`) to the index of `channel` in `dir`, created if
/// missing, from the release's downloaded assets in `assets`:
///
/// - per flavor, `<id>-<version>-<flavor>-full.nupkg` (required for at least one flavor) and
///   optionally `<id>-<version>-<flavor>-delta.nupkg`, whose base version is the newest
///   older full package in Velopack's `releases.<flavor>.json` beside it;
/// - optionally the extension, `openncalayer-chromium-<version>.zip` and
///   `openncalayer-firefox-<version>.xpi` together.
///
/// sha256 and sizes come from the files; URLs point at the release `tag` of the
/// repository. `seq` grows by one, `generated` is `now` and `expires` 30 days later
/// ([`oncl_update::MAX_AGE`]). A signature of the old index is removed.
///
/// # Errors
///
/// A tag that is not `v<semver>`, a version already listed, missing or ambiguous assets,
/// an existing index that is invalid or of another channel, or a failure to read or write.
pub fn add(
    dir: &Path,
    channel: Channel,
    tag: &str,
    assets: &Path,
    rollout: u8,
    now: OffsetDateTime,
) -> anyhow::Result<Added> {
    let version = tag
        .strip_prefix('v')
        .and_then(|v| Version::parse(v).ok())
        .with_context(|| format!("the tag {tag:?} is not v<semver>"))?;
    if rollout > 100 {
        bail!("rollout {rollout} is over 100");
    }
    let path = index_path(dir, channel);
    let mut index = if path.exists() {
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let index =
            Index::from_json(&bytes).with_context(|| format!("reading {}", path.display()))?;
        if index.channel != channel {
            bail!("{} is of the {} channel", path.display(), index.channel);
        }
        index
    } else {
        Index {
            schema: oncl_update::index::SCHEMA,
            channel,
            seq: 0,
            generated: now,
            expires: now,
            core: Vec::new(),
            extension: None,
            plugins: Vec::new(),
        }
    };
    if index.release(&version).is_some() {
        bail!("{version} is in {} already", path.display());
    }

    let names = file_names(assets)?;
    let mut release = CoreRelease {
        version: version.clone(),
        flavors: Default::default(),
        rollout,
        revoked: false,
        notes_url: Some(format!("{REPOSITORY}/releases/tag/{tag}")),
    };
    let mut flavors = Vec::new();
    for flavor in Flavor::ALL {
        let Some(full) = find_one(&names, &format!("-{version}-{flavor}-full.nupkg"))? else {
            continue;
        };
        let mut packages = FlavorPackage {
            full: package(assets, tag, full)?,
            delta_from: Default::default(),
        };
        if let Some(delta) = find_one(&names, &format!("-{version}-{flavor}-delta.nupkg"))? {
            let base = delta_base(assets, flavor, &version)?;
            packages
                .delta_from
                .insert(base, package(assets, tag, delta)?);
        }
        release.flavors.insert(flavor.as_str().to_owned(), packages);
        flavors.push(flavor);
    }
    if flavors.is_empty() {
        bail!(
            "{} has no <id>-{version}-<flavor>-full.nupkg",
            assets.display()
        );
    }

    let chromium = format!("openncalayer-chromium-{version}.zip");
    let firefox = format!("openncalayer-firefox-{version}.xpi");
    let extension = match (names.contains(&chromium), names.contains(&firefox)) {
        (true, true) => {
            index.extension = Some(Extension {
                version: version.clone(),
                chromium_zip: asset(assets, tag, &chromium)?,
                firefox_xpi: asset(assets, tag, &firefox)?,
            });
            true
        }
        (false, false) => false,
        (true, false) => bail!("{} has {chromium} but not {firefox}", assets.display()),
        (false, true) => bail!("{} has {firefox} but not {chromium}", assets.display()),
    };

    index.core.push(release);
    index.core.sort_by(|a, b| a.version.cmp(&b.version));
    index.seq = index
        .seq
        .checked_add(1)
        .context("seq cannot grow any further")?;
    index.generated = now.replace_nanosecond(0).expect("0 is a valid nanosecond");
    index.expires = index.generated + oncl_update::MAX_AGE;

    let mut json = serde_json::to_string_pretty(&index).context("serializing the index")?;
    json.push('\n');
    // What is written must read back as valid.
    Index::from_json(json.as_bytes()).context("the new index is invalid")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    let signature = signature_path(&path);
    let removed_signature = if signature.exists() {
        fs::remove_file(&signature).with_context(|| format!("removing {}", signature.display()))?;
        Some(signature)
    } else {
        None
    };
    Ok(Added {
        path,
        seq: index.seq,
        flavors,
        extension,
        removed_signature,
    })
}

/// The names of the files in `dir`.
fn file_names(dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        if entry.file_type()?.is_file()
            && let Ok(name) = entry.file_name().into_string()
        {
            names.insert(name);
        }
    }
    Ok(names)
}

/// The one name `<id><suffix>` with a non-empty `<id>`, if any.
fn find_one<'a>(names: &'a BTreeSet<String>, suffix: &str) -> anyhow::Result<Option<&'a str>> {
    let mut found = names
        .iter()
        .filter(|n| n.len() > suffix.len() && n.ends_with(suffix));
    match (found.next(), found.next()) {
        (None, _) => Ok(None),
        (Some(name), None) => Ok(Some(name)),
        (Some(a), Some(b)) => bail!("both {a} and {b} end with {suffix}"),
    }
}

/// The URL of the asset `name` of the release `tag`.
fn release_url(tag: &str, name: &str) -> anyhow::Result<String> {
    let safe = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
    };
    if !safe(tag) || !safe(name) {
        bail!("{tag}/{name}: only ASCII letters, digits and ._-+ go into an asset URL");
    }
    Ok(format!("{REPOSITORY}/releases/download/{tag}/{name}"))
}

/// The sha256 and size of `path`.
fn sum(path: &Path) -> anyhow::Result<(Sha256, u64)> {
    let mut file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((Sha256(hasher.finalize().into()), size))
}

fn package(assets: &Path, tag: &str, name: &str) -> anyhow::Result<Package> {
    let (sha256, size) = sum(&assets.join(name))?;
    Ok(Package {
        url: release_url(tag, name)?,
        sha256,
        size,
    })
}

fn asset(assets: &Path, tag: &str, name: &str) -> anyhow::Result<Asset> {
    let (sha256, _) = sum(&assets.join(name))?;
    Ok(Asset {
        url: release_url(tag, name)?,
        sha256,
    })
}

/// The version a delta package of `version` applies to: the newest full package older than
/// `version` in Velopack's `releases.<flavor>.json`, the feed `vpk pack` made it from.
fn delta_base(assets: &Path, flavor: Flavor, version: &Version) -> anyhow::Result<Version> {
    let path = assets.join(format!("releases.{flavor}.json"));
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let feed: Value =
        serde_json::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
    let entries = feed["Assets"]
        .as_array()
        .with_context(|| format!("{}: no Assets", path.display()))?;
    let mut base: Option<Version> = None;
    for entry in entries {
        if entry["Type"] != "Full" {
            continue;
        }
        let v = entry["Version"]
            .as_str()
            .and_then(|v| Version::parse(v).ok())
            .with_context(|| format!("{}: bad Version in {entry}", path.display()))?;
        if v < *version && base.as_ref().is_none_or(|b| v > *b) {
            base = Some(v);
        }
    }
    base.with_context(|| {
        format!(
            "{}: no full package older than {version} for the {flavor} delta",
            path.display()
        )
    })
}

/// The network side of [`check`].
pub trait Remote {
    /// The HTTP status of `HEAD url`, after redirects.
    ///
    /// # Errors
    ///
    /// If no response arrives.
    fn head(&self, url: &str) -> anyhow::Result<u16>;

    /// Whether the commit of `tag` has the commit status [`VM_SMOKE`] set to `success`.
    ///
    /// # Errors
    ///
    /// If the statuses cannot be read.
    fn vm_smoke_passed(&self, tag: &str) -> anyhow::Result<bool>;
}

/// [`Remote`] over the network: assets as they are, commit statuses through the GitHub API
/// (with `GITHUB_TOKEN` if set).
pub struct GitHub {
    agent: Agent,
    token: Option<String>,
}

impl GitHub {
    /// The longest a request may take.
    const TIMEOUT: Duration = Duration::from_secs(60);

    /// A client; `GITHUB_TOKEN` is read now.
    pub fn new() -> GitHub {
        GitHub {
            agent: Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Self::TIMEOUT))
                .build()
                .into(),
            token: std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()),
        }
    }
}

impl Default for GitHub {
    fn default() -> GitHub {
        GitHub::new()
    }
}

impl Remote for GitHub {
    fn head(&self, url: &str) -> anyhow::Result<u16> {
        let response = self
            .agent
            .head(url)
            .header("User-Agent", "open-ncalayer-xtask")
            .call()
            .with_context(|| format!("HEAD {url}"))?;
        Ok(response.status().as_u16())
    }

    fn vm_smoke_passed(&self, tag: &str) -> anyhow::Result<bool> {
        let repo = REPOSITORY
            .strip_prefix("https://github.com/")
            .context("the repository is not on GitHub")?;
        let url = format!("https://api.github.com/repos/{repo}/commits/{tag}/status");
        let mut request = self
            .agent
            .get(&url)
            .header("User-Agent", "open-ncalayer-xtask")
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = &self.token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let mut response = request.call().with_context(|| format!("GET {url}"))?;
        if response.status() != 200 {
            bail!("GET {url}: {}", response.status());
        }
        let body = response
            .body_mut()
            .read_to_string()
            .with_context(|| format!("GET {url}"))?;
        let status: Value = serde_json::from_str(&body).with_context(|| format!("GET {url}"))?;
        // The combined status lists the latest status of each context.
        Ok(status["statuses"].as_array().is_some_and(|statuses| {
            statuses
                .iter()
                .any(|s| s["context"] == VM_SMOKE && s["state"] == "success")
        }))
    }
}

/// What [`check`] reads besides the indexes.
pub struct CheckOptions<'a> {
    /// The trusted public keys (`crates/oncl-update/keys/`, [`trusted_keys`]).
    pub keys: &'a [PublicKey],
    /// The git revision of the base branch whose indexes `seq` must grow from; `None`
    /// skips that check.
    pub base: Option<&'a str>,
    /// Require [`VM_SMOKE`] = `success` on the tag of every version new against `base`.
    /// Needs a [`Remote`].
    pub vm_smoke: bool,
    /// The time the indexes must be valid at.
    pub now: OffsetDateTime,
}

/// An index that passed [`check`].
#[derive(Debug)]
pub struct Checked {
    /// Its channel.
    pub channel: Channel,
    /// Its `seq`.
    pub seq: u64,
    /// The `seq` of the base branch's index, if it has one.
    pub base_seq: Option<u64>,
    /// Core versions that the base branch's index lacks.
    pub new_versions: Vec<Version>,
}

/// Checks the indexes in `dir` (at least one channel): each passes the client's
/// verification (`oncl_update::verify`, signature by one of `options.keys` included) at
/// `options.now`; against `options.base`, a changed index has a greater `seq` and no index
/// is removed. With `remote`, every asset URL answers `HEAD` with 200 and, if
/// `options.vm_smoke`, every new version passed `vm-smoke`.
///
/// # Errors
///
/// The first failed check.
pub fn check(
    dir: &Path,
    options: &CheckOptions<'_>,
    remote: Option<&dyn Remote>,
) -> anyhow::Result<Vec<Checked>> {
    if options.vm_smoke && remote.is_none() {
        bail!("the {VM_SMOKE} gate needs the network");
    }
    if options.keys.is_empty() {
        bail!("no trusted public key");
    }
    let mut checked = Vec::new();
    for channel in Channel::ALL {
        let path = index_path(dir, channel);
        let signature = signature_path(&path);
        let base = match options.base {
            Some(rev) => base_index(dir, rev, channel)?,
            None => None,
        };
        if !path.exists() {
            if signature.exists() {
                bail!("{} has no index beside it", signature.display());
            }
            if base.is_some() {
                bail!(
                    "{} is in {} but removed here",
                    path.display(),
                    options.base.unwrap_or_default()
                );
            }
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let sig = fs::read(&signature).with_context(|| {
            format!(
                "reading {}: sign the index with `cargo xtask sign`",
                signature.display()
            )
        })?;
        let index = oncl_update::verify(&bytes, &sig, options.keys, channel, None, options.now)
            .with_context(|| format!("{} is refused", path.display()))?;

        let (base_seq, new_versions) = match &base {
            Some((base_bytes, base_index)) => {
                if *base_bytes != bytes && index.seq <= base_index.seq {
                    bail!(
                        "{} changed, but its seq {} does not grow from {} of {}",
                        path.display(),
                        index.seq,
                        base_index.seq,
                        options.base.unwrap_or_default()
                    );
                }
                let new = index
                    .core
                    .iter()
                    .filter(|r| base_index.release(&r.version).is_none())
                    .map(|r| r.version.clone())
                    .collect();
                (Some(base_index.seq), new)
            }
            None => (None, index.core.iter().map(|r| r.version.clone()).collect()),
        };

        if let Some(remote) = remote {
            for url in asset_urls(&index) {
                let status = remote.head(url)?;
                if status != 200 {
                    bail!("{}: HEAD {url} answered {status}", path.display());
                }
            }
            if options.vm_smoke {
                for version in &new_versions {
                    let tag = format!("v{version}");
                    if !remote.vm_smoke_passed(&tag)? {
                        bail!("{tag} has no successful {VM_SMOKE} status");
                    }
                }
            }
        }
        checked.push(Checked {
            channel,
            seq: index.seq,
            base_seq,
            new_versions,
        });
    }
    if checked.is_empty() {
        bail!("{} has no index", dir.display());
    }
    Ok(checked)
}

/// The URLs of every downloadable file of `index`.
fn asset_urls(index: &Index) -> BTreeSet<&str> {
    let mut urls = BTreeSet::new();
    for release in &index.core {
        for package in release.flavors.values() {
            urls.insert(package.full.url.as_str());
            urls.extend(package.delta_from.values().map(|d| d.url.as_str()));
        }
    }
    if let Some(ext) = &index.extension {
        urls.insert(ext.chromium_zip.url.as_str());
        urls.insert(ext.firefox_xpi.url.as_str());
    }
    urls
}

/// The index of `channel` at the git revision `rev`, in `dir`'s directory of that
/// revision: its bytes and contents, or `None` if it has none.
fn base_index(dir: &Path, rev: &str, channel: Channel) -> anyhow::Result<Option<(Vec<u8>, Index)>> {
    let commit = format!("{rev}^{{commit}}");
    if !git(dir, &["rev-parse", "--verify", "--quiet", &commit])?
        .status
        .success()
    {
        bail!(
            "the base revision {rev} is not in the repository of {}",
            dir.display()
        );
    }
    let object = format!("{rev}:./{channel}.json");
    if !git(dir, &["cat-file", "-e", &object])?.status.success() {
        return Ok(None);
    }
    let output = git(dir, &["cat-file", "blob", &object])?;
    if !output.status.success() {
        bail!(
            "git cat-file blob {object}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let index = Index::from_json(&output.stdout).with_context(|| format!("reading {object}"))?;
    Ok(Some((output.stdout, index)))
}

fn git(dir: &Path, args: &[&str]) -> anyhow::Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))
}

/// The trusted public keys in `dir`: `current.pub` and, if present, `next.pub`.
///
/// # Errors
///
/// If `current.pub` is missing or a key cannot be read.
pub fn trusted_keys(dir: &Path) -> anyhow::Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    for name in ["current.pub", "next.pub"] {
        let path = dir.join(name);
        if name == "next.pub" && !path.exists() {
            continue;
        }
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "reading {}: make the key with `cargo xtask sign keygen`",
                path.display()
            )
        })?;
        keys.push(PublicKey::decode(&text).with_context(|| format!("reading {}", path.display()))?);
    }
    Ok(keys)
}
