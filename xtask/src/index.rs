//! `cargo xtask index`: the update indexes of the channels, `updates/v1/<channel>.json`
//! (`docs/design/update-index.md`).
//!
//! - [`add`] appends a released version to an index, from the downloaded assets of its
//!   GitHub release, with the next `seq` and a new validity. The result is unsigned: sign it
//!   with `cargo xtask sign`.
//! - [`refresh`] gives an index the next `seq` and a new validity without other changes, to
//!   sign it again before it expires.
//! - [`check`] is the gate before publishing: the format, the signature by a trusted key,
//!   asset URLs on the project's releases ([`check_asset_urls`]), `seq` growth against the
//!   base branch and, with a [`Remote`], that every asset answers `HEAD` with 200 and,
//!   behind a flag, that new versions passed `vm-smoke`.

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

/// The Velopack package id (`vpk pack --packId`), the first part of package file names.
pub const PACKAGE_ID: &str = "OpenNCALayer";

/// The `vm-smoke` commit status context (set on release tags by the lab agent).
pub const VM_SMOKE: &str = "vm-smoke";

/// The index of `channel` in `dir`.
pub fn index_path(dir: &Path, channel: Channel) -> PathBuf {
    dir.join(format!("{channel}.json"))
}

/// The full package of `version` for `flavor`: `OpenNCALayer-<version>-<flavor>-full.nupkg`.
pub fn full_package_name(version: &Version, flavor: &str) -> String {
    format!("{PACKAGE_ID}-{version}-{flavor}-full.nupkg")
}

/// The delta package of `version` for `flavor`: `OpenNCALayer-<version>-<flavor>-delta.nupkg`.
pub fn delta_package_name(version: &Version, flavor: &str) -> String {
    format!("{PACKAGE_ID}-{version}-{flavor}-delta.nupkg")
}

/// The Chromium extension of `version`: `openncalayer-chromium-<version>.zip`.
pub fn chromium_name(version: &Version) -> String {
    format!("openncalayer-chromium-{version}.zip")
}

/// The Firefox extension of `version`: `openncalayer-firefox-<version>.xpi`.
pub fn firefox_name(version: &Version) -> String {
    format!("openncalayer-firefox-{version}.xpi")
}

/// The URL of the asset `name` of the release of `version`, tag `v<version>`.
pub fn release_asset_url(version: &Version, name: &str) -> String {
    format!("{REPOSITORY}/releases/download/v{version}/{name}")
}

/// The release notes of `version`.
pub fn release_notes_url(version: &Version) -> String {
    format!("{REPOSITORY}/releases/tag/v{version}")
}

/// Refuses an index whose files are not where the release workflow puts them: every URL
/// must be exactly [`release_asset_url`] of the entry's own version and the file name of
/// its kind (full or delta package of that flavor, Chromium or Firefox extension), and
/// `notes_url` [`release_notes_url`]. So no host, repository, tag, query or fragment other
/// than the project's releases gets signed or published. Flavors this version does not
/// know are refused too.
///
/// # Errors
///
/// The first URL that differs.
pub fn check_asset_urls(index: &Index) -> anyhow::Result<()> {
    let expect = |what: &str, url: &str, expected: String| {
        if url == expected {
            Ok(())
        } else {
            bail!("{what}: {url:?} is not {expected:?}, the asset of the project's release")
        }
    };
    for release in &index.core {
        let v = &release.version;
        if let Some(url) = &release.notes_url {
            expect(&format!("core {v} notes_url"), url, release_notes_url(v))?;
        }
        for (flavor, packages) in &release.flavors {
            if !Flavor::ALL.iter().any(|f| f.as_str() == flavor) {
                bail!("core {v}: unknown flavor {flavor:?}");
            }
            expect(
                &format!("core {v} {flavor}"),
                &packages.full.url,
                release_asset_url(v, &full_package_name(v, flavor)),
            )?;
            for (from, delta) in &packages.delta_from {
                expect(
                    &format!("core {v} {flavor} delta from {from}"),
                    &delta.url,
                    release_asset_url(v, &delta_package_name(v, flavor)),
                )?;
            }
        }
    }
    if let Some(ext) = &index.extension {
        let v = &ext.version;
        expect(
            "extension chromium_zip",
            &ext.chromium_zip.url,
            release_asset_url(v, &chromium_name(v)),
        )?;
        expect(
            "extension firefox_xpi",
            &ext.firefox_xpi.url,
            release_asset_url(v, &firefox_name(v)),
        )?;
    }
    Ok(())
}

/// An index written by [`add`] or [`refresh`].
#[derive(Debug)]
pub struct Written {
    /// The index.
    pub path: PathBuf,
    /// Its new `seq`.
    pub seq: u64,
    /// A signature of the previous index, removed: it does not match the new one.
    pub removed_signature: Option<PathBuf>,
}

/// What [`add`] did.
#[derive(Debug)]
pub struct Added {
    /// The index written.
    pub written: Written,
    /// The flavors of the new version.
    pub flavors: Vec<Flavor>,
    /// Whether the new version brought the browser extension.
    pub extension: bool,
}

/// Appends the version of `tag` (`v<semver>`) to the index of `channel` in `dir`, created if
/// missing, from the release's downloaded assets in `assets`:
///
/// - per flavor, [`full_package_name`] (required for at least one flavor) and optionally
///   [`delta_package_name`], whose base version is the newest older full package in
///   Velopack's `releases.<flavor>.json` beside it;
/// - optionally the extension, [`chromium_name`] and [`firefox_name`] together.
///
/// sha256 and sizes come from the files; URLs are [`release_asset_url`]. `seq` grows by
/// one, `generated` is `now` and `expires` 30 days later ([`oncl_update::MAX_AGE`]). A
/// signature of the old index is removed.
///
/// # Errors
///
/// A tag that is not `v<semver>`, a version already listed, missing or half-present assets,
/// an existing index that is invalid, of another channel or with URLs
/// [`check_asset_urls`] refuses, or a failure to read or write.
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
        .filter(|v| format!("v{v}") == tag)
        .with_context(|| format!("the tag {tag:?} is not v<semver>"))?;
    if rollout > 100 {
        bail!("rollout {rollout} is over 100");
    }
    let path = index_path(dir, channel);
    let mut index = if path.exists() {
        read_index(&path, channel)?
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
        notes_url: Some(release_notes_url(&version)),
    };
    let mut flavors = Vec::new();
    for flavor in Flavor::ALL {
        let full = full_package_name(&version, flavor.as_str());
        if !names.contains(&full) {
            continue;
        }
        let mut packages = FlavorPackage {
            full: package(assets, &version, &full)?,
            contents_sha256: None,
            delta_from: Default::default(),
        };
        let delta = delta_package_name(&version, flavor.as_str());
        if names.contains(&delta) {
            let base = delta_base(assets, flavor, &version)?;
            packages
                .delta_from
                .insert(base, package(assets, &version, &delta)?);
            // What the client checks the full package rebuilt from the delta against.
            let path = assets.join(&full);
            packages.contents_sha256 = Some(
                oncl_update::contents_sha256(&path)
                    .with_context(|| format!("reading the files of {}", path.display()))?,
            );
        }
        release.flavors.insert(flavor.as_str().to_owned(), packages);
        flavors.push(flavor);
    }
    if flavors.is_empty() {
        bail!(
            "{} has no {}",
            assets.display(),
            full_package_name(&version, "<flavor>")
        );
    }

    let chromium = chromium_name(&version);
    let firefox = firefox_name(&version);
    let extension = match (names.contains(&chromium), names.contains(&firefox)) {
        (true, true) => {
            index.extension = Some(Extension {
                version: version.clone(),
                chromium_zip: asset(assets, &version, &chromium)?,
                firefox_xpi: asset(assets, &version, &firefox)?,
            });
            true
        }
        (false, false) => false,
        (true, false) => bail!("{} has {chromium} but not {firefox}", assets.display()),
        (false, true) => bail!("{} has {firefox} but not {chromium}", assets.display()),
    };

    index.core.push(release);
    index.core.sort_by(|a, b| a.version.cmp(&b.version));
    let written = write_next(&path, index, now)?;
    Ok(Added {
        written,
        flavors,
        extension,
    })
}

/// Gives the index of `channel` in `dir` the next `seq`, `generated` = `now` and `expires`
/// 30 days later, and nothing else, so it can be signed again before it expires. A
/// signature of the old index is removed.
///
/// # Errors
///
/// A missing or invalid index, one of another channel or with URLs [`check_asset_urls`]
/// refuses, or a failure to write.
pub fn refresh(dir: &Path, channel: Channel, now: OffsetDateTime) -> anyhow::Result<Written> {
    let path = index_path(dir, channel);
    let index = read_index(&path, channel)?;
    write_next(&path, index, now)
}

/// The index at `path`, which must be of `channel` and pass [`check_asset_urls`].
fn read_index(path: &Path, channel: Channel) -> anyhow::Result<Index> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let index = Index::from_json(&bytes).with_context(|| format!("reading {}", path.display()))?;
    if index.channel != channel {
        bail!("{} is of the {} channel", path.display(), index.channel);
    }
    check_asset_urls(&index).with_context(|| format!("reading {}", path.display()))?;
    Ok(index)
}

/// Writes `index` to `path` with the next `seq` and a validity from `now`, and removes the
/// signature beside it.
fn write_next(path: &Path, mut index: Index, now: OffsetDateTime) -> anyhow::Result<Written> {
    index.seq = index
        .seq
        .checked_add(1)
        .context("seq cannot grow any further")?;
    index.generated = now.replace_nanosecond(0).expect("0 is a valid nanosecond");
    index.expires = index.generated + oncl_update::MAX_AGE;

    let mut json = serde_json::to_string_pretty(&index).context("serializing the index")?;
    json.push('\n');
    // What is written must read back as valid.
    let reread = Index::from_json(json.as_bytes()).context("the new index is invalid")?;
    check_asset_urls(&reread).context("the new index is invalid")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    let signature = signature_path(path);
    let removed_signature = if signature.exists() {
        fs::remove_file(&signature).with_context(|| format!("removing {}", signature.display()))?;
        Some(signature)
    } else {
        None
    };
    Ok(Written {
        path: path.to_owned(),
        seq: index.seq,
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

fn package(assets: &Path, version: &Version, name: &str) -> anyhow::Result<Package> {
    let (sha256, size) = sum(&assets.join(name))?;
    Ok(Package {
        url: release_asset_url(version, name),
        sha256,
        size,
    })
}

fn asset(assets: &Path, version: &Version, name: &str) -> anyhow::Result<Asset> {
    let (sha256, _) = sum(&assets.join(name))?;
    Ok(Asset {
        url: release_asset_url(version, name),
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
    /// The trusted public keys (`crates/oncl-update/keys/`, [`trusted_keys`]): every index
    /// must be signed with `current`, and every version new against `base` must be tagged
    /// with a build embedding one of them ([`check_tag_key`]).
    pub keys: &'a TrustedKeys,
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

/// Checks the indexes in `dir`: each passes the client's verification
/// (`oncl_update::verify`, the signature by `options.keys.current` only: a `next.pub` is for
/// clients, not for signing before the switch) at `options.now` and [`check_asset_urls`];
/// against `options.base`, a changed index has a greater `seq` and no index is removed.
/// With a base, every version new against it, or whose packages changed, passes
/// [`check_tag_key`] in the repository of `dir` (all versions, if the base has no index of
/// the channel). Without a base the tag gate is not applied: versions published before a
/// key rotation keep tags with the old key, and the gate ran when they were added. With
/// `remote`, every asset URL answers `HEAD` with 200 and, if `options.vm_smoke`, every new
/// version passed `vm-smoke`.
///
/// A `dir` that does not exist (no index published yet) passes with nothing checked,
/// unless the base has an index there. An existing `dir` needs at least one index.
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
    let signing = [options.keys.current.clone()];
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
        let index = oncl_update::verify(&bytes, &sig, &signing, channel, None, options.now)
            .with_context(|| format!("{} is refused", path.display()))?;
        check_asset_urls(&index).with_context(|| format!("{} is refused", path.display()))?;

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

        // A version an installation may be moved onto must be able to update itself again.
        if options.base.is_some() {
            for release in &index.core {
                let changed = match &base {
                    Some((_, base_index)) => base_index
                        .release(&release.version)
                        .is_none_or(|old| old.flavors != release.flavors),
                    None => true,
                };
                if changed {
                    check_tag_key(dir, &release.version, options.keys)
                        .with_context(|| format!("{} is refused", path.display()))?;
                }
            }
        }

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
    if checked.is_empty() && dir.exists() {
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
    let (repo, below) = existing_ancestor(dir)?;
    let commit = format!("{rev}^{{commit}}");
    if !git(repo, &["rev-parse", "--verify", "--quiet", &commit])?
        .status
        .success()
    {
        bail!(
            "the base revision {rev} is not in the repository of {}",
            dir.display()
        );
    }
    let object = format!("{rev}:./{below}{channel}.json");
    if !git(repo, &["cat-file", "-e", &object])?.status.success() {
        return Ok(None);
    }
    let output = git(repo, &["cat-file", "blob", &object])?;
    if !output.status.success() {
        bail!(
            "git cat-file blob {object}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let index = Index::from_json(&output.stdout).with_context(|| format!("reading {object}"))?;
    Ok(Some((output.stdout, index)))
}

/// The nearest directory of `dir` that exists (`dir` itself, or an ancestor when no index
/// was published yet), where git runs, and the path from it down to `dir` (`a/b/`, empty
/// for `dir` itself).
fn existing_ancestor(dir: &Path) -> anyhow::Result<(&Path, String)> {
    let repo = dir
        .ancestors()
        .find(|d| d.is_dir())
        .with_context(|| format!("{} is not in a directory", dir.display()))?;
    let mut below = String::new();
    for part in dir.strip_prefix(repo).unwrap_or(Path::new("")).components() {
        below.push_str(&part.as_os_str().to_string_lossy());
        below.push('/');
    }
    Ok((repo, below))
}

fn git(dir: &Path, args: &[&str]) -> anyhow::Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))
}

/// Where a build's update key is, from the workspace root: what the client embeds.
pub const TAG_KEY: &str = "crates/oncl-update/keys/current.pub";

/// The trusted public keys: `current.pub`, which signs the indexes, and the `next.pub` of a
/// key rotation, which only clients take (`docs/dev/release.md`).
pub struct TrustedKeys {
    /// The key every published index is signed with.
    pub current: PublicKey,
    /// The key line (base64) of `current`.
    current_line: String,
    /// The key line of `next.pub`, if present.
    next_line: Option<String>,
}

impl TrustedKeys {
    /// Whether the key file `text` is `current` or `next`.
    fn trusts(&self, text: &str) -> bool {
        let line = key_line(text);
        line == self.current_line || self.next_line.as_deref() == Some(line)
    }
}

/// The base64 line of a minisign public key file.
fn key_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .unwrap_or_default()
}

/// The trusted public keys in `dir`: `current.pub` and, if present, `next.pub`.
///
/// # Errors
///
/// If `current.pub` is missing or a key cannot be read.
pub fn trusted_keys(dir: &Path) -> anyhow::Result<TrustedKeys> {
    let read = |name: &str| -> anyhow::Result<(PublicKey, String)> {
        let path = dir.join(name);
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "reading {}: make the key with `cargo xtask sign keygen`",
                path.display()
            )
        })?;
        let key =
            PublicKey::decode(&text).with_context(|| format!("reading {}", path.display()))?;
        Ok((key, key_line(&text).to_owned()))
    };
    let (current, current_line) = read("current.pub")?;
    let next_line = if dir.join("next.pub").exists() {
        Some(read("next.pub")?.1)
    } else {
        None
    };
    Ok(TrustedKeys {
        current,
        current_line,
        next_line,
    })
}

/// Refuses `version` unless its tag `v<version>`, in the git repository of `dir`, holds
/// [`TAG_KEY`] that is a minisign public key and one of `keys`: an installation moved onto
/// it (an update, or the way off a revoked version) must be able to verify later indexes.
/// A build without the key has its updater off for good.
///
/// # Errors
///
/// The tag is missing, has no key, a malformed key, or a key `keys` does not have.
pub fn check_tag_key(dir: &Path, version: &Version, keys: &TrustedKeys) -> anyhow::Result<()> {
    let tag = format!("v{version}");
    // The index directory may not exist yet (the first index of a channel).
    let (dir, _) = existing_ancestor(dir)?;
    let commit = format!("refs/tags/{tag}^{{commit}}");
    if !git(dir, &["rev-parse", "--verify", "--quiet", &commit])?
        .status
        .success()
    {
        bail!("{version}: there is no tag {tag} (fetch the tags)");
    }
    let object = format!("refs/tags/{tag}:{TAG_KEY}");
    let output = git(dir, &["cat-file", "blob", &object])?;
    if !output.status.success() {
        bail!(
            "{version}: {tag} has no {TAG_KEY}: its build cannot update itself, so no installation may be moved onto it"
        );
    }
    let text = String::from_utf8(output.stdout).context("the key is not UTF-8")?;
    PublicKey::decode(&text)
        .with_context(|| format!("{version}: {TAG_KEY} of {tag} is not a minisign public key"))?;
    if !keys.trusts(&text) {
        bail!("{version}: {TAG_KEY} of {tag} is neither current.pub nor next.pub");
    }
    Ok(())
}
