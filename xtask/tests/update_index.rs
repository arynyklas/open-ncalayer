//! `cargo xtask sign` and `cargo xtask index`: a key pair, an index made from release assets,
//! its signature, and the checks before publishing. Every key is made here, in temporary
//! directories.

use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::process::Command;

use minisign::KeyPair;
use oncl_update::{Channel, Flavor, Index, Sha256, Version};
use time::{Duration, OffsetDateTime};
use xtask::index::{self, CheckOptions, Remote};
use xtask::sign;

const TAG: &str = "v0.2.0-beta.1";
const NEXT_TAG: &str = "v0.2.0-beta.2";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn version(tag: &str) -> Version {
    Version::parse(tag.strip_prefix('v').unwrap()).unwrap()
}

/// A test key pair, unencrypted, with `current.pub` in a keys directory.
struct TestKey {
    pair: KeyPair,
    keys: tempfile::TempDir,
}

impl TestKey {
    fn new() -> TestKey {
        let pair = KeyPair::generate_unencrypted_keypair().unwrap();
        let keys = tempfile::tempdir().unwrap();
        fs::write(
            keys.path().join("current.pub"),
            pair.pk.to_box().unwrap().into_string(),
        )
        .unwrap();
        TestKey { pair, keys }
    }

    fn trusted(&self) -> index::TrustedKeys {
        index::trusted_keys(self.keys.path()).unwrap()
    }

    fn public_text(&self) -> String {
        fs::read_to_string(self.keys.path().join("current.pub")).unwrap()
    }

    fn sign(&self, index: &Path) {
        sign::sign(index, &self.pair.sk, now()).unwrap();
    }
}

/// The assets of the release `tag`: full packages for `flavors`, the delta of win-x64 when
/// `delta_base` is given (with Velopack's feed naming its base, and the win-x64 full
/// package a zip archive, whose files the index sums), and the extension.
fn release_assets(tag: &str, flavors: &[Flavor], delta_base: Option<&str>) -> tempfile::TempDir {
    let v = version(tag);
    let dir = tempfile::tempdir().unwrap();
    for flavor in flavors {
        fs::write(
            dir.path()
                .join(format!("OpenNCALayer-{v}-{flavor}-full.nupkg")),
            format!("full {v} {flavor}"),
        )
        .unwrap();
    }
    if let Some(base) = delta_base {
        let full = dir
            .path()
            .join(format!("OpenNCALayer-{v}-win-x64-full.nupkg"));
        let mut zip = zip::ZipWriter::new(fs::File::create(full).unwrap());
        zip.start_file(
            "lib/app/openncalayer.exe",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        std::io::Write::write_all(&mut zip, format!("program {v}").as_bytes()).unwrap();
        zip.finish().unwrap();
        fs::write(
            dir.path()
                .join(format!("OpenNCALayer-{v}-win-x64-delta.nupkg")),
            format!("delta {base} -> {v}"),
        )
        .unwrap();
        let feed = serde_json::json!({"Assets": [
            {"PackageId": "OpenNCALayer", "Version": "0.1.0", "Type": "Full",
             "FileName": "OpenNCALayer-0.1.0-win-x64-full.nupkg"},
            {"PackageId": "OpenNCALayer", "Version": base, "Type": "Full",
             "FileName": format!("OpenNCALayer-{base}-win-x64-full.nupkg")},
            {"PackageId": "OpenNCALayer", "Version": v.to_string(), "Type": "Full",
             "FileName": format!("OpenNCALayer-{v}-win-x64-full.nupkg")},
            {"PackageId": "OpenNCALayer", "Version": v.to_string(), "Type": "Delta",
             "FileName": format!("OpenNCALayer-{v}-win-x64-delta.nupkg")},
        ]});
        fs::write(dir.path().join("releases.win-x64.json"), feed.to_string()).unwrap();
    }
    fs::write(
        dir.path().join(format!("openncalayer-chromium-{v}.zip")),
        "chromium",
    )
    .unwrap();
    fs::write(
        dir.path().join(format!("openncalayer-firefox-{v}.xpi")),
        "firefox",
    )
    .unwrap();
    fs::write(dir.path().join("SHA256SUMS"), "not a package").unwrap();
    dir
}

fn add(dir: &Path, tag: &str, assets: &Path) -> index::Added {
    index::add(dir, Channel::Beta, tag, assets, 100, now()).unwrap()
}

fn read(path: &Path) -> Index {
    Index::from_json(&fs::read(path).unwrap()).unwrap()
}

fn options<'a>(keys: &'a index::TrustedKeys, base: Option<&'a str>) -> CheckOptions<'a> {
    CheckOptions {
        keys,
        base,
        vm_smoke: false,
        conformance: false,
        now: now(),
    }
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "tag.forceSignAnnotated=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

/// A git repository whose first commit holds the update key `key` (the file the client
/// embeds) and is tagged [`TAG`] and [`NEXT_TAG`]: builds of both versions update
/// themselves. Its indexes are [`Repo::path`], `updates/v1`.
struct Repo {
    repo: tempfile::TempDir,
    dir: std::path::PathBuf,
}

impl Repo {
    fn path(&self) -> &Path {
        &self.dir
    }
}

fn keyed_repo(key: &str) -> Repo {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    let keys = repo.path().join(index::TAG_KEY);
    fs::create_dir_all(keys.parent().unwrap()).unwrap();
    fs::write(&keys, key).unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "--quiet", "-m", "key"]);
    for tag in [TAG, NEXT_TAG] {
        git(repo.path(), &["tag", tag]);
    }
    let dir = repo.path().join("updates").join("v1");
    Repo { repo, dir }
}

/// [`keyed_repo`] whose next commit holds `updates/v1/beta.json` at seq 1 with [`TAG`],
/// signed.
fn repository_with_index(key: &TestKey) -> (tempfile::TempDir, std::path::PathBuf) {
    let Repo { repo, dir } = keyed_repo(&key.public_text());
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(&dir, TAG, assets.path()).written.path;
    key.sign(&path);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "--quiet", "-m", "index"]);
    (repo, dir)
}

fn error_text(result: anyhow::Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn add_takes_sums_and_sizes_from_the_assets() {
    let dir = tempfile::tempdir().unwrap();
    let first = release_assets(TAG, &[Flavor::WinX64, Flavor::LinuxX64], None);
    let added = add(dir.path(), TAG, first.path());
    assert_eq!(added.written.path, dir.path().join("beta.json"));
    assert_eq!(added.written.seq, 1);
    assert_eq!(added.flavors, [Flavor::WinX64, Flavor::LinuxX64]);
    assert!(added.extension);

    let index = read(&added.written.path);
    assert_eq!((index.channel, index.seq), (Channel::Beta, 1));
    assert_eq!(index.generated, now());
    assert_eq!(index.expires, now() + Duration::days(30));
    let release = index.release(&version(TAG)).unwrap();
    assert_eq!(release.rollout, 100);
    assert!(!release.revoked);
    let linux = release.package(Flavor::LinuxX64).unwrap();
    let content = "full 0.2.0-beta.1 linux-x64";
    assert_eq!(linux.full.sha256, Sha256::of(content.as_bytes()));
    assert_eq!(linux.full.size, content.len() as u64);
    assert_eq!(
        linux.full.url,
        "https://github.com/arynyklas/open-ncalayer/releases/download/v0.2.0-beta.1/\
         OpenNCALayer-0.2.0-beta.1-linux-x64-full.nupkg"
    );
    assert!(linux.delta_from.is_empty());
    let extension = index.extension.as_ref().unwrap();
    assert_eq!(extension.version, version(TAG));
    assert_eq!(extension.firefox_xpi.sha256, Sha256::of(b"firefox"));

    // The next version: seq grows, its delta applies to the newest older full package of
    // Velopack's feed, and the stale signature goes.
    fs::write(dir.path().join("beta.json.minisig"), "stale").unwrap();
    let second = release_assets(NEXT_TAG, &[Flavor::WinX64], Some("0.2.0-beta.1"));
    let added = index::add(
        dir.path(),
        Channel::Beta,
        NEXT_TAG,
        second.path(),
        25,
        now() + Duration::days(1),
    )
    .unwrap();
    assert_eq!(added.written.seq, 2);
    assert_eq!(
        added.written.removed_signature,
        Some(dir.path().join("beta.json.minisig"))
    );
    assert!(!dir.path().join("beta.json.minisig").exists());
    let index = read(&added.written.path);
    assert_eq!(index.seq, 2);
    assert_eq!(index.expires, now() + Duration::days(31));
    let versions: Vec<_> = index.core.iter().map(|r| r.version.to_string()).collect();
    assert_eq!(versions, ["0.2.0-beta.1", "0.2.0-beta.2"]);
    let release = index.release(&version(NEXT_TAG)).unwrap();
    assert_eq!(release.rollout, 25);
    let win = release.package(Flavor::WinX64).unwrap();
    let delta = &win.delta_from[&version(TAG)];
    assert_eq!(
        delta.sha256,
        Sha256::of(b"delta 0.2.0-beta.1 -> 0.2.0-beta.2")
    );
    assert_eq!(win.delta_from.len(), 1);
    // The files of the full package, for the one the client rebuilds from the delta.
    let full = second
        .path()
        .join("OpenNCALayer-0.2.0-beta.2-win-x64-full.nupkg");
    assert_eq!(
        win.contents_sha256,
        Some(oncl_update::contents_sha256(&full).unwrap())
    );
    assert_eq!(index.extension.unwrap().version, version(NEXT_TAG));

    // A version is added once.
    let again = index::add(
        dir.path(),
        Channel::Beta,
        NEXT_TAG,
        second.path(),
        100,
        now(),
    );
    assert!(error_text(again).contains("already"));
}

#[test]
fn add_refuses_bad_input() {
    let dir = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let result = index::add(dir.path(), Channel::Beta, TAG, empty.path(), 100, now());
    assert!(error_text(result).contains("full.nupkg"));

    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let result = index::add(
        dir.path(),
        Channel::Beta,
        "0.2.0",
        assets.path(),
        100,
        now(),
    );
    assert!(error_text(result).contains("v<semver>"));

    // A delta without Velopack's feed has no known base.
    let assets = release_assets(TAG, &[Flavor::WinX64], Some("0.1.5"));
    fs::remove_file(assets.path().join("releases.win-x64.json")).unwrap();
    let result = index::add(dir.path(), Channel::Beta, TAG, assets.path(), 100, now());
    assert!(error_text(result).contains("releases.win-x64.json"));

    // Half of the extension.
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    fs::remove_file(assets.path().join("openncalayer-firefox-0.2.0-beta.1.xpi")).unwrap();
    let result = index::add(dir.path(), Channel::Beta, TAG, assets.path(), 100, now());
    assert!(error_text(result).contains("firefox"));
    assert!(!dir.path().join("beta.json").exists());

    // An index of another channel in the channel's file.
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let beta = add(dir.path(), TAG, assets.path()).written.path;
    fs::copy(&beta, dir.path().join("stable.json")).unwrap();
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let result = index::add(
        dir.path(),
        Channel::Stable,
        NEXT_TAG,
        assets.path(),
        100,
        now(),
    );
    assert!(error_text(result).contains("is of the beta channel"));
    let result = index::refresh(dir.path(), Channel::Stable, now());
    assert!(error_text(result).contains("is of the beta channel"));
}

#[test]
fn signed_index_passes_the_check() {
    let key = TestKey::new();
    let dir = keyed_repo(&key.public_text());
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(dir.path(), TAG, assets.path()).written.path;

    // Unsigned: refused.
    let unsigned = index::check(dir.path(), &options(&key.trusted(), None), None);
    assert!(error_text(unsigned).contains("cargo xtask sign"));

    key.sign(&path);
    let signature = fs::read_to_string(sign::signature_path(&path)).unwrap();
    assert!(signature.contains("trusted comment: channel=beta;seq=1\n"));

    let checked = index::check(dir.path(), &options(&key.trusted(), None), None).unwrap();
    assert_eq!(checked.len(), 1);
    assert_eq!((checked[0].channel, checked[0].seq), (Channel::Beta, 1));
    assert_eq!(checked[0].new_versions, [version(TAG)]);

    // The client accepts it too.
    let index = oncl_update::verify(
        &fs::read(&path).unwrap(),
        signature.as_bytes(),
        &[key.trusted().current],
        Channel::Beta,
        None,
        now(),
    )
    .unwrap();
    assert_eq!(index.seq, 1);

    // Another key: refused.
    let other = TestKey::new();
    let result = index::check(dir.path(), &options(&other.trusted(), None), None);
    assert!(error_text(result).contains("does not match any trusted key"));
}

#[test]
fn a_changed_byte_is_refused() {
    let key = TestKey::new();
    let dir = keyed_repo(&key.public_text());
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(dir.path(), TAG, assets.path()).written.path;
    key.sign(&path);

    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"rollout\": 100"));
    fs::write(&path, text.replace("\"rollout\": 100", "\"rollout\": 900")).unwrap();
    let result = index::check(dir.path(), &options(&key.trusted(), None), None);
    assert!(error_text(result).contains("does not match any trusted key"));

    // One byte of the signature.
    fs::write(&path, text).unwrap();
    index::check(dir.path(), &options(&key.trusted(), None), None).unwrap();
    let signature_path = sign::signature_path(&path);
    let signature = fs::read_to_string(&signature_path).unwrap();
    let lines: Vec<&str> = signature.lines().collect();
    let mut sig = lines[1].as_bytes().to_vec();
    sig[20] = if sig[20] == b'A' { b'B' } else { b'A' };
    let tampered = format!(
        "{}\n{}\n{}\n{}\n",
        lines[0],
        String::from_utf8(sig).unwrap(),
        lines[2],
        lines[3]
    );
    fs::write(&signature_path, tampered).unwrap();
    let result = index::check(dir.path(), &options(&key.trusted(), None), None);
    assert!(error_text(result).contains("signature"));
}

#[test]
fn seq_must_grow_from_the_base() {
    let key = TestKey::new();
    let (repo, dir) = repository_with_index(&key);
    let path = dir.join("beta.json");
    let keys = key.trusted();

    // Unchanged: passes, nothing new.
    let checked = index::check(&dir, &options(&keys, Some("HEAD")), None).unwrap();
    assert_eq!(checked[0].base_seq, Some(1));
    assert!(checked[0].new_versions.is_empty());

    // A new version, seq 2: passes, the version is new.
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    add(&dir, NEXT_TAG, assets.path());
    key.sign(&path);
    let checked = index::check(&dir, &options(&keys, Some("HEAD")), None).unwrap();
    assert_eq!((checked[0].seq, checked[0].base_seq), (2, Some(1)));
    assert_eq!(checked[0].new_versions, [version(NEXT_TAG)]);
    git(repo.path(), &["commit", "--quiet", "-am", "seq 2"]);

    // Changed with the same seq, then with seq going back: refused, though well signed.
    let mut index = read(&path);
    index.core[0].rollout = 50;
    for seq in [2, 1] {
        index.seq = seq;
        fs::write(&path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
        key.sign(&path);
        let result = index::check(&dir, &options(&keys, Some("HEAD")), None);
        assert!(error_text(result).contains("does not grow"), "seq {seq}");
    }

    // A removed index.
    fs::remove_file(&path).unwrap();
    fs::remove_file(sign::signature_path(&path)).unwrap();
    let result = index::check(&dir, &options(&keys, Some("HEAD")), None);
    assert!(error_text(result).contains("removed"));

    // A base that does not exist.
    let result = index::check(&dir, &options(&keys, Some("no-such-branch")), None);
    assert!(error_text(result).contains("no-such-branch"));
}

/// Answers `HEAD` with 200 except for URLs containing `missing`; a status passes for the
/// `(tag, context)` pairs of `passed`. Records the pairs asked about.
struct FakeRemote {
    missing: Option<&'static str>,
    passed: &'static [(&'static str, &'static str)],
    asked: RefCell<Vec<(String, String)>>,
}

impl FakeRemote {
    fn new(missing: Option<&'static str>, passed: &'static [(&'static str, &'static str)]) -> Self {
        FakeRemote {
            missing,
            passed,
            asked: RefCell::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<(String, String)> {
        self.asked.borrow().clone()
    }
}

impl Remote for FakeRemote {
    fn head(&self, url: &str) -> anyhow::Result<u16> {
        assert!(url.starts_with("https://github.com/arynyklas/open-ncalayer/releases/"));
        Ok(match self.missing {
            Some(m) if url.contains(m) => 404,
            _ => 200,
        })
    }

    fn status_passed(&self, tag: &str, context: &str) -> anyhow::Result<bool> {
        self.asked
            .borrow_mut()
            .push((tag.to_owned(), context.to_owned()));
        Ok(self.passed.contains(&(tag, context)))
    }
}

fn pair(tag: &str, context: &str) -> (String, String) {
    (tag.to_owned(), context.to_owned())
}

#[test]
fn network_checks_go_through_the_remote() {
    let key = TestKey::new();
    let (_repo, dir) = repository_with_index(&key);
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64, Flavor::Osx], None);
    let path = add(&dir, NEXT_TAG, assets.path()).written.path;
    key.sign(&path);
    let keys = key.trusted();

    let ok = FakeRemote::new(None, &[]);
    index::check(&dir, &options(&keys, Some("HEAD")), Some(&ok)).unwrap();
    assert!(ok.asked().is_empty(), "the status gates are off by default");

    let missing = FakeRemote::new(Some("osx-full"), &[]);
    let result = index::check(&dir, &options(&keys, Some("HEAD")), Some(&missing));
    assert!(error_text(result).contains("answered 404"));

    let gated = CheckOptions {
        vm_smoke: true,
        ..options(&keys, Some("HEAD"))
    };
    let unsmoked = FakeRemote::new(None, &[(TAG, index::VM_SMOKE)]);
    let result = index::check(&dir, &gated, Some(&unsmoked));
    assert!(error_text(result).contains("vm-smoke"));
    // Another context's success does not count.
    let other = FakeRemote::new(None, &[(NEXT_TAG, index::CONFORMANCE)]);
    let result = index::check(&dir, &gated, Some(&other));
    assert!(error_text(result).contains("v0.2.0-beta.2 has no successful vm-smoke status"));
    let smoked = FakeRemote::new(None, &[(NEXT_TAG, index::VM_SMOKE)]);
    index::check(&dir, &gated, Some(&smoked)).unwrap();
    // Only the version new against the base is asked about.
    assert_eq!(smoked.asked(), [pair(NEXT_TAG, index::VM_SMOKE)]);

    let result = index::check(&dir, &gated, None);
    assert!(error_text(result).contains("the vm-smoke gate needs the network"));
}

const STABLE_TAG: &str = "v0.2.0";

#[test]
fn check_conformance_required_for_new_stable() {
    let key = TestKey::new();
    let repo = keyed_repo(&key.public_text());
    git(repo.repo.path(), &["tag", STABLE_TAG]);
    let stable = release_assets(STABLE_TAG, &[Flavor::WinX64], None);
    let written = index::add(
        repo.path(),
        Channel::Stable,
        STABLE_TAG,
        stable.path(),
        100,
        now(),
    )
    .unwrap()
    .written;
    key.sign(&written.path);
    let beta = release_assets(TAG, &[Flavor::WinX64], None);
    key.sign(&add(repo.path(), TAG, beta.path()).written.path);
    let keys = key.trusted();
    let gated = CheckOptions {
        conformance: true,
        ..options(&keys, Some("HEAD"))
    };

    let none = FakeRemote::new(None, &[]);
    let result = index::check(repo.path(), &gated, Some(&none));
    assert!(
        error_text(result).contains("v0.2.0 has no successful conformance status"),
        "{:?}",
        none.asked()
    );
    // `vm-smoke` is not `conformance`.
    let smoked = FakeRemote::new(None, &[(STABLE_TAG, index::VM_SMOKE)]);
    let result = index::check(repo.path(), &gated, Some(&smoked));
    assert!(error_text(result).contains("no successful conformance status"));

    let conformed = FakeRemote::new(None, &[(STABLE_TAG, index::CONFORMANCE)]);
    index::check(repo.path(), &gated, Some(&conformed)).unwrap();
    // Asked about the new stable version only, not the beta one.
    assert_eq!(conformed.asked(), [pair(STABLE_TAG, index::CONFORMANCE)]);

    // Published (in the base), the version is not new and is not asked about again.
    git(repo.repo.path(), &["add", "."]);
    git(repo.repo.path(), &["commit", "--quiet", "-m", "indexes"]);
    let none = FakeRemote::new(None, &[]);
    index::check(repo.path(), &gated, Some(&none)).unwrap();
    assert!(none.asked().is_empty());
}

#[test]
fn check_conformance_not_required_for_beta() {
    let key = TestKey::new();
    let (_repo, dir) = repository_with_index(&key);
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    key.sign(&add(&dir, NEXT_TAG, assets.path()).written.path);
    let keys = key.trusted();

    let gated = CheckOptions {
        conformance: true,
        ..options(&keys, Some("HEAD"))
    };
    let none = FakeRemote::new(None, &[]);
    index::check(&dir, &gated, Some(&none)).unwrap();
    assert!(none.asked().is_empty());

    // With both gates, the new beta version needs `vm-smoke` only.
    let both = CheckOptions {
        vm_smoke: true,
        ..gated
    };
    let smoked = FakeRemote::new(None, &[(NEXT_TAG, index::VM_SMOKE)]);
    index::check(&dir, &both, Some(&smoked)).unwrap();
    assert_eq!(smoked.asked(), [pair(NEXT_TAG, index::VM_SMOKE)]);
}

#[test]
fn check_conformance_needs_network() {
    let key = TestKey::new();
    let (_repo, dir) = repository_with_index(&key);
    let keys = key.trusted();
    let gated = CheckOptions {
        conformance: true,
        ..options(&keys, Some("HEAD"))
    };
    let result = index::check(&dir, &gated, None);
    assert!(error_text(result).contains("the conformance gate needs the network"));
    // The command refuses the flag offline.
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["index", "check"])
        .arg(&dir)
        .args(["--offline", "--conformance"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--conformance"), "{stderr}");
}

#[test]
fn an_expired_index_is_not_signed() {
    let key = TestKey::new();
    let dir = tempfile::tempdir().unwrap();
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(dir.path(), TAG, assets.path()).written.path;
    let result = sign::sign(&path, &key.pair.sk, now() + Duration::days(30));
    assert!(error_text(result).contains("expired"));
    assert!(!sign::signature_path(&path).exists());
}

#[test]
fn keygen_makes_an_encrypted_pair_that_signs() {
    let out = tempfile::tempdir().unwrap();
    let out = out.path().join("index-key");
    let files = sign::keygen(&out, "correct horse").unwrap();
    assert_eq!(files.secret, out.join(sign::SECRET_KEY_FILE));
    assert_eq!(files.public, out.join(sign::PUBLIC_KEY_FILE));
    assert!(error_text(sign::load_secret_key(&files.secret, "wrong")).contains("password"));
    let secret = sign::load_secret_key(&files.secret, "correct horse").unwrap();

    let dir = keyed_repo(&fs::read_to_string(&files.public).unwrap());
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(dir.path(), TAG, assets.path()).written.path;
    sign::sign(&path, &secret, now()).unwrap();
    let keys = tempfile::tempdir().unwrap();
    fs::copy(&files.public, keys.path().join("current.pub")).unwrap();
    let trusted = index::trusted_keys(keys.path()).unwrap();
    index::check(dir.path(), &options(&trusted, None), None).unwrap();

    // The pair is not overwritten, and the password is not empty.
    assert!(error_text(sign::keygen(&out, "again")).contains("exists already"));
    let fresh = out.with_file_name("other-key");
    assert!(error_text(sign::keygen(&fresh, "")).contains("empty"));
}

#[test]
fn keygen_refuses_a_committable_directory() {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    let out = repo.path().join("keys");
    let result = sign::keygen(&out, "password");
    assert!(error_text(result).contains("not ignored"));
    assert!(!out.exists());

    fs::write(repo.path().join(".gitignore"), "/keys/\n").unwrap();
    sign::keygen(&out, "password").unwrap();
    assert!(out.join(sign::SECRET_KEY_FILE).exists());
}

/// Signs `path` as is, without the checks of `sign::sign`, as a tampered index would be.
fn sign_raw(key: &TestKey, path: &Path) {
    let bytes = fs::read(path).unwrap();
    let index: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let comment = format!(
        "channel={};seq={}",
        index["channel"].as_str().unwrap(),
        index["seq"]
    );
    let signature = minisign::sign(
        None,
        &key.pair.sk,
        std::io::Cursor::new(bytes),
        Some(&comment),
        None,
    )
    .unwrap();
    fs::write(sign::signature_path(path), signature.into_string()).unwrap();
}

#[test]
fn urls_off_the_project_releases_are_neither_signed_nor_published() {
    const FULL: &str = "https://github.com/arynyklas/open-ncalayer/releases/download/\
                        v0.2.0-beta.1/OpenNCALayer-0.2.0-beta.1-win-x64-full.nupkg";
    const CHROMIUM: &str = "https://github.com/arynyklas/open-ncalayer/releases/download/\
                            v0.2.0-beta.1/openncalayer-chromium-0.2.0-beta.1.zip";
    const NOTES: &str = "https://github.com/arynyklas/open-ncalayer/releases/tag/v0.2.0-beta.1";
    let swaps = [
        (
            FULL,
            FULL.replace("https://github.com/", "https://example.com/"),
        ),
        (
            FULL,
            FULL.replace("arynyklas/open-ncalayer", "someone/open-ncalayer"),
        ),
        (FULL, FULL.replace("/v0.2.0-beta.1/", "/v0.1.0/")),
        (FULL, FULL.replace("https://", "http://")),
        (FULL, format!("{FULL}?download=1")),
        (FULL, format!("{FULL}#x")),
        (FULL, FULL.replace("-win-x64-full", "-linux-x64-full")),
        (FULL, FULL.replace("-full.nupkg", "-delta.nupkg")),
        (
            CHROMIUM,
            CHROMIUM.replace("/v0.2.0-beta.1/", "/v0.2.0-beta.2/"),
        ),
        (
            CHROMIUM,
            CHROMIUM.replace("github.com", "github.com.example.net"),
        ),
        (NOTES, NOTES.replace("arynyklas", "someone")),
    ];
    let key = TestKey::new();
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    for (from, to) in swaps {
        let dir = tempfile::tempdir().unwrap();
        let path = add(dir.path(), TAG, assets.path()).written.path;
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("\"{from}\"")), "{from}");
        fs::write(
            &path,
            text.replace(&format!("\"{from}\""), &format!("\"{to}\"")),
        )
        .unwrap();

        let result = sign::sign(&path, &key.pair.sk, now());
        assert!(result.is_err(), "sign accepted {to}");
        assert!(!sign::signature_path(&path).exists(), "{to}");

        sign_raw(&key, &path);
        let result = index::check(dir.path(), &options(&key.trusted(), None), None);
        assert!(result.is_err(), "check accepted {to}");
    }

    // The messages name the rule for a URL the client itself would take.
    let dir = tempfile::tempdir().unwrap();
    let path = add(dir.path(), TAG, assets.path()).written.path;
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text.replace(FULL, &FULL.replace("github.com", "example.com")),
    )
    .unwrap();
    let result = sign::sign(&path, &key.pair.sk, now());
    assert!(error_text(result).contains("the asset of the project's release"));
    sign_raw(&key, &path);
    let result = index::check(dir.path(), &options(&key.trusted(), None), None);
    assert!(error_text(result).contains("the asset of the project's release"));
    // So does `add` reading it.
    let next = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let result = index::add(dir.path(), Channel::Beta, NEXT_TAG, next.path(), 100, now());
    assert!(error_text(result).contains("the asset of the project's release"));
}

#[test]
fn refresh_bumps_seq_and_validity_only() {
    let key = TestKey::new();
    let (repo, dir) = repository_with_index(&key);
    let path = dir.join("beta.json");
    let before = read(&path);

    let later = now() + Duration::days(25);
    let written = index::refresh(&dir, Channel::Beta, later).unwrap();
    assert_eq!((written.path.as_path(), written.seq), (path.as_path(), 2));
    assert_eq!(written.removed_signature, Some(sign::signature_path(&path)));
    let after = read(&path);
    assert_eq!(after.seq, 2);
    assert_eq!(after.generated, later);
    assert_eq!(after.expires, later + Duration::days(30));
    assert_eq!(
        (&after.core, &after.extension, &after.plugins),
        (&before.core, &before.extension, &before.plugins)
    );

    // Signed at that time, it passes the gate against the committed seq 1.
    sign::sign(&path, &key.pair.sk, later).unwrap();
    let checked = index::check(
        &dir,
        &CheckOptions {
            now: later,
            ..options(&key.trusted(), Some("HEAD"))
        },
        None,
    )
    .unwrap();
    assert_eq!((checked[0].seq, checked[0].base_seq), (2, Some(1)));
    assert!(checked[0].new_versions.is_empty());
    drop(repo);

    let empty = tempfile::tempdir().unwrap();
    let result = index::refresh(empty.path(), Channel::Stable, now());
    assert!(error_text(result).contains("stable.json"));
}

#[test]
fn a_signature_without_its_index_is_refused() {
    let key = TestKey::new();
    let dir = tempfile::tempdir().unwrap();
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(dir.path(), TAG, assets.path()).written.path;
    key.sign(&path);
    fs::copy(
        sign::signature_path(&path),
        dir.path().join("stable.json.minisig"),
    )
    .unwrap();
    let result = index::check(dir.path(), &options(&key.trusted(), None), None);
    assert!(error_text(result).contains("has no index beside it"));
}

#[test]
fn a_tracked_secret_key_counts_as_committable() {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    fs::write(repo.path().join(".gitignore"), "/keys/\n").unwrap();
    let secret = repo.path().join("keys").join(sign::SECRET_KEY_FILE);
    fs::create_dir(repo.path().join("keys")).unwrap();
    fs::write(&secret, "not a key").unwrap();
    sign::refuse_committable(&secret).unwrap();
    git(repo.path(), &["add", "--force", "keys"]);
    assert!(error_text(sign::refuse_committable(&secret)).contains("not ignored"));
}

#[test]
fn a_linked_work_tree_is_a_work_tree() {
    let base = tempfile::tempdir().unwrap();
    let repo = base.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "--quiet"]);
    git(
        &repo,
        &["commit", "--quiet", "--allow-empty", "-m", "start"],
    );
    let linked = base.path().join("linked");
    git(
        &repo,
        &["worktree", "add", "--quiet", linked.to_str().unwrap()],
    );
    assert!(linked.join(".git").is_file());
    let result = sign::keygen(&linked.join("keys"), "password");
    assert!(error_text(result).contains("not ignored"));
}

#[test]
fn a_directory_inside_dot_git_is_not_committable() {
    // Nothing under `.git` is committed, and git would call a path there not ignored.
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    let secret = repo
        .path()
        .join(".git")
        .join("oncl-keys")
        .join(sign::SECRET_KEY_FILE);
    sign::refuse_committable(&secret).unwrap();
}

#[test]
fn a_work_tree_git_cannot_discover_is_refused() {
    // A linked work tree whose main repository is gone: git's own discovery dies there,
    // but the directory still belongs to a work tree that could commit the key once the
    // repository is back.
    let base = tempfile::tempdir().unwrap();
    let linked = base.path().join("linked");
    fs::create_dir_all(&linked).unwrap();
    let gone = base.path().join("gone").display().to_string();
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", gone.replace('\\', "/")),
    )
    .unwrap();
    let keys = linked.join("keys");
    let text = error_text(sign::keygen(&keys, "password"));
    assert!(text.contains("check-ignore failed"), "{text}");
    assert!(!keys.join(sign::SECRET_KEY_FILE).exists());
}

#[test]
fn the_directory_is_resolved_before_git_is_asked() {
    let base = tempfile::tempdir().unwrap();
    let repo = base.path().join("repo");
    fs::create_dir_all(repo.join("inside")).unwrap();
    git(&repo, &["init", "--quiet"]);

    // `repo/../keys` is beside the work tree, not in it.
    let beside = repo.join("..").join("keys");
    sign::keygen(&beside, "password").unwrap();
    assert!(
        base.path()
            .join("keys")
            .join(sign::SECRET_KEY_FILE)
            .exists()
    );

    // A link from outside into the work tree.
    let link = base.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(repo.join("inside"), &link).unwrap();
    #[cfg(windows)]
    {
        let status = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(repo.join("inside"))
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J");
    }
    let result = sign::keygen(&link.join("keys"), "password");
    assert!(error_text(result).contains("not ignored"));
}

#[cfg(unix)]
#[test]
fn only_the_owner_reads_the_secret_key() {
    use std::os::unix::fs::PermissionsExt;
    let out = tempfile::tempdir().unwrap();
    let files = sign::keygen(&out.path().join("keys"), "password").unwrap();
    let mode = fs::metadata(&files.secret).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// Tags [`NEXT_TAG`] again on a new commit of `repo` whose update key is `key` (`None`:
/// removed).
fn retag_next(repo: &Repo, key: Option<&str>) {
    let root = repo.repo.path();
    let file = root.join(index::TAG_KEY);
    match key {
        Some(key) => fs::write(&file, key).unwrap(),
        None => fs::remove_file(&file).unwrap(),
    }
    git(root, &["add", "--all", "."]);
    git(root, &["commit", "--quiet", "-m", "another key"]);
    git(root, &["tag", "--force", NEXT_TAG]);
}

#[test]
fn a_version_tagged_without_a_trusted_key_is_refused() {
    let key = TestKey::new();
    let other = TestKey::new();
    for (tag_key, expected) in [
        (None, "has no crates/oncl-update/keys/current.pub"),
        (
            Some("untrusted comment: x\nnot a key\n".to_owned()),
            "is not a minisign public key",
        ),
        (
            Some(other.public_text()),
            "neither current.pub nor next.pub",
        ),
    ] {
        let repo = keyed_repo(&key.public_text());
        retag_next(&repo, tag_key.as_deref());
        let assets = release_assets(TAG, &[Flavor::WinX64], None);
        add(repo.path(), TAG, assets.path());
        let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
        let path = add(repo.path(), NEXT_TAG, assets.path()).written.path;
        key.sign(&path);
        // Against a base without the index: every version is new and gated.
        let result = index::check(repo.path(), &options(&key.trusted(), Some("HEAD")), None);
        let text = error_text(result);
        assert!(
            text.contains(expected) && text.contains("0.2.0-beta.2"),
            "{text}"
        );
    }

    // A tag that is not there at all (not fetched).
    let repo = keyed_repo(&key.public_text());
    let assets = release_assets("v0.3.0", &[Flavor::WinX64], None);
    let path = add(repo.path(), "v0.3.0", assets.path()).written.path;
    key.sign(&path);
    let result = index::check(repo.path(), &options(&key.trusted(), Some("HEAD")), None);
    assert!(error_text(result).contains("there is no tag v0.3.0"));

    // A tag with the next key of a rotation is fine: its clients trust both.
    let keys = tempfile::tempdir().unwrap();
    fs::write(keys.path().join("current.pub"), key.public_text()).unwrap();
    fs::write(keys.path().join("next.pub"), other.public_text()).unwrap();
    let trusted = index::trusted_keys(keys.path()).unwrap();
    let repo = keyed_repo(&key.public_text());
    retag_next(&repo, Some(&other.public_text()));
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let path = add(repo.path(), NEXT_TAG, assets.path()).written.path;
    key.sign(&path);
    index::check(repo.path(), &options(&trusted, Some("HEAD")), None).unwrap();
}

#[test]
fn only_versions_new_against_the_base_need_their_tag() {
    let key = TestKey::new();
    let (repo, dir) = repository_with_index(&key);
    // The tag of the version already published goes; unchanged, it is not looked at again.
    git(repo.path(), &["tag", "--delete", TAG]);
    let path = dir.join("beta.json");
    let mut index = read(&path);
    index.seq = 2;
    index.core[0].rollout = 50;
    fs::write(&path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
    key.sign(&path);
    index::check(&dir, &options(&key.trusted(), Some("HEAD")), None).unwrap();
    // Its packages replaced: looked at, and refused.
    index.seq = 3;
    index.core[0].flavors.values_mut().next().unwrap().full.size += 1;
    fs::write(&path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
    key.sign(&path);
    let result = index::check(&dir, &options(&key.trusted(), Some("HEAD")), None);
    assert!(error_text(result).contains("there is no tag v0.2.0-beta.1"));
}

#[test]
fn indexes_are_published_signed_by_the_current_key_only() {
    let key = TestKey::new();
    let next = TestKey::new();
    let keys = tempfile::tempdir().unwrap();
    fs::write(keys.path().join("current.pub"), key.public_text()).unwrap();
    fs::write(keys.path().join("next.pub"), next.public_text()).unwrap();
    let trusted = index::trusted_keys(keys.path()).unwrap();
    let repo = keyed_repo(&key.public_text());
    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let path = add(repo.path(), TAG, assets.path()).written.path;
    next.sign(&path);
    let result = index::check(repo.path(), &options(&trusted, None), None);
    assert!(error_text(result).contains("does not match any trusted key"));
    key.sign(&path);
    index::check(repo.path(), &options(&trusted, None), None).unwrap();
}

#[test]
fn the_add_command_refuses_a_tag_without_a_trusted_key() {
    let key = TestKey::new();
    let repo = keyed_repo(&key.public_text());
    retag_next(&repo, None);
    let xtask = |tag: &str, assets: &Path| {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["index", "add", "--channel", "beta", "--tag", tag])
            .arg("--release-assets")
            .arg(assets)
            .arg("--dir")
            .arg(repo.path())
            .arg("--keys")
            .arg(key.keys.path())
            .output()
            .unwrap()
    };
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    let refused = xtask(NEXT_TAG, assets.path());
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("has no crates/oncl-update/keys/current.pub"),
        "{stderr}"
    );
    assert!(!repo.path().join("beta.json").exists(), "nothing written");

    let assets = release_assets(TAG, &[Flavor::WinX64], None);
    let added = xtask(TAG, assets.path());
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert_eq!(
        read(&repo.path().join("beta.json")).core[0].version,
        version(TAG)
    );
}

#[test]
fn no_index_published_yet_passes_and_still_reads_the_keys() {
    let key = TestKey::new();
    let repo = keyed_repo(&key.public_text());
    assert!(!repo.path().exists(), "no updates/v1 in the tree");
    for base in [Some("HEAD"), None] {
        let checked = index::check(repo.path(), &options(&key.trusted(), base), None).unwrap();
        assert!(checked.is_empty(), "{base:?}");
    }

    // The command, as the workflows run it on a change of the keys alone.
    let xtask = |keys: &Path, base: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["index", "check"])
            .arg(repo.path())
            .arg("--offline")
            .args(base)
            .arg("--keys")
            .arg(keys)
            .output()
            .unwrap()
    };
    for base in [&["--base", "HEAD"][..], &["--no-base"]] {
        let ok = xtask(key.keys.path(), base);
        let stdout = String::from_utf8_lossy(&ok.stdout);
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        assert!(stdout.contains("no index is published yet"), "{stdout}");
    }
    let broken = tempfile::tempdir().unwrap();
    fs::write(
        broken.path().join("current.pub"),
        "untrusted comment: x\nnot a key\n",
    )
    .unwrap();
    assert!(!xtask(broken.path(), &["--no-base"]).status.success());

    // Relative, as the workflows pass it, from the repository root: `updates/` is not
    // there either.
    let relative = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .current_dir(repo.repo.path())
        .args([
            "index",
            "check",
            "updates/v1",
            "--offline",
            "--base",
            "HEAD",
            "--keys",
        ])
        .arg(key.keys.path())
        .output()
        .unwrap();
    assert!(
        relative.status.success(),
        "{}",
        String::from_utf8_lossy(&relative.stderr)
    );
    assert!(String::from_utf8_lossy(&relative.stdout).contains("no index is published yet"));

    // Once published, the directory may not go.
    let (repo, dir) = repository_with_index(&key);
    fs::remove_dir_all(repo.path().join("updates")).unwrap();
    let result = index::check(&dir, &options(&key.trusted(), Some("HEAD")), None);
    assert!(error_text(result).contains("removed here"));
}

#[test]
fn a_key_rotation_keeps_the_versions_published_before_it() {
    let old = TestKey::new();
    let new = TestKey::new();
    let repo = tempfile::tempdir().unwrap();
    let root = repo.path();
    let dir = root.join("updates").join("v1");
    git(root, &["init", "--quiet"]);
    // v0.1.0: tagged before any update key existed.
    fs::write(root.join("README"), "x").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "start"]);
    git(root, &["tag", "v0.1.0"]);
    // TAG and v0.1.5: built with the old key.
    let key_file = root.join(index::TAG_KEY);
    fs::create_dir_all(key_file.parent().unwrap()).unwrap();
    fs::write(&key_file, old.public_text()).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "old key"]);
    git(root, &["tag", TAG]);
    git(root, &["tag", "v0.1.5"]);
    // Published with the old key: v0.1.0 and TAG.
    for tag in ["v0.1.0", TAG] {
        let assets = release_assets(tag, &[Flavor::WinX64], None);
        add(&dir, tag, assets.path());
    }
    old.sign(&dir.join("beta.json"));
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "index"]);
    // The switch: the new key, NEXT_TAG built with it, the index signed with it.
    fs::write(&key_file, new.public_text()).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "new key"]);
    git(root, &["tag", NEXT_TAG]);
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64], None);
    add(&dir, NEXT_TAG, assets.path());
    new.sign(&dir.join("beta.json"));
    let trusted = new.trusted();

    // Against the base, only NEXT_TAG is new and gated; without a base (a manual Pages run)
    // the gate is not applied to what was published.
    let checked = index::check(&dir, &options(&trusted, Some("HEAD")), None).unwrap();
    assert_eq!(checked[0].new_versions, [version(NEXT_TAG)]);
    index::check(&dir, &options(&trusted, None), None).unwrap();

    // A version with the old key added now is refused.
    let assets = release_assets("v0.1.5", &[Flavor::WinX64], None);
    add(&dir, "v0.1.5", assets.path());
    new.sign(&dir.join("beta.json"));
    let result = index::check(&dir, &options(&trusted, Some("HEAD")), None);
    assert!(
        error_text(result)
            .contains("0.1.5: crates/oncl-update/keys/current.pub of v0.1.5 is neither")
    );
}
