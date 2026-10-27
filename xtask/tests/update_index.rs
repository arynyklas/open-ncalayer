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

    fn trusted(&self) -> Vec<oncl_update::PublicKey> {
        index::trusted_keys(self.keys.path()).unwrap()
    }

    fn sign(&self, index: &Path) {
        sign::sign(index, &self.pair.sk, now()).unwrap();
    }
}

/// The assets of the release `tag`: full packages for `flavors`, the delta of win-x64 when
/// `delta_base` is given (with Velopack's feed naming its base), and the extension.
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

fn options<'a>(keys: &'a [oncl_update::PublicKey], base: Option<&'a str>) -> CheckOptions<'a> {
    CheckOptions {
        keys,
        base,
        vm_smoke: false,
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
        ])
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A git repository whose single commit holds `updates/v1/beta.json` at seq 1, signed.
fn repository_with_index(key: &TestKey) -> (tempfile::TempDir, std::path::PathBuf) {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    let dir = repo.path().join("updates").join("v1");
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
    let dir = tempfile::tempdir().unwrap();
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
        &key.trusted(),
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
    let dir = tempfile::tempdir().unwrap();
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

/// Answers `HEAD` with 200 except for URLs containing `missing`; `vm-smoke` passes for
/// `smoked` tags. Records the tags asked about.
struct FakeRemote {
    missing: Option<&'static str>,
    smoked: &'static [&'static str],
    asked: RefCell<Vec<String>>,
}

impl Remote for FakeRemote {
    fn head(&self, url: &str) -> anyhow::Result<u16> {
        assert!(url.starts_with("https://github.com/arynyklas/open-ncalayer/releases/"));
        Ok(match self.missing {
            Some(m) if url.contains(m) => 404,
            _ => 200,
        })
    }

    fn vm_smoke_passed(&self, tag: &str) -> anyhow::Result<bool> {
        self.asked.borrow_mut().push(tag.to_owned());
        Ok(self.smoked.contains(&tag))
    }
}

#[test]
fn network_checks_go_through_the_remote() {
    let key = TestKey::new();
    let (_repo, dir) = repository_with_index(&key);
    let assets = release_assets(NEXT_TAG, &[Flavor::WinX64, Flavor::Osx], None);
    let path = add(&dir, NEXT_TAG, assets.path()).written.path;
    key.sign(&path);
    let keys = key.trusted();
    let remote = |missing, smoked| FakeRemote {
        missing,
        smoked,
        asked: RefCell::new(Vec::new()),
    };

    let ok = remote(None, &[]);
    index::check(&dir, &options(&keys, Some("HEAD")), Some(&ok)).unwrap();
    assert!(ok.asked.borrow().is_empty(), "vm-smoke is off by default");

    let missing = remote(Some("osx-full"), &[]);
    let result = index::check(&dir, &options(&keys, Some("HEAD")), Some(&missing));
    assert!(error_text(result).contains("answered 404"));

    let gated = CheckOptions {
        vm_smoke: true,
        ..options(&keys, Some("HEAD"))
    };
    let unsmoked = remote(None, &[TAG]);
    let result = index::check(&dir, &gated, Some(&unsmoked));
    assert!(error_text(result).contains("vm-smoke"));
    let smoked = remote(None, &[NEXT_TAG]);
    index::check(&dir, &gated, Some(&smoked)).unwrap();
    // Only the version new against the base is asked about.
    assert_eq!(*smoked.asked.borrow(), [NEXT_TAG]);

    let result = index::check(&dir, &gated, None);
    assert!(error_text(result).contains("needs the network"));
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

    let dir = tempfile::tempdir().unwrap();
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
