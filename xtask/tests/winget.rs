//! The WinGet manifest generator against SYNTHETIC fixtures.
//!
//! Everything here is made by this test: the "release" is a JSON object shaped like GitHub's, the
//! "installers" are minimal PE images carrying a payload in the format of the real entry, the
//! "probe reports" are what a proof run would write, with made-up identity values. None of it
//! is a published release and none of it was installed on a machine: no stable release of
//! OpenNCALayer exists yet, and the machines of the matrix are an external prerequisite
//! (`docs/dev/winget.md`). What is real here is the generator and checker code, the real
//! downloader streaming from a local server, the pinned schemas and (in the ignored test) the
//! real `winget validate`.

mod upstream_common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use oncl_update::Version;
use oncl_winget_setup::payload::{self, Arch as PayloadArch};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use upstream_common::{MockServer, Response};
use xtask::upstream::http::Fetcher;
use xtask::winget::download::{AssetError, AssetFetch, Downloaded, Https};
use xtask::winget::ledger::{HashChanged, Ledger};
use xtask::winget::manifest::{self, Mode};
use xtask::winget::probe::ProbeError;
use xtask::winget::release::ReleaseError;
use xtask::winget::schema::{self, Kind};
use xtask::winget::yaml;
use xtask::winget::{Arch, Generated, Request, generate};

/// An edit of a release object.
type Mutation = Box<dyn Fn(&mut Value)>;
/// An edit of a manifest text.
type TextEdit = Box<dyn Fn(&str) -> String>;

const VERSION: &str = "0.3.0";
/// A newer release the program updated itself to (synthetic).
const NEWER: &str = "0.4.0";
const PUBLISHED_AT: &str = "2026-11-09T10:00:00Z";
const RECORDED_AT: &str = "2026-11-10T12:00:00Z";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

const fn payload_arch(arch: Arch) -> PayloadArch {
    match arch {
        Arch::X64 => PayloadArch::X64,
        Arch::X86 => PayloadArch::X86,
    }
}

/// A PE image of one section; with `certificates` bytes of certificate table at its end.
fn pe(arch: Arch, section: &[u8], certificates: Option<usize>) -> Vec<u8> {
    let pe_at = 0x80usize;
    let optional_size = 0xf0usize;
    let headers = 0x200usize;
    let machine: u16 = match arch {
        Arch::X64 => 0x8664,
        Arch::X86 => 0x014c,
    };
    let mut image = vec![0u8; headers];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(pe_at as u32).to_le_bytes());
    image[pe_at..pe_at + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_at + 4;
    image[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
    let optional = coff + 20;
    image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&(headers as u32).to_le_bytes());
    image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let table = optional + optional_size;
    image[table + 16..table + 20].copy_from_slice(&(section.len() as u32).to_le_bytes());
    image[table + 20..table + 24].copy_from_slice(&(headers as u32).to_le_bytes());
    image.extend_from_slice(section);
    if let Some(size) = certificates {
        while !image.len().is_multiple_of(8) {
            image.push(0);
        }
        let offset = image.len() as u32;
        let entry = optional + 112 + 4 * 8;
        image[entry..entry + 4].copy_from_slice(&offset.to_le_bytes());
        image[entry + 4..entry + 8].copy_from_slice(&(size as u32).to_le_bytes());
        image.extend(std::iter::repeat_n(0xAB, size));
    }
    image
}

/// A synthetic installer entry: the unsigned entry with a payload of `version`, then (when
/// `signed`) a certificate table written after it, as Authenticode does.
fn installer(arch: Arch, version: &str, signed: bool) -> Vec<u8> {
    let version = Version::parse(version).unwrap();
    let image = pe(arch, &[1; 64], None);
    let setup = pe(arch, &[7; 2048], None);
    let mut entry = payload::append(&image, &setup, &version, payload_arch(arch)).unwrap();
    if signed {
        // The certificate table after the footer, its data directory pointing at it.
        while !entry.len().is_multiple_of(8) {
            entry.push(0);
        }
        let offset = entry.len() as u32;
        let at = 0x80 + 4 + 20 + 112 + 4 * 8;
        entry[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        entry[at + 4..at + 8].copy_from_slice(&64u32.to_le_bytes());
        entry.extend(std::iter::repeat_n(0xCD, 64));
    }
    entry
}

fn asset_name(version: &str, arch: Arch) -> String {
    format!("openncalayer-{version}-win-{arch}-winget-setup.exe")
}

fn asset_path(version: &str, arch: Arch) -> String {
    format!(
        "/arynyklas/OpenNCALayer/releases/download/v{version}/{}",
        asset_name(version, arch)
    )
}

/// The published bytes of the synthetic release.
struct Published {
    x64: Vec<u8>,
    x86: Vec<u8>,
}

impl Published {
    fn new() -> Published {
        Published {
            x64: installer(Arch::X64, VERSION, true),
            x86: installer(Arch::X86, VERSION, true),
        }
    }

    fn bytes(&self, arch: Arch) -> &[u8] {
        match arch {
            Arch::X64 => &self.x64,
            Arch::X86 => &self.x86,
        }
    }
}

/// A release object shaped like GitHub's; `mutate` changes it before it is serialized.
fn release_value(published: &Published) -> Value {
    let assets: Vec<Value> = [Arch::X64, Arch::X86]
        .iter()
        .map(|arch| {
            let name = asset_name(VERSION, *arch);
            json!({
                "name": name,
                "state": "uploaded",
                "size": published.bytes(*arch).len(),
                "digest": format!("sha256:{}", sha256(published.bytes(*arch))),
                "browser_download_url": format!(
                    "https://github.com/arynyklas/OpenNCALayer/releases/download/v{VERSION}/{name}"
                ),
            })
        })
        .collect();
    json!({
        "tag_name": format!("v{VERSION}"),
        "draft": false,
        "prerelease": false,
        "published_at": PUBLISHED_AT,
        "assets": assets,
    })
}

/// One cell of a synthetic probe set.
fn cell(
    published: &Published,
    candidate_sha: &str,
    arch: Arch,
    windows: u32,
    build: u32,
    os_arch: Arch,
    account: &str,
) -> Value {
    let step = |winget: i32| {
        json!({
            "winget_exit_code": winget,
            "installer_exit_code": 0,
            "postcondition_verified_after_exit": true,
            "arp_display_version": VERSION,
            "program_version": VERSION,
        })
    };
    json!({
        "synthetic": true,
        "run": { "vm_id": format!("synthetic-{arch}-{windows}-{account}"), "script_sha256": "ab".repeat(32) },
        "package_version": VERSION,
        "recorded_at": RECORDED_AT,
        "installer": {
            "asset_name": asset_name(VERSION, arch),
            "url": format!(
                "https://github.com/arynyklas/OpenNCALayer/releases/download/v{VERSION}/{}",
                asset_name(VERSION, arch)
            ),
            "arch": arch.to_string(),
            "sha256": sha256(published.bytes(arch)),
            "size": published.bytes(arch).len(),
            "authenticode": {
                "status": "valid",
                "signer_subject": "CN=Synthetic Fixture Publisher",
                "signer_thumbprint": "0123456789abcdef0123456789abcdef01234567",
                "timestamped": true,
            },
        },
        "environment": {
            "windows": windows,
            "build": build,
            "os_arch": os_arch.to_string(),
            "account": account,
            "host": "vm",
            "clean_image": true,
            "profile_belongs_to_account_sid": true,
            "winget_version": "synthetic",
        },
        "tested_switches": {
            "winget_flags": ["--manifest", "--architecture", "--silent", "--accept-package-agreements"],
            "winget_architecture": arch.to_string(),
            "silent_argv": ["--silent"],
            "silent_with_progress_argv": ["--silent"],
        },
        "tested_manifest": {
            "manifest_version": "1.12.0",
            "installer_yaml_sha256": candidate_sha,
        },
        "identity": {
            "arp_key_name": "SyntheticKey",
            "display_name": "Synthetic Display Name",
            "publisher": "Synthetic Publisher",
            "display_version": VERSION,
            "program_version": VERSION,
            "package_manifest_version": VERSION,
            "program_arch": arch.to_string(),
            "install_location_in_account_profile": true,
            "uninstall_runs_update_exe": true,
        },
        "prerequisite_free": {
            "no_redistributable_on_image": true,
            "installed_without_prerequisite_step": true,
        },
        "lifecycle": {
            "install": step(0),
            "upgrade": {
                "from_version": "0.2.0",
                "result": step(0),
                "user_data_preserved": true,
            },
            "reinstall": step(0),
            "uninstall": {
                "winget_exit_code": 0,
                "arp_entry_removed": true,
                "install_directory_removed": true,
            },
            "self_update": {
                "start_version": VERSION,
                "arp_display_version": NEWER,
                "program_version": NEWER,
                "newer_release_tested": true,
                "winget_exit_code": -1_978_335_189i64,
                "winget_installer_ran": false,
                "no_downgrade_loop": true,
            },
        },
        "safety": {
            "elevated": {
                "exit_code": 8,
                "no_artifacts_in_any_profile": true,
                "other_credentials_install_refused": true,
            },
            "signing_hold": {
                "busy_exit_code": 4,
                "signature_completed_correctly": true,
                "installation_unchanged": true,
            },
            "no_ca_trust_added": true,
            "http_api_stayed_disabled": true,
        },
    })
}

/// The whole matrix: both installers, Windows 10 and 11, standard and admin accounts; the x86
/// installer on a 32-bit Windows 10 and on 64-bit Windows 11.
fn probe_value(published: &Published, candidate_sha: &str, origin: &str) -> Value {
    let mut reports = Vec::new();
    for account in ["standard", "admin_non_elevated"] {
        for (arch, windows, build, os_arch) in [
            (Arch::X64, 10, 19045, Arch::X64),
            (Arch::X64, 11, 22631, Arch::X64),
            (Arch::X86, 10, 19045, Arch::X86),
            (Arch::X86, 11, 22631, Arch::X64),
        ] {
            reports.push(cell(
                published,
                candidate_sha,
                arch,
                windows,
                build,
                os_arch,
                account,
            ));
        }
    }
    let synthetic = origin == "synthetic-fixture";
    for report in &mut reports {
        report["synthetic"] = json!(synthetic);
    }
    let final_sha = final_digest(published, synthetic);
    let final_cells: Vec<Value> = [Arch::X64, Arch::X86]
        .iter()
        .map(|arch| {
            json!({
                "installer_arch": arch.to_string(),
                "windows": 11,
                "manifest_files_sha256": final_sha,
                "install_exit_code": 0,
                "upgrade_exit_code": 0,
                "upgrade_from_version": "0.2.0",
                "arp_display_version_after_upgrade": VERSION,
                "upgrade_correlated_installed_entry": true,
                "uninstall_exit_code": 0,
                "uninstall_removed_entry": true,
            })
        })
        .collect();
    json!({
        "report_format": 1,
        "origin": origin,
        "attestation": { "attested_by": "synthetic fixture", "run_id": "synthetic-run" },
        "reports": reports,
        "final_cells": final_cells,
    })
}

/// The digest of the three files the generator makes for the synthetic identity.
fn final_digest(published: &Published, synthetic: bool) -> String {
    let release = xtask::winget::release::parse(&release_value(published).to_string())
        .unwrap()
        .stable()
        .unwrap();
    let identity = xtask::winget::probe::ArpIdentity {
        key_name: "SyntheticKey".to_owned(),
        display_name: "Synthetic Display Name".to_owned(),
        publisher: "Synthetic Publisher".to_owned(),
        display_version: Version::parse(VERSION).unwrap(),
    };
    let hashes = [Arch::X64, Arch::X86].map(|a| (a, sha256(published.bytes(a))));
    let files = manifest::render(&manifest::Plan {
        release: &release,
        sha256: &hashes,
        identity: Some(&identity),
        synthetic,
    });
    manifest::files_digest(
        &files
            .iter()
            .map(|(n, t)| (n.clone(), t.clone().into_bytes()))
            .collect::<Vec<_>>(),
    )
}

/// A local server of the published files and the downloader that reaches it as if it were
/// `https://github.com`.
struct Rig {
    _server: MockServer,
    fetch: Mapped,
    requests: std::sync::Arc<AtomicUsize>,
}

struct Mapped {
    port: u16,
    https: Https,
    requests: std::sync::Arc<AtomicUsize>,
}

impl AssetFetch for Mapped {
    fn fetch(&self, url: &str, limit: u64, dest: &Path) -> anyhow::Result<Downloaded> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let local = url
            .strip_prefix("https://github.com")
            .map(|rest| format!("http://127.0.0.1:{}{rest}", self.port))
            .unwrap_or_else(|| panic!("{url} is not a github.com URL"));
        self.https.fetch(&local, limit, dest)
    }
}

impl Rig {
    fn new(served: &[(String, Vec<u8>)]) -> Rig {
        let server = MockServer::start();
        for (path, bytes) in served {
            server.route("GET", path, Response::ok(bytes.clone()));
        }
        let requests = std::sync::Arc::new(AtomicUsize::new(0));
        let fetch = Mapped {
            port: server.port,
            https: Https::with(Fetcher::for_tests()),
            requests: requests.clone(),
        };
        Rig {
            _server: server,
            fetch,
            requests,
        }
    }

    fn of(published: &Published) -> Rig {
        Rig::new(&[
            (asset_path(VERSION, Arch::X64), published.x64.clone()),
            (asset_path(VERSION, Arch::X86), published.x86.clone()),
        ])
    }

    fn downloads(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Run {
        Run {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn out(&self) -> PathBuf {
        self.dir.path().join("manifest")
    }

    fn evidence(&self) -> PathBuf {
        self.dir.path().join("evidence.json")
    }

    fn generate(
        &self,
        rig: &Rig,
        release: &Value,
        probe: Option<&Value>,
        ledger: &Ledger,
        allow_synthetic: bool,
    ) -> anyhow::Result<Generated> {
        let release = release.to_string();
        let probe = probe.map(Value::to_string);
        generate(
            &Request {
                release_json: &release,
                probe_json: probe.as_deref(),
                ledger,
                allow_synthetic,
                final_proof_pending: false,
                out: &self.out(),
                evidence: &self.evidence(),
            },
            &rig.fetch,
        )
    }
}

/// Runs the candidate stage and gives its `installer.yaml` hash, as a proof run's script would
/// compute it over the file.
fn candidate_sha(published: &Published) -> String {
    let run = Run::new();
    let rig = Rig::of(published);
    let done = run
        .generate(
            &rig,
            &release_value(published),
            None,
            &Ledger::default(),
            false,
        )
        .expect("the candidate of a good release");
    let text = std::fs::read(run.out().join("arynyklas.OpenNCALayer.installer.yaml")).unwrap();
    assert_eq!(done.evidence.candidate_installer_yaml_sha256, sha256(&text));
    sha256(&text)
}

fn error_of<E: std::error::Error + Send + Sync + 'static>(result: anyhow::Result<Generated>) -> E {
    match result {
        Ok(_) => panic!("a manifest was made where it must be refused"),
        Err(e) => e
            .downcast::<E>()
            .unwrap_or_else(|e| panic!("another error than expected: {e:#}")),
    }
}

fn final_manifest(published: &Published) -> (Run, Generated) {
    let candidate = candidate_sha(published);
    let run = Run::new();
    let rig = Rig::of(published);
    let probe = probe_value(published, &candidate, "synthetic-fixture");
    let done = run
        .generate(
            &rig,
            &release_value(published),
            Some(&probe),
            &Ledger::default(),
            true,
        )
        .expect("the manifest of a fully proven synthetic release");
    (run, done)
}

// ---------------------------------------------------------------------------------------------
// The plan's named tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn prerelease_and_draft_rejected() {
    let published = Published::new();
    let cases: Vec<(&str, Mutation, ReleaseError)> = vec![
        (
            "a draft",
            Box::new(|r| r["draft"] = json!(true)),
            ReleaseError::Draft,
        ),
        (
            "a pre-release flag on a stable tag",
            Box::new(|r| r["prerelease"] = json!(true)),
            ReleaseError::Prerelease,
        ),
        (
            "an alpha tag with the flag cleared",
            Box::new(|r| r["tag_name"] = json!("v0.3.0-alpha.1")),
            ReleaseError::TagNotStable("v0.3.0-alpha.1".to_owned()),
        ),
        (
            "a beta tag",
            Box::new(|r| r["tag_name"] = json!("v0.3.0-beta.2")),
            ReleaseError::TagNotStable("v0.3.0-beta.2".to_owned()),
        ),
        (
            "a tag with build metadata",
            Box::new(|r| r["tag_name"] = json!("v0.3.0+build.5")),
            ReleaseError::TagNotStable("v0.3.0+build.5".to_owned()),
        ),
        (
            "a branch name for a tag",
            Box::new(|r| r["tag_name"] = json!("latest")),
            ReleaseError::TagNotStable("latest".to_owned()),
        ),
        (
            "an unpublished release",
            Box::new(|r| r["published_at"] = Value::Null),
            ReleaseError::NotPublished,
        ),
    ];
    for (what, mutate, expected) in cases {
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut release = release_value(&published);
        mutate(&mut release);
        let error =
            error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert_eq!(error, expected, "{what}");
        // A refused release downloads nothing and leaves nothing.
        assert_eq!(
            rig.downloads(),
            0,
            "{what}: a refused release was downloaded"
        );
        assert!(!run.out().exists(), "{what}: a manifest directory exists");
        assert!(!run.evidence().exists(), "{what}: evidence exists");
    }
}

#[test]
fn mutable_latest_urls_and_foreign_assets_are_rejected_before_any_download() {
    let published = Published::new();
    let latest = format!(
        "https://github.com/arynyklas/OpenNCALayer/releases/latest/download/{}",
        asset_name(VERSION, Arch::X64)
    );
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "a latest URL",
            Box::new(move |r| r["assets"][0]["browser_download_url"] = json!(latest.clone())),
        ),
        (
            "another repository",
            Box::new(|r| {
                r["assets"][1]["browser_download_url"] = json!(format!(
                    "https://github.com/someone/else/releases/download/v{VERSION}/{}",
                    asset_name(VERSION, Arch::X86)
                ));
            }),
        ),
        (
            "plain http",
            Box::new(|r| {
                r["assets"][0]["browser_download_url"] = json!(format!(
                    "http://github.com/arynyklas/OpenNCALayer/releases/download/v{VERSION}/{}",
                    asset_name(VERSION, Arch::X64)
                ));
            }),
        ),
        (
            "another tag's URL",
            Box::new(|r| {
                r["assets"][0]["browser_download_url"] = json!(format!(
                    "https://github.com/arynyklas/OpenNCALayer/releases/download/v0.2.0/{}",
                    asset_name(VERSION, Arch::X64)
                ));
            }),
        ),
        (
            "a query string",
            Box::new(|r| {
                let url = r["assets"][0]["browser_download_url"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                r["assets"][0]["browser_download_url"] = json!(format!("{url}?x=1"));
            }),
        ),
    ];
    for (what, mutate) in cases {
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut release = release_value(&published);
        mutate(&mut release);
        let error =
            error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert!(
            matches!(error, ReleaseError::UrlNotVersionSpecific { .. }),
            "{what}: {error}"
        );
        assert_eq!(rig.downloads(), 0, "{what}");
    }

    // A WinGet installer of another version or flavor attached to the release, an asset
    // missing, one twice, one not uploaded, one empty, a digest that is not sha256.
    let extra = |name: &str| {
        let mut release = release_value(&published);
        let mut asset = release["assets"][0].clone();
        asset["name"] = json!(name);
        release["assets"].as_array_mut().unwrap().push(asset);
        release
    };
    let rig = Rig::of(&published);
    let run = Run::new();
    for name in [
        "openncalayer-0.2.0-win-x64-winget-setup.exe",
        "openncalayer-0.3.0-win7-x64-winget-setup.exe",
        "openncalayer-0.3.0-win-arm64-winget-setup.exe",
    ] {
        let error = error_of::<ReleaseError>(run.generate(
            &rig,
            &extra(name),
            None,
            &Ledger::default(),
            false,
        ));
        assert_eq!(error, ReleaseError::ForeignAsset(name.to_owned()));
    }
    let mut release = release_value(&published);
    release["assets"].as_array_mut().unwrap().remove(1);
    assert_eq!(
        error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false)),
        ReleaseError::AssetMissing(asset_name(VERSION, Arch::X86))
    );
    let mut release = release_value(&published);
    let again = release["assets"][0].clone();
    release["assets"].as_array_mut().unwrap().push(again);
    assert_eq!(
        error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false)),
        ReleaseError::AssetDuplicated(asset_name(VERSION, Arch::X64))
    );
    let mut release = release_value(&published);
    release["assets"][0]["state"] = json!("starter");
    assert!(matches!(
        error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false)),
        ReleaseError::AssetNotUploaded { .. }
    ));
    let mut release = release_value(&published);
    release["assets"][0]["size"] = json!(0);
    assert!(matches!(
        error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false)),
        ReleaseError::AssetEmpty(_)
    ));
    let mut release = release_value(&published);
    release["assets"][1]["digest"] = json!("md5:abcdef");
    assert!(matches!(
        error_of::<ReleaseError>(run.generate(&rig, &release, None, &Ledger::default(), false)),
        ReleaseError::DigestMalformed(_)
    ));
    assert_eq!(rig.downloads(), 0);
}

#[test]
fn asset_hash_or_flavor_mismatch_rejected() {
    let published = Published::new();
    let ok_release = release_value(&published);

    // The API digest is only an expected value: bytes that hash differently end the run.
    {
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut release = ok_release.clone();
        release["assets"][0]["digest"] = json!(format!("sha256:{}", sha256(b"something else")));
        let error =
            error_of::<AssetError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert!(
            matches!(error, AssetError::DigestMismatch { .. }),
            "{error}"
        );
        assert!(!run.out().exists());
    }
    // The size the API reports is not the size that arrived.
    {
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut release = ok_release.clone();
        release["assets"][1]["size"] = json!(published.x86.len() + 1);
        let error =
            error_of::<AssetError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert!(matches!(error, AssetError::SizeMismatch { .. }), "{error}");
    }
    // The x86 asset is the x64 entry: right name, wrong flavor.
    {
        let rig = Rig::new(&[
            (asset_path(VERSION, Arch::X64), published.x64.clone()),
            (asset_path(VERSION, Arch::X86), published.x64.clone()),
        ]);
        let run = Run::new();
        let mut release = ok_release.clone();
        release["assets"][1]["digest"] = json!(format!("sha256:{}", sha256(&published.x64)));
        release["assets"][1]["size"] = json!(published.x64.len());
        let error =
            error_of::<AssetError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert!(
            matches!(error, AssetError::NotTheInstaller { .. }),
            "{error}"
        );
    }
    // The entry of another version under this version's name.
    {
        let old = installer(Arch::X64, "0.2.0", true);
        let rig = Rig::new(&[
            (asset_path(VERSION, Arch::X64), old.clone()),
            (asset_path(VERSION, Arch::X86), published.x86.clone()),
        ]);
        let run = Run::new();
        let mut release = ok_release.clone();
        release["assets"][0]["digest"] = json!(format!("sha256:{}", sha256(&old)));
        release["assets"][0]["size"] = json!(old.len());
        let error =
            error_of::<AssetError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert!(
            matches!(error, AssetError::NotTheInstaller { .. }),
            "{error}"
        );
    }
    // Not an installer at all.
    {
        let junk = b"<html>not found</html>".to_vec();
        let rig = Rig::new(&[
            (asset_path(VERSION, Arch::X64), junk.clone()),
            (asset_path(VERSION, Arch::X86), published.x86.clone()),
        ]);
        let run = Run::new();
        let mut release = ok_release.clone();
        release["assets"][0]["digest"] = json!(format!("sha256:{}", sha256(&junk)));
        release["assets"][0]["size"] = json!(junk.len());
        let error =
            error_of::<AssetError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert!(
            matches!(error, AssetError::NotTheInstaller { .. }),
            "{error}"
        );
    }
    // An unsigned final file: the signature is part of what is published.
    {
        let unsigned = installer(Arch::X64, VERSION, false);
        let rig = Rig::new(&[
            (asset_path(VERSION, Arch::X64), unsigned.clone()),
            (asset_path(VERSION, Arch::X86), published.x86.clone()),
        ]);
        let run = Run::new();
        let mut release = ok_release.clone();
        release["assets"][0]["digest"] = json!(format!("sha256:{}", sha256(&unsigned)));
        release["assets"][0]["size"] = json!(unsigned.len());
        let error =
            error_of::<AssetError>(run.generate(&rig, &release, None, &Ledger::default(), false));
        assert_eq!(error, AssetError::NotSigned(asset_name(VERSION, Arch::X64)));
    }
    // A download that fails or is larger than the release says leaves nothing.
    {
        let rig = Rig::new(&[(asset_path(VERSION, Arch::X64), published.x64.clone())]);
        let run = Run::new();
        assert!(
            run.generate(&rig, &ok_release, None, &Ledger::default(), false)
                .is_err()
        );
        assert!(!run.out().exists());
    }
    // The probe ran other bytes than the ones published (the file was replaced after the run).
    {
        let candidate = candidate_sha(&published);
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut probe = probe_value(&published, &candidate, "synthetic-fixture");
        probe["reports"][0]["installer"]["sha256"] =
            json!(sha256(b"the file before it was replaced"));
        let error = error_of::<ProbeError>(run.generate(
            &rig,
            &ok_release,
            Some(&probe),
            &Ledger::default(),
            true,
        ));
        assert!(
            matches!(error, ProbeError::NotThePublishedFile(_)),
            "{error}"
        );
        assert!(!run.out().exists());
    }
    // A version submitted before may not come back with other bytes.
    {
        let rig = Rig::of(&published);
        let run = Run::new();
        let ledger = Ledger::entry(
            VERSION,
            &[
                (Arch::X64, sha256(&published.x64)),
                (Arch::X86, sha256(b"the hash submitted before")),
            ],
        );
        let error = error_of::<HashChanged>(run.generate(&rig, &ok_release, None, &ledger, false));
        assert_eq!(error.arch, Arch::X86);
        assert_eq!(error.now, sha256(&published.x86));
        assert!(!run.out().exists());
        // The same bytes under the same version are fine.
        let same = Ledger::entry(
            VERSION,
            &[
                (Arch::X64, sha256(&published.x64)),
                (Arch::X86, sha256(&published.x86)),
            ],
        );
        run.generate(&rig, &ok_release, None, &same, false).unwrap();
    }
}

#[test]
fn arp_version_mapping_must_be_proven() {
    let published = Published::new();
    let candidate = candidate_sha(&published);
    let refused = |mutate: &dyn Fn(&mut Value), allow: bool| -> ProbeError {
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut probe = probe_value(&published, &candidate, "synthetic-fixture");
        mutate(&mut probe);
        let error = error_of::<ProbeError>(run.generate(
            &rig,
            &release_value(&published),
            Some(&probe),
            &Ledger::default(),
            allow,
        ));
        assert!(
            !run.out().exists(),
            "a refused probe left a manifest: {error}"
        );
        error
    };

    // The Apps & Features version is not the package version.
    assert!(matches!(
        refused(
            &|p| p["reports"][3]["identity"]["display_version"] = json!("0.3.1"),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    // The program or the installation's own manifest says another version.
    assert!(matches!(
        refused(
            &|p| p["reports"][2]["identity"]["program_version"] = json!("0.2.9"),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][1]["identity"]["package_manifest_version"] = json!("0.3.1"),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    // No key, name or publisher.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["identity"]["arp_key_name"] = json!(" "),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    // The cells do not describe one entry.
    assert!(matches!(
        refused(
            &|p| p["reports"][5]["identity"]["publisher"] = json!("Someone Else"),
            true
        ),
        ProbeError::Inconsistent(_)
    ));
    // The entry is another architecture's, or not per-user, or uninstalls something else.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["identity"]["program_arch"] = json!("x86"),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["identity"]["install_location_in_account_profile"] = json!(false),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["identity"]["uninstall_runs_update_exe"] = json!(false),
            true
        ),
        ProbeError::ArpMapping(_)
    ));
    // A field that is not there at all is not "proven by default".
    assert!(matches!(
        refused(
            &|p| {
                p["reports"][0]["identity"]
                    .as_object_mut()
                    .unwrap()
                    .remove("display_version");
            },
            true
        ),
        ProbeError::Malformed(_)
    ));
    assert!(matches!(
        refused(
            &|p| {
                p["reports"][0].as_object_mut().unwrap().remove("lifecycle");
            },
            true
        ),
        ProbeError::Malformed(_)
    ));
    // A field nobody asked for is not tolerated either.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["identity"]["note"] = json!("trust me"),
            true
        ),
        ProbeError::Malformed(_)
    ));
}

#[test]
fn a_probe_that_proves_less_than_everything_is_refused() {
    let published = Published::new();
    let candidate = candidate_sha(&published);
    let refused = |mutate: &dyn Fn(&mut Value), allow: bool, origin: &str| -> ProbeError {
        let rig = Rig::of(&published);
        let run = Run::new();
        let mut probe = probe_value(&published, &candidate, origin);
        mutate(&mut probe);
        let error = error_of::<ProbeError>(run.generate(
            &rig,
            &release_value(&published),
            Some(&probe),
            &Ledger::default(),
            allow,
        ));
        assert!(!run.out().exists());
        error
    };
    let synth = "synthetic-fixture";

    // A synthetic report is not a real run unless the caller says so.
    assert_eq!(refused(&|_| {}, false, synth), ProbeError::Synthetic);

    // Signing state.
    for status in [
        "not_signed",
        "hash_mismatch",
        "not_trusted",
        "unknown_error",
    ] {
        assert!(
            matches!(
                refused(
                    &|p| p["reports"][0]["installer"]["authenticode"]["status"] = json!(status),
                    true,
                    synth
                ),
                ProbeError::Unsigned(_)
            ),
            "{status}"
        );
    }
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["installer"]["authenticode"]["timestamped"] = json!(false),
            true,
            synth
        ),
        ProbeError::Unsigned(_)
    ));
    // Switches: exactly `--silent`, never the generic `/S` of other installers, nothing extra.
    for argv in [
        json!(["/S"]),
        json!(["--silent", "--force"]),
        json!([]),
        json!(["--SILENT"]),
    ] {
        assert!(
            matches!(
                refused(
                    &|p| p["reports"][4]["tested_switches"]["silent_argv"] = argv.clone(),
                    true,
                    synth
                ),
                ProbeError::Switches(_)
            ),
            "{argv}"
        );
        assert!(
            matches!(
                refused(
                    &|p| p["reports"][4]["tested_switches"]["silent_with_progress_argv"] =
                        argv.clone(),
                    true,
                    synth
                ),
                ProbeError::Switches(_)
            ),
            "{argv}"
        );
    }
    for flag in [
        "--force",
        "--ignore-security-hash",
        "--override",
        "--custom",
    ] {
        assert!(
            matches!(
                refused(
                    &|p| p["reports"][0]["tested_switches"]["winget_flags"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!(flag)),
                    true,
                    synth
                ),
                ProbeError::Switches(_)
            ),
            "{flag}"
        );
    }
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["tested_switches"]["winget_flags"] = json!(["--silent"]),
            true,
            synth
        ),
        ProbeError::Switches(_)
    ));
    // The manifest that was tested is not the one the generator makes.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["tested_manifest"]["installer_yaml_sha256"] =
                json!(sha256(b"another manifest")),
            true,
            synth
        ),
        ProbeError::ManifestNotTested(_)
    ));
    // Prerequisites.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["prerequisite_free"]["installed_without_prerequisite_step"] =
                json!(false),
            true,
            synth
        ),
        ProbeError::Prerequisite(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["environment"]["clean_image"] = json!(false),
            true,
            synth
        ),
        ProbeError::Environment(_)
    ));
    // After the native exit: a zero code alone proves nothing.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["install"]["postcondition_verified_after_exit"] =
                json!(false),
            true,
            synth
        ),
        ProbeError::Postcondition(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["upgrade"]["result"]["arp_display_version"] =
                json!("0.2.0"),
            true,
            synth
        ),
        ProbeError::Postcondition(_)
    ));
    // Lifecycle and safety.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["reinstall"]["installer_exit_code"] = json!(7),
            true,
            synth
        ),
        ProbeError::Lifecycle(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["upgrade"]["user_data_preserved"] = json!(false),
            true,
            synth
        ),
        ProbeError::Lifecycle(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["upgrade"]["from_version"] = json!("0.3.0"),
            true,
            synth
        ),
        ProbeError::Lifecycle(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["self_update"]["no_downgrade_loop"] = json!(false),
            true,
            synth
        ),
        ProbeError::Lifecycle(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["lifecycle"]["uninstall"]["arp_entry_removed"] = json!(false),
            true,
            synth
        ),
        ProbeError::Lifecycle(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["safety"]["elevated"]["exit_code"] = json!(0),
            true,
            synth
        ),
        ProbeError::Safety(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["safety"]["signing_hold"]["signature_completed_correctly"] =
                json!(false),
            true,
            synth
        ),
        ProbeError::Safety(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["safety"]["no_ca_trust_added"] = json!(false),
            true,
            synth
        ),
        ProbeError::Safety(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["safety"]["http_api_stayed_disabled"] = json!(false),
            true,
            synth
        ),
        ProbeError::Safety(_)
    ));
    // The machine.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["environment"]["profile_belongs_to_account_sid"] = json!(false),
            true,
            synth
        ),
        ProbeError::Environment(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["environment"]["build"] = json!(17134),
            true,
            synth
        ),
        ProbeError::Environment(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["recorded_at"] = json!("2026-11-01T00:00:00Z"),
            true,
            synth
        ),
        ProbeError::NotThePublishedFile(_)
    ));
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["package_version"] = json!("0.3.1"),
            true,
            synth
        ),
        ProbeError::NotThePublishedFile(_)
    ));
    // A matrix with a hole is no proof: drop every standard-account cell of Windows 11.
    assert!(matches!(
        refused(
            &|p| {
                p["reports"].as_array_mut().unwrap().retain(|r| {
                    !(r["environment"]["windows"] == 11
                        && r["environment"]["account"] == "standard")
                });
            },
            true,
            synth
        ),
        ProbeError::Coverage(_)
    ));
    // No 32-bit Windows for the x86 installer.
    assert!(matches!(
        refused(
            &|p| {
                p["reports"].as_array_mut().unwrap().retain(|r| {
                    !(r["installer"]["arch"] == "x86" && r["environment"]["os_arch"] == "x86")
                });
            },
            true,
            synth
        ),
        ProbeError::Coverage(_)
    ));
    assert!(matches!(
        refused(&|p| p["reports"] = json!([]), true, synth),
        ProbeError::Coverage(_)
    ));
    // A cell that ran other bytes than the published ones.
    assert!(matches!(
        refused(
            &|p| p["reports"][0]["installer"]["sha256"] = json!("0".repeat(64)),
            true,
            synth
        ),
        ProbeError::NotThePublishedFile(_)
    ));
    // Another format.
    assert!(matches!(
        refused(&|p| p["report_format"] = json!(2), true, synth),
        ProbeError::Malformed(_)
    ));
}

// ---------------------------------------------------------------------------------------------
// What is written.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fully_proven_synthetic_release_gives_a_manifest_that_passes_the_pinned_schemas() {
    let published = Published::new();
    let (run, done) = final_manifest(&published);
    assert_eq!(done.mode, Mode::Fixture);
    assert!(done.evidence.synthetic);
    assert!(!done.evidence.submitted);
    assert!(done.evidence.reasons.join(" ").contains("synthetic"));

    // Read back from disk like any consumer would.
    let checked = manifest::check_dir(&run.out(), Mode::Fixture).unwrap();
    assert_eq!(checked.version, VERSION);
    // The hashes in the manifest are those of the bytes the server served, not of anything else.
    for (arch, url, sha) in &checked.installers {
        assert_eq!(*sha, sha256(published.bytes(*arch)).to_ascii_uppercase());
        assert!(url.ends_with(&asset_name(VERSION, *arch)));
    }
    // Each file validates against its own pinned schema.
    for (name, kind) in [
        ("arynyklas.OpenNCALayer.yaml", Kind::Version),
        (
            "arynyklas.OpenNCALayer.locale.en-US.yaml",
            Kind::DefaultLocale,
        ),
        ("arynyklas.OpenNCALayer.installer.yaml", Kind::Installer),
    ] {
        let text = std::fs::read_to_string(run.out().join(name)).unwrap();
        assert!(
            text.contains("SYNTHETIC TEST FIXTURE"),
            "{name} is not marked"
        );
        let value = yaml::parse(&text).unwrap();
        assert_eq!(
            schema::validate(kind, &value),
            Vec::<String>::new(),
            "{name}"
        );
    }
    // It was not written as a candidate.
    assert!(manifest::check_dir(&run.out(), Mode::Candidate).is_err());
    // The evidence says nothing was submitted and carries the ledger entry to commit later.
    let evidence: Value = serde_json::from_slice(&std::fs::read(run.evidence()).unwrap()).unwrap();
    assert_eq!(evidence["submitted"], false);
    assert_eq!(
        evidence["ledger_entry"]["versions"][VERSION]["x64"],
        sha256(&published.x64)
    );
    // The output directory is never reused: a stale file cannot hide among the manifest's.
    let again = Run::new();
    std::fs::create_dir_all(again.out()).unwrap();
    std::fs::write(again.out().join("stale.yaml"), "x: 1\n").unwrap();
    let rig = Rig::of(&published);
    let error = again
        .generate(
            &rig,
            &release_value(&published),
            None,
            &Ledger::default(),
            false,
        )
        .unwrap_err();
    assert!(error.to_string().contains("not empty"), "{error:#}");
}

#[test]
fn the_candidate_is_not_a_submittable_manifest() {
    let published = Published::new();
    let run = Run::new();
    let rig = Rig::of(&published);
    let done = run
        .generate(
            &rig,
            &release_value(&published),
            None,
            &Ledger::default(),
            false,
        )
        .unwrap();
    assert_eq!(done.mode, Mode::Candidate);
    manifest::check_dir(&run.out(), Mode::Candidate).unwrap();
    let problems = manifest::check_dir(&run.out(), Mode::Fixture)
        .unwrap_err()
        .0
        .join("\n");
    assert!(problems.contains("ARP mapping is not proven"), "{problems}");
    // The candidate is a pure function of the release and the published bytes.
    let again = Run::new();
    again
        .generate(
            &rig,
            &release_value(&published),
            None,
            &Ledger::default(),
            false,
        )
        .unwrap();
    for name in manifest::file_names() {
        assert_eq!(
            std::fs::read(run.out().join(&name)).unwrap(),
            std::fs::read(again.out().join(&name)).unwrap(),
            "{name}"
        );
    }
}

/// Edits `installer.yaml` of a fresh final manifest and checks it again.
fn damaged(published: &Published, edit: impl Fn(&str) -> String) -> String {
    let (run, _) = final_manifest(published);
    let path = run.out().join("arynyklas.OpenNCALayer.installer.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let edited = edit(&text);
    assert_ne!(edited, text, "the edit changed nothing");
    std::fs::write(&path, edited).unwrap();
    manifest::check_dir(&run.out(), Mode::Fixture)
        .expect_err("a damaged manifest was accepted")
        .0
        .join("\n")
}

#[test]
fn a_manifest_that_breaks_an_invariant_of_the_package_is_refused() {
    let published = Published::new();
    let cases: Vec<(&str, TextEdit, &str)> = vec![
        (
            "machine scope",
            Box::new(|t| t.replace("Scope: user", "Scope: machine")),
            "Scope is not user",
        ),
        (
            "an elevating installer",
            Box::new(|t| t.replace("elevationProhibited", "elevationRequired")),
            "ElevationRequirement",
        ),
        (
            "a generic silent switch",
            Box::new(|t| t.replace("Silent: \"--silent\"", "Silent: /S")),
            "Silent is not the proven --silent",
        ),
        (
            "an untested custom switch",
            Box::new(|t| {
                t.replace(
                    "InstallerSwitches:\n",
                    "InstallerSwitches:\n  Custom: \"/VERYSILENT\"\n",
                )
            }),
            "never tested",
        ),
        (
            "uninstallPrevious",
            Box::new(|t| {
                t.replace(
                    "UpgradeBehavior: install",
                    "UpgradeBehavior: uninstallPrevious",
                )
            }),
            "UpgradeBehavior",
        ),
        (
            "a denied upgrade",
            Box::new(|t| t.replace("UpgradeBehavior: install", "UpgradeBehavior: deny")),
            "UpgradeBehavior",
        ),
        (
            "no explicit-upgrade policy",
            Box::new(|t| {
                t.replace(
                    "RequireExplicitUpgrade: true",
                    "RequireExplicitUpgrade: false",
                )
            }),
            "RequireExplicitUpgrade",
        ),
        (
            "widened success codes",
            Box::new(|t| {
                t.replace(
                    "UpgradeBehavior:",
                    "InstallerSuccessCodes:\n- 4\nUpgradeBehavior:",
                )
            }),
            "InstallerSuccessCodes",
        ),
        (
            "an interactive mode",
            Box::new(|t| t.replace("- silent\n", "- interactive\n- silent\n")),
            "interactive",
        ),
        (
            "a lower minimum Windows",
            Box::new(|t| t.replace("10.0.17763.0", "6.1.7601.0")),
            "MinimumOSVersion",
        ),
        (
            "a zip instead of an exe",
            Box::new(|t| t.replace("InstallerType: exe\nScope", "InstallerType: zip\nScope")),
            "InstallerType",
        ),
        (
            "a misspelt key the schema itself would let pass",
            Box::new(|t| t.replace("ElevationRequirement:", "ElevationRequirment:")),
            "ElevationRequirment is not a property",
        ),
        (
            "a latest URL",
            Box::new(|t| t.replace("releases/download/v0.3.0/", "releases/latest/download/")),
            "version-specific release URL",
        ),
        (
            "a hash that is not a SHA-256",
            Box::new(|t| {
                let at = t.find("InstallerSha256: ").unwrap();
                let end = at + t[at..].find('\n').unwrap();
                format!("{}InstallerSha256: XYZ1{}", &t[..at], &t[end..])
            }),
            "InstallerSha256",
        ),
        (
            "a package version that is not the Apps & Features version",
            Box::new(|t| t.replace("DisplayVersion: 0.3.0", "DisplayVersion: 0.3.1")),
            "DisplayVersion is not the PackageVersion",
        ),
        (
            "a missing x86 installer",
            Box::new(|t| {
                let at = t.find("- Architecture: x86").unwrap();
                let end = t.find("ManifestType:").unwrap();
                format!("{}{}", &t[..at], &t[end..])
            }),
            "exactly one x64 and one x86",
        ),
        (
            "an unproven return code",
            Box::new(|t| t.replace("InstallerReturnCode: 4", "InstallerReturnCode: 5")),
            "was not proven",
        ),
        (
            "another schema version",
            Box::new(|t| t.replace("ManifestVersion: 1.12.0", "ManifestVersion: 1.10.0")),
            "ManifestVersion",
        ),
    ];
    for (what, edit, expect) in cases {
        let problems = damaged(&published, edit);
        assert!(problems.contains(expect), "{what}: {problems}");
    }
}

#[test]
fn a_manifest_directory_must_be_exactly_its_three_files() {
    let published = Published::new();
    let (run, _) = final_manifest(&published);
    std::fs::write(run.out().join("extra.yaml"), "A: 1\n").unwrap();
    assert!(
        manifest::check_dir(&run.out(), Mode::Fixture)
            .unwrap_err()
            .0
            .join("\n")
            .contains("extra.yaml")
    );
    std::fs::remove_file(run.out().join("extra.yaml")).unwrap();
    std::fs::remove_file(run.out().join("arynyklas.OpenNCALayer.locale.en-US.yaml")).unwrap();
    assert!(manifest::check_dir(&run.out(), Mode::Fixture).is_err());
}

#[test]
fn the_pinned_schema_validator_catches_what_a_schema_catches() {
    let installer = json!({
        "PackageIdentifier": "arynyklas.OpenNCALayer",
        "PackageVersion": "0.3.0",
        "Installers": [{ "Architecture": "x64", "InstallerUrl": "ftp://x", "InstallerSha256": "abc" }],
        "ManifestType": "installer",
        "ManifestVersion": "1.12.0",
    });
    let errors = schema::validate(Kind::Installer, &installer).join("\n");
    assert!(errors.contains("InstallerUrl"), "{errors}");
    assert!(errors.contains("InstallerSha256"), "{errors}");
    let bad_enum = json!({
        "PackageIdentifier": "arynyklas.OpenNCALayer", "PackageVersion": "0.3.0",
        "Installers": [{ "Architecture": "mips", "InstallerUrl": "https://x/y", "InstallerSha256": "0".repeat(64) }],
        "ManifestType": "installer", "ManifestVersion": "1.12.0",
    });
    assert!(
        schema::validate(Kind::Installer, &bad_enum)
            .join("\n")
            .contains("Architecture")
    );
    let no_required = json!({ "PackageIdentifier": "arynyklas.OpenNCALayer" });
    let errors = schema::validate(Kind::Version, &no_required).join("\n");
    assert!(errors.contains("PackageVersion is required"), "{errors}");
    let bad_id = json!({
        "PackageIdentifier": "OpenNCALayer", "PackageVersion": "0.3.0", "DefaultLocale": "en-US",
        "ManifestType": "version", "ManifestVersion": "1.12.0",
    });
    assert!(
        schema::validate(Kind::Version, &bad_id)
            .join("\n")
            .contains("PackageIdentifier")
    );
}

/// The command line as a person runs it (`cargo xtask winget …`): the same refusals, the same
/// check, an exit status that CI can use.
#[test]
fn the_command_line_refuses_an_alpha_and_checks_a_manifest_directory() {
    let published = Published::new();
    let xtask = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("winget")
            .args(args)
            .output()
            .expect("xtask runs")
    };
    let text = |output: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    };

    // A pre-release (the shape of the latest real tags): no candidate, no directory, no network.
    let run = Run::new();
    let mut alpha = release_value(&published);
    alpha["tag_name"] = json!("v0.3.0-alpha.1");
    alpha["prerelease"] = json!(true);
    let release = run.dir.path().join("release.json");
    std::fs::write(&release, alpha.to_string()).unwrap();
    let out = run.out();
    let output = xtask(&[
        "candidate".as_ref(),
        "--release-json".as_ref(),
        release.as_os_str(),
        "--out".as_ref(),
        out.as_os_str(),
    ]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("pre-release"), "{}", text(&output));
    assert!(!out.exists());

    // A proven synthetic manifest passes `check`; as a candidate it does not, and the other
    // way round.
    let (made, _) = final_manifest(&published);
    let dir = made.out();
    // A fixture says in its header that it is not for submission, and `check` believes it.
    let output = xtask(&["check".as_ref(), dir.as_os_str()]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("NOT FOR SUBMISSION"),
        "{}",
        text(&output)
    );
    for name in xtask::winget::manifest::file_names() {
        let path = dir.join(&name);
        let body = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = body
            .lines()
            .filter(|l| !l.contains("NOT FOR SUBMISSION"))
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
    }
    let output = xtask(&["check".as_ref(), dir.as_os_str()]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("not an installer proof"),
        "{}",
        text(&output)
    );
    let output = xtask(&["check".as_ref(), dir.as_os_str(), "--candidate".as_ref()]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("candidate manifest has an Apps & Features mapping"),
        "{}",
        text(&output)
    );
    let path = dir.join("arynyklas.OpenNCALayer.installer.yaml");
    let manifest = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, manifest.replace("Scope: user", "Scope: machine")).unwrap();
    let output = xtask(&["check".as_ref(), dir.as_os_str()]);
    assert!(!output.status.success());
    assert!(
        text(&output).contains("Scope is not user"),
        "{}",
        text(&output)
    );
}

/// The real `winget validate` on a synthetic manifest: schema validation by WinGet's own
/// parser, which is not an installer proof. Read-only: it changes nothing on the machine.
/// Run with `cargo test -p xtask --test winget -- --ignored real_winget`.
#[test]
#[ignore = "needs winget.exe on PATH (read-only `winget validate`)"]
fn real_winget_validates_the_emitted_manifests() {
    let published = Published::new();
    let (run, _) = final_manifest(&published);
    let validated = |dir: &Path| {
        let output = std::process::Command::new("winget")
            .arg("validate")
            .arg(dir)
            .output()
            .expect("winget is on PATH");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.code(), text)
    };
    let (code, text) = validated(&run.out());
    eprintln!("winget validate (final): exit {code:?}\n{text}");
    assert_eq!(code, Some(0), "{text}");

    // The tool is a real judge: a manifest the checker refuses is refused by it too.
    let broken = Run::new();
    let text =
        std::fs::read_to_string(run.out().join("arynyklas.OpenNCALayer.installer.yaml")).unwrap();
    std::fs::create_dir_all(broken.out()).unwrap();
    for name in manifest::file_names() {
        std::fs::copy(run.out().join(&name), broken.out().join(&name)).unwrap();
    }
    std::fs::write(
        broken.out().join("arynyklas.OpenNCALayer.installer.yaml"),
        text.replace("Scope: user", "Scope: roaming"),
    )
    .unwrap();
    let (code, text) = validated(&broken.out());
    eprintln!("winget validate (broken): exit {code:?}\n{text}");
    assert_ne!(code, Some(0));

    // The candidate passes too.
    let candidate = Run::new();
    let rig = Rig::of(&published);
    candidate
        .generate(
            &rig,
            &release_value(&published),
            None,
            &Ledger::default(),
            false,
        )
        .unwrap();
    let (code, text) = validated(&candidate.out());
    eprintln!("winget validate (candidate): exit {code:?}\n{text}");
    assert_eq!(code, Some(0), "{text}");
}

// ---------------------------------------------------------------------------------------------
// The proof scripts (they run only inside the machines of the matrix; here they are parsed, and the
// merge step, which needs no installation, is run for real).
// ---------------------------------------------------------------------------------------------

#[cfg(windows)]
mod scripts {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    fn script(name: &str) -> PathBuf {
        oncl_testkit::workspace_root()
            .join("scripts/winget")
            .join(name)
    }

    fn powershell() -> Command {
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ]);
        command
    }

    #[test]
    fn the_proof_scripts_parse() {
        for name in [
            "Invoke-WingetProbe.ps1",
            "Invoke-WingetFinalProbe.ps1",
            "Merge-ProbeCells.ps1",
            "Invoke-WingetHold.ps1",
        ] {
            let output = powershell()
                .env("ONCL_SCRIPT", script(name))
                .args([
                    "-Command",
                    "$e = $null; $t = $null; \
                     [void][System.Management.Automation.Language.Parser]::ParseFile($env:ONCL_SCRIPT, [ref]$t, [ref]$e); \
                     if ($e.Count -gt 0) { $e | ForEach-Object { $_.Message + ' @' + $_.Extent.StartLineNumber }; exit 1 }",
                ])
                .output()
                .expect("powershell.exe runs");
            assert!(
                output.status.success(),
                "{name} does not parse: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn merging_synthetic_cells_cannot_make_a_real_run() {
        let published = Published::new();
        let candidate = candidate_sha(&published);
        let whole = probe_value(&published, &candidate, "synthetic-fixture");
        let dir = tempfile::tempdir().unwrap();
        for (index, report) in whole["reports"].as_array().unwrap().iter().enumerate() {
            std::fs::write(
                dir.path().join(format!("cell-{index}.json")),
                report.to_string(),
            )
            .unwrap();
        }
        for (index, report) in whole["final_cells"].as_array().unwrap().iter().enumerate() {
            std::fs::write(
                dir.path().join(format!("final-{index}.json")),
                report.to_string(),
            )
            .unwrap();
        }
        let merged = dir.path().join("merged.json");
        let output = powershell()
            .arg("-File")
            .arg(script("Merge-ProbeCells.ps1"))
            .arg("-Cells")
            .arg(dir.path().join("cell-*.json"))
            .arg("-FinalCells")
            .arg(dir.path().join("final-*.json"))
            .args([
                "-AttestedBy",
                "synthetic fixture",
                "-RunId",
                "synthetic-run",
            ])
            .arg("-OutFile")
            .arg(&merged)
            .output()
            .expect("powershell.exe runs");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(&merged).unwrap();
        assert!(
            !bytes.starts_with(&[0xEF, 0xBB, 0xBF]),
            "the merged file has a byte order mark"
        );
        let set = xtask::winget::probe::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
        // The script marks the set synthetic because its cells say so.
        assert_eq!(set.origin, xtask::winget::probe::Origin::SyntheticFixture);
        assert_eq!(set.reports.len(), 8);
        assert_eq!(set.final_cells.len(), 2);
        let release = xtask::winget::release::parse(&release_value(&published).to_string())
            .unwrap()
            .stable()
            .unwrap();
        let downloaded = [Arch::X64, Arch::X86].map(|arch| xtask::winget::probe::Published {
            arch,
            sha256: sha256(published.bytes(arch)),
            size: published.bytes(arch).len() as u64,
        });
        assert_eq!(
            set.prove(&release, &downloaded, &candidate, false)
                .unwrap_err(),
            ProbeError::Synthetic
        );
        let proof = set.prove(&release, &downloaded, &candidate, true).unwrap();
        assert_eq!(proof.cells, 8);
        assert!(proof.synthetic);
    }
}

// ---------------------------------------------------------------------------------------------
// Review conditions: architecture, final manifest, self-update, attestation, ledger, redirects.
// ---------------------------------------------------------------------------------------------

fn refused_probe(mutate: &dyn Fn(&mut Value)) -> ProbeError {
    let published = Published::new();
    let candidate = candidate_sha(&published);
    let rig = Rig::of(&published);
    let run = Run::new();
    let mut probe = probe_value(&published, &candidate, "synthetic-fixture");
    mutate(&mut probe);
    let error = error_of::<ProbeError>(run.generate(
        &rig,
        &release_value(&published),
        Some(&probe),
        &Ledger::default(),
        true,
    ));
    assert!(!run.out().exists());
    error
}

#[test]
fn the_installer_architecture_must_be_requested_from_winget() {
    // x86 on x64 Windows works only if WinGet is told `--architecture x86`.
    assert!(matches!(
        refused_probe(
            &|p| p["reports"][3]["tested_switches"]["winget_architecture"] = json!("x64")
        ),
        ProbeError::Switches(_)
    ));
    assert!(matches!(
        refused_probe(&|p| p["reports"][3]["tested_switches"]["winget_flags"] =
            json!(["--manifest", "--silent"])),
        ProbeError::Switches(_)
    ));
    // Nothing else new is allowed with it.
    assert!(matches!(
        refused_probe(&|p| p["reports"][3]["tested_switches"]["winget_flags"]
            .as_array_mut()
            .unwrap()
            .push(json!("--locale"))),
        ProbeError::Switches(_)
    ));
}

#[test]
fn the_final_manifest_itself_must_have_been_installed_upgraded_and_uninstalled() {
    let cases: Vec<(&str, Mutation)> = vec![
        ("no final cells", Box::new(|p| p["final_cells"] = json!([]))),
        (
            "no x86 final cell",
            Box::new(|p| {
                p["final_cells"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|c| c["installer_arch"] != "x86");
            }),
        ),
        (
            "the candidate's installer.yaml",
            Box::new(|p| p["final_cells"][0]["manifest_files_sha256"] = json!("0".repeat(64))),
        ),
        (
            "an upgrade that did not correlate",
            Box::new(|p| p["final_cells"][1]["upgrade_correlated_installed_entry"] = json!(false)),
        ),
        (
            "an uninstall that left the entry",
            Box::new(|p| p["final_cells"][0]["uninstall_removed_entry"] = json!(false)),
        ),
        (
            "a failed upgrade",
            Box::new(|p| p["final_cells"][0]["upgrade_exit_code"] = json!(1)),
        ),
        (
            "a wrong version after the upgrade",
            Box::new(|p| p["final_cells"][0]["arp_display_version_after_upgrade"] = json!("0.2.0")),
        ),
    ];
    for (what, mutate) in cases {
        assert!(
            matches!(refused_probe(&*mutate), ProbeError::FinalManifest(_)),
            "{what}"
        );
    }
}

#[test]
fn the_self_update_must_be_proven_and_the_check_is_not_vacuous() {
    for (what, mutate) in [
        (
            "an installer ran",
            Box::new(|p: &mut Value| {
                p["reports"][0]["lifecycle"]["self_update"]["winget_installer_ran"] = json!(true)
            }) as Mutation,
        ),
        (
            "not the no-applicable-upgrade code",
            Box::new(|p| {
                p["reports"][0]["lifecycle"]["self_update"]["winget_exit_code"] = json!(0)
            }),
        ),
    ] {
        assert!(
            matches!(refused_probe(&*mutate), ProbeError::Lifecycle(_)),
            "{what}"
        );
    }
}

#[test]
fn a_probe_report_is_an_attestation_that_must_say_who_and_which_script() {
    // A synthetic cell inside a set that claims to be a real run.
    assert_eq!(
        {
            let published = Published::new();
            let candidate = candidate_sha(&published);
            let rig = Rig::of(&published);
            let run = Run::new();
            let mut probe = probe_value(&published, &candidate, "synthetic-fixture");
            probe["origin"] = json!("vm-run");
            error_of::<ProbeError>(run.generate(
                &rig,
                &release_value(&published),
                Some(&probe),
                &Ledger::default(),
                false,
            ))
        },
        ProbeError::Synthetic
    );
    assert!(matches!(
        refused_probe(&|p| p["attestation"]["attested_by"] = json!(" ")),
        ProbeError::Inconsistent(_)
    ));
    assert!(matches!(
        refused_probe(&|p| p["reports"][2]["run"]["script_sha256"] = json!("cd".repeat(32))),
        ProbeError::Inconsistent(_)
    ));
    assert!(matches!(
        refused_probe(&|p| p["reports"][2]["run"]["vm_id"] = json!("")),
        ProbeError::Inconsistent(_)
    ));
    assert!(matches!(
        refused_probe(
            &|p| p["reports"][0]["safety"]["elevated"]["no_artifacts_in_any_profile"] =
                json!(false)
        ),
        ProbeError::Safety(_)
    ));
    assert!(matches!(
        refused_probe(&|p| p["reports"][0]["safety"]["signing_hold"]["busy_exit_code"] = json!(0)),
        ProbeError::Safety(_)
    ));
}

#[test]
fn ledger_entries_are_validated() {
    let ok = format!(
        r#"{{"versions": {{"0.3.0": {{"x64": "{}", "x86": "{}"}}}}}}"#,
        "a".repeat(64),
        "b".repeat(64)
    );
    assert!(Ledger::parse(&ok).is_ok());
    let bad = |version: &str, keys: &str, hash: &str| {
        Ledger::parse(&format!(r#"{{"versions": {{"{version}": {keys}}}}}"#).replace("HASH", hash))
            .is_err()
    };
    let two = r#"{"x64": "HASH", "x86": "HASH"}"#;
    let h = "a".repeat(64);
    assert!(!bad("0.3.0", two, &h));
    assert!(bad("v0.3.0", two, &h), "a v prefix");
    assert!(bad("0.3.0-alpha.1", two, &h), "a pre-release");
    assert!(
        bad("0.3.0", r#"{"X64": "HASH", "x86": "HASH"}"#, &h),
        "a wrong arch key"
    );
    assert!(bad("0.3.0", r#"{"x64": "HASH"}"#, &h), "a missing arch");
    assert!(
        bad(
            "0.3.0",
            r#"{"x64": "HASH", "x86": "HASH", "arm64": "HASH"}"#,
            &h
        ),
        "an extra arch"
    );
    assert!(
        bad("0.3.0", two, &h.to_ascii_uppercase()),
        "an uppercase hash"
    );
    assert!(bad("0.3.0", two, "abc"), "a short hash");
    assert!(Ledger::parse("").is_err());
    assert!(Ledger::parse("{}").is_err());
    assert!(
        Ledger::parse(r#"{"versions": {}, "x": 1}"#).is_err(),
        "an unknown key"
    );
}

#[test]
fn a_byte_order_mark_is_read_and_a_fixture_header_is_not_believed_by_check() {
    let published = Published::new();
    let (run, _) = final_manifest(&published);
    let path = run.out().join("arynyklas.OpenNCALayer.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("\u{feff}{text}")).unwrap();
    manifest::check_dir(&run.out(), Mode::Fixture).unwrap();
    let problems = manifest::check_dir(&run.out(), Mode::Final)
        .unwrap_err()
        .0
        .join("\n");
    assert!(problems.contains("NOT FOR SUBMISSION"), "{problems}");
}

#[test]
fn redirects_leave_github_only_over_https() {
    use xtask::winget::download::github_hop;
    for good in [
        "https://github.com/arynyklas/OpenNCALayer/releases/download/v1.0.0/a.exe",
        "https://release-assets.githubusercontent.com/github-production-release-asset/1?x=y",
        "https://objects.githubusercontent.com/a",
    ] {
        assert!(github_hop(good), "{good}");
    }
    for bad in [
        "http://github.com/a",
        "https://evil.example/a",
        "https://github.com.evil.example/a",
        "https://github.com@evil.example/a",
        "https://evilgithubusercontent.com/a",
        "https://github.com:8443/a",
        "ftp://github.com/a",
    ] {
        assert!(!github_hop(bad), "{bad}");
    }
    // The client enforces it on every hop, including a redirect out of the allowed set.
    let server = MockServer::start();
    server.route("GET", "/ok", Response::redirect("/elsewhere"));
    server.route("GET", "/elsewhere", Response::ok(b"x".to_vec()));
    let fetcher = Fetcher::for_tests().restricted_to(|url| !url.ends_with("/elsewhere"));
    let dir = tempfile::tempdir().unwrap();
    let error = Https::with(fetcher)
        .fetch(&server.url("/ok"), 1024, &dir.path().join("f"))
        .unwrap_err();
    assert!(format!("{error:#}").contains("allowed hosts"), "{error:#}");
    assert!(!dir.path().join("f").exists());
}

#[test]
fn the_directory_for_the_final_proof_run_can_be_made_before_the_final_cells_exist() {
    let published = Published::new();
    let candidate = candidate_sha(&published);
    let mut probe = probe_value(&published, &candidate, "synthetic-fixture");
    probe["final_cells"] = json!([]);
    let rig = Rig::of(&published);
    let release = release_value(&published).to_string();
    let probe_text = probe.to_string();
    let run = Run::new();
    let request = |pending: bool, out: &std::path::Path, evidence: &std::path::Path| {
        generate(
            &Request {
                release_json: &release,
                probe_json: Some(&probe_text),
                ledger: &Ledger::default(),
                allow_synthetic: true,
                final_proof_pending: pending,
                out,
                evidence,
            },
            &rig.fetch,
        )
    };
    // Without the flag the missing proof is refused; with it the files are made but not ready.
    assert!(request(false, &run.out(), &run.evidence()).is_err());
    let done = request(true, &run.out(), &run.evidence()).unwrap();
    assert!(!done.evidence.ready);
    // The bytes are the ones the complete run writes, so the cells' hash will match.
    let full = final_manifest(&published).0;
    assert_eq!(
        std::fs::read(run.out().join("arynyklas.OpenNCALayer.installer.yaml")).unwrap(),
        std::fs::read(full.out().join("arynyklas.OpenNCALayer.installer.yaml")).unwrap()
    );
}

// ---------------------------------------------------------------------------------------------
// The verdict: ready / submittable-with-waiver / not-ready. The inputs below are in-test data
// that says it is a real run (origin "vm-run", cells not synthetic); the downloads come from the
// local server, so nothing reaches a network or a machine. `ready` can therefore be TRUE here.
// ---------------------------------------------------------------------------------------------

fn real_probe(published: &Published) -> Value {
    probe_value(published, &candidate_sha(published), "vm-run")
}

fn made(
    published: &Published,
    probe: &Value,
    pending: bool,
) -> (Run, anyhow::Result<xtask::winget::Generated>) {
    let run = Run::new();
    let rig = Rig::of(published);
    let release = release_value(published).to_string();
    let probe = probe.to_string();
    let result = generate(
        &Request {
            release_json: &release,
            probe_json: Some(&probe),
            ledger: &Ledger::default(),
            allow_synthetic: false,
            final_proof_pending: pending,
            out: &run.out(),
            evidence: &run.evidence(),
        },
        &rig.fetch,
    );
    (run, result)
}

fn status_of(run: &Run) -> Value {
    let path = format!("{}.status.json", run.out().display());
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn ready_is_true_only_when_every_proof_including_a_real_self_update_is_present() {
    let published = Published::new();
    let (run, done) = made(&published, &real_probe(&published), false);
    let done = done.unwrap();
    assert_eq!(done.mode, Mode::Final);
    assert!(done.evidence.ready && done.evidence.self_update_proven);
    assert_eq!(done.evidence.verdict, xtask::winget::Verdict::Ready);
    let status = status_of(&run);
    assert_eq!(status["verdict"], "ready");
    assert_eq!(status["reasons"], json!([]));
    // The status is next to the directory, never in it.
    assert_eq!(std::fs::read_dir(run.out()).unwrap().count(), 3);
    manifest::check_dir(&run.out(), Mode::Final).unwrap();
    assert_eq!(
        status["manifest_files_sha256"],
        manifest::dir_digest(&run.out()).unwrap()
    );
}

#[test]
fn each_missing_proof_flips_the_verdict_with_its_exact_reason() {
    let published = Published::new();
    // The self-update was not seen (the version did not move): never ready, with a stated reason.
    let mut none = real_probe(&published);
    for r in none["reports"].as_array_mut().unwrap() {
        let u = &mut r["lifecycle"]["self_update"];
        u["newer_release_tested"] = json!(false);
        u["arp_display_version"] = json!(VERSION);
        u["program_version"] = json!(VERSION);
    }
    let (run, done) = made(&published, &none, false);
    let done = done.unwrap();
    assert!(!done.evidence.ready && !done.evidence.self_update_proven);
    assert_eq!(done.evidence.verdict, xtask::winget::Verdict::NotReady);
    assert!(
        done.evidence
            .reasons
            .join(" ")
            .contains("self-update is NOT PROVEN")
    );
    assert_eq!(status_of(&run)["verdict"], "not-ready");

    // The claim and the versions must agree, in both directions.
    let mut liar = real_probe(&published);
    liar["reports"][0]["lifecycle"]["self_update"]["arp_display_version"] = json!(VERSION);
    liar["reports"][0]["lifecycle"]["self_update"]["program_version"] = json!(VERSION);
    assert!(matches!(
        error_of::<ProbeError>(made(&published, &liar, false).1),
        ProbeError::Lifecycle(_)
    ));
    let mut hidden = none.clone();
    hidden["reports"][0]["lifecycle"]["self_update"]["arp_display_version"] = json!(NEWER);
    hidden["reports"][0]["lifecycle"]["self_update"]["program_version"] = json!(NEWER);
    assert!(matches!(
        error_of::<ProbeError>(made(&published, &hidden, false).1),
        ProbeError::Lifecycle(_)
    ));

    // A waiver recorded by the owner covers exactly that gap and nothing else.
    let mut waived = none.clone();
    waived["waiver"] =
        json!({"reason": "first stable release", "approved_by": "owner", "date": "2026-11-06"});
    let (run, done) = made(&published, &waived, false);
    let done = done.unwrap();
    assert_eq!(
        done.evidence.verdict,
        xtask::winget::Verdict::SubmittableWithWaiver
    );
    assert!(!done.evidence.ready);
    assert_eq!(status_of(&run)["waiver"]["approved_by"], "owner");
    // The tools never invent one, and a malformed one is refused.
    for bad in [
        json!({"reason": "", "approved_by": "owner", "date": "2026-11-06"}),
        json!({"reason": "x", "approved_by": " ", "date": "2026-11-06"}),
        json!({"reason": "x", "approved_by": "owner", "date": "yesterday"}),
    ] {
        let mut p = none.clone();
        p["waiver"] = bad;
        assert!(matches!(
            error_of::<ProbeError>(made(&published, &p, false).1),
            ProbeError::Inconsistent(_)
        ));
    }
    // A waiver does not rescue a pending final proof.
    let (_, done) = made(&published, &waived, true);
    let done = done.unwrap();
    assert_eq!(done.evidence.verdict, xtask::winget::Verdict::NotReady);
    assert!(
        done.evidence
            .reasons
            .join(" ")
            .contains("--final-proof-pending")
    );
    // ... nor a missing final cell.
    let mut no_final = waived.clone();
    no_final["final_cells"] = json!([]);
    assert!(matches!(
        error_of::<ProbeError>(made(&published, &no_final, false).1),
        ProbeError::FinalManifest(_)
    ));
    // Even with everything proven a waiver is not recorded as used.
    let mut full = real_probe(&published);
    full["waiver"] = waived["waiver"].clone();
    let (run, done) = made(&published, &full, false);
    assert_eq!(
        done.unwrap().evidence.verdict,
        xtask::winget::Verdict::Ready
    );
    assert!(status_of(&run)["waiver"].is_null());

    // Synthetic fixtures and candidates are never ready.
    let (_, done) = {
        let run = Run::new();
        let rig = Rig::of(&published);
        let r = run.generate(
            &rig,
            &release_value(&published),
            Some(&probe_value(
                &published,
                &candidate_sha(&published),
                "synthetic-fixture",
            )),
            &Ledger::default(),
            true,
        );
        (run, r)
    };
    assert_eq!(
        done.unwrap().evidence.verdict,
        xtask::winget::Verdict::NotReady
    );
    let run = Run::new();
    let cand = run
        .generate(
            &Rig::of(&published),
            &release_value(&published),
            None,
            &Ledger::default(),
            false,
        )
        .unwrap();
    assert_eq!(cand.evidence.verdict, xtask::winget::Verdict::NotReady);
}

#[test]
fn for_submission_recomputes_the_verdict_and_never_believes_the_status_file() {
    let published = Published::new();
    let release = release_value(&published).to_string();
    let rig = Rig::of(&published);
    let verify = |run: &Run, probe: &Value| {
        xtask::winget::verify_for_submission(
            &run.out(),
            &release,
            &probe.to_string(),
            &Ledger::default(),
            &rig.fetch,
        )
    };
    let ready_probe = real_probe(&published);
    let (run, _) = made(&published, &ready_probe, false);
    assert_eq!(
        verify(&run, &ready_probe).unwrap().verdict,
        xtask::winget::Verdict::Ready
    );

    // Changing a file makes the status be about other files.
    let path = run.out().join("arynyklas.OpenNCALayer.locale.en-US.yaml");
    let original = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, original.replace("Apache-2.0", "MIT")).unwrap();
    assert!(format!("{:#}", verify(&run, &ready_probe).unwrap_err()).contains("other files"));
    std::fs::write(&path, &original).unwrap();
    // Other inputs than the ones the status was made from are refused.
    let mut other = ready_probe.clone();
    other["attestation"]["run_id"] = json!("another run");
    assert!(
        format!("{:#}", verify(&run, &other).unwrap_err())
            .contains("another release JSON or probe")
    );

    // Another release JSON (a harmless extra field) is another input too.
    let mut changed: Value = serde_json::from_str(&release).unwrap();
    changed["x"] = json!(1);
    let error = xtask::winget::verify_for_submission(
        &run.out(),
        &changed.to_string(),
        &ready_probe.to_string(),
        &Ledger::default(),
        &rig.fetch,
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("another release JSON"),
        "{error:#}"
    );
    // Edited files with a status rewritten to match them are not what the inputs generate.
    let status_path = format!("{}.status.json", run.out().display());
    let mut forged: Value = serde_json::from_slice(&std::fs::read(&status_path).unwrap()).unwrap();
    std::fs::write(&path, original.replace("Apache-2.0", "MIT")).unwrap();
    forged["manifest_files_sha256"] = json!(manifest::dir_digest(&run.out()).unwrap());
    std::fs::write(&status_path, forged.to_string()).unwrap();
    assert!(
        format!("{:#}", verify(&run, &ready_probe).unwrap_err())
            .contains("not what the release and the probe generate")
    );

    // A not-ready directory with a hand-written `ready` status and the right digest:
    let mut none = real_probe(&published);
    for r in none["reports"].as_array_mut().unwrap() {
        let u = &mut r["lifecycle"]["self_update"];
        u["newer_release_tested"] = json!(false);
        u["arp_display_version"] = json!(VERSION);
        u["program_version"] = json!(VERSION);
    }
    let (run, _) = made(&published, &none, false);
    let error = verify(&run, &none).unwrap_err();
    assert!(format!("{error:#}").contains("NOT READY"), "{error:#}");
    let status_path = format!("{}.status.json", run.out().display());
    let mut status: Value = serde_json::from_slice(&std::fs::read(&status_path).unwrap()).unwrap();
    status["verdict"] = json!("ready");
    status["reasons"] = json!([]);
    std::fs::write(&status_path, status.to_string()).unwrap();
    let error = verify(&run, &none).unwrap_err();
    assert!(
        format!("{error:#}").contains("the inputs give"),
        "{error:#}"
    );
    // ... and a directory without any status is not submittable.
    std::fs::remove_file(&status_path).unwrap();
    assert!(verify(&run, &none).is_err());
}

#[test]
fn the_command_line_needs_the_inputs_to_check_for_submission() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["winget", "check", "--for-submission", "nowhere"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--release-json"));
}

#[test]
fn the_final_cells_bind_all_three_manifest_files() {
    let published = Published::new();
    let (run, done) = made(&published, &real_probe(&published), false);
    done.unwrap();
    // The digest moves when any one file moves, not only installer.yaml.
    let base = manifest::dir_digest(&run.out()).unwrap();
    let path = run.out().join("arynyklas.OpenNCALayer.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("DefaultLocale: en-US", "DefaultLocale: en-GB"),
    )
    .unwrap();
    assert_ne!(manifest::dir_digest(&run.out()).unwrap(), base);
}

#[test]
fn github_hop_uses_the_parsed_host() {
    use xtask::winget::download::github_hop;
    for bad in [
        "https://evil@a.githubusercontent.com/x",
        "https://githubusercontent.com.evil.test/x",
        "https://evilgithubusercontent.com/x",
        "https://github.com:444/x",
        "https://github.com:80/x",
        "https://gıthub.com/x",
        "https://github.сom/x",
        "https://xn--githb-qva.com/x",
        "https://github.com./x",
        "https://[::1]/x",
        "HTTP://github.com/x",
    ] {
        assert!(!github_hop(bad), "{bad}");
    }
    assert!(github_hop("HTTPS://GitHub.com/x"));
    assert!(github_hop("https://github.com:443/x"));
}

#[cfg(windows)]
mod ps_flows {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    fn script(name: &str) -> PathBuf {
        oncl_testkit::workspace_root()
            .join("scripts/winget")
            .join(name)
    }

    fn ps() -> Command {
        let mut c = Command::new("powershell.exe");
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ]);
        c
    }

    /// The function of the probe script that looks for leftovers, run with an EMPTY other-admin
    /// profile (an administrator cell) and with the directories pointed at a temp folder.
    #[test]
    fn the_leftover_check_runs_for_a_cell_without_another_admin() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join("Local");
        let roaming = temp.path().join("Roaming");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::create_dir_all(&roaming).unwrap();
        let run = |other: &str| {
            let out = ps()
                .env("ONCL_SCRIPT", script("Invoke-WingetProbe.ps1"))
                .env("LOCALAPPDATA", &local)
                .env("APPDATA", &roaming)
                .env("ONCL_OTHER", other)
                .args([
                    "-Command",
                    "$ErrorActionPreference='Stop'; \
                     $ast=[System.Management.Automation.Language.Parser]::ParseFile($env:ONCL_SCRIPT,[ref]$null,[ref]$null); \
                     $f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-OtherProfileArtifacts'},$true); \
                     Invoke-Expression $f.Extent.Text; \
                     $r=@(Get-OtherProfileArtifacts $env:ONCL_OTHER); \
                     $r.Count",
                ])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<usize>()
                .unwrap()
        };
        // No leftovers in the temp profile: only what the real HKU holds counts, and the call
        // must not throw with an empty profile.
        let baseline = run("");
        std::fs::create_dir_all(roaming.join("OpenNCALayer")).unwrap();
        assert_eq!(
            run(""),
            baseline + 1,
            "a leftover in the account's roaming data is found"
        );
        let other = temp.path().join("Other");
        std::fs::create_dir_all(other.join("AppData/Local/OpenNCALayer")).unwrap();
        assert_eq!(
            run(other.to_str().unwrap()),
            baseline + 2,
            "and one in another admin's profile when there is one"
        );
    }

    /// The digest code of the shipped final-cell script gives the generator's value.
    #[test]
    fn the_powershell_manifest_digest_equals_the_rust_one() {
        let published = Published::new();
        let (run, done) = made(&published, &real_probe(&published), false);
        done.unwrap();
        let rust = manifest::dir_digest(&run.out()).unwrap();
        let out = ps()
            .env("ONCL_SCRIPT", script("Invoke-WingetFinalProbe.ps1"))
            .env("ONCL_DIR", run.out())
            .args([
                "-Command",
                "$ErrorActionPreference='Stop'; \
                 $ast=[System.Management.Automation.Language.Parser]::ParseFile($env:ONCL_SCRIPT,[ref]$null,[ref]$null); \
                 $f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ManifestFilesDigest'},$true); \
                 Invoke-Expression $f.Extent.Text; \
                 Get-ManifestFilesDigest $env:ONCL_DIR",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), rust);
    }

    /// The documented sequence, with the shipped scripts and the generator: merge without final
    /// cells, `generate --final-proof-pending`, final cells bound to the directory it made,
    /// merge again, `generate`.
    #[test]
    fn the_pending_final_sequence_runs_end_to_end() {
        let published = Published::new();
        let whole = real_probe(&published);
        let dir = tempfile::tempdir().unwrap();
        for (i, r) in whole["reports"].as_array().unwrap().iter().enumerate() {
            std::fs::write(dir.path().join(format!("cell-{i}.json")), r.to_string()).unwrap();
        }
        let merge = |extra: &[&std::ffi::OsStr], out: &std::path::Path| {
            let output = ps()
                .arg("-File")
                .arg(script("Merge-ProbeCells.ps1"))
                .arg("-Cells")
                .arg(dir.path().join("cell-*.json"))
                .args(["-AttestedBy", "in-test operator", "-RunId", "in-test-run"])
                .args(extra)
                .arg("-OutFile")
                .arg(out)
                .output()
                .unwrap();
            (
                output.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            )
        };
        // Without final cells and without the switch the script refuses.
        let pending_set = dir.path().join("pending.json");
        let (ok, text) = merge(&[], &pending_set);
        assert!(!ok && text.contains("PendingFinal"), "{text}");
        let (ok, text) = merge(&["-PendingFinal".as_ref()], &pending_set);
        assert!(ok, "{text}");
        let set = std::fs::read_to_string(&pending_set).unwrap();
        let parsed = xtask::winget::probe::parse(&set).unwrap();
        assert_eq!(parsed.origin, xtask::winget::probe::Origin::VmRun);
        assert!(parsed.final_cells.is_empty());

        // Generate the directory the final cells install from.
        let rig = Rig::of(&published);
        let release = release_value(&published).to_string();
        let first = Run::new();
        let pending = generate(
            &Request {
                release_json: &release,
                probe_json: Some(&set),
                ledger: &Ledger::default(),
                allow_synthetic: false,
                final_proof_pending: true,
                out: &first.out(),
                evidence: &first.evidence(),
            },
            &rig.fetch,
        )
        .unwrap();
        assert_eq!(pending.evidence.verdict, xtask::winget::Verdict::NotReady);

        // The cells of the run on that directory, as the final script would write them.
        let digest = manifest::dir_digest(&first.out()).unwrap();
        for (i, c) in whole["final_cells"].as_array().unwrap().iter().enumerate() {
            let mut c = c.clone();
            c["manifest_files_sha256"] = json!(digest);
            std::fs::write(dir.path().join(format!("final-{i}.json")), c.to_string()).unwrap();
        }
        let full_set = dir.path().join("full.json");
        let finals = dir.path().join("final-*.json");
        let (ok, text) = merge(&["-FinalCells".as_ref(), finals.as_os_str()], &full_set);
        assert!(ok, "{text}");
        let second = Run::new();
        let full = generate(
            &Request {
                release_json: &release,
                probe_json: Some(&std::fs::read_to_string(&full_set).unwrap()),
                ledger: &Ledger::default(),
                allow_synthetic: false,
                final_proof_pending: false,
                out: &second.out(),
                evidence: &second.evidence(),
            },
            &rig.fetch,
        )
        .unwrap();
        assert_eq!(full.evidence.verdict, xtask::winget::Verdict::Ready);
        assert_eq!(manifest::dir_digest(&second.out()).unwrap(), digest);
    }
}
