//! `nm install|uninstall|status` on sandboxed layouts (never the registry, never a real
//! browser profile): the relay and its `nmhost.json`, the host manifests, relay replacement
//! by rename, and the `openncalayer nm` command.

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use oncl_ipc::ids::HOST_NAME;
use openncalayer::nm::{
    self, Family, Item, ManifestTarget, NmLayout, RELAY_CONFIG, State, chromium_manifest,
    firefox_manifest,
};
use serde_json::Value;
use tempfile::TempDir;

/// Set for a copy of this test executable started as a stand-in for a running relay.
const STAND_IN_VAR: &str = "ONCL_NM_TEST_STAND_IN";

// A copy of this executable started with `STAND_IN_VAR` plays a relay the browser runs,
// until its stdin closes. It runs before `main`, from the platform's list of initializers
// (as the `ctor` crate does), so it never reaches libtest.
#[used]
#[cfg_attr(
    all(unix, not(target_vendor = "apple")),
    unsafe(link_section = ".init_array")
)]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__DATA,__mod_init_func")
)]
#[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
static BEFORE_MAIN: extern "C" fn() = before_main;

extern "C" fn before_main() {
    if std::env::var_os(STAND_IN_VAR).is_some() {
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
        std::process::exit(0);
    }
}

/// Runs the relay installed at `relay`, a copy of this executable, as a stand-in until its
/// stdin is closed.
fn run_stand_in(relay: &Path) -> Child {
    Command::new(relay)
        .env(STAND_IN_VAR, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn stop_stand_in(mut child: Child) {
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// A file with `bytes` to install as the relay.
fn relay_source(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// The leftovers of replaced relays in `layout`.
fn old_relays(layout: &NmLayout) -> Vec<PathBuf> {
    let mut olds: Vec<PathBuf> = fs::read_dir(&layout.relay_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("nmhost.old-"))
        })
        .collect();
    olds.sort();
    olds
}

fn states<'a>(report: &'a nm::Report, item: &Item) -> Vec<&'a State> {
    report
        .entries
        .iter()
        .filter(|entry| &entry.item == item)
        .map(|entry| &entry.state)
        .collect()
}

/// A Linux-like layout under `tmp`: the relay in the data directory, one browser of each
/// family with its config directory present.
fn data_dir_layout(tmp: &Path, data: &Path) -> NmLayout {
    let chromium = tmp.join("config").join("chromium");
    let mozilla = tmp.join("home").join(".mozilla");
    fs::create_dir_all(&chromium).unwrap();
    fs::create_dir_all(&mozilla).unwrap();
    NmLayout {
        relay_dir: data.to_path_buf(),
        manifests: vec![
            ManifestTarget {
                browser: "Chromium",
                family: Family::Chromium,
                dir: chromium.join("NativeMessagingHosts"),
                requires: vec![chromium],
            },
            ManifestTarget {
                browser: "Firefox",
                family: Family::Firefox,
                dir: mozilla.join("native-messaging-hosts"),
                requires: vec![mozilla],
            },
        ],
        registry_base: None,
    }
}

#[test]
fn sandbox_install_writes_relay_config_and_manifests() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("sbx");
    let layout = NmLayout::sandbox(&root);
    assert_eq!(layout.relay_dir, root.join("relay"));
    assert_eq!(layout.registry_base, None);
    let chromium_manifest_path = root
        .join("chromium")
        .join("NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let firefox_manifest_path = root
        .join("home")
        .join(".mozilla")
        .join("native-messaging-hosts")
        .join(format!("{HOST_NAME}.json"));
    let paths: Vec<PathBuf> = layout
        .manifests
        .iter()
        .map(|target| layout.manifest_path(target))
        .collect();
    assert_eq!(
        paths,
        [
            chromium_manifest_path.clone(),
            firefox_manifest_path.clone()
        ]
    );

    let src = relay_source(tmp.path(), "relay-src", b"relay v1");
    // Relative paths are made absolute: the relay rejects relative ones.
    let report = nm::install(
        &layout,
        &src,
        Path::new("bin/openncalayer"),
        Path::new("oncl-data"),
    )
    .unwrap();

    let relay = layout.relay();
    assert_eq!(
        relay,
        root.join("relay").join(format!("nmhost{EXE_SUFFIX}"))
    );
    assert_eq!(fs::read(&relay).unwrap(), b"relay v1");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&relay).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    let config = read_json(&layout.relay_dir.join(RELAY_CONFIG));
    assert_eq!(layout.relay_config(), layout.relay_dir.join(RELAY_CONFIG));
    let object = config.as_object().unwrap();
    assert_eq!(object.len(), 2, "{config}");
    let data_dir = Path::new(config["data_dir"].as_str().unwrap());
    let daemon = Path::new(config["daemon"].as_str().unwrap());
    assert!(
        data_dir.is_absolute() && data_dir.ends_with("oncl-data"),
        "{config}"
    );
    assert!(
        daemon.is_absolute() && daemon.ends_with(Path::new("bin").join("openncalayer")),
        "{config}"
    );

    let chromium = read_json(&chromium_manifest_path);
    assert_eq!(chromium, chromium_manifest(&relay));
    assert_eq!(chromium["path"], relay.to_str().unwrap());
    let firefox = read_json(&firefox_manifest_path);
    assert_eq!(firefox, firefox_manifest(&relay));
    assert_eq!(firefox["path"], relay.to_str().unwrap());

    assert_eq!(states(&report, &Item::Relay), [&State::Written]);
    assert_eq!(states(&report, &Item::RelayConfig), [&State::Written]);
    for browser in ["Chromium", "Firefox"] {
        assert_eq!(
            states(&report, &Item::Manifest { browser }),
            [&State::Written]
        );
    }
    assert!(states(&report, &Item::RegistryKey).is_empty());
    // No temporary files are left behind.
    let mut names: Vec<_> = fs::read_dir(&layout.relay_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    let expected: [std::ffi::OsString; 2] =
        [format!("nmhost{EXE_SUFFIX}").into(), RELAY_CONFIG.into()];
    assert_eq!(names, expected);

    // The daemon `bin/openncalayer` does not exist: everything else is in place.
    let status = nm::status(&layout);
    assert_eq!(states(&status, &Item::Relay), [&State::Present]);
    assert!(matches!(
        states(&status, &Item::RelayConfig)[..],
        [State::Invalid(_)]
    ));
    for browser in ["Chromium", "Firefox"] {
        assert_eq!(
            states(&status, &Item::Manifest { browser }),
            [&State::Present]
        );
    }
}

#[test]
fn install_without_relay_source_changes_nothing() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("sbx");
    let layout = NmLayout::sandbox(&root);
    let err = nm::install(
        &layout,
        &tmp.path().join("missing"),
        &tmp.path().join("openncalayer"),
        &tmp.path().join("data"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(!root.exists());
}

#[test]
fn status_reports_missing_and_tampered_parts() {
    let tmp = TempDir::new().unwrap();
    let layout = NmLayout::sandbox(&tmp.path().join("sbx"));
    let status = nm::status(&layout);
    assert!(!status.is_healthy());
    assert_eq!(states(&status, &Item::Relay), [&State::Missing]);
    assert_eq!(states(&status, &Item::RelayConfig), [&State::Missing]);

    let src = relay_source(tmp.path(), "relay-src", b"relay");
    let daemon = relay_source(tmp.path(), "openncalayer", b"daemon");
    nm::install(&layout, &src, &daemon, &tmp.path().join("data")).unwrap();
    assert!(nm::status(&layout).is_healthy());

    let chromium = layout.manifest_path(&layout.manifests[0]);
    fs::write(&chromium, b"{\"name\":\"other\"}").unwrap();
    fs::remove_file(&daemon).unwrap();
    let status = nm::status(&layout);
    assert!(!status.is_healthy());
    assert!(matches!(
        states(
            &status,
            &Item::Manifest {
                browser: "Chromium"
            }
        )[..],
        [State::Invalid(_)]
    ));
    assert!(matches!(
        states(&status, &Item::RelayConfig)[..],
        [State::Invalid(_)]
    ));
    assert_eq!(
        states(&status, &Item::Manifest { browser: "Firefox" }),
        [&State::Present]
    );
}

#[test]
fn reinstall_replaces_relay_by_rename_and_cleans_old() {
    let tmp = TempDir::new().unwrap();
    let layout = NmLayout::sandbox(&tmp.path().join("sbx"));
    let daemon = relay_source(tmp.path(), "openncalayer", b"daemon");
    let data = tmp.path().join("data");

    // The first relay is a real executable, so it can run while it is replaced.
    let this = std::env::current_exe().unwrap();
    nm::install(&layout, &this, &daemon, &data).unwrap();
    let relay = layout.relay();
    let mut running = run_stand_in(&relay);

    let new = relay_source(tmp.path(), "relay-v2", b"relay v2");
    let report = nm::install(&layout, &new, &daemon, &data).unwrap();
    assert_eq!(fs::read(&relay).unwrap(), b"relay v2");
    assert!(
        running.try_wait().unwrap().is_none(),
        "the old relay keeps running"
    );
    let olds = old_relays(&layout);
    if cfg!(windows) {
        // A running executable can be renamed but not deleted.
        assert_eq!(olds.len(), 1, "{olds:?}");
        let name = olds[0].file_name().unwrap().to_str().unwrap();
        let ms = name
            .strip_prefix("nmhost.old-")
            .and_then(|rest| rest.strip_suffix(".exe"))
            .unwrap();
        assert!(ms.parse::<u64>().is_ok(), "{name}");
        assert_eq!(states(&report, &Item::OldRelay), [&State::InUse]);
        let status = nm::status(&layout);
        assert_eq!(states(&status, &Item::OldRelay), [&State::Present]);
    } else {
        // Unix replaces the file in one rename; the running process keeps its inode.
        assert!(olds.is_empty(), "{olds:?}");
    }

    stop_stand_in(running);

    let newer = relay_source(tmp.path(), "relay-v3", b"relay v3");
    let report = nm::install(&layout, &newer, &daemon, &data).unwrap();
    assert_eq!(fs::read(&relay).unwrap(), b"relay v3");
    assert!(old_relays(&layout).is_empty());
    if cfg!(windows) {
        // The leftover of the previous install and the relay this install replaced.
        assert_eq!(
            states(&report, &Item::OldRelay),
            [&State::Removed, &State::Removed]
        );
    }
    assert!(nm::status(&layout).is_healthy());
}

#[test]
fn uninstall_removes_manifests_and_relay_keeps_data() {
    let tmp = TempDir::new().unwrap();
    let data = tmp.path().join("data");
    fs::create_dir_all(data.join("tls")).unwrap();
    fs::write(data.join("settings.json"), b"{}").unwrap();
    fs::write(data.join("tls").join("tls.json"), b"{}").unwrap();
    let layout = data_dir_layout(tmp.path(), &data);
    let src = relay_source(tmp.path(), "relay-src", b"relay");
    nm::install(&layout, &src, &tmp.path().join("openncalayer"), &data).unwrap();
    let manifests: Vec<PathBuf> = layout
        .manifests
        .iter()
        .map(|target| layout.manifest_path(target))
        .collect();
    assert!(manifests.iter().all(|path| path.is_file()));

    let report = nm::uninstall(&layout).unwrap();
    assert!(!layout.relay().exists());
    assert!(!layout.relay_config().exists());
    assert!(manifests.iter().all(|path| !path.exists()));
    // Other hosts may live in the manifest directories.
    assert!(layout.manifests.iter().all(|target| target.dir.is_dir()));
    assert_eq!(fs::read(data.join("settings.json")).unwrap(), b"{}");
    assert_eq!(fs::read(data.join("tls").join("tls.json")).unwrap(), b"{}");
    assert_eq!(states(&report, &Item::Relay), [&State::Removed]);
    assert_eq!(states(&report, &Item::RelayConfig), [&State::Removed]);
    for browser in ["Chromium", "Firefox"] {
        assert_eq!(
            states(&report, &Item::Manifest { browser }),
            [&State::Removed]
        );
    }

    // Temporary files of an interrupted install: status lists them, uninstall removes them.
    nm::install(&layout, &src, &tmp.path().join("openncalayer"), &data).unwrap();
    let mut temps = vec![
        with_suffix(&layout.relay(), ".new"),
        with_suffix(&layout.relay_config(), ".tmp"),
    ];
    temps.extend(manifests.iter().map(|path| with_suffix(path, ".tmp")));
    for temp in &temps {
        fs::write(temp, b"partial").unwrap();
    }
    let status = nm::status(&layout);
    assert_eq!(
        states(&status, &Item::TempFile),
        vec![&State::Present; temps.len()]
    );
    let report = nm::uninstall(&layout).unwrap();
    assert_eq!(
        states(&report, &Item::TempFile),
        vec![&State::Removed; temps.len()]
    );
    assert!(temps.iter().all(|temp| !temp.exists()));

    // Uninstalling again finds nothing and is no error.
    let again = nm::uninstall(&layout).unwrap();
    assert!(
        again
            .entries
            .iter()
            .all(|entry| entry.state == State::Missing),
        "{again:?}"
    );
}

fn openncalayer(data: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openncalayer"))
        .args(args)
        .env("ONCL_DATA_DIR", data)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn cli_installs_into_a_sandbox() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("sbx");
    let data = tmp.path().join("data");
    let src = relay_source(tmp.path(), "relay-src", b"relay");
    let sandbox = ["--sandbox".as_ref(), root.as_os_str()];
    let run = |args: &[&str]| {
        let mut all: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_ref()).collect();
        all.extend(sandbox);
        openncalayer(&data, &all)
    };

    let missing = tmp.path().join("missing");
    let out = run(&["nm", "install", "--relay", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!root.exists());

    let out = run(&["nm", "install", "--relay", src.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("записан"), "{stdout}");
    let layout = NmLayout::sandbox(&root);
    let config = read_json(&layout.relay_config());
    assert_eq!(config["data_dir"], data.to_str().unwrap());
    assert_eq!(
        fs::canonicalize(config["daemon"].as_str().unwrap()).unwrap(),
        fs::canonicalize(env!("CARGO_BIN_EXE_openncalayer")).unwrap()
    );
    assert_eq!(fs::read(layout.relay()).unwrap(), b"relay");

    let out = run(&["nm", "status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("на месте"), "{stdout}");

    let out = run(&["nm", "uninstall"]);
    assert!(out.status.success());
    assert!(!layout.relay().exists());

    let out = run(&["nm", "status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("отсутствует"));
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

#[test]
fn unwritable_manifest_dir_fails_only_that_browser() {
    let tmp = TempDir::new().unwrap();
    let data = tmp.path().join("data");
    let mut layout = data_dir_layout(tmp.path(), &data);
    // Present, but its manifest directory cannot be created: a file is in the way.
    let blocked = tmp.path().join("config").join("blocked");
    fs::create_dir_all(&blocked).unwrap();
    fs::write(blocked.join("file"), b"").unwrap();
    layout.manifests.insert(
        0,
        ManifestTarget {
            browser: "Blocked",
            family: Family::Chromium,
            dir: blocked.join("file").join("NativeMessagingHosts"),
            requires: vec![blocked.clone()],
        },
    );
    let src = relay_source(tmp.path(), "relay-src", b"relay");
    let report = nm::install(&layout, &src, &tmp.path().join("openncalayer"), &data).unwrap();
    assert!(report.has_errors());
    assert!(matches!(
        states(&report, &Item::Manifest { browser: "Blocked" })[..],
        [State::Invalid(_)]
    ));
    for browser in ["Chromium", "Firefox"] {
        assert_eq!(
            states(&report, &Item::Manifest { browser }),
            [&State::Written]
        );
    }

    // The CLI: the sandbox's Chromium directory is a file.
    let root = tmp.path().join("sbx");
    fs::create_dir_all(root.join("chromium")).unwrap();
    fs::write(root.join("chromium").join("NativeMessagingHosts"), b"").unwrap();
    let out = openncalayer(
        &data,
        &[
            "nm".as_ref(),
            "install".as_ref(),
            "--relay".as_ref(),
            src.as_os_str(),
            "--sandbox".as_ref(),
            root.as_os_str(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.contains("ошибка"), "{stdout}");
    assert!(stderr.contains("Не все браузеры"), "{stderr}");
    let sandbox = NmLayout::sandbox(&root);
    assert!(sandbox.manifest_path(&sandbox.manifests[1]).is_file());
}

#[test]
fn install_refuses_non_utf8_paths() {
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(b"sbx-\xff".to_vec())
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        // An unpaired surrogate.
        std::ffi::OsString::from_wide(&[u16::from(b's'), 0xD800])
    };
    let tmp = TempDir::new().unwrap();
    let src = relay_source(tmp.path(), "relay-src", b"relay");
    let daemon = tmp.path().join("openncalayer");
    let data = tmp.path().join("data");

    let root = tmp.path().join(&name);
    let err = nm::install(&NmLayout::sandbox(&root), &src, &daemon, &data).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    let err = nm::install(
        &NmLayout::sandbox(&tmp.path().join("sbx")),
        &src,
        &daemon,
        &tmp.path().join(&name),
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    let names: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["relay-src"], "nothing is created");
}

/// A running relay, current or replaced, keeps uninstall from finishing on Windows; the
/// rest is removed and the user is told to close the browser.
#[test]
fn cli_uninstall_with_running_relay_asks_to_close_the_browser() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("sbx");
    let data = tmp.path().join("data");
    let layout = NmLayout::sandbox(&root);
    let this = std::env::current_exe().unwrap();
    let uninstall = || {
        openncalayer(
            &data,
            &[
                "nm".as_ref(),
                "uninstall".as_ref(),
                "--sandbox".as_ref(),
                root.as_os_str(),
            ],
        )
    };
    let manifests_gone = || {
        layout
            .manifests
            .iter()
            .all(|target| !layout.manifest_path(target).exists())
    };
    const HINT: &str = "закройте браузер";

    // The current relay runs.
    nm::install(&layout, &this, &this, &data).unwrap();
    let running = run_stand_in(&layout.relay());
    let out = uninstall();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(manifests_gone());
    assert!(!layout.relay_config().exists());
    if cfg!(windows) {
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains(HINT), "{stderr}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("занят"));
        assert!(layout.relay().exists());
    } else {
        assert!(out.status.success(), "{stderr}");
        assert!(!layout.relay().exists());
    }

    // A replaced relay runs (Windows: renamed to `nmhost.old-*`).
    let src = relay_source(tmp.path(), "relay-v2", b"relay v2");
    nm::install(&layout, &src, &this, &data).unwrap();
    let out = uninstall();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(manifests_gone() && !layout.relay().exists());
    if cfg!(windows) {
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains(HINT), "{stderr}");
        assert_eq!(old_relays(&layout).len(), 1);
    } else {
        assert!(out.status.success(), "{stderr}");
    }

    stop_stand_in(running);
    let out = uninstall();
    assert!(out.status.success());
    assert!(old_relays(&layout).is_empty());
}
