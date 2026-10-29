use std::fs;

use oncl_desktop::original::{EntryState, original_autostart};
use oncl_desktop::{AutostartPaths, FileAutostart, Settings};
use serde_json::{Value, json};

use super::*;

/// A user's desktop in a sandbox under `root`: the data directory `root/data`, the browsers'
/// native messaging places under `root/nm`, the XDG autostart directory and the original's
/// Startup folder and desktop entry of the sandbox, and the program `root/<bin>/openncalayer`
/// with its relay.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(root: &Path) -> Sandbox {
        // The sandbox's browsers are there once its root exists.
        fs::create_dir_all(root.join("nm")).unwrap();
        let sandbox = Sandbox {
            root: root.to_owned(),
        };
        sandbox.program("bin");
        sandbox
    }

    /// The program and its relay in `root/<bin>`.
    fn program(&self, bin: &str) -> Executables {
        let dir = std::path::absolute(self.root.join(bin)).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let relay = dir.join(nm::relay_file_name());
        fs::write(&relay, format!("relay of {bin}")).unwrap();
        let program = dir.join("openncalayer");
        fs::write(&program, b"daemon").unwrap();
        Executables { program, relay }
    }

    fn integration(&self, bin: &str, version: &str) -> Integration {
        Integration {
            paths: Paths {
                data: self.root.join("data"),
            },
            executables: self.program(bin),
            version: version.to_owned(),
            nm: NmLayout::sandbox(&self.root.join("nm")),
            autostart: Box::new(FileAutostart::desktop_entry(&self.autostart_paths())),
            original: OriginalLocations::sandbox(&self.root.join("orig")),
        }
    }

    fn autostart_paths(&self) -> AutostartPaths {
        AutostartPaths::sandbox(&self.root.join("home"))
    }

    fn our_entry(&self) -> PathBuf {
        self.autostart_paths().desktop_entry()
    }

    /// The original's Startup shortcut.
    fn shortcut(&self) -> PathBuf {
        self.root.join("orig").join("Startup").join("NCALayer.lnk")
    }

    /// The original's XDG autostart entry.
    fn desktop_entry(&self) -> PathBuf {
        self.root
            .join("orig")
            .join(".config")
            .join("autostart")
            .join("ncalayer.desktop")
    }

    /// The original as its installer leaves it: a Startup shortcut and a desktop entry.
    fn original_installed(&self) {
        fs::create_dir_all(self.shortcut().parent().unwrap()).unwrap();
        fs::write(self.shortcut(), b"shortcut bytes").unwrap();
        fs::create_dir_all(self.desktop_entry().parent().unwrap()).unwrap();
        fs::write(
            self.desktop_entry(),
            "[Desktop Entry]\nType=Application\nExec=/opt/ncalayer/ncalayer.sh\n",
        )
        .unwrap();
    }

    /// The user's data: settings, a TLS file and a log.
    fn user_data(&self) {
        let data = self.root.join("data");
        fs::create_dir_all(data.join("tls")).unwrap();
        fs::create_dir_all(data.join("logs")).unwrap();
        fs::write(
            data.join("settings.json"),
            r#"{"recentPath": "C:/keys/a.p12", "proxy": {"mode": "system"}}"#,
        )
        .unwrap();
        fs::write(data.join("tls").join("server.pem"), b"certificate").unwrap();
        fs::write(data.join("logs").join("openncalayer.log"), b"log").unwrap();
    }

    /// Our autostart entry as it is written for `program`.
    fn entry_for(&self, program: &Path) -> String {
        let other = self.root.join("expected");
        let autostart = FileAutostart::desktop_entry(&AutostartPaths::sandbox(&other));
        autostart.set(true, program).unwrap();
        fs::read_to_string(autostart.path()).unwrap()
    }

    fn settings(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("data").join("settings.json")).unwrap())
            .unwrap()
    }

    /// The original's entries and their states.
    fn original_states(&self, integration: &Integration) -> Vec<EntryState> {
        original_autostart(&integration.original, &integration.journal())
            .entries
            .into_iter()
            .map(|e| e.state)
            .collect()
    }

    /// The daemon the installed relay starts.
    fn relay_daemon(&self, integration: &Integration) -> PathBuf {
        let config: Value =
            serde_json::from_slice(&fs::read(integration.nm.relay_config()).unwrap()).unwrap();
        PathBuf::from(config["daemon"].as_str().unwrap())
    }

    /// The files in the original's store next to the journal.
    fn stored(&self) -> Vec<String> {
        let dir = self.root.join("data").join("original-autostart");
        let mut names: Vec<String> = match fs::read_dir(dir) {
            Ok(entries) => entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }
}

fn steps(outcome: &Outcome) -> Vec<Step> {
    outcome.steps.iter().map(|(step, _)| *step).collect()
}

/// An autostart that cannot be read or changed.
struct Broken;

impl Autostart for Broken {
    fn enabled(&self) -> io::Result<bool> {
        Err(io::Error::other("the autostart is broken"))
    }

    fn set(&self, _: bool, _: &Path) -> io::Result<()> {
        Err(io::Error::other("the autostart is broken"))
    }
}

#[test]
fn install_integrates_this_user_and_repeats_as_a_repair() {
    let dir = tempfile::tempdir().unwrap();
    let s = Sandbox::new(dir.path());
    s.original_installed();
    s.user_data();
    let i = s.integration("bin", "1.0.0");
    assert_eq!(
        i.due_at_start(&Installation::Velopack),
        Some(Event::Install)
    );
    assert_eq!(i.due_at_start(&Installation::Portable), None);

    let outcome = i.run(Event::Install);
    assert!(outcome.succeeded(), "{outcome:?}");
    assert_eq!(
        steps(&outcome),
        [
            Step::RegisterRelay,
            Step::EnableAutostart,
            Step::DisableOriginal,
            Step::SaveRecord
        ]
    );
    // The relay for this program and data directory.
    assert!(nm::status(&i.nm).is_healthy());
    assert_eq!(s.relay_daemon(&i), i.executables.program);
    // Our autostart, in the entry and in settings.json; the user's keys stay.
    assert!(i.autostart.enabled().unwrap());
    assert_eq!(
        fs::read_to_string(s.our_entry()).unwrap(),
        s.entry_for(&i.executables.program)
    );
    assert_eq!(
        s.settings(),
        json!({"recentPath": "C:/keys/a.p12", "proxy": {"mode": "system"}, "autostart": true})
    );
    // The original's entries disabled by us, not removed.
    assert!(!s.shortcut().exists());
    assert_eq!(
        s.original_states(&i),
        [EntryState::DisabledByUs, EntryState::DisabledByUs]
    );
    assert_eq!(s.stored(), ["NCALayer.lnk", "ncalayer.desktop"]);
    assert_eq!(
        i.record().unwrap(),
        Some(Record {
            program: i.executables.program.clone(),
            version: "1.0.0".to_owned()
        })
    );
    assert_eq!(i.due_at_start(&Installation::Velopack), None);

    // Again (Setup.exe run a second time): the same result, nothing moved twice.
    let again = i.run(Event::Install);
    assert!(again.succeeded(), "{again:?}");
    assert_eq!(s.stored(), ["NCALayer.lnk", "ncalayer.desktop"]);
    assert_eq!(
        s.original_states(&i),
        [EntryState::DisabledByUs, EntryState::DisabledByUs]
    );
    assert!(nm::status(&i.nm).is_healthy());
    // Data is never touched.
    assert_eq!(
        fs::read(dir.path().join("data/tls/server.pem")).unwrap(),
        b"certificate"
    );
}

#[test]
fn an_install_killed_midway_is_finished_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let s = Sandbox::new(dir.path());
    s.original_installed();
    let i = s.integration("bin", "1.0.0");
    // Killed after the relay (Velopack's 30-second limit, a crash): nothing recorded.
    i.register_relay().unwrap();
    assert_eq!(
        i.due_at_start(&Installation::Velopack),
        Some(Event::Install)
    );
    let (event, outcome) = i.at_start(&Installation::Velopack).unwrap();
    assert_eq!(event, Event::Install);
    assert!(outcome.succeeded(), "{outcome:?}");
    assert!(i.autostart.enabled().unwrap());
    assert!(!s.shortcut().exists());
    assert_eq!(i.at_start(&Installation::Velopack).map(|(e, _)| e), None);
    // A record that is not one does not stop it either.
    fs::write(i.record_path(), b"{not json").unwrap();
    assert_eq!(
        i.due_at_start(&Installation::PackageManager("pacman".into())),
        Some(Event::Install)
    );
}

#[test]
fn update_refreshes_what_the_user_kept_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let s = Sandbox::new(dir.path());
    s.original_installed();
    let old = s.integration("bin", "1.0.0");
    assert!(old.run(Event::Install).succeeded());

    // The user puts the original back and turns our autostart off, as the settings window
    // does («Вернуть оригинал»).
    restore_original(&old.original, &old.journal()).unwrap();
    old.autostart.set(false, &old.executables.program).unwrap();
    oncl_desktop::settings::set_autostart(&old.paths.settings(), false).unwrap();

    // A new version in another place (an AppImage moved, a new bundle).
    let new = s.integration("bin2", "1.1.0");
    assert_eq!(
        new.due_at_start(&Installation::Velopack),
        Some(Event::Update)
    );
    let outcome = new.run(Event::Update);
    assert!(outcome.succeeded(), "{outcome:?}");
    assert_eq!(
        steps(&outcome),
        [Step::RefreshRelay, Step::AutostartLeftOff, Step::SaveRecord]
    );
    // The relay copied again from the new version, for the new program.
    assert_eq!(s.relay_daemon(&new), new.executables.program);
    assert_eq!(fs::read(new.nm.relay()).unwrap(), b"relay of bin2");
    // The user's choices stay: the original enabled, ours off.
    assert!(s.shortcut().exists());
    assert_eq!(
        s.original_states(&new),
        [EntryState::Enabled, EntryState::Enabled]
    );
    assert!(!new.autostart.enabled().unwrap());
    assert!(!Settings::load(&new.paths.settings()).unwrap().autostart);
    assert_eq!(
        new.record().unwrap().unwrap(),
        Record {
            program: new.executables.program.clone(),
            version: "1.1.0".to_owned()
        }
    );

    // Our autostart on: rewritten for the program; a relay the user unregistered stays off.
    new.autostart.set(true, &old.executables.program).unwrap();
    nm::uninstall(&new.nm).unwrap();
    let newer = s.integration("bin3", "1.2.0");
    let outcome = newer.run(Event::Update);
    assert!(outcome.succeeded(), "{outcome:?}");
    assert_eq!(
        steps(&outcome),
        [Step::RelayLeftOff, Step::RefreshAutostart, Step::SaveRecord]
    );
    assert!(!newer.nm.relay().exists() && !newer.nm.relay_config().exists());
    assert_eq!(
        fs::read_to_string(s.our_entry()).unwrap(),
        s.entry_for(&newer.executables.program)
    );
}

#[test]
fn uninstall_removes_only_ours_and_keeps_the_data() {
    let dir = tempfile::tempdir().unwrap();
    let s = Sandbox::new(dir.path());
    s.original_installed();
    s.user_data();
    let i = s.integration("bin", "1.0.0");
    assert!(i.run(Event::Install).succeeded());
    // Others' files next to ours.
    let other_manifest = i.nm.manifests[0].dir.join("org.example.other.json");
    fs::write(&other_manifest, b"{}").unwrap();
    let other_entry = s.our_entry().with_file_name("other.desktop");
    fs::write(&other_entry, b"[Desktop Entry]\n").unwrap();

    let outcome = i.run(Event::Uninstall);
    assert!(outcome.succeeded(), "{outcome:?}");
    assert_eq!(
        steps(&outcome),
        [
            Step::UnregisterRelay,
            Step::RemoveAutostart,
            Step::RestoreOriginal,
            Step::RemoveRecord
        ]
    );
    // Ours gone.
    assert!(!i.nm.relay().exists() && !i.nm.relay_config().exists());
    for target in &i.nm.manifests {
        assert!(!i.nm.manifest_path(target).exists());
    }
    assert!(!s.our_entry().exists());
    assert_eq!(i.record().unwrap(), None);
    // Theirs stay, the original is back as it was.
    assert!(other_manifest.exists() && other_entry.exists());
    assert_eq!(fs::read(s.shortcut()).unwrap(), b"shortcut bytes");
    assert_eq!(
        fs::read_to_string(s.desktop_entry()).unwrap(),
        "[Desktop Entry]\nType=Application\nExec=/opt/ncalayer/ncalayer.sh\n"
    );
    assert!(!i.journal().exists());
    // The data stays: settings (the autostart key as installing left it), TLS, logs.
    assert_eq!(s.settings()["recentPath"], "C:/keys/a.p12");
    let data = dir.path().join("data");
    assert_eq!(
        fs::read(data.join("tls/server.pem")).unwrap(),
        b"certificate"
    );
    assert!(data.join("logs/openncalayer.log").exists());

    // Twice: nothing left to do, still a success.
    assert!(i.run(Event::Uninstall).succeeded());
}

#[test]
fn a_failed_step_fails_the_event_and_the_others_still_run() {
    let dir = tempfile::tempdir().unwrap();
    let s = Sandbox::new(dir.path());
    s.original_installed();
    let mut i = s.integration("bin", "1.0.0");
    i.autostart = Box::new(Broken);

    let outcome = i.run(Event::Install);
    assert!(!outcome.succeeded());
    assert_eq!(
        outcome.failures().collect::<Vec<_>>(),
        [(Step::EnableAutostart, "the autostart is broken")]
    );
    // No record: the next start installs again. What could be done is done.
    assert_eq!(steps(&outcome).last(), Some(&Step::DisableOriginal));
    assert_eq!(i.record().unwrap(), None);
    assert!(nm::status(&i.nm).is_healthy());
    assert!(!s.shortcut().exists());

    // The next try with a working autostart finishes; nothing is moved twice.
    i.autostart = Box::new(FileAutostart::desktop_entry(&s.autostart_paths()));
    let (event, outcome) = i.at_start(&Installation::Velopack).unwrap();
    assert_eq!(event, Event::Install);
    assert!(outcome.succeeded(), "{outcome:?}");
    assert_eq!(s.stored(), ["NCALayer.lnk", "ncalayer.desktop"]);

    // Uninstall with a broken autostart: the relay and the original are still handled,
    // the record stays.
    i.autostart = Box::new(Broken);
    let outcome = i.run(Event::Uninstall);
    assert_eq!(
        outcome.failures().map(|(step, _)| step).collect::<Vec<_>>(),
        [Step::RemoveAutostart]
    );
    assert!(!i.nm.relay().exists());
    assert!(s.shortcut().exists());
    assert!(i.record().unwrap().is_some());

    // An update whose autostart cannot be read fails, and keeps the old record.
    let outcome = s.integration("bin2", "2.0.0");
    let update = Integration {
        autostart: Box::new(Broken),
        ..outcome
    };
    let result = update.run(Event::Update);
    assert!(!result.succeeded());
    assert_eq!(update.record().unwrap().unwrap().version, "1.0.0");
}

#[test]
fn a_missing_relay_fails_the_install() {
    let dir = tempfile::tempdir().unwrap();
    let s = Sandbox::new(dir.path());
    let i = s.integration("bin", "1.0.0");
    fs::remove_file(&i.executables.relay).unwrap();
    let outcome = i.run(Event::Install);
    let failures: Vec<_> = outcome.failures().collect();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].0, Step::RegisterRelay);
    assert!(
        failures[0].1.contains("the relay is missing"),
        "{failures:?}"
    );
    assert_eq!(exit_code(&outcome), ExitCode::FAILURE);
}

#[test]
fn the_program_of_an_appimage_is_the_image() {
    let dir = tempfile::tempdir().unwrap();
    let image = std::path::absolute(dir.path().join("OpenNCALayer.AppImage")).unwrap();
    fs::write(&image, b"image").unwrap();
    let appdir = std::path::absolute(dir.path().join("mount_x")).unwrap();
    let exe = appdir.join("usr").join("bin").join("openncalayer");
    let env = |appdir: &Path, image: &Path| {
        let (appdir, image) = (appdir.as_os_str().to_owned(), image.as_os_str().to_owned());
        move |name: &str| match name {
            "APPDIR" => Some(appdir.clone()),
            "APPIMAGE" => Some(image.clone()),
            _ => None,
        }
    };
    assert_eq!(appimage_of(&exe, env(&appdir, &image)), Some(image.clone()));
    // Inherited variables of another AppImage do not count for a program outside it.
    let elsewhere = std::path::absolute(dir.path().join("bin").join("openncalayer")).unwrap();
    assert_eq!(appimage_of(&elsewhere, env(&appdir, &image)), None);
    // Nor a relative or missing image.
    assert_eq!(
        appimage_of(&exe, env(&appdir, Path::new("OpenNCALayer.AppImage"))),
        None
    );
    assert_eq!(
        appimage_of(&exe, env(&appdir, &dir.path().join("gone.AppImage"))),
        None
    );
    assert_eq!(appimage_of(&exe, |_| None), None);

    let executables = executables_of(exe.clone(), env(&appdir, &image));
    assert_eq!(executables.relay, exe.with_file_name(nm::relay_file_name()));
    let expected = if cfg!(target_os = "linux") {
        image
    } else {
        exe
    };
    assert_eq!(executables.program, expected);
}

#[test]
fn a_package_manager_is_named_next_to_the_program() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("openncalayer");
    assert_eq!(package_manager(&exe), None);
    let file = dir.path().join(PACKAGE_MANAGER_FILE);
    fs::write(&file, b"pacman\n").unwrap();
    assert_eq!(package_manager(&exe).as_deref(), Some("pacman"));
    assert_eq!(
        Installation::detect(&exe),
        Installation::PackageManager("pacman".to_owned())
    );
    for bad in [&b""[..], b"\n", b"  \nx", b"pac\x07man"] {
        fs::write(&file, bad).unwrap();
        assert_eq!(package_manager(&exe), None, "{bad:?}");
    }
    // This test program is neither a package manager's nor Velopack's.
    let me = std::env::current_exe().unwrap();
    assert_eq!(Installation::detect(&me), Installation::Portable);
    assert_eq!(Installation::Portable.package_manager(), None);
}
