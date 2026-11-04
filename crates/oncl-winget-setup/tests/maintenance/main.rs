//! The installer entry: the Windows behaviour tests against real processes live in
//! `windows.rs`; elsewhere the entry must say that it is unavailable, never pretend to install.

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod elsewhere {
    use std::process::Command;

    use oncl_winget_setup::{Config, Exit, run};

    const ENTRY: &str = env!("CARGO_BIN_EXE_oncl-winget-setup");

    #[test]
    fn off_windows_the_installer_says_so_and_installs_nothing() {
        let output = Command::new(ENTRY).arg("--silent").output().unwrap();
        assert_eq!(output.status.code(), Some(Exit::Unsupported as i32));
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains("Windows only"), "{message}");
    }

    #[test]
    fn off_windows_run_reports_platform_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            image: dir.path().join("entry"),
            install_root: dir.path().join("root"),
            arp_key: String::new(),
            endpoint: oncl_ipc::maintenance::endpoint(dir.path()).unwrap(),
            wait: std::time::Duration::ZERO,
            poll: std::time::Duration::ZERO,
            setup_timeout: std::time::Duration::ZERO,
            temp_root: dir.path().to_owned(),
            elevation: || Ok(false),
            before_setup_check: None,
        };
        let report = run(&config);
        assert_eq!(report.exit, Exit::Unsupported);
        assert!(!dir.path().join("root").exists(), "nothing is written");
    }
}
