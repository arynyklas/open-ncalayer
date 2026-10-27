//! What the settings window and the TLS wizard work with in the daemon: the browser
//! extension's registration through `openncalayer nm` ([`NmExtension`]),
//! [`settings_services`] and [`tls_wizard_services`] for this user.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oncl_desktop::{
    Autostart, BrowserExtension, ExtensionError, ExtensionStatus, OriginalLocations,
    OriginalNcaLayer,
};
use oncl_tls::{SelftestReports, TlsFiles};
use oncl_ui::SettingsServices;
use oncl_ui::tls_wizard::{SystemTrust, TlsWizardServices};

use crate::nm::{self, Item, NmLayout, Report, State};
use crate::wss::Wss;
use crate::{Paths, cli};

/// The native messaging host as `openncalayer nm install|uninstall|status` handles it: the
/// relay `relay` (next to the daemon) installed for the daemon `daemon` with the data
/// directory `data_dir`.
pub struct NmExtension {
    /// The layout of this user, or why it is unknown.
    layout: Result<NmLayout, String>,
    relay: PathBuf,
    daemon: PathBuf,
    data_dir: PathBuf,
}

impl NmExtension {
    /// The host in `layout`, or nowhere (every action fails with the message) if the layout
    /// is unknown.
    pub fn new(
        layout: Result<NmLayout, String>,
        relay: PathBuf,
        daemon: PathBuf,
        data_dir: PathBuf,
    ) -> NmExtension {
        NmExtension {
            layout,
            relay,
            daemon,
            data_dir,
        }
    }

    fn layout(&self) -> io::Result<&NmLayout> {
        self.layout
            .as_ref()
            .map_err(|e| io::Error::other(e.clone()))
    }
}

impl BrowserExtension for NmExtension {
    fn status(&self) -> ExtensionStatus {
        match &self.layout {
            Ok(layout) => extension_status(&nm::status(layout)),
            Err(_) => ExtensionStatus::default(),
        }
    }

    fn register(&self) -> Result<ExtensionStatus, ExtensionError> {
        let layout = self.layout()?;
        if !self.relay.is_file() {
            return Err(ExtensionError::RelayMissing(self.relay.clone()));
        }
        let report = nm::install(layout, &self.relay, &self.daemon, &self.data_dir)?;
        failures(&report)?;
        Ok(self.status())
    }

    fn unregister(&self) -> Result<ExtensionStatus, ExtensionError> {
        let report = nm::uninstall(self.layout()?)?;
        if report.has_in_use() {
            return Err(ExtensionError::RelayInUse);
        }
        failures(&report)?;
        Ok(self.status())
    }
}

/// The failed entries of `report` as one error, if any.
fn failures(report: &Report) -> io::Result<()> {
    let failed: Vec<String> = report
        .entries
        .iter()
        .filter_map(|e| match &e.state {
            State::Invalid(why) => Some(format!("{}: {why}", e.location)),
            _ => None,
        })
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failed.join("; ")))
    }
}

/// The window's view of an `nm status` report.
fn extension_status(report: &Report) -> ExtensionStatus {
    let present = |item: &Item| {
        report
            .entries
            .iter()
            .any(|e| e.item == *item && e.state == State::Present)
    };
    let mut browsers: Vec<String> = Vec::new();
    for entry in &report.entries {
        if let Item::Manifest { browser } = entry.item
            && entry.state == State::Present
            && !browsers.iter().any(|b| b == browser)
        {
            browsers.push(browser.to_owned());
        }
    }
    let any_present = report.entries.iter().any(|e| e.state == State::Present);
    ExtensionStatus {
        installed: present(&Item::Relay) && present(&Item::RelayConfig),
        browsers,
        broken: any_present && !report.is_healthy(),
    }
}

/// An autostart that cannot be read or changed, and why.
struct NoAutostart(String);

impl Autostart for NoAutostart {
    fn enabled(&self) -> io::Result<bool> {
        Err(io::Error::other(self.0.clone()))
    }

    fn set(&self, _: bool, _: &Path) -> io::Result<()> {
        Err(io::Error::other(self.0.clone()))
    }
}

/// The settings window's services for this user and the daemon `exe` with the data
/// directory of `paths`: the original NCALayer of this user, its journal
/// `<data>/original-autostart.json`, and wss's `port` to tell who holds it.
pub fn settings_services(paths: &Paths, exe: PathBuf, port: u16) -> SettingsServices {
    let autostart = oncl_desktop::autostart::current_user().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "the autostart entry is unknown");
        Box::new(NoAutostart(e.to_string()))
    });
    let layout = NmLayout::detect(paths).map_err(|e| {
        tracing::warn!(error = %e, "the native messaging host's place is unknown");
        e.to_string()
    });
    let extension = NmExtension::new(
        layout,
        exe.with_file_name(nm::relay_file_name()),
        exe.clone(),
        paths.data.clone(),
    );
    let original = OriginalNcaLayer::new(
        OriginalLocations::detect(),
        paths.data.join(ORIGINAL_JOURNAL),
        port,
    );
    SettingsServices {
        settings_path: paths.settings(),
        exe,
        autostart,
        original: Box::new(original),
        extension: Box::new(extension),
    }
}

/// The journal of the original's autostart entries disabled by us, in the data directory.
pub const ORIGINAL_JOURNAL: &str = "original-autostart.json";

/// The TLS wizard's services for this user: the TLS files of `paths`, the trust stores of
/// this user ([`SystemTrust`]), mkcert's CA if there is one, the self-test `reports`. A
/// saved certificate goes to `wss` at once ([`Wss::reload`]: served, or wss started with
/// it); then `on_saved` runs with the files (on the wizard's worker thread).
pub fn tls_wizard_services(
    paths: &Paths,
    reports: Arc<SelftestReports>,
    wss: Arc<Wss>,
    on_saved: impl Fn(&TlsFiles) + Send + Sync + 'static,
) -> TlsWizardServices {
    let files = paths.tls();
    let saved = files.clone();
    TlsWizardServices {
        files,
        port: wss.port(),
        label: cli::label(),
        reports,
        trust: Box::new(SystemTrust),
        mkcert: Box::new(oncl_tls::mkcert_caroot),
        apply: Box::new(move || {
            let applied = wss.reload();
            on_saved(&saved);
            applied
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The extension in a sandbox under `root`: a fake relay and daemon in `root/bin`.
    fn sandboxed(root: &Path) -> NmExtension {
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let relay = bin.join(nm::relay_file_name());
        fs::write(&relay, b"relay").unwrap();
        let daemon = bin.join("openncalayer");
        fs::write(&daemon, b"daemon").unwrap();
        NmExtension::new(
            Ok(NmLayout::sandbox(&root.join("nm"))),
            relay,
            daemon,
            root.join("data"),
        )
    }

    #[test]
    fn register_and_unregister_in_a_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let ext = sandboxed(dir.path());
        // The sandbox's browsers are there once its root exists.
        fs::create_dir_all(dir.path().join("nm")).unwrap();
        assert_eq!(ext.status(), ExtensionStatus::default());

        let registered = ext.register().unwrap();
        assert_eq!(
            registered,
            ExtensionStatus {
                installed: true,
                browsers: vec!["Chromium".to_owned(), "Firefox".to_owned()],
                broken: false,
            }
        );
        assert_eq!(ext.status(), registered);

        // A manifest removed behind our back: partly there, so broken.
        let layout = NmLayout::sandbox(&dir.path().join("nm"));
        fs::remove_file(layout.manifest_path(&layout.manifests[1])).unwrap();
        let status = ext.status();
        assert!(status.installed && status.broken, "{status:?}");
        assert_eq!(status.browsers, ["Chromium"]);

        assert_eq!(ext.unregister().unwrap(), ExtensionStatus::default());
    }

    #[test]
    fn missing_relay_or_layout_fails_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut ext = sandboxed(dir.path());
        fs::remove_file(&ext.relay).unwrap();
        let relay = ext.relay.clone();
        assert!(matches!(ext.register(), Err(ExtensionError::RelayMissing(p)) if p == relay));
        assert!(!dir.path().join("nm").exists(), "nothing is installed");

        ext.layout = Err("HOME is not set".to_owned());
        assert_eq!(ext.status(), ExtensionStatus::default());
        match ext.unregister() {
            Err(ExtensionError::Io(e)) => assert_eq!(e.to_string(), "HOME is not set"),
            other => panic!("{other:?}"),
        }
    }
}
