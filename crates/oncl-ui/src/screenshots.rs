//! Screenshots of the settings, TLS wizard and About windows and of the key dialog and busy
//! indicator without a display: Slint's software renderer draws them into PNG files under
//! `target/screenshots/`. The settings window shows `target/screenshots/settings.json` and
//! this user's autostart entry (read only). The TLS wizard shows `target/screenshots/tls` (a
//! certificate is issued there if there is none) and this user's trust stores, read only;
//! its install question is shown without its button being pressed, and nothing is
//! installed. The key dialog shows made-up certificates. No button is pressed.
//!
//! `cargo test -p oncl-ui --lib screenshots -- --ignored`

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use oncl_basics::{Action, Availability, KeyCandidate, KeyPrompt, LiveAvailability, Locale};
use oncl_desktop::original::Unavailable;
use oncl_desktop::{BrowserExtension, ExtensionError, ExtensionStatus};
use oncl_pki::info::{CertInfo, KeyUsageBits};
use slint::{ComponentHandle, PhysicalSize, Rgb8Pixel};
use time::macros::datetime;

use crate::about_view::{self, AboutInfo, AboutTab};
use crate::offscreen::{self, Last};
use crate::prompter::{fill_keys, select_language, update_key};
use crate::settings_view::{self, SettingsServices};
use crate::tls_wizard::{self, Applied, IssueForm, Source, SystemTrust, TlsWizardServices};
use crate::ui::{BusyDialog, KeyDialog, SettingsWindow};
use crate::view;
use crate::windows::Desktop;

/// The extension as `nm status` shows it after registration in two browsers.
struct Registered;

impl BrowserExtension for Registered {
    fn status(&self) -> ExtensionStatus {
        ExtensionStatus {
            installed: true,
            browsers: vec!["Chrome".to_owned(), "Firefox".to_owned()],
            broken: false,
        }
    }

    fn register(&self) -> Result<ExtensionStatus, ExtensionError> {
        unreachable!("no button is pressed")
    }

    fn unregister(&self) -> Result<ExtensionStatus, ExtensionError> {
        unreachable!("no button is pressed")
    }
}

fn out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/screenshots")
}

/// Draws the last created window at `width` × `height` into `<out>/<name>.png`.
fn save(last: &Last, width: u32, height: u32, name: &str) {
    let window = last.borrow().clone().expect("a window");
    window.set_size(PhysicalSize::new(width, height));
    slint::platform::update_timers_and_animations();
    let mut pixels = vec![Rgb8Pixel::default(); (width * height) as usize];
    window.request_redraw();
    window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, width as usize);
    });
    let path = out_dir().join(format!("{name}.png"));
    let file = std::fs::File::create(&path).unwrap();
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let bytes: Vec<u8> = pixels.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&bytes)
        .unwrap();
    println!("{}", path.display());
}

#[test]
#[ignore = "writes screenshots to target/screenshots"]
fn screenshots() {
    std::fs::create_dir_all(out_dir()).unwrap();
    let last = offscreen::install();

    let services = SettingsServices {
        settings_path: out_dir().join("settings.json"),
        exe: std::env::current_exe().unwrap(),
        autostart: oncl_desktop::autostart::current_user().unwrap(),
        original: Box::new(Unavailable),
        extension: Box::new(Registered),
        updates: Box::new(settings_view::fakes::FakeUpdates {
            status: std::sync::Mutex::new(settings_view::UpdateStatus::UpToDate),
            found: settings_view::UpdateStatus::UpToDate,
        }),
    };
    let snapshot = services.load();
    for (locale, code) in [(Locale::Ru, "ru"), (Locale::Kk, "kk"), (Locale::En, "en")] {
        let ui = SettingsWindow::new().unwrap();
        select_language(locale);
        settings_view::show_snapshot(&ui, &snapshot, locale);
        ui.show().unwrap();
        save(&last, 620, 900, &format!("settings-{code}"));
        ui.hide().unwrap();
    }

    let bundles = [
        ("org.apache.felix.framework", "7.0.3"),
        ("kz.gov.pki.api.layer.NCALayerServices", "0.8.3"),
        ("kz.gov.pki.knca.applet.knca_applet", "0.4.13"),
        (
            "io.github.arynyklas.openncalayer",
            env!("CARGO_PKG_VERSION"),
        ),
    ];
    let desktop = Rc::new(Desktop {
        locale: Cell::new(Locale::Ru),
        settings: Arc::new(services),
        about: AboutInfo {
            commit: "0123456789ab".to_owned(),
            bundles: bundles.map(|(s, v)| (s.to_owned(), v.to_owned())).to_vec(),
            modules: [
                "kz.gov.pki.knca.applet.Applet",
                "kz.gov.pki.knca.basics",
                "kz.gov.pki.knca.commonUtils",
                "kz.gov.pki.ncalayerservices.accessory",
            ]
            .map(str::to_owned)
            .to_vec(),
        },
        tls: Arc::new(wizard_services()),
        plugins: Arc::new(Box::new(crate::plugins_view::fakes::FakePlugins::default())),
        on_saved: Box::new(|_| {}),
    });
    about_view::open(&desktop, AboutTab::Program);
    save(&last, 760, 640, "about-program");
    about_view::open(&desktop, AboutTab::Modules);
    save(&last, 760, 640, "about-modules");
    about_view::current().expect("the About window").set_tab(2);
    save(&last, 760, 640, "about-licences");

    // The TLS wizard: its four tabs, then the question an install button asks.
    if desktop.tls.load().info.unwrap_or_default().is_none() {
        let own = IssueForm {
            source: Source::Own,
            mkcert_consent: false,
            chain: String::new(),
            key: String::new(),
        };
        desktop
            .tls
            .issue(&own, time::OffsetDateTime::now_utc())
            .unwrap();
    }
    desktop.tls.reports.record(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
        time::OffsetDateTime::now_utc(),
    );
    for (locale, code) in [(Locale::Ru, "ru"), (Locale::En, "en")] {
        desktop.locale.set(locale);
        let ui = tls_wizard::open_loaded(&desktop);
        for (tab, name) in [(0, "status"), (1, "source"), (2, "install"), (3, "check")] {
            ui.set_tab(tab);
            save(&last, 760, 640, &format!("tls-{name}-{code}"));
        }
        ui.set_tab(1);
        ui.set_source(1);
        save(&last, 760, 640, &format!("tls-mkcert-{code}"));
        ui.set_tab(2);
        tls_wizard::preview_install_question(&desktop);
        save(&last, 760, 640, &format!("tls-confirm-{code}"));
        ui.invoke_cancel_confirm();
        ui.invoke_dismiss();
    }
}

#[test]
#[ignore = "writes screenshots to target/screenshots"]
fn key_dialog_screenshots() {
    std::fs::create_dir_all(out_dir()).unwrap();
    let last = offscreen::install();
    let info = |serial: &str| CertInfo {
        subject_cn: Some("ТЕСТОВ ТЕСТ".to_owned()),
        iin: Some("123456789011".to_owned()),
        bin: None,
        organization: None,
        serial_hex: serial.to_owned(),
        not_before: datetime!(2026-03-01 12:00 UTC),
        not_after: datetime!(2027-03-01 12:00 UTC),
        ext_key_usages: BTreeSet::new(),
        key_usage: KeyUsageBits::default(),
        signature_alg_oid: "1.2.398.3.10.1.1.2.3.2".to_owned(),
        spki_alg_oid: "1.2.398.3.10.1.1.2.3.2".to_owned(),
        ocsp_no_check: false,
    };
    let checked = [
        Availability::Enabled,
        Availability::Revoked {
            time: datetime!(2026-10-20 09:30 UTC),
        },
    ];
    for (locale, code) in [(Locale::Ru, "ru"), (Locale::Kk, "kk"), (Locale::En, "en")] {
        // Both keys still being checked.
        let p = KeyPrompt::new(
            "https://idp.egov.kz".to_owned(),
            locale,
            Action::Authenticate,
            [("auth", info("4105a0")), ("old", info("39c1f2"))]
                .map(|(alias, info)| (alias.to_owned(), info)),
            LiveAvailability::settled(vec![Availability::Pending; 2]),
        );
        let ui = KeyDialog::new().unwrap();
        select_language(locale);
        fill_keys(&ui, &p);
        ui.show().unwrap();
        save(&last, 560, 420, &format!("keys-pending-{code}"));
        // The checks end: the first key is good, the second revoked.
        for (i, availability) in checked.iter().enumerate() {
            let candidate = KeyCandidate {
                availability: availability.clone(),
                ..p.candidates[i].clone()
            };
            update_key(&ui, i, view::key_row(&candidate, locale));
        }
        save(&last, 560, 420, &format!("keys-revoked-{code}"));
        ui.hide().unwrap();

        let busy = BusyDialog::new().unwrap();
        busy.set_origin("https://idp.egov.kz".into());
        busy.show().unwrap();
        save(&last, 380, 110, &format!("busy-{code}"));
        busy.hide().unwrap();
    }
}

/// The wizard on `target/screenshots/tls` with this user's trust stores (read only here: no
/// button is pressed) and a server that is not running.
fn wizard_services() -> TlsWizardServices {
    TlsWizardServices {
        files: oncl_tls::TlsFiles {
            dir: out_dir().join("tls"),
        },
        port: 13579,
        label: "screenshots".to_owned(),
        reports: Arc::new(oncl_tls::SelftestReports::new()),
        trust: Box::new(SystemTrust),
        mkcert: Box::new(oncl_tls::mkcert_caroot),
        apply: Box::new(|| Applied::AfterRestart),
    }
}
