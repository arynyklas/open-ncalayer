//! Screenshots of the settings and About windows without a display: Slint's software
//! renderer draws them into PNG files under `target/screenshots/`. The settings window shows
//! `target/screenshots/settings.json` and this user's autostart entry (read only); no button is
//! pressed.
//!
//! `cargo test -p oncl-ui --lib screenshots -- --ignored`

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use oncl_basics::Locale;
use oncl_desktop::original::Unavailable;
use oncl_desktop::{BrowserExtension, ExtensionStatus};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize, PlatformError, Rgb8Pixel};

use crate::about_view::{self, AboutInfo, AboutTab};
use crate::prompter::select_language;
use crate::settings_view::{self, SettingsServices};
use crate::ui::SettingsWindow;
use crate::windows::Desktop;

type Last = Rc<RefCell<Option<Rc<MinimalSoftwareWindow>>>>;

/// Windows drawn in memory; the last one created is kept for drawing.
struct Offscreen(Last);

impl Platform for Offscreen {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        self.0.replace(Some(Rc::clone(&window)));
        Ok(window)
    }
}

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

    fn register(&self) -> std::io::Result<ExtensionStatus> {
        unreachable!("no button is pressed")
    }

    fn unregister(&self) -> std::io::Result<ExtensionStatus> {
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
    let last = Last::default();
    slint::platform::set_platform(Box::new(Offscreen(Rc::clone(&last)))).unwrap();

    let services = SettingsServices {
        settings_path: out_dir().join("settings.json"),
        exe: std::env::current_exe().unwrap(),
        autostart: oncl_desktop::autostart::current_user().unwrap(),
        original: Box::new(Unavailable),
        extension: Box::new(Registered),
    };
    let snapshot = services.load();
    for (locale, code) in [(Locale::Ru, "ru"), (Locale::Kk, "kk"), (Locale::En, "en")] {
        let ui = SettingsWindow::new().unwrap();
        select_language(locale);
        settings_view::show_snapshot(&ui, &snapshot, locale);
        ui.show().unwrap();
        save(&last, 620, 820, &format!("settings-{code}"));
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
        on_saved: Box::new(|_| {}),
    });
    about_view::open(&desktop, AboutTab::Program);
    save(&last, 760, 640, "about-program");
    about_view::open(&desktop, AboutTab::Modules);
    save(&last, 760, 640, "about-modules");
    about_view::current().expect("the About window").set_tab(2);
    save(&last, 760, 640, "about-licences");
}
