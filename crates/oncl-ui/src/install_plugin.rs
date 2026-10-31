//! «Установка плагина»: [`ask_install_plugin`] asks the user before a plugin is installed,
//! saying who asks (the page's origin as [`page_text`] cleans it), the installed plugin it
//! replaces, what it replaces of the original and what it may do, and warning about a
//! plugin that is not from the catalog. «Установить» is enabled only [`INSTALL_DELAY`]
//! after the window appears: a click or a key meant for another window does not install.
//! One window at a time; requests coming meanwhile wait their turn. Closing the window is
//! «Отмена». Its texts are composed here.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oncl_flows::Locale;
use oncl_flows::capabilities::{CapabilityLine, capability_text};
use slint::{
    CloseRequestResponse, ComponentHandle, ModelRc, PlatformError, SharedString, VecModel,
};

use crate::foreground;
use crate::plugins_view::{LocalizedText, ReplacedBundle};
use crate::prompter::select_desktop_language;
use crate::ui::InstallPluginWindow;
use crate::view::page_text;
use crate::windows::{self, Desktop};

/// How long after the window appears «Установить» is enabled.
pub const INSTALL_DELAY: Duration = Duration::from_millis(1500);

/// A plugin about to be installed, and what to do with the user's answer.
pub struct InstallPluginRequest {
    /// The page that asked for it, if one did.
    pub origin: Option<String>,
    pub name: LocalizedText,
    pub version: String,
    pub replaces: Option<ReplacedBundle>,
    /// The installed plugin of the same id it replaces, if any.
    pub replacing: Option<InstalledVersion>,
    /// What it may do.
    pub capabilities: Vec<CapabilityLine>,
    /// From a file the user chose, not from the catalog.
    pub local: bool,
    /// Called once with the answer (`true`: install), on a thread of its own: it may take
    /// its time.
    pub decide: Decide,
}

/// What takes the user's answer.
pub type Decide = Box<dyn FnOnce(bool) + Send>;

/// An installed plugin a new one replaces: its version and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledVersion {
    pub version: String,
    /// From a file the user chose, not from the catalog.
    pub local: bool,
}

/// The open window and the answer it waits for.
struct Open {
    ui: InstallPluginWindow,
    decide: RefCell<Option<Decide>>,
}

thread_local! {
    static OPEN: RefCell<Option<Rc<Open>>> = const { RefCell::new(None) };
    static WAITING: RefCell<VecDeque<InstallPluginRequest>> = const { RefCell::new(VecDeque::new()) };
}

/// Whether the window is open.
pub(crate) fn is_open() -> bool {
    OPEN.with_borrow(Option::is_some)
}

/// Asks the user whether to install `request`'s plugin, in the windows' language; callable
/// from any thread, returns at once. Without the daemon's windows it is declined.
pub fn ask_install_plugin(request: InstallPluginRequest) {
    let slot = Arc::new(Mutex::new(Some(request)));
    let taken = Arc::clone(&slot);
    let asked = slint::invoke_from_event_loop(move || {
        if let Some(request) = take(&taken) {
            enqueue(request);
        }
    });
    if let Err(e) = asked {
        tracing::info!(error = %e, "no windows: the plugin is not installed");
        if let Some(request) = take(&slot) {
            answer_with(request.decide, false);
        }
    }
}

fn take(slot: &Mutex<Option<InstallPluginRequest>>) -> Option<InstallPluginRequest> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// Shows `request` now, or once the window open is answered.
pub(crate) fn enqueue(request: InstallPluginRequest) {
    if windows::desktop().is_none() {
        tracing::info!("no windows: the plugin is not installed");
        answer_with(request.decide, false);
        return;
    }
    WAITING.with_borrow_mut(|waiting| waiting.push_back(request));
    if !is_open() {
        show_next();
    }
}

/// Shows the next request waiting, if any.
fn show_next() {
    let Some(desktop) = windows::desktop() else {
        return;
    };
    while let Some(request) = WAITING.with_borrow_mut(VecDeque::pop_front) {
        match create(&desktop, request) {
            Ok(()) => return,
            Err(e) => tracing::error!(error = %e, "cannot show the plugin installation window"),
        }
    }
}

/// The window of `request`; a window that cannot be shown declines it.
fn create(desktop: &Rc<Desktop>, request: InstallPluginRequest) -> Result<(), PlatformError> {
    let ui = match InstallPluginWindow::new() {
        Ok(ui) => ui,
        Err(e) => {
            answer_with(request.decide, false);
            return Err(e);
        }
    };
    let l = desktop.locale.get();
    select_desktop_language(l);
    let texts = texts(&request, l);
    ui.set_asker(texts.asker.into());
    ui.set_plugin(texts.plugin.into());
    ui.set_replacing(texts.replacing.into());
    ui.set_replaces(texts.replaces.into());
    ui.set_may(texts.may.into());
    let lines: Vec<SharedString> = texts.capabilities.into_iter().map(Into::into).collect();
    ui.set_capabilities(ModelRc::new(VecModel::from(lines)));
    ui.set_warning(texts.warning.into());
    ui.on_answer(answer);
    ui.window().on_close_requested(|| {
        answer(false);
        CloseRequestResponse::HideWindow
    });
    let open = Rc::new(Open {
        ui: ui.clone_strong(),
        decide: RefCell::new(Some(request.decide)),
    });
    OPEN.set(Some(Rc::clone(&open)));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        if let Some(decide) = open.decide.take() {
            answer_with(decide, false);
        }
        return Err(e);
    }
    foreground::take(&ui);
    let weak = ui.as_weak();
    slint::Timer::single_shot(INSTALL_DELAY, move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_can_install(true);
        }
    });
    Ok(())
}

/// «Установить» (`true`), «Отмена» or the close button: the window goes, the answer is
/// handed on, and the next request waiting is shown. «Установить» before
/// [`INSTALL_DELAY`] is over does nothing.
fn answer(yes: bool) {
    if yes && OPEN.with_borrow(|open| open.as_ref().is_some_and(|o| !o.ui.get_can_install())) {
        return;
    }
    let Some(open) = OPEN.take() else {
        return;
    };
    if let Err(e) = open.ui.hide() {
        tracing::warn!(error = %e, "cannot hide the plugin installation window");
    }
    if let Some(decide) = open.decide.take() {
        answer_with(decide, yes);
    }
    // This runs inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(open));
    show_next();
}

/// Hands `yes` to `decide` on a thread of its own: installing a plugin loads it.
fn answer_with(decide: Box<dyn FnOnce(bool) + Send>, yes: bool) {
    let spawned = std::thread::Builder::new()
        .name("plugin-install".into())
        .spawn(move || decide(yes));
    if let Err(e) = spawned {
        tracing::error!(error = %e, "cannot start a thread: the plugin is not installed");
    }
}

/// The window's texts for `request` in `l`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowTexts {
    asker: String,
    plugin: String,
    replacing: String,
    replaces: String,
    may: String,
    capabilities: Vec<String>,
    warning: String,
}

fn texts(request: &InstallPluginRequest, l: Locale) -> WindowTexts {
    let t = Texts::of(l);
    WindowTexts {
        asker: request
            .origin
            .as_ref()
            .map(|origin| t.asker.replace("{0}", &page_text(origin)))
            .unwrap_or_default(),
        plugin: t
            .plugin
            .replace("{name}", request.name.get(l))
            .replace("{version}", &request.version),
        replacing: request
            .replacing
            .as_ref()
            .map(|installed| {
                t.replacing
                    .replace("{version}", &installed.version)
                    .replace(
                        "{source}",
                        if installed.local {
                            t.installed_local
                        } else {
                            t.installed_catalog
                        },
                    )
            })
            .unwrap_or_default(),
        replaces: request
            .replaces
            .as_ref()
            .map(|r| {
                t.replaces
                    .replace("{symname}", &r.symname)
                    .replace("{version}", &r.version)
            })
            .unwrap_or_default(),
        may: if request.capabilities.is_empty() {
            t.nothing.to_owned()
        } else {
            t.may.to_owned()
        },
        capabilities: request
            .capabilities
            .iter()
            .map(|c| capability_text(c, l))
            .collect(),
        warning: if request.local {
            t.local.to_owned()
        } else {
            String::new()
        },
    }
}

/// The texts of the window, in one language.
struct Texts {
    /// `{0}`: the page's origin.
    asker: &'static str,
    /// `{name}`, `{version}`.
    plugin: &'static str,
    /// `{version}`, `{source}`: [`Texts::installed_local`] or [`Texts::installed_catalog`].
    replacing: &'static str,
    installed_local: &'static str,
    installed_catalog: &'static str,
    /// `{symname}`, `{version}`.
    replaces: &'static str,
    may: &'static str,
    nothing: &'static str,
    local: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                asker: "{0} сайты плагинді орнатуды сұрайды",
                plugin: "{name}, {version} нұсқасы",
                replacing: "Орнатылған {version} нұсқасын ({source}) алмастырады",
                installed_local: "жергілікті, файлдан",
                installed_catalog: "каталогтан",
                replaces: "Түпнұсқа NCALayer-дің {symname} {version} бандлын алмастырады",
                may: "Плагин мыналарды істей алады:",
                nothing: "Плагин сайттардың сұрауларына ғана жауап береді.",
                local: "Бұл плагин OpenNCALayer каталогында жоқ, оны мейнтейнер тексерген жоқ. Плагиндерді тек сенімді көзден орнатыңыз.",
            },
            Locale::Ru => &Texts {
                asker: "Сайт {0} просит установить плагин",
                plugin: "{name}, версия {version}",
                replacing: "Заменит установленную версию {version} ({source})",
                installed_local: "локальную, из файла",
                installed_catalog: "из каталога",
                replaces: "Заменяет {symname} {version} оригинального NCALayer",
                may: "Плагин сможет:",
                nothing: "Плагин будет только отвечать на запросы сайтов.",
                local: "Этого плагина нет в каталоге OpenNCALayer, его не проверял мейнтейнер. Устанавливайте только плагины из источника, которому доверяете.",
            },
            Locale::En => &Texts {
                asker: "The site {0} asks to install a plugin",
                plugin: "{name}, version {version}",
                replacing: "Replaces the installed version {version} ({source})",
                installed_local: "local, from a file",
                installed_catalog: "from the catalog",
                replaces: "Replaces {symname} {version} of the original NCALayer",
                may: "The plugin will be able to:",
                nothing: "The plugin will only answer the sites' requests.",
                local: "This plugin is not in the OpenNCALayer catalog; the maintainer has not reviewed it. Install plugins only from a source you trust.",
            },
        }
    }
}

/// The window on the offscreen platform of the tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins_view::fakes::FakePlugins;
    use crate::settings_view::fakes::{FakeOriginal, services};
    use crate::windows::{DesktopWindows, set_desktop_windows};
    use crate::{AboutInfo, offscreen};
    use slint::Model;
    use std::sync::mpsc::{Receiver, channel};

    fn desktop(root: &std::path::Path, locale: Locale) {
        offscreen::install();
        set_desktop_windows(DesktopWindows {
            locale,
            settings: services(root, FakeOriginal::default()),
            about: AboutInfo::default(),
            tls: crate::tls_wizard::fakes::services(root, Vec::new(), None),
            plugins: Box::new(FakePlugins::default()),
            on_saved: Box::new(|_: &oncl_desktop::Settings| {}),
        });
    }

    fn request(local: bool, origin: Option<&str>) -> (InstallPluginRequest, Receiver<bool>) {
        let (tx, rx) = channel();
        let request = InstallPluginRequest {
            origin: origin.map(str::to_owned),
            name: LocalizedText {
                ru: "Пример плагина".to_owned(),
                kk: "Плагин үлгісі".to_owned(),
                en: "Example plugin".to_owned(),
            },
            version: "0.1.0".to_owned(),
            replaces: Some(ReplacedBundle {
                symname: "kz.example.echo".to_owned(),
                version: "1.0.0".to_owned(),
            }),
            replacing: None,
            capabilities: vec![
                CapabilityLine::Keys,
                CapabilityLine::Dialogs,
                CapabilityLine::Files,
                CapabilityLine::Http(vec!["https://example.invalid/".to_owned()]),
            ],
            local,
            decide: Box::new(move |yes| tx.send(yes).unwrap()),
        };
        (request, rx)
    }

    fn the_window() -> InstallPluginWindow {
        OPEN.with_borrow(|open| open.as_ref().expect("the window is open").ui.clone_strong())
    }

    fn answered(rx: &Receiver<bool>) -> bool {
        rx.recv_timeout(Duration::from_secs(30)).expect("an answer")
    }

    /// Waits out [`INSTALL_DELAY`]: «Установить» works then, not before.
    fn armed(ui: &InstallPluginWindow) {
        assert!(!ui.get_can_install());
        ui.invoke_answer(true);
        assert!(is_open(), "«Установить» does nothing yet");
        std::thread::sleep(INSTALL_DELAY + Duration::from_millis(100));
        slint::platform::update_timers_and_animations();
        assert!(ui.get_can_install());
    }

    #[test]
    fn install_says_yes() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (request, rx) = request(false, Some("https://shop.kz"));
        enqueue(request);
        let ui = the_window();
        assert_eq!(
            ui.get_asker(),
            "Сайт https://shop.kz просит установить плагин"
        );
        assert_eq!(ui.get_plugin(), "Пример плагина, версия 0.1.0");
        assert_eq!(
            ui.get_replaces(),
            "Заменяет kz.example.echo 1.0.0 оригинального NCALayer"
        );
        assert_eq!(ui.get_may(), "Плагин сможет:");
        let lines: Vec<String> = ui
            .get_capabilities()
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            lines,
            [
                "выбирать ваш ключ и подписывать им",
                "показывать окна",
                "открывать и сохранять файлы, которые вы выберете",
                "обращаться к https://example.invalid/",
            ]
        );
        assert_eq!(ui.get_warning(), "", "a catalog plugin is not warned about");
        assert_eq!(ui.get_replacing(), "");
        armed(&ui);
        ui.invoke_answer(true);
        assert!(answered(&rx));
        assert!(!is_open());
    }

    #[test]
    fn cancel_and_close_say_no() {
        let dir = tempfile::tempdir().unwrap();
        desktop(dir.path(), Locale::Ru);
        let (mut first, first_rx) = request(true, None);
        first.replacing = Some(InstalledVersion {
            version: "0.0.9".to_owned(),
            local: false,
        });
        let (second, second_rx) = request(false, None);
        enqueue(first);
        // Waits for the first.
        enqueue(second);
        let ui = the_window();
        assert_eq!(ui.get_asker(), "");
        assert!(
            ui.get_warning()
                .starts_with("Этого плагина нет в каталоге OpenNCALayer"),
            "{}",
            ui.get_warning()
        );
        assert_eq!(
            ui.get_replacing(),
            "Заменит установленную версию 0.0.9 (из каталога)"
        );
        // «Отмена» works at once.
        ui.invoke_answer(false);
        assert!(!answered(&first_rx));
        // The second is shown now; closing it is no.
        let ui = the_window();
        assert_eq!(ui.get_warning(), "");
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::CloseRequested);
        assert!(!answered(&second_rx));
        assert!(!is_open());
    }

    #[test]
    fn texts_in_every_language() {
        for l in [Locale::Kk, Locale::En] {
            let (request, _rx) = request(true, Some("https://shop.kz"));
            let ours = texts(&request, l);
            let ru = texts(&request, Locale::Ru);
            assert!(ours.asker.contains("https://shop.kz"), "{l:?}");
            assert!(ours.plugin.contains(request.name.get(l)), "{l:?}");
            assert_ne!(ours.may, ru.may, "{l:?}");
            assert_ne!(ours.warning, ru.warning, "{l:?}");
            assert_eq!(ours.capabilities.len(), 4);
            assert!(ours.capabilities[3].contains("https://example.invalid/"));
            for (a, b) in ours.capabilities.iter().zip(&ru.capabilities) {
                assert_ne!(a, b, "{l:?}");
            }
        }
        let (mut request, _rx) = request(false, None);
        request.capabilities.clear();
        assert_eq!(
            texts(&request, Locale::Ru).may,
            "Плагин будет только отвечать на запросы сайтов."
        );
    }

    #[test]
    fn the_origin_is_cleaned_and_the_replaced_version_named() {
        let (mut request, _rx) = request(true, Some("https://shop.kz\u{202E}moc.live\n.kz"));
        let ru = texts(&request, Locale::Ru);
        assert_eq!(
            ru.asker,
            "Сайт https://shop.kzmoc.live.kz просит установить плагин"
        );
        assert_eq!(ru.replacing, "");
        let long = format!("https://{}.kz", "a".repeat(200));
        request.origin = Some(long);
        assert!(texts(&request, Locale::En).asker.contains('…'));
        request.replacing = Some(InstalledVersion {
            version: "0.0.9".to_owned(),
            local: true,
        });
        assert_eq!(
            texts(&request, Locale::En).replacing,
            "Replaces the installed version 0.0.9 (local, from a file)"
        );
        assert_eq!(
            texts(&request, Locale::Ru).replacing,
            "Заменит установленную версию 0.0.9 (локальную, из файла)"
        );
        assert!(texts(&request, Locale::Kk).replacing.contains("0.0.9"));
    }

    #[test]
    fn without_windows_it_is_declined() {
        // A thread without the daemon's windows.
        std::thread::spawn(|| {
            let (request, rx) = request(false, None);
            enqueue(request);
            assert!(!answered(&rx));
        })
        .join()
        .unwrap();
    }
}
