//! The system tray: [`start_tray`] shows OpenNCALayer's icon with its menu; picked menu
//! items reach the caller as [`TrayCommand`]s on the Slint event loop of
//! [`run_event_loop`](crate::run_event_loop).
//!
//! Windows and macOS use `tray-icon` (menus by `muda`), Linux a StatusNotifierItem over
//! D-Bus (`ksni`). The menu, icon and tooltip come from the pure [`TrayModel`].
//! [`TrayHandle::notify`] shows a [`Notification`]: a balloon of the icon on Windows, a
//! desktop notification over D-Bus on Linux, `osascript` on macOS.

use oncl_basics::Locale;
use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

#[cfg(windows)]
mod balloon;
#[cfg(any(windows, target_os = "macos"))]
mod windows_macos;
#[cfg(any(windows, target_os = "macos"))]
use windows_macos as platform;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

/// The product name: the tooltip's first line, the tray item's title.
const PRODUCT: &str = "OpenNCALayer";

/// The longest tooltip in UTF-16 code units: Windows keeps 128 including the terminating
/// NUL (`NOTIFYICONDATAW::szTip`).
#[cfg_attr(target_os = "linux", allow(dead_code))]
const TOOLTIP_UNITS: usize = 127;

/// What the user picked in the tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    /// «Настройки…»: the settings window.
    Settings,
    /// «Сертификат для браузера…»: the TLS wizard.
    TlsWizard,
    /// «Журнал»: the log directory in the file manager.
    OpenLogs,
    /// «О программе».
    About,
    /// «Остановить оригинал…»: stop the original NCALayer holding the port.
    StopOriginal,
    /// «Выход»: stop the servers and the event loop.
    Quit,
}

// Menu item ids are for `muda`; `ksni` items carry their command in a closure.
#[cfg_attr(target_os = "linux", allow(dead_code))]
impl TrayCommand {
    /// Every command, for [`TrayCommand::from_id`].
    const ALL: [TrayCommand; 6] = [
        TrayCommand::Settings,
        TrayCommand::TlsWizard,
        TrayCommand::OpenLogs,
        TrayCommand::About,
        TrayCommand::StopOriginal,
        TrayCommand::Quit,
    ];

    /// The menu item id of the command.
    fn id(self) -> &'static str {
        match self {
            TrayCommand::Settings => "settings",
            TrayCommand::TlsWizard => "tls-wizard",
            TrayCommand::OpenLogs => "open-logs",
            TrayCommand::About => "about",
            TrayCommand::StopOriginal => "stop-original",
            TrayCommand::Quit => "quit",
        }
    }

    /// The command of a menu item id.
    fn from_id(id: &str) -> Option<TrayCommand> {
        TrayCommand::ALL.into_iter().find(|c| c.id() == id)
    }
}

/// What the tray shows besides the menu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrayState {
    /// A problem for the user (TLS not set up, the certificate expiring, the port busy):
    /// the icon turns to «attention» and the tooltip says this.
    pub warning: Option<String>,
    /// The original NCALayer holds the port: the menu offers «Остановить оригинал…».
    pub stop_original: bool,
}

/// A message from the tray: a balloon of the icon on Windows (a toast on Windows 10 and
/// later), a desktop notification on Linux (`org.freedesktop.Notifications`) and macOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub body: String,
    /// What a click does: on the notification (Windows, Linux) or on its button (Linux, if
    /// the notification server shows buttons). macOS notifications only inform.
    pub action: Option<NotificationAction>,
}

/// What clicking a [`Notification`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationAction {
    /// The button's text.
    pub label: String,
    pub target: ActionTarget,
}

/// Where a [`NotificationAction`] leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionTarget {
    /// As if the menu item had been picked.
    Command(TrayCommand),
    /// The page in the default browser.
    Url(String),
}

/// The tray could not be shown (e.g. on Linux: no D-Bus session or no StatusNotifier host).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TrayError(String);

/// The tray icon; dropping it removes the icon. It lives on the thread that started it.
pub struct TrayHandle {
    tray: platform::Tray,
}

impl TrayHandle {
    /// Shows `state`: the icon and the tooltip.
    pub fn set_state(&self, state: TrayState) {
        self.tray.set_state(state);
    }

    /// Shows the menu in `locale` (the language saved in the settings window).
    pub fn set_locale(&self, locale: Locale) {
        self.tray.set_locale(locale);
    }

    /// Shows `notification`. A failure is only logged: a notification is a hint.
    pub fn notify(&self, notification: Notification) {
        tracing::info!(title = %notification.title, body = %notification.body, "tray notification");
        if let Err(e) = self.tray.notify(notification) {
            tracing::warn!(error = %e, "cannot show the notification");
        }
    }
}

impl Drop for TrayHandle {
    fn drop(&mut self) {
        ON_COMMAND.with_borrow_mut(|on_command| *on_command = None);
    }
}

/// Shows the tray icon with its menu in `locale`. Call it on the main thread, which then runs
/// [`run_event_loop`](crate::run_event_loop): `on_command` runs there, once per picked item.
///
/// # Errors
///
/// The tray cannot be shown; the caller carries on without it.
pub fn start_tray(
    locale: Locale,
    on_command: impl Fn(TrayCommand) + 'static,
) -> Result<TrayHandle, TrayError> {
    let model = TrayModel::new(locale);
    let tray = platform::Tray::start(model)?;
    ON_COMMAND.with_borrow_mut(|slot| *slot = Some(Rc::new(on_command)));
    Ok(TrayHandle { tray })
}

/// The `on_command` of [`start_tray`].
type OnCommand = Rc<dyn Fn(TrayCommand)>;

thread_local! {
    /// The `on_command` of [`start_tray`], on the thread that started the tray.
    static ON_COMMAND: RefCell<Option<OnCommand>> = const { RefCell::new(None) };
}

/// Hands `command` to the event loop, from whatever thread the tray library reports on.
fn deliver(command: TrayCommand) {
    if let Err(e) = slint::invoke_from_event_loop(move || {
        // Cloned out first: `on_command` may drop the tray (and so this slot).
        let on_command = ON_COMMAND.with_borrow(Clone::clone);
        match on_command {
            Some(on_command) => on_command(command),
            None => tracing::warn!(?command, "tray command without a tray"),
        }
    }) {
        tracing::warn!(?command, error = %e, "tray command lost");
    }
}

/// Carries out a clicked notification's `target` on the event loop, from whatever thread
/// the notification is reported on.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn deliver_click(target: ActionTarget) {
    match target {
        ActionTarget::Command(command) => deliver(command),
        ActionTarget::Url(url) => {
            let opened = std::thread::Builder::new()
                .name("browser".into())
                .spawn(move || {
                    if let Err(e) = webbrowser::open(&url) {
                        tracing::warn!(%url, error = %e, "cannot open the browser");
                    }
                });
            if let Err(e) = opened {
                tracing::warn!(error = %e, "cannot open the browser");
            }
        }
    }
}

/// The icon of a tray state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IconKind {
    /// Everything works.
    Normal,
    /// [`TrayState::warning`] is set.
    Attention,
}

impl IconKind {
    /// The bundled PNG file.
    fn png(self) -> &'static [u8] {
        match self {
            IconKind::Normal => include_bytes!("../assets/tray-ok.png"),
            IconKind::Attention => include_bytes!("../assets/tray-warn.png"),
        }
    }

    /// The icon's pixels.
    fn rgba(self) -> Result<Rgba, TrayError> {
        decode_png(self.png()).map_err(|e| TrayError(format!("tray icon {self:?}: {e}")))
    }
}

/// An image as non-premultiplied RGBA, 8 bits per channel, rows top to bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rgba {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

/// Decodes an 8-bit RGBA PNG.
fn decode_png(png: &[u8]) -> Result<Rgba, String> {
    let mut reader = png::Decoder::new(Cursor::new(png))
        .read_info()
        .map_err(|e| e.to_string())?;
    let size = reader
        .output_buffer_size()
        .ok_or("the image is too large")?;
    let mut pixels = vec![0; size];
    let frame = reader.next_frame(&mut pixels).map_err(|e| e.to_string())?;
    if (frame.color_type, frame.bit_depth) != (png::ColorType::Rgba, png::BitDepth::Eight) {
        return Err(format!(
            "not an 8-bit RGBA image: {:?} {:?}",
            frame.color_type, frame.bit_depth
        ));
    }
    pixels.truncate(frame.buffer_size());
    Ok(Rgba {
        width: frame.width,
        height: frame.height,
        pixels,
    })
}

/// One row of the tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuRow {
    Item(TrayCommand, &'static str),
    Separator,
}

/// What the tray shows, without a tray: the menu, the icon and the tooltip of a state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayModel {
    texts: &'static Texts,
    state: TrayState,
}

impl TrayModel {
    fn new(locale: Locale) -> Self {
        TrayModel {
            texts: Texts::of(locale),
            state: TrayState::default(),
        }
    }

    /// Takes `state`; whether anything shown changes.
    fn set_state(&mut self, state: TrayState) -> bool {
        let changed = state != self.state;
        self.state = state;
        changed
    }

    /// Takes the menu texts of `locale`; whether they change.
    fn set_locale(&mut self, locale: Locale) -> bool {
        let texts = Texts::of(locale);
        let changed = texts != self.texts;
        self.texts = texts;
        changed
    }

    fn menu(&self) -> Vec<MenuRow> {
        let t = self.texts;
        let mut rows = Vec::with_capacity(8);
        if self.state.stop_original {
            rows.extend([
                MenuRow::Item(TrayCommand::StopOriginal, t.stop_original),
                MenuRow::Separator,
            ]);
        }
        rows.extend([
            MenuRow::Item(TrayCommand::Settings, t.settings),
            MenuRow::Item(TrayCommand::TlsWizard, t.tls_wizard),
            MenuRow::Item(TrayCommand::OpenLogs, t.logs),
            MenuRow::Item(TrayCommand::About, t.about),
            MenuRow::Separator,
            MenuRow::Item(TrayCommand::Quit, t.quit),
        ]);
        rows
    }

    fn icon(&self) -> IconKind {
        match self.state.warning {
            Some(_) => IconKind::Attention,
            None => IconKind::Normal,
        }
    }

    /// The warning, if any.
    fn warning(&self) -> Option<&str> {
        self.state.warning.as_deref()
    }

    /// The product name, then the warning on a line of its own; cut with `…` to what a
    /// Windows tooltip holds. (A StatusNotifierItem has a title and a description instead.)
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    fn tooltip(&self) -> String {
        let full = match self.warning() {
            Some(warning) => format!("{PRODUCT}\n{warning}"),
            None => PRODUCT.to_owned(),
        };
        if full.encode_utf16().count() <= TOOLTIP_UNITS {
            return full;
        }
        let mut cut = String::new();
        let mut units = '…'.len_utf16();
        for c in full.chars() {
            units += c.len_utf16();
            if units > TOOLTIP_UNITS {
                break;
            }
            cut.push(c);
        }
        cut.push('…');
        cut
    }
}

/// The menu texts in one language.
#[derive(Debug, PartialEq, Eq)]
struct Texts {
    stop_original: &'static str,
    settings: &'static str,
    tls_wizard: &'static str,
    logs: &'static str,
    about: &'static str,
    quit: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                stop_original: "Түпнұсқаны тоқтату…",
                settings: "Баптаулар…",
                tls_wizard: "Браузерге арналған сертификат…",
                logs: "Журнал",
                about: "Бағдарлама туралы",
                quit: "Шығу",
            },
            Locale::Ru => &Texts {
                stop_original: "Остановить оригинал…",
                settings: "Настройки…",
                tls_wizard: "Сертификат для браузера…",
                logs: "Журнал",
                about: "О программе",
                quit: "Выход",
            },
            Locale::En => &Texts {
                stop_original: "Stop the original…",
                settings: "Settings…",
                tls_wizard: "Certificate for browsers…",
                logs: "Log",
                about: "About",
                quit: "Quit",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warned(warning: &str) -> TrayState {
        TrayState {
            warning: Some(warning.to_owned()),
            stop_original: false,
        }
    }

    #[test]
    fn menu_has_the_items_of_the_spec_in_order() {
        let menu = TrayModel::new(Locale::Ru).menu();
        assert_eq!(
            menu,
            [
                MenuRow::Item(TrayCommand::Settings, "Настройки…"),
                MenuRow::Item(TrayCommand::TlsWizard, "Сертификат для браузера…"),
                MenuRow::Item(TrayCommand::OpenLogs, "Журнал"),
                MenuRow::Item(TrayCommand::About, "О программе"),
                MenuRow::Separator,
                MenuRow::Item(TrayCommand::Quit, "Выход"),
            ]
        );
    }

    #[test]
    fn menu_is_translated() {
        for locale in [Locale::Kk, Locale::Ru, Locale::En] {
            let menu = TrayModel::new(locale).menu();
            let labels: Vec<&str> = menu
                .iter()
                .filter_map(|row| match row {
                    MenuRow::Item(_, label) => Some(*label),
                    MenuRow::Separator => None,
                })
                .collect();
            assert_eq!(labels.len(), 5, "{locale:?}");
            assert!(labels.iter().all(|l| !l.is_empty()), "{locale:?}");
        }
        assert_eq!(
            TrayModel::new(Locale::En).menu().last(),
            Some(&MenuRow::Item(TrayCommand::Quit, "Quit"))
        );
        assert_eq!(
            TrayModel::new(Locale::Kk).menu().last(),
            Some(&MenuRow::Item(TrayCommand::Quit, "Шығу"))
        );
    }

    #[test]
    fn stopping_the_original_is_offered_only_when_it_holds_the_port() {
        let mut model = TrayModel::new(Locale::Ru);
        let plain = model.menu();
        assert!(!plain.contains(&MenuRow::Item(
            TrayCommand::StopOriginal,
            "Остановить оригинал…"
        )));
        assert!(model.set_state(TrayState {
            warning: Some("Порт занят оригинальным NCALayer".to_owned()),
            stop_original: true,
        }));
        let menu = model.menu();
        assert_eq!(
            menu[..2],
            [
                MenuRow::Item(TrayCommand::StopOriginal, "Остановить оригинал…"),
                MenuRow::Separator,
            ]
        );
        assert_eq!(menu[2..], plain[..]);
        for locale in [Locale::Kk, Locale::En] {
            assert!(model.set_locale(locale));
            assert!(matches!(
                model.menu()[0],
                MenuRow::Item(TrayCommand::StopOriginal, label) if !label.is_empty()
            ));
        }
        // The warning stays, the item goes.
        assert!(model.set_state(warned("Порт занят")));
        assert_eq!(model.menu(), TrayModel::new(Locale::En).menu());
    }

    #[test]
    fn locale_switches_the_menu_and_keeps_the_state() {
        let mut model = TrayModel::new(Locale::Ru);
        model.set_state(warned("порт занят"));
        assert!(!model.set_locale(Locale::Ru));
        assert!(model.set_locale(Locale::En));
        assert_eq!(model.menu(), TrayModel::new(Locale::En).menu());
        assert_eq!(model.warning(), Some("порт занят"));
    }

    #[test]
    fn command_ids_round_trip_and_are_distinct() {
        for command in TrayCommand::ALL {
            assert_eq!(TrayCommand::from_id(command.id()), Some(command));
        }
        let mut ids: Vec<&str> = TrayCommand::ALL.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), TrayCommand::ALL.len());
        assert_eq!(TrayCommand::from_id("nope"), None);
    }

    #[test]
    fn warning_switches_icon_and_tooltip() {
        let mut model = TrayModel::new(Locale::Ru);
        assert_eq!(model.icon(), IconKind::Normal);
        assert_eq!(model.tooltip(), "OpenNCALayer");
        assert_eq!(model.warning(), None);

        assert!(model.set_state(warned("TLS не настроен")));
        assert_eq!(model.icon(), IconKind::Attention);
        assert_eq!(model.tooltip(), "OpenNCALayer\nTLS не настроен");
        assert_eq!(model.warning(), Some("TLS не настроен"));
        assert!(!model.set_state(warned("TLS не настроен")));

        assert!(model.set_state(TrayState::default()));
        assert_eq!(model.icon(), IconKind::Normal);
        assert_eq!(model.tooltip(), "OpenNCALayer");
    }

    #[test]
    fn long_tooltip_is_cut_to_what_windows_holds() {
        let mut model = TrayModel::new(Locale::Ru);
        // Cyrillic letters are one UTF-16 unit each, the emoji two.
        model.set_state(warned(&format!("{}😀{}", "ж".repeat(110), "з".repeat(50))));
        let tooltip = model.tooltip();
        assert_eq!(tooltip.encode_utf16().count(), TOOLTIP_UNITS);
        assert!(tooltip.starts_with("OpenNCALayer\nжжж"));
        assert!(tooltip.ends_with("😀з…"), "{tooltip}");

        // A surrogate pair is never split: 126 units of text before the emoji leave no room.
        let prefix = 126 - "OpenNCALayer\n".len();
        model.set_state(warned(&format!("{}😀", "ж".repeat(prefix))));
        let tooltip = model.tooltip();
        assert!(tooltip.encode_utf16().count() <= TOOLTIP_UNITS);
        assert!(tooltip.ends_with("ж…"), "{tooltip}");

        // Exactly the limit stays whole.
        let exact = TOOLTIP_UNITS - "OpenNCALayer\n".len();
        model.set_state(warned(&"ж".repeat(exact)));
        assert!(!model.tooltip().ends_with('…'));
        assert_eq!(model.tooltip().encode_utf16().count(), TOOLTIP_UNITS);
    }

    #[test]
    fn icons_decode_to_distinct_32_px_rgba() {
        let normal = IconKind::Normal.rgba().unwrap();
        let attention = IconKind::Attention.rgba().unwrap();
        for icon in [&normal, &attention] {
            assert_eq!((icon.width, icon.height), (32, 32));
            assert_eq!(icon.pixels.len(), 32 * 32 * 4);
            // Transparent corners, an opaque centre.
            assert_eq!(icon.pixels[3], 0);
            assert_eq!(icon.pixels[(16 * 32 + 16) * 4 + 3], 255);
        }
        assert_ne!(normal.pixels, attention.pixels);
    }

    #[test]
    fn non_rgba_png_is_rejected() {
        // A 1×1 grayscale PNG.
        let gray = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x3a, 0x7e, 0x9b, 0x55, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78,
            0xda, 0x63, 0x68, 0x00, 0x00, 0x00, 0x82, 0x00, 0x81, 0xda, 0x45, 0x08, 0x3b, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        let error = decode_png(&gray).unwrap_err();
        assert!(error.starts_with("not an 8-bit RGBA image"), "{error}");
        assert!(decode_png(b"not a png").is_err());
    }
}
