//! The tray on Windows and macOS: `tray-icon`, its menu in `muda`. Both report on the main
//! thread from inside the event loop's message dispatch; commands still go through
//! [`deliver`] so that `on_command` never runs inside a window procedure.

use super::{IconKind, MenuRow, PRODUCT, TrayCommand, TrayError, TrayModel, TrayState, deliver};
use oncl_basics::Locale;
use std::cell::RefCell;
use std::rc::Rc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// The tray of [`start_tray`](super::start_tray).
pub(super) struct Tray {
    shared: Rc<RefCell<Shared>>,
}

struct Shared {
    model: TrayModel,
    /// `None` until the icon exists (on macOS: once the event loop runs).
    icon: Option<TrayIcon>,
}

impl Tray {
    pub(super) fn start(model: TrayModel) -> Result<Tray, TrayError> {
        MenuEvent::set_event_handler(Some(|event: MenuEvent| {
            match TrayCommand::from_id(event.id.as_ref()) {
                Some(command) => deliver(command),
                None => tracing::warn!(id = ?event.id, "unknown tray menu item"),
            }
        }));
        // Clicks on the icon itself are not used (a click opens the menu); without a handler
        // they would pile up in the library's channel.
        TrayIconEvent::set_event_handler(Some(|_: TrayIconEvent| {}));
        let shared = Rc::new(RefCell::new(Shared { model, icon: None }));
        #[cfg(windows)]
        {
            // The icon's hidden window gets its messages from the event loop that the main
            // thread runs next.
            let icon = build(&shared.borrow().model)?;
            shared.borrow_mut().icon = Some(icon);
        }
        #[cfg(target_os = "macos")]
        {
            // AppKit wants the status item made while the application runs: on the event
            // loop's first turn. A failure there is only logged.
            let weak = Rc::downgrade(&shared);
            slint::Timer::single_shot(std::time::Duration::ZERO, move || {
                let Some(shared) = weak.upgrade() else {
                    return;
                };
                let mut shared = shared.borrow_mut();
                match build(&shared.model) {
                    Ok(icon) => shared.icon = Some(icon),
                    Err(e) => tracing::warn!(error = %e, "the system tray is unavailable"),
                }
            });
        }
        Ok(Tray { shared })
    }

    pub(super) fn set_state(&self, state: TrayState) {
        let mut shared = self.shared.borrow_mut();
        if !shared.model.set_state(state) {
            return;
        }
        let Shared { model, icon } = &*shared;
        let Some(tray) = icon else {
            return;
        };
        let updated = icon_of(model.icon())
            .and_then(|icon| tray.set_icon(Some(icon)).map_err(tray_error))
            .and_then(|()| tray.set_tooltip(Some(model.tooltip())).map_err(tray_error));
        if let Err(e) = updated {
            tracing::warn!(error = %e, "cannot update the tray icon");
        }
    }

    pub(super) fn set_locale(&self, locale: Locale) {
        let mut shared = self.shared.borrow_mut();
        if !shared.model.set_locale(locale) {
            return;
        }
        let Shared { model, icon } = &*shared;
        let Some(tray) = icon else {
            return;
        };
        match menu(model) {
            Ok(menu) => tray.set_menu(Some(Box::new(menu))),
            Err(e) => tracing::warn!(error = %e, "cannot update the tray menu"),
        }
    }
}

/// The menu of `model`.
fn menu(model: &TrayModel) -> Result<Menu, TrayError> {
    let menu = Menu::new();
    for row in model.menu() {
        match row {
            MenuRow::Item(command, label) => {
                menu.append(&MenuItem::with_id(command.id(), label, true, None))
            }
            MenuRow::Separator => menu.append(&PredefinedMenuItem::separator()),
        }
        .map_err(|e| TrayError(format!("tray menu: {e}")))?;
    }
    Ok(menu)
}

/// The tray icon of `model`, with its menu.
fn build(model: &TrayModel) -> Result<TrayIcon, TrayError> {
    TrayIconBuilder::new()
        .with_id(PRODUCT)
        .with_menu(Box::new(menu(model)?))
        .with_tooltip(model.tooltip())
        .with_icon(icon_of(model.icon())?)
        .build()
        .map_err(tray_error)
}

fn icon_of(kind: IconKind) -> Result<Icon, TrayError> {
    let rgba = kind.rgba()?;
    Icon::from_rgba(rgba.pixels, rgba.width, rgba.height)
        .map_err(|e| TrayError(format!("tray icon {kind:?}: {e}")))
}

fn tray_error(e: tray_icon::Error) -> TrayError {
    TrayError(format!("tray icon: {e}"))
}
