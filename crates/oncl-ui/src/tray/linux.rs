//! The tray on Linux: a StatusNotifierItem over the D-Bus session bus (`ksni`), without
//! GTK. Its service runs in a thread of its own; picked items go to the event loop through
//! [`deliver`]. Notifications go to the desktop's notification server
//! (`org.freedesktop.Notifications`) from a thread of their own, so that a slow server never
//! holds up the dialogs; another thread listens for their clicks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use super::{
    ActionTarget, IconKind, MenuRow, Notification, PRODUCT, TrayError, TrayModel, TrayState,
    deliver, deliver_click,
};
use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, ToolTip};
use oncl_basics::Locale;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::Value;

/// The notification server.
const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
/// The action of a click on the notification itself.
const DEFAULT_ACTION: &str = "default";
/// How many notifications' clicks are remembered.
const PENDING_CLICKS: usize = 16;

/// The tray of [`start_tray`](super::start_tray).
pub(super) struct Tray {
    handle: Handle<Item>,
    /// Connected at the first notification; notifications are sent one at a time.
    notifier: Arc<Mutex<Option<Notifier>>>,
}

impl Tray {
    /// Registers the item with the StatusNotifierWatcher.
    ///
    /// # Errors
    ///
    /// No session bus (`DBUS_SESSION_BUS_ADDRESS` points nowhere, no graphical session), or
    /// no StatusNotifierWatcher or host (e.g. GNOME without the AppIndicator extension).
    pub(super) fn start(model: TrayModel) -> Result<Tray, TrayError> {
        let item = Item {
            normal: vec![pixmap(IconKind::Normal)?],
            attention: vec![pixmap(IconKind::Attention)?],
            model,
        };
        let handle = item
            .spawn()
            .map_err(|e| TrayError(format!("StatusNotifierItem: {e}")))?;
        Ok(Tray {
            handle,
            notifier: Arc::default(),
        })
    }

    /// Sends `notification` from a thread of its own; a failure there is logged.
    pub(super) fn notify(&self, notification: Notification) -> Result<(), TrayError> {
        let notifier = Arc::clone(&self.notifier);
        std::thread::Builder::new()
            .name("notify".into())
            .spawn(move || {
                let mut slot = notifier.lock().unwrap_or_else(PoisonError::into_inner);
                let shown = match &*slot {
                    Some(connected) => connected.show(notification),
                    None => Notifier::connect().and_then(|connected| {
                        let shown = connected.show(notification);
                        *slot = Some(connected);
                        shown
                    }),
                };
                if let Err(e) = shown {
                    tracing::warn!(error = %notify_error(e), "cannot show the notification");
                }
            })
            .map(drop)
            .map_err(|e| TrayError(format!("notifications: {e}")))
    }

    pub(super) fn set_state(&self, state: TrayState) {
        if self
            .handle
            .update(|item| item.model.set_state(state))
            .is_none()
        {
            tracing::warn!("the tray service has stopped");
        }
    }

    pub(super) fn set_locale(&self, locale: Locale) {
        if self
            .handle
            .update(|item| item.model.set_locale(locale))
            .is_none()
        {
            tracing::warn!("the tray service has stopped");
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        // Not waited for: the process ends next, and its bus connection with it.
        drop(self.handle.shutdown());
    }
}

/// The StatusNotifierItem.
struct Item {
    model: TrayModel,
    normal: Vec<Icon>,
    attention: Vec<Icon>,
}

impl ksni::Tray for Item {
    // There is no main window to activate: a click opens the menu.
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "openncalayer".to_owned()
    }

    fn title(&self) -> String {
        PRODUCT.to_owned()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        match self.model.icon() {
            IconKind::Normal => self.normal.clone(),
            IconKind::Attention => self.attention.clone(),
        }
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            title: PRODUCT.to_owned(),
            description: self.model.warning().map(escape_markup).unwrap_or_default(),
            ..ToolTip::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        self.model
            .menu()
            .into_iter()
            .map(|row| match row {
                MenuRow::Item(command, label) => StandardItem {
                    label: label.to_owned(),
                    activate: Box::new(move |_: &mut Item| deliver(command)),
                    ..StandardItem::default()
                }
                .into(),
                MenuRow::Separator => MenuItem::Separator,
            })
            .collect()
    }
}

/// The icon as the item's pixmap: ARGB32 in network byte order.
fn pixmap(kind: IconKind) -> Result<Icon, TrayError> {
    let rgba = kind.rgba()?;
    let (pixels, _) = rgba.pixels.as_chunks::<4>();
    let data = pixels
        .iter()
        .flat_map(|&[r, g, b, a]| [a, r, g, b])
        .collect();
    let size = |n: u32| {
        i32::try_from(n).map_err(|_| TrayError(format!("tray icon {kind:?} is too large")))
    };
    Ok(Icon {
        width: size(rgba.width)?,
        height: size(rgba.height)?,
        data,
    })
}

fn notify_error(e: zbus::Error) -> TrayError {
    TrayError(format!("{NOTIFICATIONS}: {e}"))
}

/// The clicks of the notifications shown, by notification id (the latest few).
type Pending = Arc<Mutex<Vec<(u32, ActionTarget)>>>;

/// A session bus connection to the notification server.
struct Notifier {
    connection: Connection,
    pending: Pending,
}

impl Notifier {
    /// Connects and starts listening for clicks (`ActionInvoked`).
    fn connect() -> zbus::Result<Notifier> {
        let connection = Connection::session()?;
        let pending = Pending::default();
        let clicks = Proxy::new(
            &connection,
            NOTIFICATIONS,
            NOTIFICATIONS_PATH,
            NOTIFICATIONS,
        )?
        .receive_signal("ActionInvoked")?;
        let listening = Arc::clone(&pending);
        std::thread::Builder::new()
            .name("notifications".into())
            .spawn(move || {
                for signal in clicks {
                    let Ok((id, _action)) = signal.body().deserialize::<(u32, String)>() else {
                        continue;
                    };
                    let target = {
                        let mut pending = listening.lock().unwrap_or_else(PoisonError::into_inner);
                        let at = pending.iter().position(|(i, _)| *i == id);
                        at.map(|at| pending.remove(at).1)
                    };
                    if let Some(target) = target {
                        deliver_click(target);
                    }
                }
            })
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        Ok(Notifier {
            connection,
            pending,
        })
    }

    fn show(&self, notification: Notification) -> zbus::Result<()> {
        let actions: Vec<&str> = match &notification.action {
            Some(action) => vec![DEFAULT_ACTION, action.label.as_str()],
            None => Vec::new(),
        };
        let hints: HashMap<&str, Value<'_>> = HashMap::new();
        let proxy = Proxy::new(
            &self.connection,
            NOTIFICATIONS,
            NOTIFICATIONS_PATH,
            NOTIFICATIONS,
        )?;
        // Notify(app_name, replaces_id, app_icon, summary, body, actions, hints, timeout).
        let id: u32 = proxy.call(
            "Notify",
            &(
                PRODUCT,
                0u32,
                "",
                notification.title.as_str(),
                escape_markup(&notification.body),
                actions,
                hints,
                -1i32,
            ),
        )?;
        if let Some(action) = notification.action {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if pending.len() == PENDING_CLICKS {
                pending.remove(0);
            }
            pending.push((id, action.target));
        }
        Ok(())
    }
}

/// `text` for the tooltip's description or a notification's body, which hosts and
/// notification servers read as a subset of HTML.
fn escape_markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixmap_is_argb_in_network_order() {
        let rgba = IconKind::Normal.rgba().unwrap();
        let icon = pixmap(IconKind::Normal).unwrap();
        assert_eq!((icon.width, icon.height), (32, 32));
        let centre = (16 * 32 + 16) * 4;
        assert_eq!(
            icon.data[centre..centre + 4],
            [
                rgba.pixels[centre + 3],
                rgba.pixels[centre],
                rgba.pixels[centre + 1],
                rgba.pixels[centre + 2]
            ]
        );
    }

    #[test]
    fn tooltip_markup_is_escaped() {
        assert_eq!(escape_markup("a <b> & c"), "a &lt;b&gt; &amp; c");
    }
}
