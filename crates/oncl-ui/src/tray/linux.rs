//! The tray on Linux: a StatusNotifierItem over the D-Bus session bus (`ksni`), without
//! GTK. Its service runs in a thread of its own; picked items go to the event loop through
//! [`deliver`].

use super::{IconKind, MenuRow, PRODUCT, TrayError, TrayModel, TrayState, deliver};
use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, ToolTip};

/// The tray of [`start_tray`](super::start_tray).
pub(super) struct Tray {
    handle: Handle<Item>,
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
        Ok(Tray { handle })
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

/// `text` for the tooltip's description, which hosts read as a subset of HTML.
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
