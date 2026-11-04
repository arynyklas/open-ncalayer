//! The scale of the windows: one step ([`UiScale`]) chosen in the settings window, 100% to
//! 200% of the system's own scale, applied to every window of the program, the open ones when
//! it is saved and the ones opened later.
//!
//! The windows and their text grow together: a window's scale factor is the display's
//! (what the system says for the monitor the window is on) times the step, so Slint's own
//! renderer draws controls, text and spacing at that size, and the layout, which is in logical
//! pixels, is the same at every step. A window keeps its logical size when the step changes:
//! its pixels grow. The scale follows a window to another monitor ([`on_event`]).
//!
//! A window is [`track`]ed once it is shown. `SLINT_SCALE_FACTOR` set in the environment is a
//! developer's explicit override of the display's scale: it wins and nothing is applied.

use std::cell::{Cell, RefCell};

use oncl_desktop::UiScale;
use slint::platform::WindowEvent;
use slint::winit_030::winit::event::WindowEvent as WinitEvent;
use slint::winit_030::{EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, Window};

thread_local! {
    /// The step the windows of this thread (the event loop's) are at.
    static CURRENT: Cell<UiScale> = const { Cell::new(UiScale::P100) };
    /// The shown windows, until they are dropped.
    static TRACKED: RefCell<Vec<Tracked>> = const { RefCell::new(Vec::new()) };
}

/// A shown window: where it is (its address, which is not reused while it lives) and how
/// to bring it to a step; `false` once the window is gone.
struct Tracked {
    key: usize,
    apply: Box<dyn Fn(UiScale) -> bool>,
    /// Whether the window still exists.
    alive: Box<dyn Fn() -> bool>,
}

/// The least a window of the program can be, in logical pixels (the tools window's minimum, the
/// largest): the scale is kept low enough that such a window fits the screen.
const LARGEST_MINIMUM: (f32, f32) = (720.0, 480.0);
/// What the taskbar and the title bar take of a monitor's height, in pixels; the work area is
/// approximated as the monitor less this.
const CHROME: u32 = 96;

/// The scale a window really gets: the display's `os` times the `step`, but never so large
/// that the largest minimum window ([`LARGEST_MINIMUM`]) is bigger than `work` (the usable
/// pixels of the monitor), and never below the display's own scale. Past the clamp the
/// content scrolls instead of the window leaving the screen. `work` unknown: no clamp.
pub(crate) fn effective_scale(os: f32, step: UiScale, work: Option<(u32, u32)>) -> f32 {
    let wanted = os * step.factor();
    let Some((width, height)) = work else {
        return wanted;
    };
    let room = (width as f32 / LARGEST_MINIMUM.0).min(height as f32 / LARGEST_MINIMUM.1);
    wanted.min(room).max(os)
}

/// The usable pixels of the monitor of `window`, if it has a system window.
fn work_area(window: &Window) -> Option<(u32, u32)> {
    window.with_winit_window(|w| {
        let size = w.current_monitor()?.size();
        Some((size.width, size.height.saturating_sub(CHROME)))
    })?
}

/// The step the windows are at.
pub(crate) fn current() -> UiScale {
    CURRENT.get()
}

/// Makes `scale` the step of every shown window and of the windows shown later.
pub(crate) fn set(scale: UiScale) {
    CURRENT.set(scale);
    let mut windows = TRACKED.take();
    windows.retain(|window| (window.apply)(scale));
    TRACKED.with_borrow_mut(|added| {
        windows.append(added);
        *added = windows;
    });
}

/// Puts the window `ui`, just shown, at the current step and keeps it there: the step chosen
/// later reaches it, and so does a move to a monitor of another scale. Shown again, the window
/// is not tracked twice.
pub(crate) fn track<C: ComponentHandle + 'static>(ui: &C) {
    let key = std::ptr::from_ref(ui.window()) as usize;
    // Windows that are gone are forgotten at every show: the table is as long as the windows
    // that are open, however many dialogs the daemon has shown.
    TRACKED.with_borrow_mut(|windows| windows.retain(|window| (window.alive)()));
    let known = TRACKED.with_borrow(|windows| {
        windows
            .iter()
            .find(|window| window.key == key)
            .map(|window| (window.apply)(current()))
    });
    if known == Some(true) {
        return;
    }
    TRACKED.with_borrow_mut(|windows| windows.retain(|window| window.key != key));
    // The window's own scale now is the system's for it, unless the system's can be asked.
    let own = ui.window().scale_factor();
    let weak = ui.as_weak();
    let alive = {
        let weak = ui.as_weak();
        move || weak.upgrade().is_some()
    };
    let apply = move |scale| {
        let Some(ui) = weak.upgrade() else {
            return false;
        };
        apply_to(ui.window(), os_scale(ui.window()).unwrap_or(own), scale);
        true
    };
    apply(current());
    ui.window().on_winit_window_event(on_event);
    TRACKED.with_borrow_mut(|windows| {
        windows.push(Tracked {
            key,
            apply: Box::new(apply),
            alive: Box::new(alive),
        });
    });
}

/// How many windows are tracked.
#[cfg(test)]
pub(crate) fn tracked_len() -> usize {
    TRACKED.with_borrow(Vec::len)
}

/// What the system says the scale of the monitor of `window` is; `None` where the window has
/// no system window (yet).
fn os_scale(window: &Window) -> Option<f32> {
    window.with_winit_window(|window| window.scale_factor() as f32)
}

/// Gives `window` the scale `base` (the system's) × `scale`, keeping its size in logical
/// pixels: its pixels grow or shrink with the step. Idempotent.
pub(crate) fn apply_to(window: &Window, base: f32, scale: UiScale) {
    if std::env::var_os("SLINT_SCALE_FACTOR").is_some() {
        return;
    }
    let wanted = effective_scale(base, scale, work_area(window));
    let old = window.scale_factor();
    if (wanted - old).abs() < 1e-4 {
        return;
    }
    let logical = window.size().to_logical(old);
    window.dispatch_event(WindowEvent::ScaleFactorChanged {
        scale_factor: wanted,
    });
    let physical = logical.to_physical(wanted);
    if physical.width > 0 && physical.height > 0 {
        window.set_size(physical);
    }
    // Whatever size the platform gave the window, the layout is told in the new scale.
    let size = window.size();
    if size.width > 0 && size.height > 0 {
        window.dispatch_event(WindowEvent::Resized {
            size: size.to_logical(wanted),
        });
    }
}

/// The system says the monitor of `window` has scale `os` now: the window takes `os` × the
/// current step. The system resizes the window itself; its size in logical pixels stays.
pub(crate) fn os_scale_changed(window: &Window, os: f32) {
    if std::env::var_os("SLINT_SCALE_FACTOR").is_some() {
        return;
    }
    window.dispatch_event(WindowEvent::ScaleFactorChanged {
        scale_factor: effective_scale(os, current(), work_area(window)),
    });
}

/// The window events the scale needs: a new scale of the monitor is the system's times the
/// step, not the system's alone; a window that got its system window after it was shown is
/// brought to the step when it first gets the focus.
///
/// Not exercised headless (it needs winit's events): the live paths — the monitor change and the
/// first focus — belong to the native smoke (`smoke/u04-smoke.ps1`).
pub(crate) fn on_event(window: &Window, event: &WinitEvent) -> EventResult {
    match event {
        WinitEvent::ScaleFactorChanged { scale_factor, .. } => {
            os_scale_changed(window, *scale_factor as f32);
            EventResult::PreventDefault
        }
        WinitEvent::Focused(true) => {
            if let Some(os) = os_scale(window) {
                apply_to(window, os, current());
            }
            EventResult::Propagate
        }
        _ => EventResult::Propagate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offscreen;
    use crate::ui::MessageDialog;
    use oncl_desktop::UiScale;
    use slint::{ComponentHandle, PhysicalSize};

    /// A shown dialog of `size` physical pixels, on the offscreen platform of this thread.
    fn dialog(size: (u32, u32)) -> MessageDialog {
        let ui = MessageDialog::new().unwrap();
        ui.show().unwrap();
        ui.window().set_size(PhysicalSize::new(size.0, size.1));
        ui
    }

    #[test]
    fn the_scale_never_makes_the_largest_minimum_window_bigger_than_the_screen() {
        let full_hd = Some((1920, 1080 - 96));
        // 100% display: every step fits (2.0 × 720 = 1440 wide, 960 high).
        assert_eq!(effective_scale(1.0, UiScale::P200, full_hd), 2.0);
        // 150% display × 200% would be 3.0: 984 / 480 = 2.05 is all the height allows.
        let clamped = effective_scale(1.5, UiScale::P200, full_hd);
        assert!((clamped - 2.05).abs() < 1e-3, "{clamped}");
        assert!(clamped * LARGEST_MINIMUM.1 <= 984.0 + 0.01);
        assert!(clamped * LARGEST_MINIMUM.0 <= 1920.0);
        // Never below the display's own scale, even on a small screen.
        assert_eq!(
            effective_scale(1.5, UiScale::P200, Some((1366, 768 - 96))),
            1.5
        );
        assert_eq!(effective_scale(1.0, UiScale::P100, Some((800, 600))), 1.0);
        // No screen known: the plain product.
        assert_eq!(effective_scale(1.5, UiScale::P200, None), 3.0);
    }

    #[test]
    fn shown_and_dropped_windows_do_not_pile_up() {
        offscreen::install();
        for _ in 0..40 {
            let ui = dialog((400, 300));
            track(&ui);
            assert!(tracked_len() <= 2, "{}", tracked_len());
            // Closed: the daemon's windows are hidden when answered or closed.
            ui.hide().unwrap();
        }
        let ui = dialog((400, 300));
        track(&ui);
        assert_eq!(tracked_len(), 1);
    }

    #[test]
    fn a_scale_grows_the_window_and_keeps_what_it_shows_in_it() {
        offscreen::install();
        let ui = dialog((600, 400));
        assert_eq!(ui.window().scale_factor(), 1.0);

        apply_to(ui.window(), 1.0, UiScale::P200);
        assert_eq!(ui.window().scale_factor(), 2.0);
        // The same logical 600 × 400: twice the pixels.
        assert_eq!(ui.window().size(), PhysicalSize::new(1200, 800));

        // Back to the system's size, to the pixel.
        apply_to(ui.window(), 1.0, UiScale::P100);
        assert_eq!(ui.window().scale_factor(), 1.0);
        assert_eq!(ui.window().size(), PhysicalSize::new(600, 400));
    }

    #[test]
    fn the_scale_is_a_multiple_of_the_displays_own() {
        offscreen::install();
        // A display at 150%: the window is 900 × 600 pixels, 600 × 400 logical.
        let ui = dialog((900, 600));
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor: 1.5 });
        assert_eq!(ui.window().scale_factor(), 1.5);

        apply_to(ui.window(), 1.5, UiScale::P150);
        assert_eq!(ui.window().scale_factor(), 2.25);
        assert_eq!(ui.window().size(), PhysicalSize::new(1350, 900));
        // The same step again changes nothing: no creeping growth.
        apply_to(ui.window(), 1.5, UiScale::P150);
        assert_eq!(ui.window().scale_factor(), 2.25);
        assert_eq!(ui.window().size(), PhysicalSize::new(1350, 900));
        apply_to(ui.window(), 1.5, UiScale::P100);
        assert_eq!(ui.window().scale_factor(), 1.5);
        assert_eq!(ui.window().size(), PhysicalSize::new(900, 600));
    }

    #[test]
    fn a_new_display_scale_keeps_the_chosen_step() {
        offscreen::install();
        set(UiScale::P150);
        let ui = dialog((600, 400));
        track(&ui);
        assert_eq!(ui.window().scale_factor(), 1.5);

        // The window moves to a display at 200%: the system says 2.0, the window shows 3.0.
        os_scale_changed(ui.window(), 2.0);
        assert_eq!(ui.window().scale_factor(), 3.0);
        // And back to 100%.
        os_scale_changed(ui.window(), 1.0);
        assert_eq!(ui.window().scale_factor(), 1.5);
        set(UiScale::P100);
    }

    #[test]
    fn a_chosen_scale_reaches_the_open_windows_and_the_ones_opened_later() {
        offscreen::install();
        set(UiScale::P100);
        let first = dialog((600, 400));
        track(&first);
        let second = dialog((500, 300));
        track(&second);
        // Tracked twice (shown again): still one window.
        track(&second);

        set(UiScale::P175);
        assert_eq!(current(), UiScale::P175);
        assert_eq!(first.window().scale_factor(), 1.75);
        assert_eq!(second.window().scale_factor(), 1.75);
        assert_eq!(first.window().size(), PhysicalSize::new(1050, 700));

        // A window closed and dropped is forgotten; one opened later starts at the scale.
        drop(first);
        set(UiScale::P125);
        assert_eq!(second.window().scale_factor(), 1.25);
        let third = dialog((400, 200));
        track(&third);
        assert_eq!(third.window().scale_factor(), 1.25);
        set(UiScale::P100);
        assert_eq!(third.window().scale_factor(), 1.0);
    }
}
