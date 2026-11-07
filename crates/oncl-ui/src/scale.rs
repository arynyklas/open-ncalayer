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
//! A window whose system window does not exist yet (every window just shown: it is created on
//! the event loop's next turn) is not touched: it is brought to the step when it first gets the
//! focus ([`on_event`]), which Windows windows are given by `foreground::take`; one that is never
//! activated stays at the system's scale until it is. A size cut to the monitor's usable area
//! (the window cannot leave the screen: its content scrolls) is kept: the window does not grow
//! back when the step is lowered, nor when the user has made it larger than the area (it is cut
//! again, and centred, whenever its size or scale has to change).
//!
//! A window is [`track`]ed once it is shown. `SLINT_SCALE_FACTOR` set in the environment is a
//! developer's explicit override of the display's scale: it wins and nothing is applied.

use std::cell::{Cell, RefCell};

use oncl_desktop::UiScale;
use slint::platform::WindowEvent;
use slint::winit_030::winit::dpi::PhysicalPosition;
use slint::winit_030::winit::event::WindowEvent as WinitEvent;
use slint::winit_030::winit::window::Window as WinitWindow;
use slint::winit_030::{EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, PhysicalSize, Window};

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
/// What a taskbar takes of a monitor's height at the display's scale 1, in pixels: the usable
/// area is approximated as the monitor less this (scaled by the display's scale) where the system
/// does not say what it is.
const TASKBAR: f32 = 48.0;
/// The frame of a window (title bar and borders) at the display's scale 1: width, height; the
/// guess for a window whose frame cannot be measured.
const FRAME: (f32, f32) = (16.0, 39.0);

/// A monitor's pixels: where its top left is on the desktop, and how big it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// The usable area of a monitor of `monitor` pixels at the display's scale `os`, where the system
/// does not say: the monitor less the taskbar's strip at the bottom.
pub(crate) fn fallback_area(monitor: Rect, os: f32) -> Rect {
    let taskbar = (TASKBAR * os).round() as u32;
    Rect {
        height: monitor.height.saturating_sub(taskbar),
        ..monitor
    }
}

/// What of `area` is left to the content of a window whose frame is `frame` pixels: the size
/// the content is cut to.
pub(crate) fn inner_bound(area: Rect, frame: (u32, u32)) -> (u32, u32) {
    (
        area.width.saturating_sub(frame.0),
        area.height.saturating_sub(frame.1),
    )
}

/// Whether `work` is a size a monitor can have: a monitor that reports nothing, or an absurd
/// size (a virtual display, a broken driver), is as good as unknown.
fn plausible(work: Option<(u32, u32)>) -> Option<(u32, u32)> {
    work.filter(|&(w, h)| (320..=32_768).contains(&w) && (240..=32_768).contains(&h))
}

/// The scale a window really gets: the display's `os` times the `step`, but never so large
/// that the largest minimum window ([`LARGEST_MINIMUM`]) is bigger than `work` (the usable
/// pixels of the monitor), and never below the display's own scale. Past the clamp the
/// content scrolls instead of the window leaving the screen. `work` unknown: no clamp.
pub(crate) fn effective_scale(os: f32, step: UiScale, work: Option<(u32, u32)>) -> f32 {
    let wanted = os * step.factor();
    let Some((width, height)) = plausible(work) else {
        return wanted;
    };
    let room = (width as f32 / LARGEST_MINIMUM.0).min(height as f32 / LARGEST_MINIMUM.1);
    wanted.min(room).max(os)
}

/// A window's scale and its size in physical pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Sizing {
    pub scale: f32,
    pub size: (u32, u32),
}

/// What a window of `logical` size (in logical pixels) is at the display's scale `os` and the
/// `step`: its scale ([`effective_scale`]) and the `logical` size at that scale, cut to `work`
/// (the usable pixels of the monitor) if the monitor cannot hold it. The window's own minimum
/// is not touched: the scale leaves room for the largest one, so a window cut to `work` is
/// still not smaller than its minimum, and past that its content scrolls. `work` unknown: the
/// plain product, not cut.
pub(crate) fn sizing(
    logical: (f32, f32),
    os: f32,
    step: UiScale,
    work: Option<(u32, u32)>,
) -> Sizing {
    let scale = effective_scale(os, step, work);
    let mut size = (
        (logical.0 * scale).round() as u32,
        (logical.1 * scale).round() as u32,
    );
    if let Some((width, height)) = plausible(work) {
        size = (size.0.min(width), size.1.min(height));
    }
    Sizing { scale, size }
}

/// Where a window whose frame is `outer` pixels and whose top left is at `at` goes to be inside
/// `area`: `None` if it is inside already (the user's place stays), else the middle of `area`,
/// or its top left where the window is bigger than it.
pub(crate) fn origin_inside(at: (i32, i32), outer: (u32, u32), area: Rect) -> Option<(i32, i32)> {
    let fits = |origin: i64, size: u32, low: i32, extent: u32| {
        origin >= i64::from(low) && origin + i64::from(size) <= i64::from(low) + i64::from(extent)
    };
    if fits(i64::from(at.0), outer.0, area.x, area.width)
        && fits(i64::from(at.1), outer.1, area.y, area.height)
    {
        return None;
    }
    let centre = |size: u32, low: i32, extent: u32| {
        let spare = (i64::from(extent) - i64::from(size)).max(0);
        (i64::from(low) + spare / 2).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
    };
    Some((
        centre(outer.0, area.x, area.width),
        centre(outer.1, area.y, area.height),
    ))
}

/// The monitor `window` is on.
fn monitor_rect(window: &WinitWindow) -> Option<Rect> {
    let monitor = window.current_monitor()?;
    let (at, size) = (monitor.position(), monitor.size());
    Some(Rect {
        x: at.x,
        y: at.y,
        width: size.width,
        height: size.height,
    })
}

/// The area of the monitor of `window` that windows may take (without the taskbar): what the
/// system says on Windows (`rcWork`), else the monitor less a taskbar's strip.
fn work_rect(w: &WinitWindow, os: f32) -> Option<Rect> {
    #[cfg(windows)]
    if let Some(area) = os_work_area(w) {
        return Some(area);
    }
    Some(fallback_area(monitor_rect(w)?, os))
}

/// `rcWork` of the monitor the window is on, in pixels of the desktop.
#[cfg(windows)]
fn os_work_area(w: &WinitWindow) -> Option<Rect> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
    };
    let RawWindowHandle::Win32(handle) = w.window_handle().ok()?.as_raw() else {
        return None;
    };
    // SAFETY: `handle` is the live window of `w`; `info` is a plain struct of the right size.
    let info = unsafe {
        let monitor = MonitorFromWindow(handle.hwnd.get() as _, MONITOR_DEFAULTTONEAREST);
        let mut info: MONITORINFO = std::mem::zeroed();
        info.cbSize = size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(monitor, &mut info) == 0 {
            return None;
        }
        info
    };
    let r = info.rcWork;
    Some(Rect {
        x: r.left,
        y: r.top,
        width: u32::try_from(r.right - r.left).ok()?,
        height: u32::try_from(r.bottom - r.top).ok()?,
    })
}

/// The usable pixels for the content of `window` at the display's scale `os`: the work area less
/// the window's frame (measured if `measured`, else guessed for `os`). `None` where the window
/// has no system window.
fn work_area(window: &Window, os: f32, measured: bool) -> Option<(u32, u32)> {
    let area = window.with_winit_window(|w| work_rect(w, os))??;
    let frame = if measured {
        system_frame(window).map(|(frame, _)| frame)
    } else {
        None
    }
    .unwrap_or(((FRAME.0 * os).round() as u32, (FRAME.1 * os).round() as u32));
    Some(inner_bound(area, frame))
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
/// pixels (its pixels grow or shrink with the step), and keeps it on the screen: a size the
/// monitor cannot hold is cut to what it can ([`sizing`]) and a window that then sticks out
/// of the monitor's usable area is put back in it ([`origin_inside`]). Idempotent.
///
/// A window whose system window is yet to come is left alone: Slint gives such a window a
/// placeholder size and takes any size set on it for the window's own, which would replace the
/// size the window asks for, and the system window starts at the system's scale anyway. It
/// is brought to the step when it first gets the focus ([`on_event`]).
pub(crate) fn apply_to(window: &Window, base: f32, scale: UiScale) {
    if std::env::var_os("SLINT_SCALE_FACTOR").is_some() || waits_for_system_window(window) {
        return;
    }
    let work = work_area(window, base, true);
    let old = window.scale_factor();
    let before = window.size();
    let logical = before.to_logical(old);
    let fit = sizing((logical.width, logical.height), base, scale, work);
    let rescaled = (fit.scale - old).abs() >= 1e-4;
    let resized = fit.size != (before.width, before.height);
    if !rescaled && !resized {
        return;
    }
    // A maximized or full-screen window is the system's to size: only the scale reaches it.
    let held = window
        .with_winit_window(|w| w.is_maximized() || w.fullscreen().is_some())
        .unwrap_or(false);
    let frame = system_frame(window);
    if rescaled {
        window.dispatch_event(WindowEvent::ScaleFactorChanged {
            scale_factor: fit.scale,
        });
    }
    if !held && fit.size.0 > 0 && fit.size.1 > 0 {
        window.set_size(PhysicalSize::new(fit.size.0, fit.size.1));
    }
    // Whatever size the platform gave the window, the layout is told in the new scale.
    let size = window.size();
    if size.width > 0 && size.height > 0 {
        window.dispatch_event(WindowEvent::Resized {
            size: size.to_logical(fit.scale),
        });
    }
    if !held {
        put_inside(window, fit.size, frame);
    }
}

/// Whether the window will get its system window later, so that it cannot be sized yet. A
/// window of the tests has none and never will: it is sized at once, unless the test says the
/// system window is yet to come ([`tests::NO_SYSTEM_WINDOW`]).
fn waits_for_system_window(window: &Window) -> bool {
    #[cfg(test)]
    {
        let _ = window;
        tests::NO_SYSTEM_WINDOW.get()
    }
    #[cfg(not(test))]
    {
        !window.has_winit_window()
    }
}

/// The window's frame, the pixels of its title bar and borders around its content, and where
/// the window is; `None` where the system does not say.
fn system_frame(window: &Window) -> Option<((u32, u32), (i32, i32))> {
    window
        .with_winit_window(|w| {
            let (outer, inner) = (w.outer_size(), w.inner_size());
            let at = w.outer_position().ok()?;
            Some((
                (
                    outer.width.saturating_sub(inner.width),
                    outer.height.saturating_sub(inner.height),
                ),
                (at.x, at.y),
            ))
        })
        .flatten()
}

/// Moves `window`, whose content is now `inner` pixels, back into the usable area of its
/// monitor if its frame sticks out of it.
fn put_inside(window: &Window, inner: (u32, u32), frame: Option<((u32, u32), (i32, i32))>) {
    let Some(((frame_w, frame_h), at)) = frame else {
        return;
    };
    window.with_winit_window(|w| {
        let Some(area) = work_rect(w, w.scale_factor() as f32) else {
            return;
        };
        let outer = (
            inner.0.saturating_add(frame_w),
            inner.1.saturating_add(frame_h),
        );
        if let Some((x, y)) = origin_inside(at, outer, area) {
            w.set_outer_position(PhysicalPosition::new(x, y));
        }
    });
}

/// The system says the monitor of `window` has scale `os` now: the window takes `os` × the
/// current step. The system resizes the window itself; its size in logical pixels stays.
pub(crate) fn os_scale_changed(window: &Window, os: f32) {
    if std::env::var_os("SLINT_SCALE_FACTOR").is_some() {
        return;
    }
    window.dispatch_event(WindowEvent::ScaleFactorChanged {
        scale_factor: effective_scale(os, current(), work_area(window, os, false)),
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

    thread_local! {
        /// Makes the windows of the test thread behave as windows whose system window is yet to
        /// come.
        pub(super) static NO_SYSTEM_WINDOW: Cell<bool> = const { Cell::new(false) };
    }

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
        // A zero or absurd monitor is unknown, not a reason to shrink to the OS scale.
        assert_eq!(effective_scale(1.5, UiScale::P200, Some((0, 0))), 3.0);
        assert_eq!(effective_scale(1.5, UiScale::P200, Some((1920, 0))), 3.0);
        assert_eq!(
            effective_scale(1.0, UiScale::P200, Some((u32::MAX, u32::MAX))),
            2.0
        );
        // No screen known: the plain product.
        assert_eq!(effective_scale(1.5, UiScale::P200, None), 3.0);
    }

    /// The sizes (logical) the program's windows ask for: the tools window, a plugin or wizard
    /// window, About, a request dialog, and the largest minimum.
    const ASKED: [(f32, f32); 6] = [
        (900.0, 580.0),
        (640.0, 520.0),
        (640.0, 480.0),
        (640.0, 560.0),
        (420.0, 260.0),
        (720.0, 480.0),
    ];

    /// The usable pixels of 2560 × 1440 (as a monitor less 96, and as the system's own
    /// work area, 1392 high), of 1920 × 1080 and of 1366 × 768.
    const WORK: [(u32, u32); 4] = [(2560, 1344), (2560, 1392), (1920, 984), (1366, 672)];

    #[test]
    fn a_window_never_leaves_the_usable_area_at_any_display_scale_and_step() {
        for work in WORK {
            for os in [1.0, 1.25, 1.5, 2.0] {
                for step in UiScale::ALL {
                    for logical in ASKED {
                        let fit = sizing(logical, os, step, Some(work));
                        let what = format!("{logical:?} at {os} x {}% on {work:?}", step.percent());
                        assert!(
                            fit.size.0 <= work.0 && fit.size.1 <= work.1,
                            "{what}: {fit:?}"
                        );
                        // Never below the display's own scale, never above the asked-for one.
                        assert!(fit.scale >= os - 1e-6, "{what}: {fit:?}");
                        assert!(fit.scale <= os * step.factor() + 1e-6, "{what}: {fit:?}");
                        // The largest minimum window still fits at that scale, so whatever the
                        // window asks for, it is not cut below its own minimum, which then
                        // scrolls: where the screen has the room for it at the display's scale.
                        let least = (
                            (LARGEST_MINIMUM.0 * fit.scale).round() as u32,
                            (LARGEST_MINIMUM.1 * fit.scale).round() as u32,
                        );
                        let room = LARGEST_MINIMUM.0 * os <= work.0 as f32
                            && LARGEST_MINIMUM.1 * os <= work.1 as f32;
                        if room && logical.0 >= LARGEST_MINIMUM.0 && logical.1 >= LARGEST_MINIMUM.1
                        {
                            assert!(
                                fit.size.0 >= least.0 && fit.size.1 >= least.1,
                                "{what}: {fit:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_tools_window_is_cut_to_the_monitor_at_the_high_steps() {
        let tools = (900.0, 580.0);
        // 2560 × 1440 at 100%: every step fits, nothing is cut.
        assert_eq!(
            sizing(tools, 1.0, UiScale::P100, Some((2560, 1344))).size,
            (900, 580)
        );
        assert_eq!(
            sizing(tools, 1.0, UiScale::P175, Some((2560, 1344))).size,
            (1575, 1015)
        );
        assert_eq!(
            sizing(tools, 1.0, UiScale::P200, Some((2560, 1344))).size,
            (1800, 1160)
        );
        // At the display's 200% × the step 200% the scale stops at what the minimum window
        // allows (2.8), the width fits (2520) and the height is cut to the monitor's.
        let fit = sizing(tools, 2.0, UiScale::P200, Some((2560, 1344)));
        assert!((fit.scale - 2.8).abs() < 1e-4, "{fit:?}");
        assert_eq!(fit.size, (2520, 1344));
        // 1366 × 768: the scale stops at 1.4, the window is cut to 1260 × 672.
        let fit = sizing(tools, 1.0, UiScale::P200, Some((1366, 672)));
        assert!((fit.scale - 1.4).abs() < 1e-4, "{fit:?}");
        assert_eq!(fit.size, (1260, 672));
        // No monitor known (or an absurd one): the plain product, not cut.
        assert_eq!(sizing(tools, 1.0, UiScale::P200, None).size, (1800, 1160));
        assert_eq!(
            sizing(tools, 1.0, UiScale::P200, Some((0, 0))).size,
            (1800, 1160)
        );
    }

    #[test]
    fn a_window_that_sticks_out_is_put_back_in_the_middle_of_the_area() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 2560,
            height: 1392,
        };
        // Inside: stays where the user put it.
        assert_eq!(origin_inside((346, 369), (916, 619), area), None);
        assert_eq!(origin_inside((0, 0), (2560, 1392), area), None);
        // Sticking out at the right and bottom: centred.
        assert_eq!(
            origin_inside((1000, 900), (1800, 1000), area),
            Some((380, 196))
        );
        // Left or above the area: brought back.
        assert_eq!(origin_inside((-50, 10), (900, 600), area), Some((830, 396)));
        // Bigger than the area: its top left.
        assert_eq!(origin_inside((300, 300), (2896, 1959), area), Some((0, 0)));
        // A second monitor to the right and one above: the area has its own origin.
        let second = Rect {
            x: 2560,
            y: -300,
            width: 1366,
            height: 720,
        };
        assert_eq!(origin_inside((2600, -280), (900, 580), second), None);
        assert_eq!(
            origin_inside((3500, 200), (900, 580), second),
            Some((2793, -230))
        );
        assert_eq!(fallback_area(second, 1.0).height, 672);
    }

    #[test]
    fn the_frame_and_the_taskbar_of_any_display_scale_and_position_stay_inside_the_area() {
        let monitor = Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        };
        for os in [1.0f32, 1.25, 1.5, 2.0] {
            let bar = (48.0 * os).round() as u32;
            let frame = ((16.0 * os).round() as u32, (39.0 * os).round() as u32);
            // The work area with the taskbar at the bottom, on the left, on the right, on top.
            let areas = [
                Rect {
                    height: monitor.height - bar,
                    ..monitor
                },
                Rect {
                    x: bar as i32,
                    width: monitor.width - bar,
                    ..monitor
                },
                Rect {
                    width: monitor.width - bar,
                    ..monitor
                },
                Rect {
                    y: bar as i32,
                    height: monitor.height - bar,
                    ..monitor
                },
            ];
            for area in areas {
                for step in UiScale::ALL {
                    for logical in ASKED {
                        let work = inner_bound(area, frame);
                        let fit = sizing(logical, os, step, Some(work));
                        let outer = (fit.size.0 + frame.0, fit.size.1 + frame.1);
                        // The window as the system puts it by default, and in a corner.
                        for at in [(area.x + 78, area.y + 78), (area.x, area.y), (3000, 2000)] {
                            let (x, y) = origin_inside(at, outer, area).unwrap_or(at);
                            let what = format!(
                                "{logical:?} at {os} x {}% in {area:?} at {at:?}",
                                step.percent()
                            );
                            assert!(x >= area.x && y >= area.y, "{what}");
                            assert!(
                                i64::from(x) + i64::from(outer.0)
                                    <= i64::from(area.x) + i64::from(area.width),
                                "{what}: right edge"
                            );
                            assert!(
                                i64::from(y) + i64::from(outer.1)
                                    <= i64::from(area.y) + i64::from(area.height),
                                "{what}: bottom edge, outer {outer:?}"
                            );
                        }
                    }
                }
            }
        }
        // What the old fixed constants gave at 1920 × 1080 and 150%: an inner height of 984, a
        // frame of 58 more: 1042 against the 1008 the system leaves.
        let area = Rect {
            height: 1080 - 72,
            ..monitor
        };
        assert_eq!(inner_bound(area, (24, 58)), (1896, 950));
        assert_eq!(fallback_area(monitor, 1.5).height, 1008);
    }

    #[test]
    fn a_window_without_a_system_window_waits_and_is_sized_once_after() {
        offscreen::install();
        let ui = dialog((900, 580));
        NO_SYSTEM_WINDOW.set(true);
        apply_to(ui.window(), 1.0, UiScale::P175);
        // Untouched: no scale, no size.
        assert_eq!(ui.window().scale_factor(), 1.0);
        assert_eq!(ui.window().size(), PhysicalSize::new(900, 580));
        // The system window exists (the first focus): the window is brought to the step.
        NO_SYSTEM_WINDOW.set(false);
        apply_to(ui.window(), 1.0, UiScale::P175);
        assert_eq!(ui.window().scale_factor(), 1.75);
        assert_eq!(ui.window().size(), PhysicalSize::new(1575, 1015));
        // Every later focus finds it at the step and leaves it: no second scaling.
        for _ in 0..3 {
            apply_to(ui.window(), 1.0, UiScale::P175);
        }
        assert_eq!(ui.window().scale_factor(), 1.75);
        assert_eq!(ui.window().size(), PhysicalSize::new(1575, 1015));
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
