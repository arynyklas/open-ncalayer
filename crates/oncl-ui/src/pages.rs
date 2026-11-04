//! The compiled service windows, driven headless through their properties and callbacks:
//! what the common components promise (shown in `ui/common.slint`). There is no event loop and
//! no screen; Slint's software renderer is the platform, as in the other window tests. This
//! is not a native smoke: it says what the windows' bindings do, not how a window manager
//! draws them.
//!
//! Every window keeps its actions inside it at the narrowest the window allows, with the
//! longest names and errors, at every scale step; Escape is the window's own way out unless
//! it is busy; a question that writes a trust store or stops a program is answered "no" by
//! Enter alone.

use std::cell::Cell;
use std::rc::Rc;

use oncl_desktop::UiScale;
use oncl_flows::Locale;
use slint::platform::{Key, WindowEvent};
use slint::{ComponentHandle, ModelRc, PhysicalSize, SharedString, StandardListViewItem, VecModel};

use crate::prompter::select_language;
use crate::ui::{
    AboutWindow, ChoiceDialog, ConfirmDialog, CsrDialog, FileDialog, ImportDialog,
    InstallPluginWindow, KeyDialog, KeyItem, MessageDialog, Metrics, PasswordDialog, PluginsWindow,
    ReaderDialog, SaveDialog, SettingsWindow, StopOriginalWindow, StorageDialog, StorageRow,
    TlsWizardWindow,
};
use crate::{offscreen, scale};

/// A name no line break can be found in: a long path, a file name, an origin.
fn long_name() -> String {
    format!(
        "drive_C:\\Users\\Someone\\{}.p12",
        "VeryLongFolderName".repeat(12)
    )
}

/// A long error: many words, a long unbreakable name among them.
fn long_error() -> String {
    format!(
        "{} {} {}",
        "The key store could not be opened because something went wrong, and the text goes on."
            .repeat(6),
        long_name(),
        "Check the password and try again.".repeat(4),
    )
}

fn press(ui: &impl ComponentHandle, key: Key) {
    let text: SharedString = key.into();
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text });
}

/// Shows `ui` as a window of the system's size and activates it.
fn open(ui: &impl ComponentHandle, logical: (f32, f32)) {
    ui.show().unwrap();
    ui.window()
        .dispatch_event(WindowEvent::WindowActiveChanged(true));
    ui.window()
        .set_size(PhysicalSize::new(logical.0 as u32, logical.1 as u32));
}

/// The narrowest a window of a class can be, in logical pixels: `Metrics` of `ui/common.slint`,
/// which the windows take their minimum from.
fn narrowest(class: Class) -> (f32, f32) {
    let probe = MessageDialog::new().unwrap();
    let metrics = probe.global::<Metrics>();
    match class {
        Class::Dialog => (metrics.get_dialog_min_width(), metrics.get_min_height()),
        Class::Form => (metrics.get_form_min_width(), metrics.get_min_height()),
        Class::Wide => (metrics.get_wide_min_width(), metrics.get_wide_min_height()),
    }
}

#[derive(Clone, Copy)]
enum Class {
    Dialog,
    Form,
    Wide,
}

/// At the narrowest and lowest the window can be, `reachable` holds at every scale step in
/// every language (the Russian and Kazakh texts are the longest), and the window is as big in
/// logical pixels at every step as it was at the first.
fn actions_stay_reachable<C: ComponentHandle>(
    ui: &C,
    class: Class,
    reachable: impl Fn(&C) -> bool,
    what: &str,
) {
    let logical = narrowest(class);
    open(ui, logical);
    for locale in [Locale::Ru, Locale::Kk, Locale::En] {
        select_language(locale);
        for step in UiScale::ALL {
            scale::apply_to(ui.window(), 1.0, step);
            let factor = step.factor();
            assert_eq!(
                ui.window().size(),
                PhysicalSize::new(
                    (logical.0 * factor).round() as u32,
                    (logical.1 * factor).round() as u32
                ),
                "{what} at {}%",
                step.percent()
            );
            assert!(
                reachable(ui),
                "{what}: actions out of the window at {}% in {locale:?}",
                step.percent()
            );
        }
    }
    select_language(Locale::En);
}

/// Counts the calls of a callback.
fn counter() -> (Rc<Cell<u32>>, impl FnMut() + 'static) {
    let count = Rc::new(Cell::new(0));
    let seen = Rc::clone(&count);
    (count, move || seen.set(seen.get() + 1))
}

// ---- the request dialogs: Escape is the dialog's cancel; the actions stay in ----

#[test]
fn message_dialog_keeps_its_button_and_cancels_on_escape() {
    offscreen::install();
    let ui = MessageDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_source(long_name().into());
    ui.set_text(long_error().into());
    ui.set_kind(2);
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "message",
    );
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    let (okd, on_ok) = counter();
    ui.on_ok(on_ok);
    press(&ui, Key::Escape);
    assert_eq!((cancelled.get(), okd.get()), (1, 0));
}

#[test]
fn confirm_dialog_answers_no_to_escape_and_to_enter() {
    offscreen::install();
    let ui = ConfirmDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_source(long_name().into());
    ui.set_text(long_error().into());
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "confirm",
    );
    let answers = Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = Rc::clone(&answers);
    ui.on_answer(move |yes| seen.borrow_mut().push(yes));
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Return);
    assert_eq!(*answers.borrow(), [false], "Enter alone is not a yes");
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);
    assert_eq!(*answers.borrow(), [false]);
}

#[test]
fn choice_dialog_keeps_three_buttons_with_long_text() {
    offscreen::install();
    let ui = ChoiceDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_source(long_name().into());
    ui.set_text(long_error().into());
    ui.set_title_text("A plugin's heading".into());
    ui.set_buttons(ModelRc::new(VecModel::from(vec![
        SharedString::from("Continue"),
        SharedString::from("Another way"),
        SharedString::from("Stop"),
    ])));
    ui.set_default_button(2);
    ui.set_options(ModelRc::new(VecModel::from(
        (0..30)
            .map(|i| StandardListViewItem::from(SharedString::from(format!("Option {i}"))))
            .collect::<Vec<_>>(),
    )));
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "choice",
    );
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);
}

#[test]
fn password_dialog_keeps_its_buttons_and_escape_cancels_from_the_field() {
    offscreen::install();
    let ui = PasswordDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_source(long_name().into());
    ui.set_heading(long_name().into());
    ui.set_message(long_error().into());
    ui.set_ok_text("Confirm and continue".into());
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "password",
    );
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    let (confirmed, on_confirm) = counter();
    ui.on_confirm(on_confirm);
    // The focus starts in the password field: Escape there is the dialog's cancel.
    press(&ui, Key::Escape);
    assert_eq!((cancelled.get(), confirmed.get()), (1, 0));
}

#[test]
fn file_and_save_dialogs_keep_their_buttons() {
    offscreen::install();
    let ui = FileDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_source(long_name().into());
    ui.set_heading(long_error().into());
    actions_stay_reachable(&ui, Class::Dialog, |ui| ui.get_actions_reachable(), "file");
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);

    let ui = SaveDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_source(long_name().into());
    ui.set_file_name(long_name().into());
    actions_stay_reachable(&ui, Class::Dialog, |ui| ui.get_actions_reachable(), "save");
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);
}

#[test]
fn reader_dialog_keeps_its_buttons() {
    offscreen::install();
    let ui = ReaderDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_storage(long_name().into());
    ui.set_reader_note(long_error().into());
    ui.set_readers(ModelRc::new(VecModel::from(
        (0..40)
            .map(|i| StandardListViewItem::from(SharedString::from(format!("Reader {i}"))))
            .collect::<Vec<_>>(),
    )));
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "reader",
    );
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);
}

#[test]
fn csr_and_import_dialogs_keep_their_buttons_with_a_long_error() {
    offscreen::install();
    let ui = CsrDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_path(long_name().into());
    ui.set_ask_password(true);
    ui.set_error(long_error().into());
    actions_stay_reachable(&ui, Class::Form, |ui| ui.get_actions_reachable(), "csr");
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);

    let ui = ImportDialog::new().unwrap();
    ui.set_origin(long_name().into());
    ui.set_storage(long_name().into());
    ui.set_path(long_name().into());
    ui.set_error(long_error().into());
    actions_stay_reachable(&ui, Class::Form, |ui| ui.get_actions_reachable(), "import");
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);
}

// ---- the daemon's own windows ----

#[test]
fn install_plugin_window_installs_only_on_a_deliberate_press() {
    offscreen::install();
    let ui = InstallPluginWindow::new().unwrap();
    ui.set_asker(long_name().into());
    ui.set_plugin(long_name().into());
    ui.set_replacing(long_error().into());
    ui.set_warning(long_error().into());
    ui.set_capabilities(ModelRc::new(VecModel::from(vec![
        SharedString::from(long_error()),
        SharedString::from(long_name()),
    ])));
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "install plugin",
    );
    ui.set_can_install(true);
    let answers = Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = Rc::clone(&answers);
    ui.on_answer(move |yes| seen.borrow_mut().push(yes));
    press(&ui, Key::Return);
    assert_eq!(*answers.borrow(), [false], "Enter alone does not install");
    press(&ui, Key::Escape);
    assert_eq!(*answers.borrow(), [false, false]);
}

#[test]
fn stop_original_window_defaults_to_not_stopping_and_waits_while_busy() {
    offscreen::install();
    let ui = StopOriginalWindow::new().unwrap();
    ui.set_question(long_error().into());
    ui.set_message(long_error().into());
    ui.set_message_is_error(true);
    actions_stay_reachable(
        &ui,
        Class::Dialog,
        |ui| ui.get_actions_reachable(),
        "stop original",
    );
    let (stopped, on_stop) = counter();
    ui.on_stop(on_stop);
    let (dismissed, on_dismiss) = counter();
    ui.on_dismiss(on_dismiss);
    // Enter alone does not end the other program.
    press(&ui, Key::Return);
    assert_eq!((stopped.get(), dismissed.get()), (0, 1));
    // Escape is the way out, but not while stopping runs: its outcome must be seen.
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 2);
    ui.set_busy(true);
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 2);
}

#[test]
fn settings_window_keeps_save_and_close_with_long_texts_and_escape_waits_while_busy() {
    offscreen::install();
    let ui = SettingsWindow::new().unwrap();
    ui.set_message(long_error().into());
    ui.set_message_is_error(true);
    ui.set_original_state(long_error().into());
    ui.set_extension_state(long_error().into());
    ui.set_update_state(long_error().into());
    ui.set_proxy_url(long_name().into());
    actions_stay_reachable(
        &ui,
        Class::Form,
        |ui| ui.get_actions_reachable(),
        "settings",
    );
    let (dismissed, on_dismiss) = counter();
    ui.on_dismiss(on_dismiss);
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 1);
    ui.set_busy(true);
    press(&ui, Key::Escape);
    assert_eq!(
        dismissed.get(),
        1,
        "a running action's outcome must be seen"
    );
}

#[test]
fn plugins_window_escape_closes_a_question_before_the_window() {
    offscreen::install();
    let ui = PluginsWindow::new().unwrap();
    ui.set_catalog(long_error().into());
    ui.set_message(long_error().into());
    ui.set_message_is_error(true);
    actions_stay_reachable(&ui, Class::Wide, |ui| ui.get_actions_reachable(), "plugins");
    let (dismissed, on_dismiss) = counter();
    ui.on_dismiss(on_dismiss);
    // A removal asked about: Escape answers it, the window stays.
    ui.set_remove_question(long_error().into());
    ui.set_removing(1);
    press(&ui, Key::Escape);
    assert_eq!((ui.get_removing(), dismissed.get()), (-1, 0));
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 1);
    ui.set_busy(true);
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 1);
}

#[test]
fn tls_wizard_answers_its_question_no_to_escape_and_to_enter() {
    offscreen::install();
    let ui = TlsWizardWindow::new().unwrap();
    ui.set_message(long_error().into());
    ui.set_message_is_error(true);
    ui.set_status_text(long_error().into());
    actions_stay_reachable(
        &ui,
        Class::Wide,
        |ui| ui.get_actions_reachable(),
        "tls wizard",
    );
    let (dismissed, on_dismiss) = counter();
    ui.on_dismiss(on_dismiss);
    let (confirmed, on_confirm) = counter();
    ui.on_confirm(on_confirm);
    let (refused, on_cancel_confirm) = counter();
    ui.on_cancel_confirm(on_cancel_confirm);

    // A question that writes a trust store: Enter alone is a no, so is Escape, and the
    // window is not closed by either.
    ui.set_confirm_text(long_error().into());
    press(&ui, Key::Return);
    assert_eq!((confirmed.get(), refused.get(), dismissed.get()), (0, 1, 0));
    press(&ui, Key::Escape);
    assert_eq!((confirmed.get(), refused.get(), dismissed.get()), (0, 2, 0));
    // The question answered: Escape closes the window.
    ui.set_confirm_text("".into());
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 1);
}

#[test]
fn about_window_reaches_the_repository_link_from_the_keyboard() {
    offscreen::install();
    let ui = AboutWindow::new().unwrap();
    ui.set_repository("https://example.test/openncalayer".into());
    actions_stay_reachable(&ui, Class::Wide, |ui| ui.get_actions_reachable(), "about");
    let (dismissed, on_dismiss) = counter();
    ui.on_dismiss(on_dismiss);
    press(&ui, Key::Escape);
    assert_eq!(dismissed.get(), 1);

    let (opened, on_open) = counter();
    ui.on_open_repository(on_open);
    // Tab through the window, pressing Space on each stop: the link is one of them.
    for _ in 0..12 {
        press(&ui, Key::Tab);
        ui.window()
            .dispatch_event(WindowEvent::KeyPressed { text: " ".into() });
        ui.window()
            .dispatch_event(WindowEvent::KeyReleased { text: " ".into() });
    }
    assert!(
        opened.get() >= 1,
        "the link cannot be reached from the keyboard"
    );
}

// ---- the lists of the request dialogs are for the keyboard too ----

/// Tab through the window pressing Space on each stop, `stops` times.
fn tab_and_space(ui: &impl ComponentHandle, stops: u32) {
    for _ in 0..stops {
        press(ui, Key::Tab);
        ui.window()
            .dispatch_event(WindowEvent::KeyPressed { text: " ".into() });
        ui.window()
            .dispatch_event(WindowEvent::KeyReleased { text: " ".into() });
    }
}

#[test]
fn a_key_is_chosen_from_the_keyboard_and_escape_cancels_without_signing() {
    offscreen::install();
    let ui = KeyDialog::new().unwrap();
    let key = |title: &str| KeyItem {
        title: title.into(),
        details: "details".into(),
        enabled: true,
        pending: false,
        note: "".into(),
        revoked: "".into(),
    };
    ui.set_keys(ModelRc::new(VecModel::from(vec![
        key("First"),
        key("Second"),
        key("Third"),
    ])));
    ui.set_has_usable(true);
    ui.set_armed(true);
    open(&ui, (520.0, 360.0));
    let (signed, on_sign) = counter();
    ui.on_sign(on_sign);
    assert_eq!(ui.get_selected(), -1);
    // Tab reaches the rows, Space chooses the one in focus; nothing signs by it.
    tab_and_space(&ui, 2);
    assert!(
        ui.get_selected() >= 0,
        "no key can be chosen from the keyboard"
    );
    assert_eq!(signed.get(), 0);
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!((cancelled.get(), signed.get()), (1, 0));
}

#[test]
fn a_storage_is_chosen_from_the_keyboard_and_an_unsupported_one_is_skipped() {
    offscreen::install();
    let ui = StorageDialog::new().unwrap();
    let row = |label: &str, supported: bool| StorageRow {
        label: label.into(),
        supported,
        token: false,
    };
    ui.set_storages(ModelRc::new(VecModel::from(vec![
        row("Not yet", false),
        row("File", true),
    ])));
    open(&ui, (480.0, 480.0));
    let chosen = Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = Rc::clone(&chosen);
    ui.on_storage_chosen(move |i| seen.borrow_mut().push(i));
    tab_and_space(&ui, 6);
    assert!(
        chosen.borrow().contains(&1),
        "the supported storage cannot be chosen from the keyboard"
    );
    assert!(
        !chosen.borrow().contains(&0),
        "an unsupported storage was chosen"
    );
    let (cancelled, on_cancel) = counter();
    ui.on_cancel(on_cancel);
    press(&ui, Key::Escape);
    assert_eq!(cancelled.get(), 1);
}

// ---- the windows drawn by Slint's software renderer (not a native smoke) ----

/// Draws `ui` as a window of `logical` pixels at `step` into `target/service-windows/<name>.png`.
fn draw<C: ComponentHandle>(ui: &C, logical: (f32, f32), step: UiScale, name: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/service-windows");
    std::fs::create_dir_all(&dir).unwrap();
    open(ui, logical);
    scale::apply_to(ui.window(), 1.0, step);
    slint::platform::update_timers_and_animations();
    let size = ui.window().size();
    let mut pixels = vec![slint::Rgb8Pixel::default(); (size.width * size.height) as usize];
    DRAWN.with(|last| {
        let window = last.borrow().clone().expect("a window");
        window.request_redraw();
        let drew = window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, size.width as usize);
        });
        assert!(drew, "{name}: nothing was drawn");
    });
    let file = std::fs::File::create(dir.join(format!("{name}.png"))).unwrap();
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), size.width, size.height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let bytes: Vec<u8> = pixels.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&bytes)
        .unwrap();
    ui.hide().unwrap();
}

thread_local! {
    static DRAWN: offscreen::Last = offscreen::install();
}

/// `cargo test -p oncl-ui --lib service_windows_drawn -- --ignored`: every service window at
/// its narrowest, with long names and errors, at 100%, 150% and 200%, in the three languages.
#[test]
#[ignore = "writes PNG files to target/service-windows"]
fn service_windows_drawn() {
    DRAWN.with(|_| {});
    // Before any window of the test: the probe of `narrowest` is a window too.
    let (dialog, form, wide) = (
        narrowest(Class::Dialog),
        narrowest(Class::Form),
        narrowest(Class::Wide),
    );
    for (locale, code) in [(Locale::Ru, "ru"), (Locale::Kk, "kk"), (Locale::En, "en")] {
        select_language(locale);
        for step in [UiScale::P100, UiScale::P150, UiScale::P200] {
            let n = |window: &str| format!("{window}-{code}-{}", step.percent());

            let ui = MessageDialog::new().unwrap();
            ui.set_origin(long_name().into());
            ui.set_source(long_name().into());
            ui.set_text(long_error().into());
            ui.set_kind(2);
            draw(&ui, dialog, step, &n("message"));

            let ui = PasswordDialog::new().unwrap();
            ui.set_origin(long_name().into());
            ui.set_message(long_error().into());
            draw(&ui, dialog, step, &n("password"));

            let ui = ConfirmDialog::new().unwrap();
            ui.set_origin(long_name().into());
            ui.set_source(long_name().into());
            ui.set_text(long_error().into());
            draw(&ui, dialog, step, &n("confirm"));

            let ui = CsrDialog::new().unwrap();
            ui.set_origin(long_name().into());
            ui.set_path(long_name().into());
            ui.set_ask_password(true);
            ui.set_error(long_error().into());
            draw(&ui, form, step, &n("csr"));

            let ui = SettingsWindow::new().unwrap();
            ui.set_message(long_error().into());
            ui.set_message_is_error(true);
            ui.set_original_state(long_error().into());
            ui.set_update_state(long_error().into());
            draw(&ui, form, step, &n("settings"));

            let ui = SettingsWindow::new().unwrap();
            ui.set_busy(true);
            draw(&ui, (620.0, 700.0), step, &n("settings-busy-tall"));

            let ui = InstallPluginWindow::new().unwrap();
            ui.set_asker(long_name().into());
            ui.set_plugin(long_name().into());
            ui.set_warning(long_error().into());
            draw(&ui, dialog, step, &n("install-plugin"));

            let ui = StopOriginalWindow::new().unwrap();
            ui.set_question(long_error().into());
            ui.set_message(long_error().into());
            ui.set_message_is_error(true);
            draw(&ui, dialog, step, &n("stop-original"));

            let ui = PluginsWindow::new().unwrap();
            ui.set_catalog(long_error().into());
            ui.set_remove_question(long_error().into());
            ui.set_removing(0);
            draw(&ui, wide, step, &n("plugins-question"));

            let ui = TlsWizardWindow::new().unwrap();
            ui.set_status_text(long_error().into());
            ui.set_confirm_text(long_error().into());
            draw(&ui, wide, step, &n("tls-question"));

            let ui = AboutWindow::new().unwrap();
            ui.set_repository("https://example.test/openncalayer".into());
            draw(&ui, wide, step, &n("about"));
        }
    }
    select_language(Locale::En);
}
