//! The TLS wizard window on the event loop: one at a time, its loading and actions on worker
//! threads. While one runs the window waits (`busy`) and cannot be closed, so its outcome is
//! shown. Every action that writes to a trust store, and replacing the server certificate,
//! first asks in the window; the question's «Да» runs it.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use oncl_basics::Locale;
use oncl_tls::TlsSource;
use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, PlatformError, SharedString, VecModel,
};
use time::OffsetDateTime;

use super::texts::{Texts, fill};
use super::{
    IssueForm, Snapshot, Source, TlsWizardServices, browser_rows, ca_line, install_text,
    issue_error_text, issued_text, mkcert_text, outcomes_text, replaced_text, status_text,
    store_state, trust_text,
};
use crate::foreground;
use crate::prompter::select_desktop_language;
use crate::ui::{BrowserRow, TlsWizardWindow, TrustStoreRow};
use crate::windows::{self, Desktop};

/// How often the list of browsers that reported is refreshed while the window is open.
const REPORTS_EVERY: Duration = Duration::from_secs(2);

/// An action waiting for the confirmation's «Да».
#[derive(Debug)]
enum Pending {
    Issue(IssueForm),
    Install(Vec<String>),
    Remove(Vec<String>),
    InstallNca(Vec<String>),
    RemoveReplaced(Vec<String>),
}

/// The open wizard. Its callbacks find it by `id` in [`OPEN`], so that none holds it (a
/// reference cycle) and a late result never reaches a window opened since.
struct Open {
    id: u64,
    ui: TlsWizardWindow,
    desktop: Rc<Desktop>,
    pending: RefCell<Option<Pending>>,
    /// The last state shown.
    snapshot: RefCell<Option<Snapshot>>,
    /// The stores as listed, each with whether it is ticked.
    stores: RefCell<Vec<(String, bool)>>,
    /// Refreshes the browsers.
    _reports: slint::Timer,
}

thread_local! {
    static OPEN: RefCell<Option<Rc<Open>>> = const { RefCell::new(None) };
    static NEXT_ID: Cell<u64> = const { Cell::new(0) };
}

/// The wizard `id`, if it is open.
fn current(id: u64) -> Option<Rc<Open>> {
    OPEN.with_borrow(|open| open.as_ref().filter(|o| o.id == id).cloned())
}

/// Whether the wizard is open.
pub(crate) fn is_open() -> bool {
    OPEN.with_borrow(Option::is_some)
}

/// Shows the wizard, or brings the open one to the front. On the event loop.
pub(crate) fn open(desktop: &Rc<Desktop>) {
    if let Some(open) = OPEN.with_borrow(Clone::clone) {
        select_desktop_language(desktop.locale.get());
        if let Err(e) = open.ui.show() {
            tracing::warn!(error = %e, "cannot show the TLS wizard");
        }
        foreground::take(&open.ui);
        return;
    }
    if let Err(e) = create(desktop) {
        tracing::error!(error = %e, "cannot show the TLS wizard");
    }
}

fn create(desktop: &Rc<Desktop>) -> Result<(), PlatformError> {
    let ui = TlsWizardWindow::new()?;
    let locale = desktop.locale.get();
    select_desktop_language(locale);
    let t = Texts::of(locale);
    ui.set_status_text(t.loading.into());
    ui.set_selftest_url(desktop.tls.selftest_url().into());
    let id = NEXT_ID.replace(NEXT_ID.get() + 1);
    let reports = slint::Timer::default();
    reports.start(slint::TimerMode::Repeated, REPORTS_EVERY, move || {
        with(id, show_reports);
    });
    let open = Rc::new(Open {
        id,
        ui: ui.clone_strong(),
        desktop: Rc::clone(desktop),
        pending: RefCell::new(None),
        snapshot: RefCell::new(None),
        stores: RefCell::new(Vec::new()),
        _reports: reports,
    });

    ui.on_refresh(move || with(id, load));
    ui.on_issue(move || with(id, issue));
    ui.on_browse_chain(move || with(id, |open| browse(open, Field::Chain)));
    ui.on_browse_key(move || with(id, |open| browse(open, Field::Key)));
    ui.on_store_toggled(move |i, checked| with(id, |open| toggle(open, i, checked)));
    ui.on_install_ca(move || with(id, |open| ask_for_stores(open, Pending::Install)));
    ui.on_remove_ca(move || with(id, |open| ask_for_stores(open, Pending::Remove)));
    ui.on_install_nca(move || with(id, |open| ask_for_stores(open, Pending::InstallNca)));
    ui.on_remove_replaced(move || {
        with(id, |open| ask_for_stores(open, Pending::RemoveReplaced));
    });
    ui.on_open_selftest(move || with(id, open_selftest));
    ui.on_confirm(move || with(id, confirm));
    ui.on_cancel_confirm(move || {
        with(id, |open| {
            open.pending.take();
            open.ui.set_confirm_text(SharedString::new());
        });
    });
    ui.on_dismiss(move || {
        close_requested(id);
    });
    ui.window().on_close_requested(move || close_requested(id));

    OPEN.set(Some(Rc::clone(&open)));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        return Err(e);
    }
    foreground::take(&ui);
    show_reports(&open);
    load(&open);
    Ok(())
}

/// Runs `f` with the wizard `id`, if it is open.
fn with(id: u64, f: impl FnOnce(&Open)) {
    if let Some(open) = current(id) {
        f(&open);
    }
}

/// «Закрыть» or the window's close button: closes the wizard `id`, unless it waits for an
/// action, whose outcome the user must see.
fn close_requested(id: u64) -> CloseRequestResponse {
    if current(id).is_some_and(|open| open.ui.get_busy()) {
        return CloseRequestResponse::KeepWindowShown;
    }
    let Some(open) = OPEN.with_borrow_mut(|slot| slot.take_if(|open| open.id == id)) else {
        return CloseRequestResponse::HideWindow;
    };
    if let Err(e) = open.ui.hide() {
        tracing::warn!(error = %e, "cannot hide the TLS wizard");
    }
    // This runs inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(open));
    CloseRequestResponse::HideWindow
}

/// Loads the state on a worker thread, then shows it.
fn load(open: &Open) {
    run(
        open,
        |s| s.load(),
        |desktop, open, snapshot| {
            if let Some(open) = open {
                show_snapshot(open, snapshot, desktop.locale.get());
            }
        },
    );
}

/// Fills the window with `snapshot` in `l`. The first state also picks the source and the
/// mkcert consent of the saved certificate.
fn show_snapshot(open: &Open, snapshot: Snapshot, l: Locale) {
    let ui = &open.ui;
    let first = open.snapshot.borrow().is_none();
    ui.set_status_text(status_text(&snapshot, OffsetDateTime::now_utc(), l).into());
    ui.set_trust_text(trust_text(&snapshot, l).into());
    if first && let Some(source) = snapshot.source() {
        let index = Source::ALL
            .iter()
            .position(|s| *s == Source::of(source))
            .unwrap_or(0);
        ui.set_source(i32::try_from(index).unwrap_or(0));
        ui.set_mkcert_consent(matches!(source, TlsSource::Mkcert { .. }));
    }
    ui.set_mkcert_found(snapshot.mkcert.is_some());
    ui.set_mkcert_text(mkcert_text(snapshot.mkcert.as_deref(), l).into());
    ui.set_install_text(install_text(&snapshot, l).into());
    ui.set_can_install_ca(snapshot.own_ca().is_some());
    ui.set_has_replaced(!snapshot.replaced.is_empty());
    ui.set_replaced_text(replaced_text(&snapshot.replaced, l).into());

    // Ticks are kept by label; a new store starts ticked.
    let ticked: Vec<(String, bool)> = {
        let previous = open.stores.borrow();
        snapshot
            .stores
            .iter()
            .map(|row| {
                let on = previous
                    .iter()
                    .find(|(label, _)| *label == row.label)
                    .is_none_or(|(_, on)| *on);
                (row.label.clone(), on)
            })
            .collect()
    };
    let rows: Vec<TrustStoreRow> = snapshot
        .stores
        .iter()
        .zip(&ticked)
        .map(|(row, (_, on))| TrustStoreRow {
            label: row.label.as_str().into(),
            state: store_state(row, l).into(),
            selected: *on,
        })
        .collect();
    ui.set_stores(ModelRc::new(VecModel::from(rows)));
    *open.stores.borrow_mut() = ticked;
    *open.snapshot.borrow_mut() = Some(snapshot);
}

/// The browsers that reported from the self-test page.
fn show_reports(open: &Open) {
    let rows: Vec<BrowserRow> = browser_rows(&open.desktop.tls.reports.latest())
        .into_iter()
        .map(|(browser, seen)| BrowserRow {
            browser: browser.into(),
            seen: seen.into(),
        })
        .collect();
    let model = open.ui.get_browsers();
    let same = model.row_count() == rows.len()
        && model
            .iter()
            .zip(&rows)
            .all(|(a, b)| a.browser == b.browser && a.seen == b.seen);
    if !same {
        open.ui.set_browsers(ModelRc::new(VecModel::from(rows)));
    }
}

fn form_of(ui: &TlsWizardWindow) -> IssueForm {
    let source = usize::try_from(ui.get_source())
        .ok()
        .and_then(|i| Source::ALL.get(i).copied())
        .unwrap_or(Source::Own);
    IssueForm {
        source,
        mkcert_consent: ui.get_mkcert_consent(),
        chain: ui.get_chain_path().to_string(),
        key: ui.get_key_path().to_string(),
    }
}

/// «Выпустить сертификат» / «Использовать этот сертификат»: replacing a saved certificate
/// asks first.
fn issue(open: &Open) {
    let form = form_of(&open.ui);
    let configured = open
        .snapshot
        .borrow()
        .as_ref()
        .is_some_and(|s| matches!(s.info, Ok(Some(_))));
    if configured {
        let t = Texts::of(open.desktop.locale.get());
        ask(open, t.confirm_replace.to_owned(), Pending::Issue(form));
    } else {
        act(open, Pending::Issue(form));
    }
}

/// Asks to run the action `pending` makes of the ticked stores.
fn ask_for_stores(open: &Open, pending: fn(Vec<String>) -> Pending) {
    let l = open.desktop.locale.get();
    let t = Texts::of(l);
    let labels: Vec<String> = open
        .stores
        .borrow()
        .iter()
        .filter(|(_, on)| *on)
        .map(|(label, _)| label.clone())
        .collect();
    if labels.is_empty() {
        show_message(&open.ui, t.none_selected, true);
        return;
    }
    let pending = pending(labels);
    let question = {
        let snapshot = open.snapshot.borrow();
        question(&pending, snapshot.as_ref(), t)
    };
    ask(open, question, pending);
}

/// The question that confirms `pending`.
fn question(pending: &Pending, snapshot: Option<&Snapshot>, t: &Texts) -> String {
    let ca = || {
        let (name, sha1) = snapshot
            .and_then(|s| s.own_ca().map(|ca| (s, ca)))
            .map(|(s, ca)| {
                let name =
                    s.ca.as_ref()
                        .and_then(|(_, n)| n.clone())
                        .unwrap_or_default();
                (name, oncl_tls::sha1_grouped(&super::hex(&ca.sha1())))
            })
            .unwrap_or_default();
        (name, sha1)
    };
    match pending {
        Pending::Issue(_) => t.confirm_replace.to_owned(),
        Pending::Install(labels) => {
            let (name, sha1) = ca();
            fill(t.confirm_install, &[&name, &sha1, &labels.join(", ")])
        }
        Pending::Remove(labels) => {
            let (name, sha1) = ca();
            fill(t.confirm_remove, &[&name, &sha1, &labels.join(", ")])
        }
        Pending::InstallNca(labels) => fill(t.confirm_nca, &[&labels.join(", ")]),
        Pending::RemoveReplaced(labels) => {
            let replaced: Vec<String> = snapshot
                .map(|s| s.replaced.iter().map(ca_line).collect())
                .unwrap_or_default();
            format!(
                "{}\n{}",
                fill(t.confirm_replaced, &[&labels.join(", ")]),
                replaced.join("\n")
            )
        }
    }
}

fn ask(open: &Open, question: String, pending: Pending) {
    *open.pending.borrow_mut() = Some(pending);
    open.ui.set_confirm_text(question.into());
}

/// «Да»: runs the action asked about.
fn confirm(open: &Open) {
    open.ui.set_confirm_text(SharedString::new());
    if let Some(pending) = open.pending.take() {
        act(open, pending);
    }
}

/// Runs `pending` on a worker thread, then shows its outcome and the new state.
fn act(open: &Open, pending: Pending) {
    match pending {
        Pending::Issue(form) => run(
            open,
            move |s| (s.issue(&form, OffsetDateTime::now_utc()), s.load()),
            |desktop, open, (issued, snapshot)| {
                let l = desktop.locale.get();
                if let Err(e) = &issued {
                    tracing::warn!(error = ?e, "TLS wizard: no certificate issued");
                }
                let Some(open) = open else {
                    return;
                };
                match &issued {
                    Ok(issued) => {
                        let failed = matches!(issued.applied, super::Applied::Failed(_));
                        show_message(&open.ui, &issued_text(issued, l), failed);
                        // Installing the new CA comes next.
                        if issued.info.source == TlsSource::Own {
                            open.ui.set_tab(2);
                        }
                    }
                    Err(e) => show_message(&open.ui, &issue_error_text(e, l), true),
                }
                show_snapshot(open, snapshot, l);
            },
        ),
        Pending::Install(labels) => stores_action(open, move |s| s.install_ca(&labels)),
        Pending::Remove(labels) => stores_action(open, move |s| s.remove_ca(&labels)),
        Pending::InstallNca(labels) => {
            stores_action(open, move |s| Some(s.install_nca_roots(&labels)));
        }
        Pending::RemoveReplaced(labels) => {
            stores_action(open, move |s| Some(s.remove_replaced(&labels)));
        }
    }
}

/// Runs an action on the stores (`None`: there is no own CA to act with), then shows its
/// outcome per store and the new state.
fn stores_action(
    open: &Open,
    action: impl FnOnce(&TlsWizardServices) -> Option<Vec<(String, super::StoreOutcome)>>
    + Send
    + 'static,
) {
    run(
        open,
        move |s| (action(s), s.load()),
        |desktop, open, (outcomes, snapshot)| {
            let l = desktop.locale.get();
            let (text, failed) = match &outcomes {
                Some(outcomes) => outcomes_text(outcomes, l),
                None => (Texts::of(l).no_ca.to_owned(), true),
            };
            if failed {
                tracing::warn!(%text, "TLS wizard: a trust store action failed");
            }
            if let Some(open) = open {
                show_message(&open.ui, &text, failed);
                show_snapshot(open, snapshot, l);
            }
        },
    );
}

fn toggle(open: &Open, i: i32, checked: bool) {
    let Ok(i) = usize::try_from(i) else {
        return;
    };
    if let Some((_, on)) = open.stores.borrow_mut().get_mut(i) {
        *on = checked;
    }
    let model = open.ui.get_stores();
    if let Some(mut row) = model.row_data(i) {
        row.selected = checked;
        model.set_row_data(i, row);
    }
}

/// «Открыть проверку в браузере».
fn open_selftest(open: &Open) {
    let url = open.desktop.tls.selftest_url();
    let id = open.id;
    let spawned = std::thread::Builder::new()
        .name("browser".into())
        .spawn(move || {
            if let Err(e) = webbrowser::open(&url) {
                tracing::warn!(%url, error = %e, "cannot open the browser");
                let e = e.to_string();
                let _ = slint::invoke_from_event_loop(move || {
                    with(id, |open| {
                        let t = Texts::of(open.desktop.locale.get());
                        show_message(&open.ui, &fill(t.cannot_open_browser, &[&e]), true);
                    });
                });
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "cannot open the browser");
    }
}

/// A file field of the import.
#[derive(Clone, Copy)]
enum Field {
    Chain,
    Key,
}

/// Picks the chain or key file with the system file dialog.
fn browse(open: &Open, field: Field) {
    let ui = &open.ui;
    let current = match field {
        Field::Chain => ui.get_chain_path(),
        Field::Key => ui.get_key_path(),
    };
    let mut dialog = rfd::AsyncFileDialog::new()
        .add_filter("PEM", &["pem", "crt", "cer", "key"])
        .set_parent(&ui.window().window_handle());
    if let Some(dir) = std::path::Path::new(current.as_str())
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
    {
        dialog = dialog.set_directory(dir);
    }
    let weak = ui.as_weak();
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.pick_file().await else {
            tracing::info!("the file dialog returned no file");
            return;
        };
        if let Some(ui) = weak.upgrade() {
            let path = SharedString::from(file.path().display().to_string());
            match field {
                Field::Chain => ui.set_chain_path(path),
                Field::Key => ui.set_key_path(path),
            }
        }
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

/// Runs `job` on a worker thread while the window waits; then [`finish`] hands the result
/// to `done` on the event loop.
fn run<T: Send + 'static>(
    open: &Open,
    job: impl FnOnce(&TlsWizardServices) -> T + Send + 'static,
    done: impl FnOnce(&Desktop, Option<&Open>, T) + Send + 'static,
) {
    open.ui.set_busy(true);
    let services = Arc::clone(&open.desktop.tls);
    let id = open.id;
    let spawned = std::thread::Builder::new()
        .name("tls-wizard".into())
        .spawn(move || {
            let result = job(&services);
            let delivered = slint::invoke_from_event_loop(move || finish(id, result, done));
            if let Err(e) = delivered {
                tracing::warn!(error = %e, "TLS wizard: a result is lost");
            }
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "TLS wizard: cannot start a worker thread");
        open.ui.set_busy(false);
        let t = Texts::of(open.desktop.locale.get());
        show_message(&open.ui, t.cannot_start, true);
    }
}

/// Hands a worker's `result` to `done`, with the daemon's windows and the wizard `id` if it
/// is still open (it waits no longer).
fn finish<T>(id: u64, result: T, done: impl FnOnce(&Desktop, Option<&Open>, T)) {
    let open = current(id);
    if let Some(open) = &open {
        open.ui.set_busy(false);
    }
    let desktop = open
        .as_ref()
        .map(|open| Rc::clone(&open.desktop))
        .or_else(windows::desktop);
    match desktop {
        Some(desktop) => done(&desktop, open.as_deref(), result),
        None => tracing::warn!("TLS wizard: a result without the windows"),
    }
}

fn show_message(ui: &TlsWizardWindow, text: &str, error: bool) {
    ui.set_message(SharedString::from(text));
    ui.set_message_is_error(error);
}

/// Opens the wizard with the state its services load now (on the offscreen platform of the
/// tests, where a worker's result never arrives by itself); returns the window.
#[cfg(test)]
pub(crate) fn open_loaded(desktop: &Rc<Desktop>) -> TlsWizardWindow {
    open(desktop);
    let open = OPEN.with_borrow(Clone::clone).expect("the wizard is open");
    let snapshot = desktop.tls.load();
    finish(open.id, snapshot, |desktop, open, snapshot| {
        if let Some(open) = open {
            show_snapshot(open, snapshot, desktop.locale.get());
        }
    });
    open.ui.clone_strong()
}

/// Shows the question «Установить…» asks for every listed store, without the action behind
/// it (for screenshots: «Да» does nothing).
#[cfg(test)]
pub(crate) fn preview_install_question(desktop: &Desktop) {
    let Some(open) = OPEN.with_borrow(Clone::clone) else {
        return;
    };
    let labels = open
        .stores
        .borrow()
        .iter()
        .map(|(l, _)| l.clone())
        .collect();
    let text = question(
        &Pending::Install(labels),
        open.snapshot.borrow().as_ref(),
        Texts::of(desktop.locale.get()),
    );
    open.ui.set_confirm_text(text.into());
}

/// The wizard on the offscreen platform of the tests, without an event loop: a worker's
/// result never arrives by itself, so a test hands it over with [`finish`].
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_wizard::fakes::{MemoryStore, services};
    use crate::windows::{DesktopWindows, set_desktop_windows};
    use crate::{AboutInfo, offscreen};

    fn desktop(root: &std::path::Path, user: &MemoryStore) -> Rc<Desktop> {
        offscreen::install();
        set_desktop_windows(DesktopWindows {
            locale: Locale::Ru,
            settings: crate::settings_view::fakes::services(
                root,
                crate::settings_view::fakes::FakeOriginal::default(),
            ),
            about: AboutInfo::default(),
            tls: services(root, vec![("User".to_owned(), user.clone())], None),
            on_saved: Box::new(|_| {}),
        });
        windows::desktop().unwrap()
    }

    fn the_window() -> Rc<Open> {
        OPEN.with_borrow(Clone::clone).expect("the wizard is open")
    }

    /// Hands the window the state its services load now.
    fn loaded(window: &Open) {
        let snapshot = window.desktop.tls.load();
        finish(window.id, snapshot, |desktop, open, snapshot| {
            show_snapshot(open.unwrap(), snapshot, desktop.locale.get());
        });
    }

    #[test]
    fn stores_are_written_only_after_yes() {
        let dir = tempfile::tempdir().unwrap();
        let user = MemoryStore::default();
        let desktop = desktop(dir.path(), &user);
        desktop
            .tls
            .issue(
                &IssueForm {
                    source: Source::Own,
                    mkcert_consent: false,
                    chain: String::new(),
                    key: String::new(),
                },
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        open(&desktop);
        let window = the_window();
        // Loading runs on a worker: the window waits and cannot be closed.
        assert!(window.ui.get_busy());
        assert_eq!(
            close_requested(window.id),
            CloseRequestResponse::KeepWindowShown
        );
        loaded(&window);
        assert!(window.ui.get_can_install_ca());
        assert_eq!(window.ui.get_stores().row_count(), 1);

        // «Установить…» only asks; «Отмена» drops the question.
        window.ui.invoke_install_ca();
        assert!(
            window
                .ui
                .get_confirm_text()
                .contains("«OpenNCALayer Local CA")
        );
        assert!(window.ui.get_confirm_text().ends_with("в: User?"));
        assert!(!window.ui.get_busy());
        window.ui.invoke_cancel_confirm();
        assert!(window.ui.get_confirm_text().is_empty());
        window.ui.invoke_confirm();
        assert!(!window.ui.get_busy());
        assert!(user.certificates().is_empty());

        // «Да» starts the action on a worker (its result is handed over here).
        window.ui.invoke_install_ca();
        window.ui.invoke_confirm();
        assert!(window.ui.get_busy());
        assert!(window.ui.get_confirm_text().is_empty());

        // An unticked store is never asked about.
        window.ui.invoke_store_toggled(0, false);
        finish(window.id, (), |_, _, ()| {});
        window.ui.invoke_install_ca();
        assert!(window.ui.get_confirm_text().is_empty());
        assert_eq!(window.ui.get_message(), "Отметьте хотя бы одно хранилище.");

        // Replacing the certificate asks too.
        window.ui.invoke_issue();
        assert!(window.ui.get_confirm_text().starts_with("Заменить текущий"));
        window.ui.invoke_cancel_confirm();
        assert_eq!(close_requested(window.id), CloseRequestResponse::HideWindow);
        assert!(!is_open());
        assert!(user.certificates().is_empty());
    }

    #[test]
    fn reported_browsers_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        let user = MemoryStore::default();
        let desktop = desktop(dir.path(), &user);
        open(&desktop);
        let window = the_window();
        assert_eq!(window.ui.get_browsers().row_count(), 0);
        desktop.tls.reports.record(
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            OffsetDateTime::now_utc(),
        );
        show_reports(&window);
        let rows = window.ui.get_browsers();
        assert_eq!(rows.row_count(), 1);
        assert_eq!(rows.row_data(0).unwrap().browser, "Firefox 140.0");
        assert_eq!(
            window.ui.get_selftest_url(),
            "https://127.0.0.1:13579/openncalayer/selftest"
        );
        loaded(&window);
        assert_eq!(close_requested(window.id), CloseRequestResponse::HideWindow);
    }
}
