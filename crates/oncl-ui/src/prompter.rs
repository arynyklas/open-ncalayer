//! [`SlintPrompter`]: the dialogs of the signing flow on the Slint event loop.

use crate::foreground;
use crate::ui::{KeyDialog, KeyItem, StorageDialog, StorageRow};
use crate::view;
use oncl_basics::{
    Action, KeyPrompt, Locale, Prompt, Prompter, StorageAnswer, StorageKind, StoragePrompt,
};
use slint::{
    CloseRequestResponse, ComponentHandle, EventLoopError, ModelRc, PlatformError, SharedString,
    VecModel,
};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Shows one dialog at a time process-wide.
static DIALOGS: Mutex<()> = Mutex::new(());

/// How long a call waits for the main thread to start the event loop.
const LOOP_START_TIMEOUT: Duration = Duration::from_secs(10);
/// How often it checks meanwhile.
const LOOP_START_POLL: Duration = Duration::from_millis(20);

/// Runs the dialogs' event loop on the calling thread, which must be the main thread,
/// until [`quit`]. Closing the last dialog does not end it.
///
/// # Errors
///
/// The windowing system cannot be used (e.g. no display).
pub fn run_event_loop() -> Result<(), PlatformError> {
    slint::run_event_loop_until_quit()
}

/// Ends [`run_event_loop`]; callable from any thread.
pub fn quit() {
    if let Err(e) = when_loop_exists(slint::quit_event_loop) {
        tracing::warn!(error = %e, "cannot stop the dialog event loop");
    }
}

/// The signing dialogs in Slint, shown on the event loop of [`run_event_loop`]. Calls
/// block the calling thread until the user answers; a dialog that cannot be shown counts
/// as cancelled.
#[derive(Debug, Default)]
pub struct SlintPrompter {
    _private: (),
}

impl SlintPrompter {
    /// The prompter.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Prompter for SlintPrompter {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        ask(p, show_storage)
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        ask(p, show_keys)
    }
}

/// Opens a dialog with `show` on the event loop and waits for its outcome.
fn ask<P, T>(p: &P, show: fn(P, Sender<Prompt<T>>) -> Result<(), PlatformError>) -> Prompt<T>
where
    P: Clone + Send + 'static,
    T: Send + 'static,
{
    let _turn = DIALOGS.lock().unwrap_or_else(PoisonError::into_inner);
    let (tx, rx) = mpsc::channel();
    let invoked = when_loop_exists(|| {
        let (p, tx) = (p.clone(), tx.clone());
        slint::invoke_from_event_loop(move || {
            if let Err(e) = show(p, tx) {
                tracing::error!(error = %e, "cannot show a signing dialog");
            }
        })
    });
    drop(tx);
    if let Err(e) = invoked {
        tracing::error!(error = %e, "the dialog event loop is not running");
        return Prompt::Cancelled;
    }
    // The sender is dropped without an outcome if the dialog fails to open.
    rx.recv().unwrap_or(Prompt::Cancelled)
}

/// Calls `f` until it stops failing for want of an event loop: the main thread may still be
/// starting it. Gives up after [`LOOP_START_TIMEOUT`].
fn when_loop_exists<R>(
    mut f: impl FnMut() -> Result<R, EventLoopError>,
) -> Result<R, EventLoopError> {
    let deadline = Instant::now() + LOOP_START_TIMEOUT;
    loop {
        match f() {
            Err(EventLoopError::NoEventLoopProvider) if Instant::now() < deadline => {
                std::thread::sleep(LOOP_START_POLL);
            }
            result => return result,
        }
    }
}

/// The storage dialog for `p`; the outcome goes to `reply`.
fn show_storage(
    p: StoragePrompt,
    reply: Sender<Prompt<StorageAnswer>>,
) -> Result<(), PlatformError> {
    let ui = StorageDialog::new()?;
    select_language(p.locale);
    ui.set_origin(p.origin.as_str().into());
    ui.set_authenticate(p.action == Action::Authenticate);
    let rows: Vec<StorageRow> = p
        .storages
        .iter()
        .map(|k| StorageRow {
            label: view::storage_label(*k, p.locale).into(),
            supported: k.supported(),
        })
        .collect();
    ui.set_storages(ModelRc::new(VecModel::from(rows)));
    ui.set_selected(index(p.storages.iter().position(StorageKind::supported)));
    if let Some(path) = &p.recent_path {
        ui.set_path(path.display().to_string().into());
    }
    if let Some(e) = p.error {
        ui.set_error(view::error_text(e, p.locale).into());
    }

    let pending = Pending::new(&ui, reply);
    let weak = ui.as_weak();
    ui.on_browse({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                browse(&ui);
            }
        }
    });
    ui.on_open({
        let pending = pending.clone();
        let storages = p.storages;
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let Some(&storage) = usize::try_from(ui.get_selected())
                .ok()
                .and_then(|i| storages.get(i))
            else {
                return;
            };
            let password = Zeroizing::new(ui.get_password().to_string());
            ui.set_password(SharedString::new());
            pending.finish(Prompt::Answer(StorageAnswer {
                storage,
                path: PathBuf::from(ui.get_path().as_str()),
                password,
            }));
        }
    });
    show(&ui, pending)
}

/// Picks the key store file with the system file dialog, starting in the current file's
/// directory. The directory is not checked here (no file system access on the UI thread):
/// the system dialog falls back to its default folder if it is gone.
fn browse(ui: &StorageDialog) {
    let mut dialog = rfd::AsyncFileDialog::new()
        .add_filter("PKCS#12", &["p12", "pfx"])
        .set_parent(&ui.window().window_handle());
    let current = PathBuf::from(ui.get_path().as_str());
    if let Some(dir) = current.parent().filter(|d| !d.as_os_str().is_empty()) {
        dialog = dialog.set_directory(dir);
    }
    let weak = ui.as_weak();
    let picked = slint::spawn_local(async move {
        if let Some(file) = dialog.pick_file().await
            && let Some(ui) = weak.upgrade()
        {
            ui.set_path(file.path().display().to_string().into());
        }
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

/// The key dialog for `p`; the outcome goes to `reply`.
fn show_keys(p: KeyPrompt, reply: Sender<Prompt<usize>>) -> Result<(), PlatformError> {
    let ui = KeyDialog::new()?;
    select_language(p.locale);
    ui.set_origin(p.origin.as_str().into());
    ui.set_authenticate(p.action == Action::Authenticate);
    let rows = view::key_rows(&p);
    let enabled: Vec<bool> = rows.iter().map(|r| r.enabled).collect();
    let first_enabled = enabled.iter().position(|e| *e);
    ui.set_has_enabled(first_enabled.is_some());
    // Without an enabled key the first one is selected, so its note tells why.
    ui.set_selected(index(first_enabled.or((!rows.is_empty()).then_some(0))));
    let items: Vec<KeyItem> = rows
        .into_iter()
        .map(|r| KeyItem {
            title: r.title.into(),
            details: r.details.into(),
            enabled: r.enabled,
            note: r.note.unwrap_or_default().into(),
        })
        .collect();
    ui.set_keys(ModelRc::new(VecModel::from(items)));

    let pending = Pending::new(&ui, reply);
    let weak = ui.as_weak();
    ui.on_sign({
        let pending = pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if let Some(i) = usize::try_from(ui.get_selected())
                .ok()
                .filter(|&i| enabled.get(i) == Some(&true))
            {
                pending.finish(Prompt::Answer(i));
            }
        }
    });
    show(&ui, pending)
}

/// A dialog's buttons and windowing callbacks shared by both dialogs.
trait Dialog: ComponentHandle + 'static {
    /// Registers the Cancel button's handler.
    fn set_cancel(&self, f: impl FnMut() + 'static);
}

impl Dialog for StorageDialog {
    fn set_cancel(&self, f: impl FnMut() + 'static) {
        StorageDialog::on_cancel(self, f);
    }
}

impl Dialog for KeyDialog {
    fn set_cancel(&self, f: impl FnMut() + 'static) {
        KeyDialog::on_cancel(self, f);
    }
}

/// Wires Cancel and the window's close button to a cancelled outcome, then shows `ui` on
/// top with the focus in it.
fn show<C: Dialog, T: 'static>(ui: &C, pending: Rc<Pending<C, T>>) -> Result<(), PlatformError> {
    ui.set_cancel({
        let pending = pending.clone();
        move || pending.finish(Prompt::Cancelled)
    });
    ui.window().on_close_requested({
        let pending = pending.clone();
        move || {
            pending.finish(Prompt::Cancelled);
            CloseRequestResponse::HideWindow
        }
    });
    ui.show()
        .inspect_err(|_| pending.finish(Prompt::Cancelled))?;
    foreground::take(ui);
    Ok(())
}

/// An open dialog and where its outcome goes. The first outcome is sent; then the window is
/// hidden and released.
struct Pending<C, T>(RefCell<Option<(C, Sender<Prompt<T>>)>>);

impl<C: ComponentHandle + 'static, T> Pending<C, T> {
    /// Keeps `ui` alive until its outcome.
    fn new(ui: &C, reply: Sender<Prompt<T>>) -> Rc<Self> {
        Rc::new(Pending(RefCell::new(Some((ui.clone_strong(), reply)))))
    }

    /// Sends `outcome` unless one was sent; closes the window.
    fn finish(&self, outcome: Prompt<T>) {
        let Some((ui, reply)) = self.0.borrow_mut().take() else {
            return;
        };
        if let Err(e) = ui.hide() {
            tracing::warn!(error = %e, "cannot hide a signing dialog");
        }
        // The asking thread waits on the receiver for as long as the dialog is open.
        let _ = reply.send(outcome);
        // This runs inside one of the window's callbacks: release the window after it.
        slint::Timer::single_shot(Duration::ZERO, move || drop(ui));
    }
}

/// Slint's index for `i`: -1 for none.
fn index(i: Option<usize>) -> i32 {
    i.and_then(|i| i32::try_from(i).ok()).unwrap_or(-1)
}

/// Switches the bundled translation of the `.slint` texts to `l`; English is the source.
fn select_language(l: Locale) {
    let language = match l {
        Locale::Kk => "kk",
        Locale::Ru => "ru",
        Locale::En => "",
    };
    if let Err(e) = slint::select_bundled_translation(language) {
        tracing::warn!(error = %e, language, "cannot select the dialog language");
    }
}
