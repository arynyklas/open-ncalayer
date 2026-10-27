//! [`SlintPrompter`]: the module's dialogs on the Slint event loop.

use crate::foreground;
use crate::ui::{
    CertItem, CsrDialog, FileDialog, ImportDialog, KeyDialog, KeyItem, PasswordDialog,
    StorageDialog, StorageRow,
};
use crate::view;
use oncl_basics::{
    Action, CsrAnswer, CsrPrompt, FileKind, FilePrompt, ImportAnswer, ImportPrompt, KeyPrompt,
    Locale, PasswordPrompt, Prompt, Prompter, StorageAnswer, StorageKind, StoragePrompt,
};
use slint::winit_030::winit::event::WindowEvent;
use slint::winit_030::{EventResult, WinitWindowAccessor};
use slint::{
    CloseRequestResponse, ComponentHandle, EventLoopError, ModelRc, PlatformError, SharedString,
    VecModel,
};
use std::any::Any;
use std::cell::RefCell;
use std::panic::{self, UnwindSafe};
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
/// The windowing system cannot be used (e.g. no display, or a missing library such as
/// `libxkbcommon-x11.so`, which the windowing libraries report by panicking).
pub fn run_event_loop() -> Result<(), PlatformError> {
    catching_panics(slint::run_event_loop_until_quit)
}

/// `f`'s result, or its panic as an error.
fn catching_panics<R>(
    f: impl FnOnce() -> Result<R, PlatformError> + UnwindSafe,
) -> Result<R, PlatformError> {
    panic::catch_unwind(f).unwrap_or_else(|panic| {
        Err(PlatformError::Other(format!(
            "the windowing system failed: {}",
            panic_text(&*panic)
        )))
    })
}

/// The message of a panic payload.
fn panic_text(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic")
}

/// Ends [`run_event_loop`]; callable from any thread.
pub fn quit() {
    if let Err(e) = when_loop_exists(LOOP_START_TIMEOUT, slint::quit_event_loop) {
        tracing::warn!(error = %e, "cannot stop the dialog event loop");
    }
}

/// The module's dialogs in Slint, shown on the event loop of [`run_event_loop`]. Calls
/// block the calling thread until the user answers; a dialog that cannot be shown, or whose
/// window disappears, counts as cancelled.
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

    fn csr(&self, p: &CsrPrompt) -> Prompt<CsrAnswer> {
        ask(p, show_csr)
    }

    fn import_cert(&self, p: &ImportPrompt) -> Prompt<ImportAnswer> {
        ask(p, show_import)
    }

    fn file(&self, p: &FilePrompt) -> Prompt<PathBuf> {
        ask(p, show_file)
    }

    fn password(&self, p: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        ask(p, show_password)
    }
}

/// A dialog to open on the event loop: it gets the prompt and where its outcome goes.
type Show<P, T> = fn(P, Sender<Prompt<T>>) -> Result<(), PlatformError>;

/// A job for the event loop.
type Job = Box<dyn FnOnce() + Send>;

/// Opens a dialog with `show` on the event loop and waits for its outcome.
fn ask<P, T>(p: &P, show: Show<P, T>) -> Prompt<T>
where
    P: Clone + Send + 'static,
    T: Send + 'static,
{
    ask_with(p, show, LOOP_START_TIMEOUT, slint::invoke_from_event_loop)
}

/// [`ask`] with `invoke` running jobs on the event loop, waiting up to `loop_start_timeout`
/// for the loop to exist.
fn ask_with<P, T>(
    p: &P,
    show: Show<P, T>,
    loop_start_timeout: Duration,
    mut invoke: impl FnMut(Job) -> Result<(), EventLoopError>,
) -> Prompt<T>
where
    P: Clone + Send + 'static,
    T: Send + 'static,
{
    let _turn = DIALOGS.lock().unwrap_or_else(PoisonError::into_inner);
    let (tx, rx) = mpsc::channel();
    let invoked = when_loop_exists(loop_start_timeout, || {
        let (p, tx) = (p.clone(), tx.clone());
        invoke(Box::new(move || {
            if let Err(e) = show(p, tx) {
                tracing::error!(error = %e, "cannot show a dialog");
            }
        }))
    });
    drop(tx);
    if let Err(e) = invoked {
        tracing::error!(error = %e, "the dialog event loop is not running");
        return Prompt::Cancelled;
    }
    // Every sender is gone without an outcome if the dialog fails to open, or if the job or
    // the dialog is dropped unanswered.
    rx.recv().unwrap_or(Prompt::Cancelled)
}

/// Calls `f` until it stops failing for want of an event loop: the main thread may still be
/// starting it. Gives up after `timeout`.
fn when_loop_exists<R>(
    timeout: Duration,
    mut f: impl FnMut() -> Result<R, EventLoopError>,
) -> Result<R, EventLoopError> {
    let deadline = Instant::now() + timeout;
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
    ui.set_key_info(p.action == Action::KeyInfo);
    ui.set_detail(p.detail.as_deref().unwrap_or_default().into());
    ui.set_storages(storage_rows(&p.storages, p.locale, StorageKind::readable));
    ui.set_selected(index(p.storages.iter().position(StorageKind::readable)));
    if let Some(path) = &p.recent_path {
        ui.set_path(path.display().to_string().into());
    }
    if let Some(e) = p.error {
        ui.set_error(view::error_text(e, p.locale).into());
    }

    let pending = Pending::new(ui.clone_strong(), reply);
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
        .add_filter("PKCS#12, JKS", &["p12", "pfx", "jks"])
        .set_parent(&ui.window().window_handle());
    let current = PathBuf::from(ui.get_path().as_str());
    if let Some(dir) = current.parent().filter(|d| !d.as_os_str().is_empty()) {
        dialog = dialog.set_directory(dir);
    }
    let weak = ui.as_weak();
    let picked = slint::spawn_local(async move {
        match dialog.pick_file().await {
            Some(file) => {
                if let Some(ui) = weak.upgrade() {
                    ui.set_path(file.path().display().to_string().into());
                }
            }
            // rfd does not tell a cancel from a missing backend (no xdg-desktop-portal and
            // no zenity on Linux); its own `log` errors, if any, precede this line.
            None => tracing::info!("the file dialog returned no file"),
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
    ui.set_key_info(p.action == Action::KeyInfo);
    ui.set_detail(p.detail.as_deref().unwrap_or_default().into());
    ui.set_error(p.error.as_deref().unwrap_or_default().into());
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
            revoked: r.revoked.unwrap_or_default().into(),
        })
        .collect();
    ui.set_keys(ModelRc::new(VecModel::from(items)));

    let pending = Pending::new(ui.clone_strong(), reply);
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

/// The certificate request dialog for `p`; the outcome goes to `reply`.
fn show_csr(p: CsrPrompt, reply: Sender<Prompt<CsrAnswer>>) -> Result<(), PlatformError> {
    let ui = CsrDialog::new()?;
    select_language(p.locale);
    ui.set_origin(p.origin.as_str().into());
    ui.set_storages(storage_rows(&p.storages, p.locale, StorageKind::writable));
    ui.set_selected(index(p.storages.iter().position(StorageKind::writable)));
    ui.set_ask_password(p.ask_password);

    let pending = Pending::new(ui.clone_strong(), reply);
    wire_browse(&ui);
    let weak = ui.as_weak();
    ui.on_confirm({
        let pending = pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let Some(&storage) = usize::try_from(ui.get_selected())
                .ok()
                .and_then(|i| p.storages.get(i))
                .filter(|k| k.writable())
            else {
                return;
            };
            // Checked here, so that the user can correct it; whether the folder exists is
            // the backend's check (no file system access on the UI thread).
            if let Some(e) = view::folder_error(&ui.get_path(), p.locale) {
                ui.set_error(e.into());
                return;
            }
            let password = if p.ask_password {
                let Some(password) = take_new_password(&ui, p.locale) else {
                    return;
                };
                password
            } else {
                Zeroizing::default()
            };
            pending.finish(Prompt::Answer(CsrAnswer {
                storage,
                dir: PathBuf::from(ui.get_path().as_str()),
                password,
            }));
        }
    });
    show(&ui, pending)
}

/// The certificate installation dialog for `p`; the outcome goes to `reply`.
fn show_import(p: ImportPrompt, reply: Sender<Prompt<ImportAnswer>>) -> Result<(), PlatformError> {
    let ui = ImportDialog::new()?;
    select_language(p.locale);
    ui.set_origin(p.origin.as_str().into());
    let items: Vec<CertItem> = view::cert_rows(&p)
        .into_iter()
        .map(|r| CertItem {
            title: r.title.into(),
            details: r.details.into(),
        })
        .collect();
    ui.set_certificates(ModelRc::new(VecModel::from(items)));
    ui.set_storage(view::storage_label(p.storage, p.locale).into());
    ui.set_storage_supported(p.storage.writable());
    if let Some(path) = &p.path {
        ui.set_path(path.display().to_string().into());
    }

    let pending = Pending::new(ui.clone_strong(), reply);
    wire_browse(&ui);
    let weak = ui.as_weak();
    ui.on_confirm({
        let pending = pending.clone();
        let locale = p.locale;
        let supported = p.storage.writable();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if !supported {
                return;
            }
            let Some(password) = take_new_password(&ui, locale) else {
                return;
            };
            pending.finish(Prompt::Answer(ImportAnswer {
                dir: PathBuf::from(ui.get_path().as_str()),
                new_password: password,
            }));
        }
    });
    show(&ui, pending)
}

/// What the certificate request and installation dialogs share: a folder picked with
/// Browse…, and a new key file password with its confirmation.
trait FolderDialog: ComponentHandle + 'static {
    fn path(&self) -> SharedString;
    fn set_path(&self, path: SharedString);
    /// Registers Browse…'s handler.
    fn set_browse(&self, f: impl FnMut() + 'static);
    fn password(&self) -> SharedString;
    fn confirmation(&self) -> SharedString;
    /// Empties the password and its confirmation.
    fn clear_passwords(&self);
    fn set_error(&self, error: SharedString);
}

macro_rules! folder_dialog {
    ($($dialog:ty),*) => {$(
        impl FolderDialog for $dialog {
            fn path(&self) -> SharedString {
                self.get_path()
            }
            fn set_path(&self, path: SharedString) {
                <$dialog>::set_path(self, path);
            }
            fn set_browse(&self, f: impl FnMut() + 'static) {
                self.on_browse(f);
            }
            fn password(&self) -> SharedString {
                self.get_password()
            }
            fn confirmation(&self) -> SharedString {
                self.get_confirmation()
            }
            fn clear_passwords(&self) {
                <$dialog>::set_password(self, SharedString::new());
                <$dialog>::set_confirmation(self, SharedString::new());
            }
            fn set_error(&self, error: SharedString) {
                <$dialog>::set_error(self, error);
            }
        }
    )*};
}

folder_dialog!(CsrDialog, ImportDialog);

/// Wires Browse… of `ui` to the system folder dialog, starting in the dialog's folder.
fn wire_browse<D: FolderDialog>(ui: &D) {
    let weak = ui.as_weak();
    ui.set_browse(move || {
        if let Some(ui) = weak.upgrade() {
            let weak = ui.as_weak();
            pick_folder(ui.window(), &FolderDialog::path(&ui), move |dir| {
                if let Some(ui) = weak.upgrade() {
                    FolderDialog::set_path(&ui, dir.into());
                }
            });
        }
    });
}

/// The new key file password of `ui`, emptied in the dialog, if it and its confirmation
/// pass [`view::new_password_error`]; otherwise the dialog shows why and keeps them.
fn take_new_password<D: FolderDialog>(ui: &D, l: Locale) -> Option<Zeroizing<String>> {
    let password = Zeroizing::new(ui.password().to_string());
    let confirmation = Zeroizing::new(ui.confirmation().to_string());
    if let Some(e) = view::new_password_error(&password, &confirmation, l) {
        FolderDialog::set_error(ui, e.into());
        return None;
    }
    ui.clear_passwords();
    Some(password)
}

/// The rows of a storage list; the storages `usable` accepts may be picked.
fn storage_rows(
    storages: &[StorageKind],
    l: Locale,
    usable: fn(&StorageKind) -> bool,
) -> ModelRc<StorageRow> {
    let rows: Vec<StorageRow> = storages
        .iter()
        .map(|k| StorageRow {
            label: view::storage_label(*k, l).into(),
            supported: usable(k),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// Picks a folder with the system folder dialog, starting in `current`, and hands it to
/// `set`. As in [`browse`], the folder is not checked on the UI thread.
fn pick_folder(window: &slint::Window, current: &str, set: impl FnOnce(String) + 'static) {
    let mut dialog = rfd::AsyncFileDialog::new().set_parent(&window.window_handle());
    if !current.is_empty() {
        dialog = dialog.set_directory(current);
    }
    let picked = slint::spawn_local(async move {
        match dialog.pick_folder().await {
            Some(dir) => set(dir.path().display().to_string()),
            // As in `browse`: a cancel and a missing backend look the same.
            None => tracing::info!("the folder dialog returned no folder"),
        }
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the folder dialog");
    }
}

/// The file chooser for `p`: a small always-on-top window naming the requesting page, which
/// takes the foreground and opens the system file (or folder) dialog over itself, with the
/// original's extension filter and start folder; the outcome goes to `reply`. As in
/// [`browse`], the start folder is not checked here.
fn show_file(p: FilePrompt, reply: Sender<Prompt<PathBuf>>) -> Result<(), PlatformError> {
    let ui = FileDialog::new()?;
    select_language(p.locale);
    ui.set_origin(p.origin.as_str().into());
    ui.set_heading(view::file_dialog_title(p.kind, p.locale).into());
    let pending = Pending::new(ui.clone_strong(), reply);
    let weak = ui.as_weak();
    ui.on_browse({
        let pending = pending.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                pick(&ui, &p, pending.clone());
            }
        }
    });
    show(&ui, pending)?;
    ui.invoke_browse();
    Ok(())
}

/// Opens the system dialog for `p` over `ui`; a choice answers `pending`, a cancel cancels
/// it (rfd does not tell a cancel from a missing backend).
fn pick(ui: &FileDialog, p: &FilePrompt, pending: Rc<Pending<FileDialog, PathBuf>>) {
    let mut dialog = rfd::AsyncFileDialog::new()
        .set_title(view::file_dialog_title(p.kind, p.locale))
        .set_parent(&ui.window().window_handle());
    let extensions = p.kind.extensions();
    if !extensions.is_empty() {
        dialog = dialog.add_filter(view::file_filter_name(p.kind), extensions);
    }
    if let Some(dir) = &p.directory {
        dialog = dialog.set_directory(dir);
    }
    let folder = p.kind == FileKind::Directory;
    let picked = slint::spawn_local(async move {
        let picked = if folder {
            dialog.pick_folder().await
        } else {
            dialog.pick_file().await
        };
        match picked {
            Some(handle) => pending.finish(Prompt::Answer(handle.path().to_path_buf())),
            None => pending.cancel(),
        };
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

/// The password dialog for `p`; the outcome goes to `reply`.
fn show_password(
    p: PasswordPrompt,
    reply: Sender<Prompt<Zeroizing<String>>>,
) -> Result<(), PlatformError> {
    let ui = PasswordDialog::new()?;
    select_language(p.locale);
    ui.set_origin(p.origin.as_str().into());
    ui.set_message(p.message.as_deref().unwrap_or_default().into());

    let pending = Pending::new(ui.clone_strong(), reply);
    let weak = ui.as_weak();
    ui.on_confirm({
        let pending = pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let password = Zeroizing::new(ui.get_password().to_string());
            ui.set_password(SharedString::new());
            pending.finish(Prompt::Answer(password));
        }
    });
    show(&ui, pending)
}

/// A dialog's buttons and windowing callbacks shared by every dialog.
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

impl Dialog for CsrDialog {
    fn set_cancel(&self, f: impl FnMut() + 'static) {
        CsrDialog::on_cancel(self, f);
    }
}

impl Dialog for ImportDialog {
    fn set_cancel(&self, f: impl FnMut() + 'static) {
        ImportDialog::on_cancel(self, f);
    }
}

impl Dialog for FileDialog {
    fn set_cancel(&self, f: impl FnMut() + 'static) {
        FileDialog::on_cancel(self, f);
    }
}

impl Dialog for PasswordDialog {
    fn set_cancel(&self, f: impl FnMut() + 'static) {
        PasswordDialog::on_cancel(self, f);
    }
}

/// Wires Cancel, the window's close button and the window's destruction to a cancelled
/// outcome, then shows `ui` on top with the focus in it.
fn show<C: Dialog, T: 'static>(ui: &C, pending: Rc<Pending<C, T>>) -> Result<(), PlatformError> {
    ui.set_cancel({
        let pending = pending.clone();
        move || {
            pending.cancel();
        }
    });
    ui.window().on_close_requested({
        let pending = pending.clone();
        move || on_close_requested(&pending)
    });
    // A window destroyed underneath Slint (xkill, `xdotool windowclose`, a compositor
    // restart) sends no close request; without this the asking thread would wait forever.
    ui.window().on_winit_window_event({
        let pending = pending.clone();
        move |_, event| on_window_event(&pending, event)
    });
    ui.show().inspect_err(|_| {
        pending.cancel();
    })?;
    foreground::take(ui);
    Ok(())
}

/// The window's close button: cancelled.
fn on_close_requested<W: Closable, T>(pending: &Pending<W, T>) -> CloseRequestResponse {
    pending.cancel();
    CloseRequestResponse::HideWindow
}

/// A window gone without a close request: cancelled. Other events go on to Slint.
fn on_window_event<W: Closable, T>(pending: &Pending<W, T>, event: &WindowEvent) -> EventResult {
    if matches!(event, WindowEvent::Destroyed) && pending.cancel() {
        tracing::warn!("a dialog window was destroyed without being closed");
    }
    EventResult::Propagate
}

/// What [`Pending`] needs of a dialog: closing it once the outcome is known.
trait Closable {
    /// Hides the window and releases it.
    fn close(self);
}

impl<D: Dialog> Closable for D {
    fn close(self) {
        if let Err(e) = self.hide() {
            tracing::warn!(error = %e, "cannot hide a dialog");
        }
        // This runs inside one of the window's callbacks: release the window after it.
        slint::Timer::single_shot(Duration::ZERO, move || drop(self));
    }
}

/// An open dialog and where its outcome goes. The first outcome is sent; then the window is
/// closed. Dropped unanswered, it drops the sender, which the asking thread reads as
/// cancelled.
struct Pending<W, T>(RefCell<Option<(W, Sender<Prompt<T>>)>>);

impl<W: Closable, T> Pending<W, T> {
    /// Keeps `ui` (a strong handle) until the outcome.
    fn new(ui: W, reply: Sender<Prompt<T>>) -> Rc<Self> {
        Rc::new(Pending(RefCell::new(Some((ui, reply)))))
    }

    /// Closes the window and sends `outcome`, unless an outcome was sent already. Returns
    /// whether this call sent it.
    fn finish(&self, outcome: Prompt<T>) -> bool {
        let Some((ui, reply)) = self.0.borrow_mut().take() else {
            return false;
        };
        ui.close();
        // The asking thread waits on the receiver for as long as the dialog is open.
        let _ = reply.send(outcome);
        true
    }

    /// [`Self::finish`] with [`Prompt::Cancelled`].
    fn cancel(&self) -> bool {
        self.finish(Prompt::Cancelled)
    }
}

/// Slint's index for `i`: -1 for none.
fn index(i: Option<usize>) -> i32 {
    i.and_then(|i| i32::try_from(i).ok()).unwrap_or(-1)
}

/// Switches the bundled translation of the `.slint` texts to `l`; English is the source. The
/// translation is the process's: every open dialog and window follows it.
pub(crate) fn select_language(l: Locale) {
    let language = match l {
        Locale::Kk => "kk",
        Locale::Ru => "ru",
        Locale::En => "",
    };
    if let Err(e) = slint::select_bundled_translation(language) {
        tracing::warn!(error = %e, language, "cannot select the dialog language");
    }
}

/// The control flow around the dialogs, without a display: windows are stand-ins and the
/// event loop is a thread.
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    /// A window that counts how often it was closed.
    struct FakeWindow(Rc<Cell<u32>>);

    impl Closable for FakeWindow {
        fn close(self) {
            self.0.set(self.0.get() + 1);
        }
    }

    type Outcomes = mpsc::Receiver<Prompt<u8>>;

    /// A pending dialog, its outcomes and how often its window was closed.
    fn pending() -> (Rc<Pending<FakeWindow, u8>>, Outcomes, Rc<Cell<u32>>) {
        let closed = Rc::new(Cell::new(0));
        let (tx, rx) = mpsc::channel();
        (Pending::new(FakeWindow(closed.clone()), tx), rx, closed)
    }

    fn outcomes(rx: &mpsc::Receiver<Prompt<u8>>) -> Vec<Prompt<u8>> {
        rx.try_iter().collect()
    }

    #[test]
    fn first_outcome_wins_and_closes_once() {
        let (p, rx, closed) = pending();
        assert!(p.finish(Prompt::Answer(5)));
        assert!(!p.cancel());
        assert!(!p.finish(Prompt::Answer(6)));
        assert_eq!(outcomes(&rx), [Prompt::Answer(5)]);
        assert_eq!(closed.get(), 1);
    }

    #[test]
    fn close_button_cancels() {
        let (p, rx, closed) = pending();
        assert!(matches!(
            on_close_requested(&p),
            CloseRequestResponse::HideWindow
        ));
        assert_eq!(outcomes(&rx), [Prompt::Cancelled]);
        assert_eq!(closed.get(), 1);
        // A late button press after the close changes nothing.
        assert!(!p.finish(Prompt::Answer(1)));
        assert!(outcomes(&rx).is_empty());
    }

    #[test]
    fn destroyed_window_cancels() {
        let (p, rx, closed) = pending();
        assert_eq!(
            on_window_event(&p, &WindowEvent::Focused(true)),
            EventResult::Propagate
        );
        assert!(
            outcomes(&rx).is_empty(),
            "other events keep the dialog open"
        );
        assert_eq!(
            on_window_event(&p, &WindowEvent::Destroyed),
            EventResult::Propagate
        );
        assert_eq!(outcomes(&rx), [Prompt::Cancelled]);
        assert_eq!(closed.get(), 1);

        // Destroyed after an answer (the window released after Sign): no second outcome.
        let (p, rx, closed) = pending();
        assert!(p.finish(Prompt::Answer(2)));
        on_window_event(&p, &WindowEvent::Destroyed);
        assert_eq!(outcomes(&rx), [Prompt::Answer(2)]);
        assert_eq!(closed.get(), 1);
    }

    #[test]
    fn dropped_pending_reads_as_cancelled() {
        let (p, rx, closed) = pending();
        drop(p);
        assert_eq!(rx.recv(), Err(mpsc::RecvError));
        assert_eq!(closed.get(), 0);
    }

    /// An event loop on a thread: runs each job there, after failing `missing` times for
    /// want of an event loop. Counts the attempts.
    fn event_loop(
        missing: usize,
        attempts: Arc<AtomicUsize>,
    ) -> impl FnMut(Job) -> Result<(), EventLoopError> {
        move |job| {
            if attempts.fetch_add(1, Ordering::SeqCst) < missing {
                return Err(EventLoopError::NoEventLoopProvider);
            }
            thread::spawn(job);
            Ok(())
        }
    }

    fn answer(p: u8, reply: Sender<Prompt<u8>>) -> Result<(), PlatformError> {
        reply.send(Prompt::Answer(p + 1)).unwrap();
        Ok(())
    }

    #[test]
    fn retries_until_the_event_loop_exists() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let r = ask_with(
            &41,
            answer,
            Duration::from_secs(10),
            event_loop(3, attempts.clone()),
        );
        assert_eq!(r, Prompt::Answer(42));
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn no_event_loop_is_cancelled() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let r = ask_with(
            &1,
            answer,
            Duration::from_millis(100),
            event_loop(usize::MAX, attempts.clone()),
        );
        assert_eq!(r, Prompt::Cancelled);
        assert!(attempts.load(Ordering::SeqCst) > 1, "it retried");
        assert!(started.elapsed() < Duration::from_secs(5));

        // A terminated loop is not waited for.
        let r = ask_with(&1, answer, Duration::from_secs(10), |_| {
            Err(EventLoopError::EventLoopTerminated)
        });
        assert_eq!(r, Prompt::Cancelled);
    }

    #[test]
    fn dropped_sender_is_cancelled() {
        fn drops(_: u8, reply: Sender<Prompt<u8>>) -> Result<(), PlatformError> {
            drop(reply);
            Ok(())
        }
        fn fails(_: u8, _: Sender<Prompt<u8>>) -> Result<(), PlatformError> {
            Err(PlatformError::Other("no window".into()))
        }
        for show in [drops as Show<u8, u8>, fails] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let r = ask_with(&1, show, Duration::from_secs(10), event_loop(0, attempts));
            assert_eq!(r, Prompt::Cancelled);
        }
        // The event loop drops the job without running it (e.g. it is shutting down).
        let r = ask_with(&1, answer, Duration::from_secs(10), |job| {
            drop(job);
            Ok(())
        });
        assert_eq!(r, Prompt::Cancelled);
    }

    #[test]
    fn panics_of_the_windowing_system_are_errors() {
        let r: Result<(), _> =
            catching_panics(|| panic!("Library libxkbcommon-x11.so could not be loaded."));
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("the windowing system failed: Library libxkbcommon-x11.so"),
            "{e}"
        );
        let r: Result<(), _> = catching_panics(|| panic!("{}", String::from("formatted")));
        assert!(r.unwrap_err().to_string().ends_with("formatted"));
        assert_eq!(catching_panics(|| Ok(3)).unwrap(), 3);
    }
}
