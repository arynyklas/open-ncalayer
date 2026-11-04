//! The tools window («Инструменты»): one place for the actions the user starts by hand, as
//! opposed to the windows a site's request opens. A sidebar picks the page; a status line under
//! all pages shows what runs, how far it is and how it ended; the pages' errors sit by their
//! fields. Today its pages are the overview, the hash of a file and the public details of a
//! certificate, a signature file, a key store or the tokens plugged in.
//!
//! [`open_workspace`] shows it (or brings the open one forward) when the host asks: the tray
//! menu, `openncalayer tools`, a second start of the program. Nothing opens it by itself: not a
//! site's request, not the start or the login.
//!
//! The actions run through the SDK's [`Engine`](oncl_core::Engine) on a worker thread, so the
//! event loop never waits for a file ([`controller`]); the window holds nothing of a password
//! once an action has started.

mod controller;
mod evidence;
mod jobs;
mod operations;
#[doc(hidden)]
pub mod progress;
mod sign;
mod tools;

pub use self::controller::JobControl;
pub(crate) use self::controller::JobError;
pub(crate) use self::evidence::Evidence;
pub(crate) use self::jobs::hash_file;
pub(crate) use self::operations::{
    Destination, Document, ExtendFormat, Level, NCA_TSA_POLICY, PlannedOutput, SignFormat,
    SignInput, SignOptions, SignSpec, StampOptions, ToolSpec, VerifyFormat, VerifyOptions,
    batch_operation_error, evidence_limits, open_regular, plan_output, read_limited, run_tool,
    sign_operation, tsa_spec, view_of_summary,
};

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use oncl_core::{Engine, ErrorCode};
use oncl_flows::Locale;
use oncl_pki::key::HashAlg;
use oncl_token::{ScanProblem, TokenKind, Tokens};
use slint::{CloseRequestResponse, ComponentHandle, PlatformError};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use self::controller::{Busy, Controller, Job, MissingField, Settled};
use self::jobs::{Entry, HashOutput, Inspect, InspectOutput};
use self::progress::{Reporter, Stamp, Update};
use crate::foreground;
use crate::prompter::select_desktop_language;
use crate::reports::controller::BatchView;
use crate::ui::{ReportRow, WorkspaceWindow};
use crate::windows;

/// What the tools window works with: the engine of this program and its hardware tokens.
/// The host builds it once; cloning shares the same engine (and so its one resource budget:
/// one operation at a time).
#[derive(Clone)]
pub struct DesktopEngineServices {
    pub engine: Arc<Engine>,
    /// Lets the engine apply the key only for the user's confirmation; built with the engine.
    pub guard: Arc<crate::signing::runner::ConsentGuard>,
    pub tokens: Arc<Tokens>,
    /// The time the certificates are judged by (the system clock; tests set their own).
    pub clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    /// `settings.json`: where the recent files and favourite certificates are kept.
    pub settings_path: PathBuf,
}

/// The pages of the window, as the sidebar numbers them.
const SECTION_SIGN: i32 = 1;
const SECTION_HASH: i32 = 6;
const SECTION_INSPECT: i32 = 7;

/// What an action gives back to its page.
enum Output {
    /// The digest and the index of the algorithm in the page's list.
    Hash(HashOutput, i32),
    Inspect(InspectOutput),
    Sign(sign::SignOutput),
    /// The report of a run of a tool that uses no key.
    Tool(BatchView),
}

struct Workspace {
    ui: WorkspaceWindow,
    services: DesktopEngineServices,
    controller: RefCell<Controller>,
    /// The language the texts were composed in.
    locale: Cell<Locale>,
    /// What the page was asked to inspect by the action that runs or ran last.
    inspect_kind: Cell<i32>,
    sign: RefCell<sign::State>,
    tools: RefCell<tools::State>,
}

thread_local! {
    static OPEN: RefCell<Option<Rc<Workspace>>> = const { RefCell::new(None) };
}

/// Shows the tools window, or brings the open one to the front; callable from any thread,
/// returns at once. Without an event loop the request is only logged.
pub fn open_workspace(services: DesktopEngineServices) {
    if let Err(e) = slint::invoke_from_event_loop(move || open_now(services)) {
        tracing::info!(error = %e, "no windows: the tools window is not opened");
    }
}

/// Whether the tools window is open. On the event loop; elsewhere it is `false`.
pub(crate) fn is_open() -> bool {
    OPEN.with_borrow(Option::is_some)
}

fn current() -> Option<Rc<Workspace>> {
    OPEN.with_borrow(Clone::clone)
}

fn desktop_locale() -> Locale {
    windows::desktop().map_or(Locale::Ru, |d| d.locale.get())
}

fn open_now(services: DesktopEngineServices) {
    if let Some(open) = current() {
        select_desktop_language(desktop_locale());
        if let Err(e) = open.ui.show() {
            tracing::warn!(error = %e, "cannot show the tools window");
        }
        foreground::take(&open.ui);
        return;
    }
    if let Err(e) = create(services) {
        tracing::error!(error = %e, "cannot show the tools window");
    }
}

fn create(services: DesktopEngineServices) -> Result<(), PlatformError> {
    let ui = WorkspaceWindow::new()?;
    let settings_path = services.settings_path.clone();
    let locale = desktop_locale();
    // After the window exists: the bundled translations come with it.
    select_desktop_language(locale);
    let texts = Texts::of(locale);
    ui.set_status_text(texts.ready.into());
    ui.on_start_hash(|| with_open(start_hash));
    ui.on_start_inspect(|| with_open(start_inspect));
    ui.on_browse(|| with_open(browse));
    ui.on_cancel(|| with_open(cancel));
    sign::connect(&ui);
    tools::connect(&ui);
    ui.window().on_close_requested(|| {
        if closing_is_blocked() {
            return CloseRequestResponse::KeepWindowShown;
        }
        close();
        CloseRequestResponse::HideWindow
    });
    let workspace = Rc::new(Workspace {
        ui: ui.clone_strong(),
        services,
        controller: RefCell::new(Controller::default()),
        locale: Cell::new(locale),
        inspect_kind: Cell::new(0),
        sign: RefCell::new(sign::State::new(
            oncl_desktop::Remembered::load(&settings_path).unwrap_or_default(),
        )),
        tools: RefCell::default(),
    });
    OPEN.set(Some(Rc::clone(&workspace)));
    sign::render(&workspace);
    if let Err(e) = ui.show() {
        OPEN.set(None);
        return Err(e);
    }
    foreground::take(&ui);
    Ok(())
}

/// A workspace on the test thread's offscreen platform, wired exactly as [`create`] wires it
/// (the same callbacks, the same state), without showing a window.
#[cfg(test)]
fn test_workspace(services: DesktopEngineServices) -> Rc<Workspace> {
    thread_local! {
        static OFFSCREEN: crate::offscreen::Last = crate::offscreen::install();
    }
    OFFSCREEN.with(|_| ());
    let ui = WorkspaceWindow::new().unwrap();
    ui.on_start_hash(|| with_open(start_hash));
    ui.on_start_inspect(|| with_open(start_inspect));
    ui.on_browse(|| with_open(browse));
    ui.on_cancel(|| with_open(cancel));
    sign::connect(&ui);
    tools::connect(&ui);
    let settings_path = services.settings_path.clone();
    let workspace = Rc::new(Workspace {
        ui,
        services,
        controller: RefCell::new(Controller::default()),
        locale: Cell::new(Locale::En),
        inspect_kind: Cell::new(0),
        sign: RefCell::new(sign::State::new(
            oncl_desktop::Remembered::load(&settings_path).unwrap_or_default(),
        )),
        tools: RefCell::default(),
    });
    OPEN.set(Some(Rc::clone(&workspace)));
    sign::render(&workspace);
    workspace
}

/// Runs `f` with the open window, if any (the callbacks hold no strong reference to it).
fn with_open(f: impl FnOnce(&Rc<Workspace>)) {
    if let Some(open) = current() {
        f(&open);
    }
}

/// Closes the window: what runs is asked to stop, and its result is dropped when it comes.
fn close() {
    let Some(open) = OPEN.take() else {
        return;
    };
    abandon_signing(&open);
    open.controller.borrow_mut().close();
    if let Err(e) = open.ui.hide() {
        tracing::warn!(error = %e, "cannot hide the tools window");
    }
    // This runs inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(open));
}

fn cancel(open: &Rc<Workspace>) {
    if open.ui.get_section() == SECTION_SIGN {
        // Escape and the status line's Cancel mean what the page's Cancel means at its step.
        return sign::cancel(open);
    }
    if open.controller.borrow_mut().cancel() {
        open.ui
            .set_status_text(Texts::of(open.locale.get()).cancelling.into());
    }
}

fn algorithm(index: i32) -> HashAlg {
    match index {
        1 => HashAlg::Gost34311,
        2 => HashAlg::Streebog512,
        _ => HashAlg::Sha256,
    }
}

fn algorithm_name(t: &Texts, index: i32) -> &'static str {
    match index {
        1 => t.gost2004,
        2 => t.gost2015,
        _ => "SHA-256",
    }
}

/// The limits of the manual tools: what the platform allows a document (10 GiB), and no
/// short deadline, because a hash of a large file over a slow disk may take hours and the
/// user stops it with Cancel. The tools' text says so.
pub fn desktop_limits() -> oncl_pki::resource::ResourceLimits {
    oncl_pki::resource::ResourceLimits {
        operation_timeout: Duration::from_secs(24 * 60 * 60),
        ..oncl_pki::resource::ResourceLimits::default()
    }
}

/// A path as typed or pasted: Explorer's «Copy as path» wraps it in quotes.
fn typed_path(text: slint::SharedString) -> String {
    text.trim().trim_matches('"').trim().to_owned()
}

/// The rows of a report as the page's model.
fn report_rows(rows: &[crate::reports::Row]) -> slint::ModelRc<ReportRow> {
    slint::ModelRc::new(slint::VecModel::from(
        rows.iter()
            .map(|row| ReportRow {
                depth: row.depth,
                tone: crate::reports::tone_number(row.tone),
                text: row.text.as_str().into(),
                detail: row.detail.as_str().into(),
            })
            .collect::<Vec<_>>(),
    ))
}

fn start_hash(open: &Rc<Workspace>) {
    let path = typed_path(open.ui.get_hash_path());
    if path.is_empty() {
        return reject(open, SECTION_HASH, &JobError::Input(MissingField::Path));
    }
    let index = open.ui.get_hash_algorithm();
    let alg = algorithm(index);
    open.ui.set_hash_digest("".into());
    open.ui.set_hash_summary("".into());
    start(open, Job::Hash, move |services, control| {
        let out = jobs::hash_file(&services.engine, alg, &PathBuf::from(path), control)?;
        Ok(Output::Hash(out, index))
    });
}

fn start_inspect(open: &Rc<Workspace>) {
    let kind = open.ui.get_inspect_kind();
    open.inspect_kind.set(kind);
    let path = typed_path(open.ui.get_inspect_path());
    // Taken out of the window at once; the worker owns it from here and zeroizes it.
    let password = Zeroizing::new(open.ui.get_inspect_password().to_string());
    let aliases = open.ui.get_inspect_aliases().to_string();
    let problem = match kind {
        3 => None,
        _ if path.is_empty() => Some(MissingField::Path),
        2 if password.is_empty() => Some(MissingField::Password),
        _ => None,
    };
    if let Some(problem) = problem {
        return reject(open, SECTION_INSPECT, &JobError::Input(problem));
    }
    let what = match kind {
        0 => Inspect::Certificate(path.into()),
        1 => Inspect::Signature(path.into()),
        2 => Inspect::KeyStore {
            path: path.into(),
            password,
            aliases: aliases
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .map(str::to_owned)
                .collect(),
        },
        _ => Inspect::Tokens,
    };
    open.ui.set_inspect_password("".into());
    open.ui.set_inspect_report("".into());
    start(open, Job::Inspect, move |services, control| {
        jobs::inspect(&services.engine, &services.tokens, what, control).map(Output::Inspect)
    });
}

/// Starts `work` on a worker thread; its result comes back to [`settle`], and how far it is to
/// [`apply_progress`], both on the event loop and both only if the window and the operation
/// they were started by are still the current ones ([`progress`]).
fn start(
    open: &Rc<Workspace>,
    job: Job,
    work: impl FnOnce(&DesktopEngineServices, &Arc<JobControl>) -> Result<Output, JobError>
    + Send
    + 'static,
) {
    let started = match open.controller.borrow_mut().begin(job, |stamp| {
        JobControl::reporting(Reporter::new(stamp, apply_progress))
    }) {
        Ok(started) => started,
        Err(Busy) => return,
    };
    let ui = &open.ui;
    let t = Texts::of(open.locale.get());
    ui.set_error_text("".into());
    ui.set_busy(true);
    ui.set_status_kind(1);
    ui.set_progress(-1.0);
    ui.set_status_text(
        match job {
            Job::Hash => t.hashing,
            Job::Inspect => t.inspecting,
            Job::Sign | Job::Tool => t.working,
        }
        .into(),
    );
    if job == Job::Sign {
        sign::render(open);
    }
    let (stamp, control) = (started.stamp, started.control);
    let services = open.services.clone();
    #[cfg(test)]
    let ui_thread = std::thread::current().id();
    let Some(reporter) = control.reporter().cloned() else {
        // The control was made above with its reporter: a missing one is a bug, said as a
        // failure to start, never as silence.
        tracing::error!("an operation without a reporter");
        settle(stamp, Err(JobError::Worker));
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("workspace".into())
        .spawn(move || {
            #[cfg(test)]
            WORKER_FOR.with(|c| c.set(Some(ui_thread)));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                work(&services, &control)
            }))
            .unwrap_or_else(|panic| {
                tracing::error!(
                    panic = crate::prompter::panic_text(&*panic),
                    "an action broke off"
                );
                Err(JobError::Worker)
            });
            // On its own path: a full progress queue cannot lose the outcome.
            reporter.finish(result, settle);
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "cannot start a worker thread");
        settle(stamp, Err(JobError::Worker));
    }
}

/// The way a worker's closure reaches the event loop, for the progress handoff: whether it was
/// handed over. The same function serves the application and the integration test on a real
/// event loop; the unit tests of the windows have none and pump their queue instead.
#[cfg(not(test))]
fn deliver_boxed(f: Box<dyn FnOnce() + Send>) -> bool {
    match slint::invoke_from_event_loop(f) {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(error = %e, "a worker's word or outcome is lost: the event loop is gone");
            false
        }
    }
}

#[cfg(test)]
fn deliver_boxed(f: Box<dyn FnOnce() + Send>) -> bool {
    deliver(f);
    true
}

/// Hands `f` from a worker to the event loop. Tests have no loop: they pump the queue.
#[cfg(not(test))]
pub(crate) fn deliver(f: impl FnOnce() + Send + 'static) {
    if let Err(e) = slint::invoke_from_event_loop(f) {
        tracing::warn!(error = %e, "a worker's answer is lost");
    }
}

#[cfg(test)]
mod parity;

#[cfg(test)]
type Delivery = Box<dyn FnOnce() + Send>;

/// Deliveries by the thread they are for: tests run in parallel, each with its own page.
#[cfg(test)]
static DELIVERIES: std::sync::Mutex<Vec<(std::thread::ThreadId, Delivery)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
thread_local! {
    /// On a worker: the thread whose page it works for.
    static WORKER_FOR: Cell<Option<std::thread::ThreadId>> = const { Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn deliver(f: impl FnOnce() + Send + 'static) {
    let target = WORKER_FOR
        .with(Cell::get)
        .expect("deliver is called by a worker");
    DELIVERIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((target, Box::new(f)));
}

/// This thread's pending deliveries, held back; they go back to the queue when this is dropped,
/// whichever way the test ends. Other pages' deliveries are never touched.
#[cfg(test)]
pub(crate) struct Held(Vec<(std::thread::ThreadId, Delivery)>);

#[cfg(test)]
impl Held {
    pub(crate) fn take_mine() -> Held {
        let me = std::thread::current().id();
        let mut all = DELIVERIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mine, rest) = std::mem::take(&mut *all)
            .into_iter()
            .partition::<Vec<_>, _>(|(t, _)| *t == me);
        *all = rest;
        Held(mine)
    }
}

#[cfg(test)]
impl Drop for Held {
    fn drop(&mut self) {
        DELIVERIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .append(&mut self.0);
    }
}

/// Runs what the workers delivered, on this thread, in order; how many ran.
#[cfg(test)]
pub(crate) fn pump() -> usize {
    let me = std::thread::current().id();
    let mine: Vec<Delivery> = {
        let mut all = DELIVERIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mine, rest) = std::mem::take(&mut *all)
            .into_iter()
            .partition::<Vec<_>, _>(|(t, _)| *t == me);
        *all = rest;
        mine.into_iter().map(|(_, f)| f).collect()
    };
    let n = mine.len();
    for f in mine {
        f();
    }
    n
}

/// A word of a running action reaches the event loop: shown only if the window and the
/// operation it names are still the current ones.
fn apply_progress(stamp: Stamp, update: Update) {
    with_open(|open| {
        let controller = open.controller.borrow();
        if !controller.accepts(stamp) {
            return;
        }
        let Some((job, control)) = controller.running() else {
            return;
        };
        // «Cancelling…» stays until the action ends; the signing page tells its own state
        // while it waits for the user's confirmation.
        if control.is_cancelled() || (job == Job::Sign && !sign::shows_progress(open)) {
            return;
        }
        let (fraction, text) = describe(Texts::of(open.locale.get()), update);
        open.ui.set_progress(fraction);
        open.ui.set_status_text(text.into());
    });
}

/// How far the action is, for the status line: the fraction of the bar (below 0: not known)
/// and the words. A batch counts documents: the bytes of each pass over each document are not
/// known beforehand, so they are told as they are and never turned into a percentage.
fn describe(t: &Texts, update: Update) -> (f32, String) {
    if update.items > 0 {
        if update.started == 0 {
            return (
                -1.0,
                t.preparing
                    .replace("{0}", &update.items.to_string())
                    .replace("{1}", &size(t, update.bytes_in)),
            );
        }
        let before = (update.started - 1).min(update.items);
        return (
            before as f32 / update.items as f32,
            t.document
                .replace("{0}", &update.started.to_string())
                .replace("{1}", &update.items.to_string())
                .replace("{2}", &size(t, update.bytes_in)),
        );
    }
    match update.total {
        Some(total) => (
            (update.bytes_in as f64 / total as f64).min(1.0) as f32,
            t.progress
                .replace("{0}", &size(t, update.bytes_in))
                .replace("{1}", &size(t, total)),
        ),
        None => (
            -1.0,
            t.progress_unknown.replace("{0}", &size(t, update.bytes_in)),
        ),
    }
}

/// A signing that the user confirmed is running (and no cancel has run out its wait): the window
/// stays, and says why. After the cancel notice the step is Result, so the window may be closed
/// («Close anyway»): see [`abandon_signing`].
fn closing_is_blocked() -> bool {
    current().is_some_and(|open| closing_is_blocked_for(&open))
}

fn closing_is_blocked_for(open: &Rc<Workspace>) -> bool {
    if sign::is_running(open) {
        open.ui.set_status_kind(4);
        open.ui
            .set_status_text(Texts::of(open.locale.get()).signing_running.into());
        true
    } else {
        false
    }
}

/// The window is closed while a signing worker is alive. Whether the key could have been applied
/// is read from the operation's own control, which the runner marks when it lets the key be
/// applied (never from the UI step): before that gate (the worker waits for the decision) the key
/// was never used and the worker is aborted: logged quietly with `key_use="none"`; after it the
/// answer is only the engine's, so it is `key_use="unknown"` at error level. The worker is left
/// to finish in the background (it holds no UI handle: its words and outcome are refused by the
/// closed window's lifecycle and logged). Returns the stamp and whether the key may have been
/// applied.
fn abandon_signing(open: &Rc<Workspace>) -> Option<(Stamp, bool)> {
    let controller = open.controller.borrow();
    let (job, control) = controller.running()?;
    if job != Job::Sign {
        return None;
    }
    let stamp = controller.running_stamp()?;
    let may_have_applied = control.key_gate_passed();
    if may_have_applied {
        tracing::error!(
            window = stamp.window,
            generation = stamp.generation,
            key_use = "unknown",
            "the window was closed while a signing had not answered: whether the key was applied is unknown; the worker finishes in the background"
        );
    } else {
        tracing::info!(
            window = stamp.window,
            generation = stamp.generation,
            key_use = "none",
            "the window was closed before the key could be used; the waiting worker is aborted"
        );
    }
    Some((stamp, may_have_applied))
}

/// What an outcome says, for the log when it cannot be shown: for a signing, the key use of each
/// item by number (never a document's name).
fn lost_summary(result: &Result<Output, JobError>) -> String {
    match result {
        Ok(Output::Sign(sign::SignOutput::Signed(crate::signing::runner::Outcome::Done(view)))) => {
            let items: Vec<String> = view
                .items
                .iter()
                .enumerate()
                .map(|(i, item)| format!("#{i} {:?}", item.applied))
                .collect();
            format!("a signing finished, key use per item: {}", items.join(", "))
        }
        Ok(_) => "a result".to_owned(),
        Err(e) => format!("a failure: {e:?}"),
    }
}

/// The outcome of the action `stamp` into the window; a result that is not the running
/// action's of the open window (its window was closed and another opened) changes nothing.
fn settle(stamp: Stamp, result: Result<Output, JobError>) {
    let summary = lost_summary(&result);
    let Some(open) = current() else {
        tracing::error!(
            window = stamp.window,
            generation = stamp.generation,
            outcome = %summary,
            "an outcome arrived with no window open and is dropped"
        );
        return;
    };
    let settled = open.controller.borrow_mut().finish(stamp, result);
    let Some(settled) = settled else {
        tracing::error!(
            window = stamp.window,
            generation = stamp.generation,
            outcome = %summary,
            "the outcome of an operation that was left or whose window was closed is dropped"
        );
        return;
    };
    let ui = &open.ui;
    ui.set_busy(false);
    let t = Texts::of(open.locale.get());
    match settled {
        Settled::Done(_, Output::Hash(out, index)) => {
            let name = algorithm_name(t, index);
            ui.set_hash_summary(
                t.hash_summary
                    .replace("{0}", &size(t, out.bytes))
                    .replace("{1}", &out.bytes.to_string())
                    .replace("{2}", name)
                    .into(),
            );
            ui.set_hash_digest(out.digest.into());
            done(ui, t.hash_done);
        }
        Settled::Done(_, Output::Inspect(out)) => {
            ui.set_inspect_report(report(t, &out).into());
            done(ui, t.inspect_done);
        }
        Settled::Done(_, Output::Sign(out)) => {
            sign::settled(&open, Ok(out));
            done(ui, t.ready);
        }
        Settled::Done(_, Output::Tool(view)) => {
            use crate::reports::controller::Tone;
            let (tone, headline) = tools::settled(&open, &view);
            match tone {
                Tone::Success => done(ui, &headline),
                // Not proven either way, or partial: not styled as done.
                Tone::Caution | Tone::Neutral => {
                    ui.set_status_kind(4);
                    ui.set_status_text(headline.into());
                    ui.set_progress(-1.0);
                }
                Tone::Failure => {
                    ui.set_status_kind(3);
                    ui.set_status_text(headline.into());
                    ui.set_progress(-1.0);
                }
            }
        }
        Settled::Cancelled(Job::Sign) => {
            sign::settled(&open, Err(JobError::Cancelled));
            done(ui, t.ready);
        }
        Settled::Failed(Job::Sign, error) => {
            sign::settled(&open, Err(error));
            done(ui, t.ready);
        }
        Settled::Cancelled(_) => {
            ui.set_status_kind(4);
            ui.set_status_text(t.cancelled.into());
            ui.set_progress(-1.0);
        }
        Settled::Failed(job, error) => {
            let section = match job {
                Job::Hash => SECTION_HASH,
                Job::Inspect => SECTION_INSPECT,
                Job::Sign => SECTION_SIGN,
                // The error goes next to the fields of the page the tool runs on.
                Job::Tool => open.ui.get_section(),
            };
            reject(&open, section, &error);
        }
    }
}

fn done(ui: &WorkspaceWindow, text: &str) {
    ui.set_status_kind(2);
    ui.set_status_text(text.into());
    ui.set_progress(-1.0);
    ui.set_error_text("".into());
}

/// An error next to the fields of `section`, and in the status line.
fn reject(open: &Rc<Workspace>, section: i32, error: &JobError) {
    let text = error_text(Texts::of(open.locale.get()), error, open.inspect_kind.get());
    open.ui.set_error_section(section);
    open.ui.set_error_text(text.into());
    open.ui.set_status_kind(3);
    open.ui.set_status_text(text.into());
    open.ui.set_progress(-1.0);
}

/// «Обзор…»: the system file dialog; the chosen path goes into the page's field.
fn browse(open: &Rc<Workspace>) {
    let t = Texts::of(open.locale.get());
    let section = open.ui.get_section();
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(t.pick_title)
        .set_parent(&open.ui.window().window_handle());
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.pick_file().await else {
            return;
        };
        let path = file.path().display().to_string();
        with_open(|open| match section {
            SECTION_HASH => open.ui.set_hash_path(path.into()),
            _ => open.ui.set_inspect_path(path.into()),
        });
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

// ---- texts ----

/// The texts Rust composes, in one language.
struct Texts {
    ready: &'static str,
    hashing: &'static str,
    inspecting: &'static str,
    working: &'static str,
    cancelling: &'static str,
    cancelled: &'static str,
    hash_done: &'static str,
    inspect_done: &'static str,
    /// `{0}` of `{1}`.
    progress: &'static str,
    /// `{0}` read so far; the size is not known.
    progress_unknown: &'static str,
    /// A batch being prepared: `{0}` documents, `{1}` read so far.
    preparing: &'static str,
    /// A batch at work: document `{0}` of `{1}`, `{2}` processed so far.
    document: &'static str,
    /// `{0}` human size, `{1}` bytes, `{2}` algorithm.
    hash_summary: &'static str,
    pick_title: &'static str,
    pick_folder_title: &'static str,
    gost2004: &'static str,
    gost2015: &'static str,
    alias: &'static str,
    id_card: &'static str,
    busy_engine: &'static str,
    not_regular: &'static str,
    dest_exists: &'static str,
    no_such_key: &'static str,
    no_links: &'static str,
    store_changed: &'static str,
    units: [&'static str; 4],
    no_path: &'static str,
    no_password: &'static str,
    no_aliases: &'static str,
    no_folder: &'static str,
    no_evidence: &'static str,
    signing_running: &'static str,
    duplicate_output: &'static str,
    not_found: &'static str,
    access_denied: &'static str,
    unreadable: &'static str,
    not_recognized: &'static str,
    wrong_store: &'static str,
    limit: &'static str,
    deadline: &'static str,
    denied: &'static str,
    failed: &'static str,
    worker: &'static str,
    // The report.
    structural: &'static str,
    count: &'static str,
    subject: &'static str,
    serial: &'static str,
    valid: &'static str,
    signature_oid: &'static str,
    key_oid: &'static str,
    fingerprint: &'static str,
    store_mac_ok: &'static str,
    store_no_mac: &'static str,
    detached: &'static str,
    attached: &'static str,
    content_size: &'static str,
    signers: &'static str,
    tokens_off: &'static str,
    no_tokens: &'static str,
    pin_tries: &'static str,
    reader: &'static str,
    no_service: &'static str,
    service_failed: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Ru => &RU,
            Locale::Kk => &KK,
            Locale::En => &EN,
        }
    }
}

static RU: Texts = Texts {
    ready: "Готово к работе",
    hashing: "Вычисление хеша…",
    inspecting: "Чтение…",
    working: "Выполняется…",
    cancelling: "Отмена…",
    cancelled: "Отменено",
    hash_done: "Хеш вычислен",
    inspect_done: "Сведения получены",
    progress: "Прочитано {0} из {1}",
    progress_unknown: "Прочитано {0} (размер неизвестен)",
    preparing: "Подготовка документов: {0}, прочитано {1}",
    document: "Документ {0} из {1}, обработано {2}",
    hash_summary: "{0} ({1} байт), алгоритм {2}",
    pick_title: "Выберите файл",
    pick_folder_title: "Выберите папку",
    gost2004: "ГОСТ Р 34.11-94",
    gost2015: "ГОСТ Р 34.11-2012 (512)",
    alias: "Имя ключа",
    id_card: "ID-карта РК",
    busy_engine: "Предыдущая операция ещё завершается. Повторите через несколько секунд.",
    not_regular: "Это не обычный файл (канал или устройство): его нельзя прочитать.",
    no_such_key: "В хранилище нет ключа с таким именем.",
    dest_exists: "Файл с именем результата уже есть в папке назначения: он не будет заменён. Переименуйте или уберите его; ничего не выполнялось, ключ не применялся.",
    no_links: "В папке назначения нельзя создать файл результата надёжно (нужны жёсткие ссылки: FAT, exFAT и часть сетевых папок их не дают). Выберите другую папку или диск; ничего не выполнялось, ключ не применялся.",
    store_changed: "Файл хранилища ключей изменился после показа сертификата. Откройте его заново; ключ не применялся.",
    units: ["Б", "КиБ", "МиБ", "ГиБ"],
    no_path: "Укажите путь к файлу.",
    no_password: "Введите пароль.",
    no_aliases: "Укажите имена ключей, которые показать.",
    no_folder: "Укажите папку для результатов.",
    no_evidence: "Для уровней LT и LTA нужны данные проверки: сертификаты цепочки и хотя бы один ответ OCSP или список отзыва (CRL). Укажите файлы; ничего не выполнялось, ключ не применялся.",
    signing_running: "Идёт подпись: ключ мог быть уже применён. Дождитесь результата или нажмите «Отмена»; окно не закрывается, чтобы вы узнали, чем всё кончилось.",
    duplicate_output: "Два документа дали бы один и тот же файл результата. Уберите один из них или выберите другое назначение; ничего не выполнялось.",
    not_found: "Файл не найден.",
    access_denied: "Нет доступа к файлу.",
    unreadable: "Файл не удалось прочитать.",
    not_recognized: "Файл не распознан: проверьте, что выбран нужный тип.",
    wrong_store: "Хранилище не открылось: неверный пароль, имя ключа или формат.",
    limit: "Файл или результат больше допустимых пределов программы.",
    deadline: "Время операции истекло.",
    denied: "Действие не разрешено.",
    failed: "Не удалось выполнить действие.",
    worker: "Не удалось запустить фоновую задачу.",
    structural: "Это структурные сведения из файла: подлинность подписи, доверие к сертификату и его отзыв не проверялись.",
    count: "Сертификатов",
    subject: "Субъект (CN)",
    serial: "Серийный номер",
    valid: "Срок действия",
    signature_oid: "Алгоритм подписи (OID)",
    key_oid: "Алгоритм ключа (OID)",
    fingerprint: "Отпечаток SHA-256",
    store_mac_ok: "Целостность хранилища: пароль подтверждён (MAC)",
    store_no_mac: "Целостность хранилища: MAC отсутствует",
    detached: "Подписанные данные: отдельный файл",
    attached: "Подписанные данные: внутри подписи",
    content_size: "Размер данных, байт",
    signers: "Подписантов",
    tokens_off: "Поддержка токенов выключена. Включите её в настройках.",
    no_tokens: "Подключённых токенов не найдено.",
    pin_tries: "Осталось попыток PIN",
    reader: "Считыватель",
    no_service: "Служба смарт-карт недоступна.",
    service_failed: "Служба смарт-карт вернула ошибку",
};

static KK: Texts = Texts {
    ready: "Жұмысқа дайын",
    hashing: "Хешті есептеу…",
    inspecting: "Оқу…",
    working: "Орындалуда…",
    cancelling: "Бас тарту…",
    cancelled: "Тоқтатылды",
    hash_done: "Хеш есептелді",
    inspect_done: "Мәліметтер алынды",
    progress: "{1} ішінен {0} оқылды",
    progress_unknown: "{0} оқылды (көлемі белгісіз)",
    preparing: "Құжаттарды дайындау: {0}, {1} оқылды",
    document: "Құжат {0}/{1}: {2} өңделді",
    hash_summary: "{0} ({1} байт), алгоритм {2}",
    pick_title: "Файлды таңдаңыз",
    pick_folder_title: "Қалтаны таңдаңыз",
    gost2004: "ГОСТ Р 34.11-94",
    gost2015: "ГОСТ Р 34.11-2012 (512)",
    alias: "Кілт атауы",
    id_card: "ҚР жеке куәлігі",
    busy_engine: "Алдыңғы операция әлі аяқталуда. Бірнеше секундтан кейін қайталаңыз.",
    not_regular: "Бұл қарапайым файл емес (арна немесе құрылғы): оны оқуға болмайды.",
    no_such_key: "Қоймада мұндай атты кілт жоқ.",
    dest_exists: "Нәтиже файлының аты бар файл тағайындалған қалтада бұрыннан бар: ол ауыстырылмайды. Атын өзгертіңіз немесе алыңыз; ештеңе орындалмады, кілт қолданылмады.",
    no_links: "Тағайындалған қалтада нәтиже файлын сенімді жасау мүмкін емес (қатты сілтемелер керек: FAT, exFAT және кейбір желілік қалталарда жоқ). Басқа қалта немесе диск таңдаңыз; ештеңе орындалмады, кілт қолданылмады.",
    store_changed: "Сертификат көрсетілгеннен кейін кілттер қоймасының файлы өзгерген. Оны қайта ашыңыз; кілт қолданылмады.",
    units: ["Б", "КиБ", "МиБ", "ГиБ"],
    no_path: "Файлға жолды көрсетіңіз.",
    no_password: "Құпиясөзді енгізіңіз.",
    no_aliases: "Көрсетілетін кілт атауларын жазыңыз.",
    no_folder: "Нәтижелерге арналған қалтаны көрсетіңіз.",
    no_evidence: "LT және LTA деңгейлеріне тексеру деректері қажет: тізбек сертификаттары және кемінде бір OCSP жауабы немесе күшін жою тізімі (CRL). Файлдарды көрсетіңіз; ештеңе орындалмады, кілт қолданылмады.",
    signing_running: "Қол қою жүріп жатыр: кілт қолданылған болуы мүмкін. Нәтижені күтіңіз немесе «Бас тарту» басыңыз; немен аяқталғанын білуіңіз үшін терезе жабылмайды.",
    duplicate_output: "Екі құжат бір нәтиже файлын берер еді. Біреуін алыңыз немесе басқа тағайындауды таңдаңыз; ештеңе орындалмады.",
    not_found: "Файл табылмады.",
    access_denied: "Файлға қол жеткізу жоқ.",
    unreadable: "Файлды оқу мүмкін болмады.",
    not_recognized: "Файл танылмады: түрін дұрыс таңдағаныңызды тексеріңіз.",
    wrong_store: "Қойма ашылмады: құпиясөз, кілт атауы немесе пішімі қате.",
    limit: "Файл немесе нәтиже бағдарламаның рұқсат етілген шегінен асады.",
    deadline: "Операция уақыты аяқталды.",
    denied: "Әрекетке рұқсат жоқ.",
    failed: "Әрекетті орындау мүмкін болмады.",
    worker: "Фондық тапсырманы іске қосу мүмкін болмады.",
    structural: "Бұл файлдағы құрылымдық мәліметтер: қолтаңбаның түпнұсқалығы, сертификатқа сенім және оның қайтарып алынуы тексерілмеді.",
    count: "Сертификаттар",
    subject: "Субъект (CN)",
    serial: "Сериялық нөмірі",
    valid: "Жарамдылық мерзімі",
    signature_oid: "Қолтаңба алгоритмі (OID)",
    key_oid: "Кілт алгоритмі (OID)",
    fingerprint: "SHA-256 саусақ ізі",
    store_mac_ok: "Қойма тұтастығы: құпиясөз расталды (MAC)",
    store_no_mac: "Қойма тұтастығы: MAC жоқ",
    detached: "Қол қойылған деректер: бөлек файл",
    attached: "Қол қойылған деректер: қолтаңба ішінде",
    content_size: "Деректер өлшемі, байт",
    signers: "Қол қоюшылар",
    tokens_off: "Токендерді қолдау өшірулі. Оны баптауларда қосыңыз.",
    no_tokens: "Қосылған токендер табылмады.",
    pin_tries: "PIN әрекеті қалды",
    reader: "Оқу құрылғысы",
    no_service: "Смарт-карта қызметі қолжетімсіз.",
    service_failed: "Смарт-карта қызметі қате қайтарды",
};

static EN: Texts = Texts {
    ready: "Ready",
    hashing: "Hashing…",
    inspecting: "Reading…",
    working: "Working…",
    cancelling: "Cancelling…",
    cancelled: "Cancelled",
    hash_done: "Hash computed",
    inspect_done: "Details read",
    progress: "Read {0} of {1}",
    progress_unknown: "Read {0} (the size is not known)",
    preparing: "Preparing {0} document(s): read {1}",
    document: "Document {0} of {1}, {2} processed",
    hash_summary: "{0} ({1} bytes), algorithm {2}",
    pick_title: "Choose a file",
    pick_folder_title: "Choose a folder",
    gost2004: "GOST R 34.11-94",
    gost2015: "GOST R 34.11-2012 (512)",
    alias: "Key name",
    id_card: "KZ ID card",
    busy_engine: "The previous operation is still finishing. Try again in a few seconds.",
    not_regular: "This is not a regular file (a pipe or a device): it cannot be read.",
    no_such_key: "The key store has no key with that name.",
    dest_exists: "A file with the result's name already exists in the destination and will not be replaced. Rename or remove it; nothing was done and no key was used.",
    no_links: "The destination folder cannot publish a result file safely (it needs hard links, which FAT, exFAT and some network shares lack). Choose another folder or drive; nothing was done and no key was used.",
    store_changed: "The key store file changed after the certificate was shown. Open it again; no key was used.",
    units: ["B", "KiB", "MiB", "GiB"],
    no_path: "Enter the path to a file.",
    no_password: "Enter the password.",
    no_aliases: "Enter the names of the keys to show.",
    no_folder: "Enter the folder for the results.",
    no_evidence: "Levels LT and LTA need validation data: the certificates of the chain and at least one OCSP response or CRL. Name the files; nothing was done and no key was used.",
    signing_running: "A signing is running: the key may be applied already. Wait for the result or press Cancel; the window stays open so that you learn how it ended.",
    duplicate_output: "Two documents would give the same result file. Remove one of them or choose another destination; nothing was done.",
    not_found: "The file was not found.",
    access_denied: "No access to the file.",
    unreadable: "The file could not be read.",
    not_recognized: "The file is not recognised: check that it is of the chosen type.",
    wrong_store: "The key store did not open: wrong password, key name or format.",
    limit: "The file or the result is over the program's limits.",
    deadline: "The operation timed out.",
    denied: "The action is not allowed.",
    failed: "The action failed.",
    worker: "A background task could not be started.",
    structural: "These are structural details from the file: the signature's validity, trust in the certificate and its revocation were not checked.",
    count: "Certificates",
    subject: "Subject (CN)",
    serial: "Serial number",
    valid: "Validity period",
    signature_oid: "Signature algorithm (OID)",
    key_oid: "Key algorithm (OID)",
    fingerprint: "SHA-256 fingerprint",
    store_mac_ok: "Key store integrity: password confirmed (MAC)",
    store_no_mac: "Key store integrity: no MAC",
    detached: "Signed data: a separate file",
    attached: "Signed data: inside the signature",
    content_size: "Data size, bytes",
    signers: "Signers",
    tokens_off: "Token support is off. Turn it on in the settings.",
    no_tokens: "No tokens are plugged in.",
    pin_tries: "PIN tries left",
    reader: "Reader",
    no_service: "The smart card service is not available.",
    service_failed: "The smart card service failed",
};

/// `n` bytes as `12.5 МиБ`.
fn size(t: &Texts, n: u64) -> String {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < t.units.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", t.units[0])
    } else {
        format!("{value:.1} {}", t.units[unit])
    }
}

/// What went wrong, for the user.
fn error_text(t: &Texts, error: &JobError, inspect_kind: i32) -> &'static str {
    match error {
        JobError::Cancelled => t.cancelled,
        JobError::Input(MissingField::Path) => t.no_path,
        JobError::Input(MissingField::Password) => t.no_password,
        JobError::Input(MissingField::Aliases) => t.no_aliases,
        JobError::Input(MissingField::Folder) => t.no_folder,
        JobError::Input(MissingField::Evidence) => t.no_evidence,
        JobError::DuplicateOutput => t.duplicate_output,
        JobError::Worker => t.worker,
        JobError::NotRegular => t.not_regular,
        JobError::DestinationExists => t.dest_exists,
        JobError::NoLinks => t.no_links,
        JobError::StoreChanged => t.store_changed,
        JobError::Io(kind) => match kind {
            std::io::ErrorKind::NotFound => t.not_found,
            std::io::ErrorKind::PermissionDenied => t.access_denied,
            _ => t.unreadable,
        },
        JobError::Operation(code) => match code {
            ErrorCode::InvalidInput if inspect_kind == 2 => t.wrong_store,
            ErrorCode::InvalidInput => t.not_recognized,
            ErrorCode::SecretRequired => t.no_password,
            ErrorCode::KeyNotFound => t.no_such_key,
            ErrorCode::PermissionDenied => t.denied,
            ErrorCode::DeadlineExceeded => t.deadline,
            ErrorCode::CapacityExceeded => t.busy_engine,
            ErrorCode::InputLimit
            | ErrorCode::ContainerLimit
            | ErrorCode::FramingLimit
            | ErrorCode::OutputLimit
            | ErrorCode::MemoryLimit
            | ErrorCode::TempLimit
            | ErrorCode::MetadataLimit => t.limit,
            ErrorCode::Io => t.unreadable,
            _ => t.failed,
        },
    }
}

fn token_name(t: &Texts, kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Kaztoken => "Kaztoken",
        TokenKind::KzIdCard => t.id_card,
        TokenKind::EToken72K => "eToken PRO 72K",
        TokenKind::EToken5110 => "eToken 5110",
        TokenKind::JaCarta => "JaCarta",
        TokenKind::AKey => "AKey",
    }
}

fn when(t: OffsetDateTime) -> String {
    format!(
        "{:02}.{:02}.{:04} {:02}:{:02} UTC",
        t.day(),
        u8::from(t.month()),
        t.year(),
        t.hour(),
        t.minute()
    )
}

fn entry_lines(t: &Texts, e: &Entry, out: &mut String) {
    let mut line = |label: &str, value: &str| {
        out.push_str(label);
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    };
    if let Some(alias) = &e.alias {
        line(t.alias, alias);
    }
    if let Some(cn) = &e.subject_cn {
        line(t.subject, cn);
    }
    if let Some(serial) = &e.serial {
        line(t.serial, serial);
    }
    if let (Some(from), Some(to)) = (e.not_before, e.not_after) {
        line(t.valid, &format!("{} — {}", when(from), when(to)));
    }
    if let Some(oid) = &e.signature_oid {
        line(t.signature_oid, oid);
    }
    if let Some(oid) = &e.key_oid {
        line(t.key_oid, oid);
    }
    if let Some(fp) = &e.fingerprint {
        line(t.fingerprint, fp);
    }
}

/// The text of an inspection's result.
fn report(t: &Texts, out: &InspectOutput) -> String {
    use oncl_pki::info::MetadataIntegrity;
    let mut text = String::new();
    match out {
        InspectOutput::Certificates { integrity, entries } => {
            match integrity {
                Some(MetadataIntegrity::PasswordMacVerified) => {
                    text.push_str(t.store_mac_ok);
                    text.push('\n');
                }
                Some(MetadataIntegrity::NotPresent) => {
                    text.push_str(t.store_no_mac);
                    text.push('\n');
                }
                _ => {}
            }
            text.push_str(&format!("{}: {}\n", t.count, entries.len()));
            for entry in entries {
                text.push('\n');
                entry_lines(t, entry, &mut text);
            }
            text.push('\n');
            text.push_str(t.structural);
        }
        InspectOutput::Signature {
            detached,
            content_len,
            signers,
        } => {
            text.push_str(if *detached { t.detached } else { t.attached });
            text.push('\n');
            text.push_str(&format!("{}: {content_len}\n", t.content_size));
            text.push_str(&format!("{}: {signers}\n\n", t.signers));
            text.push_str(t.structural);
        }
        InspectOutput::Tokens {
            enabled,
            found,
            problem,
        } => {
            if !enabled {
                text.push_str(t.tokens_off);
                return text;
            }
            match problem {
                Some(ScanProblem::NoService) => {
                    text.push_str(t.no_service);
                    text.push('\n');
                }
                Some(ScanProblem::Failed(e)) => {
                    text.push_str(&format!("{}: {e}\n", t.service_failed));
                }
                None => {}
            }
            if found.is_empty() && problem.is_none() {
                text.push_str(t.no_tokens);
            }
            for token in found {
                text.push_str(token_name(t, token.kind));
                text.push('\n');
                text.push_str(&format!("{}: {}\n", t.reader, token.reader));
                if let Some(tries) = token.pin_tries {
                    text.push_str(&format!("{}: {tries}\n", t.pin_tries));
                }
                text.push('\n');
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every error the page can show maps to some text in every language: an action never
    /// ends in a silent blank status.
    #[test]
    fn every_failure_has_a_text_in_every_language() {
        let errors = [
            JobError::Cancelled,
            JobError::Worker,
            JobError::Io(std::io::ErrorKind::NotFound),
            JobError::Io(std::io::ErrorKind::PermissionDenied),
            JobError::Io(std::io::ErrorKind::Other),
            JobError::Input(MissingField::Path),
            JobError::Operation(ErrorCode::InvalidInput),
            JobError::Operation(ErrorCode::InputLimit),
            JobError::Operation(ErrorCode::DeadlineExceeded),
            JobError::Operation(ErrorCode::AuditFailed),
        ];
        for locale in [Locale::Ru, Locale::Kk, Locale::En] {
            for error in &errors {
                assert!(!error_text(Texts::of(locale), error, 0).is_empty());
            }
        }
    }

    #[test]
    fn sizes_are_scaled_to_their_unit() {
        let t = Texts::of(Locale::En);
        assert_eq!(size(t, 0), "0 B");
        assert_eq!(size(t, 1023), "1023 B");
        assert_eq!(size(t, 1536), "1.5 KiB");
        assert_eq!(size(t, 10 << 30), "10.0 GiB");
    }
}
