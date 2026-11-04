//! The signing page of the tools window: glue between the page, the [`Controller`] of the
//! steps ([`crate::signing`]) and the workers that freeze documents, open the key store and
//! sign. The page agrees to nothing by itself: the key is applied after the button that names
//! the action, for the documents the engine froze and the certificate the user chose.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use oncl_core::ErrorCode;
use oncl_desktop::Remembered;
use oncl_flows::Locale;
use oncl_pki::key::AppliedState;
use slint::{
    ComponentHandle, ModelRc, SharedString, StandardListViewItem, Timer, TimerMode, VecModel,
};
use zeroize::Zeroizing;

use super::controller::{Job, JobControl, JobError};
use super::{DesktopEngineServices, Output, Workspace, start, with_open};
use crate::signing::controller::{
    ActionKind, Candidate, Controller, Effect, Event, Item, Refusal, Step, Unsuitable,
};
use crate::signing::runner::{Decision, OpenError, Outcome, Signed, freeze, open_key_store, sign};
use crate::ui::SigningState;

/// The confirmation cannot be pressed for this long after it is shown.
const ARM_AFTER: Duration = Duration::from_millis(600);
/// An abandoned confirmation ends after this: the frozen copies go, nothing was agreed to.
const IDLE_LIMIT: Duration = Duration::from_secs(300);
/// Two clicks on the same certificate within this are a double-click.
const DOUBLE_CLICK: Duration = Duration::from_millis(500);

/// What a worker of the page gives back.
pub(super) enum SignOutput {
    Frozen(PathBuf, Item),
    Unlocked(Result<Vec<Candidate>, OpenError>),
    Signed(Outcome),
}

/// The page's state on the event loop.
pub(super) struct State {
    controller: Controller,
    /// The operation the running worker belongs to: its late answer for another is dropped.
    pending_op: Option<u64>,
    /// Where the confirmation was shown; arms the button after a quiet moment, and ends an
    /// abandoned confirmation.
    frozen_at: Option<Instant>,
    outputs: Vec<PathBuf>,
    tick: Timer,
    documents: Vec<(PathBuf, Item)>,
    /// The engine's frozen copy of the documents, once the worker has it.
    frozen: Vec<Item>,
    /// Answers the worker that waits for the user's decision.
    decision: Option<Sender<Decision>>,
    last_click: Option<(i32, Instant)>,
    remembered: Remembered,
}

impl State {
    pub(super) fn new(remembered: Remembered) -> State {
        State {
            controller: manual(),
            pending_op: None,
            frozen_at: None,
            outputs: Vec::new(),
            tick: Timer::default(),
            documents: Vec::new(),
            frozen: Vec::new(),
            decision: None,
            last_click: None,
            remembered,
        }
    }
}

/// The caller of a manual signing: the user themselves, in this window.
fn manual() -> Controller {
    Controller::new("manual", ActionKind::Sign)
}

pub(super) fn connect(ui: &crate::ui::WorkspaceWindow) {
    let s = ui.global::<SigningState>();
    s.on_add_doc(|| with_open(add_doc));
    s.on_clear_docs(|| with_open(clear_docs));
    s.on_pick_recent(|| with_open(pick_recent));
    s.on_pick_recent_store(|| with_open(pick_recent_store));
    s.on_browse_doc(|| with_open(|open| browse(open, true)));
    s.on_browse_store(|| with_open(|open| browse(open, false)));
    s.on_to_unlock(|| with_open(to_unlock));
    s.on_unlock(|| with_open(unlock));
    s.on_cert_clicked(|i| with_open(|open| cert_clicked(open, i)));
    s.on_cert_chosen(|i| with_open(|open| cert_chosen(open, i)));
    s.on_toggle_favorite(|| with_open(toggle_favorite));
    s.on_clear_remembered(|| with_open(clear_remembered));
    s.on_confirm(|| with_open(confirm));
    s.on_back(|| with_open(back));
    s.on_cancel(|| with_open(cancel));
    s.on_finish(|| with_open(finish));
}

fn locale(open: &Rc<Workspace>) -> &'static SignTexts {
    SignTexts::of(open.locale.get())
}

fn state(open: &Rc<Workspace>) -> std::cell::RefMut<'_, State> {
    open.sign.borrow_mut()
}

fn list(items: impl IntoIterator<Item = String>) -> ModelRc<StandardListViewItem> {
    let v: Vec<StandardListViewItem> = items
        .into_iter()
        .map(|t| StandardListViewItem::from(t.as_str()))
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn short(sha: &[u8; 32]) -> String {
    sha.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn full(sha: &[u8; 32]) -> String {
    sha.iter().map(|b| format!("{b:02x}")).collect()
}

fn size_text(l: Locale, bytes: u64) -> String {
    super::size(super::Texts::of(l), bytes)
}

/// Shows the controller's step with everything the step needs.
pub(super) fn render(open: &Rc<Workspace>) {
    let t = locale(open);
    let st = open.sign.borrow();
    let ui = open.ui.global::<SigningState>();
    let c = &st.controller;
    let step = match c.step() {
        Step::Source => 0,
        Step::Unlock => 1,
        Step::Confirm => 2,
        Step::Running => 3,
        Step::Result => 4,
    };
    ui.set_step(step);
    ui.set_step_title(t.titles[step as usize].into());
    ui.set_trust_line(
        t.trust
            .replace(
                "{0}",
                if c.caller() == "manual" {
                    t.manual
                } else {
                    c.caller()
                },
            )
            .replace(
                "{1}",
                match c.action() {
                    ActionKind::Sign => t.action_sign,
                    ActionKind::Authenticate => t.action_auth,
                    ActionKind::KeyInfo => t.action_info,
                },
            )
            .into(),
    );
    ui.set_docs(list(st.documents.iter().map(|(_, i)| {
        format!("{} — {}", i.name, size_text(open.locale.get(), i.bytes))
    })));
    ui.set_recent(ModelRc::new(VecModel::from(
        st.remembered
            .files
            .iter()
            .map(|f| SharedString::from(f.as_str()))
            .collect::<Vec<_>>(),
    )));
    ui.set_certs(list(c.candidates().iter().map(|cand| {
        let star = if st.remembered.is_favorite(&full(&cand.sha256)) {
            "★ "
        } else {
            ""
        };
        let why = match cand.unsuitable {
            None => String::new(),
            Some(Unsuitable::Expired) => format!(" — {}", t.expired),
            Some(Unsuitable::NotYetValid) => format!(" — {}", t.not_yet),
            Some(_) => format!(" — {}", t.not_for_signing),
        };
        format!("{star}{} ({}){why}", cand.subject, cand.alias)
    })));
    ui.set_frozen(list(st.frozen.iter().map(|i| {
        format!(
            "{} — {}, SHA-256 {}…",
            i.name,
            size_text(open.locale.get(), i.bytes),
            short(&i.sha256)
        )
    })));
    ui.set_frozen_ready(c.armed());
    ui.set_outputs(
        t.outputs
            .replace(
                "{0}",
                &st.outputs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .into(),
    );
    ui.set_recent_stores(ModelRc::new(VecModel::from(
        st.remembered
            .key_stores
            .iter()
            .map(|f| SharedString::from(f.as_str()))
            .collect::<Vec<_>>(),
    )));
    if let Some(cand) = c.chosen() {
        ui.set_cert_line(
            t.cert_line
                .replace("{0}", &cand.subject)
                .replace("{1}", &cand.alias)
                .replace("{2}", &full(&cand.sha256))
                .into(),
        );
    }
    ui.set_confirm_label(
        t.confirm
            .replace("{0}", &c.items().len().to_string())
            .into(),
    );
    let favorite = c
        .candidates()
        .get(usize::try_from(ui.get_cert_index()).unwrap_or(usize::MAX))
        .is_some_and(|cand| st.remembered.is_favorite(&full(&cand.sha256)));
    ui.set_favorite_label(if favorite { t.unfavorite } else { t.favorite }.into());
}

fn error(open: &Rc<Workspace>, text: &str) {
    open.ui.global::<SigningState>().set_error(text.into());
}

/// A step is refused while a worker still runs, and the page says so.
fn busy(open: &Rc<Workspace>) -> bool {
    if open.ui.get_busy() {
        error(open, locale(open).busy);
        true
    } else {
        false
    }
}

fn add_doc(open: &Rc<Workspace>) {
    if busy(open) {
        return;
    }
    let t = locale(open);
    let ui = open.ui.global::<SigningState>();
    let path = super::typed_path(ui.get_doc_path());
    if path.is_empty() {
        return error(open, t.no_path);
    }
    ui.set_error("".into());
    ui.set_doc_path("".into());
    let path = PathBuf::from(path);
    start_sign(open, move |services, control| {
        let item = freeze(&services.engine, &path, control)?;
        Ok(SignOutput::Frozen(path, item))
    });
}

fn pick_recent(open: &Rc<Workspace>) {
    let ui = open.ui.global::<SigningState>();
    let Ok(i) = usize::try_from(ui.get_recent_index()) else {
        return;
    };
    let file = open.sign.borrow().remembered.files.get(i).cloned();
    if let Some(file) = file {
        // An entry proves nothing: the file is read again like any other.
        ui.set_doc_path(file.into());
        add_doc(open);
    }
}

fn pick_recent_store(open: &Rc<Workspace>) {
    let ui = open.ui.global::<SigningState>();
    let Ok(i) = usize::try_from(ui.get_recent_store_index()) else {
        return;
    };
    let file = open.sign.borrow().remembered.key_stores.get(i).cloned();
    if let Some(file) = file {
        // Only a path in the field: the file is read when the store is opened.
        ui.set_store_path(file.into());
    }
}

fn clear_docs(open: &Rc<Workspace>) {
    {
        let mut st = state(open);
        st.documents.clear();
        let items = Vec::new();
        st.controller.dispatch(Event::Documents(items));
    }
    // A controller keeps its documents when told none: start the page over.
    let mut st = state(open);
    st.controller = manual();
    drop(st);
    render(open);
}

fn clear_remembered(open: &Rc<Workspace>) {
    let path = open.services.settings_path.clone();
    if let Err(e) = Remembered::clear(&path) {
        tracing::warn!(error = %e, "cannot forget the remembered files");
    }
    state(open).remembered = Remembered::default();
    render(open);
}

fn to_unlock(open: &Rc<Workspace>) {
    let t = locale(open);
    let ui = open.ui.global::<SigningState>();
    let store = super::typed_path(ui.get_store_path());
    {
        let mut st = state(open);
        let items: Vec<Item> = st.documents.iter().map(|(_, i)| i.clone()).collect();
        st.controller.dispatch(Event::Documents(items));
        if st.documents.is_empty() {
            drop(st);
            return error(open, t.no_documents);
        }
        if store.is_empty() {
            drop(st);
            return error(open, t.no_key_store);
        }
        st.controller.dispatch(Event::KeyStore(store));
    }
    ui.set_error("".into());
    render(open);
}

fn unlock(open: &Rc<Workspace>) {
    let ui = open.ui.global::<SigningState>();
    // Taken out of the page at once; Enter here opens the key store and agrees to nothing.
    let secret = Zeroizing::new(ui.get_password().to_string());
    if secret.is_empty() {
        // A repeated Enter finds the field already emptied: it must not replace the password
        // that is being used.
        if !open.ui.get_busy() {
            error(open, locale(open).no_password);
        }
        return;
    }
    if busy(open) {
        return;
    }
    ui.set_password("".into());
    ui.set_error("".into());
    let (store, effect) = {
        let mut st = state(open);
        let store = super::typed_path(ui.get_store_path());
        let effect = st.controller.dispatch(Event::PasswordSubmitted(secret));
        (store, effect)
    };
    if effect != Effect::OpenKeyStore {
        return;
    }
    let secret = state(open).controller.unlock_secret();
    let Some(secret) = secret else {
        return;
    };
    start_sign(open, move |services, _| {
        Ok(SignOutput::Unlocked(open_key_store(
            &PathBuf::from(store),
            &secret,
            (services.clock)(),
        )))
    });
}

/// A click: two on one certificate in quick succession are a double-click, which chooses it.
fn cert_clicked(open: &Rc<Workspace>, i: i32) {
    let now = Instant::now();
    let double = {
        let mut st = state(open);
        let double = st
            .last_click
            .is_some_and(|(last, at)| last == i && now.duration_since(at) <= DOUBLE_CLICK);
        st.last_click = if double { None } else { Some((i, now)) };
        double
    };
    if double {
        cert_chosen(open, i);
    } else {
        render(open);
    }
}

/// Enter or a double-click: the certificate is chosen and the confirmation shown; nothing is
/// signed, the engine only freezes the documents for the user to see.
fn cert_chosen(open: &Rc<Workspace>, i: i32) {
    let t = locale(open);
    if busy(open) {
        return;
    }
    let Ok(index) = usize::try_from(i) else {
        return;
    };
    let effect = state(open)
        .controller
        .dispatch(Event::CertificateChosen(index));
    if let Effect::Refused(r) = effect {
        let text = match r {
            Refusal::UnsuitableCertificate(Unsuitable::Expired) => t.expired_refusal,
            Refusal::UnsuitableCertificate(Unsuitable::NotYetValid) => t.not_yet_refusal,
            Refusal::UnsuitableCertificate(_) => t.not_for_signing_refusal,
            _ => return,
        };
        return error(open, text);
    }
    open.ui.global::<SigningState>().set_error("".into());
    let (store, alias, password, paths) = {
        let st = open.sign.borrow();
        let store = super::typed_path(open.ui.global::<SigningState>().get_store_path());
        let alias = st
            .controller
            .chosen()
            .map(|c| c.alias.clone())
            .unwrap_or_default();
        (
            store,
            alias,
            st.controller.unlock_secret(),
            st.documents
                .iter()
                .map(|(p, _)| p.clone())
                .collect::<Vec<_>>(),
        )
    };
    let Some(password) = password else {
        return;
    };
    let (tx, rx) = channel::<Decision>();
    let op = state(open).controller.id();
    state(open).decision = Some(tx);
    state(open).frozen.clear();
    render(open);
    start_sign(open, move |services, control| {
        let outcome = run_signing(
            op,
            services,
            &PathBuf::from(store),
            &alias,
            &password,
            &paths,
            control,
            rx,
        );
        Ok(SignOutput::Signed(outcome))
    });
}

/// The worker's side of the handshake: freeze, show, wait for the user.
#[allow(clippy::too_many_arguments)]
fn run_signing(
    op: u64,
    services: &DesktopEngineServices,
    store: &std::path::Path,
    alias: &str,
    password: &Zeroizing<String>,
    paths: &[PathBuf],
    control: &Arc<JobControl>,
    rx: Receiver<Decision>,
) -> Outcome {
    let waiting = Arc::clone(control);
    sign(
        &services.engine,
        &services.guard,
        store,
        alias,
        password,
        paths,
        control,
        move |frozen| {
            let (shown, outputs) = (frozen.items.clone(), frozen.outputs.clone());
            if slint::invoke_from_event_loop(move || {
                with_open(|open| frozen_arrived(open, op, shown, outputs));
            })
            .is_err()
            {
                return Decision::Abort;
            }
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(decision) => return decision,
                    Err(RecvTimeoutError::Timeout) if !waiting.is_cancelled() => {}
                    Err(_) => return Decision::Abort,
                }
            }
        },
    )
}

/// The engine froze the documents: they are shown, and the action can be confirmed if they are
/// the ones the user picked.
fn frozen_arrived(open: &Rc<Workspace>, op: u64, items: Vec<Item>, outputs: Vec<PathBuf>) {
    let t = locale(open);
    let effect = {
        let mut st = state(open);
        if st.controller.step() != Step::Confirm || st.controller.id() != op {
            // The user left meanwhile: the waiting worker sees its channel closed.
            return;
        }
        st.frozen = items.clone();
        st.outputs = outputs;
        st.frozen_at = Some(Instant::now());
        st.controller.dispatch(Event::Frozen(&items))
    };
    if effect == Effect::Refused(Refusal::DocumentsChanged) {
        // What was frozen is not what was shown: nothing was agreed to, the key is not touched.
        let mut st = state(open);
        if let Some(tx) = st.decision.take() {
            let _ = tx.send(Decision::Abort);
        }
        st.documents = st
            .documents
            .iter()
            .zip(&items)
            .map(|((p, _), i)| (p.clone(), i.clone()))
            .collect();
        st.frozen.clear();
        drop(st);
        error(open, t.changed);
    }
    if effect == Effect::None {
        open.ui.set_status_text(t.waiting.into());
        start_tick(open);
    }
    render(open);
}

/// Arms the confirmation after a quiet moment and ends it when abandoned.
fn start_tick(open: &Rc<Workspace>) {
    state(open)
        .tick
        .start(TimerMode::Repeated, Duration::from_millis(200), || {
            with_open(tick);
        });
}

fn tick(open: &Rc<Workspace>) {
    let t = locale(open);
    let (expired, armed_now) = {
        let mut st = state(open);
        let Some(at) = st.frozen_at else {
            st.tick.stop();
            return;
        };
        if st.controller.step() != Step::Confirm {
            st.frozen_at = None;
            st.tick.stop();
            return;
        }
        let elapsed = at.elapsed();
        let armed_now = elapsed >= ARM_AFTER && !st.controller.armed() && {
            st.controller.dispatch(Event::Arm);
            true
        };
        (elapsed >= IDLE_LIMIT, armed_now)
    };
    if expired {
        leave_confirmation(open);
        error(open, t.idle);
        render(open);
    } else if armed_now {
        render(open);
    }
}

/// Back from the confirmation, whichever way it was left: the worker that holds the frozen
/// copies lets them go, nothing was agreed to.
fn leave_confirmation(open: &Rc<Workspace>) {
    let mut st = state(open);
    if st.controller.step() == Step::Confirm {
        st.controller.dispatch(Event::Back);
    }
    if let Some(tx) = st.decision.take() {
        let _ = tx.send(Decision::Abort);
    }
    st.frozen.clear();
    st.outputs.clear();
    st.frozen_at = None;
    st.tick.stop();
}

fn toggle_favorite(open: &Rc<Workspace>) {
    let ui = open.ui.global::<SigningState>();
    let Ok(i) = usize::try_from(ui.get_cert_index()) else {
        return;
    };
    {
        let mut st = state(open);
        let Some(cand) = st.controller.candidates().get(i).cloned() else {
            return;
        };
        st.remembered
            .toggle_favorite(&full(&cand.sha256), &cand.subject);
        if let Err(e) = st.remembered.save(&open.services.settings_path) {
            tracing::warn!(error = %e, "cannot save the favourite certificates");
        }
    }
    render(open);
}

/// The button that names the action: the only way to the key.
fn confirm(open: &Rc<Workspace>) {
    let t = locale(open);
    let mut st = state(open);
    let frozen = st.frozen.clone();
    match st.controller.dispatch(Event::Confirm { frozen: &frozen }) {
        Effect::None => {}
        Effect::Refused(Refusal::DocumentsChanged) => {
            if let Some(tx) = st.decision.take() {
                let _ = tx.send(Decision::Abort);
            }
            drop(st);
            error(open, t.changed);
            return render(open);
        }
        Effect::Refused(_) | Effect::OpenKeyStore => return,
    }
    let Some(approved) = st.controller.take_approved() else {
        return;
    };
    let decision = st.decision.take();
    drop(st);
    if let Some(tx) = decision {
        let _ = tx.send(Decision::Proceed(Box::new(approved)));
    }
    open.ui
        .global::<SigningState>()
        .set_result(t.signing.into());
    render(open);
}

fn back(open: &Rc<Workspace>) {
    {
        let st = state(open);
        let was_confirm = st.controller.step() == Step::Confirm;
        drop(st);
        if was_confirm {
            leave_confirmation(open);
        } else {
            state(open).controller.dispatch(Event::Back);
        }
    }
    open.ui.global::<SigningState>().set_error("".into());
    render(open);
}

/// Leaves the operation: nothing of it stays, and the next one unlocks again.
fn cancel(open: &Rc<Workspace>) {
    if open.sign.borrow().controller.step() == Step::Running {
        // The key may be applied already: stay on the page until the worker says how far it
        // got, and show that.
        open.controller.borrow_mut().cancel();
        open.ui
            .set_status_text(super::Texts::of(open.locale.get()).cancelling.into());
        return;
    }
    leave_confirmation(open);
    {
        let mut st = state(open);
        st.controller.dispatch(Event::Cancel);
        st.pending_op = None;
    }
    open.controller.borrow_mut().cancel();
    finish(open);
}

/// A new operation from the documents: no key store, password, certificate or permission of
/// the last one is kept.
fn finish(open: &Rc<Workspace>) {
    {
        let mut st = state(open);
        st.controller = manual();
        st.documents.clear();
        st.frozen.clear();
        st.outputs.clear();
        st.frozen_at = None;
        st.tick.stop();
        st.decision = None;
    }
    let ui = open.ui.global::<SigningState>();
    ui.set_password("".into());
    ui.set_error("".into());
    ui.set_result("".into());
    ui.set_cert_index(-1);
    render(open);
}

fn browse(open: &Rc<Workspace>, document: bool) {
    let t = super::Texts::of(open.locale.get());
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(t.pick_title)
        .set_parent(&open.ui.window().window_handle());
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.pick_file().await else {
            return;
        };
        let path = file.path().display().to_string();
        with_open(|open| {
            let ui = open.ui.global::<SigningState>();
            if document {
                ui.set_doc_path(path.into());
                add_doc(open);
            } else {
                ui.set_store_path(path.into());
            }
        });
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

fn start_sign(
    open: &Rc<Workspace>,
    work: impl FnOnce(&DesktopEngineServices, &Arc<JobControl>) -> Result<SignOutput, JobError>
    + Send
    + 'static,
) {
    let op = open.sign.borrow().controller.id();
    open.sign.borrow_mut().pending_op = Some(op);
    start(open, Job::Sign, move |s, c| work(s, c).map(Output::Sign));
}

/// A worker of the page ended.
pub(super) fn settled(open: &Rc<Workspace>, result: Result<SignOutput, JobError>) {
    let t = locale(open);
    {
        let mut st = state(open);
        let mine = st.pending_op.take();
        if mine != Some(st.controller.id()) {
            // The answer of an operation that was left: it changes nothing here.
            return;
        }
    }
    let ui = open.ui.global::<SigningState>();
    match result {
        Ok(SignOutput::Frozen(path, item)) => {
            {
                let mut st = state(open);
                st.documents.retain(|(p, _)| *p != path);
                st.documents.push((path, item));
            }
            render(open);
        }
        Ok(SignOutput::Unlocked(Ok(mut candidates))) => {
            {
                let mut st = state(open);
                // The favourites first: marked certificates are the ones used most.
                let marked = |c: &Candidate| st.remembered.is_favorite(&full(&c.sha256));
                candidates.sort_by_key(|c| !marked(c));
                st.controller.dispatch(Event::Unlocked(candidates));
            }
            ui.set_cert_index(-1);
            render(open);
        }
        Ok(SignOutput::Unlocked(Err(e))) => {
            state(open).controller.dispatch(Event::UnlockFailed);
            error(
                open,
                match e {
                    OpenError::Unreadable => t.store_unreadable,
                    OpenError::WrongPasswordOrFormat => t.wrong_password,
                },
            );
            render(open);
        }
        Ok(SignOutput::Signed(outcome)) => signed(open, outcome),
        Err(JobError::Cancelled) => {
            let step = open.sign.borrow().controller.step();
            match step {
                Step::Running => end_with(open, t.cancelled_applied_unknown),
                // Escape cancelled the job under the confirmation: the page goes back with
                // it, nothing is left to confirm.
                Step::Confirm => {
                    leave_confirmation(open);
                    render(open);
                }
                _ => {}
            }
        }
        Err(e) => {
            // The page stays where it is; the error says what could not be done.
            let text = super::error_text(super::Texts::of(open.locale.get()), &e, 0);
            error(open, text);
            render(open);
        }
    }
}

fn signed(open: &Rc<Workspace>, outcome: Outcome) {
    let t = locale(open);
    match outcome {
        Outcome::Done(done) => {
            let (files, store) = {
                let st = open.sign.borrow();
                (
                    st.documents
                        .iter()
                        .map(|(p, _)| p.display().to_string())
                        .collect::<Vec<_>>(),
                    super::typed_path(open.ui.global::<SigningState>().get_store_path()),
                )
            };
            {
                let mut st = state(open);
                for file in files.iter().rev() {
                    st.remembered.remember_file(file);
                }
                st.remembered.remember_key_store(&store);
                if let Err(e) = st.remembered.save(&open.services.settings_path) {
                    tracing::warn!(error = %e, "cannot save the recent files");
                }
            }
            end_with(open, &result_text(t, &done));
        }
        Outcome::DocumentsChanged(items) => {
            {
                let mut st = state(open);
                st.frozen.clear();
                let _ = items;
            }
            end_with(open, t.changed_no_key);
        }
        Outcome::NotApplied(JobError::Cancelled) => {
            let running = open.sign.borrow().controller.step() == Step::Running;
            if running {
                end_with(open, t.cancelled_before);
            }
        }
        Outcome::NotApplied(e) => {
            let text = super::error_text(super::Texts::of(open.locale.get()), &e, 0);
            end_with(open, &format!("{text}\n{}", t.no_key_used));
        }
    }
}

/// Ends the operation with `text` on the result step; nothing of its unlock stays.
fn end_with(open: &Rc<Workspace>, text: &str) {
    {
        let mut st = state(open);
        st.controller.dispatch(Event::Finished);
        st.decision = None;
    }
    open.ui.global::<SigningState>().set_result(text.into());
    render(open);
}

fn result_text(t: &SignTexts, done: &[Signed]) -> String {
    let mut text = String::new();
    for item in done {
        let line = match (&item.output, item.error) {
            (Some(output), None) => t
                .signed_line
                .replace("{0}", &item.name)
                .replace("{1}", &output.display().to_string()),
            (_, Some(code)) => t
                .failed_line
                .replace("{0}", &item.name)
                .replace("{1}", code_text(t, code))
                .replace(
                    "{2}",
                    match item.applied {
                        AppliedState::NotApplied => t.key_not_used,
                        AppliedState::Applied => t.key_used,
                        _ => t.key_unknown,
                    },
                ),
            (None, None) => t
                .failed_line
                .replace("{0}", &item.name)
                .replace("{1}", "?")
                .replace("{2}", ""),
        };
        text.push_str(&line);
        text.push('\n');
    }
    text
}

fn code_text(t: &SignTexts, code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Cancelled => t.code_cancelled,
        ErrorCode::PermissionDenied => t.code_denied,
        ErrorCode::ValidationRequired | ErrorCode::MissingValidationServices => t.code_validation,
        ErrorCode::KeyFailure | ErrorCode::KeyNotFound => t.code_key,
        ErrorCode::Io => t.code_io,
        _ => t.code_other,
    }
}

/// The page's texts in one language.
struct SignTexts {
    /// One per step.
    titles: [&'static str; 5],
    /// `{0}` caller, `{1}` action.
    trust: &'static str,
    manual: &'static str,
    action_sign: &'static str,
    action_auth: &'static str,
    action_info: &'static str,
    expired: &'static str,
    not_yet: &'static str,
    not_for_signing: &'static str,
    expired_refusal: &'static str,
    not_yet_refusal: &'static str,
    not_for_signing_refusal: &'static str,
    /// `{0}` subject, `{1}` key name, `{2}` fingerprint.
    cert_line: &'static str,
    /// `{0}` count.
    confirm: &'static str,
    favorite: &'static str,
    unfavorite: &'static str,
    no_path: &'static str,
    no_documents: &'static str,
    no_key_store: &'static str,
    store_unreadable: &'static str,
    wrong_password: &'static str,
    changed: &'static str,
    changed_no_key: &'static str,
    signing: &'static str,
    waiting: &'static str,
    busy: &'static str,
    idle: &'static str,
    no_password: &'static str,
    /// `{0}` the files.
    outputs: &'static str,
    cancelled_before: &'static str,
    cancelled_applied_unknown: &'static str,
    no_key_used: &'static str,
    signed_line: &'static str,
    failed_line: &'static str,
    key_not_used: &'static str,
    key_used: &'static str,
    key_unknown: &'static str,
    code_cancelled: &'static str,
    code_denied: &'static str,
    code_validation: &'static str,
    code_key: &'static str,
    code_io: &'static str,
    code_other: &'static str,
}

impl SignTexts {
    fn of(l: Locale) -> &'static SignTexts {
        match l {
            Locale::Ru => &RU,
            Locale::Kk => &KK,
            Locale::En => &EN,
        }
    }
}

static RU: SignTexts = SignTexts {
    titles: [
        "Подпись: документы и хранилище ключей",
        "Подпись: пароль и сертификат",
        "Подпись: подтверждение",
        "Подпись: выполняется",
        "Подпись: результат",
    ],
    trust: "Запрос: {0} · Действие: {1}",
    manual: "вы сами, в этом окне",
    action_sign: "подписать документы (файлы подписи CMS .p7s рядом с документами)",
    action_auth: "аутентификация",
    action_info: "сведения о ключе",
    expired: "срок действия истёк",
    not_yet: "срок действия ещё не начался",
    not_for_signing: "не предназначен для подписи",
    expired_refusal: "Этим сертификатом нельзя подписать: срок его действия истёк.",
    not_yet_refusal: "Этим сертификатом нельзя подписать: срок его действия ещё не начался.",
    not_for_signing_refusal: "Этот сертификат не предназначен для подписи.",
    cert_line: "{0} · ключ «{1}» · SHA-256 {2}",
    confirm: "Подписать документов: {0}",
    favorite: "В избранное",
    unfavorite: "Убрать из избранного",
    no_path: "Укажите путь к файлу.",
    no_documents: "Добавьте хотя бы один документ.",
    no_key_store: "Укажите файл хранилища ключей.",
    store_unreadable: "Файл хранилища не удалось прочитать.",
    wrong_password: "Хранилище не открылось: неверный пароль или это не хранилище ключей.",
    changed: "Документы изменились после выбора. Они показаны заново; согласие не действует, начните с хранилища ключей.",
    changed_no_key: "Документы изменились после выбора, подпись не выполнялась и ключ не применялся.",
    busy: "Предыдущее действие ещё выполняется. Подождите.",
    idle: "Подтверждение закрыто: оно простояло без действий. Ничего не подписано, ключ не применялся.",
    no_password: "Введите пароль.",
    outputs: "Файлы подписи будут записаны:\n{0}",
    waiting: "Документы зафиксированы. Ключ не применяется, пока вы не подтвердите.",
    signing: "Идёт подпись. Отмена остановит остальные документы, уже применённый ключ вернуть нельзя.",
    cancelled_before: "Отменено до применения ключа. Ключ не применялся.",
    cancelled_applied_unknown: "Отменено. Часть документов могла быть подписана: проверьте файлы .p7s.",
    no_key_used: "Ключ не применялся.",
    signed_line: "Подписан: {0} → {1}",
    failed_line: "Не подписан: {0} — {1} ({2})",
    key_not_used: "ключ не применялся",
    key_used: "ключ был применён",
    key_unknown: "применён ли ключ, неизвестно",
    code_cancelled: "отменено",
    code_denied: "действие не разрешено",
    code_validation: "сертификат не прошёл проверку (цепочка, срок или отзыв)",
    code_key: "ключ недоступен",
    code_io: "не удалось записать файл подписи: возможно, он уже появился (существующие файлы не заменяются)",
    code_other: "не удалось выполнить",
};

static KK: SignTexts = SignTexts {
    titles: [
        "Қол қою: құжаттар және кілттер қоймасы",
        "Қол қою: құпиясөз және сертификат",
        "Қол қою: растау",
        "Қол қою: орындалуда",
        "Қол қою: нәтиже",
    ],
    trust: "Сұрау: {0} · Әрекет: {1}",
    manual: "өзіңіз, осы терезеде",
    action_sign: "құжаттарға қол қою (құжаттың жанында CMS .p7s файлдары)",
    action_auth: "аутентификация",
    action_info: "кілт туралы мәліметтер",
    expired: "жарамдылық мерзімі өткен",
    not_yet: "жарамдылық мерзімі әлі басталмаған",
    not_for_signing: "қол қоюға арналмаған",
    expired_refusal: "Бұл сертификатпен қол қоюға болмайды: оның мерзімі өткен.",
    not_yet_refusal: "Бұл сертификатпен қол қоюға болмайды: оның мерзімі әлі басталмаған.",
    not_for_signing_refusal: "Бұл сертификат қол қоюға арналмаған.",
    cert_line: "{0} · «{1}» кілті · SHA-256 {2}",
    confirm: "Құжаттарға қол қою: {0}",
    favorite: "Таңдаулыға қосу",
    unfavorite: "Таңдаулыдан алу",
    no_path: "Файлға жолды көрсетіңіз.",
    no_documents: "Кемінде бір құжат қосыңыз.",
    no_key_store: "Кілттер қоймасының файлын көрсетіңіз.",
    store_unreadable: "Қойма файлын оқу мүмкін болмады.",
    wrong_password: "Қойма ашылмады: құпиясөз қате немесе бұл кілттер қоймасы емес.",
    changed: "Таңдағаннан кейін құжаттар өзгерген. Олар қайта көрсетілді; келісім жарамсыз, кілттер қоймасынан бастаңыз.",
    changed_no_key: "Таңдағаннан кейін құжаттар өзгерген: қол қойылмады, кілт қолданылмады.",
    busy: "Алдыңғы әрекет әлі орындалуда. Күте тұрыңыз.",
    idle: "Растау әрекетсіз тұрғандықтан жабылды. Ештеңеге қол қойылмады, кілт қолданылмады.",
    no_password: "Құпиясөзді енгізіңіз.",
    outputs: "Қолтаңба файлдары жазылады:\n{0}",
    waiting: "Құжаттар бекітілді. Растағанша кілт қолданылмайды.",
    signing: "Қол қойылуда. Бас тарту қалған құжаттарды тоқтатады; қолданылған кілтті қайтаруға болмайды.",
    cancelled_before: "Кілт қолданылмай тұрып тоқтатылды. Кілт қолданылмады.",
    cancelled_applied_unknown: "Тоқтатылды. Кейбір құжаттарға қол қойылған болуы мүмкін: .p7s файлдарын тексеріңіз.",
    no_key_used: "Кілт қолданылмады.",
    signed_line: "Қол қойылды: {0} → {1}",
    failed_line: "Қол қойылмады: {0} — {1} ({2})",
    key_not_used: "кілт қолданылмады",
    key_used: "кілт қолданылды",
    key_unknown: "кілттің қолданылғаны белгісіз",
    code_cancelled: "тоқтатылды",
    code_denied: "әрекетке рұқсат жоқ",
    code_validation: "сертификат тексеруден өтпеді (тізбек, мерзім немесе қайтарып алу)",
    code_key: "кілт қолжетімсіз",
    code_io: "қолтаңба файлын жазу мүмкін болмады: ол пайда болған болуы мүмкін (бар файлдар ауыстырылмайды)",
    code_other: "орындау мүмкін болмады",
};

static EN: SignTexts = SignTexts {
    titles: [
        "Sign: documents and key store",
        "Sign: password and certificate",
        "Sign: confirmation",
        "Sign: in progress",
        "Sign: result",
    ],
    trust: "Request: {0} · Action: {1}",
    manual: "you, in this window",
    action_sign: "sign documents (CMS .p7s signature files next to the documents)",
    action_auth: "authenticate",
    action_info: "key details",
    expired: "expired",
    not_yet: "not valid yet",
    not_for_signing: "not for signing",
    expired_refusal: "This certificate cannot sign: it has expired.",
    not_yet_refusal: "This certificate cannot sign: it is not valid yet.",
    not_for_signing_refusal: "This certificate is not meant for signing.",
    cert_line: "{0} · key “{1}” · SHA-256 {2}",
    confirm: "Sign {0} document(s)",
    favorite: "Add to favourites",
    unfavorite: "Remove from favourites",
    no_path: "Enter the path to a file.",
    no_documents: "Add at least one document.",
    no_key_store: "Enter the key store file.",
    store_unreadable: "The key store file could not be read.",
    wrong_password: "The key store did not open: wrong password, or it is not a key store.",
    changed: "The documents changed after you picked them. They are shown again; nothing you agreed to stands, start from the key store.",
    changed_no_key: "The documents changed after you picked them: nothing was signed and no key was used.",
    busy: "The previous action is still running. Please wait.",
    idle: "The confirmation was closed after sitting idle. Nothing was signed and no key was used.",
    no_password: "Enter the password.",
    outputs: "The signature files will be written to:\n{0}",
    waiting: "The documents are frozen. The key is not used until you confirm.",
    signing: "Signing. Cancel stops the remaining documents; a key already applied cannot be taken back.",
    cancelled_before: "Cancelled before the key was applied. No key was used.",
    cancelled_applied_unknown: "Cancelled. Some documents may be signed: check the .p7s files.",
    no_key_used: "No key was used.",
    signed_line: "Signed: {0} → {1}",
    failed_line: "Not signed: {0} — {1} ({2})",
    key_not_used: "the key was not used",
    key_used: "the key was applied",
    key_unknown: "whether the key was applied is unknown",
    code_cancelled: "cancelled",
    code_denied: "the action is not allowed",
    code_validation: "the certificate failed its checks (chain, validity or revocation)",
    code_key: "the key is not available",
    code_io: "the signature file could not be written; it may have appeared meanwhile (existing files are never replaced)",
    code_other: "it could not be done",
};
