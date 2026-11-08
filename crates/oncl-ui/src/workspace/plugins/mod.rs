//! The Plugins page of the tools window: the operations of the installed plugins that the
//! manual window can run, grouped by plugin; an operation's form built from its declared
//! parameters; the key (the same key store, password and certificate flow as the Sign page);
//! the confirmation page that shows what Core prepared and whose one button names the action;
//! the run on a worker with a deadline and a cancel; and the result, said honestly.
//!
//! **Who agrees to what.** The page agrees to nothing by itself. The key is applied only by the
//! plugin, inside Core's `plugin_call_approved`, only for an approval that Core issued for the
//! user's confirmation of the very summary the page showed. The confirmation is made in
//! [`consent::user_confirmed`] and nowhere else, from the handler of the confirm button, after the
//! controller let that press through (prepared, shown, armed: [`controller`]). Enter alone never
//! confirms (the focus starts on «Cancel»); Escape cancels; nothing of a confirmation is kept.
//!
//! **Who says what.** The host's lines are the host's: Core's summary, the declared operation's
//! own wording ([`consent`]). A plugin's own text (its name, its label of an operation, the reply
//! of its module) is only ever drawn in a frame under a caption that says whose words they are.
//!
//! **The password** is cleared from the page's field the moment it is submitted, held by the
//! controller until the certificate is chosen (at most [`KEY_IDLE`]), then moved into the run's
//! worker, which drops (zeroizes) it when the run ends whichever way ([`run`]). It is never logged.
//!
//! **Outputs.** A manual call has no file output of its own. The reply of a call that was
//! verified applied can be saved, whole and as received, to a `.json` file the user places in
//! the host's dialog ([`save`], [`report`]); nothing else is written.

mod confirm;
mod consent;
mod controller;
mod form;
mod offer;
mod report;
mod run;
mod save;
#[cfg(test)]
mod tests;
mod texts;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::time::{Duration, Instant};

use oncl_flows::Locale;
use oncl_flows::capabilities::is_operation_name;
use slint::{
    ComponentHandle, ModelRc, SharedString, StandardListViewItem, Timer, TimerMode, VecModel,
};
use zeroize::Zeroizing;

use self::consent::{ConsentInput, ConsentView, compose};
use self::controller::{Effect, Event, PluginController, Refusal, Step};
use self::form::{FieldKind, FieldValue, FormError, FormField, FreezeError, Frozen};
pub use self::offer::{
    ManualListing, ManualPluginSource, NoManualPlugins, OfferError, OfferedOperation,
    PluginEngineKit, PluginOffer, UnusablePlugin, WithoutOperations, WithoutReason, plugin_offer,
};
use self::report::{ResultView, RunFacts, TicketWords};
use self::run::{Decision, NotPrepared, Prepared, RunOutcome, RunSpec};
use self::save::SaveError;
use self::texts::Texts;
use super::controller::{Job, JobError};
use super::{Output, Workspace, start, with_open};
use crate::install_plugin::{frame_caption, untrusted_label};
use crate::signing::controller::{Candidate, Unsuitable};
use crate::signing::runner::{OpenError, open_key_store};
use crate::ui::{
    PluginFormField, PluginGroupRow, PluginHiddenRow, PluginOperationRow, PluginsState,
};
use oncl_core::plugins::ManualLimits;

/// The page's place in the window's sidebar.
pub(super) const SECTION: i32 = 8;

/// The confirmation cannot be pressed for this long after it is shown, so that a burst of
/// clicks aimed at something else cannot land on it the moment it appears.
const ARM_AFTER: Duration = Duration::from_millis(600);
/// The password of a key store stays on the key page this long at most: then the page is
/// closed and the password forgotten.
const KEY_IDLE: Duration = Duration::from_secs(300);
/// How long a cancel of a running plugin waits for the worker before the page says it is still
/// working and lets the user leave.
const CANCEL_WAIT: Duration = Duration::from_secs(10);
/// Two clicks on the same certificate within this are a double-click.
const DOUBLE_CLICK: Duration = Duration::from_millis(500);

/// What a worker of the page gives back.
pub(super) enum PluginOutput {
    /// The plugins installed now.
    Offer(Result<Arc<PluginOffer>, OfferError>),
    Unlocked(Result<Vec<Candidate>, OpenError>),
    Run(RunOutcome),
}

/// Whether the installed plugins have been read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Plugins {
    Unread,
    InProgress,
    Ready,
    Unavailable,
}

/// The confirmation on the page: the summary Core prepared (what a confirmation names) and the
/// text composed from it.
struct Shown {
    summary: oncl_core::plugins::ConsentSummary,
    view: ConsentView,
    /// What the page was composed from, kept so that a language switch while the confirmation
    /// is open composes the same page again in the new language.
    operation: OfferedOperation,
    file_name: String,
    entered: Vec<(String, Frozen)>,
    /// The language of `view`.
    locale: Locale,
}

/// The confirmation page for `shown`'s inputs in `l`, as the registry of `st` declares the
/// operation; `None` if Core's summary and the registry no longer agree.
fn compose_for(
    st: &State,
    summary: &oncl_core::plugins::ConsentSummary,
    operation: &OfferedOperation,
    file_name: &str,
    entered: &[(String, Frozen)],
    l: Locale,
) -> Option<ConsentView> {
    let offer = st.offer.clone()?;
    let operations = offer.engine.plugin_operations(&operation.plugin_id).ok()?;
    let declared = operations
        .into_iter()
        .find(|d| d.name() == operation.operation)?;
    compose(&ConsentInput {
        summary,
        declared,
        offered: operation,
        file_name,
        entered,
        ttl: st.approval_ttl,
        locale: l,
    })
    .ok()
}

/// A language switch while a confirmation is open: its text is composed again in the new
/// language (from the same summary and values), never left in the old one.
fn recompose_for_locale(open: &Rc<Workspace>, l: Locale) {
    let mut st = open.plugins.borrow_mut();
    let Some(shown) = st.shown.as_ref().filter(|s| s.locale != l) else {
        return;
    };
    let view = compose_for(
        &st,
        &shown.summary,
        &shown.operation,
        &shown.file_name,
        &shown.entered,
        l,
    );
    if let (Some(view), Some(shown)) = (view, st.shown.as_mut()) {
        shown.view = view;
        shown.locale = l;
    }
}

/// The page's state on the event loop.
pub(super) struct State {
    controller: PluginController,
    offer: Option<Arc<PluginOffer>>,
    reading: Plugins,
    fields: Vec<FormField>,
    values: Vec<FieldValue>,
    /// The operation the running worker belongs to: its late answer for another is dropped.
    pending_op: Option<u64>,
    /// Answers the run's worker that waits for the user's decision.
    decision: Option<Sender<Decision>>,
    shown: Option<Shown>,
    /// The operation of the run in progress, from the registry snapshot the run was prepared
    /// from (not the list's, which may be older).
    running_op: Option<OfferedOperation>,
    result: Option<ResultView>,
    /// How saving the reply went (a message under the result), until the page is left.
    save_note: String,
    /// A message for the step the page is on (an idle close, a refused operation).
    notice: String,
    /// The message is an error of a field or a step (red), not a note.
    since: Instant,
    shown_at: Option<Instant>,
    tick: Timer,
    cancel_wait: Timer,
    last_click: Option<(i32, Instant)>,
    /// The quiet time before the confirmation works, how long a confirmation or the key page
    /// may sit idle, how long an approval lives, and how long a cancel waits for the worker.
    arm_after: Duration,
    consent_idle: Duration,
    key_idle: Duration,
    approval_ttl: Duration,
    cancel_after: Duration,
}

impl State {
    pub(super) fn new() -> State {
        State {
            controller: PluginController::default(),
            offer: None,
            reading: Plugins::Unread,
            fields: Vec::new(),
            values: Vec::new(),
            pending_op: None,
            decision: None,
            shown: None,
            running_op: None,
            result: None,
            save_note: String::new(),
            notice: String::new(),
            since: Instant::now(),
            shown_at: None,
            tick: Timer::default(),
            cancel_wait: Timer::default(),
            last_click: None,
            arm_after: ARM_AFTER,
            consent_idle: offer::CONSENT_IDLE,
            key_idle: KEY_IDLE,
            approval_ttl: oncl_core::plugins::APPROVAL_TTL,
            cancel_after: CANCEL_WAIT,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::new()
    }
}

pub(super) fn connect(ui: &crate::ui::WorkspaceWindow) {
    let s = ui.global::<PluginsState>();
    s.on_refresh(|| with_open(refresh));
    s.on_open_operation(|g, o| with_open(|open| open_operation(open, g, o)));
    s.on_field_text(|i, text| with_open(|open| field_text(open, i, text.as_str())));
    s.on_field_choice(|i, index| with_open(|open| field_choice(open, i, index)));
    s.on_field_flag(|i, on| with_open(|open| field_flag(open, i, on)));
    s.on_browse_field(|i| with_open(|open| browse_field(open, i)));
    s.on_browse_store(|| with_open(browse_store));
    s.on_form_continue(|| with_open(form_continue));
    s.on_unlock(|| with_open(unlock));
    s.on_cert_clicked(|i| with_open(|open| cert_clicked(open, i)));
    s.on_cert_chosen(|i| with_open(|open| cert_chosen(open, i)));
    confirm::wire(ui);
    s.on_cancel(|| with_open(cancel));
    s.on_back(|| with_open(back));
    s.on_again(|| with_open(again));
    s.on_save_reply(|| with_open(save_reply));
    s.on_finish(|| with_open(finish));
}

fn locale(open: &Rc<Workspace>) -> Locale {
    open.locale.get()
}

fn texts(open: &Rc<Workspace>) -> &'static Texts {
    Texts::of(locale(open))
}

fn state(open: &Rc<Workspace>) -> std::cell::RefMut<'_, State> {
    open.plugins.borrow_mut()
}

fn ui_state(open: &Rc<Workspace>) -> PluginsState<'_> {
    open.ui.global::<PluginsState>()
}

/// A step is refused while a worker still runs, and the page says so.
fn busy(open: &Rc<Workspace>) -> bool {
    if open.ui.get_busy() {
        state(open).notice = texts(open).busy.to_owned();
        render(open);
        true
    } else {
        false
    }
}

/// The sidebar picked page `section`: the plugins are read when this one is first shown; leaving
/// the page while it holds a form, a password or a confirmation cancels those (a run in
/// progress goes on, and the status line tells it).
pub(super) fn section_changed(open: &Rc<Workspace>, section: i32) {
    if section == SECTION {
        // Every open of the page reads the installed plugins again: a plugin turned off or
        // withdrawn meanwhile does not stay runnable in a window that was open.
        let at_list = open.plugins.borrow().controller.step() == Step::List;
        if at_list {
            refresh(open);
        } else {
            render(open);
        }
    } else if matches!(
        open.plugins.borrow().controller.step(),
        Step::Form | Step::Key | Step::Consent
    ) {
        leave(open);
        render(open);
    }
}

/// Whether the page shows how far its worker is: never (its own status line tells the phase).
pub(super) fn shows_progress(_open: &Rc<Workspace>) -> bool {
    false
}

/// Whether a confirmed run is going: the key may be applied already, so the window is not
/// closed under it (the user waits or cancels, and is told how it ended).
pub(super) fn is_running(open: &Rc<Workspace>) -> bool {
    open.plugins.borrow().controller.step() == Step::Running
}

/// The window is closed. Whether the key could have been applied is read from the operation's own
/// control, which the run marks when it lets the key be applied (never from the page's step):
/// before that gate the key was never used and the waiting worker is told to let go (quietly);
/// after it the answer is only Core's, which nobody will see, so it is logged at error level with
/// "unknown". The worker is left to finish in the background; it holds no UI handle.
pub(super) fn abandon(open: &Rc<Workspace>) {
    let gate = {
        let controller = open.controller.borrow();
        match controller.running() {
            Some((Job::Plugin, control)) => Some(control.key_gate_passed()),
            _ => None,
        }
    };
    {
        let mut st = state(open);
        if let Some(tx) = st.decision.take() {
            let _ = tx.send(Decision::Abort);
        }
        st.shown = None;
        st.tick.stop();
        st.cancel_wait.stop();
    }
    match gate {
        Some(true) => tracing::error!(
            key_use = "unknown",
            "the window was closed while a plugin run had not answered: whether the key was applied is unknown; the worker finishes in the background"
        ),
        Some(false) => tracing::info!(
            key_use = "none",
            "the window was closed before the plugin could use the key; the waiting worker is aborted"
        ),
        None => {}
    }
}

// ---- the list ----

/// The offered operations of one plugin, as indices into the listing, in the listing's order.
struct Group {
    id: String,
    version: String,
    name: oncl_plugin::Localized,
    operations: Vec<usize>,
}

fn groups(listing: &ManualListing) -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();
    for (index, op) in listing.operations.iter().enumerate() {
        match out.last_mut() {
            Some(g) if g.id == op.plugin_id && g.version == op.plugin_version => {
                g.operations.push(index);
            }
            _ => out.push(Group {
                id: op.plugin_id.clone(),
                version: op.plugin_version.clone(),
                name: op.plugin_name.clone(),
                operations: vec![index],
            }),
        }
    }
    out
}

/// Reads the installed plugins again (on a worker): the registry and the list of the window.
fn refresh(open: &Rc<Workspace>) {
    if open.ui.get_busy() {
        // A step of the page is running: the list is read when it ends.
        return;
    }
    {
        let mut st = state(open);
        if st.controller.step() != Step::List {
            return;
        }
        st.reading = Plugins::InProgress;
        st.notice.clear();
        st.pending_op = Some(st.controller.id());
    }
    render(open);
    let source = Arc::clone(&open.services.plugins);
    start(open, Job::Plugin, move |_, _| {
        Ok(Output::Plugin(PluginOutput::Offer(
            source.offer().map(Arc::new),
        )))
    });
    open.ui.set_status_text(texts(open).s_reading.into());
}

fn open_operation(open: &Rc<Workspace>, group: i32, index: i32) {
    if busy(open) {
        return;
    }
    let (Ok(g), Ok(o)) = (usize::try_from(group), usize::try_from(index)) else {
        return;
    };
    let l = locale(open);
    let chosen = {
        let st = open.plugins.borrow();
        let Some(offer) = st.offer.clone() else {
            return;
        };
        let operation = groups(&offer.listing)
            .get(g)
            .and_then(|group| group.operations.get(o).copied())
            .map(|i| offer.listing.operations[i].clone());
        operation.map(|op| (offer, op))
    };
    let Some((offer, operation)) = chosen else {
        return;
    };
    // The engine's own registry is the authority: the operation must be declared there, use a
    // key (what is approved is the use of the key), and give the form its parameters.
    let declared = offer
        .engine
        .plugin_operations(&operation.plugin_id)
        .ok()
        .and_then(|ops| {
            ops.into_iter()
                .find(|d| d.name() == operation.operation)
                .map(|d| (d.params().to_vec(), !d.uses().keys().is_empty()))
        });
    let mut st = state(open);
    let Some((params, uses_key)) = declared else {
        st.notice = Texts::of(l).stale.to_owned();
        drop(st);
        return render(open);
    };
    if !uses_key || !operation.uses_key || !is_operation_name(&operation.operation) {
        st.notice = Texts::of(l).p_not_runnable.to_owned();
        drop(st);
        return render(open);
    }
    st.notice.clear();
    st.fields = form::fields_of(&params);
    st.values = form::initial(&st.fields, l);
    let index = offer
        .listing
        .operations
        .iter()
        .position(|o| *o == operation)
        .unwrap_or_default();
    st.controller.dispatch(Event::Select(index));
    drop(st);
    ui_state(open).set_store_path("".into());
    ui_state(open).set_password("".into());
    render(open);
}

/// The offered operation the page is on.
fn current_operation(st: &State) -> Option<OfferedOperation> {
    if matches!(
        st.controller.step(),
        Step::Consent | Step::Running | Step::Result
    ) && st.running_op.is_some()
    {
        return st.running_op.clone();
    }
    let offer = st.offer.as_ref()?;
    offer
        .listing
        .operations
        .get(st.controller.operation()?)
        .cloned()
}

// ---- the form ----

fn field_text(open: &Rc<Workspace>, i: i32, text: &str) {
    let mut st = state(open);
    if let Some(FieldValue::Text(value)) =
        usize::try_from(i).ok().and_then(|i| st.values.get_mut(i))
    {
        *value = text.to_owned();
    }
}

/// A choice or a language: the index of the row of the page's combo box (a choice's first row is
/// «Choose…», no choice).
fn field_choice(open: &Rc<Workspace>, i: i32, index: i32) {
    let mut st = state(open);
    let Some(i) = usize::try_from(i).ok() else {
        return;
    };
    let Some(field) = st.fields.get(i).cloned() else {
        return;
    };
    let value = match field.kind {
        FieldKind::Choice { .. } => {
            FieldValue::Index(usize::try_from(index).ok().and_then(|n| n.checked_sub(1)))
        }
        FieldKind::Locale => FieldValue::Index(usize::try_from(index).ok()),
        _ => return,
    };
    st.values[i] = value;
}

fn field_flag(open: &Rc<Workspace>, i: i32, on: bool) {
    let mut st = state(open);
    if let Some(value @ FieldValue::Flag(_)) =
        usize::try_from(i).ok().and_then(|i| st.values.get_mut(i))
    {
        *value = FieldValue::Flag(on);
    }
}

fn browse_field(open: &Rc<Workspace>, i: i32) {
    let t = super::Texts::of(locale(open));
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(t.pick_title)
        .set_parent(&open.ui.window().window_handle());
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.pick_file().await else {
            return;
        };
        let path = file.path().display().to_string();
        with_open(|open| {
            field_text(open, i, &path);
            render(open);
        });
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

fn browse_store(open: &Rc<Workspace>) {
    let t = super::Texts::of(locale(open));
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(t.pick_title)
        .set_parent(&open.ui.window().window_handle());
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.pick_file().await else {
            return;
        };
        let path = file.path().display().to_string();
        with_open(|open| ui_state(open).set_store_path(path.into()));
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

fn size_text(open: &Rc<Workspace>, bytes: u64) -> String {
    super::size(super::Texts::of(locale(open)), bytes)
}

/// The words for a form that cannot be read.
fn form_error_text(open: &Rc<Workspace>, e: &FormError, fields: &[FormField]) -> String {
    let t = texts(open);
    match e {
        FormError::NoPath(name) => t.e_no_path.replace("{0}", name),
        FormError::TextTooLong { name, max } => t
            .e_text_long
            .replace("{0}", name)
            .replace("{1}", &max.to_string()),
        FormError::BadText(name) => t.e_text_bad.replace("{0}", name),
        FormError::NoChoice(name) => {
            let _ = fields;
            t.p_value.to_owned() + " " + name
        }
    }
}

fn freeze_error_text(open: &Rc<Workspace>, e: &FreezeError) -> String {
    let t = texts(open);
    match e {
        FreezeError::Unreadable(name) => t.e_unreadable.replace("{0}", name),
        FreezeError::TooBig { name, max } => t
            .e_too_big
            .replace("{0}", name)
            .replace("{1}", &size_text(open, *max)),
        FreezeError::Empty(name) => t.e_empty.replace("{0}", name),
        FreezeError::Cancelled => super::Texts::of(locale(open)).cancelled.to_owned(),
    }
}

/// Reads the form and looks at its documents (their size, not their bytes) so that a missing or
/// oversize file is told before a password is asked for. The bytes are read at the run.
fn form_continue(open: &Rc<Workspace>) {
    if busy(open) {
        return;
    }
    let t = texts(open);
    let store = super::typed_path(ui_state(open).get_store_path());
    let (fields, values) = {
        let st = open.plugins.borrow();
        if st.controller.step() != Step::Form {
            return;
        }
        (st.fields.clone(), st.values.clone())
    };
    let typed = match form::read(&fields, &values) {
        Ok(typed) => typed,
        Err(e) => {
            state(open).notice = form_error_text(open, &e, &fields);
            return render(open);
        }
    };
    for ((name, value), field) in typed.iter().zip(&fields) {
        if let (form::Typed::Document(path), FieldKind::Document { max_bytes }) =
            (value, &field.kind)
        {
            let problem = match std::fs::metadata(path) {
                Ok(meta) if meta.is_file() && meta.len() == 0 => {
                    Some(FreezeError::Empty(name.clone()))
                }
                Ok(meta) if meta.is_file() && meta.len() > *max_bytes => {
                    Some(FreezeError::TooBig {
                        name: name.clone(),
                        max: *max_bytes,
                    })
                }
                Ok(meta) if meta.is_file() => None,
                _ => Some(FreezeError::Unreadable(name.clone())),
            };
            if let Some(problem) = problem {
                state(open).notice = freeze_error_text(open, &problem);
                return render(open);
            }
        }
    }
    if store.is_empty() {
        state(open).notice = t.e_no_store.to_owned();
        return render(open);
    }
    {
        let mut st = state(open);
        st.notice.clear();
        st.controller.dispatch(Event::KeyStore(store));
        st.since = Instant::now();
    }
    start_tick(open);
    render(open);
}

// ---- the key ----

fn unlock(open: &Rc<Workspace>) {
    // Taken out of the page at once; Enter here opens the key store and agrees to nothing.
    let secret = Zeroizing::new(ui_state(open).get_password().to_string());
    if secret.is_empty() {
        // A repeated Enter finds the field already emptied: it must not replace the password
        // that is being used.
        if !open.ui.get_busy() {
            state(open).notice = texts(open).no_password.to_owned();
            render(open);
        }
        return;
    }
    if busy(open) {
        return;
    }
    ui_state(open).set_password("".into());
    let (store, effect) = {
        let mut st = state(open);
        if st.controller.step() != Step::Key {
            return;
        }
        st.notice.clear();
        let store = st.controller.key_store().unwrap_or_default().to_owned();
        let effect = st.controller.dispatch(Event::PasswordSubmitted(secret));
        (store, effect)
    };
    if effect != Effect::OpenKeyStore {
        return;
    }
    let Some(secret) = state(open).controller.unlock_secret() else {
        return;
    };
    {
        let mut st = state(open);
        st.pending_op = Some(st.controller.id());
    }
    start(open, Job::Plugin, move |services, _| {
        Ok(Output::Plugin(PluginOutput::Unlocked(open_key_store(
            &PathBuf::from(store),
            &secret,
            (services.clock)(),
        ))))
    });
    render(open);
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
    }
}

/// Enter, a double-click or the button: the certificate is chosen and the confirmation is
/// prepared; nothing is signed (the plugin is not even started until the user confirms).
fn cert_chosen(open: &Rc<Workspace>, i: i32) {
    if busy(open) {
        return;
    }
    let Ok(index) = usize::try_from(i) else {
        return;
    };
    let t = texts(open);
    let effect = state(open)
        .controller
        .dispatch(Event::CertificateChosen(index));
    match effect {
        Effect::Refused(Refusal::UnsuitableCertificate(why)) => {
            state(open).notice = match why {
                Unsuitable::Expired => t.expired_refusal,
                Unsuitable::NotYetValid => t.not_yet_refusal,
                _ => t.not_for_signing_refusal,
            }
            .to_owned();
            return render(open);
        }
        Effect::Prepare => {}
        _ => return,
    }
    state(open).notice.clear();
    start_run(open);
    render(open);
}

/// The run's worker: freeze, prepare, wait for the user, call. The password moves into it.
fn start_run(open: &Rc<Workspace>) {
    let (spec, rx, op, source) = {
        let mut st = state(open);
        let (Some(offer), Some(operation)) = (st.offer.clone(), current_operation(&st)) else {
            st.controller.dispatch(Event::PrepareFailed);
            return;
        };
        let typed = form::read(&st.fields, &st.values);
        let (Some(chosen), Some(store), Some(password), Ok(typed)) = (
            st.controller.chosen().cloned(),
            st.controller.key_store().map(PathBuf::from),
            st.controller.take_secret(),
            typed,
        ) else {
            st.controller.dispatch(Event::PrepareFailed);
            return;
        };
        let Some(certificate) = chosen.sha256 else {
            st.controller.dispatch(Event::PrepareFailed);
            return;
        };
        let (tx, rx) = channel::<Decision>();
        st.decision = Some(tx);
        let op = st.controller.id();
        st.pending_op = Some(op);
        st.running_op = Some(operation.clone());
        let source = Arc::clone(&open.services.plugins);
        let spec = RunSpec {
            offer,
            operation,
            fields: st.fields.clone(),
            typed,
            store,
            alias: chosen.alias,
            certificate,
            password,
            ttl: st.approval_ttl,
            idle: st.consent_idle,
        };
        (spec, rx, op, source)
    };
    start(open, Job::Plugin, move |_, control| {
        // The registry is read again for THIS run: what is prepared, confirmed and called is
        // the current registry, and an operation that vanished meanwhile (a plugin turned off,
        // withdrawn, updated) is refused before anything is shown.
        let mut spec = spec;
        let fresh = source.offer().ok().map(Arc::new).and_then(|offer| {
            let same = |o: &&OfferedOperation| {
                o.plugin_id == spec.operation.plugin_id
                    && o.plugin_version == spec.operation.plugin_version
                    && o.operation == spec.operation.operation
                    && o.uses_key
            };
            let operation = offer.listing.operations.iter().find(same)?.clone();
            Some((offer, operation))
        });
        let Some((offer, operation)) = fresh else {
            return Ok(Output::Plugin(PluginOutput::Run(RunOutcome::NotPrepared(
                NotPrepared::Registry,
            ))));
        };
        spec.offer = offer;
        spec.operation = operation;
        let outcome = run::run(spec, control, &rx, move |prepared| {
            super::deliver(move || with_open(|open| prepared_arrived(open, op, prepared)));
        });
        Ok(Output::Plugin(PluginOutput::Run(outcome)))
    });
    open.ui.set_status_text(texts(open).s_preparing.into());
}

/// Core prepared the confirmation: it is composed from what Core says and shown, if it is the
/// operation the page is still on.
fn prepared_arrived(open: &Rc<Workspace>, op: u64, prepared: Prepared) {
    let t = texts(open);
    let l = locale(open);
    let mut st = state(open);
    if st.controller.step() != Step::Consent || st.controller.id() != op {
        // The user left meanwhile: the waiting worker is told so by whoever left.
        return;
    }
    st.offer = Some(Arc::clone(&prepared.offer));
    st.running_op = Some(prepared.operation.clone());
    let composed = compose_for(
        &st,
        &prepared.summary,
        &prepared.operation,
        &prepared.file_name,
        &prepared.entered,
        l,
    );
    match composed {
        Some(view) => {
            st.shown = Some(Shown {
                summary: prepared.summary,
                view,
                operation: prepared.operation,
                file_name: prepared.file_name,
                entered: prepared.entered,
                locale: l,
            });
            st.shown_at = Some(Instant::now());
            st.since = Instant::now();
            st.controller.dispatch(Event::Prepared);
            drop(st);
            open.ui.set_status_text(t.s_waiting.into());
            start_tick(open);
        }
        None => {
            // What Core prepared and what the registry declares do not agree: nothing is shown
            // to confirm, the worker is told to let go, and the page goes back to the list.
            if let Some(tx) = st.decision.take() {
                let _ = tx.send(Decision::Abort);
            }
            st.controller.dispatch(Event::Cancel);
            st.pending_op = None;
            st.notice = t.consent_invalid.to_owned();
            drop(st);
            open.controller.borrow_mut().cancel();
        }
    }
    render(open);
}

// ---- the confirmation ----

fn start_tick(open: &Rc<Workspace>) {
    state(open)
        .tick
        .start(TimerMode::Repeated, Duration::from_millis(200), || {
            with_open(tick);
        });
}

/// Arms the confirmation after a quiet moment, and closes a confirmation or a key page that sat
/// idle.
fn tick(open: &Rc<Workspace>) {
    let t = texts(open);
    let (armed_now, idle) = {
        let mut st = state(open);
        match st.controller.step() {
            Step::Consent => {
                let Some(at) = st.shown_at else {
                    return;
                };
                let elapsed = at.elapsed();
                let armed_now = elapsed >= st.arm_after && !st.controller.armed() && {
                    st.controller.dispatch(Event::Arm);
                    true
                };
                (
                    armed_now,
                    (elapsed >= st.consent_idle).then_some(t.consent_idle),
                )
            }
            Step::Key => {
                let idle = st.since.elapsed() >= st.key_idle;
                (false, idle.then_some(t.key_idle))
            }
            _ => {
                st.tick.stop();
                return;
            }
        }
    };
    if let Some(why) = idle {
        leave(open);
        state(open).notice = why.to_owned();
        render(open);
    } else if armed_now {
        render(open);
    }
}

// ---- leaving ----

/// Cancel, Escape and the status line's Cancel, at every step: the form, the key and the
/// confirmation are left (the waiting worker is told to let go, the password is forgotten, the
/// next operation starts clean); a running plugin is asked to stop at its next checkpoint, and
/// if the worker has not answered within [`CANCEL_WAIT`] the page says so and lets the user
/// leave; its answer, when it comes, still shows what really happened.
pub(super) fn cancel(open: &Rc<Workspace>) {
    let step = open.plugins.borrow().controller.step();
    match step {
        Step::Running => cancel_running(open),
        Step::Result => {
            state(open).controller.dispatch(Event::Done);
            clear_session(open);
            render(open);
        }
        Step::List => {
            // A worker that reads the plugins: asked to stop; there is nothing to leave.
            if plugin_job_runs(open) {
                open.controller.borrow_mut().cancel();
            }
        }
        _ => {
            leave(open);
            render(open);
        }
    }
}

fn plugin_job_runs(open: &Rc<Workspace>) -> bool {
    open.controller
        .borrow()
        .running()
        .is_some_and(|(job, _)| job == Job::Plugin)
}

fn cancel_running(open: &Rc<Workspace>) {
    // The key may be applied already: the page stays until the worker says how far it got.
    open.controller.borrow_mut().cancel();
    open.ui
        .set_status_text(super::Texts::of(locale(open)).cancelling.into());
    let (op, wait) = {
        let st = open.plugins.borrow();
        (st.controller.id(), st.cancel_after)
    };
    open.plugins
        .borrow()
        .cancel_wait
        .start(TimerMode::SingleShot, wait, move || {
            with_open(|open| {
                let still = {
                    let st = open.plugins.borrow();
                    st.controller.step() == Step::Running && st.controller.id() == op
                };
                if still {
                    // The worker has not answered: the page is not left waiting silently. Its
                    // late answer is dropped (and logged by the window's lifecycle).
                    let t = texts(open);
                    let mut st = state(open);
                    st.controller.dispatch(Event::Finished);
                    st.pending_op = None;
                    let facts = facts_of(&st);
                    let mut view = report::render_lost(&facts.as_facts(), locale(open));
                    view.headline = t.r_cancel_slow.to_owned();
                    st.result = Some(view);
                    drop(st);
                    render(open);
                }
            });
        });
}

/// Leaves the operation: the waiting worker is told to let go, its job is asked to stop, and
/// nothing of the operation stays (password, form, confirmation, result).
fn leave(open: &Rc<Workspace>) {
    let worker = plugin_job_runs(open);
    {
        let mut st = state(open);
        if let Some(tx) = st.decision.take() {
            let _ = tx.send(Decision::Abort);
        }
        st.controller.dispatch(Event::Cancel);
        st.pending_op = None;
    }
    if worker {
        open.controller.borrow_mut().cancel();
    }
    clear_session(open);
}

/// Nothing of the last operation is kept: the confirmation, the result, the form's values, the
/// password field.
fn clear_session(open: &Rc<Workspace>) {
    {
        let mut st = state(open);
        st.shown = None;
        st.shown_at = None;
        st.running_op = None;
        st.result = None;
        st.save_note.clear();
        st.fields.clear();
        st.values.clear();
        st.tick.stop();
        st.cancel_wait.stop();
    }
    let ui = ui_state(open);
    ui.set_password("".into());
    ui.set_cert_index(-1);
}

fn back(open: &Rc<Workspace>) {
    if busy(open) {
        return;
    }
    let step = open.plugins.borrow().controller.step();
    match step {
        Step::Form => {
            leave(open);
        }
        Step::Key => {
            state(open).controller.dispatch(Event::Back);
            ui_state(open).set_password("".into());
            ui_state(open).set_cert_index(-1);
            state(open).notice.clear();
        }
        _ => return,
    }
    render(open);
}

fn again(open: &Rc<Workspace>) {
    {
        let mut st = state(open);
        if st.controller.dispatch(Event::Again) != Effect::None {
            return;
        }
        st.result = None;
        st.notice.clear();
        st.save_note.clear();
        // The values the user entered stay; the password and the confirmation do not.
        st.pending_op = None;
    }
    ui_state(open).set_password("".into());
    render(open);
}

fn finish(open: &Rc<Workspace>) {
    state(open).controller.dispatch(Event::Done);
    clear_session(open);
    state(open).notice.clear();
    render(open);
}

/// The user asked to save the reply: the host's own dialog asks where, with the name the host
/// built. Nothing is written until the dialog returns a place.
fn save_reply(open: &Rc<Workspace>) {
    if busy(open) {
        return;
    }
    let name = {
        let st = open.plugins.borrow();
        match (
            st.controller.step(),
            st.result.as_ref().and_then(|r| r.save.as_ref()),
        ) {
            (Step::Result, Some(offer)) => offer.name.clone(),
            _ => return,
        }
    };
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(texts(open).save_dialog_title)
        .set_file_name(&name)
        .add_filter("JSON", &["json"])
        .set_parent(&open.ui.window().window_handle());
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.save_file().await else {
            return;
        };
        let path = file.path().to_owned();
        with_open(|open| write_reply(open, path));
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

/// Writes the reply to `path` (always as a `.json` file) and says in the page how it went.
///
/// The write runs on the UI thread: the reply is at most the plugin's `max_transfer` and the
/// page holds the only copy, which is not `Send` (the workspace is a `Rc`), so moving it to
/// the job thread would need a second copy of the reply and a hand-back of the note; the
/// user's click waits for one file of that size and nothing else runs meanwhile.
fn write_reply(open: &Rc<Workspace>, path: PathBuf) {
    let path = if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        path
    } else {
        let mut os = path.into_os_string();
        os.push(".json");
        PathBuf::from(os)
    };
    let t = texts(open);
    let cap = ManualLimits::desktop().instance.max_transfer;
    let saved = {
        let st = open.plugins.borrow();
        let Some(offer) = st
            .result
            .as_ref()
            .filter(|_| st.controller.step() == Step::Result)
            .and_then(|r| r.save.as_ref())
        else {
            return;
        };
        save::save_reply(&path, offer.reply.bytes(), cap)
    };
    let note = match saved {
        Ok(()) => t.saved_to.replace("{0}", &path.display().to_string()),
        Err(SaveError::TooLarge { len, cap }) => t
            .save_too_large
            .replace("{0}", &size_text(open, len as u64))
            .replace("{1}", &size_text(open, cap as u64)),
        Err(SaveError::BadName) => t.save_bad_name.to_owned(),
        Err(SaveError::Job(JobError::DestinationExists)) => t.save_exists.to_owned(),
        Err(SaveError::Job(e)) => t.save_failed.replace(
            "{0}",
            super::error_text(super::Texts::of(locale(open)), &e, 0),
        ),
    };
    state(open).save_note = note;
    render(open);
}

// ---- what a worker gave back ----

/// The facts of the run for the result, from the host's own data.
struct OwnedFacts {
    operation: String,
    plugin_id: String,
    plugin_version: String,
}

impl OwnedFacts {
    fn as_facts(&self) -> RunFacts<'_> {
        RunFacts {
            operation: &self.operation,
            plugin_id: &self.plugin_id,
            plugin_version: &self.plugin_version,
        }
    }
}

fn facts_of(st: &State) -> OwnedFacts {
    let op = current_operation(st);
    OwnedFacts {
        operation: op.as_ref().map(|o| o.operation.clone()).unwrap_or_default(),
        plugin_id: op.as_ref().map(|o| o.plugin_id.clone()).unwrap_or_default(),
        plugin_version: op
            .as_ref()
            .map(|o| o.plugin_version.clone())
            .unwrap_or_default(),
    }
}

/// A worker of the page ended.
pub(super) fn settled(open: &Rc<Workspace>, result: Result<PluginOutput, JobError>) {
    let t = texts(open);
    let l = locale(open);
    let mine = {
        let mut st = state(open);
        let mine = st.pending_op.take();
        mine == Some(st.controller.id())
    };
    if !mine {
        // The answer of an operation that was left: it changes nothing of the operation, but
        // the page must not stay disabled for a job that has ended.
        if let Ok(PluginOutput::Run(RunOutcome::Done(report))) = &result {
            // A confirmed run whose page was left: whatever it did is known only here, and
            // only the log can tell it.
            tracing::error!(
                applied = ?report.applied,
                refusals = report.refusals.len(),
                "a plugin run finished after its page was left"
            );
        }
        return render(open);
    }
    match result {
        Ok(PluginOutput::Offer(Ok(offer))) => {
            let mut st = state(open);
            st.offer = Some(offer);
            st.reading = Plugins::Ready;
        }
        Ok(PluginOutput::Offer(Err(e))) => {
            tracing::warn!(error = ?e, "the plugins cannot be offered");
            let mut st = state(open);
            st.offer = None;
            st.reading = Plugins::Unavailable;
        }
        Ok(PluginOutput::Unlocked(Ok(mut candidates))) => {
            // Chosen from the certificates of the key store: the ones that can sign first.
            candidates.sort_by_key(|c| c.unsuitable.is_some());
            let mut st = state(open);
            st.controller.dispatch(Event::Unlocked(candidates));
            drop(st);
            ui_state(open).set_cert_index(-1);
        }
        Ok(PluginOutput::Unlocked(Err(e))) => {
            let mut st = state(open);
            st.controller.dispatch(Event::UnlockFailed);
            st.notice = match e {
                OpenError::Unreadable => t.store_unreadable,
                OpenError::WrongPasswordOrFormat => t.wrong_password,
            }
            .to_owned();
        }
        Ok(PluginOutput::Run(outcome)) => ran(open, outcome),
        Err(error) => {
            let mut st = state(open);
            if st.controller.step() == Step::Running {
                // The worker was lost after the user's confirmation: the key may have been
                // applied, and nobody can say. It is never reported as unused.
                st.controller.dispatch(Event::Finished);
                let facts = facts_of(&st);
                st.result = Some(report::render_lost(&facts.as_facts(), l));
            } else {
                st.notice = super::error_text(super::Texts::of(l), &error, 0).to_owned();
                if st.controller.step() == Step::Consent {
                    st.controller.dispatch(Event::PrepareFailed);
                }
            }
        }
    }
    status_after(open);
    render(open);
}

/// The status line says how a finished run ended, never "ready" for a failure.
fn status_after(open: &Rc<Workspace>) {
    let st = open.plugins.borrow();
    let Some(view) = st
        .result
        .as_ref()
        .filter(|_| st.controller.step() == Step::Result)
    else {
        return;
    };
    let kind = match view.tone {
        crate::reports::controller::Tone::Success => 2,
        crate::reports::controller::Tone::Failure => 3,
        _ => 4,
    };
    open.ui.set_status_kind(kind);
    open.ui.set_status_text(view.headline.as_str().into());
}

fn ran(open: &Rc<Workspace>, outcome: RunOutcome) {
    let l = locale(open);
    let mut st = state(open);
    match outcome {
        RunOutcome::Done(call) => {
            let facts = facts_of(&st);
            st.controller.dispatch(Event::Finished);
            let view = report::render(&call, &facts.as_facts(), l, &TicketWords);
            st.result = Some(view);
            st.decision = None;
        }
        RunOutcome::Declined => {
            // The worker stopped because the page was left, which is handled where it was left;
            // reaching here with the page still on the confirmation means the worker gave up
            // alone.
            match st.controller.step() {
                Step::Running => {
                    // The key was never applied (the worker declined before the call): the
                    // page is not left waiting.
                    let facts = facts_of(&st);
                    st.controller.dispatch(Event::Finished);
                    st.result = Some(report::render_cancelled(&facts.as_facts(), l));
                }
                Step::Consent => {
                    st.controller.dispatch(Event::Cancel);
                    st.notice = Texts::of(l).consent_idle.to_owned();
                    st.shown = None;
                }
                _ => {}
            }
        }
        RunOutcome::NotPrepared(why) => {
            let t = Texts::of(l);
            st.shown = None;
            st.decision = None;
            // Back to where it can be mended: a file that cannot be read goes back to the form,
            // everything else to the key (the password is asked again).
            let (text, to_form) = match &why {
                NotPrepared::Freeze(e) => {
                    drop(st);
                    let text = freeze_error_text(open, e);
                    st = state(open);
                    (text, true)
                }
                NotPrepared::Store(JobError::StoreChanged) => (t.p_cert_mismatch.to_owned(), false),
                NotPrepared::Store(e) => (
                    super::error_text(super::Texts::of(l), e, 0).to_owned(),
                    false,
                ),
                NotPrepared::Registry => (t.stale.to_owned(), false),
                NotPrepared::Prepare(e) => (
                    format!(
                        "{} ({})",
                        report::prepare_error_text(l, e),
                        e.subcode().id()
                    ),
                    false,
                ),
            };
            st.controller.dispatch(Event::PrepareFailed);
            if to_form {
                st.controller.dispatch(Event::Back);
            }
            st.notice = text;
        }
    }
}

// ---- rendering ----

/// Shows the controller's step with everything the step needs.
pub(super) fn render(open: &Rc<Workspace>) {
    let l = locale(open);
    let t = Texts::of(l);
    recompose_for_locale(open, l);
    let st = open.plugins.borrow();
    let ui = ui_state(open);
    let step = st.controller.step();
    ui.set_step(match step {
        Step::List => 0,
        Step::Form => 1,
        Step::Key => 2,
        Step::Consent => 3,
        Step::Running => 4,
        Step::Result => 5,
    });
    ui.set_busy(open.ui.get_busy() && !matches!(step, Step::Consent | Step::Running));
    ui.set_error(st.notice.as_str().into());
    ui.set_refresh_label(t.refresh.into());
    ui.set_open_label(t.open_operation.into());
    ui.set_continue_label(t.continue_.into());
    ui.set_back_label(t.back.into());
    ui.set_cancel_label(t.cancel.into());
    ui.set_again_label(t.again.into());
    ui.set_finish_label(t.finish.into());
    let operation = current_operation(&st);
    ui.set_title(
        match (&step, &operation) {
            (Step::Form, Some(op)) => t.form_title.replace("{0}", &op.operation),
            (Step::Key, _) => t.key_title.to_owned(),
            (Step::Consent, _) => t.consent_title.to_owned(),
            _ => t.page_title.to_owned(),
        }
        .as_str()
        .into(),
    );
    render_list(open, &st, &ui, t, l);
    render_form(open, &st, &ui, t, l, operation.as_ref());
    render_key(&st, &ui, t);
    render_consent(&st, &ui, t);
    render_result(&st, &ui, t);
    ui.set_running(t.running.into());
}

fn text_model(items: impl IntoIterator<Item = String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        items
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    ))
}

fn render_list(open: &Rc<Workspace>, st: &State, ui: &PluginsState<'_>, t: &Texts, l: Locale) {
    let _ = open;
    ui.set_intro(t.intro.into());
    let (mut rows, mut hidden) = (Vec::new(), Vec::new());
    if let Some(offer) = st
        .offer
        .as_ref()
        .filter(|_| st.reading != Plugins::Unavailable)
    {
        for group in groups(&offer.listing) {
            rows.push(PluginGroupRow {
                heading: t
                    .plugin_heading
                    .replace("{0}", &group.id)
                    .replace("{1}", &group.version)
                    .into(),
                name_caption: t.frame_name.into(),
                name: untrusted_label(group.name.get(l)).into(),
                operations: ModelRc::new(VecModel::from(
                    group
                        .operations
                        .iter()
                        .map(|&i| {
                            let op = &offer.listing.operations[i];
                            // The identifier was checked at parse and is checked again here:
                            // a name that is not one is not drawn and cannot be opened.
                            let valid = is_operation_name(&op.operation);
                            PluginOperationRow {
                                heading: if valid {
                                    t.operation_heading.replace("{0}", &op.operation)
                                } else {
                                    t.operation_invalid.to_owned()
                                }
                                .into(),
                                key_line: if op.uses_key {
                                    t.key_use_yes
                                } else {
                                    t.key_use_no
                                }
                                .into(),
                                label_caption: frame_caption(l).into(),
                                label: untrusted_label(op.label.get(l)).into(),
                                open_label: t.open_label.replace("{0}", &op.operation).into(),
                                can_open: valid && op.uses_key,
                            }
                        })
                        .collect::<Vec<_>>(),
                )),
            });
        }
        for plugin in &offer.listing.without_operations {
            hidden.push(PluginHiddenRow {
                line: format!(
                    "{} {}",
                    t.without_ops
                        .replace("{0}", &plugin.plugin_id)
                        .replace("{1}", &plugin.plugin_version),
                    match plugin.reason {
                        WithoutReason::NoOperations => t.why_no_operations,
                        WithoutReason::NoManualOperations => t.why_no_manual,
                        WithoutReason::UnsupportedNetwork => t.why_network,
                        WithoutReason::NotRegistered => t.why_not_registered,
                    }
                )
                .into(),
                name_caption: t.frame_name.into(),
                name: untrusted_label(plugin.plugin_name.get(l)).into(),
            });
        }
        for plugin in &offer.listing.unusable {
            hidden.push(PluginHiddenRow {
                line: t.unusable.replace("{0}", &plugin.plugin_id).into(),
                name_caption: SharedString::default(),
                name: SharedString::default(),
            });
        }
    }
    let note = match st.reading {
        Plugins::Unread | Plugins::InProgress => t.reading,
        Plugins::Unavailable => t.no_source,
        Plugins::Ready if rows.is_empty() => t.none_offered,
        Plugins::Ready => "",
    };
    ui.set_list_note(note.into());
    ui.set_groups(ModelRc::new(VecModel::from(rows)));
    ui.set_hidden_heading(
        if hidden.is_empty() {
            ""
        } else {
            t.hidden_heading
        }
        .into(),
    );
    ui.set_hidden(ModelRc::new(VecModel::from(hidden)));
}

fn render_form(
    open: &Rc<Workspace>,
    st: &State,
    ui: &PluginsState<'_>,
    t: &Texts,
    l: Locale,
    operation: Option<&OfferedOperation>,
) {
    let Some(op) = operation.filter(|_| st.controller.step() == Step::Form) else {
        ui.set_fields(ModelRc::default());
        ui.set_form_intro("".into());
        ui.set_label("".into());
        ui.set_label_caption("".into());
        return;
    };
    ui.set_form_intro(
        t.form_intro
            .replace("{0}", &op.plugin_id)
            .replace("{1}", &op.plugin_version)
            .as_str()
            .into(),
    );
    ui.set_label_caption(frame_caption(l).into());
    ui.set_label(untrusted_label(op.label.get(l)).into());
    ui.set_store_label(t.store_label.into());
    ui.set_store_placeholder(t.store_placeholder.into());
    let rows: Vec<PluginFormField> = st
        .fields
        .iter()
        .zip(&st.values)
        .map(|(field, value)| {
            let text = match value {
                FieldValue::Text(text) => text.as_str(),
                _ => "",
            };
            let (kind, label, choices, index) = match &field.kind {
                FieldKind::Document { max_bytes } => (
                    0,
                    t.doc_label
                        .replace("{0}", &field.name)
                        .replace("{1}", &size_text(open, *max_bytes)),
                    Vec::new(),
                    0,
                ),
                FieldKind::Text { max_chars } => (
                    1,
                    t.text_label
                        .replace("{0}", &field.name)
                        .replace("{1}", &max_chars.to_string()),
                    Vec::new(),
                    0,
                ),
                FieldKind::Choice { choices } => (
                    2,
                    t.choice_label.replace("{0}", &field.name),
                    std::iter::once(t.choose_one.to_owned())
                        .chain(choices.iter().map(|c| crate::view::page_text(c)))
                        .collect(),
                    match value {
                        FieldValue::Index(Some(i)) => i32::try_from(*i + 1).unwrap_or(0),
                        _ => 0,
                    },
                ),
                FieldKind::Flag => (3, t.flag_label.replace("{0}", &field.name), Vec::new(), 0),
                FieldKind::Locale => (
                    4,
                    t.locale_label.replace("{0}", &field.name),
                    form::LOCALES
                        .iter()
                        .map(|code| match *code {
                            "ru" => "Русский",
                            "kk" => "Қазақша",
                            _ => "English",
                        })
                        .map(str::to_owned)
                        .collect(),
                    match value {
                        FieldValue::Index(Some(i)) => i32::try_from(*i).unwrap_or(0),
                        _ => 0,
                    },
                ),
            };
            PluginFormField {
                kind,
                label: label.into(),
                placeholder: t.doc_placeholder.into(),
                text: text.into(),
                choices: text_model(choices),
                index,
                flag: matches!(value, FieldValue::Flag(true)),
            }
        })
        .collect();
    ui.set_fields(ModelRc::new(VecModel::from(rows)));
}

fn render_key(st: &State, ui: &PluginsState<'_>, t: &Texts) {
    ui.set_password_label(t.password_label.into());
    ui.set_open_store_label(t.open_store.into());
    ui.set_choose_label(t.choose_cert.into());
    ui.set_show_consent_label(t.show_consent.into());
    let rows: Vec<StandardListViewItem> = st
        .controller
        .candidates()
        .iter()
        .map(|c| {
            let why = match c.unsuitable {
                None => String::new(),
                Some(Unsuitable::Expired) => format!(" — {}", t.expired),
                Some(Unsuitable::NotYetValid) => format!(" — {}", t.not_yet),
                Some(_) => format!(" — {}", t.not_for_signing),
            };
            StandardListViewItem::from(
                t.cert_row
                    .replace("{0}", &crate::view::page_text(&c.subject))
                    .replace("{1}", &crate::view::page_text(&c.alias))
                    .replace("{2}", &why)
                    .as_str(),
            )
        })
        .collect();
    ui.set_certs(ModelRc::new(VecModel::from(rows)));
}

fn render_consent(st: &State, ui: &PluginsState<'_>, t: &Texts) {
    let view = st
        .shown
        .as_ref()
        .filter(|_| st.controller.step() == Step::Consent)
        .map(|shown| &shown.view);
    let empty = ConsentView::default();
    let v = view.unwrap_or(&empty);
    ui.set_c_title(v.title.as_str().into());
    ui.set_c_lead(v.lead.as_str().into());
    ui.set_c_trusted(text_model(v.trusted.iter().cloned()));
    ui.set_c_package_caption(v.package_caption.as_str().into());
    ui.set_c_package_sha(v.package_sha.as_str().into());
    ui.set_c_file_lines(text_model(v.file_lines.iter().cloned()));
    ui.set_c_file_sha_caption(v.file_sha_caption.as_str().into());
    ui.set_c_file_sha(v.file_sha.as_str().into());
    ui.set_c_prehash_caption(v.prehash_caption.as_str().into());
    ui.set_c_prehash(v.prehash.as_str().into());
    ui.set_c_key_heading(v.key_heading.as_str().into());
    ui.set_c_key_lines(text_model(v.key_lines.iter().cloned()));
    ui.set_c_fingerprint_caption(v.fingerprint_caption.as_str().into());
    ui.set_c_fingerprint(v.fingerprint.as_str().into());
    ui.set_c_inputs_caption(v.inputs_caption.as_str().into());
    ui.set_c_inputs(text_model(v.inputs.iter().cloned()));
    ui.set_c_ttl(v.ttl_line.as_str().into());
    ui.set_c_trust_note(v.trust_note.as_str().into());
    ui.set_c_frame_caption(v.frame.caption.as_str().into());
    ui.set_c_frame_name_caption(v.frame.name_caption.as_str().into());
    ui.set_c_frame_name(v.frame.name.as_str().into());
    ui.set_c_frame_label(v.frame.label.as_str().into());
    ui.set_c_frame_lines(text_model(v.frame.lines.iter().cloned()));
    // Before the summary is ready the buttons still have their real, localized names.
    let operation = current_operation(st)
        .map(|o| o.operation)
        .unwrap_or_default();
    if st.controller.step() == Step::Consent && view.is_none() {
        ui.set_confirm_label(t.confirm_label.replace("{0}", &operation).as_str().into());
    } else {
        ui.set_confirm_label(v.confirm_label.as_str().into());
    }
    if st.controller.step() == Step::Consent {
        ui.set_cancel_label(t.consent_cancel.into());
    }
    // From the step and the controller, never from a running job: the job that prepared the
    // confirmation waits for the very button this enables.
    ui.set_confirm_enabled(st.controller.step() == Step::Consent && st.controller.armed());
    ui.set_confirm_hint(
        if st.controller.step() != Step::Consent {
            ""
        } else if !st.controller.prepared() {
            t.preparing
        } else {
            t.consent_arming
        }
        .into(),
    );
}

fn render_result(st: &State, ui: &PluginsState<'_>, t: &Texts) {
    let Some(view) = st
        .result
        .as_ref()
        .filter(|_| st.controller.step() == Step::Result)
    else {
        ui.set_report_headline("".into());
        ui.set_report_tone(3);
        ui.set_report_rows(ModelRc::default());
        ui.set_reply("".into());
        ui.set_reply_caption("".into());
        ui.set_result_note("".into());
        ui.set_save_offered(false);
        ui.set_save_note("".into());
        return;
    };
    ui.set_report_headline(view.headline.as_str().into());
    ui.set_report_tone(crate::reports::tone_number(view.tone));
    ui.set_report_rows(super::report_rows(&view.rows));
    match &view.reply {
        Some(reply) => {
            ui.set_reply(reply.text.as_str().into());
            ui.set_reply_caption(reply.caption.as_str().into());
            ui.set_reply_cut(reply.cut_note.as_str().into());
        }
        None => {
            ui.set_reply("".into());
            ui.set_reply_caption("".into());
            ui.set_reply_cut("".into());
        }
    }
    ui.set_result_note(view.note.as_str().into());
    ui.set_save_offered(view.save.is_some());
    ui.set_save_reply_label(t.save_reply.into());
    ui.set_save_note(st.save_note.as_str().into());
}
