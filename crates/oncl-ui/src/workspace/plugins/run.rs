//! The worker's side of one plugin operation: freeze what the user chose, bind the key the
//! backend signs with, have Core prepare the confirmation, wait for the user's decision, and run
//! the plugin under the approval Core issues for it.
//!
//! Nothing here asks the user anything and nothing touches Slint. The key is applied only by the
//! plugin, inside [`oncl_core::Engine::plugin_call_approved`], and only for an approval that
//! [`PluginPrepared::approve`] issued for the [`UserConfirmation`] this function was handed: the
//! page makes that confirmation in the handler of the confirm button
//! ([`super::consent::user_confirmed`]) and sends it here.
//!
//! **The password.** It is moved in with the [`RunSpec`] when the user chose the certificate, is
//! used to open the key store at the preparation (to compare its certificate with the one shown)
//! and again in the call, and is dropped (zeroized) when this function returns, whichever way it
//! ends: a failed preparation, a cancel, the idle limit, the call's end, a panic. Nothing here
//! logs it.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use oncl_core::keys::{KeyRequest, KeySelector};
use oncl_core::plugins::{
    ApprovalIssueError, ConsentSummary, ManualCall, ManualHost, PluginKeyBinding, PluginParam,
    PluginPermission, PluginPrepareError, UserConfirmation,
};
use oncl_core::{Action, ErrorCode, ExecutionGrant, OperationError, OperationPolicy};
use oncl_pki::key::AppliedState;
use oncl_plugin::operations::{ContentForm, Profile};
use zeroize::Zeroizing;

use super::form::{FormField, FreezeError, Frozen, Typed, freeze};
use super::offer::{OfferedOperation, PluginOffer, RUN_LIMIT};
use super::report::CallReport;
use crate::signing::runner::{key_certificate, read_key_store, sha256_of};
use crate::workspace::{JobControl, JobError};

/// The handle the plugin sees the bound key by (the only key it can name).
const KEY_HANDLE: u32 = 1;

/// Everything the worker needs; the password is in it.
pub(super) struct RunSpec {
    pub(super) offer: Arc<PluginOffer>,
    pub(super) operation: OfferedOperation,
    pub(super) fields: Vec<FormField>,
    pub(super) typed: Vec<(String, Typed)>,
    pub(super) store: PathBuf,
    pub(super) alias: String,
    /// SHA-256 of the certificate the user chose from the key store's list.
    pub(super) certificate: [u8; 32],
    pub(super) password: Zeroizing<String>,
    /// How long the approval lives after the confirmation.
    pub(super) ttl: Duration,
    /// How long the confirmation may wait for the user before the worker gives up by itself.
    pub(super) idle: Duration,
}

/// What the user decided, sent to the worker that waits for it.
pub(super) enum Decision {
    /// The user's confirmation of the summary the page showed.
    Proceed(UserConfirmation),
    /// The user left: nothing happens.
    Abort,
}

/// What the page is told when the confirmation is prepared: the trusted summary Core made, and
/// what the page needs besides it.
pub(super) struct Prepared {
    /// The registry snapshot the run was prepared on, and the operation in it.
    pub(super) offer: Arc<PluginOffer>,
    pub(super) operation: OfferedOperation,
    pub(super) summary: ConsentSummary,
    /// The name of the file the user picked, as its path gives it.
    pub(super) file_name: String,
    /// The other values the user entered (no document bytes).
    pub(super) entered: Vec<(String, Frozen)>,
}

/// Why no confirmation was prepared. The key was not used in any of them.
#[derive(Debug)]
pub(in crate::workspace) enum NotPrepared {
    Freeze(FreezeError),
    Store(JobError),
    /// The plugin or the operation is not (or no longer) in the engine's registry.
    Registry,
    Prepare(PluginPrepareError),
}

/// How a run ended.
#[derive(Debug)]
pub(in crate::workspace) enum RunOutcome {
    NotPrepared(NotPrepared),
    /// The user did not confirm (left the page, cancelled, did not answer in time): the plugin
    /// never ran and the key was not used.
    Declined,
    /// The call ran (or was refused by Core): what Core reports of it.
    Done(CallReport),
}

fn param(frozen: &Frozen) -> PluginParam<'_> {
    match frozen {
        Frozen::Document { bytes, .. } => PluginParam::Document(bytes),
        Frozen::Text(t) => PluginParam::Text(t),
        Frozen::Choice(c) => PluginParam::Choice(c),
        Frozen::Flag(f) => PluginParam::Flag(*f),
        Frozen::Locale(l) => PluginParam::Locale(l),
    }
}

/// Runs the operation. `prepared` runs on the worker when Core has prepared the confirmation,
/// and must hand it to the page; the page's decision then arrives on `decision`.
///
/// # Panics
///
/// Never on purpose; a panic ends the worker and the page says that it was lost.
pub(super) fn run(
    spec: RunSpec,
    control: &Arc<JobControl>,
    decision: &Receiver<Decision>,
    prepared: impl FnOnce(Prepared),
) -> RunOutcome {
    match run_inner(spec, control, decision, prepared) {
        Ok(outcome) => outcome,
        Err(not_prepared) => RunOutcome::NotPrepared(not_prepared),
    }
}

fn engine_error(e: OperationError) -> NotPrepared {
    NotPrepared::Store(JobError::from(e))
}

fn run_inner(
    spec: RunSpec,
    control: &Arc<JobControl>,
    decision: &Receiver<Decision>,
    prepared: impl FnOnce(Prepared),
) -> Result<RunOutcome, NotPrepared> {
    let RunSpec {
        offer,
        operation,
        fields,
        typed,
        store,
        alias,
        certificate,
        password,
        ttl,
        idle,
    } = spec;
    let engine = &offer.engine;

    // What the user chose is read once, here, into memory: what is shown, approved and given to
    // the plugin is these bytes, not the file as it is later.
    let frozen = freeze(&fields, typed, control.as_ref()).map_err(NotPrepared::Freeze)?;
    let file_name = frozen
        .iter()
        .find_map(|(_, f)| match f {
            Frozen::Document { file_name, .. } => Some(file_name.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let params: Vec<(&str, PluginParam<'_>)> =
        frozen.iter().map(|(n, f)| (n.as_str(), param(f))).collect();
    let entered: Vec<(String, Frozen)> = frozen
        .iter()
        .filter(|(_, f)| !matches!(f, Frozen::Document { .. }))
        .cloned()
        .collect();

    // The key store is read once; the certificate the user chose from the list is compared with
    // this copy, and the engine signs with this copy only, so a file swapped later is never used.
    let bytes = read_key_store(&store).map_err(NotPrepared::Store)?;
    let cert = key_certificate(&bytes, &password, &alias).map_err(NotPrepared::Store)?;
    let der = der::Encode::to_der(&cert).map_err(|_| NotPrepared::Store(JobError::StoreChanged))?;
    if sha256_of(&der) != certificate {
        return Err(NotPrepared::Store(JobError::StoreChanged));
    }
    let selector = KeySelector::inline(bytes.to_vec(), Some(alias.clone()));
    let key_id = selector.key_id();

    // The registry's own declaration is the authority for what the operation may import and how
    // it signs; the offer's list only says what to show.
    let operations = engine
        .plugin_operations(&operation.plugin_id)
        .map_err(|_| NotPrepared::Registry)?;
    let declared = operations
        .into_iter()
        .find(|o| o.name() == operation.operation)
        .ok_or(NotPrepared::Registry)?;
    let digest =
        declared.uses().keys().iter().any(
            |k| matches!(k.profile(), Profile::CmsEx(p) if p.content_form == ContentForm::Digest),
        );
    let mut permission = PluginPermission::new(
        operation.plugin_id.clone(),
        operation.operation.clone(),
        offer.caller.clone(),
        declared.uses().imports().iter().copied(),
    )
    .with_keys([key_id.clone()]);
    if !operation.pki_endpoints.is_empty() {
        permission = permission
            .with_pki_endpoints(
                operation
                    .pki_endpoints
                    .iter()
                    .map(|(m, u)| (*m, u.as_str())),
            )
            .map_err(engine_error)?;
    }
    let mut actions = vec![Action::Sign, Action::Hash];
    if digest {
        actions.push(Action::SignDigest);
    }
    let grant = ExecutionGrant::new(actions)
        .with_keys([key_id])
        .with_plugins([permission]);
    let policy = OperationPolicy {
        allow_prehashed: digest,
        ..OperationPolicy::strict_online()
    };
    let mut ctx = engine
        .begin(grant, policy, control.clone())
        .map_err(engine_error)?;
    // The copy, the selector's copy and the decrypted key are charged to the operation's budget
    // for as long as the operation lives.
    let _store_memory = ctx
        .resources()
        .reserve_memory(bytes.len() as u64 * 4)
        .map_err(OperationError::from)
        .map_err(engine_error)?;

    let binding = PluginKeyBinding::new(
        KEY_HANDLE,
        KeyRequest::new(&selector, Some(password.as_str())),
    )
    .with_public_metadata(&alias, &cert, &[]);
    let call = ManualCall {
        plugin_id: &operation.plugin_id,
        operation: &operation.operation,
        params: &params,
        key: &binding,
        caller: &offer.caller,
    };
    let prepared_key_use = engine
        .plugin_prepare(&call, &mut ctx)
        .map_err(NotPrepared::Prepare)?;
    prepared(Prepared {
        offer: Arc::clone(&offer),
        operation: operation.clone(),
        summary: prepared_key_use.summary().clone(),
        file_name,
        entered,
    });

    // Waiting for the user. The page ends the wait by itself (its idle limit, a cancel); this
    // loop also gives up on its own a little after the same limit, and on a cancel of the
    // operation (a closed window).
    let waited = Instant::now();
    let confirmation = loop {
        match decision.recv_timeout(Duration::from_millis(100)) {
            Ok(Decision::Proceed(confirmation)) => break confirmation,
            Ok(Decision::Abort) | Err(RecvTimeoutError::Disconnected) => {
                return Ok(RunOutcome::Declined);
            }
            Err(RecvTimeoutError::Timeout) => {
                if control.is_cancelled() || waited.elapsed() > idle + Duration::from_secs(5) {
                    return Ok(RunOutcome::Declined);
                }
            }
        }
    };
    if control.is_cancelled() {
        return Ok(RunOutcome::Declined);
    }
    let approval = match prepared_key_use.approve(confirmation, Some(ttl)) {
        Ok(approval) => approval,
        Err(e) => {
            let _: ApprovalIssueError = e;
            return Ok(RunOutcome::Done(CallReport {
                applied: AppliedState::NotApplied,
                refusals: Vec::new(),
                response: None,
                error: Some(ErrorCode::PermissionDenied),
            }));
        }
    };
    // From here on the key may be applied: whether it was is only known from Core's answer.
    control.mark_key_gate_passed();
    control.set_deadline(RUN_LIMIT);
    let host = ManualHost {
        transport: &offer.host.transport,
        network: &offer.host.network,
        ocsp_cache: &offer.host.ocsp_cache,
    };
    let result = engine.plugin_call_approved(&call, approval, &host, &mut ctx);
    Ok(RunOutcome::Done(CallReport {
        applied: result.applied(),
        refusals: result.refusals().to_vec(),
        response: result.response().map(str::to_owned),
        error: result.error().map(OperationError::code),
    }))
}
