//! The engine's side of one signing operation: freezing documents, opening a key store to list
//! its certificates, and the batch that applies the key once the user's consent exists.
//!
//! Nothing here asks the user anything and nothing touches Slint. The key is applied only by
//! [`sign`], and only after the controller's [`Approved`] reached it through the caller's
//! handshake; the engine's guard ([`ConsentGuard`]) refuses any application that is not for
//! exactly that consent, one per approved document.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use der::Encode;
use oncl_core::batch::{BatchEvent, BatchItem, BatchOutput};
use oncl_core::keys::{KeyId, KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard};
use oncl_core::keys::{KeyUseOutcome, KeyUseReceipt};
use oncl_core::{
    Action, CadesConfiguration, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationError,
    OperationPolicy, ValidationServices,
};
use oncl_pki::cms::ades::ValidationMaterial;
use oncl_pki::http::HttpTransport;
use oncl_pki::info::cert_info;
use oncl_pki::io::{Source, TemporaryStore};
use oncl_pki::key::HashAlg;
use oncl_pki::pkix::CaSet;
use oncl_pki::resource::ResourceLimits;
use oncl_pki::validation::NetworkPolicy;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::controller::{Approved, Candidate, Item, Unsuitable};
use crate::reports::controller::{BatchView, Family};
use crate::workspace::{
    Destination, JobControl, JobError, PlannedOutput, SignFormat, SignInput, SignSpec,
    batch_operation_error, open_regular, plan_output, read_limited, sign_operation,
    view_of_summary,
};

/// The origins of the national certification authority's revocation and time services; the
/// only network the signing checks may reach unless the host adds its own.
pub const NCA_ORIGINS: [&str; 5] = [
    "http://ocsp.pki.gov.kz",
    "http://ocsp.pki.gov.kz:8080",
    "http://crl.pki.gov.kz",
    "http://crl.root.gov.kz",
    "http://tsp.pki.gov.kz",
];

/// What the host adds to the national authority: roots it trusts and origins its checks may
/// reach, both explicit.
#[derive(Default)]
pub struct ExtraTrust {
    pub anchors: Vec<oncl_pki::cert::Certificate>,
    pub origins: Vec<String>,
}

struct Grant {
    operation: u64,
    key: KeyId,
    action: Action,
    uses_left: usize,
}

/// Lets the engine apply the key exactly for the consent the user gave: one operation, one
/// key, one action, one application per approved document.
#[derive(Default)]
pub struct ConsentGuard {
    grant: Mutex<Option<Grant>>,
    applications: std::sync::atomic::AtomicUsize,
    /// Holds the spool's owner lock for the life of the engine: another process sharing the
    /// directory sees it and leaves the spool alone.
    _spool_lock: Option<File>,
}

impl ConsentGuard {
    fn allow(&self, operation: u64, key: KeyId, action: Action, uses: usize) {
        *self.grant.lock().unwrap_or_else(PoisonError::into_inner) = Some(Grant {
            operation,
            key,
            action,
            uses_left: uses,
        });
    }

    /// Allows the engine to apply `key` `uses` times for `operation`, as the consented run does;
    /// for tests that drive the SDK directly.
    #[cfg(test)]
    pub(crate) fn allow_for_tests(&self, operation: u64, key: KeyId, action: Action, uses: usize) {
        self.allow(operation, key, action, uses);
    }

    /// How many times the engine was allowed to apply the key.
    pub fn applications(&self) -> usize {
        self.applications.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn revoke(&self) {
        *self.grant.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl KeyUseGuard for ConsentGuard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let mut grant = self.grant.lock().unwrap_or_else(PoisonError::into_inner);
        match grant.as_mut() {
            Some(g)
                if g.operation == event.operation_id.get()
                    && g.key == event.key_id
                    && g.action == event.action
                    && g.uses_left > 0 =>
            {
                g.uses_left -= 1;
                self.applications
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(KeyUseReceipt::new(event.clone()))
            }
            _ => Err(OperationError::PermissionDenied),
        }
    }

    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        tracing::info!(
            operation = receipt.event().operation_id.get(),
            applied = ?outcome.applied,
            succeeded = outcome.succeeded,
            "a private key was applied"
        );
        Ok(())
    }
}

/// The engine of the desktop's tools and signing: hashing and inspecting need nothing, signing
/// needs the key sources, the guard, the validation of the certificate and a place for frozen
/// documents. `spool` is a directory this program owns.
pub fn desktop_engine(
    limits: ResourceLimits,
    http: Arc<dyn HttpTransport>,
    extra: ExtraTrust,
    spool: &Path,
    clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
) -> Result<(Engine, Arc<ConsentGuard>), OperationError> {
    std::fs::create_dir_all(spool).map_err(oncl_pki::resource::ProcessingError::from)?;
    // Only the process that holds the spool's owner lock may clean it: a live spool of another
    // process on the same data directory is never touched.
    let spool_lock = claim_spool(spool);
    if spool_lock.is_some() {
        remove_stale_spool(spool);
    }
    let guard = Arc::new(ConsentGuard {
        _spool_lock: spool_lock,
        ..ConsentGuard::default()
    });
    let mut anchors = CaSet::nca_production().certs().to_vec();
    anchors.extend(extra.anchors);
    let origins = NCA_ORIGINS
        .iter()
        .map(|o| (*o).to_owned())
        .chain(extra.origins);
    let network = NetworkPolicy::only_endpoints(origins)
        .map_err(|_| oncl_pki::resource::ProcessingError::InvalidInput("PKI endpoint"))?;

    let store = TemporaryStore::new(spool)?;
    let tsa = crate::workspace::tsa_spec(HashAlg::Sha256, Some(crate::workspace::NCA_TSA_POLICY))
        .map_err(|_| oncl_pki::resource::ProcessingError::InvalidInput("TSA"))?;
    let services = EngineServices::hash_only(limits)
        .with_keys(Arc::new(KeySources::new()), guard.clone())
        .with_validation(ValidationServices::new(
            CaSet::new(anchors),
            Vec::new(),
            http,
            network,
            clock,
        ))
        .with_cades(CadesConfiguration::new(
            crate::workspace::evidence_limits(),
            tsa,
        ))
        .with_temporary_store(store);
    Ok((Engine::new(services)?, guard))
}

/// The spool's owner lock: `None` if another process holds it.
fn claim_spool(spool: &Path) -> Option<File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(spool.join(".owner"))
        .ok()?;
    file.try_lock().ok().map(|()| file)
}

/// Whether `name` is one of the temporary store's own names: `oncl-` and 32 hex digits.
fn is_store_name(name: &str) -> bool {
    name.strip_prefix("oncl-")
        .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Frozen copies and staged outputs of a run that died stay in the spool this program owns:
/// they are removed at start by the process that holds the owner lock, and nothing else in
/// the directory is.
fn remove_stale_spool(spool: &Path) {
    let Ok(entries) = std::fs::read_dir(spool) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if is_store_name(&name.to_string_lossy()) {
            let path = entry.path();
            let removed = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            if let Err(e) = removed {
                tracing::warn!(error = %e, "cannot remove a stale spool entry");
            }
        }
    }
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(&HashAlg::Sha256.digest(bytes));
    out
}

/// A document frozen for the user to see: its size and SHA-256, read in pieces.
pub(crate) fn freeze(
    engine: &Engine,
    path: &Path,
    control: &Arc<JobControl>,
) -> Result<Item, JobError> {
    let out = crate::workspace::hash_file(engine, HashAlg::Sha256, path, control)?;
    let mut sha256 = [0; 32];
    for (i, byte) in sha256.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&out.digest[2 * i..2 * i + 2], 16).map_err(|_| JobError::Worker)?;
    }
    Ok(Item {
        name: path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        bytes: out.bytes,
        sha256,
    })
}

/// Why a key store did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// The file cannot be read, or is not a regular file.
    Unreadable,
    /// The password is wrong, or the file is not a key store.
    WrongPasswordOrFormat,
}

/// The certificates of the key store at `path`, opened with `password`, and whether each can
/// sign now. The private keys are dropped (zeroized) before this returns.
pub(crate) fn open_key_store(
    path: &Path,
    password: &str,
    now: OffsetDateTime,
) -> Result<Vec<Candidate>, OpenError> {
    let meta = std::fs::metadata(path).map_err(|_| OpenError::Unreadable)?;
    if !meta.is_file() || meta.len() > oncl_pki::keystore::MAX_KEY_FILE {
        return Err(OpenError::Unreadable);
    }
    let bytes = std::fs::read(path).map_err(|_| OpenError::Unreadable)?;
    let entries = if oncl_pki::jks::is_jks(&bytes) {
        oncl_pki::jks::load(&bytes, password).map_err(|_| OpenError::WrongPasswordOrFormat)?
    } else {
        oncl_pki::pkcs12::load(&bytes, password).map_err(|_| OpenError::WrongPasswordOrFormat)?
    };
    entries
        .iter()
        .map(|entry| {
            let info = cert_info(&entry.cert);
            let der = entry
                .cert
                .to_der()
                .map_err(|_| OpenError::WrongPasswordOrFormat)?;
            let unsuitable = if now < info.not_before {
                Some(Unsuitable::NotYetValid)
            } else if now > info.not_after {
                Some(Unsuitable::Expired)
            } else if !(info.key_usage.digital_signature || info.key_usage.non_repudiation) {
                Some(Unsuitable::NotForSigning)
            } else {
                None
            };
            Ok(Candidate {
                alias: entry.alias.clone(),
                sha256: Some(sha256_of(&der)),
                subject: info.subject_cn.unwrap_or_default(),
                unsuitable,
            })
        })
        .collect()
}

/// The handshake between the worker and the page: the worker freezes the documents, hands
/// over what it froze, and waits. `Proceed` carries the controller's permission; `Abort`
/// (or a closed channel) ends the operation before any key is touched.
pub(crate) enum Decision {
    Proceed(Box<Approved>),
    Abort,
}

/// How a signing operation ended.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Per document, as the engine reported each: whether it completed, what it wrote and
    /// whether the key was applied.
    Done(BatchView),
    /// The documents the engine froze are not the ones the user agreed to; no key was used.
    DocumentsChanged(Vec<Item>),
    /// Not started or stopped before any key was applied.
    NotApplied(JobError),
}

/// Freezes `documents` (batch capture), reports what was frozen to `frozen`, waits for the
/// decision, and signs each document as `spec` says into `destination`.
///
/// `frozen` runs on the worker and must hand the items to the controller; the controller's
/// answer comes back as the [`Decision`]. The consent must be for exactly these documents, this
/// key and this `spec`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign(
    engine: &Engine,
    guard: &ConsentGuard,
    key_store: &Path,
    alias: &str,
    password: &Zeroizing<String>,
    documents: &[PathBuf],
    spec: &SignSpec,
    destination: &Destination,
    control: &Arc<JobControl>,
    frozen: impl FnOnce(Frozen) -> Decision,
) -> Outcome {
    match sign_inner(
        engine,
        guard,
        key_store,
        alias,
        password,
        documents,
        spec,
        destination,
        control,
        frozen,
    ) {
        Ok(outcome) => outcome,
        Err(e) => Outcome::NotApplied(e),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_inner(
    engine: &Engine,
    guard: &ConsentGuard,
    key_store: &Path,
    alias: &str,
    password: &Zeroizing<String>,
    documents: &[PathBuf],
    spec: &SignSpec,
    destination: &Destination,
    control: &Arc<JobControl>,
    frozen: impl FnOnce(Frozen) -> Decision,
) -> Result<Outcome, JobError> {
    // The key store is read once; listing's certificate is compared with this copy below, and
    // the engine signs with this copy only, so a file swapped later is never used.
    // LT and LTA of CAdES and PAdES cannot be built from nothing, and the engine would only say
    // so after the key was applied: refused here, before anything is read or used.
    let loaded = if spec.needs_material() {
        spec.options.evidence.require()?;
        Some(spec.options.evidence.load()?)
    } else {
        None
    };
    let (ocsp, crls) = loaded.as_ref().map_or((Vec::new(), Vec::new()), |l| {
        (l.ocsp_slices(), l.crl_slices())
    });
    let certificates = loaded.as_ref().map_or(&[][..], |l| &l.certificates[..]);
    let bytes = read_key_store(key_store)?;
    let selector = KeySelector::inline(bytes.to_vec(), Some(alias.to_owned()));
    let key_id = selector.key_id();
    let grant = ExecutionGrant::new([Action::Sign]).with_keys([key_id.clone()]);
    let mut ctx = engine.begin(grant, OperationPolicy::strict_online(), control.clone())?;
    // The copy, the selector's copy and the decrypted key are charged to the operation's
    // budget for as long as the operation lives.
    let _store_memory = ctx
        .resources()
        .reserve_memory(bytes.len() as u64 * 4)
        .map_err(OperationError::from)?;
    let entry_certificate = certificate_of(&bytes, password, alias)?;
    control.set_items(documents.len());
    let payload_limit = if spec.format == SignFormat::Jws {
        oncl_core::jose::MAX_PAYLOAD_BYTES
    } else {
        oncl_core::jose::MAX_CLAIMS_BYTES
    };
    let mut files: Vec<Option<(File, u64)>> = Vec::with_capacity(documents.len());
    let mut payloads: Vec<Option<Vec<u8>>> = Vec::with_capacity(documents.len());
    let mut outputs: Vec<PlannedOutput> = Vec::with_capacity(documents.len());
    let mut claimed = Vec::new();
    for path in documents {
        if spec.signs_a_payload() {
            payloads.push(Some(read_limited(path, payload_limit)?));
            files.push(None);
        } else {
            files.push(Some(open_regular(path)?));
            payloads.push(None);
        }
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        outputs.push(plan_output(
            destination,
            path,
            &spec.output_name(&name),
            &mut claimed,
            &mut ctx,
        )?);
    }
    let ids: Vec<String> = (0..documents.len()).map(|i| format!("doc{i}")).collect();
    let mut items = Vec::with_capacity(documents.len());
    for (((file, payload), planned), id) in files
        .iter_mut()
        .zip(&payloads)
        .zip(outputs.iter_mut())
        .zip(&ids)
    {
        let stage = planned
            .stage
            .take()
            .ok_or(OperationError::InvalidKeySource)?;
        let input = match (file, payload) {
            (Some((file, len)), _) => SignInput::Source(Source::seekable(file, Some(*len))),
            (None, Some(bytes)) => SignInput::Payload(bytes),
            (None, None) => return Err(JobError::Operation(ErrorCode::InvalidInput)),
        };
        let operation = sign_operation(
            spec,
            KeyRequest::new(&selector, Some(password.as_str())),
            input,
            BatchOutput::OwnedStaged(stage),
            ValidationMaterial {
                certificates,
                ocsp: &ocsp,
                crls: &crls,
            },
        )?;
        items.push(BatchItem::new(id, operation));
    }
    let plan = engine
        .capture_batch(items, &mut ctx)
        .map_err(|e| JobError::from(batch_operation_error(e)))?;
    let mut captured = Vec::with_capacity(documents.len());
    for (view, path) in plan.items().zip(documents) {
        let [source] = view.sources else {
            return Err(JobError::Operation(ErrorCode::InvalidInput));
        };
        if view.capture_error.is_some() {
            return Err(JobError::Operation(
                view.capture_error.unwrap_or(ErrorCode::InvalidInput),
            ));
        }
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(source.sha256().as_bytes());
        captured.push(Item {
            name: path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            bytes: source.bytes(),
            sha256,
        });
    }
    let destinations: Vec<PathBuf> = outputs.iter().map(|o| o.destination.clone()).collect();
    let approved = match frozen(Frozen {
        items: captured.clone(),
        outputs: destinations.clone(),
    }) {
        Decision::Proceed(approved) => approved,
        Decision::Abort => return Err(JobError::Cancelled),
    };
    // The consent must be for exactly what was frozen, for this key and for what is made of it.
    if !approved.consent.covers(&captured) || approved.consent.alias() != alias {
        return Ok(Outcome::DocumentsChanged(captured));
    }
    // Compared with the label of the evidence bytes loaded and frozen above, never with a fresh
    // read of the paths: a file swapped after the confirmation (even swapped back) is refused.
    let evidence_label = loaded
        .as_ref()
        .map_or_else(|| spec.options.evidence.label(), |l| l.label.clone());
    if approved.consent.profile() != spec.label_with(&evidence_label) {
        // The user agreed to another format or other options: nothing agreed to stands.
        return Ok(Outcome::NotApplied(JobError::Operation(
            ErrorCode::PermissionDenied,
        )));
    }
    // The certificate shown is the certificate of the bytes the engine will use.
    if approved.consent.certificate() != Some(&entry_certificate) {
        return Ok(Outcome::NotApplied(JobError::StoreChanged));
    }
    let approval = plan
        .authorize(&ctx)
        .map_err(|e| JobError::from(batch_operation_error(e)))?;
    guard.allow(ctx.id().get(), key_id, Action::Sign, documents.len());
    let mut published = vec![false; documents.len()];
    let summary = engine.run_batch_with_outputs(
        plan,
        approval,
        &mut ctx,
        |event: BatchEvent<'_>| {
            if let BatchEvent::ItemStarted { index, .. } = event {
                control.begin_item(index);
            }
        },
        |index, _id, _report, completed| {
            completed.commit(&destinations[index])?;
            published[index] = true;
            Ok(())
        },
    );
    guard.revoke();
    // Cancelled maps to JobError::Cancelled only before any key use; after key use a cancel
    // ends in Done with the per-item applied state.
    let summary = summary.map_err(|e| JobError::from(batch_operation_error(e)))?;
    let names: Vec<String> = captured.iter().map(|c| c.name.clone()).collect();
    let position: Vec<usize> = (0..documents.len()).collect();
    let paths: Vec<Option<PathBuf>> = destinations.into_iter().map(Some).collect();
    let mut view = view_of_summary(
        Family::Sign,
        &names,
        &position,
        &[],
        &paths,
        &published,
        spec.format_name(),
        &summary,
    );
    view.network = spec.uses_network();
    Ok(Outcome::Done(view))
}

/// What the engine froze and where the signatures will go.
pub(crate) struct Frozen {
    pub(crate) items: Vec<Item>,
    pub(crate) outputs: Vec<PathBuf>,
}

/// The key store file, read once into zeroizing memory. The limit caps what is READ (a file
/// swapped in after a size check cannot exceed it), on the opened file, not on its name.
fn read_key_store(path: &Path) -> Result<Zeroizing<Vec<u8>>, JobError> {
    use std::io::Read;
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(JobError::NotRegular);
    }
    let limit = oncl_pki::keystore::MAX_KEY_FILE;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(JobError::Operation(ErrorCode::ContainerLimit));
    }
    Ok(bytes)
}

/// SHA-256 of the certificate stored under `alias` in the key store `bytes`, opened with
/// `password`. The private key is dropped here.
fn certificate_of(bytes: &[u8], password: &str, alias: &str) -> Result<[u8; 32], JobError> {
    let entries = if oncl_pki::jks::is_jks(bytes) {
        oncl_pki::jks::load(bytes, password)
            .map_err(|_| JobError::Operation(ErrorCode::InvalidInput))?
    } else {
        oncl_pki::pkcs12::load(bytes, password)
            .map_err(|_| JobError::Operation(ErrorCode::InvalidInput))?
    };
    let entry = entries
        .iter()
        .find(|e| e.alias == alias)
        .ok_or(JobError::StoreChanged)?;
    let der = entry
        .cert
        .to_der()
        .map_err(|_| JobError::Operation(ErrorCode::InvalidInput))?;
    Ok(sha256_of(&der))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oncl_pki::pkcs12;
    use oncl_pki::testing::{TestCertSpec, issue_cert};

    use super::*;
    use crate::reports::controller::{Headline, Outcome as ItemOutcome};
    use crate::signing::controller::{ActionKind, Controller, Effect, Event};
    use crate::signing::testing::*;
    use crate::workspace::SignOptions;
    use oncl_pki::key::AppliedState;

    /// The format the plain tests sign as: a detached CMS next to each document.
    fn cms() -> SignSpec {
        SignSpec {
            format: SignFormat::Cms,
            options: SignOptions::default(),
        }
    }

    /// The page's side: a controller driven to the confirmation for `shown`, then confirmed
    /// against what the engine froze, or not confirmed at all (`confirm == false`).
    fn page(
        w: &World,
        shown: &[Item],
        captured: &[Item],
        confirm: bool,
        applications: &AtomicUsize,
        guard_probe: &ConsentGuard,
        spec: &SignSpec,
    ) -> Decision {
        assert_eq!(
            applications.load(Ordering::SeqCst),
            0,
            "the key is not applied before the confirmation"
        );
        let _ = guard_probe;
        let mut c = Controller::new("tools", ActionKind::Sign);
        c.dispatch(Event::Documents(shown.to_vec()));
        c.dispatch(Event::Profile(spec.label()));
        c.dispatch(Event::KeyStore(w.store.display().to_string()));
        assert_eq!(
            c.dispatch(Event::PasswordSubmitted(Zeroizing::new(
                PASSWORD.to_owned()
            ))),
            Effect::OpenKeyStore
        );
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        c.dispatch(Event::Unlocked(candidates));
        c.dispatch(Event::CertificateChosen(0));
        if !confirm {
            return Decision::Abort;
        }
        c.dispatch(Event::Frozen(captured));
        c.dispatch(Event::Arm);
        match c.dispatch(Event::Confirm { frozen: captured }) {
            Effect::None => Decision::Proceed(Box::new(c.take_approved().unwrap())),
            Effect::Refused(_) | Effect::OpenKeyStore => Decision::Abort,
        }
    }

    fn run(
        w: &World,
        paths: &[PathBuf],
        shown: &[Item],
        confirm: bool,
    ) -> (Outcome, Arc<ConsentGuard>) {
        run_as(w, paths, shown, confirm, &cms(), &Destination::Beside)
    }

    /// Signs `paths` as `spec` says into `destination`, the page confirming for the spec it
    /// was shown (`confirm`) or not at all.
    fn run_as(
        w: &World,
        paths: &[PathBuf],
        shown: &[Item],
        confirm: bool,
        spec: &SignSpec,
        destination: &Destination,
    ) -> (Outcome, Arc<ConsentGuard>) {
        let (engine, guard) = engine(w);
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        let outcome = sign(
            &engine,
            &guard,
            &w.store,
            &candidates[0].alias,
            &Zeroizing::new(PASSWORD.to_owned()),
            paths,
            spec,
            destination,
            &Arc::new(JobControl::default()),
            |frozen| {
                page(
                    w,
                    shown,
                    &frozen.items,
                    confirm,
                    &AtomicUsize::new(guard.applications()),
                    &guard,
                    spec,
                )
            },
        );
        (outcome, guard)
    }

    fn shown(engine: &Engine, paths: &[PathBuf]) -> Vec<Item> {
        paths
            .iter()
            .map(|p| freeze(engine, p, &Arc::new(JobControl::default())).unwrap())
            .collect()
    }

    fn store_name(n: u8) -> String {
        format!("oncl-{n:032x}")
    }

    /// Only the temporary store's own names are removed from the spool; anything else stays.
    /// And not while another process (the lock holder) is using the spool.
    #[test]
    fn the_spool_cleanup_removes_only_store_entries_and_not_under_another_owner() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let mine = [store_name(1), store_name(2)];
        let keep = [
            "notes.txt",
            "oncl-short",
            "oncl-zz00000000000000000000000000000000",
            "other",
        ];
        std::fs::create_dir(spool.join(&mine[0])).unwrap();
        std::fs::write(spool.join(&mine[0]).join("frozen"), b"x").unwrap();
        std::fs::write(spool.join(&mine[1]), b"x").unwrap();
        for k in keep {
            std::fs::write(spool.join(k), b"x").unwrap();
        }
        // Another owner is alive: its spool is not touched.
        let other = claim_spool(&spool).expect("the first claim");
        let (_engine, guard) = desktop_engine(
            ResourceLimits::default(),
            Arc::new(oncl_pki::http::UreqTransport::with_proxy(
                oncl_pki::http::ProxySetting::None,
            )),
            ExtraTrust::default(),
            &spool,
            Arc::new(now),
        )
        .unwrap();
        assert!(
            mine.iter().all(|n| spool.join(n).exists()),
            "live spool kept"
        );
        drop((_engine, guard));
        drop(other);
        // No owner: the next start cleans its own names and nothing else.
        let (_engine, _guard) = desktop_engine(
            ResourceLimits::default(),
            Arc::new(oncl_pki::http::UreqTransport::with_proxy(
                oncl_pki::http::ProxySetting::None,
            )),
            ExtraTrust::default(),
            &spool,
            Arc::new(now),
        )
        .unwrap();
        assert!(
            mine.iter().all(|n| !spool.join(n).exists()),
            "stale copies removed"
        );
        for k in keep {
            assert!(spool.join(k).exists(), "{k} must stay");
        }
    }

    /// The key store limit caps what is read from the opened file.
    #[test]
    fn the_key_store_read_is_capped_and_zeroizing() {
        let w = world();
        let big = w.dir.path().join("big.p12");
        let file = File::create(&big).unwrap();
        file.set_len(oncl_pki::keystore::MAX_KEY_FILE + 1).unwrap();
        assert_eq!(
            read_key_store(&big).err(),
            Some(JobError::Operation(ErrorCode::ContainerLimit))
        );
        assert!(read_key_store(&w.store).is_ok());
        assert!(matches!(
            read_key_store(w.dir.path()).err(),
            Some(JobError::NotRegular | JobError::Io(_))
        ));
    }

    /// A two-document packet is signed once the user confirmed what the engine froze: both
    /// signature files exist and the key was applied once per document.
    #[test]
    fn a_confirmed_two_item_packet_is_signed_document_by_document() {
        let w = world();
        let paths = documents(&w, &["a.txt", "b.txt"]);
        let (e, _) = engine(&w);
        let before = shown(&e, &paths);
        let (outcome, guard) = run(&w, &paths, &before, true);
        let Outcome::Done(done) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(done.items.len(), 2);
        assert_eq!(done.headline(), Headline::AllSucceeded { total: 2 });
        for (item, path) in done.items.iter().zip(&paths) {
            assert!(
                matches!(item.outcome, ItemOutcome::Completed(_)),
                "{item:?}"
            );
            assert_eq!(item.applied, AppliedState::Applied);
            let sig = item.output.as_ref().expect("a signature file");
            assert_eq!(
                sig.file_name().unwrap(),
                &format!("{}.p7s", path.file_name().unwrap().to_string_lossy())[..]
            );
            assert!(std::fs::metadata(sig).unwrap().len() > 100);
        }
        assert_eq!(guard.applications(), 2, "once per document");
    }

    /// An evidence file swapped between the confirmation and the run: the runner compares the
    /// consent with the digests of the bytes it LOADED, never with a fresh read of the path.
    /// Case 1: B is on disk when the evidence is loaded. Case 2 (A->B->A): B is loaded, then A
    /// is put back before the consent check, so a re-read would see A and match. Both are
    /// refused before any key use (0 applications) and nothing is written.
    #[test]
    fn an_evidence_file_swapped_after_the_confirmation_is_refused_before_any_key_use() {
        for swap_back in [false, true] {
            let w = world();
            let paths = documents(&w, &["a.txt"]);
            let evidence = evidence_files(&w);
            let file = evidence.ocsp[0].clone();
            let original = std::fs::read(&file).unwrap();
            let spec = SignSpec {
                format: SignFormat::Cades(crate::workspace::Level::Lt),
                options: SignOptions {
                    evidence,
                    ..SignOptions::default()
                },
            };
            // The page confirmed this label (the files as they were: A).
            let agreed = spec.label();
            let (engine, guard) = engine(&w);
            let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
            let shown = shown(&engine, &paths);
            // B replaces A before the run loads the evidence.
            let mut swapped = original.clone();
            swapped.push(0);
            std::fs::write(&file, &swapped).unwrap();
            let outcome = sign(
                &engine,
                &guard,
                &w.store,
                &candidates[0].alias,
                &Zeroizing::new(PASSWORD.to_owned()),
                &paths,
                &spec,
                &Destination::Beside,
                &Arc::new(JobControl::default()),
                |frozen| {
                    if swap_back {
                        // The evidence was loaded (B) before this callback; A is back now.
                        std::fs::write(&file, &original).unwrap();
                    }
                    let mut c = Controller::new("tools", ActionKind::Sign);
                    c.dispatch(Event::Documents(shown.clone()));
                    c.dispatch(Event::Profile(agreed.clone()));
                    c.dispatch(Event::KeyStore(w.store.display().to_string()));
                    c.dispatch(Event::PasswordSubmitted(Zeroizing::new(
                        PASSWORD.to_owned(),
                    )));
                    c.dispatch(Event::Unlocked(candidates.clone()));
                    c.dispatch(Event::CertificateChosen(0));
                    c.dispatch(Event::Frozen(&frozen.items));
                    c.dispatch(Event::Arm);
                    match c.dispatch(Event::Confirm {
                        frozen: &frozen.items,
                    }) {
                        Effect::None => Decision::Proceed(Box::new(c.take_approved().unwrap())),
                        _ => Decision::Abort,
                    }
                },
            );
            assert!(
                matches!(
                    outcome,
                    Outcome::NotApplied(JobError::Operation(ErrorCode::PermissionDenied))
                ),
                "swap_back={swap_back}: {outcome:?}"
            );
            assert_eq!(guard.applications(), 0, "swap_back={swap_back}");
            assert!(!w.dir.path().join("a.txt.p7s").exists());
        }
    }

    /// The results go where the user said: one folder, not next to the documents; and a
    /// consent for another format than the one that is run is refused by the runner itself,
    /// before any key use.
    #[test]
    fn the_destination_is_honoured_and_a_consent_for_another_format_is_refused() {
        let w = world();
        let paths = documents(&w, &["a.txt"]);
        let out = w.dir.path().join("results");
        std::fs::create_dir(&out).unwrap();
        let (e, _) = engine(&w);
        let before = shown(&e, &paths);
        let (outcome, guard) = run_as(
            &w,
            &paths,
            &before,
            true,
            &cms(),
            &Destination::Folder(out.clone()),
        );
        let Outcome::Done(done) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(
            done.items[0].output.as_deref(),
            Some(out.join("a.txt.p7s").as_path())
        );
        assert!(out.join("a.txt.p7s").exists());
        assert!(
            !w.dir.path().join("a.txt.p7s").exists(),
            "not beside the document"
        );
        assert_eq!(guard.applications(), 1);
        // The page agreed to a detached CMS; the engine is asked for an attached one.
        let attached = SignSpec {
            format: SignFormat::Cms,
            options: SignOptions {
                attached: true,
                ..SignOptions::default()
            },
        };
        let (engine, guard) = engine(&w);
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        let outcome = sign(
            &engine,
            &guard,
            &w.store,
            &candidates[0].alias,
            &Zeroizing::new(PASSWORD.to_owned()),
            &paths,
            &attached,
            &Destination::Beside,
            &Arc::new(JobControl::default()),
            |frozen| confirmed(&w, &before, &frozen),
        );
        assert!(
            matches!(
                outcome,
                Outcome::NotApplied(JobError::Operation(ErrorCode::PermissionDenied))
            ),
            "{outcome:?}"
        );
        assert_eq!(guard.applications(), 0);
        assert!(!w.dir.path().join("a.txt.p7m").exists());
    }

    /// Without the confirmation no key is applied and nothing is written.
    #[test]
    fn nothing_is_applied_without_the_confirmation() {
        let w = world();
        let paths = documents(&w, &["a.txt", "b.txt"]);
        let (e, _) = engine(&w);
        let before = shown(&e, &paths);
        let (outcome, guard) = run(&w, &paths, &before, false);
        assert!(
            matches!(outcome, Outcome::NotApplied(JobError::Cancelled)),
            "{outcome:?}"
        );
        assert_eq!(guard.applications(), 0);
        assert!(paths.iter().all(|p| !p.with_extension("txt.p7s").exists()));
    }

    /// A document that changed after the user was shown it: the engine's frozen copy is not
    /// what they agreed to, the page cannot confirm, and the key is never applied.
    #[test]
    fn a_document_changed_after_it_was_shown_is_not_signed() {
        let w = world();
        let paths = documents(&w, &["a.txt", "b.txt"]);
        let (e, _) = engine(&w);
        let before = shown(&e, &paths);
        std::fs::write(&paths[1], "other bytes now").unwrap();
        let (outcome, guard) = run(&w, &paths, &before, true);
        assert!(
            matches!(outcome, Outcome::NotApplied(JobError::Cancelled)),
            "{outcome:?}"
        );
        assert_eq!(guard.applications(), 0);
    }

    /// The same key under the same alias with another certificate, written over the key store.
    fn swap_key_store(w: &World) {
        let mut spec = TestCertSpec::from_cert(&w.leaf.cert);
        spec.serial = vec![0x71, 4, 99];
        let other = issue_cert(&w.root_entry, spec);
        let bytes = pkcs12::write(
            &[pkcs12::WriteEntry {
                alias: w.leaf.alias.clone(),
                pkcs8_der: w.leaf.key.to_pkcs8_der().unwrap().to_vec(),
                cert_der: Some(other.to_der().unwrap()),
            }],
            &[],
            PASSWORD,
            &pkcs12::WriteOptions::default(),
            &mut |b| b.fill(0x5a),
        )
        .unwrap();
        std::fs::write(&w.store, bytes).unwrap();
    }

    fn confirmed(w: &World, shown: &[Item], frozen: &Frozen) -> Decision {
        page(
            w,
            shown,
            &frozen.items,
            true,
            &AtomicUsize::new(0),
            &ConsentGuard::default(),
            &cms(),
        )
    }

    /// The certificate the user was shown is the certificate that signs: a key store replaced
    /// between the listing and the signing is refused and no key is applied.
    #[test]
    fn a_swapped_key_store_is_refused_before_any_key_use() {
        let w = world();
        let paths = documents(&w, &["a.txt"]);
        let (engine, guard) = engine(&w);
        let before = shown(&engine, &paths);
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        swap_key_store(&w);
        let swapped = open_key_store(&w.store, PASSWORD, now()).unwrap();
        assert_ne!(
            candidates[0].sha256, swapped[0].sha256,
            "the swap changed the certificate"
        );
        // The page confirms the certificate it listed before the swap.
        let outcome = sign(
            &engine,
            &guard,
            &w.store,
            &candidates[0].alias,
            &Zeroizing::new(PASSWORD.to_owned()),
            &paths,
            &cms(),
            &Destination::Beside,
            &Arc::new(JobControl::default()),
            |frozen| {
                let mut c = Controller::new("tools", ActionKind::Sign);
                c.dispatch(Event::Documents(before.clone()));
                c.dispatch(Event::Profile(cms().label()));
                c.dispatch(Event::KeyStore(w.store.display().to_string()));
                c.dispatch(Event::PasswordSubmitted(Zeroizing::new(
                    PASSWORD.to_owned(),
                )));
                c.dispatch(Event::Unlocked(candidates.clone()));
                c.dispatch(Event::CertificateChosen(0));
                c.dispatch(Event::Frozen(&frozen.items));
                c.dispatch(Event::Arm);
                c.dispatch(Event::Confirm {
                    frozen: &frozen.items,
                });
                Decision::Proceed(Box::new(c.take_approved().unwrap()))
            },
        );
        assert!(
            matches!(outcome, Outcome::NotApplied(JobError::StoreChanged)),
            "{outcome:?}"
        );
        assert_eq!(guard.applications(), 0);
        assert!(!paths[0].with_extension("txt.p7s").exists());
    }

    /// An existing signature file is told before anything is frozen or asked: no key use.
    #[test]
    fn an_existing_signature_file_is_refused_before_any_key_use() {
        let w = world();
        let paths = documents(&w, &["a.txt", "b.txt"]);
        std::fs::write(w.dir.path().join("b.txt.p7s"), b"mine").unwrap();
        let (engine, _) = engine(&w);
        let before = shown(&engine, &paths);
        let (outcome, guard) = run(&w, &paths, &before, true);
        assert!(
            matches!(outcome, Outcome::NotApplied(JobError::DestinationExists)),
            "{outcome:?}"
        );
        assert_eq!(guard.applications(), 0);
        assert_eq!(
            std::fs::read(w.dir.path().join("b.txt.p7s")).unwrap(),
            b"mine"
        );
    }

    /// The second destination appears after the preflight: the first document is signed and
    /// published, the second is refused after its key use and says so, nothing is replaced.
    #[test]
    fn a_destination_that_appears_late_fails_one_item_honestly() {
        let w = world();
        let paths = documents(&w, &["a.txt", "b.txt"]);
        let (engine, guard) = engine(&w);
        let before = shown(&engine, &paths);
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        let late = w.dir.path().join("b.txt.p7s");
        let outcome = sign(
            &engine,
            &guard,
            &w.store,
            &candidates[0].alias,
            &Zeroizing::new(PASSWORD.to_owned()),
            &paths,
            &cms(),
            &Destination::Beside,
            &Arc::new(JobControl::default()),
            |frozen| {
                std::fs::write(&late, b"appeared").unwrap();
                confirmed(&w, &before, &frozen)
            },
        );
        let Outcome::Done(done) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(matches!(done.items[0].outcome, ItemOutcome::Completed(_)));
        assert!(done.items[0].output.is_some());
        assert!(
            matches!(done.items[1].outcome, ItemOutcome::Failed(_)),
            "{:?}",
            done.items[1]
        );
        assert!(done.items[1].output.is_none());
        assert_eq!(
            done.items[1].applied,
            AppliedState::Applied,
            "the key was used for it"
        );
        // A failure after the key was applied stops the batch (the engine's own rule): the
        // headline says it was stopped, never that everything was done.
        assert_eq!(
            done.headline(),
            Headline::Stopped {
                completed: 1,
                total: 2
            },
            "a batch with a failed item is never completed-all"
        );
        assert_eq!(guard.applications(), 2);
        assert_eq!(
            std::fs::read(&late).unwrap(),
            b"appeared",
            "nothing was replaced"
        );
    }

    /// A consent for other documents than the frozen ones is refused by the runner itself,
    /// whatever the page did.
    #[test]
    fn a_consent_for_other_documents_is_refused_by_the_runner() {
        let w = world();
        let paths = documents(&w, &["a.txt"]);
        let (engine, guard) = engine(&w);
        let before = shown(&engine, &paths);
        let mut other = before.clone();
        other[0].sha256 = [1; 32];
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        let outcome = sign(
            &engine,
            &guard,
            &w.store,
            &candidates[0].alias,
            &Zeroizing::new(PASSWORD.to_owned()),
            &paths,
            &cms(),
            &Destination::Beside,
            &Arc::new(JobControl::default()),
            |_frozen| {
                let mut c = Controller::new("tools", ActionKind::Sign);
                c.dispatch(Event::Documents(other.clone()));
                c.dispatch(Event::Profile(cms().label()));
                c.dispatch(Event::KeyStore(w.store.display().to_string()));
                c.dispatch(Event::PasswordSubmitted(Zeroizing::new(
                    PASSWORD.to_owned(),
                )));
                c.dispatch(Event::Unlocked(candidates.clone()));
                c.dispatch(Event::CertificateChosen(0));
                // The page confirms what it showed, not what the engine froze.
                c.dispatch(Event::Frozen(&other));
                c.dispatch(Event::Arm);
                c.dispatch(Event::Confirm { frozen: &other });
                Decision::Proceed(Box::new(c.take_approved().unwrap()))
            },
        );
        assert!(
            matches!(outcome, Outcome::DocumentsChanged(_)),
            "{outcome:?}"
        );
        assert_eq!(guard.applications(), 0);
    }

    /// The guard applies a key for one operation and one key only.
    #[test]
    fn the_guard_refuses_what_was_not_consented() {
        let w = world();
        let paths = documents(&w, &["a.txt"]);
        let (engine, guard) = engine(&w);
        let selector = KeySelector::file(&w.store, None).unwrap();
        let ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign]),
                OperationPolicy::strict_online(),
                Arc::new(JobControl::default()),
            )
            .unwrap();
        let event = KeyUseEvent::new(&ctx, selector.key_id(), Action::Sign);
        assert!(guard.before_use(&event).is_err(), "no grant at all");
        guard.allow(ctx.id().get(), selector.key_id(), Action::Sign, 1);
        assert!(guard.before_use(&event).is_ok());
        assert!(guard.before_use(&event).is_err(), "one use per grant");
        guard.allow(ctx.id().get() + 1, selector.key_id(), Action::Sign, 1);
        assert!(guard.before_use(&event).is_err(), "another operation");
        drop(paths);
    }

    #[test]
    fn a_wrong_password_and_an_unsuitable_certificate_are_told_before_anything_runs() {
        let w = world();
        assert_eq!(
            open_key_store(&w.store, "wrong", now()),
            Err(OpenError::WrongPasswordOrFormat)
        );
        assert_eq!(
            open_key_store(&w.dir.path().join("missing.p12"), PASSWORD, now()),
            Err(OpenError::Unreadable)
        );
        let later = now() + time::Duration::days(365 * 300);
        let candidates = open_key_store(&w.store, PASSWORD, later).unwrap();
        assert_eq!(candidates[0].unsuitable, Some(Unsuitable::Expired));
        let earlier = now() - time::Duration::days(365 * 300);
        let candidates = open_key_store(&w.store, PASSWORD, earlier).unwrap();
        assert_eq!(candidates[0].unsuitable, Some(Unsuitable::NotYetValid));
    }
}
