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
use oncl_core::batch::{BatchEvent, BatchItem, BatchOperation, BatchOutcome, BatchOutput};
use oncl_core::keys::{KeyId, KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard};
use oncl_core::keys::{KeyUseOutcome, KeyUseReceipt};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationError, OperationPolicy,
    SignRequest, ValidationServices,
};
use oncl_pki::http::HttpTransport;
use oncl_pki::info::cert_info;
use oncl_pki::io::{Source, TemporaryStore};
use oncl_pki::key::{AppliedState, HashAlg};
use oncl_pki::pkix::CaSet;
use oncl_pki::resource::ResourceLimits;
use oncl_pki::validation::NetworkPolicy;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::controller::{Approved, Candidate, Item, Unsuitable};
use crate::workspace::{JobControl, JobError};

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
    let guard = Arc::new(ConsentGuard::default());
    let mut anchors = CaSet::nca_production().certs().to_vec();
    anchors.extend(extra.anchors);
    let origins = NCA_ORIGINS
        .iter()
        .map(|o| (*o).to_owned())
        .chain(extra.origins);
    let network = NetworkPolicy::only_endpoints(origins)
        .map_err(|_| oncl_pki::resource::ProcessingError::InvalidInput("PKI endpoint"))?;
    std::fs::create_dir_all(spool).map_err(oncl_pki::resource::ProcessingError::from)?;
    remove_stale_spool(spool);
    let store = TemporaryStore::new(spool)?;
    let services = EngineServices::hash_only(limits)
        .with_keys(Arc::new(KeySources::new()), guard.clone())
        .with_validation(ValidationServices::new(
            CaSet::new(anchors),
            Vec::new(),
            http,
            network,
            clock,
        ))
        .with_temporary_store(store);
    Ok((Engine::new(services)?, guard))
}

/// Frozen copies and staged outputs of a run that died stay in the spool this program owns:
/// they are removed at start (no operation is running yet).
fn remove_stale_spool(spool: &Path) {
    let Ok(entries) = std::fs::read_dir(spool) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("oncl-") {
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
                sha256: sha256_of(&der),
                subject: info.subject_cn.unwrap_or_default(),
                unsuitable,
            })
        })
        .collect()
}

/// What happened to one document.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Signed {
    pub name: String,
    /// The signature file, if it was written.
    pub output: Option<PathBuf>,
    pub error: Option<ErrorCode>,
    /// Whether the key was applied for this document, whatever came after.
    pub applied: AppliedState,
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
    /// Per document.
    Done(Vec<Signed>),
    /// The documents the engine froze are not the ones the user agreed to; no key was used.
    DocumentsChanged(Vec<Item>),
    /// Not started or stopped before any key was applied.
    NotApplied(JobError),
}

/// Freezes `documents` (batch capture), reports what was frozen to `frozen`, waits for the
/// decision, and signs each document into `<name>.p7s` next to it.
///
/// `frozen` runs on the worker and must hand the items to the controller; the controller's
/// answer comes back as the [`Decision`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign(
    engine: &Engine,
    guard: &ConsentGuard,
    key_store: &Path,
    alias: &str,
    password: &Zeroizing<String>,
    documents: &[PathBuf],
    control: &Arc<JobControl>,
    frozen: impl FnOnce(Frozen) -> Decision,
) -> Outcome {
    match sign_inner(
        engine, guard, key_store, alias, password, documents, control, frozen,
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
    control: &Arc<JobControl>,
    frozen: impl FnOnce(Frozen) -> Decision,
) -> Result<Outcome, JobError> {
    // The key store is read once; listing's certificate is compared with this copy below, and
    // the engine signs with this copy only, so a file swapped later is never used.
    let bytes = read_key_store(key_store)?;
    let selector = KeySelector::inline(bytes.to_vec(), Some(alias.to_owned()));
    let entry_certificate = certificate_of(&bytes, password, alias)?;
    let key_id = selector.key_id();
    let grant = ExecutionGrant::new([Action::Sign]).with_keys([key_id.clone()]);
    let mut ctx = engine.begin(grant, OperationPolicy::strict_online(), control.clone())?;
    let mut files = Vec::with_capacity(documents.len());
    let mut stages = Vec::with_capacity(documents.len());
    let mut destinations = Vec::with_capacity(documents.len());
    for path in documents {
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(JobError::NotRegular);
        }
        let len = file.metadata()?.len();
        control.set_total(len.max(1));
        files.push((file, len));
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let store = TemporaryStore::new(parent).map_err(OperationError::from)?;
        stages.push(Some(
            store.stage(ctx.resources()).map_err(OperationError::from)?,
        ));
        let mut name = path.as_os_str().to_owned();
        name.push(".p7s");
        let destination = PathBuf::from(name);
        preflight_destination(&destination, parent)?;
        destinations.push(destination);
    }
    let ids: Vec<String> = (0..documents.len()).map(|i| format!("doc{i}")).collect();
    let mut items = Vec::with_capacity(documents.len());
    for (((file, len), stage), id) in files.iter_mut().zip(stages.iter_mut()).zip(&ids) {
        items.push(BatchItem::new(
            id,
            BatchOperation::Sign {
                request: SignRequest::cms_create(
                    vec![KeyRequest::new(&selector, Some(password.as_str()))],
                    false,
                ),
                input: Source::seekable(file, Some(*len)),
                output: BatchOutput::OwnedStaged(
                    stage.take().ok_or(OperationError::InvalidKeySource)?,
                ),
            },
        ));
    }
    let plan = engine
        .capture_batch(items, &mut ctx)
        .map_err(|e| JobError::from(operation_of(e)))?;
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
    let approved = match frozen(Frozen {
        items: captured.clone(),
        outputs: destinations.clone(),
    }) {
        Decision::Proceed(approved) => approved,
        Decision::Abort => return Err(JobError::Cancelled),
    };
    // The consent must be for exactly what was frozen, and for this key.
    if !approved.consent.covers(&captured) || approved.consent.alias() != alias {
        return Ok(Outcome::DocumentsChanged(captured));
    }
    // The certificate shown is the certificate of the bytes the engine will use.
    if approved.consent.certificate() != &entry_certificate {
        return Ok(Outcome::NotApplied(JobError::StoreChanged));
    }
    let approval = plan
        .authorize(&ctx)
        .map_err(|e| JobError::from(operation_of(e)))?;
    guard.allow(ctx.id().get(), key_id, Action::Sign, documents.len());
    let mut published = vec![false; documents.len()];
    let summary = engine.run_batch_with_outputs(
        plan,
        approval,
        &mut ctx,
        |_: BatchEvent<'_>| {},
        |index, _id, _report, completed| {
            completed.commit(&destinations[index])?;
            published[index] = true;
            Ok(())
        },
    );
    guard.revoke();
    let summary = summary.map_err(|e| JobError::from(operation_of(e)))?;
    let mut done = Vec::with_capacity(documents.len());
    for (i, result) in summary.results().iter().enumerate() {
        let name = captured.get(i).map(|c| c.name.clone()).unwrap_or_default();
        let error = match result.outcome() {
            BatchOutcome::Completed(_) => None,
            BatchOutcome::Failed(e) => Some(e.code()),
            BatchOutcome::NotRun => Some(ErrorCode::Cancelled),
        };
        done.push(Signed {
            name,
            output: published
                .get(i)
                .copied()
                .unwrap_or(false)
                .then(|| destinations[i].clone()),
            error,
            applied: result.applied_state(),
        });
    }
    Ok(Outcome::Done(done))
}

/// What the engine froze and where the signatures will go.
pub(crate) struct Frozen {
    pub(crate) items: Vec<Item>,
    pub(crate) outputs: Vec<PathBuf>,
}

fn read_key_store(path: &Path) -> Result<Zeroizing<Vec<u8>>, JobError> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(JobError::NotRegular);
    }
    if meta.len() > oncl_pki::keystore::MAX_KEY_FILE {
        return Err(JobError::Operation(ErrorCode::ContainerLimit));
    }
    Ok(Zeroizing::new(std::fs::read(path)?))
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

/// Before any key is used: the signature file must not exist, and the folder must be able to
/// publish one without replacing anything (publication is an exclusive hard link).
fn preflight_destination(destination: &Path, parent: &Path) -> Result<(), JobError> {
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(JobError::DestinationExists);
    }
    let id = std::process::id();
    let a = parent.join(format!(".oncl-probe-{id}-a"));
    let b = parent.join(format!(".oncl-probe-{id}-b"));
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    std::fs::write(&a, b"")?;
    let linked = std::fs::hard_link(&a, &b);
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    linked.map_err(|_| JobError::NoLinks)
}

fn operation_of(e: oncl_core::batch::BatchError) -> OperationError {
    match e {
        oncl_core::batch::BatchError::Operation(e) => e,
        oncl_core::batch::BatchError::ConsentMismatch => OperationError::PermissionDenied,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use der::asn1::{ObjectIdentifier, OctetString};
    use oncl_pki::keygen::{self, KeySpec};
    use oncl_pki::ocsp::MockOcsp;
    use oncl_pki::pkcs12::{self, KeyEntry};
    use oncl_pki::testing::{TestCertSpec, issue_cert};
    use x509_cert::ext::Extension;

    use super::*;
    use crate::signing::controller::{ActionKind, Controller, Effect, Event};

    const NOW: i64 = 1_793_620_800;
    const ORIGIN: &str = "http://127.0.0.1:9";
    const PASSWORD: &str = "synthetic loopback password";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW).unwrap()
    }

    fn fixture(name: &str) -> KeyEntry {
        let f = oncl_testkit::synthetic(name);
        pkcs12::load(&oncl_testkit::read(f.path), &f.password)
            .unwrap()
            .remove(0)
    }

    fn short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(body);
        out
    }

    fn aia(url: &str) -> Extension {
        let mut access = vec![6, 8, 43, 6, 1, 5, 5, 7, 48, 1];
        access.extend(short_tlv(0x86, url.as_bytes()));
        Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
            critical: false,
            extn_value: OctetString::new(short_tlv(0x30, &short_tlv(0x30, &access))).unwrap(),
        }
    }

    fn strip(spec: &mut TestCertSpec) {
        spec.extensions.retain(|e| {
            !matches!(
                e.extn_id.to_string().as_str(),
                "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        });
    }

    /// A synthetic root, an OCSP responder and a signing key under it, all made here.
    struct World {
        dir: tempfile::TempDir,
        root_entry: KeyEntry,
        leaf: KeyEntry,
        root: oncl_pki::cert::Certificate,
        ocsp: Arc<MockOcsp>,
        store: PathBuf,
    }

    fn world() -> World {
        let mut root = fixture("user-rsa-sign");
        root.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
        let mut spec = TestCertSpec::from_cert(
            &oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
        );
        strip(&mut spec);
        spec.public_key = root.key.public_key().to_spki();
        spec.serial = vec![0x71, 4, 1];
        root.cert = issue_cert(&root, spec.clone());
        root.cert = issue_cert(&root, spec);
        let mut responder = fixture("user-rsa-sign");
        responder.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
        let mut spec = TestCertSpec::from_cert(&fixture("ocsp-gost2015").cert);
        strip(&mut spec);
        spec.public_key = responder.key.public_key().to_spki();
        spec.serial = vec![0x71, 4, 3];
        responder.cert = issue_cert(&root, spec);
        let mut leaf = fixture("user-rsa-sign");
        let mut spec = TestCertSpec::from_cert(&leaf.cert);
        strip(&mut spec);
        spec.serial = vec![0x71, 4, 10];
        spec.extensions.push(aia(&format!("{ORIGIN}/ocsp")));
        leaf.cert = issue_cert(&root, spec);
        let dir = tempfile::tempdir().unwrap();
        let bytes = pkcs12::write(
            &[pkcs12::WriteEntry {
                alias: leaf.alias.clone(),
                pkcs8_der: leaf.key.to_pkcs8_der().unwrap().to_vec(),
                cert_der: Some(leaf.cert.to_der().unwrap()),
            }],
            &[],
            PASSWORD,
            &pkcs12::WriteOptions::default(),
            &mut |b| b.fill(0x5a),
        )
        .unwrap();
        let store = dir.path().join("key.p12");
        std::fs::write(&store, bytes).unwrap();
        World {
            dir,
            root_entry: root.clone(),
            leaf,
            root: root.cert,
            ocsp: Arc::new(MockOcsp::new(responder).with_now(now())),
            store,
        }
    }

    fn engine(w: &World) -> (Engine, Arc<ConsentGuard>) {
        desktop_engine(
            ResourceLimits::default(),
            w.ocsp.clone(),
            ExtraTrust {
                anchors: vec![w.root.clone()],
                origins: vec![ORIGIN.to_owned()],
            },
            &w.dir.path().join("spool"),
            Arc::new(now),
        )
        .unwrap()
    }

    fn documents(w: &World, names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|n| {
                let p = w.dir.path().join(n);
                std::fs::write(&p, format!("the document {n}")).unwrap();
                p
            })
            .collect()
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
    ) -> Decision {
        assert_eq!(
            applications.load(Ordering::SeqCst),
            0,
            "the key is not applied before the confirmation"
        );
        let _ = guard_probe;
        let mut c = Controller::new("tools", ActionKind::Sign);
        c.dispatch(Event::Documents(shown.to_vec()));
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
        let (engine, guard) = engine(w);
        let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
        let outcome = sign(
            &engine,
            &guard,
            &w.store,
            &candidates[0].alias,
            &Zeroizing::new(PASSWORD.to_owned()),
            paths,
            &Arc::new(JobControl::default()),
            |frozen| {
                page(
                    w,
                    shown,
                    &frozen.items,
                    confirm,
                    &AtomicUsize::new(guard.applications()),
                    &guard,
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
        assert_eq!(done.len(), 2);
        for (item, path) in done.iter().zip(&paths) {
            assert_eq!(item.error, None, "{item:?}");
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
            &Arc::new(JobControl::default()),
            |frozen| {
                let mut c = Controller::new("tools", ActionKind::Sign);
                c.dispatch(Event::Documents(before.clone()));
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
            &Arc::new(JobControl::default()),
            |frozen| {
                std::fs::write(&late, b"appeared").unwrap();
                confirmed(&w, &before, &frozen)
            },
        );
        let Outcome::Done(done) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(done[0].error, None);
        assert!(done[0].output.is_some());
        assert!(done[1].error.is_some(), "{:?}", done[1]);
        assert!(done[1].output.is_none());
        assert_eq!(
            done[1].applied,
            AppliedState::Applied,
            "the key was used for it"
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
            &Arc::new(JobControl::default()),
            |_frozen| {
                let mut c = Controller::new("tools", ActionKind::Sign);
                c.dispatch(Event::Documents(other.clone()));
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
