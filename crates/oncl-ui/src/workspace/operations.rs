//! The operations of the manual tools: which request the SDK is given for what the user chose,
//! where the results are written, and how the SDK's structured reports become the owned views
//! the page shows ([`crate::reports`]). Nothing here touches Slint, and nothing checks a
//! signature again: the views hold what the engine decided.
//!
//! Families reached from the tools window: signing (CMS and CAdES B/T/LT/LTA, XML and XAdES,
//! WS-Security, PDF and PAdES, JWS and JWT) in [`SignSpec`]; verifying all of them, extending
//! CAdES/XAdES/PAdES evidence, extracting the content of a signature container and the
//! timestamp tools (acquire and verify) in [`ToolSpec`]; hashing and the structural
//! inspection of certificates, signature files and key stores are in [`super::jobs`].
//!
//! Encrypt and decrypt are deliberately not here: the Kazakhstani GOST encryption backend
//! (G01/G02) is not available, and no RSA-only substitute is offered. There is no screen,
//! switch or placeholder for them.
//!
//! Every document goes through the SDK's batch ([`Engine::capture_batch`]): its bytes are
//! frozen first, the batch is approved by the host (for a key, after the user's confirmation;
//! for the tools that use none, by the button that names the action) and then run, one
//! document after another, with the results of each kept apart: one bad document does not
//! hide the others, and what is not run is said not to have run.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oncl_core::batch::{
    BatchEvent, BatchItem, BatchJoseOperation, BatchOperation, BatchOutcome, BatchOutput,
    BatchReport, BatchStop, BatchSummary,
};
use oncl_core::jose::{
    JoseProfile, JwsSerialization, JwsVerificationReport, JwsVerifyRequest, JwtValidationPolicy,
};
use oncl_core::keys::KeyRequest;
use oncl_core::{
    Action, Engine, ErrorCode, ExecutionGrant, ExtendRequest, OperationContext, OperationError,
    OperationPolicy, OperationReport, SignRequest, StampRequest, StampVerifyRequest,
    TimestampReport, VerificationReport, VerifyRequest,
};
use oncl_pdf::{PdfLimits, PdfSignProfile};
use oncl_pki::cms::ades::ValidationMaterial;
use oncl_pki::evidence::{AdesLevel, EvidenceLimits};
use oncl_pki::http::NonceSpec;
use oncl_pki::io::{Source, StagedArtifact, TemporaryStore};
use oncl_pki::key::{AppliedState, HashAlg};
use oncl_pki::tsp::{TsaProfile, TsaSpec};
use oncl_pki::validation::{SignerValidation, ValidationPolicy};
use oncl_xml::wsse::{SourceWsseSignProfile, WsseVerifyProfile};
use oncl_xml::{XmlSignMode, XmlSignProfile};

use super::controller::{JobControl, JobError, MissingField};
use super::evidence::Evidence;
use crate::reports::controller::{
    BatchView, Check, ClaimsView, Detail, Family, ItemView, Note, Outcome, SignerView, StampCheck,
    StampView, Stop, VerificationView, combine_verdicts,
};

/// The level of an AdES format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    B,
    T,
    Lt,
    Lta,
}

impl Level {
    pub(crate) fn sdk(self) -> AdesLevel {
        match self {
            Level::B => AdesLevel::B,
            Level::T => AdesLevel::T,
            Level::Lt => AdesLevel::Lt,
            Level::Lta => AdesLevel::Lta,
        }
    }

    /// The level as the formats' names write it: `B`, `T`, `LT`, `LTA`.
    fn title(self) -> &'static str {
        match self {
            Level::B => "B",
            Level::T => "T",
            Level::Lt => "LT",
            Level::Lta => "LTA",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Level::B => "b",
            Level::T => "t",
            Level::Lt => "lt",
            Level::Lta => "lta",
        }
    }
}

/// What a signature is made as. The family and the level are the user's two choices; the
/// plain formats (CMS, XMLDSig, PDF) have no level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignFormat {
    Cms,
    Cades(Level),
    Xml,
    Xades(Level),
    Wsse,
    Pdf,
    Pades(Level),
    Jws,
    Jwt,
}

/// What the user chose besides the format: the options that are rarely needed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SignOptions {
    /// CMS and CAdES: the content inside the signature instead of beside it.
    pub(crate) attached: bool,
    /// XML, XAdES and WS-Security: add a signature to a document that is signed already.
    pub(crate) add: bool,
    /// XML and XAdES: the element to sign, the element that gets the signature, and the
    /// signature's own identity, as unique XML IDs. Empty: the format's default.
    pub(crate) target: String,
    pub(crate) parent: String,
    pub(crate) signature_id: String,
    /// CAdES and PAdES LT/LTA: the public material their evidence is built from.
    pub(crate) evidence: Evidence,
}

/// What is made of each document: the whole of what the user agrees to besides the documents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignSpec {
    pub(crate) format: SignFormat,
    pub(crate) options: SignOptions,
}

impl SignSpec {
    /// The spec as one label, which the consent binds: another format or other options are
    /// another thing to agree to.
    pub(crate) fn label(&self) -> String {
        self.label_with(&self.options.evidence.label())
    }

    /// As [`SignSpec::label`] with the evidence label given: the runner passes the label of the
    /// evidence bytes it actually loaded, and never re-reads the paths.
    pub(crate) fn label_with(&self, evidence_label: &str) -> String {
        let name = match self.format {
            SignFormat::Cms => "cms".to_owned(),
            SignFormat::Cades(l) => format!("cades-{}", l.name()),
            SignFormat::Xml => "xml".to_owned(),
            SignFormat::Xades(l) => format!("xades-{}", l.name()),
            SignFormat::Wsse => "wsse".to_owned(),
            SignFormat::Pdf => "pdf".to_owned(),
            SignFormat::Pades(l) => format!("pades-{}", l.name()),
            SignFormat::Jws => "jws".to_owned(),
            SignFormat::Jwt => "jwt".to_owned(),
        };
        let o = &self.options;
        format!(
            "{name};attached={};add={};target={};parent={};id={};{}",
            o.attached, o.add, o.target, o.parent, o.signature_id, evidence_label
        )
    }

    /// Whether signing in this format reaches a network service: the levels with a time stamp
    /// (T, LT, LTA).
    pub(crate) fn uses_network(&self) -> bool {
        matches!(
            self.format,
            SignFormat::Cades(Level::T | Level::Lt | Level::Lta)
                | SignFormat::Xades(Level::T | Level::Lt | Level::Lta)
                | SignFormat::Pades(Level::T | Level::Lt | Level::Lta)
        )
    }
    /// Whether the format needs evidence material from the user: the LT and LTA levels of CAdES
    /// and PAdES (XAdES fetches its own).
    pub(crate) fn needs_material(&self) -> bool {
        matches!(
            self.format,
            SignFormat::Cades(Level::Lt | Level::Lta) | SignFormat::Pades(Level::Lt | Level::Lta)
        )
    }

    /// Whether this format signs bytes held in memory (JOSE: small, bounded by the SDK)
    /// rather than a document read in pieces.
    pub(crate) fn signs_a_payload(&self) -> bool {
        matches!(self.format, SignFormat::Jws | SignFormat::Jwt)
    }

    /// The name of the file written for the document `name`.
    pub(crate) fn output_name(&self, name: &str) -> String {
        match self.format {
            SignFormat::Cms | SignFormat::Cades(_) => {
                format!(
                    "{name}.{}",
                    if self.options.attached { "p7m" } else { "p7s" }
                )
            }
            SignFormat::Xml | SignFormat::Xades(_) | SignFormat::Wsse => {
                inserted(name, ".signed", ".xml")
            }
            SignFormat::Pdf | SignFormat::Pades(_) => inserted(name, ".signed", ".pdf"),
            SignFormat::Jws => format!("{name}.jws"),
            SignFormat::Jwt => format!("{name}.jwt"),
        }
    }

    /// The format as people name it, the same in every language: shown with the result.
    pub(crate) fn format_name(&self) -> String {
        match self.format {
            SignFormat::Cms => "CMS".to_owned(),
            SignFormat::Cades(l) => format!("CAdES-{}", l.title()),
            SignFormat::Xml => "XMLDSig".to_owned(),
            SignFormat::Xades(l) => format!("XAdES-{}", l.title()),
            SignFormat::Wsse => "WS-Security".to_owned(),
            SignFormat::Pdf => "PDF".to_owned(),
            SignFormat::Pades(l) => format!("PAdES-{}", l.title()),
            SignFormat::Jws => "JWS".to_owned(),
            SignFormat::Jwt => "JWT".to_owned(),
        }
    }
}

/// `report.xml` → `report.signed.xml`; a name without that extension gets it appended.
fn inserted(name: &str, middle: &str, extension: &str) -> String {
    match name
        .len()
        .checked_sub(extension.len())
        .filter(|&at| name.is_char_boundary(at) && name[at..].eq_ignore_ascii_case(extension))
    {
        Some(at) => format!("{}{middle}{}", &name[..at], &name[at..]),
        None => format!("{name}{middle}{extension}"),
    }
}

/// What is checked, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifyFormat {
    Cms,
    Cades(Level),
    Xml,
    XmlKalkan,
    Xades(Level),
    Wsse,
    Pdf,
    Pades(Level),
    Jws,
    Jwt,
}

/// The rarely needed choices of a verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VerifyOptions {
    /// No network: revocation is not fetched, and a result that needs it is said not to be
    /// fully checked.
    pub(crate) offline: bool,
    /// JWT: the issuer and audience the claims must name; empty: not checked.
    pub(crate) issuer: String,
    pub(crate) audience: String,
    /// WS-Security: a timestamp must be present.
    pub(crate) timestamp_required: bool,
}

/// What an extension adds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtendFormat {
    Cms(Level),
    Xml(Level),
    Pdf(Level),
}

impl ExtendFormat {
    /// Whether extending to this level needs evidence material from the user: LT and LTA of
    /// CAdES and PAdES (XAdES fetches its own).
    pub(crate) fn needs_material(self) -> bool {
        matches!(
            self,
            ExtendFormat::Cms(Level::Lt | Level::Lta) | ExtendFormat::Pdf(Level::Lt | Level::Lta)
        )
    }
}

/// The rarely needed choices of a timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StampOptions {
    pub(crate) algorithm: HashAlg,
    /// Checking a token: the policy OID it must carry and the oldest age it may have, in
    /// seconds; empty or zero: not checked.
    pub(crate) policy: String,
    pub(crate) max_age: u64,
}

impl Default for StampOptions {
    fn default() -> Self {
        StampOptions {
            algorithm: HashAlg::Sha256,
            policy: String::new(),
            max_age: 0,
        }
    }
}

/// A tool that uses no private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ToolSpec {
    Verify(VerifyFormat, VerifyOptions),
    Extend(ExtendFormat, Evidence),
    Extract,
    Stamp(StampOptions),
    StampCheck(StampOptions),
}

impl ToolSpec {
    /// Whether the tool reaches a network service: a time stamp service, or revocation status
    /// (an online verification, an extension, a time stamp check).
    pub(crate) fn uses_network(&self) -> bool {
        match self {
            ToolSpec::Verify(_, options) => !options.offline,
            ToolSpec::Extract => false,
            ToolSpec::Extend(..) | ToolSpec::Stamp(_) | ToolSpec::StampCheck(_) => true,
        }
    }

    pub(crate) fn family(&self) -> Family {
        match self {
            ToolSpec::Verify(..) => Family::Verify,
            ToolSpec::Extend(..) => Family::Extend,
            ToolSpec::Extract => Family::Extract,
            ToolSpec::Stamp(_) => Family::Stamp,
            ToolSpec::StampCheck(_) => Family::StampCheck,
        }
    }

    fn action(&self) -> Action {
        match self {
            ToolSpec::Verify(..) => Action::Verify,
            ToolSpec::Extend(..) => Action::Extend,
            ToolSpec::Extract => Action::Extract,
            ToolSpec::Stamp(_) => Action::Stamp,
            ToolSpec::StampCheck(_) => Action::VerifyStamp,
        }
    }

    /// The format as people name it, the same in every language: shown with the result.
    pub(crate) fn format_name(&self) -> String {
        match self {
            ToolSpec::Verify(format, _) => match format {
                VerifyFormat::Cms => "CMS".to_owned(),
                VerifyFormat::Cades(l) => format!("CAdES-{}", l.title()),
                VerifyFormat::Xml => "XMLDSig".to_owned(),
                VerifyFormat::XmlKalkan => "XMLDSig (Kalkan)".to_owned(),
                VerifyFormat::Xades(l) => format!("XAdES-{}", l.title()),
                VerifyFormat::Wsse => "WS-Security".to_owned(),
                VerifyFormat::Pdf => "PDF".to_owned(),
                VerifyFormat::Pades(l) => format!("PAdES-{}", l.title()),
                VerifyFormat::Jws => "JWS".to_owned(),
                VerifyFormat::Jwt => "JWT".to_owned(),
            },
            ToolSpec::Extend(ExtendFormat::Cms(l), _) => format!("CAdES-{}", l.title()),
            ToolSpec::Extend(ExtendFormat::Xml(l), _) => format!("XAdES-{}", l.title()),
            ToolSpec::Extend(ExtendFormat::Pdf(l), _) => format!("PAdES-{}", l.title()),
            ToolSpec::Extract => "CMS".to_owned(),
            ToolSpec::Stamp(_) | ToolSpec::StampCheck(_) => "RFC 3161".to_owned(),
        }
    }

    /// Whether the tool writes a file for each document, and under which name.
    fn output_name(&self, name: &str) -> Option<String> {
        match self {
            ToolSpec::Extend(ExtendFormat::Cms(_), _) => Some(inserted_any(name)),
            ToolSpec::Extend(ExtendFormat::Xml(_), _) => Some(inserted(name, ".extended", ".xml")),
            ToolSpec::Extend(ExtendFormat::Pdf(_), _) => Some(inserted(name, ".extended", ".pdf")),
            ToolSpec::Extract => Some(extracted_name(name)),
            ToolSpec::Stamp(_) => Some(format!("{name}.tst")),
            ToolSpec::Verify(..) | ToolSpec::StampCheck(_) => None,
        }
    }
}

/// `a.p7s` → `a.extended.p7s`: the extension stays last, so that what is made is still what it
/// was.
fn inserted_any(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => format!("{stem}.extended.{extension}"),
        _ => format!("{name}.extended"),
    }
}

/// `a.txt.p7s` → `a.txt`; a name that is not one of the signature containers' gets `.content`.
fn extracted_name(name: &str) -> String {
    for extension in [".p7s", ".p7m", ".sig", ".cms", ".p7"] {
        if let Some(stem) = name
            .len()
            .checked_sub(extension.len())
            .filter(|&at| at > 0 && name.is_char_boundary(at))
            .filter(|&at| name[at..].eq_ignore_ascii_case(extension))
            .map(|at| &name[..at])
        {
            return stem.to_owned();
        }
    }
    format!("{name}.content")
}

/// Where the results are written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    /// Next to each document.
    Beside,
    /// One folder, for all.
    Folder(PathBuf),
}

impl Destination {
    fn folder_for(&self, document: &Path) -> PathBuf {
        match self {
            Destination::Beside => document
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_owned(),
            Destination::Folder(folder) => folder.clone(),
        }
    }
}

/// A document of a batch: its file, and the second file some formats need (the data a
/// detached signature is of, the data a timestamp is of).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Document {
    pub(crate) path: PathBuf,
    pub(crate) second: Option<PathBuf>,
}

impl Document {
    pub(crate) fn name(&self) -> String {
        self.path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    }
}

/// What the SDK is given as evidence limits: the same bounds as the command line's.
pub(crate) fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 256,
        max_bytes: 16 * 1024 * 1024,
        max_item_bytes: 1024 * 1024,
        max_crl_bytes: 16 * 1024 * 1024,
        max_crl_item_bytes: 1024 * 1024,
        max_total_bytes: 16 * 1024 * 1024,
        max_chain_len: 16,
        max_proofs: 16,
        max_coverage_parts: 65536,
        max_coverage_bytes: 64 * 1024 * 1024,
    }
}

/// The national authority's time stamp policy (`TSA_RSA`). The SDK requires the time stamp
/// configuration of every level above B to name a policy (a token of any policy proves nothing
/// of which service made it), so the signing configuration always carries one.
pub(crate) const NCA_TSA_POLICY: &str = "1.2.398.3.3.2.6.2";

/// The TSA the desktop asks: the national authority's, as its own clients ask it (its GET
/// binding and its policy). There is no other: the desktop adds no network address of its own.
/// No retries, a thirty second timeout, a random nonce, the token's signer must be a timestamp
/// authority. `policy` overrides the policy the token must carry.
pub(crate) fn tsa_spec(hash: HashAlg, policy: Option<&str>) -> Result<TsaSpec, JobError> {
    let policy = policy
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.trim().parse())
        .transpose()
        .map_err(|_| JobError::Operation(ErrorCode::InvalidInput))?;
    let mut spec = TsaSpec::from(TsaProfile::kalkan_default());
    spec.hash = hash;
    spec.nonce = NonceSpec::Random(16);
    spec.timeout = Duration::from_secs(30);
    spec.check_skew = Some(Duration::from_secs(300));
    if policy.is_some() {
        spec.policy = policy;
    }
    Ok(spec)
}

// ---- opening the documents and the places the results go -------------------------------------

/// A file opened only if it is a regular one: a pipe or a device is refused before it is read,
/// where no cancel could reach it.
pub(crate) fn open_regular(path: &Path) -> Result<(File, u64), JobError> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(JobError::NotRegular);
    }
    let file = File::open(path)?;
    let meta = file.metadata()?;
    // The path may have been swapped between the two calls.
    if !meta.is_file() {
        return Err(JobError::NotRegular);
    }
    Ok((file, meta.len()))
}

/// A small file, read whole, for the formats that sign or verify bytes held in memory (the
/// SDK bounds them): over `limit` it is refused before it is read in full.
pub(crate) fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, JobError> {
    let (file, len) = open_regular(path)?;
    if len > limit as u64 {
        return Err(JobError::Operation(ErrorCode::InputLimit));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(JobError::Operation(ErrorCode::InputLimit));
    }
    Ok(bytes)
}

/// Before any key is used: the file must not exist, and the folder must be able to publish one
/// without replacing anything (publication is an exclusive hard link).
pub(crate) fn preflight_destination(destination: &Path, parent: &Path) -> Result<(), JobError> {
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(JobError::DestinationExists);
    }
    // Names no one else uses (process, a counter, the clock); the first is created exclusively
    // (never through a link someone planted), and only what this call created is removed.
    static PROBE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let a = parent.join(format!(".oncl-probe-{unique}-a"));
    let b = parent.join(format!(".oncl-probe-{unique}-b"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&a)?;
    let linked = std::fs::hard_link(&a, &b);
    let _ = std::fs::remove_file(&a);
    if linked.is_ok() {
        let _ = std::fs::remove_file(&b);
    }
    linked.map_err(|_| JobError::NoLinks)
}

/// The staged output of one document and the file it will be published as.
pub(crate) struct PlannedOutput {
    pub(crate) stage: Option<StagedArtifact>,
    pub(crate) destination: PathBuf,
}

/// Plans where the result for `document` goes: the file must not exist and the folder must be
/// able to publish it; nothing is written yet. Two documents may not claim one file.
pub(crate) fn plan_output(
    destination: &Destination,
    document: &Path,
    file_name: &str,
    claimed: &mut Vec<PathBuf>,
    ctx: &mut OperationContext,
) -> Result<PlannedOutput, JobError> {
    let parent = destination.folder_for(document);
    if !std::fs::metadata(&parent)?.is_dir() {
        return Err(JobError::Io(std::io::ErrorKind::NotFound));
    }
    let path = parent.join(file_name);
    if claimed.contains(&path) {
        return Err(JobError::DuplicateOutput);
    }
    preflight_destination(&path, &parent)?;
    let store = TemporaryStore::new(&parent).map_err(OperationError::from)?;
    let stage = store.stage(ctx.resources()).map_err(OperationError::from)?;
    claimed.push(path.clone());
    Ok(PlannedOutput {
        stage: Some(stage),
        destination: path,
    })
}

// ---- the requests ----------------------------------------------------------------------------

fn non_empty(text: &str) -> Option<&str> {
    let text = text.trim();
    (!text.is_empty()).then_some(text)
}

/// What is signed: a document read in pieces, or small bytes held in memory.
pub(crate) enum SignInput<'a> {
    Source(Source<'a>),
    Payload(&'a [u8]),
}

/// The batch operation that signs one document as `spec` says, with `key`.
pub(crate) fn sign_operation<'a>(
    spec: &'a SignSpec,
    key: KeyRequest<'a>,
    input: SignInput<'a>,
    output: BatchOutput<'a>,
    material: ValidationMaterial<'a>,
) -> Result<BatchOperation<'a>, JobError> {
    let o = &spec.options;
    let xml_profile = || XmlSignProfile {
        target: non_empty(&o.target),
        parent: non_empty(&o.parent),
        signature_id: non_empty(&o.signature_id),
        mode: if o.add {
            XmlSignMode::Add
        } else {
            XmlSignMode::Create
        },
        evidence_limits: Some(evidence_limits()),
        ..XmlSignProfile::default()
    };
    let request = match spec.format {
        SignFormat::Cms => SignRequest::cms_create(vec![key], o.attached),
        SignFormat::Cades(level) => SignRequest::cades_create(
            vec![key],
            o.attached,
            level.sdk(),
            material,
            evidence_limits(),
        ),
        SignFormat::Xml => SignRequest::xml(key, xml_profile()),
        SignFormat::Xades(level) => SignRequest::xades(key, xml_profile(), level.sdk()),
        SignFormat::Wsse => SignRequest::wsse(
            key,
            SourceWsseSignProfile {
                mode: if o.add {
                    XmlSignMode::Add
                } else {
                    XmlSignMode::Create
                },
                ..SourceWsseSignProfile::default()
            },
        ),
        SignFormat::Pdf => SignRequest::pdf(key, PdfSignProfile::default()),
        SignFormat::Pades(level) => SignRequest::pades(
            key,
            PdfSignProfile::default(),
            level.sdk(),
            material,
            evidence_limits(),
        ),
        SignFormat::Jws => {
            let SignInput::Payload(payload) = input else {
                return Err(JobError::Operation(ErrorCode::InvalidInput));
            };
            return Ok(BatchOperation::Jose(BatchJoseOperation::Create {
                profile: JoseProfile::new(JwsSerialization::Compact, false),
                keys: vec![key],
                payload,
                output,
            }));
        }
        SignFormat::Jwt => {
            let SignInput::Payload(claims) = input else {
                return Err(JobError::Operation(ErrorCode::InvalidInput));
            };
            return Ok(BatchOperation::Jose(BatchJoseOperation::JwtEncode {
                key,
                claims,
                output,
            }));
        }
    };
    let SignInput::Source(input) = input else {
        return Err(JobError::Operation(ErrorCode::InvalidInput));
    };
    Ok(BatchOperation::Sign {
        request,
        input,
        output,
    })
}

/// The files a verification or an extension reads, opened. Kept alive for the batch: the
/// operations borrow them.
struct Opened {
    file: File,
    len: u64,
    second: Option<(File, u64)>,
    /// The bytes of a small document, for the formats that work on bytes in memory.
    payload: Option<Vec<u8>>,
}

/// JOSE reads the whole token: its container is bounded, so is what is read.
fn jose_limit(format: Option<VerifyFormat>) -> usize {
    match format {
        Some(VerifyFormat::Jwt) => oncl_core::jose::MAX_CLAIMS_BYTES + 8 * 1024,
        _ => oncl_core::jose::MAX_CONTAINER_BYTES,
    }
}

/// How the batch is run: the policy the checks are made under.
fn policy(spec: &ToolSpec) -> OperationPolicy {
    match spec {
        ToolSpec::Verify(_, o) if o.offline => OperationPolicy::offline_report(),
        _ => OperationPolicy::strict_online(),
    }
}

/// Runs `spec` on `documents`, as one batch, and returns what the SDK found for each. No
/// private key is used. `now` is the host's clock (a JWT is judged at it).
pub(crate) fn run_tool(
    engine: &Engine,
    spec: &ToolSpec,
    documents: &[Document],
    destination: &Destination,
    now: i64,
    control: &Arc<JobControl>,
) -> Result<BatchView, JobError> {
    if documents.is_empty() {
        return Err(JobError::Input(MissingField::Path));
    }
    // Evidence cannot be built from nothing: refused before any file is read.
    let loaded = match spec {
        ToolSpec::Extend(format, evidence) if format.needs_material() => {
            evidence.require()?;
            Some(evidence.load()?)
        }
        ToolSpec::Extend(_, evidence) if !evidence.is_empty() => Some(evidence.load()?),
        _ => None,
    };
    let (ocsp, crls) = loaded.as_ref().map_or((Vec::new(), Vec::new()), |l| {
        (l.ocsp_slices(), l.crl_slices())
    });
    let certificates = loaded.as_ref().map_or(&[][..], |l| &l.certificates[..]);
    let material = ValidationMaterial {
        certificates,
        ocsp: &ocsp,
        crls: &crls,
    };
    let mut ctx = engine.begin(
        ExecutionGrant::new([spec.action()]),
        policy(spec),
        control.clone(),
    )?;
    let verify_format = match spec {
        ToolSpec::Verify(format, _) => Some(*format),
        _ => None,
    };
    let words_in_memory = matches!(verify_format, Some(VerifyFormat::Jws | VerifyFormat::Jwt));
    // Open everything first; a document that cannot be opened is that document's failure and
    // not the batch's, so the others still run.
    let mut opened: Vec<Result<Opened, JobError>> = Vec::with_capacity(documents.len());
    for document in documents {
        opened.push(open_document(document, words_in_memory, verify_format));
    }
    let mut claimed = Vec::new();
    let mut outputs: Vec<Option<PlannedOutput>> = Vec::with_capacity(documents.len());
    for (document, opened) in documents.iter().zip(&opened) {
        outputs.push(match (opened, spec.output_name(&document.name())) {
            (Ok(_), Some(name)) => Some(plan_output(
                destination,
                &document.path,
                &name,
                &mut claimed,
                &mut ctx,
            )?),
            _ => None,
        });
    }
    let destinations: Vec<Option<PathBuf>> = outputs
        .iter()
        .map(|o| o.as_ref().map(|p| p.destination.clone()))
        .collect();
    let names: Vec<String> = documents.iter().map(Document::name).collect();
    let ids: Vec<String> = (0..documents.len()).map(|i| format!("doc{i}")).collect();
    let policy_jwt = match spec {
        ToolSpec::Verify(VerifyFormat::Jwt, o) => {
            let mut policy = JwtValidationPolicy::new(now);
            policy.expected_issuer = non_empty(&o.issuer).map(str::to_owned);
            policy.expected_audience = non_empty(&o.audience).map(str::to_owned);
            Some(policy)
        }
        _ => None,
    };
    control.set_items(documents.len());
    let mut items = Vec::with_capacity(documents.len());
    let mut local_failures: Vec<(usize, JobError)> = Vec::new();
    for (index, ((opened, output), id)) in opened
        .iter_mut()
        .zip(outputs.iter_mut())
        .zip(&ids)
        .enumerate()
    {
        let opened = match opened {
            Ok(opened) => opened,
            Err(e) => {
                // This document stays out of the batch; it is reported as not done.
                local_failures.push((index, e.clone()));
                continue;
            }
        };
        let owned_output = output
            .as_mut()
            .and_then(|o| o.stage.take())
            .map(BatchOutput::OwnedStaged);
        let operation = tool_operation(
            spec,
            opened,
            owned_output,
            policy_jwt.as_ref(),
            ValidationMaterial {
                certificates: material.certificates,
                ocsp: material.ocsp,
                crls: material.crls,
            },
        )?;
        items.push((index, BatchItem::new(id, operation)));
    }
    let mut position = Vec::new();
    let batch_items: Vec<BatchItem<'_>> = items
        .into_iter()
        .map(|(index, item)| {
            position.push(index);
            item
        })
        .collect();
    let plan = engine
        .capture_batch(batch_items, &mut ctx)
        .map_err(|e| JobError::from(batch_operation_error(e)))?;
    let approval = plan
        .authorize(&ctx)
        .map_err(|e| JobError::from(batch_operation_error(e)))?;
    let mut published = vec![false; documents.len()];
    let summary = engine.run_batch_with_outputs(
        plan,
        approval,
        &mut ctx,
        |event: BatchEvent<'_>| {
            if let BatchEvent::ItemStarted { index, .. } = event {
                control.begin_item(position.get(index).copied().unwrap_or(index));
            }
        },
        |index, _id, _report, completed| {
            let original = position.get(index).copied().unwrap_or(index);
            let Some(destination) = destinations.get(original).and_then(Option::as_ref) else {
                return Err(OperationError::InvalidKeySource);
            };
            completed.commit(destination)?;
            published[original] = true;
            Ok(())
        },
    );
    let summary = summary.map_err(|e| JobError::from(batch_operation_error(e)))?;
    let mut view = view_of_summary(
        spec.family(),
        &names,
        &position,
        &local_failures,
        &destinations,
        &published,
        spec.format_name(),
        &summary,
    );
    view.network = spec.uses_network();
    Ok(view)
}

fn open_document(
    document: &Document,
    words_in_memory: bool,
    format: Option<VerifyFormat>,
) -> Result<Opened, JobError> {
    let (file, len) = open_regular(&document.path)?;
    let second = document.second.as_deref().map(open_regular).transpose()?;
    let payload = if words_in_memory {
        Some(read_limited(&document.path, jose_limit(format))?)
    } else {
        None
    };
    Ok(Opened {
        file,
        len,
        second,
        payload,
    })
}

fn tool_operation<'a>(
    spec: &'a ToolSpec,
    opened: &'a mut Opened,
    output: Option<BatchOutput<'a>>,
    jwt: Option<&'a JwtValidationPolicy>,
    material: ValidationMaterial<'a>,
) -> Result<BatchOperation<'a>, JobError> {
    let Opened {
        file,
        len,
        second,
        payload,
    } = opened;
    let input = Source::seekable(file, Some(*len));
    let second = second
        .as_mut()
        .map(|(file, len)| Source::seekable(file, Some(*len)));
    let invalid = || JobError::Operation(ErrorCode::InvalidInput);
    Ok(match spec {
        ToolSpec::Verify(format, options) => match format {
            VerifyFormat::Jws => BatchOperation::Jose(BatchJoseOperation::Verify {
                request: JwsVerifyRequest::new(JoseProfile::new(JwsSerialization::Compact, false)),
                input: payload.as_deref().ok_or_else(invalid)?,
                detached: None,
            }),
            VerifyFormat::Jwt => BatchOperation::Jose(BatchJoseOperation::JwtVerify {
                certificate: None,
                input: payload.as_deref().ok_or_else(invalid)?,
                policy: jwt.ok_or_else(invalid)?,
            }),
            other => {
                let request = match other {
                    VerifyFormat::Cms => VerifyRequest::cms(),
                    VerifyFormat::Cades(l) => VerifyRequest::cades(l.sdk(), evidence_limits()),
                    VerifyFormat::Xml => VerifyRequest::xml(),
                    VerifyFormat::XmlKalkan => VerifyRequest::xml_kalkan(),
                    VerifyFormat::Xades(l) => VerifyRequest::xades(l.sdk()),
                    VerifyFormat::Wsse => {
                        let mut profile = WsseVerifyProfile::default();
                        profile.timestamp.required = options.timestamp_required;
                        VerifyRequest::wsse(profile)
                    }
                    VerifyFormat::Pdf => VerifyRequest::pdf(),
                    VerifyFormat::Pades(l) => VerifyRequest::pades(l.sdk(), evidence_limits()),
                    VerifyFormat::Jws | VerifyFormat::Jwt => unreachable!("matched above"),
                };
                BatchOperation::Verify {
                    request,
                    input,
                    detached: second,
                }
            }
        },
        ToolSpec::Extend(format, _) => {
            let request = match format {
                ExtendFormat::Cms(l) => ExtendRequest::cms(l.sdk()),
                ExtendFormat::Xml(l) => ExtendRequest::xml(l.sdk()),
                ExtendFormat::Pdf(l) => ExtendRequest::pdf(l.sdk(), PdfLimits::default()),
            }
            .with_evidence_limits(evidence_limits())
            .with_material(material);
            let request = match second {
                Some(detached) => request.with_detached(detached),
                None => request,
            };
            BatchOperation::Extend {
                request,
                input,
                output: output.ok_or_else(invalid)?,
            }
        }
        ToolSpec::Extract => BatchOperation::Extract {
            input,
            output: output.ok_or_else(invalid)?,
        },
        ToolSpec::Stamp(options) => BatchOperation::Stamp {
            request: StampRequest::new(tsa_spec(options.algorithm, None)?),
            input,
            output: output.ok_or_else(invalid)?,
        },
        ToolSpec::StampCheck(options) => {
            let mut request = StampVerifyRequest::new().with_algorithm(options.algorithm);
            if let Some(policy) = non_empty(&options.policy) {
                request = request.with_policy(policy.parse().map_err(|_| invalid())?);
            }
            if options.max_age > 0 {
                request = request.with_maximum_age(Duration::from_secs(options.max_age));
            }
            BatchOperation::VerifyStamp {
                request,
                token: input,
                data: second,
            }
        }
    })
}

pub(crate) fn batch_operation_error(e: oncl_core::batch::BatchError) -> OperationError {
    match e {
        oncl_core::batch::BatchError::Operation(e) => e,
        oncl_core::batch::BatchError::ConsentMismatch => OperationError::PermissionDenied,
    }
}

// ---- the views ---------------------------------------------------------------------------------

/// What a batch run found, as the views of the page.
#[allow(clippy::too_many_arguments)]
pub(crate) fn view_of_summary(
    family: Family,
    names: &[String],
    position: &[usize],
    local_failures: &[(usize, JobError)],
    destinations: &[Option<PathBuf>],
    published: &[bool],
    profile: String,
    summary: &BatchSummary,
) -> BatchView {
    let mut items: Vec<Option<ItemView>> = (0..names.len()).map(|_| None).collect();
    for (index, error) in local_failures {
        items[*index] = Some(ItemView {
            name: names[*index].clone(),
            outcome: Outcome::Failed(error_code_of(error)),
            applied: AppliedState::NotApplied,
            output: None,
        });
    }
    for (slot, result) in summary.results().iter().enumerate() {
        let index = position.get(slot).copied().unwrap_or(slot);
        let outcome = match result.outcome() {
            BatchOutcome::Completed(report) => match detail_of(report, family, &profile) {
                Some(detail) => Outcome::Completed(detail),
                // A report this tool never asks for: not shown as a result of anything.
                None => Outcome::Failed(ErrorCode::InvalidInput),
            },
            BatchOutcome::Failed(error) => Outcome::Failed(error.code()),
            BatchOutcome::NotRun => Outcome::NotRun,
        };
        let published_path = published
            .get(index)
            .copied()
            .unwrap_or(false)
            .then(|| destinations.get(index).cloned().flatten())
            .flatten();
        items[index] = Some(ItemView {
            name: names[index].clone(),
            outcome,
            applied: result.applied_state(),
            output: published_path,
        });
    }
    let items = items
        .into_iter()
        .enumerate()
        .map(|(i, item)| {
            item.unwrap_or_else(|| ItemView {
                name: names[i].clone(),
                outcome: Outcome::NotRun,
                applied: AppliedState::NotApplied,
                output: None,
            })
        })
        .collect();
    BatchView {
        family,
        items,
        stop: summary.stop.as_ref().map(stop_of),
        network: false,
    }
}

fn stop_of(stop: &BatchStop) -> Stop {
    match stop.code() {
        ErrorCode::Cancelled => Stop::Cancelled,
        ErrorCode::DeadlineExceeded => Stop::Deadline,
        code => Stop::Failed(code),
    }
}

fn error_code_of(error: &JobError) -> ErrorCode {
    match error {
        JobError::Cancelled => ErrorCode::Cancelled,
        JobError::Operation(code) => *code,
        _ => ErrorCode::Io,
    }
}

/// The detail of one completed item.
fn detail_of(report: &BatchReport, family: Family, profile: &str) -> Option<Detail> {
    Some(match report {
        BatchReport::Hash(report) => Detail::Hash {
            digest: hex(report.digest.as_bytes()),
            bytes: report.bytes_in,
        },
        BatchReport::Sign(report) | BatchReport::Extend(report) => written_detail(report, profile),
        BatchReport::Verify(report) | BatchReport::Validate(report) => {
            Detail::Verified(verification_view(report))
        }
        BatchReport::Extract(report) => Detail::Extracted {
            bytes: report.bytes_written,
        },
        BatchReport::Inspect(_) | BatchReport::JwtDecode(_) => return None,
        // Acquiring and checking a time stamp both report a timestamp; what was asked says
        // which of them this is.
        BatchReport::Stamp(report) if family == Family::StampCheck => {
            Detail::StampChecked(stamp_view(report))
        }
        BatchReport::Stamp(report) => Detail::Stamped(stamp_view(report)),
        BatchReport::JoseWrite(report) => Detail::Written {
            profile: profile.to_owned(),
            signers: report.signer_count,
            bytes_out: report.bytes_out,
            check: None,
        },
        BatchReport::JwsVerify(report) => Detail::Verified(jws_view(report, None)),
        BatchReport::JwtVerify(report) => Detail::Verified(jws_view(report.jws(), Some(report))),
    })
}

fn written_detail(report: &OperationReport, profile: &str) -> Detail {
    let check = report.validation_reports().map(|reports| {
        let mut view = VerificationView {
            verdict: combine_verdicts(reports.iter().map(|r| r.verdict)),
            policy: reports
                .first()
                .map_or(ValidationPolicy::StrictOnline, |r| r.policy),
            checked_at: reports
                .first()
                .map_or(time::OffsetDateTime::UNIX_EPOCH, |r| r.checked_at),
            level: None,
            signers: reports
                .iter()
                .flat_map(|r| r.signers.iter())
                .map(signer_view)
                .collect(),
            notes: Vec::new(),
            claims: None,
        };
        view.level = view
            .signers
            .iter()
            .map(|s| s.level)
            .try_fold(None, |lowest: Option<AdesLevel>, level| {
                level.map(|l| Some(lowest.map_or(l, |m| m.min(l))))
            })
            .flatten();
        if let Some(xml) = report.xml() {
            xml_notes(xml.signatures(), &mut view);
        }
        if let Some(pdf) = report.pdf_revision_facts() {
            pdf_notes(pdf, &mut view);
        }
        view
    });
    Detail::Written {
        profile: profile.to_owned(),
        signers: report.signer_count(),
        bytes_out: report.bytes_out,
        check,
    }
}

fn signer_view(s: &SignerValidation) -> SignerView {
    SignerView {
        verdict: s.verdict(),
        checks: vec![
            (Check::Signature, s.signature),
            (Check::Chain, s.chain),
            (Check::Validity, s.validity),
            (Check::Revocation, s.revocation),
            (Check::Timestamp, s.timestamp),
            (Check::KeyUsage, s.key_usage),
        ],
        reasons: s.reasons.clone(),
        level: s.ades_level,
        claimed_signing_time: s.claimed_signing_time,
        basis: s.time_basis,
        algorithm: None,
        certificate_sha256: None,
    }
}

fn xml_notes(signatures: &[oncl_xml::XmlSignerResult], view: &mut VerificationView) {
    for (i, signature) in signatures.iter().enumerate() {
        if let Some(signer) = view.signers.get_mut(i) {
            signer.algorithm = Some(format!("{:?}", signature.algorithm));
            signer.certificate_sha256 = Some(signature.certificate_sha256);
        }
        for (r, reference) in signature.references().iter().enumerate() {
            view.notes.push(Note::XmlReference {
                signature: i,
                reference: r,
                resolved: reference.target.is_some(),
                digest_matches: reference.digest_matches,
            });
        }
    }
}

fn pdf_notes(facts: &oncl_pdf::PdfRevisionFacts, view: &mut VerificationView) {
    view.notes.push(Note::PdfExtent(facts.extent));
    for signature in facts.signatures.iter() {
        view.notes.push(Note::PdfRevision {
            revision: signature.revision,
            later_changes: signature.later_changes,
            signers: signature.signers.len(),
        });
    }
}

/// A verification as the SDK reported it.
pub(crate) fn verification_view(report: &VerificationReport) -> VerificationView {
    let mut view = VerificationView {
        verdict: report.verdict,
        policy: report.policy,
        checked_at: report.checked_at,
        level: report.ades_level,
        signers: report.signers.iter().map(signer_view).collect(),
        notes: Vec::new(),
        claims: None,
    };
    if let Some(xml) = &report.xml {
        xml_notes(xml.signatures(), &mut view);
    }
    if let Some(pdf) = &report.pdf {
        pdf_notes(pdf, &mut view);
    }
    view
}

/// A JWS (and its claims, if it is a JWT) as the SDK reported it.
fn jws_view(
    jws: &JwsVerificationReport,
    jwt: Option<&oncl_core::jose::JwtVerificationReport>,
) -> VerificationView {
    VerificationView {
        verdict: jwt.map_or_else(
            || jws.verdict(),
            oncl_core::jose::JwtVerificationReport::verdict,
        ),
        policy: jws.policy(),
        checked_at: jws.checked_at(),
        level: None,
        signers: jws
            .signers()
            .iter()
            .map(|s| {
                let mut signer = signer_view(s.trust());
                // The signature itself is the JOSE layer's check; the trust facts are the
                // shared validation's.
                signer.checks[0].1 = s.crypto();
                signer.verdict = s.verdict();
                signer.algorithm = Some(s.algorithm().name().to_owned());
                signer
            })
            .collect(),
        notes: Vec::new(),
        claims: jwt.map(|report| ClaimsView {
            verdict: report.claims().verdict(),
            failures: report.claims().failures().to_vec(),
        }),
    }
}

/// A timestamp as the SDK reported it.
fn stamp_view(report: &TimestampReport) -> StampView {
    let facts = report.facts();
    StampView {
        verdict: report.verdict(),
        policy: facts.validation_policy(),
        checked_at: facts.checked_at(),
        gen_time: facts.gen_time(),
        checks: vec![
            (StampCheck::Signature, facts.signature()),
            (StampCheck::TsaUsage, facts.eku()),
            (StampCheck::Chain, facts.chain()),
            (StampCheck::Validity, facts.validity()),
            (StampCheck::Revocation, facts.revocation()),
            (StampCheck::Expectations, facts.expectations()),
        ],
        imprint: facts.imprint(),
        algorithm: facts.algorithm(),
        tsa_policy: facts.tsa_policy().to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::controller::{Headline, Tone};
    use crate::signing::runner::Outcome as SignOutcome;
    use crate::signing::testing::*;
    use oncl_pki::validation::Verdict;

    fn control() -> Arc<JobControl> {
        Arc::new(JobControl::default())
    }

    fn verify(w: &World, spec: &ToolSpec, documents: &[Document]) -> Result<BatchView, JobError> {
        let (engine, _) = engine(w);
        run_tool(
            &engine,
            spec,
            documents,
            &Destination::Beside,
            NOW,
            &control(),
        )
    }

    fn signed(name: &str, w: &World, spec: &SignSpec, paths: &[PathBuf]) -> (BatchView, usize) {
        let (engine, guard) = engine(w);
        let outcome = sign_confirmed(&engine, &guard, w, paths, spec, &Destination::Beside);
        let SignOutcome::Done(view) = outcome else {
            panic!("{name}: {outcome:?}");
        };
        (view, guard.applications())
    }

    fn spec(format: SignFormat) -> SignSpec {
        SignSpec {
            format,
            options: SignOptions::default(),
        }
    }

    fn verdicts(view: &BatchView) -> Vec<Verdict> {
        view.items
            .iter()
            .map(|i| match &i.outcome {
                Outcome::Completed(Detail::Verified(v)) => v.verdict,
                other => panic!("not a verification: {other:?}"),
            })
            .collect()
    }

    fn write(w: &World, name: &str, bytes: &[u8]) -> PathBuf {
        let path = w.dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    const XML: &[u8] = b"<r><p Id='p'>protected</p><s Id='s'/></r>";

    /// The element identities XAdES is made over: what is signed, where the signature goes and
    /// its own identity.
    fn xml_ids() -> SignOptions {
        SignOptions {
            target: "p".into(),
            parent: "s".into(),
            signature_id: "sig".into(),
            ..SignOptions::default()
        }
    }
    const SOAP: &[u8] = b"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header/><soapenv:Body><a>hi</a></soapenv:Body></soapenv:Envelope>";

    fn pdf(w: &World) -> PathBuf {
        let source = oncl_testkit::workspace_root()
            .join("crates/oncl-pdf/tests/fixtures/external-multipage.pdf");
        let path = w.dir.path().join("doc.pdf");
        std::fs::copy(source, &path).unwrap();
        path
    }

    /// Every family the page signs, signed by the real engine under the user's confirmation and
    /// verified by the real engine through the verify tool: each report is `Valid`, the key
    /// was applied once, and the file is where the naming says.
    #[test]
    fn every_signature_family_signs_and_its_own_verify_says_valid() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        let xml = write(&w, "doc.xml", XML);
        let soap = write(&w, "soap.xml", SOAP);
        let pdf = pdf(&w);
        let jws = write(&w, "payload.txt", b"{\"hello\":\"jws\"}");
        let jwt = write(
            &w,
            "claims.json",
            b"{\"iss\":\"issuer\",\"aud\":\"audience\",\"exp\":1893456000}",
        );
        let attached = SignOptions {
            attached: true,
            ..SignOptions::default()
        };
        let cases: Vec<(&str, SignSpec, PathBuf, VerifyFormat, bool, &str)> = vec![
            (
                "cms detached",
                spec(SignFormat::Cms),
                text.clone(),
                VerifyFormat::Cms,
                true,
                "doc.txt.p7s",
            ),
            (
                "cms attached",
                SignSpec {
                    format: SignFormat::Cms,
                    options: attached.clone(),
                },
                text.clone(),
                VerifyFormat::Cms,
                false,
                "doc.txt.p7m",
            ),
            (
                "cades-b",
                spec(SignFormat::Cades(Level::B)),
                text.clone(),
                VerifyFormat::Cades(Level::B),
                true,
                "doc.txt.p7s",
            ),
            (
                "xml",
                SignSpec {
                    format: SignFormat::Xml,
                    options: xml_ids(),
                },
                xml.clone(),
                VerifyFormat::Xml,
                false,
                "doc.signed.xml",
            ),
            (
                "xades-b",
                SignSpec {
                    format: SignFormat::Xades(Level::B),
                    options: xml_ids(),
                },
                xml.clone(),
                VerifyFormat::Xades(Level::B),
                false,
                "doc.signed.xml",
            ),
            (
                "wsse",
                spec(SignFormat::Wsse),
                soap,
                VerifyFormat::Wsse,
                false,
                "soap.signed.xml",
            ),
            (
                "pdf",
                spec(SignFormat::Pdf),
                pdf.clone(),
                VerifyFormat::Pdf,
                false,
                "doc.signed.pdf",
            ),
            (
                "pades-b",
                spec(SignFormat::Pades(Level::B)),
                pdf,
                VerifyFormat::Pades(Level::B),
                false,
                "doc.signed.pdf",
            ),
            (
                "jws",
                spec(SignFormat::Jws),
                jws,
                VerifyFormat::Jws,
                false,
                "payload.txt.jws",
            ),
            (
                "jwt",
                spec(SignFormat::Jwt),
                jwt,
                VerifyFormat::Jwt,
                false,
                "claims.json.jwt",
            ),
        ];
        for (name, sign_spec, input, verify_format, detached, output_name) in cases {
            // Each family writes next to its document; clear what an earlier family left.
            let expected = input.parent().unwrap().join(output_name);
            let _ = std::fs::remove_file(&expected);
            let (view, applications) = signed(name, &w, &sign_spec, std::slice::from_ref(&input));
            assert_eq!(applications, 1, "{name}: the key was applied once");
            assert_eq!(
                view.headline(),
                Headline::AllSucceeded { total: 1 },
                "{name}: {view:?}"
            );
            assert_eq!(
                view.items[0].output.as_deref(),
                Some(expected.as_path()),
                "{name}"
            );
            let document = Document {
                path: expected.clone(),
                second: detached.then(|| input.clone()),
            };
            let report = verify(
                &w,
                &ToolSpec::Verify(verify_format, VerifyOptions::default()),
                &[document],
            )
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                verdicts(&report),
                vec![Verdict::Valid],
                "{name}: {report:?}"
            );
            assert_eq!(report.tone(), Tone::Success, "{name}");
        }
    }

    /// What each family needs to be signed at a level: the XML identities for XAdES, the
    /// operator's evidence files for the LT and LTA levels of CAdES and PAdES.
    fn level_spec(w: &World, format: SignFormat) -> SignSpec {
        let mut options = SignOptions::default();
        if matches!(format, SignFormat::Xades(_)) {
            options = xml_ids();
        }
        if matches!(
            format,
            SignFormat::Cades(Level::Lt | Level::Lta) | SignFormat::Pades(Level::Lt | Level::Lta)
        ) {
            options.evidence = evidence_files(w);
        }
        SignSpec { format, options }
    }

    fn verified_at(view: &BatchView, level: Level, name: &str) {
        assert_eq!(verdicts(view), vec![Verdict::Valid], "{name}: {view:?}");
        let Outcome::Completed(Detail::Verified(v)) = &view.items[0].outcome else {
            panic!("{name}: {view:?}");
        };
        assert_eq!(v.level, Some(level.sdk()), "{name}: verified at its level");
    }

    /// Every level above B of CAdES, XAdES and PAdES is signed through the engine under the
    /// user's confirmation and verified back at exactly that level: the TSA configuration
    /// carries the policy the SDK requires, XAdES fetches its own evidence, and CAdES/PAdES
    /// LT/LTA are built from the operator's evidence files. (The cause of the earlier failures
    /// was the UI's request: no TSA policy for XAdES, no evidence material for CAdES-LT.)
    #[test]
    fn every_level_above_b_signs_and_verifies_at_its_level() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        let xml = write(&w, "doc.xml", XML);
        let pdf = pdf(&w);
        for level in [Level::T, Level::Lt, Level::Lta] {
            let cases = [
                (
                    "cades",
                    SignFormat::Cades(level),
                    text.clone(),
                    VerifyFormat::Cades(level),
                    true,
                    "doc.txt.p7s",
                ),
                (
                    "xades",
                    SignFormat::Xades(level),
                    xml.clone(),
                    VerifyFormat::Xades(level),
                    false,
                    "doc.signed.xml",
                ),
                (
                    "pades",
                    SignFormat::Pades(level),
                    pdf.clone(),
                    VerifyFormat::Pades(level),
                    false,
                    "doc.signed.pdf",
                ),
            ];
            for (family, format, input, verify_format, detached, output_name) in cases {
                let name = format!("{family}-{}", level.name());
                let expected = input.parent().unwrap().join(output_name);
                let _ = std::fs::remove_file(&expected);
                let (view, applications) = signed(
                    &name,
                    &w,
                    &level_spec(&w, format),
                    std::slice::from_ref(&input),
                );
                assert_eq!(applications, 1, "{name}");
                assert_eq!(
                    view.headline(),
                    Headline::AllSucceeded { total: 1 },
                    "{name}: {view:?}"
                );
                let document = Document {
                    path: expected,
                    second: detached.then(|| input.clone()),
                };
                let report = verify(
                    &w,
                    &ToolSpec::Verify(verify_format, VerifyOptions::default()),
                    &[document],
                )
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                verified_at(&report, level, &name);
            }
        }
    }

    /// LT and LTA of CAdES and PAdES cannot be built from nothing, and the engine would only
    /// say so after the key was applied: the runner refuses before anything is read or used,
    /// with nothing written and the key not applied.
    #[test]
    fn lt_and_lta_without_evidence_are_refused_before_any_key_use() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        let pdf = pdf(&w);
        let partial = Evidence {
            certificates: evidence_files(&w).certificates,
            ..Evidence::default()
        };
        for (name, format, input) in [
            ("cades-lt", SignFormat::Cades(Level::Lt), text.clone()),
            ("cades-lta", SignFormat::Cades(Level::Lta), text.clone()),
            ("pades-lt", SignFormat::Pades(Level::Lt), pdf.clone()),
            ("pades-lta", SignFormat::Pades(Level::Lta), pdf.clone()),
        ] {
            for evidence in [Evidence::default(), partial.clone()] {
                let (engine, guard) = engine(&w);
                let sign_spec = SignSpec {
                    format,
                    options: SignOptions {
                        evidence,
                        ..SignOptions::default()
                    },
                };
                let outcome = sign_confirmed(
                    &engine,
                    &guard,
                    &w,
                    std::slice::from_ref(&input),
                    &sign_spec,
                    &Destination::Beside,
                );
                assert!(
                    matches!(
                        &outcome,
                        SignOutcome::NotApplied(JobError::Input(MissingField::Evidence))
                    ),
                    "{name}: {outcome:?}"
                );
                assert_eq!(guard.applications(), 0, "{name}: no key was used");
            }
            let output = spec(format).output_name(&input.file_name().unwrap().to_string_lossy());
            assert!(
                !input.parent().unwrap().join(output).exists(),
                "{name}: nothing was written"
            );
        }
    }

    /// Extension walks CAdES, XAdES and PAdES from B to T, LT and LTA without a key: the
    /// original stays, every step verifies at its level, and the CAdES/PAdES steps that need
    /// evidence are refused without it before anything is read or written.
    #[test]
    fn extend_takes_every_family_from_b_to_lta_without_a_key() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        let xml = write(&w, "doc.xml", XML);
        let pdf = pdf(&w);
        type Family = (
            &'static str,
            SignFormat,
            PathBuf,
            &'static str,
            fn(Level) -> ExtendFormat,
            fn(Level) -> VerifyFormat,
            bool,
        );
        let families: [Family; 3] = [
            (
                "cades",
                SignFormat::Cades(Level::B),
                text.clone(),
                "doc.txt.p7s",
                ExtendFormat::Cms,
                VerifyFormat::Cades,
                true,
            ),
            (
                "xades",
                SignFormat::Xades(Level::B),
                xml.clone(),
                "doc.signed.xml",
                ExtendFormat::Xml,
                VerifyFormat::Xades,
                false,
            ),
            (
                "pades",
                SignFormat::Pades(Level::B),
                pdf.clone(),
                "doc.signed.pdf",
                ExtendFormat::Pdf,
                VerifyFormat::Pades,
                false,
            ),
        ];
        for (family, format, input, first_output, extend, verify_format, detached) in families {
            let (_, applications) = signed(
                family,
                &w,
                &level_spec(&w, format),
                std::slice::from_ref(&input),
            );
            assert_eq!(applications, 1, "{family}");
            let mut current = input.parent().unwrap().join(first_output);
            let original = std::fs::read(&current).unwrap();
            for level in [Level::T, Level::Lt, Level::Lta] {
                let name = format!("{family}-{}", level.name());
                let second = detached.then(|| input.clone());
                let document = Document {
                    path: current.clone(),
                    second: second.clone(),
                };
                if extend(level).needs_material() {
                    let refused = verify(
                        &w,
                        &ToolSpec::Extend(extend(level), Evidence::default()),
                        std::slice::from_ref(&document),
                    );
                    assert_eq!(
                        refused.err(),
                        Some(JobError::Input(MissingField::Evidence)),
                        "{name}"
                    );
                }
                let evidence = if extend(level).needs_material() {
                    evidence_files(&w)
                } else {
                    Evidence::default()
                };
                let report = verify(&w, &ToolSpec::Extend(extend(level), evidence), &[document])
                    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                let item = &report.items[0];
                assert!(
                    matches!(item.outcome, Outcome::Completed(Detail::Written { .. })),
                    "{name}: {item:?}"
                );
                assert_eq!(
                    item.applied,
                    AppliedState::NotApplied,
                    "{name}: an extension applies no key"
                );
                let extended = item.output.clone().expect("the extended file");
                assert_ne!(extended, current, "{name}");
                let checked = verify(
                    &w,
                    &ToolSpec::Verify(verify_format(level), VerifyOptions::default()),
                    &[Document {
                        path: extended.clone(),
                        second,
                    }],
                )
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                verified_at(&checked, level, &name);
                current = extended;
            }
            assert_eq!(
                std::fs::read(input.parent().unwrap().join(first_output)).unwrap(),
                original,
                "{family}: the original is untouched"
            );
        }
    }

    /// Extraction gives the content of an attached CMS exactly, labels itself as not verified
    /// (a neutral result, never success), and writes next to the container under the name
    /// without its suffix.
    #[test]
    fn extract_returns_the_content_and_is_never_styled_as_verified() {
        let w = world();
        let text = write(&w, "doc.txt", b"the exact content");
        let attached = SignSpec {
            format: SignFormat::Cms,
            options: SignOptions {
                attached: true,
                ..SignOptions::default()
            },
        };
        signed("cms attached", &w, &attached, std::slice::from_ref(&text));
        std::fs::remove_file(&text).unwrap();
        let report = verify(
            &w,
            &ToolSpec::Extract,
            &[Document {
                path: w.dir.path().join("doc.txt.p7m"),
                second: None,
            }],
        )
        .unwrap();
        let item = &report.items[0];
        assert!(
            matches!(
                item.outcome,
                Outcome::Completed(Detail::Extracted { bytes: 17 })
            ),
            "{item:?}"
        );
        assert_eq!(item.output.as_deref(), Some(text.as_path()));
        assert_eq!(std::fs::read(&text).unwrap(), b"the exact content");
        assert_eq!(item.tone(), Tone::Neutral);
        assert_ne!(report.tone(), Tone::Success);
    }

    /// A time stamp is got and written; checked with its data it is valid; checked without the
    /// data it is only not fully checked (never valid), and with other data it is invalid.
    #[test]
    fn a_time_stamp_is_valid_only_for_the_data_it_is_of() {
        let w = world();
        let text = write(&w, "doc.txt", b"stamp me");
        let got = verify(
            &w,
            &ToolSpec::Stamp(StampOptions {
                ..StampOptions::default()
            }),
            &[Document {
                path: text.clone(),
                second: None,
            }],
        )
        .unwrap();
        let item = &got.items[0];
        assert!(
            matches!(item.outcome, Outcome::Completed(Detail::Stamped(_))),
            "{item:?}"
        );
        let token = w.dir.path().join("doc.txt.tst");
        assert_eq!(item.output.as_deref(), Some(token.as_path()));
        let check = |data: Option<&PathBuf>| {
            verify(
                &w,
                &ToolSpec::StampCheck(StampOptions::default()),
                &[Document {
                    path: token.clone(),
                    second: data.cloned(),
                }],
            )
            .unwrap()
        };
        let valid = check(Some(&text));
        let Outcome::Completed(Detail::StampChecked(view)) = &valid.items[0].outcome else {
            panic!("{valid:?}");
        };
        assert_eq!(view.verdict, Verdict::Valid);
        assert_eq!(valid.tone(), Tone::Success);
        let without = check(None);
        let Outcome::Completed(Detail::StampChecked(view)) = &without.items[0].outcome else {
            panic!("{without:?}");
        };
        assert_eq!(
            view.verdict,
            Verdict::Indeterminate,
            "no data: not proof of any document"
        );
        assert_ne!(without.tone(), Tone::Success);
        let other = write(&w, "other.txt", b"other data");
        let wrong = check(Some(&other));
        let Outcome::Completed(Detail::StampChecked(view)) = &wrong.items[0].outcome else {
            panic!("{wrong:?}");
        };
        assert_eq!(view.verdict, Verdict::Invalid);
        assert_eq!(wrong.tone(), Tone::Failure);
    }

    /// A batch with a bad document: the good ones keep their verdicts, an altered document is
    /// invalid, a missing file is that file's failure, and the batch is never «all valid».
    #[test]
    fn a_batch_with_a_bad_document_keeps_every_other_result() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        signed(
            "cms",
            &w,
            &spec(SignFormat::Cms),
            std::slice::from_ref(&text),
        );
        let sig = w.dir.path().join("doc.txt.p7s");
        let altered = write(&w, "altered.txt", b"another document");
        let good = Document {
            path: sig.clone(),
            second: Some(text.clone()),
        };
        let report = verify(
            &w,
            &ToolSpec::Verify(VerifyFormat::Cms, VerifyOptions::default()),
            &[
                good.clone(),
                Document {
                    path: sig.clone(),
                    second: Some(altered),
                },
                Document {
                    path: w.dir.path().join("missing.p7s"),
                    second: None,
                },
                good,
            ],
        )
        .unwrap();
        let kinds: Vec<_> = report.items.iter().map(|i| &i.outcome).collect();
        assert!(
            matches!(kinds[0], Outcome::Completed(Detail::Verified(v)) if v.verdict == Verdict::Valid),
            "{kinds:?}"
        );
        assert!(
            matches!(kinds[1], Outcome::Completed(Detail::Verified(v)) if v.verdict == Verdict::Invalid),
            "{kinds:?}"
        );
        assert!(matches!(kinds[2], Outcome::Failed(_)), "{kinds:?}");
        assert!(
            matches!(kinds[3], Outcome::Completed(Detail::Verified(v)) if v.verdict == Verdict::Valid),
            "{kinds:?}"
        );
        assert_eq!(
            report.headline(),
            Headline::Partial {
                completed: 3,
                total: 4
            }
        );
        assert_ne!(report.tone(), Tone::Success);
    }

    /// Without the network a verification cannot be complete: it is not fully checked, never
    /// valid, and the report says why (revocation could not be checked).
    #[test]
    fn an_offline_verification_is_not_fully_checked() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        signed(
            "cms",
            &w,
            &spec(SignFormat::Cms),
            std::slice::from_ref(&text),
        );
        let report = verify(
            &w,
            &ToolSpec::Verify(
                VerifyFormat::Cms,
                VerifyOptions {
                    offline: true,
                    ..VerifyOptions::default()
                },
            ),
            &[Document {
                path: w.dir.path().join("doc.txt.p7s"),
                second: Some(text),
            }],
        )
        .unwrap();
        assert_eq!(
            verdicts(&report),
            vec![Verdict::Indeterminate],
            "{report:?}"
        );
        assert_ne!(report.tone(), Tone::Success);
    }

    /// Two documents that would write one file, an existing result and a folder that is not
    /// there are all refused before anything is read or written.
    #[test]
    fn clashing_and_existing_outputs_are_refused_before_anything_is_written() {
        let w = world();
        let a = w.dir.path().join("one");
        let b = w.dir.path().join("two");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let first = a.join("same.p7s");
        let second = b.join("same.p7s");
        std::fs::write(&first, b"x").unwrap();
        std::fs::write(&second, b"y").unwrap();
        let folder = w.dir.path().join("out");
        std::fs::create_dir(&folder).unwrap();
        let (engine, _) = engine(&w);
        let run = |destination: &Destination, documents: &[Document]| {
            run_tool(
                &engine,
                &ToolSpec::Extract,
                documents,
                destination,
                NOW,
                &control(),
            )
        };
        let docs = [
            Document {
                path: first.clone(),
                second: None,
            },
            Document {
                path: second.clone(),
                second: None,
            },
        ];
        assert_eq!(
            run(&Destination::Folder(folder.clone()), &docs).err(),
            Some(JobError::DuplicateOutput)
        );
        std::fs::write(folder.join("same"), b"taken").unwrap();
        assert_eq!(
            run(&Destination::Folder(folder.clone()), &docs[..1]).err(),
            Some(JobError::DestinationExists)
        );
        assert_eq!(std::fs::read(folder.join("same")).unwrap(), b"taken");
        assert_eq!(
            run(
                &Destination::Folder(w.dir.path().join("nowhere")),
                &docs[..1]
            )
            .err(),
            Some(JobError::Io(std::io::ErrorKind::NotFound))
        );
    }

    /// A cancel before the work reaches it ends the run as a cancel, not as a result.
    #[test]
    fn a_cancelled_run_is_a_cancel() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        let (engine, _) = engine(&w);
        let control = control();
        control.cancel();
        let result = run_tool(
            &engine,
            &ToolSpec::Stamp(StampOptions::default()),
            &[Document {
                path: text.clone(),
                second: None,
            }],
            &Destination::Beside,
            NOW,
            &control,
        );
        assert_eq!(result.err(), Some(JobError::Cancelled));
        assert!(!w.dir.path().join("doc.txt.tst").exists());
    }

    #[test]
    fn output_names_keep_the_extension_that_says_what_the_file_is() {
        assert_eq!(
            inserted("report.xml", ".signed", ".xml"),
            "report.signed.xml"
        );
        assert_eq!(
            inserted("REPORT.XML", ".signed", ".xml"),
            "REPORT.signed.XML"
        );
        assert_eq!(inserted("report", ".signed", ".xml"), "report.signed.xml");
        assert_eq!(inserted_any("a.txt.p7s"), "a.txt.extended.p7s");
        assert_eq!(inserted_any("a"), "a.extended");
        assert_eq!(extracted_name("a.txt.p7s"), "a.txt");
        assert_eq!(extracted_name("a.P7M"), "a");
        assert_eq!(extracted_name(".p7s"), ".p7s.content");
        assert_eq!(extracted_name("a.bin"), "a.bin.content");
    }

    #[test]
    fn the_destination_probe_leaves_no_files() {
        let dir = tempfile::tempdir().unwrap();
        preflight_destination(&dir.path().join("x.p7s"), dir.path()).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let taken = dir.path().join("y.p7s");
        std::fs::write(&taken, b"x").unwrap();
        assert_eq!(
            preflight_destination(&taken, dir.path()),
            Err(JobError::DestinationExists)
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// F2, recorded: why the first synthetic world's mock TSA answered HTTP 400. The mock is
    /// not restricted and the SDK signs GOST time stamps: the committed GOST fixture, and the
    /// same key re-issued under a GOST root, are answered 200. Only a GOST key whose
    /// certificate was issued by the RSA test root is refused, by the CMS signer
    /// (`KeyError::UnsupportedAlgorithm`): the algorithm of the key and of its issuer must
    /// agree, as in the CLI's own worlds (an RSA TSA key under the RSA root, a GOST one under
    /// the GOST root).
    #[test]
    fn a_gost_time_stamp_is_signed_when_the_chain_agrees_and_refused_when_it_does_not() {
        use oncl_pki::http::{GetOptions, HttpRequest, HttpTransport};
        use oncl_pki::testing::{TestCertSpec, issue_cert};
        use oncl_pki::tsp::{MockTsa, TsaProfile, request_der};
        let ask = |tsa: oncl_pki::pkcs12::KeyEntry| {
            let request = request_der(
                &TsaProfile::kalkan_default(),
                &[7u8; 32],
                &[1, 2, 3, 4, 5, 6, 7, 8],
            );
            let reply = MockTsa::new(tsa)
                .with_gen_time(now())
                .send(&HttpRequest::post(
                    "http://tsa.test/tsa",
                    Some("application/timestamp-query"),
                    &request,
                    GetOptions::default(),
                ))
                .unwrap();
            (
                reply.status,
                String::from_utf8_lossy(&reply.body).into_owned(),
            )
        };
        let reissued = |issuer: &oncl_pki::pkcs12::KeyEntry| {
            let mut tsa = fixture("tsa-gost2015");
            let mut spec = TestCertSpec::from_cert(&tsa.cert);
            strip(&mut spec);
            spec.serial = vec![0x71, 4, 20];
            tsa.cert = issue_cert(issuer, spec);
            tsa
        };
        assert_eq!(
            ask(fixture("tsa-gost2015")).0,
            200,
            "the committed GOST fixture"
        );
        assert_eq!(
            ask(reissued(&fixture("root-gost2015.key"))).0,
            200,
            "under a GOST root"
        );
        let w = world();
        let (status, body) = ask(reissued(&w.root_entry));
        assert_eq!(status, 400, "under the RSA test root");
        assert!(
            body.contains("signature algorithm not supported for this key"),
            "{body}"
        );
    }

    /// SDK-level characterization, with no UI request builder: the engine applies the key and
    /// only then finds that a CAdES-LT has no evidence material, and reports it as a failure
    /// AFTER key use (`AppliedState::Applied`, "malformed CMS input"). The command line
    /// documents this ("sufficiency is still checked by the SDK and reported truthfully if it
    /// fails after key use") and refuses before any I/O itself; so does the workspace
    /// (`Evidence::require`). If the SDK ever refuses earlier this test fails and the host
    /// check can be revisited.
    #[test]
    fn the_sdk_applies_the_key_before_it_finds_lt_evidence_missing() {
        use oncl_core::keys::KeySelector;
        let w = world();
        let (engine, guard) = engine(&w);
        let alias = crate::signing::runner::open_key_store(&w.store, PASSWORD, now()).unwrap()[0]
            .alias
            .clone();
        let selector = KeySelector::inline(std::fs::read(&w.store).unwrap(), Some(alias));
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign]).with_keys([selector.key_id()]),
                OperationPolicy::strict_online(),
                control(),
            )
            .unwrap();
        guard.allow_for_tests(ctx.id().get(), selector.key_id(), Action::Sign, 1);
        let request = SignRequest::cades_create(
            vec![KeyRequest::new(&selector, Some(PASSWORD))],
            false,
            AdesLevel::Lt,
            ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            evidence_limits(),
        );
        let mut input: &[u8] = b"the document";
        let mut out = Vec::new();
        let error = engine
            .sign(
                request,
                Source::sequential(&mut input, Some(12)),
                &mut out,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::Applied, "{error:?}");
        assert_eq!(error.code(), ErrorCode::InvalidInput, "{error:?}");
        assert_eq!(guard.applications(), 1, "the key was applied once");
        assert!(out.is_empty(), "nothing was produced");
    }

    fn render_en(view: &BatchView) -> crate::reports::Rendered {
        crate::reports::render(oncl_flows::Locale::En, view)
    }

    fn sign_one(name: &str, w: &World, spec: &SignSpec, path: &Path) {
        let (view, applications) = signed(name, w, spec, std::slice::from_ref(&path.to_owned()));
        assert_eq!(applications, 1, "{name}");
        assert_eq!(
            view.headline(),
            Headline::AllSucceeded { total: 1 },
            "{name}"
        );
    }

    /// JWT claims through the report: a token whose signature is good but whose claims fail
    /// (the wrong issuer, the wrong audience, an expired token) is Invalid, styled as a
    /// failure, and says WHICH of the two it is; the signature itself is not called invalid.
    #[test]
    fn jwt_claim_failures_are_shown_as_claims_not_as_a_bad_signature() {
        let w = world();
        let claims = write(
            &w,
            "claims.json",
            b"{\"iss\":\"issuer\",\"aud\":\"audience\",\"exp\":1893456000}",
        );
        sign_one("jwt", &w, &spec(SignFormat::Jwt), &claims);
        let token = w.dir.path().join("claims.json.jwt");
        let check = |issuer: &str, audience: &str, path: &Path| {
            verify(
                &w,
                &ToolSpec::Verify(
                    VerifyFormat::Jwt,
                    VerifyOptions {
                        issuer: issuer.into(),
                        audience: audience.into(),
                        ..VerifyOptions::default()
                    },
                ),
                &[Document {
                    path: path.to_owned(),
                    second: None,
                }],
            )
            .unwrap()
        };
        let ok = check("issuer", "audience", &token);
        assert_eq!(verdicts(&ok), vec![Verdict::Valid]);
        assert!(
            render_en(&ok)
                .rows
                .iter()
                .any(|r| r.text == "JWT claims: hold")
        );
        for (issuer, audience, reason) in [
            ("other", "audience", "the issuer is not the expected one"),
            ("issuer", "other", "the audience is not the expected one"),
        ] {
            let view = check(issuer, audience, &token);
            assert_eq!(
                verdicts(&view),
                vec![Verdict::Invalid],
                "{issuer}/{audience}"
            );
            assert_eq!(view.tone(), Tone::Failure);
            let rendered = render_en(&view);
            let texts: Vec<&str> = rendered.rows.iter().map(|r| r.text.as_str()).collect();
            assert!(
                texts[0].contains("signature is valid, but the token's claims do not hold"),
                "{texts:?}"
            );
            assert!(!texts[0].contains("signature is invalid"), "{texts:?}");
            assert!(texts.contains(&"JWT claims: do not hold"), "{texts:?}");
            assert!(texts.contains(&reason), "{texts:?}");
            assert!(
                texts
                    .iter()
                    .any(|t| t.starts_with("Signer 1: the signature is valid"))
            );
        }
        let expired = write(
            &w,
            "old.json",
            b"{\"iss\":\"issuer\",\"aud\":\"audience\",\"exp\":1700000000}",
        );
        sign_one("jwt-expired", &w, &spec(SignFormat::Jwt), &expired);
        let view = check("issuer", "audience", &w.dir.path().join("old.json.jwt"));
        assert_eq!(verdicts(&view), vec![Verdict::Invalid]);
        assert!(
            render_en(&view)
                .rows
                .iter()
                .any(|r| r.text == "the token has expired")
        );
        // The same words in the other two languages (the claim failure is not left in English).
        for locale in [oncl_flows::Locale::Ru, oncl_flows::Locale::Kk] {
            let rendered = crate::reports::render(locale, &view);
            assert!(
                rendered
                    .rows
                    .iter()
                    .all(|r| !r.text.contains("the token has expired")),
                "{locale:?}"
            );
        }
    }

    /// WS-Security with «a timestamp is required»: a message signed without one is not Valid
    /// (the SDK refuses it as an unfit file, which the page shows as a failure, never as
    /// success), while the same message without the requirement is Valid.
    #[test]
    fn a_required_wsse_timestamp_that_is_missing_is_never_success() {
        let w = world();
        let soap = write(&w, "s.xml", SOAP);
        sign_one("wsse", &w, &spec(SignFormat::Wsse), &soap);
        let signed_message = w.dir.path().join("s.signed.xml");
        let document = Document {
            path: signed_message,
            second: None,
        };
        let plain = verify(
            &w,
            &ToolSpec::Verify(VerifyFormat::Wsse, VerifyOptions::default()),
            std::slice::from_ref(&document),
        )
        .unwrap();
        assert_eq!(verdicts(&plain), vec![Verdict::Valid]);
        let required = verify(
            &w,
            &ToolSpec::Verify(
                VerifyFormat::Wsse,
                VerifyOptions {
                    timestamp_required: true,
                    ..VerifyOptions::default()
                },
            ),
            &[document],
        )
        .unwrap();
        assert!(
            matches!(
                required.items[0].outcome,
                Outcome::Failed(ErrorCode::InvalidInput)
            ),
            "{:?}",
            required.items[0]
        );
        assert_ne!(required.tone(), Tone::Success);
        assert!(matches!(
            required.headline(),
            Headline::Partial {
                completed: 0,
                total: 1
            }
        ));
    }

    /// XML in Kalkan mode: the document the engine signed verifies in both modes, each with its
    /// own request, and a tampered document is Invalid in Kalkan mode too.
    #[test]
    fn xml_kalkan_mode_verifies_and_still_catches_tampering() {
        let w = world();
        let xml = write(&w, "x.xml", XML);
        sign_one(
            "xml",
            &w,
            &SignSpec {
                format: SignFormat::Xml,
                options: xml_ids(),
            },
            &xml,
        );
        let path = w.dir.path().join("x.signed.xml");
        for format in [VerifyFormat::Xml, VerifyFormat::XmlKalkan] {
            let view = verify(
                &w,
                &ToolSpec::Verify(format, VerifyOptions::default()),
                &[Document {
                    path: path.clone(),
                    second: None,
                }],
            )
            .unwrap();
            assert_eq!(verdicts(&view), vec![Verdict::Valid], "{format:?}");
        }
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace("protected", "changed!!");
        let tampered_path = w.dir.path().join("t.signed.xml");
        std::fs::write(&tampered_path, tampered).unwrap();
        let view = verify(
            &w,
            &ToolSpec::Verify(VerifyFormat::XmlKalkan, VerifyOptions::default()),
            &[Document {
                path: tampered_path,
                second: None,
            }],
        )
        .unwrap();
        assert_eq!(verdicts(&view), vec![Verdict::Invalid]);
        assert_eq!(view.tone(), Tone::Failure);
        assert!(
            render_en(&view)
                .rows
                .iter()
                .any(|r| r.text.contains("digest does not match")),
            "{:?}",
            render_en(&view).rows
        );
    }

    /// PDF: a document signed twice shows both signatures and, for the first revision, the note
    /// that the file was changed after it (a caution), and for the last that it was not; a file
    /// with bytes appended after the signature is not recognised (never a quiet success).
    #[test]
    fn a_pdf_signed_twice_says_the_first_revision_was_changed_after_signing() {
        let w = world();
        let pdf = pdf(&w);
        sign_one("pdf", &w, &spec(SignFormat::Pdf), &pdf);
        let once = w.dir.path().join("doc.signed.pdf");
        let single = verify(
            &w,
            &ToolSpec::Verify(VerifyFormat::Pdf, VerifyOptions::default()),
            &[Document {
                path: once.clone(),
                second: None,
            }],
        )
        .unwrap();
        assert!(
            render_en(&single)
                .rows
                .iter()
                .any(|r| r.text
                    == "Revision 1 (1 signature(s)): the file was not changed after signing"),
            "{:?}",
            render_en(&single).rows
        );
        sign_one("pdf-2", &w, &spec(SignFormat::Pdf), &once);
        let twice = w.dir.path().join("doc.signed.signed.pdf");
        let view = verify(
            &w,
            &ToolSpec::Verify(VerifyFormat::Pdf, VerifyOptions::default()),
            &[Document {
                path: twice,
                second: None,
            }],
        )
        .unwrap();
        assert_eq!(verdicts(&view), vec![Verdict::Valid]);
        let rendered = render_en(&view);
        let revision = |n: u32| {
            rendered
                .rows
                .iter()
                .find(|r| r.text.starts_with(&format!("Revision {n} ")))
                .unwrap_or_else(|| panic!("revision {n}: {:?}", rendered.rows))
        };
        assert_eq!(
            revision(1).text,
            "Revision 1 (1 signature(s)): later revisions exist after this signature (another signature or an allowed change)"
        );
        assert_eq!(revision(1).tone, Tone::Caution);
        assert_eq!(
            revision(2).text,
            "Revision 2 (1 signature(s)): the file was not changed after signing"
        );
        assert!(
            rendered
                .rows
                .iter()
                .any(|r| r.text == "Signer 2: the signature is valid")
        );
        let mut bytes = std::fs::read(&once).unwrap();
        bytes.extend_from_slice(b"\n% appended after signing\n");
        let appended = w.dir.path().join("appended.pdf");
        std::fs::write(&appended, bytes).unwrap();
        let refused = verify(
            &w,
            &ToolSpec::Verify(VerifyFormat::Pdf, VerifyOptions::default()),
            &[Document {
                path: appended,
                second: None,
            }],
        )
        .unwrap();
        assert!(
            matches!(
                refused.items[0].outcome,
                Outcome::Failed(ErrorCode::InvalidInput)
            ),
            "{:?}",
            refused.items[0]
        );
        assert_ne!(refused.tone(), Tone::Success);
    }

    /// The consent binds what is made: every option, and the evidence files, change the label
    /// the consent is bound to, and equal choices give equal labels.
    #[test]
    fn the_consent_label_binds_every_option_and_the_evidence_files() {
        let base = SignSpec {
            format: SignFormat::Cades(Level::Lt),
            options: SignOptions::default(),
        };
        let with = |f: &dyn Fn(&mut SignOptions)| {
            let mut spec = base.clone();
            f(&mut spec.options);
            spec.label()
        };
        assert_eq!(base.label(), base.clone().label());
        let variants = [
            with(&|o| o.attached = true),
            with(&|o| o.add = true),
            with(&|o| o.target = "t".into()),
            with(&|o| o.parent = "p".into()),
            with(&|o| o.signature_id = "i".into()),
            with(&|o| o.evidence.certificates = vec![PathBuf::from("c.der")]),
            with(&|o| o.evidence.ocsp = vec![PathBuf::from("o.ocsp")]),
            with(&|o| o.evidence.crls = vec![PathBuf::from("r.crl")]),
        ];
        let mut seen = std::collections::BTreeSet::from([base.label()]);
        for label in variants {
            assert!(
                seen.insert(label.clone()),
                "two choices share the label {label}"
            );
        }
        for other in [
            SignFormat::Cades(Level::Lta),
            SignFormat::Cms,
            SignFormat::Pades(Level::Lt),
        ] {
            let label = SignSpec {
                format: other,
                options: SignOptions::default(),
            }
            .label();
            assert!(seen.insert(label.clone()), "{label}");
        }
    }

    /// A time stamp service that does not answer is a network failure, not a file one: a T-level
    /// signature fails AFTER the key was applied, says so (the key was applied) and names the
    /// service in all three languages; a signature without a time stamp keeps the file wording
    /// for a file failure.
    #[test]
    fn an_unreachable_time_service_is_worded_as_the_network_after_key_use() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        let (engine, guard) = engine_without_tsa(&w);
        let outcome = sign_confirmed(
            &engine,
            &guard,
            &w,
            std::slice::from_ref(&text),
            &spec(SignFormat::Cades(Level::T)),
            &Destination::Beside,
        );
        let SignOutcome::Done(view) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(view.network, "T-level signing reaches the network");
        assert!(
            matches!(
                view.items[0].outcome,
                Outcome::Failed(ErrorCode::ValidationRequired)
            ),
            "{view:?}"
        );
        assert_eq!(
            view.items[0].applied,
            AppliedState::Applied,
            "the key was applied"
        );
        assert_eq!(view.tone(), Tone::Failure);
        for (locale, network, file, applied) in [
            (
                oncl_flows::Locale::En,
                "did not pass checks",
                "could not be read or written",
                "the key was applied",
            ),
            (
                oncl_flows::Locale::Ru,
                "не прошло проверки",
                "не удалось прочитать",
                "ключ был применён",
            ),
            (
                oncl_flows::Locale::Kk,
                "тексеруден өтпейтін",
                "оқу немесе жазу",
                "кілт қолданылды",
            ),
        ] {
            let row = crate::reports::render(locale, &view).rows[0].text.clone();
            assert!(
                row.contains(network) && row.contains(applied),
                "{locale:?}: {row}"
            );
            // A token that arrived and failed its checks is not called «a service did not answer».
            assert!(
                !row.contains("a service did not answer"),
                "{locale:?}: {row}"
            );
            assert!(!row.contains("служба не ответила") && !row.contains("қызмет жауап бермеді"));
            assert!(!row.contains(file), "{locale:?}: {row}");
            // A transport failure (Io) of a network family keeps the «did not answer» wording.
            let mut transport = view.clone();
            transport.items[0].outcome = Outcome::Failed(ErrorCode::Io);
            let said = crate::reports::render(locale, &transport).rows[0]
                .text
                .clone();
            assert!(
                said.contains("a service did not answer")
                    || said.contains("служба не ответила")
                    || said.contains("қызмет жауап бермеді"),
                "{locale:?}: {said}"
            );
            // The same Io failure of a pure-file family keeps the file wording.
            let mut local = view.clone();
            local.network = false;
            local.items[0].outcome = Outcome::Failed(ErrorCode::Io);
            assert!(
                crate::reports::render(locale, &local).rows[0]
                    .text
                    .contains(file)
            );
        }
        assert!(!ToolSpec::Extract.uses_network());
        assert!(spec(SignFormat::Cades(Level::T)).uses_network());
        assert!(!spec(SignFormat::Cades(Level::B)).uses_network());
        assert!(!spec(SignFormat::Cms).uses_network());
    }

    /// C2: extending with a time stamp service that does not answer returns ValidationRequired
    /// with no key use; it is worded as the service (not the certificate), has no key clause, and
    /// the file is not written, in all three languages.
    #[test]
    fn an_extend_with_an_unreachable_time_service_is_worded_as_the_service() {
        let w = world();
        let text = write(&w, "doc.txt", b"the document");
        signed(
            "cades-b",
            &w,
            &spec(SignFormat::Cades(Level::B)),
            std::slice::from_ref(&text),
        );
        let (engine, _) = engine_without_tsa(&w);
        let view = run_tool(
            &engine,
            &ToolSpec::Extend(ExtendFormat::Cms(Level::T), Evidence::default()),
            &[Document {
                path: w.dir.path().join("doc.txt.p7s"),
                second: Some(text),
            }],
            &Destination::Beside,
            NOW,
            &control(),
        )
        .unwrap();
        assert!(view.network);
        assert!(
            matches!(
                view.items[0].outcome,
                Outcome::Failed(ErrorCode::ValidationRequired)
            ),
            "{view:?}"
        );
        assert_eq!(view.items[0].applied, AppliedState::NotApplied);
        for (locale, said, certificate) in [
            (
                oncl_flows::Locale::En,
                "a service did not answer",
                "failed its checks",
            ),
            (
                oncl_flows::Locale::Ru,
                "служба не ответила",
                "не прошёл проверку",
            ),
            (
                oncl_flows::Locale::Kk,
                "қызмет жауап бермеді",
                "тексеруден өтпеді",
            ),
        ] {
            let row = crate::reports::render(locale, &view).rows[0].text.clone();
            assert!(row.contains(said), "{locale:?}: {row}");
            assert!(!row.contains(certificate), "{locale:?}: {row}");
            assert!(
                !row.contains("key") && !row.contains("ключ") && !row.contains("кілт"),
                "{row}"
            );
        }
        assert!(!w.dir.path().join("doc.txt.extended.p7s").exists());
    }
}
