//! The plugin ABI, version [`ABI_VERSION`]: what a plugin module exports, the host functions
//! it may import from [`IMPORT_MODULE`], and the CBOR values they exchange. The core and
//! the guest SDK both build on these definitions.
//!
//! # Exports
//!
//! A plugin is a WebAssembly module (wasm32) exporting:
//!
//! - `memory`: its linear memory;
//! - `oncl_abi_version() -> i32`: [`ABI_VERSION`];
//! - `oncl_alloc(len: i32) -> i32`: `len` bytes the host may write, `0` if they cannot be
//!   had; the buffer belongs to the guest;
//! - `oncl_free(ptr: i32, len: i32)`: gives back a buffer `oncl_alloc` returned;
//! - `oncl_process(ptr: i32, len: i32) -> i64`: answers one request. `ptr`/`len` is an
//!   [`Input`] the host wrote into a buffer from `oncl_alloc`, which the guest now owns (and
//!   frees). The result is [`pack`]ed: an [`Output`] in a buffer from `oncl_alloc`, which the
//!   host reads and gives back with `oncl_free`.
//!
//! # Host functions
//!
//! Every [`Import`] is `(ptr: i32, len: i32) -> i64`: the argument is a CBOR value in guest
//! memory, still owned by the guest; the result is a [`pack`]ed CBOR [`HostResult`] in a
//! buffer the host got from `oncl_alloc`, which the guest owns from then on. A host
//! function may only be called while `oncl_process` runs, and not from `oncl_alloc` or
//! `oncl_free` while the host is calling them.
//!
//! The CBOR is serde's data model as `ciborium` writes it, so a guest in another language
//! reads and writes:
//!
//! - a struct as a map keyed by its field names (text strings); a field with
//!   `#[serde(default)]` may be left out;
//! - a byte string ([`Bytes`]) as a CBOR byte string (major type 2), not an array of integers;
//! - `()` and `None` as `null`, `Some(v)` as `v`;
//! - a unit enum variant ([`ErrorCode`], [`Level`], [`Action`], [`MessageKind`],
//!   [`Method`]) as a text string, its name in `snake_case`;
//! - a [`HostResult`] (Rust's `Result`) as a map of one entry: `{"Ok": value}` or
//!   `{"Err": {"code": …, "message": …}}`, the keys as written.
//!
//! An argument a host function cannot decode is not a trap: the function answers
//! `{"Err": {"code": "invalid", …}}`. An [`Output`] the host cannot decode fails the request.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A byte string of the ABI: a CBOR byte string.
pub use serde_bytes::ByteBuf as Bytes;

/// The ABI version a plugin's `oncl_abi_version` returns.
pub const ABI_VERSION: u32 = 1;

/// The import module of the host functions.
pub const IMPORT_MODULE: &str = "oncl";

/// The names of the exports a plugin module has.
pub mod exports {
    /// The linear memory.
    pub const MEMORY: &str = "memory";
    /// `() -> i32`: [`ABI_VERSION`](super::ABI_VERSION).
    pub const ABI_VERSION: &str = "oncl_abi_version";
    /// `(len: i32) -> i32`: a buffer of `len` bytes.
    pub const ALLOC: &str = "oncl_alloc";
    /// `(ptr: i32, len: i32)`: gives back a buffer.
    pub const FREE: &str = "oncl_free";
    /// `(ptr: i32, len: i32) -> i64`: answers a request.
    pub const PROCESS: &str = "oncl_process";
}

/// Most bytes [`Import::Random`] returns at once.
pub const MAX_RANDOM: u32 = 1024;

/// `ptr` and `len` as one `i64`: `ptr` in the high 32 bits, `len` in the low ones.
pub fn pack(ptr: u32, len: u32) -> i64 {
    // The same 64 bits, read as signed: the WebAssembly i64.
    ((u64::from(ptr) << 32) | u64::from(len)) as i64
}

/// The `ptr` and `len` of a [`pack`]ed `i64`.
pub fn unpack(packed: i64) -> (u32, u32) {
    // The same 64 bits, read as unsigned; each half is a u32.
    let packed = packed as u64;
    ((packed >> 32) as u32, packed as u32)
}

/// CBOR of `value`.
///
/// # Panics
///
/// If `value`'s `Serialize` fails, which the ABI types never do.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("ABI values always encode");
    out
}

/// The value CBOR `bytes` hold: one value, nothing after it.
///
/// # Errors
///
/// [`ErrorCode::Invalid`] if `bytes` are not CBOR of a `T`, or have bytes after it.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, HostError> {
    let mut rest = bytes;
    let value = ciborium::from_reader(&mut rest)
        .map_err(|e| HostError::new(ErrorCode::Invalid, format!("malformed CBOR: {e}")))?;
    if !rest.is_empty() {
        return Err(HostError::new(
            ErrorCode::Invalid,
            format!("{} bytes after the CBOR value", rest.len()),
        ));
    }
    Ok(value)
}

/// What `oncl_process` gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// The request as the page sent it: a JSON text.
    pub request: String,
    /// The page's origin, if the connection sent one.
    pub origin: Option<String>,
    /// The language of OpenNCALayer's windows: `"ru"`, `"kk"` or `"en"`.
    pub locale: String,
}

/// What `oncl_process` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    /// The reply sent to the page as it is.
    pub response: String,
}

/// The outcome of a host function.
pub type HostResult<T> = Result<T, HostError>;

/// Why a host function failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostError {
    /// The kind of failure.
    pub code: ErrorCode,
    /// What happened, in English, for logs.
    pub message: String,
}

impl HostError {
    /// An error of `code`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        HostError {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for HostError {}

/// The kind of a [`HostError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Not allowed: outside the plugin's capabilities or allowlist.
    Denied,
    /// The arguments are wrong: malformed, or a handle that names nothing.
    Invalid,
    /// Over a limit: size, count.
    Limit,
    /// The operation failed (I/O, network, signing).
    Failed,
}

/// What a plugin may do beyond the basic host functions, as its manifest declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// `keys = true`.
    Keys,
    /// `dialogs = true`.
    Dialogs,
    /// `files = true`.
    Files,
    /// A non-empty `http`.
    Http,
}

/// A host function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Import {
    /// `log`: [`LogArgs`] → `()`.
    Log,
    /// `now`: `()` → `i64`, the time in Unix milliseconds.
    Now,
    /// `random`: [`RandomArgs`] → [`Bytes`], at most [`MAX_RANDOM`].
    Random,
    /// `cert_info`: [`CertArgs`] → [`CertInfo`].
    CertInfo,
    /// `keys_choose`: [`ChooseArgs`] → `Option<`[`Chosen`]`>`; `None` if the user cancels.
    KeysChoose,
    /// `keys_sign_cms`: [`SignCmsArgs`] → [`Bytes`], the DER CMS.
    KeysSignCms,
    /// `keys_sign_raw`: [`SignRawArgs`] → [`Bytes`], the signature.
    KeysSignRaw,
    /// `keys_sign_xml`: [`SignXmlArgs`] → [`Bytes`], the signed document.
    KeysSignXml,
    /// `keys_release`: [`Handle`] → `()`.
    KeysRelease,
    /// `dialog_message`: [`MessageArgs`] → `()`.
    DialogMessage,
    /// `dialog_confirm`: [`ConfirmArgs`] → `bool`; `false` if the user says no or closes it.
    DialogConfirm,
    /// `file_open`: `()` → `Option<`[`OpenedFile`]`>`; `None` if the user cancels.
    FileOpen,
    /// `file_save`: [`SaveArgs`] → `Option<String>`, the path written; `None` if the user
    /// cancels.
    FileSave,
    /// `http_request`: [`HttpArgs`] → [`HttpResponse`].
    HttpRequest,
}

impl Import {
    /// Every host function.
    pub const ALL: [Import; 14] = [
        Import::Log,
        Import::Now,
        Import::Random,
        Import::CertInfo,
        Import::KeysChoose,
        Import::KeysSignCms,
        Import::KeysSignRaw,
        Import::KeysSignXml,
        Import::KeysRelease,
        Import::DialogMessage,
        Import::DialogConfirm,
        Import::FileOpen,
        Import::FileSave,
        Import::HttpRequest,
    ];

    /// Its import name in [`IMPORT_MODULE`].
    pub fn name(&self) -> &'static str {
        match self {
            Import::Log => "log",
            Import::Now => "now",
            Import::Random => "random",
            Import::CertInfo => "cert_info",
            Import::KeysChoose => "keys_choose",
            Import::KeysSignCms => "keys_sign_cms",
            Import::KeysSignRaw => "keys_sign_raw",
            Import::KeysSignXml => "keys_sign_xml",
            Import::KeysRelease => "keys_release",
            Import::DialogMessage => "dialog_message",
            Import::DialogConfirm => "dialog_confirm",
            Import::FileOpen => "file_open",
            Import::FileSave => "file_save",
            Import::HttpRequest => "http_request",
        }
    }

    /// The capability it needs; `None` for the basic functions every plugin has.
    pub fn capability(&self) -> Option<Capability> {
        match self {
            Import::Log | Import::Now | Import::Random | Import::CertInfo => None,
            Import::KeysChoose
            | Import::KeysSignCms
            | Import::KeysSignRaw
            | Import::KeysSignXml
            | Import::KeysRelease => Some(Capability::Keys),
            Import::DialogMessage | Import::DialogConfirm => Some(Capability::Dialogs),
            Import::FileOpen | Import::FileSave => Some(Capability::Files),
            Import::HttpRequest => Some(Capability::Http),
        }
    }

    /// The host function imported as `name`.
    pub fn from_name(name: &str) -> Option<Import> {
        Import::ALL.into_iter().find(|i| i.name() == name)
    }
}

/// How important a [`LogArgs`] line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Something failed.
    Error,
    /// Something is off.
    Warn,
    /// What happened.
    Info,
    /// Details for debugging.
    Debug,
}

/// `log`: a line in OpenNCALayer's log, with the plugin's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogArgs {
    /// How important it is.
    pub level: Level,
    /// The line.
    pub message: String,
}

/// `random`: random bytes from the system's generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomArgs {
    /// How many, at most [`MAX_RANDOM`].
    pub len: u32,
}

/// `cert_info`: the details of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertArgs {
    /// The certificate, DER.
    pub der: Bytes,
}

/// The key usage bits of a certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    /// digitalSignature.
    pub digital_signature: bool,
    /// nonRepudiation (contentCommitment).
    pub non_repudiation: bool,
    /// keyEncipherment.
    pub key_encipherment: bool,
    /// keyAgreement.
    pub key_agreement: bool,
}

/// The details of a certificate, as the key dialog reads them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    /// First subject CN.
    pub subject_cn: Option<String>,
    /// The IIN of the subject's SERIALNUMBER.
    pub iin: Option<String>,
    /// The BIN of the subject's OU.
    pub bin: Option<String>,
    /// First subject O.
    pub organization: Option<String>,
    /// Lowercase hex of the serial's DER INTEGER content.
    pub serial_hex: String,
    /// Start of validity, Unix milliseconds.
    pub not_before: i64,
    /// End of validity, Unix milliseconds.
    pub not_after: i64,
    /// Extended key usage OIDs.
    pub ext_key_usages: Vec<String>,
    /// Key usage bits.
    pub key_usage: KeyUsage,
    /// OID of the certificate's signature algorithm.
    pub signature_alg_oid: String,
    /// OID of the subject public key algorithm.
    pub spki_alg_oid: String,
    /// The certificate as PEM.
    pub pem: String,
}

/// What a key is chosen for, as the dialogs word it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Signing.
    Sign,
    /// Authentication.
    Authenticate,
    /// The certificate's details only.
    KeyInfo,
}

/// The conditions a key must meet, as `signerParams` and `signingParams` of the basics
/// module. Absent fields: no condition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Filter {
    /// Extended key usage OIDs the certificate must all have.
    pub ext_key_usages: Vec<String>,
    /// Required IIN; empty: any.
    pub iin: String,
    /// Required BIN; empty: any.
    pub bin: String,
    /// Required serial number in hex; empty: any.
    pub serial_number: String,
    /// Whether an expired certificate may be picked.
    pub allow_expired: bool,
    /// The CA certificates (DER) the certificate must chain through; `None`: the NCA
    /// production CAs; empty: no path and no OCSP check.
    pub chain: Option<Vec<Bytes>>,
    /// Whether to skip the OCSP check.
    pub allow_revoked: bool,
}

/// `keys_choose`: the storage and key dialogs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChooseArgs {
    /// What the key is for.
    pub action: Action,
    /// Storage names (`PKCS12`, `JKS`, …) to offer; empty: PKCS#12 and JKS.
    #[serde(default)]
    pub storages: Vec<String>,
    /// The conditions a key must meet.
    #[serde(default)]
    pub filter: Filter,
    /// A line the dialogs show after the plugin's name, e.g. the document.
    #[serde(default)]
    pub detail: Option<String>,
}

/// The chosen key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chosen {
    /// The key, until `keys_release` or the end of the plugin instance.
    pub handle: u32,
    /// Its alias in the key store.
    pub alias: String,
    /// Its certificate, DER.
    pub certificate: Bytes,
}

/// `keys_sign_cms`: a CAdES signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignCmsArgs {
    /// The key.
    pub handle: u32,
    /// What to sign.
    pub data: Bytes,
    /// Whether the data goes into the CMS.
    pub attached: bool,
    /// Whether to time-stamp the signature (the basics TSA).
    pub timestamp: bool,
}

/// `keys_sign_raw`: a signature of the data with the key's algorithm (RSA: SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRawArgs {
    /// The key.
    pub handle: u32,
    /// What to sign.
    pub data: Bytes,
}

/// `keys_sign_xml`: an enveloped XMLDSig.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignXmlArgs {
    /// The key.
    pub handle: u32,
    /// The document, UTF-8.
    pub xml: Bytes,
    /// An XPath to the element to sign, which has an `Id` (absolute element paths, `[n]`
    /// steps and `//`); `None`: the whole document.
    #[serde(default)]
    pub element: Option<String>,
    /// An XPath to the element the signature goes into; `None`: the document element. Only
    /// with `element`.
    #[serde(default)]
    pub parent: Option<String>,
}

/// `keys_release`: a key the plugin no longer needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handle {
    /// The key.
    pub handle: u32,
}

/// How a [`MessageArgs`] looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Information.
    Info,
    /// A warning.
    Warning,
    /// An error.
    Error,
}

/// `dialog_message`: a message with an OK button.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageArgs {
    /// How it looks.
    pub kind: MessageKind,
    /// The text, shown as plain text.
    pub text: String,
}

/// `dialog_confirm`: a yes/no question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmArgs {
    /// The question, shown as plain text.
    pub text: String,
}

/// A file the user chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedFile {
    /// Its path.
    pub path: String,
    /// Its contents.
    pub data: Bytes,
}

/// `file_save`: data saved where the user chooses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveArgs {
    /// The file name the dialog suggests.
    pub suggested_name: String,
    /// The contents.
    pub data: Bytes,
}

/// An HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
}

/// `http_request`: one HTTPS request to a URL under the manifest's prefixes. Redirects are
/// not followed: a 3xx comes back with its `location`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpArgs {
    /// GET or POST.
    pub method: Method,
    /// The URL.
    pub url: String,
    /// The body's `Content-Type` of a POST.
    #[serde(default)]
    pub content_type: Option<String>,
    /// The body of a POST.
    #[serde(default)]
    pub body: Bytes,
}

/// The reply to an [`HttpArgs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Its `Content-Type`.
    pub content_type: Option<String>,
    /// The `Location` of a 3xx reply.
    pub location: Option<String>,
    /// The body.
    pub body: Bytes,
}
