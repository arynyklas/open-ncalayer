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
    /// Which failure of the core's it is, when a guest tells them apart: a stable
    /// `<area>.<variant>` string of [`mod@cause`]. Absent from older cores' errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

impl HostError {
    /// An error of `code`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        HostError {
            code,
            message: message.into(),
            cause: None,
        }
    }

    /// The same error naming its `cause` (one of [`mod@cause`]).
    #[must_use]
    pub fn with_cause(self, cause: &str) -> Self {
        HostError {
            cause: Some(cause.to_owned()),
            ..self
        }
    }

    /// Which failure of the core's it is, if the core says.
    pub fn cause(&self) -> Option<&str> {
        self.cause.as_deref()
    }
}

/// The causes a [`HostError`] names: `<area>.<variant>`, stable across cores. A failure of
/// a key inside a CMS or XML signature names the key's cause; one of a CMS inside a
/// time-stamp, the CMS's.
pub mod cause {
    /// A CMS without the content to verify or co-sign.
    pub const CMS_NO_ENCAPSULATED_DATA: &str = "cms.no_encapsulated_data";
    /// A CMS signer's algorithm the core does not sign or verify with.
    pub const CMS_UNKNOWN_ALGORITHM: &str = "cms.unknown_algorithm";
    /// A CMS that is not valid, or a value that cannot go into one.
    pub const CMS_MALFORMED: &str = "cms.malformed";
    /// A CMS signer without its certificate.
    pub const CMS_CERT_NOT_FOUND: &str = "cms.cert_not_found";
    /// A CMS signer whose messageDigest does not match the content.
    pub const CMS_DIGEST_MISMATCH: &str = "cms.digest_mismatch";
    /// A CMS signature that does not verify.
    pub const CMS_BAD_SIGNATURE: &str = "cms.bad_signature";
    /// A CMS signer whose signingCertificateV2 does not match its certificate.
    pub const CMS_SIGNING_CERTIFICATE_MISMATCH: &str = "cms.signing_certificate_mismatch";
    /// A CMS signature that cannot be made as asked.
    pub const CMS_CONSTRAINT: &str = "cms.constraint";
    /// An XML document that does not parse.
    pub const XML_PARSE: &str = "xml.parse";
    /// An XML document with a DOCTYPE.
    pub const XML_DOCTYPE: &str = "xml.doctype";
    /// An XML document over the processing limits.
    pub const XML_TOO_LARGE: &str = "xml.too_large";
    /// An XML document nested too deep.
    pub const XML_TOO_DEEP: &str = "xml.too_deep";
    /// An XPath outside the subset the core reads.
    pub const XML_XPATH: &str = "xml.xpath";
    /// An element to sign or a signature parent that breaks a signing rule.
    pub const XML_CONSTRAINT: &str = "xml.constraint";
    /// An XML signature algorithm the core does not sign or verify with.
    pub const XML_UNSUPPORTED_ALGORITHM: &str = "xml.unsupported_algorithm";
    /// An XML document without a signature.
    pub const XML_NO_SIGNATURE: &str = "xml.no_signature";
    /// An XML signature reference whose digest does not match.
    pub const XML_BAD_DIGEST: &str = "xml.bad_digest";
    /// An XML signature value that does not verify.
    pub const XML_BAD_SIGNATURE: &str = "xml.bad_signature";
    /// A key that does not decode.
    pub const KEY_MALFORMED: &str = "key.malformed";
    /// A key of an algorithm the core does not know.
    pub const KEY_UNKNOWN_KEY_ALGORITHM: &str = "key.unknown_key_algorithm";
    /// A signature algorithm the key cannot sign with.
    pub const KEY_UNSUPPORTED: &str = "key.unsupported";
    /// A private key that does not belong to its certificate.
    pub const KEY_MISMATCH: &str = "key.mismatch";
    /// A signature of the key that does not verify.
    pub const KEY_BAD_SIGNATURE: &str = "key.bad_signature";
    /// A private key that stays on its token.
    pub const KEY_NOT_EXPORTABLE: &str = "key.not_exportable";
    /// A token that failed or refused the operation.
    pub const KEY_TOKEN: &str = "key.token";
    /// No HTTP reply from the TSA.
    pub const TSP_HTTP: &str = "tsp.http";
    /// An HTTP status other than 200 from the TSA.
    pub const TSP_STATUS: &str = "tsp.status";
    /// A reply of another content type from the TSA.
    pub const TSP_CONTENT_TYPE: &str = "tsp.content_type";
    /// A request the TSA refused.
    pub const TSP_REJECTED: &str = "tsp.rejected";
    /// A time-stamp whose nonce is not the request's.
    pub const TSP_NONCE_MISMATCH: &str = "tsp.nonce_mismatch";
    /// A time-stamp whose message imprint is not the request's.
    pub const TSP_IMPRINT_MISMATCH: &str = "tsp.imprint_mismatch";
    /// A time-stamp of an imprint algorithm the core does not compute.
    pub const TSP_UNSUPPORTED_IMPRINT_ALGORITHM: &str = "tsp.unsupported_imprint_algorithm";
    /// A time-stamp of another policy.
    pub const TSP_POLICY_MISMATCH: &str = "tsp.policy_mismatch";
    /// A time-stamp without a TSA certificate with the timeStamping key usage.
    pub const TSP_NO_TSA_CERTIFICATE: &str = "tsp.no_tsa_certificate";
    /// A time-stamp whose genTime is too far from the core's clock.
    pub const TSP_CLOCK_SKEW: &str = "tsp.clock_skew";
    /// A TSA reply that is not a `TimeStampResp`.
    pub const TSP_MALFORMED: &str = "tsp.malformed";
    /// A file that is not a regular disk file a page may name, or cannot be read.
    pub const PAGE_FILE_NOT_FOUND: &str = "page_file.not_found";
    /// A file over the size the core reads.
    pub const PAGE_FILE_TOO_LARGE: &str = "page_file.too_large";
    /// A file type the chooser does not know.
    pub const FILE_UNKNOWN_KIND: &str = "file.unknown_kind";
    /// A key file's signature algorithm (or RSA length) the core does not generate.
    pub const KEYSTORE_UNKNOWN_ALGORITHM: &str = "keystore.unknown_algorithm";
    /// No key file of the folder opens with the password and holds the certificate's key.
    pub const KEYSTORE_KEYSTORE_FILE_NOT_FOUND: &str = "keystore.keystore_file_not_found";
    /// A certificate whose KeyStoreInfo names another storage.
    pub const KEYSTORE_UNSUITED_STORAGE: &str = "keystore.unsuited_storage";
    /// A key under the certificate's alias that is not the certificate's.
    pub const KEYSTORE_INAPPROPRIATE_CERT: &str = "keystore.inappropriate_cert";
    /// A key file that does not open with the password.
    pub const KEYSTORE_WRONG_PASSWORD: &str = "keystore.wrong_password";
    /// A new password that is empty or does not match the PKCS#12 pattern.
    pub const KEYSTORE_WRONG_PASSWORD_PATTERN: &str = "keystore.wrong_password_pattern";
    /// A key file without a key.
    pub const KEYSTORE_CHANGE_PASSWORD_CONSTRAINT: &str = "keystore.change_password_constraint";
    /// A certificate without a SubjectKeyIdentifier.
    pub const KEYSTORE_EXTENSION_NOT_FOUND: &str = "keystore.extension_not_found";
    /// A storage the core does not write.
    pub const KEYSTORE_UNSUPPORTED_STORAGE: &str = "keystore.unsupported_storage";
    /// A subject or alternative name that does not encode.
    pub const KEYSTORE_INVALID_REQUEST: &str = "keystore.invalid_request";
    /// A certificate extension that does not parse, or a value that does not encode.
    pub const KEYSTORE_MALFORMED: &str = "keystore.malformed";
    /// A file that cannot be read, written or renamed.
    pub const KEYSTORE_IO: &str = "keystore.io";
    /// A key file that is not a readable PKCS#12 key store.
    pub const KEYSTORE_PKCS12: &str = "keystore.pkcs12";
    /// A folder a page names that a page may not name.
    pub const KEYSTORE_FOLDER_REFUSED: &str = "keystore.folder.refused";
    /// A folder that is not an existing folder named by an absolute path.
    pub const KEYSTORE_FOLDER_MISSING: &str = "keystore.folder.missing";

    /// The steps of `keystore_new_key`. Its failure's cause is the step, `.` and the
    /// key file failure's variant: `keystore.generate.unknown_algorithm`,
    /// `csr.invalid_request`, `keystore.write.io` (the variant of [`KEYSTORE_IO`] after
    /// `keystore.`). A folder's failure is [`KEYSTORE_FOLDER_REFUSED`] or
    /// [`KEYSTORE_FOLDER_MISSING`].
    pub const NEW_KEY_STEPS: [&str; 3] = [KEYSTORE_GENERATE, CSR, KEYSTORE_WRITE];
    /// The new key.
    pub const KEYSTORE_GENERATE: &str = "keystore.generate";
    /// Its request.
    pub const CSR: &str = "csr";
    /// Its key file.
    pub const KEYSTORE_WRITE: &str = "keystore.write";

    /// The key file failures, `keystore.<variant>`.
    pub const KEYSTORE: [&str; 13] = [
        KEYSTORE_UNKNOWN_ALGORITHM,
        KEYSTORE_KEYSTORE_FILE_NOT_FOUND,
        KEYSTORE_UNSUITED_STORAGE,
        KEYSTORE_INAPPROPRIATE_CERT,
        KEYSTORE_WRONG_PASSWORD,
        KEYSTORE_WRONG_PASSWORD_PATTERN,
        KEYSTORE_CHANGE_PASSWORD_CONSTRAINT,
        KEYSTORE_EXTENSION_NOT_FOUND,
        KEYSTORE_UNSUPPORTED_STORAGE,
        KEYSTORE_INVALID_REQUEST,
        KEYSTORE_MALFORMED,
        KEYSTORE_IO,
        KEYSTORE_PKCS12,
    ];

    /// Every cause but the steps of `keystore_new_key` ([`NEW_KEY_STEPS`]).
    pub const ALL: &[&str] = &[
        CMS_NO_ENCAPSULATED_DATA,
        CMS_UNKNOWN_ALGORITHM,
        CMS_MALFORMED,
        CMS_CERT_NOT_FOUND,
        CMS_DIGEST_MISMATCH,
        CMS_BAD_SIGNATURE,
        CMS_SIGNING_CERTIFICATE_MISMATCH,
        CMS_CONSTRAINT,
        XML_PARSE,
        XML_DOCTYPE,
        XML_TOO_LARGE,
        XML_TOO_DEEP,
        XML_XPATH,
        XML_CONSTRAINT,
        XML_UNSUPPORTED_ALGORITHM,
        XML_NO_SIGNATURE,
        XML_BAD_DIGEST,
        XML_BAD_SIGNATURE,
        KEY_MALFORMED,
        KEY_UNKNOWN_KEY_ALGORITHM,
        KEY_UNSUPPORTED,
        KEY_MISMATCH,
        KEY_BAD_SIGNATURE,
        KEY_NOT_EXPORTABLE,
        KEY_TOKEN,
        TSP_HTTP,
        TSP_STATUS,
        TSP_CONTENT_TYPE,
        TSP_REJECTED,
        TSP_NONCE_MISMATCH,
        TSP_IMPRINT_MISMATCH,
        TSP_UNSUPPORTED_IMPRINT_ALGORITHM,
        TSP_POLICY_MISMATCH,
        TSP_NO_TSA_CERTIFICATE,
        TSP_CLOCK_SKEW,
        TSP_MALFORMED,
        PAGE_FILE_NOT_FOUND,
        PAGE_FILE_TOO_LARGE,
        FILE_UNKNOWN_KIND,
        KEYSTORE_UNKNOWN_ALGORITHM,
        KEYSTORE_KEYSTORE_FILE_NOT_FOUND,
        KEYSTORE_UNSUITED_STORAGE,
        KEYSTORE_INAPPROPRIATE_CERT,
        KEYSTORE_WRONG_PASSWORD,
        KEYSTORE_WRONG_PASSWORD_PATTERN,
        KEYSTORE_CHANGE_PASSWORD_CONSTRAINT,
        KEYSTORE_EXTENSION_NOT_FOUND,
        KEYSTORE_UNSUPPORTED_STORAGE,
        KEYSTORE_INVALID_REQUEST,
        KEYSTORE_MALFORMED,
        KEYSTORE_IO,
        KEYSTORE_PKCS12,
        KEYSTORE_FOLDER_REFUSED,
        KEYSTORE_FOLDER_MISSING,
    ];

    /// Whether `cause` is one the core names: one of [`ALL`], or a step of
    /// `keystore_new_key` with a key file failure's variant.
    pub fn is_known(cause: &str) -> bool {
        ALL.contains(&cause)
            || NEW_KEY_STEPS.iter().any(|step| {
                cause
                    .strip_prefix(step)
                    .and_then(|rest| rest.strip_prefix('.'))
                    .is_some_and(|variant| {
                        KEYSTORE
                            .iter()
                            .any(|k| k.strip_prefix("keystore.") == Some(variant))
                    })
            })
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
    /// A non-empty `http`, `origins` or `http_insecure`.
    Http,
    /// `page_files = true`.
    PageFiles,
    /// `settings = true`.
    Settings,
    /// `shared = true`.
    Shared,
    /// `builtin = true`: reserved for the core's own modules.
    Builtin,
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
    /// `reply_drop`: `()` → `()`. The request being answered ends with the connection
    /// dropped, without a reply; the plugin still returns its [`Output`], which is not sent.
    ReplyDrop,
    /// `hash`: [`HashArgs`] → [`Bytes`], the digest.
    Hash,
    /// `cert_details`: [`CertArgs`] → [`CertDetails`].
    CertDetails,
    /// `local_time`: [`LocalTimeArgs`] → [`LocalTime`], the system's time zone then.
    LocalTime,
    /// `platform`: `()` → [`Platform`].
    Platform,
    /// `ca_list`: `()` → `Vec<`[`Bytes`]`>`, the NCA CA certificates the core trusts.
    CaList,
    /// `ca_issuer`: [`CertArgs`] → `Option<`[`Bytes`]`>`, the CA certificate that issued it.
    CaIssuer,
    /// `keys_select`: [`SelectArgs`] → `Option<`[`Chosen`]`>`; `None` if the user cancels.
    KeysSelect,
    /// `keys_chain`: [`Handle`] → `Vec<`[`Bytes`]`>`, the key's certificate chain from it up.
    KeysChain,
    /// `keys_terminals`: [`TerminalsArgs`] → `Vec<String>`, the readers of a token storage.
    KeysTerminals,
    /// `keys_open`: [`OpenArgs`] → [`OpenOutcome`].
    KeysOpen,
    /// `dialog_password`: [`PasswordArgs`] → `Option<`[`SecretRef`]`>`; `None` if the user
    /// cancels. An instance keeps the 8 newest passwords; an older id is `invalid`.
    DialogPassword,
    /// `keys_sign_cms_ex`: [`SignCmsExArgs`] → [`CmsOutcome`].
    KeysSignCmsEx,
    /// `tsp_stamp`: [`StampArgs`] → [`StampOutcome`].
    TspStamp,
    /// `tsp_request`: [`TspRequestArgs`] → [`TspOutcome`].
    TspRequest,
    /// `ocsp_fetch`: [`OcspArgs`] → [`OcspOutcome`].
    OcspFetch,
    /// `crl_fetch`: [`CrlArgs`] → [`CrlOutcome`].
    CrlFetch,
    /// `cms_verify`: [`VerifyArgs`] → [`VerifyReport`].
    CmsVerify,
    /// `keys_sign_xml_ex`: [`SignXmlExArgs`] → [`Bytes`], the signed document.
    KeysSignXmlEx,
    /// `xml_verify`: [`XmlVerifyArgs`] → `Vec<`[`XmlSigReport`]`>`.
    XmlVerify,
    /// `http_request_ex`: [`HttpExArgs`] → [`HttpResponse`].
    HttpRequestEx,
    /// `file_choose`: [`ChooseFileArgs`] → `Option<`[`ChosenPath`]`>`; `None` if the user
    /// cancels.
    FileChoose,
    /// `file_open_ex`: [`ChooseFileArgs`] → `Option<`[`OpenedFile`]`>`; `None` if the user
    /// cancels.
    FileOpenEx,
    /// `page_file_read`: [`PagePathArgs`] → [`PageRead`].
    PageFileRead,
    /// `page_file_write`: [`PageWriteArgs`] → [`PageWrite`].
    PageFileWrite,
    /// `dialog_choice`: [`ChoiceArgs`] → `Option<u8>`; `None` if the user closes it.
    DialogChoice,
    /// `settings_get`: `()` → `BTreeMap<String, String>`.
    SettingsGet,
    /// `settings_put`: `BTreeMap<String, String>` → `()`.
    SettingsPut,
    /// `shared_get`: [`SharedKey`] → `Option<`[`Bytes`]`>`.
    SharedGet,
    /// `shared_put`: [`SharedPut`] → `()`.
    SharedPut,
    /// `keys_sign_xades`: [`XadesArgs`] → [`XadesOutcome`].
    KeysSignXades,
    /// `call_locale`: [`LocaleArgs`] → `()`: the language of the windows for the rest of
    /// the call.
    CallLocale,
    /// `core_modules`: `()` → [`CoreModules`].
    CoreModules,
    /// `core_bundles`: `()` → [`CoreBundles`].
    CoreBundles,
    /// `core_install_bundle`: [`InstallBundleArgs`] → `bool`, whether a plugin porting the
    /// bundle is offered to the user; the page's origin is the call's.
    CoreInstallBundle,
    /// `core_open_window`: [`WindowArgs`] → `()`, the window opened in the background.
    CoreOpenWindow,
    /// `keys_flow_open`: [`FlowArgs`] → [`FlowOutcome`]: the storage dialog of a key choice
    /// with the flow's rules; the opened flow lasts until the call returns.
    KeysFlowOpen,
    /// `keys_flow_pick`: [`PickArgs`] → `Option<`[`Chosen`]`>`: the key dialog of an opened
    /// flow; `None` if the user cancels.
    KeysFlowPick,
    /// `keys_describe`: [`Handle`] → [`KeyDescription`].
    KeysDescribe,
    /// `tokens_scan`: `()` → [`TokenScan`].
    TokensScan,
    /// `dialog_reader`: [`ReaderArgs`] → `Option<String>`, the reader chosen; `None` if the
    /// user cancels.
    DialogReader,
    /// `file_choose_kind`: [`FileKindArgs`] → `Option<String>`, the path of an existing file
    /// or folder the user chose; `None` if the user cancels.
    FileChooseKind,
    /// `pkix_path`: [`PathArgs`] → [`PathOutcome`].
    PkixPath,
    /// `dialog_csr`: [`CsrDialogArgs`] → `Option<`[`CsrChoice`]`>`: the `generateCsr`
    /// window; `None` if the user cancels.
    DialogCsr,
    /// `dialog_import`: [`ImportDialogArgs`] → `Option<`[`ImportChoice`]`>`: the
    /// `importCertificate` window; `None` if the user cancels.
    DialogImport,
    /// `keystore_new_key`: [`NewKeyArgs`] → [`NewKey`]: a key in a new key file and its
    /// request.
    KeystoreNewKey,
    /// `keystore_install_cert`: [`InstallCertArgs`] → [`InstalledCert`].
    KeystoreInstallCert,
    /// `keystore_change_password`: [`ChangePasswordArgs`] → `()`.
    KeystoreChangePassword,
    /// `tokens_id_card`: [`ReaderName`] → [`IdCardHolder`].
    TokensIdCard,
}

impl Import {
    /// Every host function.
    pub const ALL: [Import; 63] = [
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
        Import::ReplyDrop,
        Import::Hash,
        Import::CertDetails,
        Import::LocalTime,
        Import::Platform,
        Import::CaList,
        Import::CaIssuer,
        Import::KeysSelect,
        Import::KeysChain,
        Import::KeysTerminals,
        Import::KeysOpen,
        Import::DialogPassword,
        Import::KeysSignCmsEx,
        Import::TspStamp,
        Import::TspRequest,
        Import::OcspFetch,
        Import::CrlFetch,
        Import::CmsVerify,
        Import::KeysSignXmlEx,
        Import::XmlVerify,
        Import::HttpRequestEx,
        Import::FileChoose,
        Import::FileOpenEx,
        Import::PageFileRead,
        Import::PageFileWrite,
        Import::DialogChoice,
        Import::SettingsGet,
        Import::SettingsPut,
        Import::SharedGet,
        Import::SharedPut,
        Import::KeysSignXades,
        Import::CallLocale,
        Import::CoreModules,
        Import::CoreBundles,
        Import::CoreInstallBundle,
        Import::CoreOpenWindow,
        Import::KeysFlowOpen,
        Import::KeysFlowPick,
        Import::KeysDescribe,
        Import::TokensScan,
        Import::DialogReader,
        Import::FileChooseKind,
        Import::PkixPath,
        Import::DialogCsr,
        Import::DialogImport,
        Import::KeystoreNewKey,
        Import::KeystoreInstallCert,
        Import::KeystoreChangePassword,
        Import::TokensIdCard,
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
            Import::ReplyDrop => "reply_drop",
            Import::Hash => "hash",
            Import::CertDetails => "cert_details",
            Import::LocalTime => "local_time",
            Import::Platform => "platform",
            Import::CaList => "ca_list",
            Import::CaIssuer => "ca_issuer",
            Import::KeysSelect => "keys_select",
            Import::KeysChain => "keys_chain",
            Import::KeysTerminals => "keys_terminals",
            Import::KeysOpen => "keys_open",
            Import::DialogPassword => "dialog_password",
            Import::KeysSignCmsEx => "keys_sign_cms_ex",
            Import::TspStamp => "tsp_stamp",
            Import::TspRequest => "tsp_request",
            Import::OcspFetch => "ocsp_fetch",
            Import::CrlFetch => "crl_fetch",
            Import::CmsVerify => "cms_verify",
            Import::KeysSignXmlEx => "keys_sign_xml_ex",
            Import::XmlVerify => "xml_verify",
            Import::HttpRequestEx => "http_request_ex",
            Import::FileChoose => "file_choose",
            Import::FileOpenEx => "file_open_ex",
            Import::PageFileRead => "page_file_read",
            Import::PageFileWrite => "page_file_write",
            Import::DialogChoice => "dialog_choice",
            Import::SettingsGet => "settings_get",
            Import::SettingsPut => "settings_put",
            Import::SharedGet => "shared_get",
            Import::SharedPut => "shared_put",
            Import::KeysSignXades => "keys_sign_xades",
            Import::CallLocale => "call_locale",
            Import::CoreModules => "core_modules",
            Import::CoreBundles => "core_bundles",
            Import::CoreInstallBundle => "core_install_bundle",
            Import::CoreOpenWindow => "core_open_window",
            Import::KeysFlowOpen => "keys_flow_open",
            Import::KeysFlowPick => "keys_flow_pick",
            Import::KeysDescribe => "keys_describe",
            Import::TokensScan => "tokens_scan",
            Import::DialogReader => "dialog_reader",
            Import::FileChooseKind => "file_choose_kind",
            Import::PkixPath => "pkix_path",
            Import::DialogCsr => "dialog_csr",
            Import::DialogImport => "dialog_import",
            Import::KeystoreNewKey => "keystore_new_key",
            Import::KeystoreInstallCert => "keystore_install_cert",
            Import::KeystoreChangePassword => "keystore_change_password",
            Import::TokensIdCard => "tokens_id_card",
        }
    }

    /// The capability it needs; `None` for the basic functions every plugin has.
    pub fn capability(&self) -> Option<Capability> {
        match self {
            Import::Log
            | Import::Now
            | Import::Random
            | Import::CertInfo
            | Import::ReplyDrop
            | Import::Hash
            | Import::CertDetails
            | Import::LocalTime
            | Import::Platform
            | Import::CaList
            | Import::CaIssuer
            | Import::CallLocale
            | Import::PkixPath => None,
            Import::KeysChoose
            | Import::KeysSignCms
            | Import::KeysSignRaw
            | Import::KeysSignXml
            | Import::KeysRelease
            | Import::KeysSelect
            | Import::KeysChain
            | Import::KeysTerminals
            | Import::KeysOpen
            | Import::KeysSignCmsEx
            | Import::TspStamp
            | Import::TspRequest
            | Import::OcspFetch
            | Import::CrlFetch
            | Import::CmsVerify
            | Import::KeysSignXmlEx
            | Import::XmlVerify
            | Import::KeysSignXades
            | Import::KeysFlowOpen
            | Import::KeysFlowPick
            | Import::KeysDescribe
            | Import::TokensScan
            | Import::DialogReader => Some(Capability::Keys),
            Import::DialogMessage
            | Import::DialogConfirm
            | Import::DialogPassword
            | Import::DialogChoice => Some(Capability::Dialogs),
            Import::FileOpen
            | Import::FileSave
            | Import::FileChoose
            | Import::FileOpenEx
            | Import::FileChooseKind => Some(Capability::Files),
            Import::HttpRequest | Import::HttpRequestEx => Some(Capability::Http),
            Import::PageFileRead | Import::PageFileWrite => Some(Capability::PageFiles),
            Import::SettingsGet | Import::SettingsPut => Some(Capability::Settings),
            Import::SharedGet | Import::SharedPut => Some(Capability::Shared),
            Import::CoreModules
            | Import::CoreBundles
            | Import::CoreInstallBundle
            | Import::CoreOpenWindow
            | Import::DialogCsr
            | Import::DialogImport
            | Import::KeystoreNewKey
            | Import::KeystoreInstallCert
            | Import::KeystoreChangePassword
            | Import::TokensIdCard => Some(Capability::Builtin),
        }
    }

    /// The core version it appeared in: a plugin importing it needs at least that core
    /// (its manifest's `min_core`). A core without it refuses to load the plugin
    /// ([`IMPORT_MODULE`] imports are linked by name).
    pub fn since(&self) -> semver::Version {
        let version = match self {
            // The first core with plugins.
            Import::Log
            | Import::Now
            | Import::Random
            | Import::CertInfo
            | Import::KeysChoose
            | Import::KeysSignCms
            | Import::KeysSignRaw
            | Import::KeysSignXml
            | Import::KeysRelease
            | Import::DialogMessage
            | Import::DialogConfirm
            | Import::FileOpen
            | Import::FileSave
            | Import::HttpRequest => "0.1.0-alpha.3",
            // The plugin ports' functions.
            Import::ReplyDrop
            | Import::Hash
            | Import::CertDetails
            | Import::LocalTime
            | Import::Platform
            | Import::CaList
            | Import::CaIssuer
            | Import::KeysSelect
            | Import::KeysChain
            | Import::KeysTerminals
            | Import::KeysOpen
            | Import::DialogPassword
            | Import::KeysSignCmsEx
            | Import::TspStamp
            | Import::TspRequest
            | Import::OcspFetch
            | Import::CrlFetch
            | Import::CmsVerify
            | Import::KeysSignXmlEx
            | Import::XmlVerify
            | Import::HttpRequestEx
            | Import::FileChoose
            | Import::FileOpenEx
            | Import::PageFileRead
            | Import::PageFileWrite
            | Import::DialogChoice
            | Import::SettingsGet
            | Import::SettingsPut
            | Import::SharedGet
            | Import::SharedPut
            | Import::KeysSignXades => "0.1.0-alpha.4",
            // The built-in modules' functions.
            Import::CallLocale
            | Import::CoreModules
            | Import::CoreBundles
            | Import::CoreInstallBundle
            | Import::CoreOpenWindow
            | Import::KeysFlowOpen
            | Import::KeysFlowPick
            | Import::KeysDescribe
            | Import::TokensScan
            | Import::DialogReader
            | Import::FileChooseKind
            | Import::PkixPath
            | Import::DialogCsr
            | Import::DialogImport
            | Import::KeystoreNewKey
            | Import::KeystoreInstallCert
            | Import::KeystoreChangePassword
            | Import::TokensIdCard => "0.1.0-alpha.5",
        };
        semver::Version::parse(version).expect("a valid version")
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

// The functions the plugin ports need.

/// A digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlg {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
    /// GOST 34.311-95 (Kalkan's parameters).
    Gost34311,
    /// GOST 34.11-2015, 256 bits.
    Streebog256,
    /// GOST 34.11-2015, 512 bits.
    Streebog512,
}

/// `hash`: the digest of the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashArgs {
    /// The algorithm.
    pub alg: HashAlg,
    /// The data.
    pub data: Bytes,
}

/// The details of a certificate as Kalkan renders them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertDetails {
    /// The subject as Kalkan writes it (`CN=…,SURNAME=…,C=KZ`).
    pub subject_dn: String,
    /// The issuer, likewise.
    pub issuer_dn: String,
    /// Kalkan's types (`SIGNATURE`, `AUTHENTICATION`, `SSL`, `OCSP_RESPONSE_SIGNING`,
    /// `TSP_SIGNING`), in that order; empty where Kalkan has no type for it.
    pub knca_types: Vec<String>,
    /// Lowercase hex of the subjectKeyIdentifier.
    pub ski_hex: Option<String>,
    /// Lowercase hex of the keyIdentifier of the authorityKeyIdentifier.
    pub aki_hex: Option<String>,
    /// The serial number in decimal.
    pub serial_dec: String,
    /// The OCSP URLs of the authorityInfoAccess, in order.
    pub ocsp_urls: Vec<String>,
    /// The CA issuer URLs of the authorityInfoAccess, in order.
    pub ca_issuers_urls: Vec<String>,
    /// The `http(s)` URLs of the CRL distribution points, in order.
    pub crl_urls: Vec<String>,
    /// The algorithm the key signs with: `gost2004`, `gost2015_512`, `rsa_sha256` or
    /// `rsa_sha1`; `None` for another.
    pub signing_alg: Option<String>,
    /// The common name of the issuer. Absent from older cores' details.
    #[serde(default)]
    pub issuer_cn: Option<String>,
}

/// `local_time`: the offset of the system's time zone at an instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTimeArgs {
    /// The instant, Unix milliseconds.
    pub unix_ms: i64,
}

/// The system's time zone at an instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTime {
    /// The offset from UTC, seconds (east positive).
    pub offset_seconds: i32,
}

/// An operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
    /// Linux and other Unix systems.
    Linux,
}

/// The system the core runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// The operating system.
    pub os: Os,
    /// Its line separator: `"\r\n"` on Windows, `"\n"` elsewhere.
    pub line_separator: String,
}

/// A key usage bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsageBit {
    /// digitalSignature.
    DigitalSignature,
    /// nonRepudiation (contentCommitment).
    NonRepudiation,
    /// keyEncipherment.
    KeyEncipherment,
    /// keyAgreement.
    KeyAgreement,
}

/// Conditions of [`SelectArgs`] beyond [`Filter`]. Absent fields: no condition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterMore {
    /// Extended key usage OIDs of which the certificate must have at least one.
    pub any_ext_key_usages: Vec<String>,
    /// Extended key usage OIDs the certificate must not have.
    pub exclude_ext_key_usages: Vec<String>,
    /// Kalkan types (`SIGNATURE`, `AUTHENTICATION`, …) of which the certificate must be at
    /// least one.
    pub knca_types: Vec<String>,
    /// The required BIN, or for a certificate without one the IIN; empty: any.
    pub tin: String,
    /// Key usage bits the certificate must all have.
    pub key_usage: Vec<KeyUsageBit>,
    /// A requested clientAuth also accepts every GOST 2015-512 certificate and sha256RSA
    /// certificates with keyEncipherment.
    pub obsolete_auth: bool,
}

/// The order of the keys in the key dialog.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrder {
    /// The latest notBefore first.
    #[default]
    NewestFirst,
    /// The earliest notBefore first.
    OldestFirst,
}

/// `keys_select`: `keys_choose` with more conditions and the dialogs' order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectArgs {
    /// What the key is for.
    pub action: Action,
    /// Storage names to offer; empty: PKCS#12 and JKS.
    #[serde(default)]
    pub storages: Vec<String>,
    /// The conditions of `keys_choose`.
    #[serde(default)]
    pub filter: Filter,
    /// More conditions.
    #[serde(default)]
    pub more: FilterMore,
    /// A line the dialogs show after the plugin's name.
    #[serde(default)]
    pub detail: Option<String>,
    /// A key store path the storage dialog starts with, if a page may name it (a local
    /// file, or a network path the user chose before); otherwise the dialog starts as usual.
    #[serde(default)]
    pub initial_path: Option<String>,
    /// The order of the keys.
    #[serde(default)]
    pub order: KeyOrder,
}

/// `keys_terminals`: the readers of a token storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalsArgs {
    /// The storage's Kalkan name (`AKKaztokenStore`, …).
    pub storage: String,
}

/// Where `keys_open` reads a key store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// A file the page names (manifest `key_files = true`).
    PagePath(String),
    /// The key store itself.
    Bytes(Bytes),
    /// A token in this reader ([`Import::KeysTerminals`]).
    Terminal(String),
}

/// The password of a key store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Password {
    /// As text.
    Text(String),
    /// The id of a password the user typed in `dialog_password`, which the guest never saw.
    Secret(u32),
}

/// `keys_open`: a key store the plugin names, every key in it opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenArgs {
    /// The storage's Kalkan name: `PKCS12`, `JKS`, or a token.
    pub storage: String,
    /// Where it is.
    pub source: KeySource,
    /// Its password.
    pub password: Password,
}

/// A key of an opened store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedKey {
    /// The key, until `keys_release` or the end of the plugin instance.
    pub handle: u32,
    /// Its alias in the key store.
    pub alias: String,
    /// Its certificate, DER.
    pub certificate: Bytes,
}

/// What `keys_open` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenOutcome {
    /// Every key of the store with a certificate, in store order.
    Opened(Vec<OpenedKey>),
    /// The password is wrong; a token may say how many tries are left.
    WrongPassword {
        /// Tries left before the token blocks, if it says.
        tries_left: Option<u8>,
    },
    /// The token is blocked.
    Blocked,
    /// No such token or reader.
    NoDevice,
    /// No such file, or not one a page may name.
    NotFound,
    /// Not a key store of the storage, or too large.
    Corrupt,
    /// The store holds no key with a certificate.
    NoKeys,
    /// The user did not allow the page to open the file, or to send its PIN to the token.
    Declined,
}

/// `dialog_password`: a password the user types, which stays in the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordArgs {
    /// The heading.
    pub title: String,
    /// The text above the field.
    pub label: String,
    /// The OK button's text.
    pub ok: String,
    /// The Cancel button's text.
    pub cancel: String,
    /// Whether an empty password is an answer.
    pub allow_empty: bool,
}

/// A password the user typed, by id: for [`Password::Secret`] of this plugin instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    /// The id.
    pub id: u32,
}

// CMS by profile, time-stamps, OCSP and CRL: the core makes every request, only to the
// PKI hosts.

/// The longest timeout of a request to a PKI service, milliseconds.
pub const MAX_PKI_TIMEOUT_MS: u32 = 60_000;

/// The most repeats of a time-stamp request.
pub const MAX_TSP_RETRIES: u8 = 10;

/// What [`SignCmsExArgs`] signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmsContent {
    /// The content; messageDigest is its hash.
    Data(Bytes),
    /// The content's hash: messageDigest as it is. Never encapsulated.
    Digest(Bytes),
}

/// Whether [`SignCmsExArgs`] adds its signer to an existing CMS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoSign {
    /// As Kalkan's `createCAdES`: content that is a CMS with encapsulated content gets
    /// co-signed.
    #[default]
    Auto,
    /// Never.
    Never,
    /// Into this CMS: its signers kept, the new one over the content added.
    Into(Bytes),
}

/// When a signingTime is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    /// The core's clock.
    Now,
    /// This instant, Unix milliseconds.
    UnixMs(i64),
}

/// How a signingTime is encoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeForm {
    /// RFC 5652: UTCTime for 1950–2049, GeneralizedTime otherwise.
    #[default]
    Auto,
    /// UTCTime.
    Utc,
    /// GeneralizedTime.
    Generalized,
}

/// The signingTime attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningTime {
    /// When.
    pub at: TimeSource,
    /// The encoding.
    #[serde(default)]
    pub form: TimeForm,
}

/// A signed attribute the plugin encodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAttribute {
    /// The attribute type, a dotted OID.
    pub oid: String,
    /// Its values, each a DER value.
    pub values: Vec<Bytes>,
}

/// The signed attributes of [`SignCmsExArgs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttrs {
    /// contentType.
    pub content_type: bool,
    /// messageDigest.
    pub message_digest: bool,
    /// signingCertificateV2 with the SHA-256 of the signer certificate.
    pub signing_certificate_v2: bool,
    /// signingTime.
    #[serde(default)]
    pub signing_time: Option<SigningTime>,
    /// Other attributes, none of a type a flag above adds; sorted into the DER SET.
    #[serde(default)]
    pub extra: Vec<RawAttribute>,
}

/// The certificates of [`SignCmsExArgs`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmsCerts {
    /// The signer certificate.
    #[default]
    Signer,
    /// The key's chain ([`Import::KeysChain`]).
    Chain,
    /// The signer certificate and these.
    Extra(Vec<Bytes>),
}

/// `keys_sign_cms_ex`: a CMS signature by profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignCmsExArgs {
    /// The key.
    pub handle: u32,
    /// What is signed.
    pub content: CmsContent,
    /// Put the content into the CMS.
    pub encapsulate: bool,
    /// Co-signing.
    #[serde(default)]
    pub cosign: CoSign,
    /// The eContentType, a dotted OID; `None`: id-data (or the co-signed CMS's).
    #[serde(default)]
    pub econtent_type: Option<String>,
    /// The digest; `None`: the certificate's. Only that one is accepted.
    #[serde(default)]
    pub digest: Option<HashAlg>,
    /// The signed attributes.
    pub attrs: SignedAttrs,
    /// The certificates.
    #[serde(default)]
    pub certificates: CmsCerts,
    /// A time-stamp on the new signer, replacing none.
    #[serde(default)]
    pub timestamp: Option<TsaChoice>,
    /// The form of [`CmsOutcome::Signed`]: the core encodes it, so the module never holds
    /// the DER beside its text.
    #[serde(default)]
    pub output: CmsOutput,
}

/// The form of the CMS `keys_sign_cms_ex` returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmsOutput {
    /// DER.
    #[default]
    Der,
    /// Base64 (standard alphabet, padded) of the DER, as ASCII bytes.
    Base64,
    /// `-----BEGIN CMS-----`, the base64 in lines of 64 characters, `-----END CMS-----`,
    /// each line ended by the core's line separator ([`Platform::line_separator`]), as
    /// ASCII bytes.
    Pem,
}

/// What `keys_sign_cms_ex` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmsOutcome {
    /// The DER CMS.
    Signed(Bytes),
    /// Signed, but the time-stamp failed.
    TspFailed(NetFailure),
}

/// The signers [`StampArgs`] time-stamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerSel {
    /// The last one.
    Last,
    /// The one at this index.
    Index(u32),
    /// Every one without a time-stamp yet.
    AllUnstamped,
    /// The first one of this certificate (DER), as Kalkan finds a signer;
    /// [`StampOutcome::NoSigner`] without one.
    OfCert(Bytes),
}

/// What [`StampArgs`] does with an earlier time-stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StampMode {
    /// Replaces it.
    Replace,
    /// Keeps it and adds another.
    Append,
}

/// What goes into the id-aa-timeStampToken attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenForm {
    /// The token.
    Token,
    /// The whole `TimeStampResp`.
    WholeResponse,
}

/// `tsp_stamp`: time-stamps of signers of a CMS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StampArgs {
    /// The CMS (DER or BER).
    pub cms: Bytes,
    /// Which signers.
    pub signers: SignerSel,
    /// The TSA.
    pub tsa: TsaChoice,
    /// Replace or append.
    pub mode: StampMode,
    /// What goes into the attribute.
    pub token: TokenForm,
}

/// What `tsp_stamp` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StampOutcome {
    /// The DER CMS.
    Stamped(Bytes),
    /// The time-stamp failed.
    Failed(NetFailure),
    /// No signer of the certificate of [`SignerSel::OfCert`]; nothing was requested.
    NoSigner,
}

/// `tsp_request`: a time-stamp of a hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TspRequestArgs {
    /// The TSA.
    pub tsa: TsaSpec,
    /// The message imprint, hashed with `tsa.hash`.
    pub imprint: Bytes,
}

/// What `tsp_request` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TspOutcome {
    /// Granted.
    Ok {
        /// The `TimeStampResp`, as received.
        response: Bytes,
        /// Its token, DER.
        token: Bytes,
        /// genTime, Unix milliseconds.
        gen_time_ms: i64,
        /// The certificate that signed the token.
        tsa_cert: Option<Bytes>,
    },
    /// No time-stamp.
    Failed(NetFailure),
}

/// The TSA of a time-stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsaChoice {
    /// As the basics module: Streebog-512, policy 1.2.398.3.3.2.6.4.
    Basics,
    /// As Kalkan's default profile: SHA-256, policy 1.2.398.3.3.2.6.2.
    Kalkan,
    /// As given.
    Custom(TsaSpec),
}

/// A TSA and how to ask it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaSpec {
    /// Where.
    pub url: PkiUrl,
    /// The binding.
    pub method: PkiMethod,
    /// The imprint's hash.
    pub hash: HashAlg,
    /// The policy asked for (and then required), a dotted OID.
    pub policy: Option<String>,
    /// The nonce.
    pub nonce: Nonce,
    /// `certReq`.
    pub cert_req: bool,
    /// Repeats while the TSA does not answer, at most [`MAX_TSP_RETRIES`].
    #[serde(default)]
    pub retries: u8,
    /// Timeout of each request, at most [`MAX_PKI_TIMEOUT_MS`].
    pub timeout_ms: u32,
    /// genTime at most this far from the core's clock.
    #[serde(default)]
    pub check_skew_ms: Option<u32>,
    /// The token's signer must have the timeStamping key usage.
    #[serde(default)]
    pub require_tsa_eku: bool,
}

/// Where a PKI service is. The core asks only its PKI hosts (`*.pki.gov.kz`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PkiUrl {
    /// `http://tsp.pki.gov.kz`, `http://ocsp.pki.gov.kz`.
    Default,
    /// The URL this certificate names (OCSP: its authorityInfoAccess; TSA: the
    /// time-stamping access of its subjectInfoAccess or authorityInfoAccess).
    FromCert(Bytes),
    /// This URL.
    Fixed(String),
}

/// How a request reaches a PKI service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PkiMethod {
    /// `GET url/<base64>`.
    Get,
    /// `GET url/<percent-encoded base64>`.
    GetUrlEncoded,
    /// `POST url`, this `Content-Type` or the protocol's.
    Post {
        /// The `Content-Type`.
        content_type: Option<String>,
    },
    /// `POST url/<percent-encoded base64>` with the request as the body too.
    PostWithPath,
    /// `GetUrlEncoded` while the encoded request is shorter than this, else POST.
    GetUnder(u16),
}

/// A request's nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nonce {
    /// None.
    None,
    /// This many random bytes.
    Random(u8),
    /// These bytes.
    Value(Bytes),
}

/// `ocsp_fetch`: an OCSP request about a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcspArgs {
    /// The certificate.
    pub cert: Bytes,
    /// Its issuer.
    pub issuer: IssuerSel,
    /// The hash of the `CertID`.
    pub cert_id_hash: HashAlg,
    /// The nonce extension.
    pub nonce: Nonce,
    /// The responder.
    pub url: PkiUrl,
    /// The binding.
    pub method: PkiMethod,
    /// Timeout, at most [`MAX_PKI_TIMEOUT_MS`].
    pub timeout_ms: u32,
    /// Check the response as the core checks its own (responder trusted, signature,
    /// current, the nonce echoed).
    pub check: bool,
}

/// The issuer of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerSel {
    /// Among the CAs the core trusts ([`Import::CaIssuer`]).
    HostCas,
    /// This certificate.
    Given(Bytes),
    /// The first of these whose key verifies the certificate's signature.
    VerifiesCert(Vec<Bytes>),
}

/// What `ocsp_fetch` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspOutcome {
    /// The responder answered with an `OCSPResponse`.
    Ok {
        /// The HTTP status.
        http_status: u16,
        /// The `OCSPResponse`, as received.
        response: Bytes,
        /// Its `BasicOCSPResponse`, DER.
        basic: Option<Bytes>,
        /// `OCSPResponseStatus`.
        response_status: u8,
        /// The certificate's status (with `check`, only if the response passed).
        cert_status: Option<CertStatusAbi>,
        /// producedAt, Unix milliseconds.
        produced_at_ms: Option<i64>,
        /// Why the response failed the check.
        problem: Option<Problem>,
    },
    /// No `OCSPResponse`.
    Failed(NetFailure),
}

/// A certificate's revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatusAbi {
    /// Not revoked.
    Good,
    /// Revoked.
    Revoked {
        /// When, Unix milliseconds.
        at_ms: i64,
        /// The CRLReason.
        reason: Option<u8>,
    },
    /// Unknown to the responder.
    Unknown,
}

/// `crl_fetch`: the CRLs of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlArgs {
    /// The certificate.
    pub cert: Bytes,
    /// Its issuer.
    pub issuer: IssuerSel,
    /// Timeout of each download, at most [`MAX_PKI_TIMEOUT_MS`].
    pub timeout_ms: u32,
}

/// What `crl_fetch` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrlOutcome {
    /// The complete CRL (and the delta CRL, if any), as received, and the status in them.
    Ok {
        /// The CRLs.
        crls: Vec<Bytes>,
        /// The certificate's status.
        status: CertStatusAbi,
    },
    /// No CRL arrived.
    Failed(NetFailure),
    /// A CRL arrived but is not a valid one of the issuer.
    Invalid(Problem),
}

/// A request to a PKI service that failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFailure {
    /// Which service.
    pub stage: NetStage,
    /// How.
    pub kind: NetKind,
    /// The host asked (or the URL, without one).
    pub address: String,
    /// What went wrong, for the log.
    pub detail: String,
}

/// A PKI service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetStage {
    /// The TSA.
    Tsp,
    /// An OCSP responder.
    Ocsp,
    /// A CRL distribution point.
    Crl,
}

/// How a request to a PKI service failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetKind {
    /// The name does not resolve.
    UnknownHost,
    /// No connection.
    Connect,
    /// No answer in time.
    Timeout,
    /// The TLS handshake failed.
    Tls,
    /// An HTTP status other than 200.
    Http(u16),
    /// Not a valid answer to the request.
    InvalidResponse,
    /// Refused: the service's status.
    Rejected(u8),
    /// The answer's time is too far from the core's clock.
    ClockSkew,
    /// Anything else (no URL among them).
    Other,
}

/// What is wrong with a signature, a response or a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Problem {
    /// Not readable.
    Malformed,
    /// No content to verify against.
    NoContent,
    /// The signer's certificate is not there.
    NoSignerCert,
    /// The signature does not verify.
    BadSignature,
    /// The messageDigest does not match the content.
    DigestMismatch,
    /// The signingCertificate(V2) does not match the signer's certificate.
    EssCertIdMismatch,
    /// Expired.
    Expired,
    /// Not yet valid.
    NotYetValid,
    /// Issued by no CA the core trusts.
    UnknownCa,
    /// The chain does not hold.
    PathInvalid,
    /// Revoked.
    Revoked {
        /// When, Unix milliseconds.
        at_ms: i64,
        /// The CRLReason.
        reason: Option<u8>,
    },
    /// The responder does not know the certificate.
    StatusUnknown,
    /// The responder is not trusted, or its signature does not verify.
    ResponderUnverified,
    /// The nonce was not echoed.
    NonceMismatch,
    /// The response is not current.
    OcspStale,
    /// A CRL is not valid.
    CrlInvalid,
    /// No time-stamp.
    TspMissing,
    /// The time-stamp is not valid.
    TspInvalid,
    /// The time-stamp is of another signature.
    TspImprintMismatch,
    /// The certificate is not of the KNCA type asked for.
    WrongKncaType,
    /// The certificate has this extended key usage, which is refused.
    BlockedEku(String),
    /// The network failed.
    Net(NetFailure),
}

/// The time a signer is judged at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyAt {
    /// Now.
    Now,
    /// Its signingTime attribute (now without one).
    SigningTime,
    /// The genTime of its verified time-stamp (now without one).
    TspTime,
}

/// Where a signer certificate's revocation status comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Revocation {
    /// Not checked.
    None,
    /// Only the OCSP answer the CMS carries (an id-pkix-ocsp-basic attribute, or an
    /// id-ri-ocsp-response in `crls`).
    EmbeddedOcsp,
    /// The OCSP answer the CMS carries, else the certificate's OCSP responder.
    LiveOcsp,
    /// As `live_ocsp`, then the certificate's CRL if the responder fails.
    LiveOcspThenCrl,
}

/// `cms_verify`: a report on the signers of a CMS. Responders and distribution points are
/// asked only on the PKI hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyArgs {
    /// The CMS, DER or BER.
    pub cms: Bytes,
    /// The content of a detached CMS.
    #[serde(default)]
    pub data: Option<Bytes>,
    /// The time each signer is judged at.
    pub at: VerifyAt,
    /// The CAs of the certification paths: `None`, the ones the core trusts; empty, no
    /// path is built.
    #[serde(default)]
    pub chain: Option<Vec<Bytes>>,
    /// Where revocation status comes from.
    pub revocation: Revocation,
    /// Only the first signer.
    #[serde(default)]
    pub first_signer_only: bool,
    /// Key usage bits the signer certificate must have: among the certificates its signer
    /// identifier names, the first that has them all is the signer's.
    #[serde(default)]
    pub require_key_usage: Vec<KeyUsageBit>,
}

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    /// It holds.
    Ok,
    /// Not checked: not asked for, or nothing to check it on.
    Skipped,
    /// It fails.
    Fail(Problem),
}

/// The time-stamp of a signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TspReport {
    /// Its genTime, Unix milliseconds, if it verifies.
    pub gen_time_ms: Option<i64>,
    /// Whether it verifies (`tsp_invalid`, `tsp_imprint_mismatch`).
    pub check: Check,
    /// The TSA certificate, if it verifies.
    pub tsa_cert: Option<Bytes>,
}

/// One signer of a [`VerifyReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerReport {
    /// Its certificate, if the CMS has it.
    pub certificate: Option<Bytes>,
    /// Its signingTime attribute, Unix milliseconds.
    pub signing_time_ms: Option<i64>,
    /// The signature and messageDigest.
    pub signature: Check,
    /// signingCertificateV2; skipped without the attribute.
    pub ess_cert_id: Check,
    /// The certificate's validity at the time the signer is judged at.
    pub validity: Check,
    /// The certification path.
    pub path: Check,
    /// The revocation status; a revocation after the time the signer is judged at is good.
    pub revocation: Check,
    /// The time-stamp token, if the signer has one.
    pub tsp: Option<TspReport>,
}

/// The reply of `cms_verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// The encapsulated content, if the CMS has it.
    pub content: Option<Bytes>,
    /// The signers, in order.
    pub signers: Vec<SignerReport>,
}

/// A namespace binding of [`SignXmlExArgs`]'s XPaths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsBinding {
    /// The prefix.
    pub prefix: String,
    /// The namespace URI.
    pub uri: String,
}

/// Where an XML signature goes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// Last child of the document element.
    #[default]
    DocumentElement,
    /// Last child of the document's first node, which must be an element.
    FirstChildOfDocument,
    /// Last child of the element [`SignXmlExArgs::parent`] selects.
    Parent,
}

/// A canonicalization method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C14n {
    /// Canonical XML 1.0.
    Inclusive,
    /// Canonical XML 1.0 with comments.
    InclusiveWithComments,
    /// Exclusive XML Canonicalization 1.0.
    Exclusive,
    /// Exclusive XML Canonicalization 1.0 with comments.
    ExclusiveWithComments,
}

/// A transform of the signed reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// enveloped-signature.
    Enveloped,
    /// A canonicalization.
    C14n(C14n),
}

/// A `ds:Object` with the signing time: `<ds:SignatureProperty Id="<property_id>"
/// Target="#<signature_id>">` around an unqualified `<timestamp>` holding `text`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningTimeObject {
    /// The `Id` of the `SignatureProperty`.
    pub property_id: String,
    /// A second reference (`URI="#<property_id>"`) signs it.
    pub target_ref: bool,
    /// The text of `<timestamp>`.
    pub text: String,
}

/// The bytes `keys_sign_xml_ex` returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XmlOutput {
    /// The input bytes with the signature spliced in.
    #[default]
    AsIs,
    /// As a JDK `Transformer` writes the document: the XML declaration replaced
    /// (`<?xml version="1.0" encoding="UTF-8"?>`, `standalone="no"` if asked), nothing
    /// before the first node, and with `trim` no whitespace at either end.
    Serialize {
        /// Write the declaration.
        declaration: bool,
        /// With `standalone="no"`.
        standalone_no: bool,
        /// No whitespace at either end.
        trim: bool,
    },
}

/// `keys_sign_xml_ex`: an XML signature as the plugin's clients expect it. Unset fields
/// give [`SignXmlArgs`]'s signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignXmlExArgs {
    /// The key.
    pub handle: u32,
    /// The document, UTF-8.
    pub xml: Bytes,
    /// An XPath to the element to sign, which has an `Id`; `None`: the whole document.
    #[serde(default)]
    pub element: Option<String>,
    /// An XPath to the element the signature goes into ([`Placement::Parent`]).
    #[serde(default)]
    pub parent: Option<String>,
    /// Prefix → namespace URI of the XPaths' names; with them (or `other_prefix_uri`)
    /// names match by namespace, otherwise as written.
    #[serde(default)]
    pub namespaces: Vec<NsBinding>,
    /// The namespace of every prefix `namespaces` does not bind.
    #[serde(default)]
    pub other_prefix_uri: Option<String>,
    /// Where the signature goes.
    #[serde(default)]
    pub placement: Placement,
    /// The `SignatureMethod` URI; `None`: Kalkan's for the certificate. Known URIs only, and
    /// only one fitting the key.
    #[serde(default)]
    pub signature_method: Option<String>,
    /// The `DigestMethod` URI; `None`: the one paired with the signature method.
    #[serde(default)]
    pub digest_method: Option<String>,
    /// The `CanonicalizationMethod` of `SignedInfo`; `None`: Kalkan's.
    #[serde(default)]
    pub signed_info_c14n: Option<C14n>,
    /// The reference's transforms; `None`: Kalkan's.
    #[serde(default)]
    pub transforms: Option<Vec<Transform>>,
    /// The `Id` of `ds:Signature`.
    #[serde(default)]
    pub signature_id: Option<String>,
    /// A signing-time object (needs `signature_id`).
    #[serde(default)]
    pub signing_time_object: Option<SigningTimeObject>,
    /// No line breaks between the signature's elements.
    #[serde(default)]
    pub strip_whitespace: bool,
    /// Base64 in lines of 76 characters; `None`: as Kalkan (in lines).
    #[serde(default)]
    pub base64_line_breaks: Option<bool>,
    /// The output form.
    #[serde(default)]
    pub output: XmlOutput,
}

/// `xml_verify`: every XML signature of a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlVerifyArgs {
    /// The document, UTF-8.
    pub xml: Bytes,
}

/// How much a XAdES signature of [`XadesArgs`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XadesLevel {
    /// XAdES-BASELINE-B: the signed properties.
    B,
    /// XAdES-BASELINE-T: and a signature time-stamp.
    T,
    /// XAdES-BASELINE-LT: and the chain and the revocation data of every certificate but
    /// a self-signed root: OCSP responses, or the CRLs of a certificate naming no responder.
    Lt,
}

/// `keys_sign_xades`: a XAdES-BASELINE signature of the whole document by the key
/// `handle`, enveloped, the last child of the document element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XadesArgs {
    /// The key.
    pub handle: u32,
    /// The document, UTF-8.
    pub xml: Bytes,
    /// The level.
    pub level: XadesLevel,
    /// The TSA of T and LT.
    pub tsa: TsaChoice,
    /// The signer's issuers, from its issuer up (DER): the certificates of LT and the
    /// issuers its OCSP requests and CRLs name.
    #[serde(default)]
    pub chain: Vec<Bytes>,
    /// The `SignatureMethod` URI; `None`: Kalkan's for the key.
    #[serde(default)]
    pub signature_method: Option<String>,
    /// The `DigestMethod` URI; `None`: the one paired with the signature method.
    #[serde(default)]
    pub digest_method: Option<String>,
}

/// The outcome of `keys_sign_xades`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XadesOutcome {
    /// The signed document.
    Signed(Bytes),
    /// The time-stamp, an OCSP request or a CRL download failed, or a certificate names
    /// neither a responder nor a distribution point.
    Failed(NetFailure),
    /// A certificate of the chain is revoked or unknown to its responder, or its CRL does
    /// not verify.
    Invalid(Problem),
}

/// One signature of an [`XmlVerifyArgs`] document, in document order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlSigReport {
    /// The certificate of its `KeyInfo`; empty if it does not read.
    pub certificate: Bytes,
    /// Whether it verifies with that certificate.
    pub valid: bool,
}

/// Most headers of an [`HttpExArgs`].
pub const MAX_HEADERS: usize = 16;

/// Most bytes of the names and values of an [`HttpExArgs`]'s headers together.
pub const MAX_HEADER_BYTES: usize = 8 << 10;

/// The headers a plugin may send, compared without case.
pub const ALLOWED_HEADERS: [&str; 5] = [
    "Cookie",
    "User-Agent",
    "Accept",
    "Accept-Language",
    "X-Requested-With",
];

/// An HTTP header of an [`HttpExArgs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// One of [`ALLOWED_HEADERS`].
    pub name: String,
    /// Without CR, LF or NUL.
    pub value: String,
}

/// `http_request_ex`: one request to a URL under the manifest's `http` prefixes, to the
/// page's own origin when it matches the manifest's `origins`, or under an `http_insecure`
/// prefix. Redirects are not followed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpExArgs {
    /// GET or POST.
    pub method: Method,
    /// The URL; with `relative_to_origin`, resolved against the page's origin.
    pub url: String,
    /// Resolve `url` against the origin of the page that sent the request.
    #[serde(default)]
    pub relative_to_origin: bool,
    /// Headers among [`ALLOWED_HEADERS`].
    #[serde(default)]
    pub headers: Vec<Header>,
    /// The body's `Content-Type` of a POST; `None` sends none.
    #[serde(default)]
    pub content_type: Option<String>,
    /// The body of a POST.
    #[serde(default)]
    pub body: Bytes,
    /// The timeout, milliseconds; `None`: the core's.
    #[serde(default)]
    pub timeout_ms: Option<u32>,
}

/// What a path chooser picks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    /// A file.
    #[default]
    Open,
    /// A folder.
    Directory,
}

/// A file type of a path chooser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFilter {
    /// What the dialog calls it.
    pub name: String,
    /// The extensions, without the dot.
    pub extensions: Vec<String>,
}

/// `file_choose`, `file_open_ex`: the system's file or folder dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChooseFileArgs {
    /// A file or a folder.
    pub mode: FileMode,
    /// The dialog's title.
    #[serde(default)]
    pub title: Option<String>,
    /// The file types offered.
    #[serde(default)]
    pub filters: Vec<FileFilter>,
    /// The folder it starts in.
    #[serde(default)]
    pub initial_dir: Option<String>,
}

/// A path the user chose, not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChosenPath {
    /// The path.
    pub path: String,
    /// A file's size in bytes; `None` for a folder.
    pub size: Option<u64>,
}

/// `page_file_read`: a file the page names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagePathArgs {
    /// The path, as the page sent it.
    pub path: String,
}

/// The outcome of `page_file_read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageRead {
    /// Read.
    Ok(OpenedFile),
    /// No such readable file, or a path pages may not name.
    NotFound,
    /// Over the size limit.
    TooLarge,
    /// The user said no.
    Declined,
}

/// `page_file_write`: a file the page names, in a folder it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageWriteArgs {
    /// The folder, as the page sent it.
    pub dir: String,
    /// The file name: no separators, an extension of `page_files_ext`.
    pub name: String,
    /// The contents.
    pub data: Bytes,
}

/// The outcome of `page_file_write`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageWrite {
    /// Written: the path.
    Written(String),
    /// Not a folder pages may name, or a name not allowed.
    Invalid,
    /// The user said no.
    Declined,
}

/// Most options of a [`ChoiceArgs`].
pub const MAX_CHOICE_OPTIONS: usize = 32;

/// `dialog_choice`: a message with 1 to 3 buttons, and a list to pick from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceArgs {
    /// How it looks.
    pub kind: MessageKind,
    /// The heading.
    #[serde(default)]
    pub title: Option<String>,
    /// The text, plain.
    pub text: String,
    /// The buttons' texts, left to right.
    pub buttons: Vec<String>,
    /// The button Enter presses.
    pub default: u8,
    /// The list, at most [`MAX_CHOICE_OPTIONS`]; with one, the reply is the option picked
    /// with the first button.
    #[serde(default)]
    pub options: Vec<String>,
}

/// Largest serialized size of a plugin's settings, bytes.
pub const MAX_SETTINGS: usize = 64 << 10;

/// Most keys of a plugin's settings.
pub const MAX_SETTINGS_KEYS: usize = 256;

/// Most bytes of a plugin's shared values and their keys together.
pub const MAX_SHARED: usize = 64 << 10;

/// Most keys of a plugin's shared values.
pub const MAX_SHARED_KEYS: usize = 64;

/// `shared_get`: a value the plugin's instances share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedKey {
    /// The key.
    pub key: String,
}

/// `shared_put`: a value for every instance of the plugin, until the plugin is reloaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedPut {
    /// The key.
    pub key: String,
    /// The value; `None` removes it.
    pub value: Option<Bytes>,
    /// It goes after this long, milliseconds; `None`: it stays.
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

/// `call_locale`: the language of OpenNCALayer's windows until the call returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocaleArgs {
    /// `"ru"`, `"kk"` or `"en"`; anything else is `invalid`.
    pub locale: String,
}

/// `core_modules`: the module names the core serves now.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreModules {
    /// The built-in modules', sorted.
    pub builtin: Vec<String>,
    /// The plugins'.
    pub plugins: Vec<String>,
}

/// `core_bundles`: the core's version and the original bundles the enabled plugins port.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreBundles {
    /// The core's version.
    pub core_version: String,
    /// `(symname, version)` of the bundles the enabled plugins port.
    pub plugins: Vec<(String, String)>,
}

/// `core_install_bundle`: the page asks to install the original bundle `symname`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallBundleArgs {
    /// The bundle's symbolic name.
    pub symname: String,
}

/// `core_open_window`: a window of the core a page asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowArgs {
    /// The window.
    pub window: Window,
}

/// A window of the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Window {
    /// The settings.
    Settings,
    /// The plugins.
    BundleManager,
    /// A key store explorer.
    KeystoreExplorer,
    /// AdES signing.
    AdesSigning,
    /// AdES validation.
    AdesValidation,
    /// Where to find a plugin porting the bundle `symname`, which no plugin of the catalog
    /// offers; the page's origin is the call's.
    BundleHint {
        /// The bundle's symbolic name.
        symname: String,
    },
}

// Key choice flows, tokens, the typed file chooser and certificate paths.

/// Most flows a call opens with `keys_flow_open`.
pub const MAX_FLOWS: usize = 4;

/// The readers a flow's storage dialog offers for tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowReaders {
    /// Those holding a token, scanned when the dialog opens, while token support is on.
    Live,
    /// These, the first one first; each must hold a token of its storage's family now.
    Fixed(Vec<FlowReader>),
    /// None: the token storages are not selectable.
    None,
}

/// A reader of [`FlowReaders::Fixed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowReader {
    /// The token's storage (`AKKaztokenStore`, …).
    pub storage: String,
    /// The reader's name ([`Import::KeysTerminals`]).
    pub reader: String,
}

/// The key store file a flow's storage dialog starts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStart {
    /// The last one opened.
    Recent,
    /// This path from the page, if a page may name it; otherwise none.
    Page(String),
    /// None.
    Empty,
}

/// How a flow reads the key store file the user chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowFile {
    /// Any file the system opens.
    Open,
    /// A regular disk file of at most the size of a page's file, on a network share too,
    /// never a device.
    Chosen,
}

/// The storage dialog's error when a flow has no key to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowNone {
    /// No keys.
    NoKeys,
    /// No signing keys.
    NoSigningKeys,
    /// No authentication keys.
    NoAuthKeys,
}

/// The order of a flow's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowOrder {
    /// As stored.
    Store,
    /// The latest notBefore first.
    NewestFirst,
    /// The earliest notBefore first.
    OldestFirst,
}

/// How a flow checks the keys it lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowChecks {
    /// Not at all: every key may be picked.
    Settled,
    /// Against these conditions and the keys' OCSP responders, the key dialog following
    /// the checks.
    Live {
        /// The conditions of `keys_choose`.
        filter: Box<Filter>,
        /// More conditions.
        more: Box<FilterMore>,
    },
}

/// `keys_flow_open`: a key choice's storage dialog and the rules of its key dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowArgs {
    /// What the key is for.
    pub action: Action,
    /// Storage names to offer, in order, duplicates kept; empty: none (only cancel).
    #[serde(default)]
    pub storages: Vec<String>,
    /// The readers offered for tokens.
    pub readers: FlowReaders,
    /// The key store file the dialog starts with.
    pub start: FlowStart,
    /// The path of an opened file becomes the last one opened.
    pub remember: bool,
    /// A line both dialogs show (after a plugin's name).
    #[serde(default)]
    pub detail: Option<String>,
    /// An empty password is refused before the store is opened.
    pub non_empty_password: bool,
    /// The password must match the policy for keys of internal systems.
    pub inner_password_policy: bool,
    /// An answer of a storage not offered is refused before the store is read.
    pub same_storage: bool,
    /// How the file is read.
    pub file: FlowFile,
    /// The keys listed: those of one of these Kalkan types (`SIGNATURE`, …); `None`: all.
    #[serde(default)]
    pub knca_types: Option<Vec<String>>,
    /// The dialog's error when no key is left to list.
    pub none: FlowNone,
    /// An empty store is a store without keys to list.
    pub empty_is_none: bool,
    /// The order of the keys.
    pub order: FlowOrder,
    /// How the keys are checked.
    pub checks: FlowChecks,
    /// A reader whose token refused the PIN as blocked is not tried again.
    pub skip_blocked_reader: bool,
}

/// A key of an opened flow, in the key dialog's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowKey {
    /// Its alias in the key store.
    pub alias: String,
    /// Its certificate, DER.
    pub certificate: Bytes,
}

/// A flow whose store opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowOpened {
    /// The flow, for [`PickArgs`], until the call returns.
    pub flow: u32,
    /// Its keys.
    pub keys: Vec<FlowKey>,
}

/// The last wrong PIN of a flow's storage dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowWrongPin {
    /// The token's storage.
    pub storage: String,
    /// Tries left before the PIN is blocked, if the token tells.
    pub tries_left: Option<u8>,
}

/// What `keys_flow_open` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowOutcome {
    /// The opened flow; `None` if the user cancelled.
    pub opened: Option<FlowOpened>,
    /// The last wrong PIN typed, whether the store opened or not.
    pub wrong_pin: Option<FlowWrongPin>,
}

/// `keys_flow_pick`: the key dialog of an opened flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PickArgs {
    /// The flow.
    pub flow: u32,
    /// The dialog's error line: why the previous key did not do.
    #[serde(default)]
    pub error: Option<String>,
}

/// `keys_describe`: a key the instance holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDescription {
    /// Its alias in the key store.
    pub alias: String,
    /// Its algorithm: `gost2004`, `gost2015_512` or `rsa`.
    pub alg: String,
    /// Its certificate, DER.
    pub certificate: Bytes,
}

/// What `tokens_scan` saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenScan {
    /// Token support is on.
    pub enabled: bool,
    /// The storages of the tokens connected, in Kalkan's order.
    pub present: Vec<String>,
    /// A card of any kind is in a reader.
    pub any_card: bool,
}

/// `dialog_reader`: the choice of a reader holding a token of a storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderArgs {
    /// The token's storage (`AKKaztokenStore`, …).
    pub storage: String,
}

/// `file_choose_kind`: the original's file chooser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileKindArgs {
    /// The original's `FileChooser.FileType` name (`P12`, `XML`, `ALL`, …); empty: a folder.
    pub kind: String,
    /// The folder it starts in, if a page may name it.
    #[serde(default)]
    pub directory: Option<String>,
}

/// The time a certification path is valid at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTime {
    /// The core's clock.
    Now,
    /// The core's clock, or for an expired certificate its notAfter.
    NotAfterIfExpired,
    /// This instant, Unix milliseconds.
    UnixMs(i64),
}

/// `pkix_path`: a certification path through the CAs the core trusts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathArgs {
    /// The certificate, DER.
    pub cert: Bytes,
    /// When.
    pub at: PathTime,
}

/// What `pkix_path` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOutcome {
    /// A valid path.
    Valid,
    /// No CA the core trusts has the certificate's issuer name.
    IssuerNotFound,
    /// No valid path: why, in English.
    Invalid(String),
}

// The built-in modules' key files and certificate windows (capability `builtin`).

/// `dialog_csr`: where the new key files of `generateCsr` go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrDialogArgs {
    /// Storages to offer, in order.
    pub storages: Vec<String>,
    /// Ask for the key file password (the page gave none).
    pub ask_password: bool,
}

/// The answer to the `generateCsr` window: a PKCS#12 folder the user chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrChoice {
    /// The folder, for [`Folder::Chosen`] until the call returns.
    pub folder: u32,
    /// The storage chosen.
    pub storage: String,
    /// The key file password typed, with `ask_password`.
    pub password: Option<SecretRef>,
}

/// `dialog_import`: the `importCertificate` window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDialogArgs {
    /// The storage the page names.
    pub storage: String,
    /// The folder the window starts with, if a page may name it.
    #[serde(default)]
    pub path: Option<String>,
    /// The certificates to install, DER, in request order.
    pub certificates: Vec<Bytes>,
}

/// The answer to the `importCertificate` window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportChoice {
    /// The folder (or key file) of the keys, for [`Folder::Chosen`] until the call returns.
    pub folder: u32,
    /// The password the key files get.
    pub new_password: SecretRef,
}

/// Where key files are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Folder {
    /// A folder the user chose in a window of this call.
    Chosen(u32),
    /// A folder the page names: an existing folder by an absolute path a page may name.
    Page(String),
}

/// The request a new key comes with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestForm {
    /// `generateCsr`'s: PEM, SubjectAltName and KeyStoreInfo with the folder.
    Essentials {
        /// Subject attributes, `(dotted OID, value)`.
        dn: Vec<(String, String)>,
        /// dNSNames.
        dns_names: Vec<String>,
        /// rfc822Name; blank or `None` for none.
        email: Option<String>,
    },
    /// The legacy Applet's: DER with its key identifier, its key file named by it.
    Applet {
        /// Subject attributes, `(dotted OID, value)`, in this order.
        dn: Vec<(String, String)>,
        /// dNSNames; `None` for no SubjectAltName.
        dns_names: Option<Vec<String>>,
    },
}

/// `keystore_new_key`: a new key alone in a PKCS#12 key file of a folder, and its request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewKeyArgs {
    /// Where the key file goes.
    pub folder: Folder,
    /// The key file password.
    pub password: Password,
    /// The signature algorithm, a dotted OID.
    pub alg: String,
    /// The RSA key length.
    #[serde(default)]
    pub bits: Option<u32>,
    /// The request.
    pub form: RequestForm,
}

/// A new key's request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewKey {
    /// The request, DER.
    pub der: Bytes,
    /// The request as PEM (`CERTIFICATE REQUEST`, lines of 64, the platform's line
    /// separator), for [`RequestForm::Essentials`].
    pub pem: Option<String>,
    /// The key identifier: of the BIT STRING (`generateCsr`) or of the whole
    /// SubjectPublicKeyInfo (the Applet), lowercase hex.
    pub key_id: String,
}

/// `keystore_install_cert`: a certificate installed next to its key in a key file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallCertArgs {
    /// Where the key file is.
    pub folder: Folder,
    /// The key file password.
    pub password: Password,
    /// The certificate, DER.
    pub cert: Bytes,
    /// The storage, a dotted OID (PKCS#12, JKS).
    pub storage_oid: String,
    /// The password the key file gets afterwards, checked first.
    #[serde(default)]
    pub new_password: Option<Password>,
}

/// The key file a certificate went into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCert {
    /// Its absolute path.
    pub path: String,
}

/// `keystore_change_password`: a key file the page names, re-encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePasswordArgs {
    /// The key file.
    pub file: String,
    /// Its password.
    pub old: Password,
    /// Its new password.
    pub new: Password,
}

/// `tokens_id_card`: a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderName {
    /// The reader's name.
    pub reader: String,
}

/// The holder of the ID card in a reader, read without the PIN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdCardHolder {
    /// The IIN.
    pub iin: String,
    /// The full name, as the card writes it.
    pub full_name: String,
}
