//! Buhta NcaModule (`com.buhta.cert.ncamodule`) as an OpenNCALayer plugin.
//!
//! The page calls `InvokerService.call` through the original's `CommonInvoker` (a request
//! org.json cannot read drops the connection, as one without `addInfo.origin` does); the
//! method runs a Protocol Buffers RPC, `{format, version, handler, payload}`, and answers
//! with its result as a **string** body: `JsonFormat`'s text (format 0) or the base64 of
//! the binary message (format 1).
//!
//! - handler 1, SELECT_SIGN_CERT: a key whose BIN (or, without one, IIN) equals `tin`,
//!   from a PKCS#12 store, with no chain or OCSP check; its uuid stays valid in this
//!   session while it is among the 15 latest selected.
//! - handler 2, SIGN_DOCUMENT, and 3, BULK_SIGN_DOCUMENT: a file as CAdES-T (Kalkan's
//!   profile and TSA), an XML document with an enveloped signature in the document
//!   element, whitespace-free, base64 without line breaks.

mod json;
mod rpc;

use oncl_pdk::abi::{Action, Filter, FilterMore, SelectArgs};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{
    BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
};
use oncl_pdk::keys::{
    self, CmsCerts, CmsContent, CmsOutcome, CoSign, Key, SignCmsExArgs, SignXmlExArgs, SignedAttrs,
    SigningTime, TimeForm, TimeSource, XmlOutput,
};
use oncl_pdk::orgjson::{self, JValue};
use oncl_pdk::pki::TsaChoice;
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64};
use rpc::{Content, FileDocument, Sign, SignedDocument, XmlDocument};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// The most keys SELECT_SIGN_CERT keeps: one fewer than the core holds for an instance, so
/// a sign request may still choose a key of its own.
const MAX_SELECTED: usize = 15;

thread_local! {
    /// The keys SELECT_SIGN_CERT gave out in this session (the plugin instance), by uuid,
    /// oldest first; past [`MAX_SELECTED`] the oldest is dropped (its key released, its
    /// uuid then unknown).
    static SELECTED: RefCell<VecDeque<(String, Rc<Key>)>> =
        const { RefCell::new(VecDeque::new()) };
}

/// The errors of the RPC: `{"status":false,"code":<name>,"message":<text>}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcFailure {
    UnknownRpcVersion,
    UnknownCommand,
    InvalidPayload,
    InvalidCertSelected,
    UnexpectedSignError,
}

impl RpcFailure {
    fn failure(self) -> Failure {
        let (code, message) = match self {
            RpcFailure::UnknownRpcVersion => (
                "UNKNOWN_RPC_VERSION",
                "Unknown version, currently supported oldest version: `v1alpha1`",
            ),
            RpcFailure::UnknownCommand => ("UNKNOWN_COMMAND", "Unknown `handler`"),
            RpcFailure::InvalidPayload => ("INVALID_PAYLOAD", "Invalid payload"),
            RpcFailure::InvalidCertSelected => (
                "INVALID_CERT_SELECTED",
                "Selected signing certificate is either invalid or not supported",
            ),
            RpcFailure::UnexpectedSignError => {
                ("UNEXPECTED_SIGN_ERROR", "Unexpected signing error")
            }
        };
        Failure::Custom {
            code: code.to_owned(),
            message: Some(message.to_owned()),
            details: None,
        }
    }
}

/// How the payload and the result are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Binary,
}

/// `InvokerService`: one method, `call(String)`.
struct InvokerService;

const METHODS: &[NlMethod] = &[NlMethod {
    name: "call",
    annotation: None,
    params: 1,
}];

impl NlClass for InvokerService {
    fn class_name(&self) -> &'static str {
        "InvokerService"
    }

    fn methods(&self) -> &'static [NlMethod] {
        METHODS
    }

    fn call(&self, _: &NlMethod, args: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
        let empty = Map::new();
        call(args.unwrap_or(&empty)).map(JValue::Str)
    }
}

fn handle(request: &Request) -> String {
    // The module reads `addInfo.origin` before anything else: without it the exception
    // leaves the module and the connection drops.
    if request.origin.is_none() {
        let _ = host::reply_drop();
        return String::new();
    }
    let options = InvokeOptions {
        bad_request: BadRequest::Drop,
    };
    match invoke_with(
        &request.text,
        &request.add_info(),
        &[&InvokerService],
        &options,
    ) {
        Reply::Text(text) => text,
        Reply::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

oncl_pdk::plugin!(handle);

/// `call`: the RPC, its result as text.
fn call(args: &Map<String, Value>) -> Result<String, Failure> {
    let format = match orgjson::opt_int(args, "format", 0) {
        0 => Format::Json,
        1 => Format::Binary,
        // The original answers an unknown format with the version's failure.
        _ => return Err(RpcFailure::UnknownRpcVersion.failure()),
    };
    let version = orgjson::opt_string(args, "version").unwrap_or_else(|| "v1alpha1".into());
    if version != "v1alpha1" {
        return Err(RpcFailure::UnknownRpcVersion.failure());
    }
    let handler = orgjson::opt_int(args, "handler", 0);
    if !(1..=3).contains(&handler) {
        return Err(RpcFailure::UnknownCommand.failure());
    }
    // A missing payload is a NullPointerException of the method (`EMPTY_PAYLOAD` is never
    // used by the original).
    let Some(payload) = orgjson::opt_string(args, "payload") else {
        return Err(Failure::Invocation(Some(
            "java.lang.NullPointerException".to_owned(),
        )));
    };
    let payload = Payload::read(format, &payload)?;
    match handler {
        1 => payload
            .message()
            .and_then(|args| payload.write(&select_cert(&args))),
        2 => payload
            .message()
            .and_then(|args| sign_document(&args))
            .and_then(|result| payload.write(&result)),
        _ => payload
            .message()
            .and_then(|args| bulk_sign(&args))
            .and_then(|result| payload.write(&result)),
    }
}

/// The payload in its format.
enum Payload {
    Json(String),
    Binary(Vec<u8>),
}

impl Payload {
    fn read(format: Format, text: &str) -> Result<Payload, Failure> {
        match format {
            Format::Json => Ok(Payload::Json(text.to_owned())),
            // Unverified against the original: which Base64 decoder reads a binary payload
            // (taken as Java's strict one; its exception is the method's).
            Format::Binary => javab64::decode_java(text)
                .map(Payload::Binary)
                .map_err(|e| {
                    Failure::Invocation(Some(format!("java.lang.IllegalArgumentException: {e}")))
                }),
        }
    }

    fn message<M: json::Json + prost::Message>(&self) -> Result<M, Failure> {
        match self {
            Payload::Json(text) => json::parse(text),
            Payload::Binary(bytes) => M::decode(bytes.as_slice()).map_err(|_| json::Invalid),
        }
        .map_err(|_| RpcFailure::InvalidPayload.failure())
    }

    fn write<M: json::Json + prost::Message>(&self, message: &M) -> Result<String, Failure> {
        Ok(match self {
            Payload::Json(_) => json::print(message),
            Payload::Binary(_) => json::encode_binary(&message.encode_to_vec()),
        })
    }
}

/// SELECT_SIGN_CERT: the uuid of the key chosen, or an empty result.
fn select_cert(args: &rpc::SelectSignCertArgs) -> rpc::SelectSignCertResult {
    let tin = args.tin.clone().unwrap_or_default();
    let Some(key) = select(&tin) else {
        return rpc::SelectSignCertResult::default();
    };
    let uuid = uuid();
    SELECTED.with_borrow_mut(|keys| {
        keys.push_back((uuid.clone(), Rc::new(key)));
        while keys.len() > MAX_SELECTED {
            keys.pop_front();
        }
    });
    rpc::SelectSignCertResult {
        cert: Some(rpc::SignCert { cert: uuid }),
    }
}

/// A key of a PKCS#12 store whose TIN (BIN, or IIN without a BIN) is `tin`; `None` if the
/// user cancels.
fn select(tin: &str) -> Option<Key> {
    // An empty `tin` matches no certificate in the original: no key, so no dialog either.
    if tin.is_empty() {
        return None;
    }
    keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec!["PKCS12".to_owned()],
        // The original checks only the certificate's validity and its TIN.
        filter: Filter {
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
        more: FilterMore {
            tin: tin.to_owned(),
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: Default::default(),
    })
    .ok()
    .flatten()
}

/// A random (version 4) UUID, as `UUID.randomUUID().toString()`.
fn uuid() -> String {
    let mut bytes = host::random(16).unwrap_or_else(|_| vec![0; 16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// The key of a sign request: one selected before (its uuid), or one selected now.
fn signing_key(sign: Option<&Sign>) -> Result<Rc<Key>, Failure> {
    let key = match sign {
        Some(Sign::SignCert(uuid)) => SELECTED.with_borrow(|keys| {
            keys.iter()
                .find(|(selected, _)| selected == uuid)
                .map(|(_, key)| Rc::clone(key))
        }),
        Some(Sign::SignCertArgs(args)) => select(args.tin.as_deref().unwrap_or("")).map(Rc::new),
        None => select("").map(Rc::new),
    };
    key.ok_or_else(|| RpcFailure::InvalidCertSelected.failure())
}

/// SIGN_DOCUMENT.
fn sign_document(args: &rpc::SignDocumentArgs) -> Result<rpc::SignDocumentResult, Failure> {
    let key = signing_key(args.sign.as_ref())?;
    let document = sign_one(&key, args.document.as_ref())?;
    Ok(rpc::SignDocumentResult {
        document: Some(document),
    })
}

/// BULK_SIGN_DOCUMENT: every document in order; the first failure ends the call.
fn bulk_sign(args: &rpc::BulkSignDocumentArgs) -> Result<rpc::BulkSignDocumentResult, Failure> {
    let key = signing_key(args.sign.as_ref())?;
    let documents = args
        .documents
        .iter()
        .map(|document| sign_one(&key, Some(document)))
        .collect::<Result<_, _>>()?;
    Ok(rpc::BulkSignDocumentResult { documents })
}

/// A file as CAdES-T, an XML document with an enveloped signature.
fn sign_one(key: &Key, document: Option<&rpc::Signable>) -> Result<SignedDocument, Failure> {
    let unexpected = || RpcFailure::UnexpectedSignError.failure();
    let id = document.and_then(|d| d.id.clone());
    let content = match document.and_then(|d| d.content.as_ref()) {
        Some(Content::File(file)) => Content::File(FileDocument {
            data: cades_t(key, &file.data, file.attached).ok_or_else(unexpected)?,
            ..FileDocument::default()
        }),
        Some(Content::Xml(xml)) => Content::Xml(XmlDocument {
            data: sign_xml(key, &xml.data).ok_or_else(unexpected)?,
        }),
        None => return Err(RpcFailure::InvalidPayload.failure()),
    };
    Ok(SignedDocument {
        id,
        content: Some(content),
        x509_cert: None,
    })
}

/// Kalkan's `createCAdES` (contentType, signingTime, messageDigest, signingCertificateV2;
/// a CMS given as data is co-signed) with a time-stamp of Kalkan's TSA profile.
fn cades_t(key: &Key, data: &[u8], attached: bool) -> Option<Vec<u8>> {
    let outcome = key
        .sign_cms_ex(SignCmsExArgs {
            handle: key.handle(),
            content: CmsContent::Data(data.to_vec().into()),
            encapsulate: attached,
            cosign: CoSign::Auto,
            econtent_type: None,
            digest: None,
            attrs: SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: true,
                signing_time: Some(SigningTime {
                    at: TimeSource::Now,
                    form: TimeForm::Auto,
                }),
                extra: Vec::new(),
            },
            certificates: CmsCerts::Signer,
            timestamp: Some(TsaChoice::Kalkan),
            output: oncl_pdk::abi::CmsOutput::Der,
        })
        .ok()?;
    match outcome {
        CmsOutcome::Signed(cms) => Some(cms.into_vec()),
        CmsOutcome::TspFailed(_) => None,
    }
}

/// `(SignatureMethod, DigestMethod)` by the key's algorithm name, as the original chooses
/// them.
fn xml_uris(key: &Key) -> Option<(&'static str, &'static str)> {
    let info = host::cert_info(key.certificate()).ok()?;
    let name = oncl_port_pki::x509text::kalkan_key_alg_name(&info.spki_alg_oid).unwrap_or_default();
    let cert_sig =
        oncl_port_pki::x509text::kalkan_sig_alg_name(&info.signature_alg_oid).unwrap_or_default();
    if name == "RSA" {
        Some((
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ))
    } else if name.contains("2015") || cert_sig.contains("2015-512") {
        Some((
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        ))
    } else if name.contains("GOST") {
        Some((
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        ))
    } else {
        None
    }
}

/// An enveloped signature of the whole document in its document element, no whitespace
/// inside it, base64 in one line; written with an XML declaration and trimmed.
fn sign_xml(key: &Key, xml: &str) -> Option<String> {
    let (signature_method, digest_method) = xml_uris(key)?;
    let signed = key
        .sign_xml_ex(SignXmlExArgs {
            handle: key.handle(),
            xml: xml.as_bytes().to_vec().into(),
            element: None,
            parent: None,
            namespaces: Vec::new(),
            other_prefix_uri: None,
            placement: keys::Placement::DocumentElement,
            signature_method: Some(signature_method.to_owned()),
            digest_method: Some(digest_method.to_owned()),
            signed_info_c14n: None,
            transforms: None,
            signature_id: None,
            signing_time_object: None,
            strip_whitespace: true,
            base64_line_breaks: Some(false),
            output: XmlOutput::Serialize {
                declaration: true,
                standalone_no: false,
                trim: true,
            },
        })
        .ok()?;
    String::from_utf8(signed).ok()
}
