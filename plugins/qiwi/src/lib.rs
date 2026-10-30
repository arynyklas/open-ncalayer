//! QIWI Kazakhstan SecurityUtils (`kz.qiwi.osgi.SecurityUtils`): `signXml` signs a document
//! with the key of a session that lasts 20 minutes after its last signature; `logOut` ends
//! it. The session lives in this instance (one connection).
//!
//! The signature is the original's XMLDSig: the last child of the document's first node,
//! the xmldsig-more URIs by the certificate's algorithm, inclusive c14n of `SignedInfo`, the
//! reference transformed enveloped + c14n with comments, the document written back with
//! `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`. Replies are its beans as
//! org.json writes them (`HashMap`s of 16 buckets).
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, Bytes, C14n, Filter, KeyOrder, Placement, SignXmlExArgs, Transform, XmlOutput,
};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::{Request, host, pki};
use std::sync::Mutex;

oncl_pdk::plugin!(handle);

/// How long a session lasts after its last signature, milliseconds.
const SESSION_MS: i64 = 1_200_000;

/// The session: its key and when it ends (Unix milliseconds).
static SESSION: Mutex<Option<(Key, i64)>> = Mutex::new(None);

/// The `Result` bean of a reply.
struct Outcome {
    call_id: String,
    signed_xml: Option<String>,
    verification: bool,
    log_out: bool,
}

fn handle(request: &Request) -> String {
    // The prologue runs outside the original's `try`: a failure drops the connection.
    let prologue = || {
        let JValue::Obj(root) = orgjson::parse(&request.text).ok()? else {
            return None;
        };
        let root = root.to_map();
        let method = orgjson::get_string(&root, "method").ok()?.to_owned();
        let args = orgjson::get_array(&root, "args").ok()?.to_vec();
        let call_id = orgjson::array_get_string(&args, 0).ok()?.to_owned();
        Some((method, args, call_id))
    };
    let Some((method, args, call_id)) = prologue() else {
        let _ = host::reply_drop();
        return String::new();
    };
    let outcome = match method.as_str() {
        "signXml" => sign_xml(&args, call_id),
        "logOut" => {
            end_session();
            Some(Outcome {
                call_id,
                signed_xml: None,
                verification: false,
                log_out: true,
            })
        }
        _ => None,
    };
    let mut reply = JObject::hash_map();
    match outcome {
        Some(outcome) => {
            let mut result = JObject::hash_map();
            // `callID` and `verificationResult` share a bucket: `callID` first.
            result.put("callID", outcome.call_id);
            result.put("verificationResult", outcome.verification);
            result.put("logOutResult", outcome.log_out);
            result.put_opt("signedXml", outcome.signed_xml);
            reply.put("responseObject", result);
            reply.put("code", "200");
        }
        None => {
            reply.put("code", "500");
        }
    }
    reply.to_json()
}

fn end_session() {
    *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// `signXml[callID, xml]`: `None` (code 500) when the dialog is cancelled or anything but
/// the signature fails; a failed signature still answers, without `signedXml`.
fn sign_xml(args: &[oncl_pdk::serde_json::Value], call_id: String) -> Option<Outcome> {
    let outcome = session_sign(args);
    if outcome.is_none() {
        end_session();
    }
    outcome.map(|(signed_xml, verification)| Outcome {
        call_id,
        signed_xml,
        verification,
        log_out: false,
    })
}

/// The signed document (if signing worked) and its verification, in the session.
fn session_sign(args: &[oncl_pdk::serde_json::Value]) -> Option<(Option<String>, bool)> {
    let now = host::now().ok()?;
    let mut session = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if session.as_ref().is_some_and(|(_, ends)| now >= *ends) {
        *session = None;
    }
    let key = match session.take() {
        Some((key, _)) => key,
        None => keys::select(&SelectArgs {
            action: Action::Sign,
            storages: vec!["PKCS12".to_owned()],
            filter: Filter {
                // An expired key is flagged in the original's dialog and still signs.
                allow_expired: true,
                chain: Some(Vec::new()),
                allow_revoked: true,
                ..Filter::default()
            },
            more: Default::default(),
            detail: None,
            initial_path: None,
            order: KeyOrder::OldestFirst,
        })
        .ok()??,
    };
    let xml = orgjson::array_get_string(args, 1).ok()?;
    let signed = sign(&key, xml);
    // Unverified against the original: it verifies every signature from the last one,
    // removing each, and answers the last check; here the document's last signature.
    let verification = signed.as_deref().is_some_and(|signed| {
        pki::xml_verify(signed.as_bytes())
            .ok()
            .and_then(|reports| reports.last().map(|report| report.valid))
            .unwrap_or(false)
    });
    *session = Some((key, now + SESSION_MS));
    Some((signed, verification))
}

/// The original's XMLDSig of `xml`; `None` if it fails.
fn sign(key: &Key, xml: &str) -> Option<String> {
    let info = host::cert_info(key.certificate()).ok()?;
    let (signature, digest) = match info.signature_alg_oid.as_str() {
        "1.2.840.113549.1.1.5" => (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1",
            "http://www.w3.org/2001/04/xmldsig-more#sha1",
        ),
        "1.2.840.113549.1.1.11" => (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
        // Every GOST certificate, 2015 too, gets the GOST 2004 URIs.
        _ => (
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        ),
    };
    let signed = key
        .sign_xml_ex(SignXmlExArgs {
            handle: key.handle(),
            xml: Bytes::from(xml.as_bytes().to_vec()),
            element: None,
            parent: None,
            namespaces: Vec::new(),
            other_prefix_uri: None,
            placement: Placement::FirstChildOfDocument,
            signature_method: Some(signature.to_owned()),
            digest_method: Some(digest.to_owned()),
            signed_info_c14n: Some(C14n::Inclusive),
            transforms: Some(vec![
                Transform::Enveloped,
                Transform::C14n(C14n::InclusiveWithComments),
            ]),
            signature_id: None,
            signing_time_object: None,
            strip_whitespace: false,
            base64_line_breaks: None,
            output: XmlOutput::Serialize {
                declaration: true,
                standalone_no: true,
                trim: false,
            },
        })
        .ok()?;
    String::from_utf8(signed).ok()
}
