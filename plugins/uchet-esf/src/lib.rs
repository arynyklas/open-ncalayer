//! Uchet.kz esfSignUtil (`kz.uchet.esfSignUtil`): without dialogs of its own, the key store
//! the page names (`pkcsPath`, `pkcsPassword`; its last key) signs an XML document
//! (`signXml`) or e-invoice texts (`signEsfList`, raw signatures). The core asks the user
//! once per connection before it opens a file the page names.
//!
//! Every failure but an unknown method drops the connection, as the original's exceptions
//! did.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{KeySource, OpenArgs, Password};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host, javab64};

oncl_pdk::plugin!(handle);

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        return dropped();
    };
    let root = root.to_map();
    let method = orgjson::opt_string(&root, "method").unwrap_or_default();
    let reply = match method.as_str() {
        "signXml" => sign_xml(&root),
        "signEsfList" => sign_esf_list(&root),
        _ => {
            let mut reply = JObject::stringer();
            reply.put("success", false);
            reply.put("errorCode", "method_not_defined");
            return reply.to_json();
        }
    };
    reply.map_or_else(dropped, |reply| reply.to_json())
}

/// The connection is dropped without a reply, as for an exception the original let out.
fn dropped() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// The page's key store and password: its last key.
fn open(args: &Map<String, Value>) -> Option<Key> {
    let path = orgjson::get_string(args, "pkcsPath").ok()?;
    let password = orgjson::get_string(args, "pkcsPassword").ok()?;
    let keys = keys::open(&OpenArgs {
        storage: "PKCS12".to_owned(),
        source: KeySource::PagePath(path.to_owned()),
        password: Password::Text(password.to_owned()),
    })
    .ok()?
    .ok()?;
    keys.into_iter().last()
}

/// `signXml{pkcsPath, pkcsPassword, data}`: `{"signedXml":…,"status":200}`, the whole
/// document signed.
fn sign_xml(root: &Map<String, Value>) -> Option<JObject> {
    let args = orgjson::get_object(root, "args").ok()?;
    let xml = orgjson::get_string(args, "data").ok()?;
    let key = open(args)?;
    let signed = key.sign_xml(xml.as_bytes(), None, None).ok()?;
    let mut reply = JObject::hash_map();
    reply.put("signedXml", String::from_utf8(signed).ok()?);
    reply.put("status", 200);
    Some(reply)
}

/// `signEsfList{pkcsPath, pkcsPassword, esfList}`: a raw signature of each text, with the
/// certificate.
fn sign_esf_list(root: &Map<String, Value>) -> Option<JObject> {
    let args = orgjson::get_object(root, "args").ok()?;
    let list = orgjson::get_array(args, "esfList").ok()?;
    let key = open(args)?;
    let cert = key.certificate();
    let pem = host::cert_info(cert).ok()?.pem;
    // `Signature.getInstance(cert.getSigAlgName())`: OpenNCALayer makes no SHA-1 RSA (nor
    // GOST 2015-256) signatures, which fail as the original's signing errors do.
    let alg = host::cert_details(cert).ok()?.signing_alg;
    if !matches!(
        alg.as_deref(),
        Some("gost2004" | "gost2015_512" | "rsa_sha256")
    ) {
        return None;
    }
    let mut signed = Vec::with_capacity(list.len());
    for i in 0..list.len() {
        let text = orgjson::array_get_string(list, i).ok()?;
        let mut item = JObject::hash_map();
        item.put("signature", base64(&key.sign_raw(text.as_bytes()).ok()?));
        item.put("pem", pem.as_str());
        signed.push(JValue::Obj(item));
    }
    let mut reply = JObject::hash_map();
    reply.put("signedEsf", JValue::Arr(signed));
    reply.put("x509", base64(cert));
    Some(reply)
}

/// `Base64.getEncoder()`: without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
