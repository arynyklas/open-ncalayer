//! The Samruk-Kazyna e-procurement module (`kz.sapa.eproc.osgi.EprocModule`): `version` and
//! `signXml`. A signature returns a one-time `newChain` token; the next `signXml` naming it
//! signs with the same key without a dialog. Tokens live in this instance (one connection).
//!
//! Replies are the original's `HashMap` (`code`, `uid`, `message`, `responseObject`,
//! `newChain`, `null`s left out) passed to `new JSONObject(map)`: a `HashMap` of 8 buckets.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{Action, Filter, FilterMore, KeyOrder};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host};
use std::sync::Mutex;

oncl_pdk::plugin!(handle);

/// The Kalkan storages `StorageInfo` knows.
const STORAGES: [&str; 9] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
    "JKS",
    "ABCloudServiceStore",
];

/// Kalkan's `KNCACertificateType` constants.
const KEY_TYPES: [&str; 5] = [
    "SIGNATURE",
    "AUTHENTICATION",
    "SSL",
    "OCSP_RESPONSE_SIGNING",
    "TSP_SIGNING",
];

/// Most chain tokens kept: the original keeps 100, but each token here holds an open key
/// and the core keeps at most 16 keys an instance.
const CHAINS: usize = 12;

/// Chain tokens and their keys, oldest first.
static CHAIN: Mutex<Vec<(String, Key)>> = Mutex::new(Vec::new());

/// A reply: its fields, `None` left out.
#[derive(Default)]
struct Reply {
    code: &'static str,
    uid: Option<String>,
    message: Option<String>,
    response_object: Option<String>,
    new_chain: Option<String>,
}

impl Reply {
    /// `new JSONObject(map)` of the original's `HashMap` of five entries.
    fn into_json(self) -> String {
        let mut source = JObject::hash_map();
        source.put("code", self.code);
        source.put_opt("uid", self.uid);
        source.put_opt("message", self.message);
        source.put_opt("responseObject", self.response_object);
        source.put_opt("newChain", self.new_chain);
        let mut reply = JObject::from_map(5);
        for (key, value) in source.iter() {
            reply.put(key, value.clone());
        }
        reply.to_json()
    }
}

/// An error reply: code 500 with `message`, and `uid` once read.
fn error(uid: Option<&str>, message: impl Into<String>) -> Reply {
    Reply {
        code: "500",
        uid: uid.map(str::to_owned),
        message: Some(message.into()),
        ..Reply::default()
    }
}

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        let _ = host::reply_drop();
        return String::new();
    };
    let root = root.to_map();
    let reply = match orgjson::get_string(&root, "method") {
        Err(message) => error(None, message),
        Ok("version") => Reply {
            code: "200",
            message: Some("Первый релиз".to_owned()),
            response_object: Some("1".to_owned()),
            ..Reply::default()
        },
        Ok("signXml") => sign_xml(&root),
        Ok(other) => Reply {
            code: "400",
            message: Some(format!("Incorrect method: {other}")),
            ..Reply::default()
        },
    };
    reply.into_json()
}

/// `signXml{uid, chain, storageName, keyType, xml, tbsElementXPath,
/// signatureParentElementXPath}`.
fn sign_xml(root: &Map<String, Value>) -> Reply {
    let uid = match orgjson::get_string(root, "uid") {
        Ok(uid) => uid,
        Err(message) => return error(None, message),
    };
    match sign_with(root) {
        Ok((signed, new_chain)) => Reply {
            code: "200",
            uid: Some(uid.to_owned()),
            response_object: Some(signed),
            new_chain: Some(new_chain),
            ..Reply::default()
        },
        Err(message) => error(Some(uid), message),
    }
}

/// The signed document and its new chain token, or the error message.
fn sign_with(root: &Map<String, Value>) -> Result<(String, String), String> {
    let chain = orgjson::opt_string(root, "chain").unwrap_or_default();
    let storage = orgjson::get_string(root, "storageName")?;
    let key_type = orgjson::get_string(root, "keyType")?;
    if !KEY_TYPES.contains(&key_type) {
        return Err(format!(
            "No enum constant kz.gov.pki.reference.KNCACertificateType.{key_type}"
        ));
    }
    let xml = orgjson::get_string(root, "xml")?;
    let tbs = orgjson::opt_string(root, "tbsElementXPath").unwrap_or_default();
    let parent = orgjson::opt_string(root, "signatureParentElementXPath").unwrap_or_default();
    // The token is used up before signing, even if the signature then fails.
    let key = match take_chain(&chain) {
        Some(key) => key,
        None => choose(storage, key_type)?,
    };
    let signed = sign_document(&key, xml, &tbs, &parent)?;
    let token = uuid()?;
    let mut chains = CHAIN.lock().unwrap_or_else(|e| e.into_inner());
    if chains.len() >= CHAINS {
        chains.remove(0);
    }
    chains.push((token.clone(), key));
    Ok((signed, token))
}

/// The key of the token `chain`, taken out; a blank or unknown token is none.
fn take_chain(chain: &str) -> Option<Key> {
    if chain.trim().is_empty() {
        return None;
    }
    let mut chains = CHAIN.lock().unwrap_or_else(|e| e.into_inner());
    let at = chains.iter().position(|(token, _)| token == chain)?;
    Some(chains.remove(at).1)
}

/// The storage checks of `StorageInfo`, then the key dialog over keys of `key_type`.
fn choose(storage: &str, key_type: &str) -> Result<Key, String> {
    if storage.trim().is_empty() {
        return Err("storageName.param.empty".to_owned());
    }
    if !STORAGES.contains(&storage) {
        return Err("storage.unknown".to_owned());
    }
    if !matches!(storage, "PKCS12" | "JKS") {
        let readers = keys::terminals(storage).map_err(|e| e.message)?;
        if readers.is_empty() {
            return Err("storage.empty".to_owned());
        }
    }
    let request = SelectArgs {
        action: if key_type == "AUTHENTICATION" {
            Action::Authenticate
        } else {
            Action::Sign
        },
        storages: vec![storage.to_owned()],
        filter: Filter {
            // Expired keys are flagged and still signable; no path or OCSP check.
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
        more: FilterMore {
            knca_types: vec![key_type.to_owned()],
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: KeyOrder::OldestFirst,
    };
    match keys::select(&request) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err("action.canceled".to_owned()),
        Err(e) => Err(e.message),
    }
}

/// `XMLUtil.createXmlSignature`: the whole document for an empty `tbs`, else that element,
/// the signature going into `parent` (the document element for an empty one).
fn sign_document(key: &Key, xml: &str, tbs: &str, parent: &str) -> Result<String, String> {
    let signed = if tbs.is_empty() {
        key.sign_xml(xml.as_bytes(), None, None)
    } else {
        if equals_ignore_case(parent, tbs) {
            return Err("При подписи элемента XML, элемент подписи не может быть родительским элементом подписи.".to_owned());
        }
        let parent = (!parent.is_empty()).then_some(parent);
        key.sign_xml(xml.as_bytes(), Some(tbs), parent)
    }
    .map_err(|e| e.message)?;
    String::from_utf8(signed).map_err(|e| e.to_string())
}

/// Java's `String.equalsIgnoreCase` for the characters XPaths hold.
fn equals_ignore_case(a: &str, b: &str) -> bool {
    let fold = |c: char| c.to_uppercase().next().unwrap_or(c);
    a.chars().count() == b.chars().count()
        && a.chars().zip(b.chars()).all(|(x, y)| fold(x) == fold(y))
}

/// `UUID.randomUUID().toString()`.
fn uuid() -> Result<String, String> {
    let mut bytes = host::random(16).map_err(|e| e.message)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
