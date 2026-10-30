//! The ESF signer (`com.osdkz.esf.signer.esfSigner`): raw signatures of e-invoice texts
//! (`signPlainData`, `signPlainDataMap`) and of a sign-in challenge (`auth`), with the
//! chosen key's details (`keyInfo`).
//!
//! Replies are the original's `ResponseMessage` bean (`responseObject`, `code`, `message`)
//! as org.json writes it; the response objects are `HashMap`s passed to
//! `new JSONObject(map)`.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{Action, Filter, FilterMore, KeyOrder};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::{Request, host, javab64};
use oncl_port_pki::x509text;

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

/// The cancelled dialog's message.
const CANCELED: &str = "action.canceled";

/// Kalkan's name of a GOST 2015 public key.
const GOST2015: &str = "ECGOST3410-2015";

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        return dropped();
    };
    let map = root.to_map();
    // `method`, `storageName` and `data` are read outside the original's `try`.
    let Ok(method) = orgjson::get_string(&map, "method") else {
        return dropped();
    };
    let outcome = match method {
        "signPlainData" | "auth" => {
            let (Ok(storage), Ok(data)) = (
                orgjson::get_string(&map, "storageName"),
                orgjson::get_string(&map, "data"),
            ) else {
                return dropped();
            };
            if method == "auth" {
                auth(storage, data)
            } else {
                sign_plain_data(storage, data)
            }
        }
        "signPlainDataMap" => {
            let Ok(storage) = orgjson::get_string(&map, "storageName") else {
                return dropped();
            };
            let Some(JValue::Obj(data)) = root.get("data") else {
                return dropped();
            };
            sign_plain_data_map(storage, data)
        }
        _ => {
            let mut reply = JObject::hash_map();
            reply.put("code", "404");
            return reply.to_json();
        }
    };
    let mut reply = JObject::hash_map();
    match outcome {
        Ok(object) => {
            reply.put("code", "200");
            reply.put("responseObject", object);
        }
        Err(message) => {
            reply.put("code", "500");
            reply.put_opt("message", message);
        }
    }
    reply.to_json()
}

/// The connection is dropped without a reply, as for an exception the original let out.
fn dropped() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// What failed: `getMessage()`, `None` for an exception without one.
type Outcome = Result<JObject, Option<String>>;

/// `new JSONObject(map)` of a `HashMap` filled with `entries` in order.
fn from_map(entries: Vec<(String, JValue)>) -> JObject {
    let mut source = JObject::hash_map();
    for (key, value) in entries {
        source.put(key, value);
    }
    let mut object = JObject::from_map(source.len());
    for (key, value) in source.iter() {
        object.put(key, value.clone());
    }
    object
}

/// `signPlainData`: the signature of `data`, the certificate and its details.
fn sign_plain_data(storage: &str, data: &str) -> Outcome {
    let key = choose(storage, "SIGNATURE", Action::Sign)?;
    let signature = sign(&key, data)?;
    let (info, pem) = key_info(&key)?;
    Ok(from_map(vec![
        ("signature".to_owned(), signature.into()),
        ("pem".to_owned(), pem.into()),
        ("keyInfo".to_owned(), info.into()),
    ]))
}

/// `signPlainDataMap`: one key, a signature of every value; a page key `keyInfo` takes the
/// key details' place.
fn sign_plain_data_map(storage: &str, data: &JObject) -> Outcome {
    let key = choose(storage, "SIGNATURE", Action::Sign)?;
    let (info, _) = key_info(&key)?;
    let mut entries = vec![("keyInfo".to_owned(), JValue::Obj(info))];
    // `data.toMap()` in its order; each value cast to `String`.
    for (name, value) in data.iter() {
        let text = match value {
            JValue::Str(text) => text,
            // `toMap()` makes JSONObject.NULL a Java null: signing it dereferences null.
            JValue::Null => return Err(None),
            other => {
                return Err(Some(format!(
                    "{} cannot be cast to java.lang.String",
                    java_class(other)
                )));
            }
        };
        entries.push((name.to_owned(), sign(&key, text)?.into()));
    }
    Ok(from_map(entries))
}

/// The class `toMap()` gives a value.
fn java_class(value: &JValue) -> &'static str {
    match value {
        JValue::Null => "null",
        JValue::Bool(_) => "java.lang.Boolean",
        JValue::Int(i) if i32::try_from(*i).is_ok() => "java.lang.Integer",
        JValue::Int(_) => "java.lang.Long",
        JValue::Dec(text) if text.contains(['.', 'e', 'E']) => "java.math.BigDecimal",
        JValue::Dec(_) => "java.math.BigInteger",
        JValue::Str(_) | JValue::Raw(_) => "java.lang.String",
        JValue::Obj(_) => "java.util.HashMap",
        JValue::Arr(_) => "java.util.ArrayList",
    }
}

/// `auth`: an authentication key (or, without one, a GOST 2015 signing key) signs `data`.
fn auth(storage: &str, data: &str) -> Outcome {
    // Unverified against the original: it offers GOST 2015 signing keys only when the store
    // has no authentication key; here a second dialog follows whenever the first one ends
    // without a key.
    let key = match choose(storage, "AUTHENTICATION", Action::Authenticate) {
        Err(Some(message)) if message == CANCELED => {
            let key = choose(storage, "SIGNATURE", Action::Authenticate)?;
            let info = host::cert_info(key.certificate()).map_err(|e| Some(e.message))?;
            if x509text::kalkan_key_alg_name(&info.spki_alg_oid) != Some(GOST2015) {
                return Err(Some(CANCELED.to_owned()));
            }
            key
        }
        other => other?,
    };
    let signature = sign(&key, data)?;
    let (info, _) = key_info(&key)?;
    Ok(from_map(vec![
        ("keyInfo".to_owned(), info.into()),
        ("data".to_owned(), data.into()),
        ("signature".to_owned(), signature.into()),
    ]))
}

/// The storage checks of `StorageInfo`, then the key dialog over keys of `key_type`.
fn choose(storage: &str, key_type: &str, action: Action) -> Result<Key, Option<String>> {
    if storage.trim().is_empty() {
        return Err(Some("storageName.param.empty".to_owned()));
    }
    if !STORAGES.contains(&storage) {
        return Err(Some("storage.unknown".to_owned()));
    }
    if !matches!(storage, "PKCS12" | "JKS") {
        let readers = keys::terminals(storage).map_err(|e| Some(e.message))?;
        if readers.is_empty() {
            return Err(Some("storage.empty".to_owned()));
        }
    }
    let request = SelectArgs {
        action,
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
        Ok(None) => Err(Some(CANCELED.to_owned())),
        Err(e) => Err(Some(e.message)),
    }
}

/// `Signature.getInstance(cert.getSigAlgName(), "KALKAN")` over the UTF-8 of `data`:
/// base64.
fn sign(key: &Key, data: &str) -> Result<String, Option<String>> {
    let details = host::cert_details(key.certificate()).map_err(|e| Some(e.message))?;
    if !matches!(
        details.signing_alg.as_deref(),
        Some("gost2004" | "gost2015_512" | "rsa_sha256")
    ) {
        // OpenNCALayer makes no SHA-1 RSA signatures (nor GOST 2015-256 ones).
        let info = host::cert_info(key.certificate()).map_err(|e| Some(e.message))?;
        let name = x509text::kalkan_sig_alg_name(&info.signature_alg_oid)
            .unwrap_or(&info.signature_alg_oid)
            .to_owned();
        return Err(Some(format!(
            "no such algorithm: {name} for provider KALKAN"
        )));
    }
    let signature = key.sign_raw(data.as_bytes()).map_err(|e| Some(e.message))?;
    Ok(base64(&signature))
}

/// The `keyInfo` bean of `key` (a `HashMap` of 16 buckets, `null`s left out) and the
/// certificate's PEM.
fn key_info(key: &Key) -> Result<(JObject, String), Option<String>> {
    let cert = key.certificate();
    let info = host::cert_info(cert).map_err(|e| Some(e.message))?;
    let details = host::cert_details(cert).map_err(|e| Some(e.message))?;
    // Without a subjectKeyIdentifier both identifiers are left out.
    let authority = details.ski_hex.as_ref().and(details.aki_hex.clone());
    let mut object = JObject::hash_map();
    // Keys sharing a bucket go in the getter order the specs give (alias before pem,
    // algorithm before subjectDn).
    object.put("alias", key.alias());
    object.put_opt("keyId", details.ski_hex.clone());
    object.put_opt(
        "algorithm",
        x509text::kalkan_key_alg_name(&info.spki_alg_oid),
    );
    object.put_opt("subjectCn", info.subject_cn.clone());
    object.put("subjectDn", details.subject_dn.as_str());
    object.put_opt("issuerCn", x509text::ldap_first(&details.issuer_dn, "CN"));
    object.put("issuerDn", details.issuer_dn.as_str());
    object.put("serialNumber", info.serial_hex.as_str());
    object.put("certNotAfter", info.not_after.to_string());
    object.put("certNotBefore", info.not_before.to_string());
    object.put_opt("authorityKeyIdentifier", authority);
    object.put("pem", info.pem.as_str());
    object.put("base64Pem", base64(cert));
    Ok((object, info.pem))
}

/// `Base64.getEncoder()`: without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
