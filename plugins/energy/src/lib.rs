//! Sign Energy (`kz.energy.sign.SignEnergy`): `ping`, `getKeyInfo` (the details of a key the
//! user chooses) and `sign` (a CAdES of each document). A key signed with under a page's
//! `alias` is remembered in this instance (one connection): the next `sign` with that alias
//! is silent. Replies are written as `JSONStringer` writes them, the original's
//! `JSONObject`s inside them in `HashMap` order.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, Bytes, CmsContent, CmsOutcome, CoSign, Filter, KeyOrder, MessageKind, SignCmsExArgs,
    SignedAttrs, SigningTime, TimeForm, TimeSource, TsaChoice,
};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, dialogs, host, javab64, settings};
use oncl_port_pki::x509text;
use std::sync::Mutex;

oncl_pdk::plugin!(handle);

const ALIAS_MISMATCH: &str = "Сертификат ЭЦП не соответствует сертификату в профиле пользователя.";
const SIGNING_ERROR: &str = "Ошибка при подписи. Проверьте параметры ключа.";
const UNKNOWN_ERROR: &str = "Произошла неизвестная ошибка.";

/// Keys signed with under a page's alias, in this instance.
static REMEMBERED: Mutex<Vec<(String, Key)>> = Mutex::new(Vec::new());

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        return dropped();
    };
    let root = root.to_map();
    let method = orgjson::opt_string(&root, "method").unwrap_or_default();
    if !matches!(method.as_str(), "ping" | "getKeyInfo" | "sign") {
        let mut reply = JObject::stringer();
        reply.put("success", false);
        reply.put("message", "method_not_defined");
        return reply.to_json();
    }
    // Unverified against the original: whether `args` is read before the method is
    // looked up (here after: an unknown method answers even without args).
    let Ok(args) = orgjson::get_object(&root, "args") else {
        return dropped();
    };
    match method.as_str() {
        "ping" => {
            let number = orgjson::opt_int(args, "number", 0).wrapping_add(1);
            let mut body = JObject::stringer();
            body.put("result", format!("Pong={number}"));
            success(true, body)
        }
        "getKeyInfo" => key_info(args),
        _ => sign(args),
    }
}

/// `{"success":…,"message":"null","body":…}`: the message is `String.valueOf(null)`.
fn success(success: bool, body: JObject) -> String {
    let mut reply = JObject::stringer();
    reply.put("success", success);
    reply.put("message", "null");
    reply.put("body", body);
    reply.to_json()
}

/// The connection is dropped without a reply, as for an exception the original let out.
fn dropped() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// The storage the page names, `PKCS12` by default.
fn store_type(args: &Map<String, Value>) -> String {
    orgjson::opt_string(args, "keyStoreType").unwrap_or_else(|| "PKCS12".to_owned())
}

/// The key dialog for `action` over the storage `store`, every key of it offered as the
/// original's key store list was (no path, validity or revocation conditions).
fn choose(action: Action, store: &str) -> Result<Option<Key>, ()> {
    keys::select(&SelectArgs {
        action,
        storages: vec![store.to_owned()],
        filter: Filter {
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
    .map_err(|_| ())
}

/// `getKeyInfo{keyStoreType}`: the details of the key the user chooses. A cancelled dialog
/// or a failure has no reply: the connection drops, as the original's.
fn key_info(args: &Map<String, Value>) -> String {
    let Ok(Some(key)) = choose(Action::KeyInfo, &store_type(args)) else {
        return dropped();
    };
    let Some((info, record)) = describe(&key) else {
        return dropped();
    };
    let mut reply = JObject::stringer();
    reply.put("code", "200");
    reply.put("responseObject", info);
    remember_record(key.alias(), record);
    reply.to_json()
}

/// provider_util's `KeyInfo` of `key` (`put` in its order into a `HashMap`, `null`s left
/// out) and the record kept in the settings.
fn describe(key: &Key) -> Option<(JObject, JObject)> {
    let cert = key.certificate();
    let info = host::cert_info(cert).ok()?;
    let details = host::cert_details(cert).ok()?;
    // Without a subjectKeyIdentifier the original leaves out both identifiers.
    let authority = details.ski_hex.as_ref().and(details.aki_hex.clone());
    let mut object = JObject::hash_map();
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
    let mut record = JObject::hash_map();
    record.put("alias", key.alias());
    record.put_opt("subjectCn", info.subject_cn);
    record.put("certNotAfter", info.not_after.to_string());
    record.put("certNotBefore", info.not_before.to_string());
    Some((object, record))
}

/// Keeps the key's record under `alias` in the settings: no path, no password. A failure
/// to keep it changes nothing in the reply.
fn remember_record(alias: &str, record: JObject) {
    let Ok(mut stored) = settings::get() else {
        return;
    };
    stored.insert(alias.to_owned(), record.to_json());
    let _ = settings::put(&stored);
}

/// A document of `sign`.
struct Document {
    id: Option<String>,
    name: Option<String>,
    base64: Option<String>,
}

/// `sign{alias, keyStoreType, encapsulate, isDigested, tsaProfile, data[{id, name,
/// base64}]}`.
fn sign(args: &Map<String, Value>) -> String {
    let alias = orgjson::opt_string(args, "alias").filter(|a| !a.is_empty());
    let store = store_type(args);
    let encapsulate = orgjson::opt_boolean(args, "encapsulate", true);
    let digested = orgjson::opt_boolean(args, "isDigested", false);
    let timestamp = orgjson::opt_boolean(args, "tsaProfile", false);
    let mut documents = Vec::new();
    for item in orgjson::opt_array(args, "data").unwrap_or_default() {
        // `getJSONObject(i)`: an element that is not an object drops the connection.
        let Some(item) = item.as_object() else {
            return dropped();
        };
        documents.push(Document {
            id: orgjson::opt_string(item, "id"),
            name: orgjson::opt_string(item, "name"),
            base64: orgjson::opt_string(item, "base64"),
        });
    }
    loop {
        let key = match alias.as_deref().and_then(take_remembered) {
            Some(key) => key,
            None => match choose(Action::Sign, &store) {
                Ok(Some(key)) => key,
                Ok(None) => {
                    let mut body = JObject::stringer();
                    body.put("result", JValue::Arr(Vec::new()));
                    let mut reply = JObject::stringer();
                    reply.put("success", false);
                    reply.put("message", "signing_cancelled_by_user");
                    reply.put("body", body);
                    return reply.to_json();
                }
                Err(()) => {
                    let _ = dialogs::message(MessageKind::Error, UNKNOWN_ERROR);
                    let mut body = JObject::stringer();
                    body.put("result", JValue::Arr(Vec::new()));
                    return success(false, body);
                }
            },
        };
        if alias.as_deref().is_some_and(|alias| alias != key.alias()) {
            let _ = dialogs::message(MessageKind::Error, ALIAS_MISMATCH);
            continue;
        }
        // A failure shows the original's message and starts over with an empty result;
        // a remembered key that failed is forgotten, so the dialog comes back.
        let Some(signed) = sign_all(&key, &documents, encapsulate, digested, timestamp) else {
            let _ = dialogs::message(MessageKind::Error, SIGNING_ERROR);
            continue;
        };
        if let Some(alias) = &alias {
            if let Some((_, record)) = describe(&key) {
                remember_record(alias, record);
            }
            REMEMBERED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((alias.clone(), key));
        }
        let mut body = JObject::stringer();
        body.put("result", JValue::Arr(signed));
        return success(true, body);
    }
}

/// The key remembered under `alias`, taken out.
fn take_remembered(alias: &str) -> Option<Key> {
    let mut remembered = REMEMBERED.lock().unwrap_or_else(|e| e.into_inner());
    let at = remembered.iter().position(|(a, _)| a == alias)?;
    Some(remembered.remove(at).1)
}

/// A CAdES of every document (`{"name","signedBase64","id"}` in `HashMap` order); `None`
/// if one fails.
fn sign_all(
    key: &Key,
    documents: &[Document],
    encapsulate: bool,
    digested: bool,
    timestamp: bool,
) -> Option<Vec<JValue>> {
    documents
        .iter()
        .map(|document| {
            let data = javab64::decode_java(document.base64.as_deref()?).ok()?;
            let args = SignCmsExArgs {
                handle: key.handle(),
                content: if digested {
                    CmsContent::Digest(Bytes::from(data))
                } else {
                    CmsContent::Data(Bytes::from(data))
                },
                encapsulate,
                cosign: if digested {
                    CoSign::Never
                } else {
                    CoSign::Auto
                },
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
                certificates: Default::default(),
                timestamp: timestamp.then_some(TsaChoice::Kalkan),
                output: oncl_pdk::abi::CmsOutput::Der,
            };
            let Ok(CmsOutcome::Signed(cms)) = key.sign_cms_ex(args) else {
                return None;
            };
            let mut signed = JObject::hash_map();
            signed.put_opt("id", document.id.clone());
            signed.put_opt("name", document.name.clone());
            signed.put(
                "signedBase64",
                javab64::encode_mime(&cms).replace("\r\n", ""),
            );
            Some(JValue::Obj(signed))
        })
        .collect()
}
