//! The Digital TaxTech multisign module (`kz.digital.taxtech.documents.multisign.NCAModule`):
//! the basics module's "choose a key once, sign many" flow. `selectKey` keeps the chosen key
//! bound to the page's origin; `sign` signs with it as `xml`, `cms` (PEM) or `raw`.
//!
//! Replies are the original's response beans as org.json writes them: a `HashMap` of 16
//! buckets (`success`, `errorCode`, `errorMessage`, `version`, `result`, `subjectDN`, `iin`,
//! `bin`; absent values left out). The key lives in this instance (one connection), not in
//! the process as the original's.
#![cfg(target_arch = "wasm32")]

use oncl_pdk::abi::{
    Action, Bytes, CmsContent, CmsOutcome, CoSign, Filter, FilterMore, HostError, KeyOrder,
    SignCmsExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource, TsaChoice,
};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host, javab64};
use std::sync::Mutex;

oncl_pdk::plugin!(handle);

/// clientAuth: a key for authentication.
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// Every Kalkan storage, in Kalkan's order: the original's storage dialog offers them all.
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

/// The origin of a page without one (or one the pattern does not match).
const UNDEFINED: &str = "UNDEFINED";

/// The original's failures: code and message.
const SIGNING_FAILURE: (&str, &str) = ("SIGNING_FAILURE", "Signing has failed.");
const INVALID_SIGNING_PARAMS: (&str, &str) = (
    "INVALID_SIGNING_PARAMS",
    "Invalid signing parameters provided.",
);
const CERTIFICATE_PARSING_FAILURE: (&str, &str) = (
    "CERTIFICATE_PARSING_FAILURE",
    "Certificate parsing failure.",
);
const CERTIFICATE_EXPIRED: (&str, &str) = ("CERTIFICATE_EXPIRED", "Certificate expired.");
const KEY_NOT_SELECTED: (&str, &str) = ("KEY_NOT_SELECTED", "Key not selected.");

/// The key `selectKey` chose and what its reply said.
struct Holder {
    origin: String,
    key: Key,
    subject_dn: String,
    iin: Option<String>,
    bin: Option<String>,
}

/// The selected key of this instance.
static HOLDER: Mutex<Option<Holder>> = Mutex::new(None);

/// Why a method failed.
enum Failure {
    /// A `CommonException`: its code and message.
    Common(&'static str, &'static str),
    /// Any other exception: `TECH_ERROR` with its `getMessage()`, if any.
    Tech(Option<String>),
}

impl From<(&'static str, &'static str)> for Failure {
    fn from((code, message): (&'static str, &'static str)) -> Failure {
        Failure::Common(code, message)
    }
}

/// An org.json reader's failure: `TECH_ERROR` with its message.
fn tech(message: String) -> Failure {
    Failure::Tech(Some(message))
}

/// A response bean as org.json writes it. Entries go in the getter order the specs give for
/// keys sharing a bucket (`success` before `bin`, `subjectDN` before `iin`).
fn bean(success: bool) -> JObject {
    let mut reply = JObject::hash_map();
    reply.put("success", success);
    reply
}

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(root)) = orgjson::parse(&request.text) else {
        return dropped();
    };
    let root = root.to_map();
    // Read before the original's `try`: a missing method drops the connection.
    let Ok(method) = orgjson::get_string(&root, "method") else {
        return dropped();
    };
    let origin = normalized_origin(request.origin.as_deref());
    let outcome = match method {
        "version" => {
            let mut reply = bean(true);
            reply.put("version", "1.0");
            Ok(reply)
        }
        "selectKey" => select_key(&root, origin),
        "selectedKeyInfo" => selected_key_info(&origin),
        "reset" => {
            *HOLDER.lock().unwrap_or_else(|e| e.into_inner()) = None;
            Ok(bean(true))
        }
        "sign" => sign(&root, &origin),
        // The command map has no entry: a NullPointerException.
        _ => Err(Failure::Tech(None)),
    };
    match outcome {
        Ok(reply) => reply.to_json(),
        Err(failure) => {
            let mut reply = bean(false);
            match failure {
                Failure::Common(code, message) => {
                    reply.put("errorMessage", message);
                    reply.put("errorCode", code);
                }
                Failure::Tech(message) => {
                    reply.put_opt("errorMessage", message);
                    reply.put("errorCode", "TECH_ERROR");
                }
            }
            reply.to_json()
        }
    }
}

/// The connection is dropped without a reply, as for an exception the original let out.
fn dropped() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// `scheme://host[:port]` of the origin: the first match of `(https?://[^/]*)/*.*`, else
/// `UNDEFINED`.
fn normalized_origin(origin: Option<&str>) -> String {
    let Some(origin) = origin else {
        return UNDEFINED.to_owned();
    };
    for (at, _) in origin.match_indices("http") {
        let rest = &origin[at + 4..];
        let rest = rest.strip_prefix('s').unwrap_or(rest);
        if let Some(after) = rest.strip_prefix("://") {
            let host = after.split('/').next().unwrap_or_default();
            let end = origin.len() - after.len() + host.len();
            return origin[at..end].to_owned();
        }
    }
    UNDEFINED.to_owned()
}

/// The class org.json holds a parsed value as, for a `ClassCastException` message.
fn java_class(value: &Value) -> &'static str {
    match value {
        Value::Null => "org.json.JSONObject$Null",
        Value::Bool(_) => "java.lang.Boolean",
        Value::Number(n) => match n.as_i64() {
            Some(i) if i32::try_from(i).is_ok() => "java.lang.Integer",
            Some(_) => "java.lang.Long",
            None if n.is_u64() => "java.math.BigInteger",
            None => "java.math.BigDecimal",
        },
        Value::String(_) => "java.lang.String",
        Value::Array(_) => "org.json.JSONArray",
        Value::Object(_) => "org.json.JSONObject",
    }
}

/// An element of a JSON array cast to `String`, as the original's loops do.
fn cast_string(value: &Value) -> Result<&str, Failure> {
    value.as_str().ok_or_else(|| {
        tech(format!(
            "{} cannot be cast to java.lang.String",
            java_class(value)
        ))
    })
}

/// `selectKey{locale, signerParams{extKeyUsageOids, iin, bin, serialNumber, chain}}`.
fn select_key(root: &Map<String, Value>, origin: String) -> Result<JObject, Failure> {
    let args = orgjson::get_object(root, "args").map_err(tech)?;
    // The windows speak OpenNCALayer's language; args.locale is read and not used.
    let _locale = orgjson::opt_string(args, "locale");
    let params = orgjson::get_object(args, "signerParams").map_err(tech)?;
    let chain = match orgjson::opt_array(params, "chain") {
        None => None,
        Some(certs) => Some(
            certs
                .iter()
                .map(|cert| {
                    let text = cast_string(cert)?.replace(['\r', '\n'], "");
                    javab64::decode_java(text.trim())
                        .map(Bytes::from)
                        .map_err(|_| Failure::from(CERTIFICATE_PARSING_FAILURE))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    let ext_key_usages = orgjson::get_array(params, "extKeyUsageOids")
        .map_err(tech)?
        .iter()
        .map(|oid| cast_string(oid).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let text = |key| orgjson::opt_string(params, key).unwrap_or_default();
    let client_auth = ext_key_usages.iter().any(|oid| oid == CLIENT_AUTH);
    let request = SelectArgs {
        action: if client_auth {
            Action::Authenticate
        } else {
            Action::Sign
        },
        storages: STORAGES.map(str::to_owned).to_vec(),
        filter: Filter {
            ext_key_usages,
            iin: text("iin"),
            bin: text("bin"),
            serial_number: text("serialNumber"),
            allow_expired: false,
            chain,
            allow_revoked: false,
        },
        more: FilterMore {
            obsolete_auth: true,
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: KeyOrder::OldestFirst,
    };
    let key = match keys::select(&request) {
        Ok(Some(key)) => key,
        Ok(None) => return Err(KEY_NOT_SELECTED.into()),
        Err(e) if e.message.starts_with("chain") => return Err(CERTIFICATE_PARSING_FAILURE.into()),
        Err(e) => return Err(host_failure(e)),
    };
    let subject_dn = host::cert_details(key.certificate())
        .map_err(host_failure)?
        .subject_dn;
    let holder = Holder {
        origin,
        iin: twelve_digits_after(&subject_dn, "SERIALNUMBER=IIN"),
        bin: twelve_digits_after(&subject_dn, "OU=BIN"),
        subject_dn,
        key,
    };
    let reply = key_reply(&holder);
    *HOLDER.lock().unwrap_or_else(|e| e.into_inner()) = Some(holder);
    Ok(reply)
}

/// A host function's failure: `TECH_ERROR` without a message.
fn host_failure(_: HostError) -> Failure {
    Failure::Tech(None)
}

/// The group of `.*<marker>(\d{12}).*` in `dn`: the last `marker` followed by 12 digits.
fn twelve_digits_after(dn: &str, marker: &str) -> Option<String> {
    dn.rmatch_indices(marker).find_map(|(at, _)| {
        let digits = dn[at + marker.len()..].get(..12)?;
        digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.to_owned())
    })
}

/// The reply of `selectKey` and `selectedKeyInfo`.
fn key_reply(holder: &Holder) -> JObject {
    let mut reply = bean(true);
    reply.put_opt("bin", holder.bin.clone());
    reply.put("subjectDN", holder.subject_dn.as_str());
    reply.put_opt("iin", holder.iin.clone());
    reply
}

/// `selectedKeyInfo`: the selected key's reply, for the origin that selected it.
fn selected_key_info(origin: &str) -> Result<JObject, Failure> {
    let holder = HOLDER.lock().unwrap_or_else(|e| e.into_inner());
    match holder.as_ref() {
        Some(holder) if holder.origin == origin => Ok(key_reply(holder)),
        _ => Err(KEY_NOT_SELECTED.into()),
    }
}

/// `sign{format, data, signingParams{decode, encapsulate, digested, tsaProfile{withTsp}}}`.
fn sign(root: &Map<String, Value>, origin: &str) -> Result<JObject, Failure> {
    let holder = HOLDER.lock().unwrap_or_else(|e| e.into_inner());
    let Some(holder) = holder.as_ref().filter(|h| h.origin == origin) else {
        return Err(KEY_NOT_SELECTED.into());
    };
    let info = host::cert_info(holder.key.certificate()).map_err(host_failure)?;
    let now = host::now().map_err(host_failure)?;
    if now < info.not_before || now > info.not_after {
        return Err(CERTIFICATE_EXPIRED.into());
    }
    let args = orgjson::get_object(root, "args").map_err(tech)?;
    let format = orgjson::get_string(args, "format").map_err(tech)?;
    let params = orgjson::opt_object(args, "signingParams");
    let decode = params.is_some_and(|p| orgjson::opt_boolean(p, "decode", false));
    // Unverified against the original: whether a malformed `data` is a TECH_ERROR (read
    // before signing, as here) or a SIGNING_FAILURE.
    let data: Vec<String> = match orgjson::opt_array(args, "data") {
        Some(items) => (0..items.len())
            .map(|i| orgjson::array_get_string(items, i).map(str::to_owned))
            .collect::<Result<_, _>>()
            .map_err(tech)?,
        None => vec![orgjson::get_string(args, "data").map_err(tech)?.to_owned()],
    };
    let result = match format {
        "xml" => JValue::Arr(
            data.iter()
                .map(|xml| {
                    let signed = holder
                        .key
                        .sign_xml(xml.as_bytes(), None, None)
                        .map_err(|_| Failure::from(SIGNING_FAILURE))?;
                    String::from_utf8(signed)
                        .map(JValue::Str)
                        .map_err(|_| SIGNING_FAILURE.into())
                })
                .collect::<Result<_, Failure>>()?,
        ),
        "cms" => {
            // Without signingParams the original dereferences null.
            let params = params.ok_or(Failure::Tech(None))?;
            let bytes = first(&data, decode)?;
            JValue::Str(sign_cms(&holder.key, bytes, params)?)
        }
        "raw" => {
            let bytes = first(&data, decode)?;
            let signature = holder
                .key
                .sign_raw(&bytes)
                .map_err(|_| Failure::from(SIGNING_FAILURE))?;
            JValue::Str(base64(&signature))
        }
        _ => return Err(INVALID_SIGNING_PARAMS.into()),
    };
    let mut reply = bean(true);
    reply.put("result", result);
    Ok(reply)
}

/// The first document: base64 (`decode`) or UTF-8 text. Only it is signed.
fn first(data: &[String], decode: bool) -> Result<Vec<u8>, Failure> {
    let text = data.first().ok_or(Failure::from(SIGNING_FAILURE))?;
    if decode {
        javab64::decode_java(text).map_err(|_| SIGNING_FAILURE.into())
    } else {
        Ok(text.as_bytes().to_vec())
    }
}

/// `createCAdES(entity, bytes, encapsulate, digested)`, time-stamped by Kalkan's default
/// TSA profile with `tsaProfile.withTsp`: the CMS as PEM.
fn sign_cms(key: &Key, bytes: Vec<u8>, params: &Map<String, Value>) -> Result<String, Failure> {
    let encapsulate = orgjson::opt_boolean(params, "encapsulate", true);
    let digested = orgjson::opt_boolean(params, "digested", false);
    let with_tsp = orgjson::opt_object(params, "tsaProfile")
        .is_some_and(|tsa| orgjson::opt_boolean(tsa, "withTsp", false));
    let args = SignCmsExArgs {
        handle: key.handle(),
        content: if digested {
            CmsContent::Digest(Bytes::from(bytes))
        } else {
            CmsContent::Data(Bytes::from(bytes))
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
        timestamp: with_tsp.then_some(TsaChoice::Kalkan),
    };
    // Unverified against the original: provider_util codes of signing failures (here all
    // SIGNING_FAILURE).
    let cms = match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => cms,
        Ok(CmsOutcome::TspFailed(_)) | Err(_) => return Err(SIGNING_FAILURE.into()),
    };
    let separator = host::platform().map_err(host_failure)?.line_separator;
    Ok(pem("CMS", &cms, &separator))
}

/// Kalkan's `PEMWriter`: the base64 in lines of 64, every line ended by `separator`.
fn pem(label: &str, der: &[u8], separator: &str) -> String {
    let body = base64(der);
    let mut out = format!("-----BEGIN {label}-----{separator}");
    for line in body.as_bytes().chunks(64) {
        // Base64 is ASCII.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push_str(separator);
    }
    out.push_str(&format!("-----END {label}-----{separator}"));
    out
}

/// `Base64.getEncoder()`: without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
