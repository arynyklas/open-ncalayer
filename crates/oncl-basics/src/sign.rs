//! `PKIExtras.sign`: the arguments as the original reads them with org.json, then the
//! storage → key → sign flow under the process-wide signing-flow lock.

use crate::Basics;
use crate::filter::{Availability, KeyFilter};
use crate::prompt::{
    Action, KeyCandidate, KeyPrompt, Locale, OpenError, Prompt, StorageAnswer, StorageKind,
    StoragePrompt,
};
use base64::Engine;
use base64::alphabet;
use base64::engine::general_purpose::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use der::Encode;
use oncl_pki::cms::{self, CmsError, SignOptions};
use oncl_pki::info::cert_info;
use oncl_pki::key::{KeyAlg, KeyError, SigAlg};
use oncl_pki::pkcs12::{self, KeyEntry, Pkcs12Error};
use oncl_pki::{pem, tsp};
use oncl_protocol::AddInfo;
use oncl_protocol::invoker::{CallResult, Failure};
use serde_json::{Map, Value, json};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::sync::{Mutex, PoisonError};

const SIGNING_FAILURE: &str = "SIGNING_FAILURE";
const SIGNING_FAILURE_MESSAGE: &str = "Signing has failed.";
const INVALID_SIGNING_PARAMS: &str = "INVALID_SIGNING_PARAMS";
const INVALID_SIGNING_PARAMS_MESSAGE: &str = "Invalid signing parameters provided.";
const CMS_NO_ENCAPSULATED_DATA: &str = "CMS_NO_ENCAPSULATED_DATA";
const UNKNOWN_ALGORITHM: &str = "UNKNOWN_ALGORITHM";
const TIMESTAMP_CREATION_FAILURE: &str = "TIMESTAMP_CREATION_FAILURE";

/// Origin shown when the connection sent none.
const UNIDENTIFIED: &str = "UNIDENTIFIED";
/// clientAuth: asking for it makes the dialog an authentication.
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// Serializes signing flows process-wide: the dialogs of two requests never interleave, and
/// a second request waits for the first instead of failing as busy.
static SIGN_FLOW: Mutex<()> = Mutex::new(());

/// Java's `Base64.getDecoder()`: the standard alphabet, no whitespace, padding optional but
/// complete when present, trailing bits ignored. Inputs ending in `=` use [`PADDED`].
const UNPADDED: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);
const PADDED: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

/// What to produce.
enum Format {
    Cms {
        encapsulate: bool,
        digested: bool,
        timestamp: bool,
    },
    Raw {
        output_cert: bool,
    },
}

/// A parsed `sign` request; `data` borrows from the request unless base64-decoded.
struct SignRequest<'a> {
    storages: Vec<StorageKind>,
    origin: String,
    locale: Locale,
    action: Action,
    format: Format,
    data: Vec<Cow<'a, [u8]>>,
    filter: KeyFilter,
}

/// `PKIExtras.sign`.
pub(crate) fn sign(basics: &Basics, args: &Map<String, Value>, add_info: &AddInfo) -> CallResult {
    let request = SignRequest::parse(args, add_info)?;
    let _flow = SIGN_FLOW.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(mut entries) = open_storage(basics, &request) else {
        return Ok(json!({}));
    };
    let Some(index) = choose_key(basics, &request, &entries) else {
        return Ok(json!({}));
    };
    let entry = entries.swap_remove(index);
    let result = match request.format {
        Format::Cms {
            encapsulate,
            digested,
            timestamp,
        } => {
            let opts = SignOptions {
                encapsulate,
                digested,
                signing_time: (basics.clock)(),
            };
            let pems = request
                .data
                .iter()
                .map(|data| sign_cms(basics, &entry, data, &opts, timestamp).map(Value::String))
                .collect::<Result<Vec<_>, _>>()?;
            Value::Array(pems)
        }
        Format::Raw { output_cert } => sign_raw(&entry, &request.data, output_cert)?,
    };
    Ok(json!({ "result": result }))
}

impl<'a> SignRequest<'a> {
    /// Reads the arguments in the original's order, so the first missing one is reported.
    fn parse(args: &'a Map<String, Value>, add_info: &AddInfo) -> Result<Self, Failure> {
        // `(String) e` on each entry: a non-string is a ClassCastException; null and unknown
        // names are dropped (`Storage.get` finds nothing); duplicates stay.
        let storages = match args.get("allowedStorages") {
            Some(Value::Array(names)) => {
                let mut storages = Vec::with_capacity(names.len());
                for name in names {
                    match name {
                        Value::String(name) => storages.extend(StorageKind::from_name(name)),
                        Value::Null => {}
                        other => return Err(class_cast(other)),
                    }
                }
                storages
            }
            _ => StorageKind::all(),
        };
        let origin = add_info
            .origin
            .clone()
            .unwrap_or_else(|| UNIDENTIFIED.to_owned());
        let locale = Locale::from_arg(opt_string(args, "locale").as_deref());

        let format = get_string(args, "format")?;
        let signing_params = get_object(args, "signingParams")?;
        let decode = opt_bool(signing_params, "decode", false);
        let format = match format {
            "cms" => Format::Cms {
                encapsulate: opt_bool(signing_params, "encapsulate", true),
                digested: opt_bool(signing_params, "digested", false),
                // Only its presence counts; the profile is always the basics one.
                timestamp: matches!(signing_params.get("tsaProfile"), Some(Value::Object(_))),
            },
            "raw" => Format::Raw {
                output_cert: opt_bool(signing_params, "outputCert", false),
            },
            _ => {
                return Err(Failure::Custom {
                    code: INVALID_SIGNING_PARAMS.to_owned(),
                    message: Some(INVALID_SIGNING_PARAMS_MESSAGE.to_owned()),
                    details: None,
                });
            }
        };

        let data: Vec<&str> = match args.get("data") {
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    item.as_str()
                        .ok_or_else(|| json_exception(format!("JSONArray[{i}] is not a string.")))
                })
                .collect::<Result<_, _>>()?,
            _ => vec![get_string(args, "data")?],
        };

        let signer_params = get_object(args, "signerParams")?;
        // `toList().stream().map(Object::toString)`: a null entry is a NullPointerException.
        let ext_key_usages = get_array(signer_params, "extKeyUsageOids")?
            .iter()
            .map(|oid| match oid {
                Value::String(s) => Ok(s.clone()),
                Value::Null => Err(Failure::Invocation(Some(
                    "java.lang.NullPointerException".to_owned(),
                ))),
                other => Ok(other.to_string()),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let action = if ext_key_usages.contains(CLIENT_AUTH) {
            Action::Authenticate
        } else {
            Action::Sign
        };
        let filter = KeyFilter {
            ext_key_usages,
            iin: opt_string(signer_params, "iin").unwrap_or_default(),
            bin: opt_string(signer_params, "bin").unwrap_or_default(),
            serial_number: opt_string(signer_params, "serialNumber").unwrap_or_default(),
            allow_expired: false,
        };

        // P1 deviation: invalid base64 fails before the dialog (the original fails after it,
        // with the same code).
        let data = data
            .into_iter()
            .map(|item| {
                if decode {
                    decode_base64(item).map(Cow::Owned).map_err(signing_failure)
                } else {
                    Ok(Cow::Borrowed(item.as_bytes()))
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(SignRequest {
            storages,
            origin,
            locale,
            action,
            format,
            data,
            filter,
        })
    }
}

/// Asks for a storage until one opens; `None` if the user cancels. Saves the opened path.
fn open_storage(basics: &Basics, request: &SignRequest<'_>) -> Option<Vec<KeyEntry>> {
    let mut prompt = StoragePrompt {
        origin: request.origin.clone(),
        locale: request.locale,
        action: request.action,
        storages: request.storages.clone(),
        recent_path: basics.recent.load(),
        error: None,
    };
    loop {
        let answer = match basics.prompter.storage(&prompt) {
            Prompt::Answer(answer) => answer,
            Prompt::Cancelled => return None,
        };
        match open(&answer, &prompt.storages) {
            Ok(entries) => {
                basics.recent.save(&answer.path);
                return Some(entries);
            }
            Err(e) => {
                prompt.error = Some(e);
                prompt.recent_path = Some(answer.path);
            }
        }
    }
}

/// Opens the key store of `answer`, which must be an offered, supported storage.
fn open(answer: &StorageAnswer, offered: &[StorageKind]) -> Result<Vec<KeyEntry>, OpenError> {
    if !answer.storage.supported() || !offered.contains(&answer.storage) {
        return Err(OpenError::UnsupportedStorage);
    }
    let pfx = std::fs::read(&answer.path).map_err(|_| OpenError::FileNotFound)?;
    match pkcs12::load(&pfx, &answer.password) {
        Ok(entries) if entries.is_empty() => Err(OpenError::NoKeys),
        Ok(entries) => Ok(entries),
        Err(Pkcs12Error::WrongPassword) => Err(OpenError::WrongPassword),
        Err(Pkcs12Error::Malformed(_) | Pkcs12Error::Unsupported(_)) => Err(OpenError::NotPkcs12),
    }
}

/// Asks for a key until an enabled one is picked; `None` if the user cancels.
fn choose_key(basics: &Basics, request: &SignRequest<'_>, entries: &[KeyEntry]) -> Option<usize> {
    let now = (basics.clock)();
    let candidates = entries
        .iter()
        .map(|entry| {
            let info = cert_info(&entry.cert);
            KeyCandidate {
                alias: entry.alias.clone(),
                availability: request.filter.availability(&info, now),
                info,
            }
        })
        .collect();
    let prompt = KeyPrompt {
        origin: request.origin.clone(),
        locale: request.locale,
        action: request.action,
        candidates,
    };
    loop {
        match basics.prompter.key(&prompt) {
            Prompt::Answer(i)
                if prompt
                    .candidates
                    .get(i)
                    .is_some_and(|c| c.availability == Availability::Enabled) =>
            {
                return Some(i);
            }
            Prompt::Answer(_) => {}
            Prompt::Cancelled => return None,
        }
    }
}

/// A CAdES PEM of `data`, time-stamped on the new (last) signer if asked.
fn sign_cms(
    basics: &Basics,
    entry: &KeyEntry,
    data: &[u8],
    opts: &SignOptions,
    timestamp: bool,
) -> Result<String, Failure> {
    let mut der = cms::sign(entry, data, opts).map_err(cms_failure)?;
    if timestamp {
        let last = cms::signer_count(&der)
            .map_err(cms_failure)?
            .checked_sub(1)
            .ok_or_else(|| signing_failure("signed CMS has no signers"))?;
        der = tsp::timestamp_signer(&der, last, &basics.tsa, basics.http.as_ref())
            .map_err(|e| provider_failure(TIMESTAMP_CREATION_FAILURE, e.to_string(), &e))?;
    }
    Ok(cms::to_pem(&der))
}

/// Raw signatures with the key's algorithm (RSA: SHA-256): one string for one input, an
/// array for several, `{signatures, certificate}` with `output_cert`.
fn sign_raw(entry: &KeyEntry, data: &[Cow<'_, [u8]>], output_cert: bool) -> CallResult {
    let alg = match entry.key.alg() {
        KeyAlg::Gost2004 => SigAlg::Gost2004,
        KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        KeyAlg::Rsa => SigAlg::RsaSha256,
    };
    let mut signatures = data
        .iter()
        .map(|d| {
            entry
                .key
                .sign(alg, d)
                .map(|sig| STANDARD.encode(sig))
                .map_err(key_failure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(if output_cert {
        let cert = entry.cert.to_der().map_err(signing_failure)?;
        json!({ "signatures": signatures, "certificate": pem::encode("CERTIFICATE", &cert) })
    } else if signatures.len() == 1 {
        Value::String(signatures.swap_remove(0))
    } else {
        Value::from(signatures)
    })
}

fn decode_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if s.ends_with('=') {
        PADDED.decode(s)
    } else {
        UNPADDED.decode(s)
    }
}

fn cms_failure(e: CmsError) -> Failure {
    match e {
        CmsError::NoEncapsulatedData => {
            provider_failure(CMS_NO_ENCAPSULATED_DATA, CMS_NO_ENCAPSULATED_DATA, &e)
        }
        CmsError::UnknownAlgorithm(_) | CmsError::Key(KeyError::UnsupportedAlgorithm) => {
            provider_failure(UNKNOWN_ALGORITHM, UNKNOWN_ALGORITHM, &e)
        }
        e => signing_failure(e),
    }
}

fn key_failure(e: KeyError) -> Failure {
    match e {
        KeyError::UnsupportedAlgorithm => {
            provider_failure(UNKNOWN_ALGORITHM, UNKNOWN_ALGORITHM, &e)
        }
        e => signing_failure(e),
    }
}

/// The original's `ProviderUtilFailure`: the `ProviderUtilExceptionCode` name, the provider
/// exception's message, and our error as details.
fn provider_failure(code: &str, message: impl Into<String>, cause: &dyn Display) -> Failure {
    Failure::Custom {
        code: code.to_owned(),
        message: Some(message.into()),
        details: Some(cause.to_string()),
    }
}

fn signing_failure(details: impl Display) -> Failure {
    Failure::Custom {
        code: SIGNING_FAILURE.to_owned(),
        message: Some(SIGNING_FAILURE_MESSAGE.to_owned()),
        details: Some(details.to_string()),
    }
}

/// org.json `getString`.
fn get_string<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    match obj.get(key) {
        None => Err(not_found(key)),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(wrong_type(key, "a string")),
    }
}

/// org.json `getJSONObject`.
fn get_object<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    match obj.get(key) {
        None => Err(not_found(key)),
        Some(Value::Object(o)) => Ok(o),
        Some(_) => Err(wrong_type(key, "a JSONObject")),
    }
}

/// org.json `getJSONArray`.
fn get_array<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], Failure> {
    match obj.get(key) {
        None => Err(not_found(key)),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(wrong_type(key, "a JSONArray")),
    }
}

/// org.json `optString`: `None` when absent or `null`, any other value as text.
fn opt_string(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

/// org.json `optBoolean`: a boolean, or the string `true`/`false` in any case.
fn opt_bool(obj: &Map<String, Value>, key: &str, default: bool) -> bool {
    match obj.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => true,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") => false,
        _ => default,
    }
}

fn not_found(key: &str) -> Failure {
    json_exception(format!("JSONObject[\"{key}\"] not found."))
}

fn wrong_type(key: &str, what: &str) -> Failure {
    json_exception(format!("JSONObject[\"{key}\"] is not {what}."))
}

/// An org.json error escaping the method: INVOCATION_ERROR with the exception as details.
fn json_exception(message: String) -> Failure {
    Failure::Invocation(Some(format!("org.json.JSONException: {message}")))
}

/// `(String) value` on a JSON value that is not a string.
fn class_cast(value: &Value) -> Failure {
    // JRE 8 (bundled with the original) words it without "class " or module details.
    Failure::Invocation(Some(format!(
        "java.lang.ClassCastException: {} cannot be cast to java.lang.String",
        java_class(value)
    )))
}

/// Java class of a value of org.json's `JSONArray.toList()` (org.json 20211205
/// `stringToNumber`): integers are the narrowest of Integer, Long, BigInteger; numbers in
/// decimal notation are BigDecimal, except negative zero (`-0`, `-0.0`, …), a Double.
fn java_class(value: &Value) -> &'static str {
    match value {
        Value::Null => "org.json.JSONObject$Null",
        Value::Bool(_) => "java.lang.Boolean",
        Value::Number(n) if n.as_i64().is_some_and(|n| i32::try_from(n).is_ok()) => {
            "java.lang.Integer"
        }
        Value::Number(n) if n.is_i64() => "java.lang.Long",
        Value::Number(n) if n.is_u64() => "java.math.BigInteger",
        // serde_json parses `-0` to the f64 −0.0 as well.
        Value::Number(n) if n.as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative()) => {
            "java.lang.Double"
        }
        Value::Number(_) => "java.math.BigDecimal",
        Value::String(_) => "java.lang.String",
        Value::Array(_) => "java.util.ArrayList",
        Value::Object(_) => "java.util.HashMap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cms_errors_map_to_codes() {
        let code = |e: CmsError| match cms_failure(e) {
            Failure::Custom { code, message, .. } => (code, message),
            other => panic!("{other:?}"),
        };
        let own = |c: &str| (c.to_owned(), Some(c.to_owned()));
        assert_eq!(
            code(CmsError::NoEncapsulatedData),
            own(CMS_NO_ENCAPSULATED_DATA)
        );
        assert_eq!(
            code(CmsError::UnknownAlgorithm("1.2.3".to_owned())),
            own(UNKNOWN_ALGORITHM)
        );
        // A sha1WithRSA signer certificate: refused, never upgraded to SHA-256.
        assert_eq!(
            code(CmsError::Key(KeyError::UnsupportedAlgorithm)),
            own(UNKNOWN_ALGORITHM)
        );
        assert_eq!(
            code(CmsError::Malformed("x".to_owned())),
            (
                SIGNING_FAILURE.to_owned(),
                Some(SIGNING_FAILURE_MESSAGE.to_owned())
            )
        );
        assert_eq!(
            code(CmsError::Key(KeyError::KeyMismatch)),
            (
                SIGNING_FAILURE.to_owned(),
                Some(SIGNING_FAILURE_MESSAGE.to_owned())
            )
        );
    }

    #[test]
    fn org_json_accessors() {
        let obj = json!({"s": "v", "n": 5, "null": null, "b": "TRUE", "o": {}, "a": []});
        let obj = obj.as_object().unwrap();
        assert_eq!(get_string(obj, "s"), Ok("v"));
        assert_eq!(
            get_string(obj, "n"),
            Err(Failure::Invocation(Some(
                "org.json.JSONException: JSONObject[\"n\"] is not a string.".to_owned()
            )))
        );
        assert_eq!(
            get_string(obj, "x"),
            Err(Failure::Invocation(Some(
                "org.json.JSONException: JSONObject[\"x\"] not found.".to_owned()
            )))
        );
        assert!(get_object(obj, "o").is_ok());
        assert!(get_object(obj, "a").is_err());
        assert!(get_array(obj, "a").is_ok());
        assert!(get_array(obj, "null").is_err());
        assert_eq!(opt_string(obj, "n").as_deref(), Some("5"));
        assert_eq!(opt_string(obj, "null"), None);
        assert!(opt_bool(obj, "b", false));
        assert!(!opt_bool(obj, "n", false));
        assert!(opt_bool(obj, "x", true));
    }

    #[test]
    fn java_classes() {
        let class = |v: Value| java_class(&v);
        assert_eq!(class(json!(5)), "java.lang.Integer");
        assert_eq!(class(json!(-2_147_483_648_i64)), "java.lang.Integer");
        assert_eq!(class(json!(2_147_483_648_i64)), "java.lang.Long");
        assert_eq!(class(json!(u64::MAX)), "java.math.BigInteger");
        assert_eq!(class(json!(1.5)), "java.math.BigDecimal");
        assert_eq!(class(json!(0.0)), "java.math.BigDecimal");
        assert_eq!(class(json!(-0.0)), "java.lang.Double");
        for text in ["-0", "-0.0", "-0e3", "1e2", "2.5"] {
            let v: Value = serde_json::from_str(text).unwrap();
            let expected = if text.starts_with("-0") {
                "java.lang.Double"
            } else {
                "java.math.BigDecimal"
            };
            assert_eq!(java_class(&v), expected, "{text}");
        }
        assert_eq!(class(json!(true)), "java.lang.Boolean");
        assert_eq!(class(json!([])), "java.util.ArrayList");
        assert_eq!(class(json!({})), "java.util.HashMap");
        assert_eq!(class(json!("s")), "java.lang.String");
        assert_eq!(class(Value::Null), "org.json.JSONObject$Null");
    }
}
