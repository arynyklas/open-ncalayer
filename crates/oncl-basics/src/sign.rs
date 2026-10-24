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
use der::asn1::AnyRef;
use der::{Decode, Encode, Reader, SliceReader};
use oncl_pki::cert::Certificate;
use oncl_pki::cms::{self, CmsError, SignOptions};
use oncl_pki::info::cert_info;
use oncl_pki::key::{KeyAlg, KeyError, SigAlg};
use oncl_pki::pkcs12::{self, KeyEntry, Pkcs12Error};
use oncl_pki::tsp;
use oncl_protocol::AddInfo;
use oncl_protocol::invoker::{CallResult, Failure};
use serde_json::{Map, Value, json};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

const SIGNING_FAILURE: &str = "SIGNING_FAILURE";
const SIGNING_FAILURE_MESSAGE: &str = "Signing has failed.";
const INVALID_SIGNING_PARAMS: &str = "INVALID_SIGNING_PARAMS";
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

/// Line separator of the PEM writer (Java's `line.separator`), as in `cms::to_pem`.
const NL: &str = if cfg!(windows) { "\r\n" } else { "\n" };

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
        let storages = match args.get("allowedStorages") {
            Some(Value::Array(names)) => {
                let mut storages = Vec::new();
                for kind in names
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(StorageKind::from_name)
                {
                    if !storages.contains(&kind) {
                        storages.push(kind);
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
                    message: None,
                    details: None,
                });
            }
        };

        let data: Vec<&str> = match args.get("data") {
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    item.as_str().ok_or_else(|| {
                        Failure::Invocation(Some(format!("JSONArray[{i}] is not a string.")))
                    })
                })
                .collect::<Result<_, _>>()?,
            _ => vec![get_string(args, "data")?],
        };

        let signer_params = get_object(args, "signerParams")?;
        let ext_key_usages = get_array(signer_params, "extKeyUsageOids")?
            .iter()
            .map(|oid| match oid {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect::<BTreeSet<_>>();
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
        let last = signer_count(&der)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| signing_failure("signed CMS has no readable signers"))?;
        der =
            tsp::timestamp_signer(&der, last, &basics.tsa, basics.http.as_ref()).map_err(|e| {
                Failure::Custom {
                    code: TIMESTAMP_CREATION_FAILURE.to_owned(),
                    message: None,
                    details: Some(e.to_string()),
                }
            })?;
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
        json!({ "signatures": signatures, "certificate": certificate_pem(&entry.cert)? })
    } else if signatures.len() == 1 {
        Value::String(signatures.swap_remove(0))
    } else {
        Value::from(signatures)
    })
}

/// Number of `signerInfos` of a DER `ContentInfo{SignedData}`: the last element of the
/// `SignedData` SEQUENCE.
fn signer_count(cms: &[u8]) -> der::Result<usize> {
    let content_info = AnyRef::from_der(cms)?;
    let mut fields = SliceReader::new(content_info.value())?;
    let _content_type: AnyRef<'_> = fields.decode()?;
    let explicit: AnyRef<'_> = fields.decode()?;
    let signed_data = AnyRef::from_der(explicit.value())?;
    let signer_infos = elements(signed_data)?
        .pop()
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    Ok(elements(signer_infos)?.len())
}

/// Elements of a constructed value.
fn elements(any: AnyRef<'_>) -> der::Result<Vec<AnyRef<'_>>> {
    let mut reader = SliceReader::new(any.value())?;
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(reader.decode()?);
    }
    Ok(out)
}

/// The certificate as Kalkan's `PEMWriter` writes it.
fn certificate_pem(cert: &Certificate) -> Result<String, Failure> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let der = cert.to_der().map_err(signing_failure)?;
    let body = STANDARD.encode(der);
    let mut pem = String::with_capacity(BEGIN.len() + END.len() + body.len() * 33 / 32 + 8);
    pem.push_str(BEGIN);
    pem.push_str(NL);
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push_str(NL);
    }
    pem.push_str(END);
    pem.push_str(NL);
    Ok(pem)
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
        CmsError::NoEncapsulatedData => custom(CMS_NO_ENCAPSULATED_DATA, &e),
        CmsError::UnknownAlgorithm(_) | CmsError::Key(KeyError::UnsupportedAlgorithm) => {
            custom(UNKNOWN_ALGORITHM, &e)
        }
        e => signing_failure(e),
    }
}

fn key_failure(e: KeyError) -> Failure {
    match e {
        KeyError::UnsupportedAlgorithm => custom(UNKNOWN_ALGORITHM, &e),
        e => signing_failure(e),
    }
}

/// A failure whose original message is unknown: the message is omitted.
fn custom(code: &str, details: &dyn std::fmt::Display) -> Failure {
    Failure::Custom {
        code: code.to_owned(),
        message: None,
        details: Some(details.to_string()),
    }
}

fn signing_failure(details: impl std::fmt::Display) -> Failure {
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
    Failure::Invocation(Some(format!("JSONObject[\"{key}\"] not found.")))
}

fn wrong_type(key: &str, what: &str) -> Failure {
    Failure::Invocation(Some(format!("JSONObject[\"{key}\"] is not {what}.")))
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
        assert_eq!(
            code(CmsError::NoEncapsulatedData),
            (CMS_NO_ENCAPSULATED_DATA.to_owned(), None)
        );
        assert_eq!(
            code(CmsError::UnknownAlgorithm("1.2.3".to_owned())),
            (UNKNOWN_ALGORITHM.to_owned(), None)
        );
        // A sha1WithRSA signer certificate: refused, never upgraded to SHA-256.
        assert_eq!(
            code(CmsError::Key(KeyError::UnsupportedAlgorithm)),
            (UNKNOWN_ALGORITHM.to_owned(), None)
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
                "JSONObject[\"n\"] is not a string.".to_owned()
            )))
        );
        assert_eq!(
            get_string(obj, "x"),
            Err(Failure::Invocation(Some(
                "JSONObject[\"x\"] not found.".to_owned()
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
}
