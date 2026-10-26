//! `PKIEssentials`: `generateCsr` (new keys in PKCS#12 key files of a folder the user picks,
//! and their certificate requests) and `importCertificate` (the NCA's certificates installed
//! next to those keys, then the key files re-encrypted with the user's password). Both read
//! their arguments as the original does with org.json and run under the module's dialog-flow
//! lock.
//!
//! Only PKCS#12 key files are written. Hardware tokens and JKS are shown but cannot be picked
//! (an answer naming them fails with UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION; a JKS import
//! first runs the certificate's own checks, so a certificate for PKCS#12 is
//! UNSUITED_STORAGE, as in the original), so `omittedKeyIds` and the ID card's key
//! bookkeeping never apply. Deviations from the original:
//! - `params` are read before the dialog: a bad entry or algorithm fails the request with the
//!   original's code without asking (the original asks first, then fails); more than
//!   [`MAX_KEYS_PER_REQUEST`] entries are an INVOCATION_ERROR (`IllegalArgumentException:
//!   too many keys requested`; the original has no limit);
//! - a `keystorePath` a page may not name (a network or device path) does not pre-fill the
//!   import dialog;
//! - without a `defaultPassword` the dialog asks for the key file password (the original
//!   cannot be confirmed then);
//! - the new password's pattern is checked before the first certificate is installed, so a
//!   wrong pattern changes no file (the original installs the certificate first);
//! - key files are only created in an existing folder given by an absolute path;
//! - the page's `defaultPassword` and the chosen folder are never logged.

use crate::page_file::local_page_path;
use crate::prompt::{CsrPrompt, ImportPrompt, Locale, Prompt, StorageKind};
use crate::sign::{
    UNIDENTIFIED, get_array, get_string, json_exception, not_found, parse_pem_or_base64,
    provider_failure, storage_list, wrong_type,
};
use crate::{Basics, lock_dialog_flow};
use der::asn1::ObjectIdentifier;
use oncl_pki::cert::Certificate;
use oncl_pki::csr::{CsrRequest, KeyStoreInfo, build_csr};
use oncl_pki::info::cert_info;
use oncl_pki::keygen::{KeySpec, MAX_KEYS_PER_REQUEST, generate};
use oncl_pki::keystore::{
    KeystoreError, change_password, check_password_pattern, create_key_file, install_certificate,
};
use oncl_pki::oid;
use oncl_protocol::AddInfo;
use oncl_protocol::invoker::{CallResult, Failure};
use oncl_protocol::orgjson::{int_value, opt_string};
use serde_json::{Map, Value, json};
use std::path::Path;
use zeroize::Zeroizing;

const CSR_GENERATING_FAILURE: &str = "CSR_GENERATING_FAILURE";
const CSR_GENERATING_FAILURE_MESSAGE: &str = "CSR generation has failed.";
const CERTIFICATE_IMPORTING_FAILURE: &str = "CERTIFICATE_IMPORTING_FAILURE";
const CERTIFICATE_IMPORTING_FAILURE_MESSAGE: &str = "Certificate importing failure.";
const INVALID_IMPORTING_CERTIFICATE: &str = "INVALID_IMPORTING_CERTIFICATE";
const INVALID_IMPORTING_CERTIFICATE_MESSAGE: &str = "Importing certificate is invalid.";
/// The original's message when `subjectAltNames` lacks the subject's CN.
const SAN_WITHOUT_CN: &str = "java.lang.IllegalArgumentException: Subject alternative names do not contain corresponding common name";
/// Over [`MAX_KEYS_PER_REQUEST`] `params` entries.
const TOO_MANY_KEYS: &str = "java.lang.IllegalArgumentException: too many keys requested";

/// `PKIEssentials.generateCsr`: `{"pems": [...]}`, one request (and key file) per `params`
/// entry; `{}` if the user cancels.
pub(crate) fn generate_csr(
    basics: &Basics,
    args: &Map<String, Value>,
    add_info: &AddInfo,
) -> CallResult {
    let request = CsrArgs::parse(args)?;
    let _flow = lock_dialog_flow();
    let prompt = CsrPrompt {
        origin: origin(add_info),
        locale: locale(args),
        storages: request.storages,
        ask_password: request.default_password.is_empty(),
    };
    let answer = match basics.prompter.csr(&prompt) {
        Prompt::Answer(answer) => answer,
        Prompt::Cancelled => return Ok(json!({})),
    };
    if answer.storage != StorageKind::Pkcs12 || !prompt.storages.contains(&answer.storage) {
        return Err(csr_failure(KeystoreError::UnsupportedStorage));
    }
    // Key files go into a folder the user picked, never next to the daemon's working
    // directory.
    if !answer.dir.is_absolute() || !answer.dir.is_dir() {
        return Err(csr_failure(KeystoreError::Io(format!(
            "{}: not a folder",
            answer.dir.display()
        ))));
    }
    let password = if prompt.ask_password {
        answer.password
    } else {
        request.default_password
    };
    let keystore_info = KeyStoreInfo {
        storage_oid: oid::STORAGE_PKCS12,
        path: Some(answer.dir.display().to_string()),
    };

    let mut pems = Vec::with_capacity(request.specs.len());
    for &spec in &request.specs {
        let key = generate(spec).map_err(csr_failure)?;
        // The request first: a subject that does not encode leaves no key file behind.
        let pem = build_csr(
            &key,
            spec,
            &CsrRequest {
                dn: &request.dn,
                dns_names: &request.alt_names,
                email: Some(&request.email),
                keystore_info: keystore_info.clone(),
            },
        )
        .map_err(csr_failure)?;
        create_key_file(&answer.dir, &key, spec, &password).map_err(csr_failure)?;
        pems.push(pem);
    }
    tracing::info!(requests = pems.len(), "generateCsr: key files created");
    Ok(json!({ "pems": pems }))
}

/// `PKIEssentials.importCertificate`: `{"result": true}` once every certificate is
/// installed and its key file has the user's password; `{}` if the user cancels.
pub(crate) fn import_certificate(
    basics: &Basics,
    args: &Map<String, Value>,
    add_info: &AddInfo,
) -> CallResult {
    let default_password = Zeroizing::new(opt_string(args, "defaultPassword").unwrap_or_default());
    let storage_name = get_string(args, "allowedStorage")?;
    let keystore_path = opt_string(args, "keystorePath").unwrap_or_default();
    let certificates = get_array(args, "certificates")?;
    let storage = StorageKind::from_name(storage_name).ok_or_else(|| {
        Failure::Invocation(Some(format!(
            "java.lang.NullPointerException: Unsupported storage: {storage_name}"
        )))
    })?;
    // `X509Util.getX509Certificate(e.toString())`: anything that is not a certificate (null
    // included) is INVALID_IMPORTING_CERTIFICATE.
    let certificates: Vec<Certificate> = certificates
        .iter()
        .map(|c| {
            c.as_str()
                .and_then(parse_pem_or_base64)
                .ok_or_else(invalid_importing_certificate)
        })
        .collect::<Result<_, _>>()?;

    let _flow = lock_dialog_flow();
    let prompt = ImportPrompt {
        origin: origin(add_info),
        locale: locale(args),
        storage,
        // Like every path a page names: a network or device path is not shown, so the
        // dialog never browses or opens a host the page chose.
        path: local_page_path(&keystore_path)
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf),
        certificates: certificates.iter().map(cert_info).collect(),
    };
    let answer = match basics.prompter.import_cert(&prompt) {
        Prompt::Answer(answer) => answer,
        Prompt::Cancelled => return Ok(json!({})),
    };
    tracing::info!(
        storage = storage.name(),
        "importCertificate: installing certificates"
    );
    // Only PKCS#12 key files are written: JKS is refused by `install_certificate` after the
    // certificate's own checks, as the original orders them; tokens cannot be picked yet.
    let storage_oid = match storage {
        StorageKind::Pkcs12 => Some(oid::STORAGE_PKCS12),
        StorageKind::Jks => Some(oid::STORAGE_JKS),
        StorageKind::Token(_) => None,
    };
    for (cert, info) in certificates.iter().zip(&prompt.certificates) {
        let serial = info.serial_hex.as_str();
        let fail = |e: KeystoreError| import_failure(serial, e);
        tracing::info!(serial, "importCertificate: installing a certificate");
        let storage_oid = storage_oid.ok_or_else(|| fail(KeystoreError::UnsupportedStorage))?;
        check_password_pattern(&answer.new_password).map_err(fail)?;
        let path = install_certificate(&answer.dir, &default_password, cert, &storage_oid)
            .map_err(fail)?;
        change_password(&path, &default_password, &answer.new_password).map_err(fail)?;
        tracing::info!(
            serial,
            "importCertificate: certificate installed, password changed"
        );
    }
    Ok(json!({ "result": true }))
}

/// The arguments of `generateCsr`, read in the original's order.
struct CsrArgs {
    default_password: Zeroizing<String>,
    storages: Vec<StorageKind>,
    /// Subject attributes, in `dn` order.
    dn: Vec<(ObjectIdentifier, String)>,
    /// rfc822Name; blank for none.
    email: String,
    /// dNSNames, each once, in `subjectAltNames` order.
    alt_names: Vec<String>,
    /// One key per `params` entry.
    specs: Vec<KeySpec>,
}

impl CsrArgs {
    fn parse(args: &Map<String, Value>) -> Result<Self, Failure> {
        let default_password =
            Zeroizing::new(opt_string(args, "defaultPassword").unwrap_or_default());
        // `optJSONArray(…).toList()`: no array is a NullPointerException.
        let storages = match args.get("allowedStorages") {
            Some(Value::Array(names)) => storage_list(names)?,
            _ => return Err(null_pointer()),
        };
        let Some(Value::Object(dn_object)) = args.get("dn") else {
            return Err(null_pointer());
        };
        let dn = dn_object
            .iter()
            .map(|(oid, value)| {
                let oid = ObjectIdentifier::new(oid).map_err(|_| {
                    Failure::Invocation(Some(format!(
                        "java.lang.IllegalArgumentException: string {oid} not an OID"
                    )))
                })?;
                Ok((oid, java_string(value)?))
            })
            .collect::<Result<_, Failure>>()?;
        let email = opt_string(args, "email").unwrap_or_default();
        let mut alt_names: Vec<String> = Vec::new();
        if let Some(Value::Array(names)) = args.get("subjectAltNames")
            && !names.is_empty()
        {
            for name in names {
                let name = java_string(name)?;
                if !alt_names.contains(&name) {
                    alt_names.push(name);
                }
            }
            let common_name = get_string(dn_object, &oid::COMMON_NAME.to_string())?;
            if !alt_names.iter().any(|n| n == common_name) {
                return Err(Failure::Invocation(Some(SAN_WITHOUT_CN.to_owned())));
            }
        }
        let params = get_array(args, "params")?;
        if params.len() > MAX_KEYS_PER_REQUEST {
            return Err(Failure::Invocation(Some(TOO_MANY_KEYS.to_owned())));
        }
        // Token bookkeeping only; the original reads the entries with `getString`.
        if let Some(Value::Array(ids)) = args.get("omittedKeyIds")
            && let Some(i) = ids.iter().position(|id| !id.is_string())
        {
            return Err(json_exception(format!("JSONArray[{i}] is not a String.")));
        }
        let specs = params
            .iter()
            .enumerate()
            .map(|(i, param)| key_spec(i, param))
            .collect::<Result<_, _>>()?;
        Ok(CsrArgs {
            default_password,
            storages,
            dn,
            email,
            alt_names,
            specs,
        })
    }
}

/// The key of `params[i]`: `algorithm` (a signature algorithm OID) and `length`. Bad
/// entries are the original's CSR_GENERATING_FAILURE; algorithms it does not generate (and
/// sha1WithRSA, which we refuse) UNKNOWN_ALGORITHM.
fn key_spec(i: usize, param: &Value) -> Result<KeySpec, Failure> {
    let Value::Object(param) = param else {
        return Err(param_failure(json_exception(format!(
            "JSONArray[{i}] is not a JSONObject."
        ))));
    };
    let algorithm = get_string(param, "algorithm").map_err(param_failure)?;
    let length = get_int(param, "length").map_err(param_failure)?;
    // A negative length is no RSA length; GOST ignores it.
    match KeySpec::from_oid_len(algorithm, u32::try_from(length).unwrap_or(0)) {
        Ok(KeySpec::Rsa1Sha1(_)) => Err(csr_failure(KeystoreError::UnknownAlgorithm)),
        Ok(spec) => Ok(spec),
        Err(e) => Err(csr_failure(e)),
    }
}

/// org.json `getInt` ([`int_value`]).
fn get_int(obj: &Map<String, Value>, key: &str) -> Result<i32, Failure> {
    let value = obj.get(key).ok_or_else(|| not_found(key))?;
    int_value(value).ok_or_else(|| wrong_type(key, "a int"))
}

/// `value.toString()` of an org.json `toMap()`/`toList()` value; null is a
/// NullPointerException.
fn java_string(value: &Value) -> Result<String, Failure> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Null => Err(null_pointer()),
        other => Ok(other.to_string()),
    }
}

/// The requesting page's origin, or `"UNIDENTIFIED"`.
fn origin(add_info: &AddInfo) -> String {
    add_info
        .origin
        .clone()
        .unwrap_or_else(|| UNIDENTIFIED.to_owned())
}

/// `optString("locale", "kk")`.
fn locale(args: &Map<String, Value>) -> Locale {
    Locale::from_arg(opt_string(args, "locale").as_deref())
}

fn null_pointer() -> Failure {
    Failure::Invocation(Some("java.lang.NullPointerException".to_owned()))
}

/// A `generateCsr` error: the provider's code and message, or CSR_GENERATING_FAILURE.
fn csr_failure(e: KeystoreError) -> Failure {
    match e.provider_code() {
        Some(code) => provider_failure(code, e.to_string(), &e),
        None => Failure::Custom {
            code: CSR_GENERATING_FAILURE.to_owned(),
            message: Some(CSR_GENERATING_FAILURE_MESSAGE.to_owned()),
            details: Some(e.to_string()),
        },
    }
}

/// An org.json error the original meets after its dialog, inside its generic catch:
/// CSR_GENERATING_FAILURE with the exception as details.
fn param_failure(f: Failure) -> Failure {
    let details = match f {
        Failure::General(d) | Failure::Invocation(d) => d,
        Failure::Custom { details, .. } => details,
    };
    Failure::Custom {
        code: CSR_GENERATING_FAILURE.to_owned(),
        message: Some(CSR_GENERATING_FAILURE_MESSAGE.to_owned()),
        details,
    }
}

/// An `importCertificate` error for the certificate with serial `serial` (hex): the
/// provider's code and its message after `[<serial>] `, or CERTIFICATE_IMPORTING_FAILURE.
fn import_failure(serial: &str, e: KeystoreError) -> Failure {
    match e.provider_code() {
        Some(code) => provider_failure(code, format!("[{serial}] {e}"), &e),
        None => Failure::Custom {
            code: CERTIFICATE_IMPORTING_FAILURE.to_owned(),
            message: Some(CERTIFICATE_IMPORTING_FAILURE_MESSAGE.to_owned()),
            details: Some(e.to_string()),
        },
    }
}

fn invalid_importing_certificate() -> Failure {
    Failure::Custom {
        code: INVALID_IMPORTING_CERTIFICATE.to_owned(),
        message: Some(INVALID_IMPORTING_CERTIFICATE_MESSAGE.to_owned()),
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_int_reads_as_org_json() {
        let obj = json!({"n": 2048, "f": 2048.9, "s": "3072", "x": "abc", "b": true, "big": 4294969344_u64});
        let obj = obj.as_object().unwrap();
        assert_eq!(get_int(obj, "n"), Ok(2048));
        assert_eq!(get_int(obj, "f"), Ok(2048));
        assert_eq!(get_int(obj, "s"), Ok(3072));
        assert_eq!(get_int(obj, "big"), Ok(2048));
        let not_int = Err(Failure::Invocation(Some(
            "org.json.JSONException: JSONObject[\"x\"] is not a int.".to_owned(),
        )));
        assert_eq!(get_int(obj, "x"), not_int);
        assert!(get_int(obj, "b").is_err());
        assert_eq!(
            get_int(obj, "missing"),
            Err(Failure::Invocation(Some(
                "org.json.JSONException: JSONObject[\"missing\"] not found.".to_owned()
            )))
        );
    }

    #[test]
    fn key_specs() {
        let spec = |v: Value| key_spec(0, &v);
        let code = |r: Result<KeySpec, Failure>| match r {
            Err(Failure::Custom { code, .. }) => code,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            spec(json!({"algorithm": "1.2.398.3.10.1.1.2.3.2", "length": 512})),
            Ok(KeySpec::Gost2015_512)
        );
        assert_eq!(
            spec(json!({"algorithm": "1.2.840.113549.1.1.11", "length": "2048"})),
            Ok(KeySpec::RsaSha256(2048))
        );
        for unknown in [
            json!({"algorithm": "1.2.840.113549.1.1.5", "length": 2048}),
            json!({"algorithm": "1.2.840.113549.1.1.11", "length": 1024}),
            json!({"algorithm": "1.2.840.113549.1.1.11", "length": -2048}),
            json!({"algorithm": "1.2.3", "length": 256}),
        ] {
            assert_eq!(code(spec(unknown)), "UNKNOWN_ALGORITHM");
        }
        for bad in [
            json!("x"),
            json!({"length": 512}),
            json!({"algorithm": "1.2.398.3.10.1.1.2.3.2"}),
        ] {
            assert_eq!(code(spec(bad)), CSR_GENERATING_FAILURE);
        }
    }
}
