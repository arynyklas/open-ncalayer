//! `PKIEssentials`: `generateCsr` (new keys in PKCS#12 key files of a folder the user picks,
//! and their certificate requests) and `importCertificate` (the NCA's certificates installed
//! next to those keys, then the key files re-encrypted with the user's password). Both read
//! their arguments as the original does with org.json.
//!
//! Only PKCS#12 key files are written. Hardware tokens and JKS are shown but cannot be picked
//! (an answer naming them fails with UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION; a JKS import
//! first runs the certificate's own checks, so a certificate for PKCS#12 is
//! UNSUITED_STORAGE, as in the original), so `omittedKeyIds` and the ID card's key
//! bookkeeping never apply. Deviations from the original:
//! - `params` are read before the window: a bad entry or algorithm fails the request with
//!   the original's code without asking (the original asks first, then fails); more than
//!   [`MAX_KEYS_PER_REQUEST`] entries are an INVOCATION_ERROR (`IllegalArgumentException:
//!   too many keys requested`; the original has no limit);
//! - more than [`MAX_CERTIFICATES_PER_REQUEST`] `certificates` are an INVOCATION_ERROR
//!   (`IllegalArgumentException: too many certificates`, before the window; the original
//!   has no limit);
//! - a `keystorePath` a page may not name (a device path, or a network path the user did not
//!   choose in the file chooser) does not pre-fill the import window;
//! - without a `defaultPassword` the window asks for the key file password (the original
//!   cannot be confirmed then);
//! - the new password's pattern is checked before the first certificate is installed, so a
//!   wrong pattern changes no file (the original installs the certificate first);
//! - key files are only created in an existing folder given by an absolute path;
//! - the page's `defaultPassword` and the chosen folder are never logged.

use crate::args::{
    STORAGES, get_array, get_int, get_string, java_string, json_exception, locale, null_pointer,
    pem_or_base64, storage_list,
};
use crate::failures::{
    UNKNOWN_ALGORITHM, csr_failure, csr_generating_failure, csr_provider_failure, import_failure,
    import_unsupported_storage, invalid_importing_certificate,
};
use crate::{CallResult, Core};
use der::asn1::ObjectIdentifier;
use oncl_pdk::abi::{
    Bytes, CertInfo, CsrDialogArgs, Folder, ImportDialogArgs, InstallCertArgs, NewKeyArgs,
    Password, RequestForm,
};
use oncl_pdk::invoker::Failure;
use oncl_pdk::orgjson::opt_string;
use oncl_pdk::serde_json::{Map, Value, json};
use std::collections::HashSet;

/// Most keys one `generateCsr` makes (the core's limit too).
const MAX_KEYS_PER_REQUEST: usize = 16;
/// Most certificates one `importCertificate` installs (the core's limit too).
const MAX_CERTIFICATES_PER_REQUEST: usize = 16;
/// The original's message when `subjectAltNames` lacks the subject's CN.
const SAN_WITHOUT_CN: &str = "java.lang.IllegalArgumentException: Subject alternative names do not contain corresponding common name";
/// Over [`MAX_KEYS_PER_REQUEST`] `params` entries.
const TOO_MANY_KEYS: &str = "java.lang.IllegalArgumentException: too many keys requested";
/// Over [`MAX_CERTIFICATES_PER_REQUEST`] `certificates` entries.
const TOO_MANY_CERTIFICATES: &str = "java.lang.IllegalArgumentException: too many certificates";

/// commonName.
const COMMON_NAME: &str = "2.5.4.3";
/// KeyStoreInfo storages.
const STORAGE_PKCS12: &str = "1.2.398.3.3.5.1.1";
const STORAGE_JKS: &str = "1.2.398.3.3.5.1.2";
/// The signature algorithms keys are generated for.
const GOST_2015_512_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.398.3.10.1.1.2.3.2");
const GOST_2004_SIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.10.1.1.1.2");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// RSA lengths of sha256WithRSA keys.
const RSA_BITS: [u32; 3] = [2048, 3072, 4096];

/// `PKIEssentials.generateCsr`: `{"pems": [...]}`, one request (and key file) per `params`
/// entry; `{}` if the user cancels.
pub(crate) fn generate_csr<C: Core>(core: &C, args: &Map<String, Value>) -> CallResult {
    let request = CsrArgs::parse(args)?;
    core.set_locale(locale(args));
    let ask_password = request.default_password.is_empty();
    let choice = match core.dialog_csr(&CsrDialogArgs {
        storages: request.storages,
        ask_password,
    }) {
        Ok(Some(choice)) => choice,
        Ok(None) => return Ok(json!({})),
        Err(e) => return Err(csr_failure(&e)),
    };
    let password = match choice.password {
        Some(typed) => Password::Secret(typed.id),
        None => Password::Text(request.default_password),
    };
    let mut pems = Vec::with_capacity(request.specs.len());
    for spec in request.specs {
        let made = core
            .new_key(&NewKeyArgs {
                folder: Folder::Chosen(choice.folder),
                password: password.clone(),
                alg: spec.alg,
                bits: Some(spec.bits),
                form: RequestForm::Essentials {
                    dn: request.dn.clone(),
                    dns_names: request.alt_names.clone(),
                    email: Some(request.email.clone()),
                },
            })
            .map_err(|e| csr_failure(&e))?;
        pems.push(
            made.pem
                .expect("the core writes generateCsr's request as PEM"),
        );
    }
    core.log(&format!("generateCsr: {} key files created", pems.len()));
    Ok(json!({ "pems": pems }))
}

/// `PKIEssentials.importCertificate`: `{"result": true}` once every certificate is
/// installed and its key file has the user's password; `{}` if the user cancels.
pub(crate) fn import_certificate<C: Core>(core: &C, args: &Map<String, Value>) -> CallResult {
    let default_password = opt_string(args, "defaultPassword").unwrap_or_default();
    let storage = get_string(args, "allowedStorage")?;
    let keystore_path = opt_string(args, "keystorePath").unwrap_or_default();
    let certificates = get_array(args, "certificates")?;
    if !STORAGES.contains(&storage) {
        return Err(Failure::Invocation(Some(format!(
            "java.lang.NullPointerException: Unsupported storage: {storage}"
        ))));
    }
    if certificates.len() > MAX_CERTIFICATES_PER_REQUEST {
        return Err(Failure::Invocation(Some(TOO_MANY_CERTIFICATES.to_owned())));
    }
    // `X509Util.getX509Certificate(e.toString())`: anything that is not a certificate (null
    // included) is INVALID_IMPORTING_CERTIFICATE.
    let certificates: Vec<(Vec<u8>, CertInfo)> = certificates
        .iter()
        .map(|c| {
            c.as_str()
                .and_then(pem_or_base64)
                .and_then(|der| Some((der.clone(), core.cert_info(&der)?)))
                .ok_or_else(invalid_importing_certificate)
        })
        .collect::<Result<_, _>>()?;

    core.set_locale(locale(args));
    let Some(choice) = core.dialog_import(&ImportDialogArgs {
        storage: storage.to_owned(),
        // The core shows it only if a page may name it.
        path: Some(keystore_path),
        certificates: certificates
            .iter()
            .map(|(der, _)| Bytes::from(der.clone()))
            .collect(),
    }) else {
        return Ok(json!({}));
    };
    // Only PKCS#12 key files are written: JKS is refused by the core after the certificate's
    // own checks, as the original orders them; tokens cannot be picked yet.
    let storage_oid = match storage {
        "PKCS12" => Some(STORAGE_PKCS12),
        "JKS" => Some(STORAGE_JKS),
        _ => None,
    };
    core.log(&format!(
        "importCertificate: installing certificates into {storage}"
    ));
    for (der, info) in certificates {
        let serial = info.serial_hex.as_str();
        core.log(&format!(
            "importCertificate: installing the certificate {serial}"
        ));
        let storage_oid = storage_oid.ok_or_else(|| import_unsupported_storage(serial))?;
        core.install_cert(&InstallCertArgs {
            folder: Folder::Chosen(choice.folder),
            password: Password::Text(default_password.clone()),
            cert: Bytes::from(der),
            storage_oid: storage_oid.to_owned(),
            new_password: Some(Password::Secret(choice.new_password.id)),
        })
        .map_err(|e| import_failure(serial, &e))?;
        core.log(&format!(
            "importCertificate: certificate {serial} installed, password changed"
        ));
    }
    Ok(json!({ "result": true }))
}

/// The key of a `params` entry: the signature algorithm OID as the page wrote it, and the
/// key length as the core reads it.
#[derive(Debug, PartialEq, Eq)]
struct KeySpec {
    alg: String,
    bits: u32,
}

/// The arguments of `generateCsr`, read in the original's order.
struct CsrArgs {
    default_password: String,
    storages: Vec<String>,
    /// Subject attributes, `(OID, value)` in `dn` order.
    dn: Vec<(String, String)>,
    /// rfc822Name; blank for none.
    email: String,
    /// dNSNames, each once, in `subjectAltNames` order.
    alt_names: Vec<String>,
    /// One key per `params` entry.
    specs: Vec<KeySpec>,
}

impl CsrArgs {
    fn parse(args: &Map<String, Value>) -> Result<Self, Failure> {
        let default_password = opt_string(args, "defaultPassword").unwrap_or_default();
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
                if ObjectIdentifier::new(oid).is_err() {
                    return Err(Failure::Invocation(Some(format!(
                        "java.lang.IllegalArgumentException: string {oid} not an OID"
                    ))));
                }
                Ok((oid.clone(), java_string(value)?))
            })
            .collect::<Result<_, Failure>>()?;
        let email = opt_string(args, "email").unwrap_or_default();
        let mut alt_names: Vec<String> = Vec::new();
        if let Some(Value::Array(names)) = args.get("subjectAltNames")
            && !names.is_empty()
        {
            let names: Vec<String> = names.iter().map(java_string).collect::<Result<_, _>>()?;
            // Each name once, in first-seen order; linear, as a page sends any number.
            let mut seen = HashSet::with_capacity(names.len());
            let first: Vec<bool> = names.iter().map(|n| seen.insert(n.as_str())).collect();
            drop(seen);
            alt_names = names
                .into_iter()
                .zip(first)
                .filter_map(|(name, first)| first.then_some(name))
                .collect();
            let common_name = get_string(dn_object, COMMON_NAME)?;
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
/// entries are the original's CSR_GENERATING_FAILURE; algorithms the core does not generate
/// (and sha1WithRSA, which it refuses) UNKNOWN_ALGORITHM.
fn key_spec(i: usize, param: &Value) -> Result<KeySpec, Failure> {
    let Value::Object(param) = param else {
        return Err(param_failure(json_exception(format!(
            "JSONArray[{i}] is not a JSONObject."
        ))));
    };
    let algorithm = get_string(param, "algorithm").map_err(param_failure)?;
    let length = get_int(param, "length").map_err(param_failure)?;
    // A negative length is no RSA length; GOST ignores it.
    let bits = u32::try_from(length).unwrap_or(0);
    let generated = match ObjectIdentifier::new(algorithm) {
        Ok(oid) if oid == GOST_2015_512_SIGNATURE || oid == GOST_2004_SIGNATURE => true,
        Ok(oid) if oid == SHA256_WITH_RSA => RSA_BITS.contains(&bits),
        _ => false,
    };
    if !generated {
        return Err(csr_provider_failure(UNKNOWN_ALGORITHM));
    }
    Ok(KeySpec {
        alg: algorithm.to_owned(),
        bits,
    })
}

/// An org.json error the original meets after its window, inside its generic catch:
/// CSR_GENERATING_FAILURE with the exception as details.
fn param_failure(f: Failure) -> Failure {
    let details = match f {
        Failure::General(d) | Failure::Invocation(d) => d,
        Failure::Custom { details, .. } => details,
    };
    csr_generating_failure(details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pdk::serde_json::json;

    #[test]
    fn key_specs() {
        let spec = |v: Value| key_spec(0, &v);
        let code = |r: Result<KeySpec, Failure>| match r {
            Err(Failure::Custom { code, .. }) => code,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            spec(json!({"algorithm": "1.2.398.3.10.1.1.2.3.2", "length": 512})),
            Ok(KeySpec {
                alg: "1.2.398.3.10.1.1.2.3.2".to_owned(),
                bits: 512
            })
        );
        assert_eq!(
            spec(json!({"algorithm": "1.2.840.113549.1.1.11", "length": "2048"})),
            Ok(KeySpec {
                alg: "1.2.840.113549.1.1.11".to_owned(),
                bits: 2048
            })
        );
        for unknown in [
            json!({"algorithm": "1.2.840.113549.1.1.5", "length": 2048}),
            json!({"algorithm": "1.2.840.113549.1.1.11", "length": 1024}),
            json!({"algorithm": "1.2.840.113549.1.1.11", "length": -2048}),
            json!({"algorithm": "1.2.3", "length": 256}),
            json!({"algorithm": "not an oid", "length": 256}),
        ] {
            assert_eq!(code(spec(unknown)), UNKNOWN_ALGORITHM);
        }
        for bad in [
            json!("x"),
            json!({"length": 512}),
            json!({"algorithm": "1.2.398.3.10.1.1.2.3.2"}),
        ] {
            assert_eq!(code(spec(bad)), "CSR_GENERATING_FAILURE");
        }
    }
}
