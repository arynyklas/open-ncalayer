//! The original's failures of `sign`, `generateCsr` and `importCertificate`: the core's
//! failures by their cause, with the core's text.

use oncl_pdk::abi::{HostError, cause};
use oncl_pdk::invoker::Failure;
use std::fmt::Display;

const SIGNING_FAILURE: &str = "SIGNING_FAILURE";
const SIGNING_FAILURE_MESSAGE: &str = "Signing has failed.";
const INVALID_SIGNING_PARAMS: &str = "INVALID_SIGNING_PARAMS";
const INVALID_SIGNING_PARAMS_MESSAGE: &str = "Invalid signing parameters provided.";
const CERTIFICATE_PARSING_FAILURE: &str = "CERTIFICATE_PARSING_FAILURE";
const CERTIFICATE_PARSING_FAILURE_MESSAGE: &str = "Certificate parsing failure.";
const CMS_NO_ENCAPSULATED_DATA: &str = "CMS_NO_ENCAPSULATED_DATA";
pub(crate) const UNKNOWN_ALGORITHM: &str = "UNKNOWN_ALGORITHM";
const UNABLE_TO_PARSE_XML: &str = "UNABLE_TO_PARSE_XML";
const TIMESTAMP_CREATION_FAILURE: &str = "TIMESTAMP_CREATION_FAILURE";
const CSR_GENERATING_FAILURE: &str = "CSR_GENERATING_FAILURE";
const CSR_GENERATING_FAILURE_MESSAGE: &str = "CSR generation has failed.";
const CERTIFICATE_IMPORTING_FAILURE: &str = "CERTIFICATE_IMPORTING_FAILURE";
const CERTIFICATE_IMPORTING_FAILURE_MESSAGE: &str = "Certificate importing failure.";
const INVALID_IMPORTING_CERTIFICATE: &str = "INVALID_IMPORTING_CERTIFICATE";
const INVALID_IMPORTING_CERTIFICATE_MESSAGE: &str = "Importing certificate is invalid.";
/// The provider's code (and message) of a storage the core does not write.
pub(crate) const UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION: &str =
    "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION";

/// sha1WithRSAEncryption: the original signs XML with it, the core refuses.
const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";

/// The original's `ProviderUtilFailure`: the `ProviderUtilExceptionCode` name, the provider
/// exception's message, and the core's error as details.
fn provider_failure(code: &str, message: impl Into<String>, cause: &dyn Display) -> Failure {
    Failure::Custom {
        code: code.to_owned(),
        message: Some(message.into()),
        details: Some(cause.to_string()),
    }
}

pub(crate) fn signing_failure(details: impl Display) -> Failure {
    Failure::Custom {
        code: SIGNING_FAILURE.to_owned(),
        message: Some(SIGNING_FAILURE_MESSAGE.to_owned()),
        details: Some(details.to_string()),
    }
}

/// The original's `BasicsFailure.INVALID_SIGNING_PARAMS`.
pub(crate) fn invalid_signing_params() -> Failure {
    Failure::Custom {
        code: INVALID_SIGNING_PARAMS.to_owned(),
        message: Some(INVALID_SIGNING_PARAMS_MESSAGE.to_owned()),
        details: None,
    }
}

/// The original's `BasicsFailure.CERTIFICATE_PARSING_FAILURE`.
pub(crate) fn certificate_parsing_failure() -> Failure {
    Failure::Custom {
        code: CERTIFICATE_PARSING_FAILURE.to_owned(),
        message: Some(CERTIFICATE_PARSING_FAILURE_MESSAGE.to_owned()),
        details: None,
    }
}

/// A CMS that did not sign.
pub(crate) fn cms_failure(e: &HostError) -> Failure {
    match e.cause() {
        Some(cause::CMS_NO_ENCAPSULATED_DATA) => provider_failure(
            CMS_NO_ENCAPSULATED_DATA,
            CMS_NO_ENCAPSULATED_DATA,
            &e.message,
        ),
        Some(cause::CMS_UNKNOWN_ALGORITHM | cause::KEY_UNSUPPORTED) => {
            provider_failure(UNKNOWN_ALGORITHM, UNKNOWN_ALGORITHM, &e.message)
        }
        _ => signing_failure(&e.message),
    }
}

/// A time-stamp that failed: the core's text.
pub(crate) fn tsp_failure(detail: &str) -> Failure {
    provider_failure(TIMESTAMP_CREATION_FAILURE, detail, &detail)
}

/// A raw signature that failed.
pub(crate) fn key_failure(e: &HostError) -> Failure {
    match e.cause() {
        Some(cause::KEY_UNSUPPORTED) => {
            provider_failure(UNKNOWN_ALGORITHM, UNKNOWN_ALGORITHM, &e.message)
        }
        _ => signing_failure(&e.message),
    }
}

/// `XMLUtil.createXmlSignature`'s failures as `PKIExtras.sign` reports them, for a key whose
/// certificate is signed with `cert_alg` (an OID):
///
/// - the document does not parse (DOCTYPE and the core's size, depth and work limits
///   included): the provider's `UNABLE_TO_PARSE_XML`, the parser error as the message;
/// - a certificate signature algorithm other than GOST 2015-512, GOST 2004 or sha256RSA:
///   the original's `IllegalArgumentException`, a SIGNING_FAILURE; except sha1RSA, which
///   the original signs with rsa-sha1 and the core refuses as for cms (`UNKNOWN_ALGORITHM`);
/// - anything else: SIGNING_FAILURE.
pub(crate) fn xml_failure(e: &HostError, cert_alg: &str) -> Failure {
    match e.cause() {
        Some(
            cause::XML_PARSE | cause::XML_DOCTYPE | cause::XML_TOO_LARGE | cause::XML_TOO_DEEP,
        ) => provider_failure(UNABLE_TO_PARSE_XML, e.message.clone(), &e.message),
        Some(cause::XML_UNSUPPORTED_ALGORITHM) if cert_alg == SHA1_WITH_RSA => {
            provider_failure(UNKNOWN_ALGORITHM, UNKNOWN_ALGORITHM, &e.message)
        }
        Some(cause::XML_UNSUPPORTED_ALGORITHM) => signing_failure(format!(
            "java.lang.IllegalArgumentException: Incorrect algorithm: {cert_alg}"
        )),
        Some(cause::KEY_UNSUPPORTED) => {
            provider_failure(UNKNOWN_ALGORITHM, UNKNOWN_ALGORITHM, &e.message)
        }
        _ => signing_failure(&e.message),
    }
}

/// The original's `ProviderUtilExceptionCode` of a key file failure, where the original
/// raises one.
fn provider_code(e: &HostError) -> Option<&'static str> {
    let cause = e.cause()?;
    // A failure of `keystore_new_key`'s steps is its variant's.
    let variant = cause::NEW_KEY_STEPS
        .iter()
        .find_map(|step| {
            cause
                .strip_prefix(step)
                .and_then(|rest| rest.strip_prefix('.'))
        })
        .map_or(cause, |variant| variant);
    let variant = variant.strip_prefix("keystore.").unwrap_or(variant);
    Some(match variant {
        "unknown_algorithm" => UNKNOWN_ALGORITHM,
        "keystore_file_not_found" => "KEYSTORE_FILE_NOT_FOUND",
        "unsuited_storage" => "UNSUITED_STORAGE",
        "inappropriate_cert" => "INAPPROPRIATE_CERT",
        "wrong_password" => "WRONG_KEYSTORE_PASSWORD",
        "wrong_password_pattern" => "WRONG_PASSWORD_PATTERN",
        "change_password_constraint" => "CHANGE_PASSWORD_CONSTRAINT",
        "extension_not_found" => "EXTENSION_NOT_FOUND",
        "unsupported_storage" => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
        _ => return None,
    })
}

/// A `generateCsr` failure of the core: the provider's code and message, or
/// CSR_GENERATING_FAILURE.
pub(crate) fn csr_failure(e: &HostError) -> Failure {
    match provider_code(e) {
        Some(code) => provider_failure(code, e.message.clone(), &e.message),
        None => csr_generating_failure(Some(e.message.clone())),
    }
}

/// The original's provider failure `code` of `generateCsr` with the provider's text, which
/// is the code.
pub(crate) fn csr_provider_failure(code: &str) -> Failure {
    provider_failure(code, code, &code)
}

/// CSR_GENERATING_FAILURE with `details`.
pub(crate) fn csr_generating_failure(details: Option<String>) -> Failure {
    Failure::Custom {
        code: CSR_GENERATING_FAILURE.to_owned(),
        message: Some(CSR_GENERATING_FAILURE_MESSAGE.to_owned()),
        details,
    }
}

/// An `importCertificate` failure of the core for the certificate with serial `serial`
/// (hex): the provider's code and its message after `[<serial>] `, or
/// CERTIFICATE_IMPORTING_FAILURE.
pub(crate) fn import_failure(serial: &str, e: &HostError) -> Failure {
    match provider_code(e) {
        Some(code) => provider_failure(code, format!("[{serial}] {}", e.message), &e.message),
        None => Failure::Custom {
            code: CERTIFICATE_IMPORTING_FAILURE.to_owned(),
            message: Some(CERTIFICATE_IMPORTING_FAILURE_MESSAGE.to_owned()),
            details: Some(e.message.clone()),
        },
    }
}

/// The certificate with serial `serial` goes to a storage the core does not write.
pub(crate) fn import_unsupported_storage(serial: &str) -> Failure {
    let code = UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION;
    provider_failure(code, format!("[{serial}] {code}"), &code)
}

pub(crate) fn invalid_importing_certificate() -> Failure {
    Failure::Custom {
        code: INVALID_IMPORTING_CERTIFICATE.to_owned(),
        message: Some(INVALID_IMPORTING_CERTIFICATE_MESSAGE.to_owned()),
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pdk::abi::ErrorCode;

    fn error(cause: &str) -> HostError {
        HostError::new(ErrorCode::Failed, "the core's text").with_cause(cause)
    }

    fn code(f: Failure) -> (String, Option<String>) {
        match f {
            Failure::Custom { code, message, .. } => (code, message),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cms_errors_map_to_codes() {
        let own = |c: &str| (c.to_owned(), Some(c.to_owned()));
        assert_eq!(
            code(cms_failure(&error(cause::CMS_NO_ENCAPSULATED_DATA))),
            own(CMS_NO_ENCAPSULATED_DATA)
        );
        assert_eq!(
            code(cms_failure(&error(cause::CMS_UNKNOWN_ALGORITHM))),
            own(UNKNOWN_ALGORITHM)
        );
        // A sha1WithRSA signer certificate: refused, never upgraded to SHA-256.
        assert_eq!(
            code(cms_failure(&error(cause::KEY_UNSUPPORTED))),
            own(UNKNOWN_ALGORITHM)
        );
        let signing = (
            SIGNING_FAILURE.to_owned(),
            Some(SIGNING_FAILURE_MESSAGE.to_owned()),
        );
        assert_eq!(code(cms_failure(&error(cause::CMS_MALFORMED))), signing);
        assert_eq!(code(cms_failure(&error(cause::KEY_MISMATCH))), signing);
        assert_eq!(
            cms_failure(&error(cause::CMS_MALFORMED)),
            signing_failure("the core's text")
        );
    }

    #[test]
    fn key_file_errors_map_to_provider_codes() {
        for (cause, expected) in [
            (
                "keystore.unsupported_storage",
                Some(UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION),
            ),
            (
                "keystore.generate.unknown_algorithm",
                Some(UNKNOWN_ALGORITHM),
            ),
            ("csr.unknown_algorithm", Some(UNKNOWN_ALGORITHM)),
            (
                "keystore.write.wrong_password",
                Some("WRONG_KEYSTORE_PASSWORD"),
            ),
            (
                "keystore.wrong_password_pattern",
                Some("WRONG_PASSWORD_PATTERN"),
            ),
            ("csr.invalid_request", None),
            ("keystore.write.io", None),
            ("keystore.io", None),
            ("keystore.pkcs12", None),
            ("keystore.malformed", None),
        ] {
            assert_eq!(provider_code(&error(cause)), expected, "{cause}");
        }
        assert_eq!(
            import_failure("4105a0", &error("keystore.wrong_password")),
            Failure::Custom {
                code: "WRONG_KEYSTORE_PASSWORD".to_owned(),
                message: Some("[4105a0] the core's text".to_owned()),
                details: Some("the core's text".to_owned()),
            }
        );
        assert_eq!(
            csr_failure(&error("keystore.io")),
            csr_generating_failure(Some("the core's text".to_owned()))
        );
    }
}
