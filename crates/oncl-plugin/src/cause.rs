//! The [`HostError::cause`](oncl_pdk::abi::HostError::cause) of each failure of the core's
//! signatures, time-stamps, page files and key files: one of [`oncl_pdk::abi::cause`] per
//! variant of the core's errors, so a guest tells them apart as the core's modules did.

use oncl_flows::PageFileError;
use oncl_pdk::abi::cause;
use oncl_pki::cms::CmsError;
use oncl_pki::key::KeyError;
use oncl_pki::keystore::KeystoreError;
use oncl_pki::tsp::TspError;
use oncl_pki::xmldsig::XmlError;

/// The cause of a CMS failure; a key's failure inside it is the key's.
pub fn cms(e: &CmsError) -> &'static str {
    match e {
        CmsError::NoEncapsulatedData => cause::CMS_NO_ENCAPSULATED_DATA,
        CmsError::UnknownAlgorithm(_) => cause::CMS_UNKNOWN_ALGORITHM,
        CmsError::Malformed(_) => cause::CMS_MALFORMED,
        CmsError::CertNotFound(_) => cause::CMS_CERT_NOT_FOUND,
        CmsError::DigestMismatch(_) => cause::CMS_DIGEST_MISMATCH,
        CmsError::BadSignature(_) => cause::CMS_BAD_SIGNATURE,
        CmsError::SigningCertificateMismatch(_) => cause::CMS_SIGNING_CERTIFICATE_MISMATCH,
        CmsError::Key(e) => key(e),
        CmsError::Constraint(_) => cause::CMS_CONSTRAINT,
    }
}

/// The cause of an XML signature failure; a key's failure inside it is the key's.
pub fn xml(e: &XmlError) -> &'static str {
    match e {
        XmlError::Parse(_) | XmlError::NotWellFormed(_) => cause::XML_PARSE,
        XmlError::Doctype => cause::XML_DOCTYPE,
        XmlError::TooLarge => cause::XML_TOO_LARGE,
        XmlError::TooDeep => cause::XML_TOO_DEEP,
        XmlError::XPath(_) => cause::XML_XPATH,
        XmlError::Constraint(_) => cause::XML_CONSTRAINT,
        XmlError::UnsupportedAlgorithm(_) => cause::XML_UNSUPPORTED_ALGORITHM,
        XmlError::NoSignature => cause::XML_NO_SIGNATURE,
        XmlError::BadDigest => cause::XML_BAD_DIGEST,
        XmlError::BadSignature => cause::XML_BAD_SIGNATURE,
        XmlError::Key(e) => key(e),
    }
}

/// The cause of a key's failure.
pub fn key(e: &KeyError) -> &'static str {
    match e {
        KeyError::Malformed(_) => cause::KEY_MALFORMED,
        KeyError::UnknownKeyAlgorithm(_) => cause::KEY_UNKNOWN_KEY_ALGORITHM,
        KeyError::UnsupportedAlgorithm => cause::KEY_UNSUPPORTED,
        KeyError::KeyMismatch => cause::KEY_MISMATCH,
        KeyError::BadSignature => cause::KEY_BAD_SIGNATURE,
        KeyError::NotExportable => cause::KEY_NOT_EXPORTABLE,
        KeyError::Token(_) => cause::KEY_TOKEN,
    }
}

/// The cause of a time-stamp's failure; an invalid CMS is the CMS's.
pub fn tsp(e: &TspError) -> &'static str {
    match e {
        TspError::Http(_) => cause::TSP_HTTP,
        TspError::Status(_) => cause::TSP_STATUS,
        TspError::ContentType(_) => cause::TSP_CONTENT_TYPE,
        TspError::Rejected(_) => cause::TSP_REJECTED,
        TspError::NonceMismatch => cause::TSP_NONCE_MISMATCH,
        TspError::ImprintMismatch => cause::TSP_IMPRINT_MISMATCH,
        TspError::UnsupportedImprintAlgorithm(_) => cause::TSP_UNSUPPORTED_IMPRINT_ALGORITHM,
        TspError::PolicyMismatch => cause::TSP_POLICY_MISMATCH,
        TspError::NoTsaCertificate => cause::TSP_NO_TSA_CERTIFICATE,
        TspError::ClockSkew => cause::TSP_CLOCK_SKEW,
        TspError::Cms(e) => cms(e),
        TspError::Malformed(_) => cause::TSP_MALFORMED,
    }
}

/// The cause of a file the core does not read.
pub fn page_file(e: PageFileError) -> &'static str {
    match e {
        PageFileError::NotFound => cause::PAGE_FILE_NOT_FOUND,
        PageFileError::TooLarge => cause::PAGE_FILE_TOO_LARGE,
    }
}

/// The cause of a key file failure, `keystore.<variant>`.
pub fn keystore(e: &KeystoreError) -> &'static str {
    match e {
        KeystoreError::UnknownAlgorithm => cause::KEYSTORE_UNKNOWN_ALGORITHM,
        KeystoreError::KeystoreFileNotFound(_) => cause::KEYSTORE_KEYSTORE_FILE_NOT_FOUND,
        KeystoreError::UnsuitedStorage => cause::KEYSTORE_UNSUITED_STORAGE,
        KeystoreError::InappropriateCert => cause::KEYSTORE_INAPPROPRIATE_CERT,
        KeystoreError::WrongPassword => cause::KEYSTORE_WRONG_PASSWORD,
        KeystoreError::WrongPasswordPattern { .. } => cause::KEYSTORE_WRONG_PASSWORD_PATTERN,
        KeystoreError::ChangePasswordConstraint => cause::KEYSTORE_CHANGE_PASSWORD_CONSTRAINT,
        KeystoreError::ExtensionNotFound => cause::KEYSTORE_EXTENSION_NOT_FOUND,
        KeystoreError::UnsupportedStorage => cause::KEYSTORE_UNSUPPORTED_STORAGE,
        KeystoreError::InvalidRequest(_) => cause::KEYSTORE_INVALID_REQUEST,
        KeystoreError::Malformed(_) => cause::KEYSTORE_MALFORMED,
        KeystoreError::Io(_) => cause::KEYSTORE_IO,
        KeystoreError::Pkcs12(_) => cause::KEYSTORE_PKCS12,
    }
}

/// The cause of a failure of `keystore_new_key` at `step` (one of
/// [`cause::NEW_KEY_STEPS`]): the step, `.` and the variant of [`keystore`], e.g.
/// `csr.invalid_request`.
pub fn new_key(step: &str, e: &KeystoreError) -> String {
    let variant = keystore(e)
        .strip_prefix("keystore.")
        .expect("a key file cause starts with keystore.");
    format!("{step}.{variant}")
}
