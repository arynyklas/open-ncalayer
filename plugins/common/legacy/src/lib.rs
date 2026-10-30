//! What the ports of the original's `commonUtils` clones share (the modules answering
//! through the reflective dispatcher, [`oncl_pdk::legacy`], and their relatives):
//!
//! - the `ResponseMessage` bean of their replies ([`response`], [`ok`], [`fail`]);
//! - the checks of their `StorageInfo` ([`storage`]) and the key types of their key dialog
//!   ([`knca_types`]), and on wasm32 the key choice itself ([`select`]);
//! - the official `KeyInfo` ([`official_key_info`]) and the certificate details it reads;
//! - Java's standard Base64 encoder ([`base64`]), the ESEDO file names ([`split_names`]) and
//!   the texts of Java's network exceptions ([`net_exception`]).

use der::{Decode, Encode};
use oncl_pdk::abi::{
    Bytes, CmsCerts, CmsContent, CoSign, NetFailure, NetKind, SignCmsExArgs, SignedAttrs,
    SigningTime, TimeForm, TimeSource, TsaChoice,
};
use oncl_pdk::javaexc::Throwable;
use oncl_pdk::legacy::Outcome;
use oncl_pdk::orgjson::{JObject, JValue};
use x509_cert::Certificate;

/// The dialogs were cancelled.
pub const ACTION_CANCELED: &str = "action.canceled";
/// `StorageInfo` without a storage name.
pub const STORAGE_NAME_EMPTY: &str = "storageName.param.empty";
/// `StorageInfo` with a name Kalkan does not know.
pub const STORAGE_UNKNOWN: &str = "storage.unknown";
/// `StorageInfo` of a token storage without a connected token.
pub const STORAGE_EMPTY: &str = "storage.empty";
/// Kalkan's `ProviderUtilException` for a certificate algorithm it cannot sign with.
pub const UNKNOWN_ALGORITHM: &str = "UNKNOWN_ALGORITHM";
/// The clones' text of a failed `applyCAdEST`: `"Ошибка. Код: " + code` of the
/// `ProviderUtilException`, whose code is then `TIMESTAMP_CREATION_FAILURE`.
pub const TSA_FAILED: &str = "Ошибка. Код: TIMESTAMP_CREATION_FAILURE";

/// Kalkan's token storages, in its `Storage` order.
pub const TOKEN_STORAGES: [&str; 7] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "ABCloudServiceStore",
];

/// Kalkan's `KNCACertificateType` names the core knows.
const KNCA_TYPES: [&str; 5] = [
    "SIGNATURE",
    "AUTHENTICATION",
    "SSL",
    "OCSP_RESPONSE_SIGNING",
    "TSP_SIGNING",
];

/// A storage `StorageInfo` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// A key store file: `PKCS12` or `JKS`.
    File(&'static str),
    /// A token storage, by its Kalkan name.
    Token(&'static str),
}

impl Storage {
    /// Its Kalkan name.
    pub fn name(self) -> &'static str {
        match self {
            Storage::File(name) | Storage::Token(name) => name,
        }
    }
}

/// `StorageInfo`'s checks of `name`: blank (Java's `trim`) is [`STORAGE_NAME_EMPTY`], a
/// name Kalkan does not know (exact case) [`STORAGE_UNKNOWN`].
///
/// # Errors
///
/// The message of the check that fails.
pub fn storage(name: &str) -> Result<Storage, &'static str> {
    if name.trim_matches(|c| c <= ' ').is_empty() {
        return Err(STORAGE_NAME_EMPTY);
    }
    match name {
        "PKCS12" => Ok(Storage::File("PKCS12")),
        "JKS" => Ok(Storage::File("JKS")),
        _ => TOKEN_STORAGES
            .into_iter()
            .find(|token| *token == name)
            .map(Storage::Token)
            .ok_or(STORAGE_UNKNOWN),
    }
}

/// The key types the key dialog lists for `KNCACertificateType.valueOf(key_type)`: that
/// type, or for a name that is not one (`null`, no filter) signing and authentication keys,
/// as the built-in commonUtils lists them.
pub fn knca_types(key_type: &str) -> Vec<String> {
    match KNCA_TYPES.into_iter().find(|t| *t == key_type) {
        Some(t) => vec![t.to_owned()],
        None => vec!["SIGNATURE".to_owned(), "AUTHENTICATION".to_owned()],
    }
}

/// The `ResponseMessage` bean as `JSONObject.wrap` writes it: `responseObject`, `code`,
/// `message`, the `None` ones left out, in Java's `HashMap` order.
pub fn response(object: Option<JValue>, code: &str, message: Option<&str>) -> JObject {
    let mut bean = JObject::hash_map();
    bean.put("code", code);
    bean.put_opt("message", message);
    bean.put_opt("responseObject", object);
    bean
}

/// `{"responseObject":…,"code":"200"}`.
pub fn ok(object: impl Into<JValue>) -> Outcome {
    Outcome::Json(response(Some(object.into()), "200", None))
}

/// `{"code":"500","message":…}`, without `message` for an exception without one.
pub fn fail(message: Option<&str>) -> Outcome {
    Outcome::Json(response(None, "500", message))
}

/// Java's `Base64.getEncoder().encodeToString`: the standard alphabet, padded, one line.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> shift) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Kalkan's `CMSUtil.createCAdES` of `data` by the key `handle`: contentType, signingTime,
/// messageDigest and signingCertificateV2, the signer certificate, `cosign` as asked; with
/// `timestamp`, then `applyCAdEST` of Kalkan's default TSA profile on the new signer.
pub fn cades_args(
    handle: u32,
    data: &[u8],
    encapsulate: bool,
    cosign: CoSign,
    timestamp: bool,
) -> SignCmsExArgs {
    SignCmsExArgs {
        handle,
        content: CmsContent::Data(Bytes::from(data.to_vec())),
        encapsulate,
        cosign,
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
        certificates: CmsCerts::Signer,
        timestamp: timestamp.then_some(TsaChoice::Kalkan),
    }
}

/// The ESEDO file names of `text`: split on `<>` as Java's `split` (trailing empty parts
/// dropped), each trimmed; a blank text is none.
pub fn split_names(text: &str) -> Vec<String> {
    if text.trim_matches(|c| c <= ' ').is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = text.split("<>").collect();
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    parts
        .into_iter()
        .map(|p| p.trim_matches(|c| c <= ' ').to_owned())
        .collect()
}

/// The Java exception a request to a PKI service ended with:
/// `java.net.UnknownHostException: <host>`, a read time-out, a refused connection, else an
/// `IOException` with the core's detail.
fn net_throwable(failure: &NetFailure) -> Throwable {
    match failure.kind {
        NetKind::UnknownHost => Throwable::unknown_host(failure.address.clone()),
        NetKind::Timeout => Throwable::socket_timeout(true),
        NetKind::Connect => Throwable::connect_refused(),
        _ => Throwable::new("java.io.IOException", Some(failure.detail.clone())),
    }
}

/// `toString()` of the Java exception of `failure` (`java.net.UnknownHostException: <host>`).
pub fn net_exception(failure: &NetFailure) -> String {
    net_throwable(failure).to_string()
}

/// `getMessage()` of the Java exception of `failure` (the host alone for an unknown host).
pub fn net_message(failure: &NetFailure) -> String {
    net_throwable(failure).message.unwrap_or_default()
}

/// The values of the attributes of type `oid` (dotted) of the Name `name` (DER), in DER
/// order; only values of a string type.
///
/// # Errors
///
/// `name` is not the DER of a Name.
pub fn name_values(name: &[u8], oid: &str) -> Result<Vec<String>, String> {
    let name = x509_cert::name::Name::from_der(name).map_err(|e| e.to_string())?;
    Ok(name
        .iter_rdn()
        .flat_map(|rdn| rdn.iter())
        .filter(|ava| ava.oid.to_string() == oid)
        .filter_map(|ava| {
            std::str::from_utf8(ava.value.value())
                .ok()
                .map(str::to_owned)
        })
        .collect())
}

/// The DER of the subject and the issuer of the certificate `der`.
///
/// # Errors
///
/// `der` is not a certificate.
pub fn subject_and_issuer(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert = Certificate::from_der(der).map_err(|e| e.to_string())?;
    let tbs = cert.tbs_certificate();
    let subject = tbs.subject().to_der().map_err(|e| e.to_string())?;
    let issuer = tbs.issuer().to_der().map_err(|e| e.to_string())?;
    Ok((subject, issuer))
}

/// The first CN of the Name `name` (DER), as `X509Util` reads it.
pub fn common_name(name: &[u8]) -> Option<String> {
    name_values(name, "2.5.4.3").ok()?.into_iter().next()
}

#[cfg(target_arch = "wasm32")]
mod guest;
#[cfg(target_arch = "wasm32")]
pub use guest::{Select, cades, into_text, official_key_info, select, sign_xml};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_checks() {
        assert_eq!(storage(""), Err(STORAGE_NAME_EMPTY));
        assert_eq!(storage(" \t"), Err(STORAGE_NAME_EMPTY));
        assert_eq!(storage(" PKCS12"), Err(STORAGE_UNKNOWN));
        assert_eq!(storage("pkcs12"), Err(STORAGE_UNKNOWN));
        assert_eq!(storage("PKCS12"), Ok(Storage::File("PKCS12")));
        assert_eq!(storage("JKS"), Ok(Storage::File("JKS")));
        assert_eq!(
            storage("AKKZIDCardStore"),
            Ok(Storage::Token("AKKZIDCardStore"))
        );
    }

    #[test]
    fn key_types() {
        assert_eq!(knca_types("SIGNATURE"), ["SIGNATURE"]);
        assert_eq!(knca_types("AUTHENTICATION"), ["AUTHENTICATION"]);
        assert_eq!(knca_types("sign"), ["SIGNATURE", "AUTHENTICATION"]);
        assert_eq!(knca_types(""), ["SIGNATURE", "AUTHENTICATION"]);
    }

    #[test]
    fn beans_in_hash_map_order() {
        assert_eq!(
            response(Some("x".into()), "200", Some("m")).to_json(),
            r#"{"responseObject":"x","code":"200","message":"m"}"#
        );
        assert_eq!(response(None, "500", None).to_json(), r#"{"code":"500"}"#);
    }

    #[test]
    fn base64_like_java() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn names_split_like_java() {
        assert_eq!(split_names(""), Vec::<String>::new());
        assert_eq!(split_names("  "), Vec::<String>::new());
        assert_eq!(split_names(" a <> b "), ["a", "b"]);
        assert_eq!(split_names("a<><>"), ["a"]);
        assert_eq!(split_names("<>a"), ["", "a"]);
    }

    #[test]
    fn network_texts() {
        let failure = |kind| NetFailure {
            stage: oncl_pdk::abi::NetStage::Ocsp,
            kind,
            address: "ocsp.pki.gov.kz".to_owned(),
            detail: "d".to_owned(),
        };
        assert_eq!(
            net_exception(&failure(NetKind::UnknownHost)),
            "java.net.UnknownHostException: ocsp.pki.gov.kz"
        );
        assert_eq!(
            net_exception(&failure(NetKind::Timeout)),
            "java.net.SocketTimeoutException: Read timed out"
        );
    }
}
