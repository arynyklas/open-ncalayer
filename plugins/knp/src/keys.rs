//! The key stores the page names (a PKCS#12 as a data URL with its password, or a token
//! reader), their certificates and the cabinet's XML signature.

use crate::Fail;
use der::Decode;
use oncl_pdk::abi::{KeySource, OpenOutcome, Password};
use oncl_pdk::host;
use oncl_pdk::javab64;
use oncl_pdk::keys::{
    self, C14n, Key, OpenArgs, Placement, SignXmlExArgs, SigningTimeObject, Transform, XmlOutput,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_port_pki::x509text;

/// The date of `validTo` and of the signing time: the system's time zone.
pub const DATE: &str = "dd-MM-yyyy HH:mm:ss Z";

/// The Kalkan storage of a storage type of the page; `None` for another.
fn storage(kind: &str) -> Option<&'static str> {
    match kind {
        "PKCS12" => Some("PKCS12"),
        "KAZTOKEN" => Some("AKKaztokenStore"),
        "KZIDCARD" => Some("AKKZIDCardStore"),
        "ETOKEN_72K" => Some("AKEToken72KStore"),
        "JACARTA" => Some("AKJaCartaStore"),
        _ => None,
    }
}

/// The Kalkan token storage of a token type (for its readers).
pub fn token_storage(kind: &str) -> Option<&'static str> {
    storage(kind).filter(|s| *s != "PKCS12")
}

/// Every key of the store of type `kind` at `path` (`storagePath`).
pub fn open(kind: &str, path: &str, password: &str) -> Result<Vec<Key>, Fail> {
    let storage = storage(kind).ok_or(Fail::Generic)?;
    let source = if storage == "PKCS12" {
        // Everything after the first `base64,`, or the whole path, is the store's base64.
        let data = path.split_once("base64,").map_or(path, |(_, data)| data);
        // Unverified against the original: which Base64 decoder reads it (taken as Java's
        // strict one; a failure is the general error).
        KeySource::Bytes(
            javab64::decode_java(data)
                .map_err(|_| Fail::Generic)?
                .into(),
        )
    } else {
        KeySource::Terminal(path.to_owned())
    };
    let opened = keys::open(&OpenArgs {
        storage: storage.to_owned(),
        source,
        password: Password::Text(password.to_owned()),
    })
    .map_err(|_| Fail::Generic)?;
    match opened {
        Ok(keys) => Ok(keys),
        Err(OpenOutcome::NoKeys) => Ok(Vec::new()),
        Err(OpenOutcome::WrongPassword { .. } | OpenOutcome::Blocked) => {
            Err(Fail::Crypto("STORE_WRONG_PASSWORD"))
        }
        Err(_) => Err(Fail::Crypto("KEY_STORE_ERROR")),
    }
}

/// The key usage bits of `der` (none without the extension).
fn key_usage(der: &[u8]) -> [bool; 9] {
    let mut bits = [false; 9];
    let Ok(cert) = x509_cert::Certificate::from_der(der) else {
        return bits;
    };
    let Some(ext) = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "2.5.29.15")
    else {
        return bits;
    };
    if let Ok(usage) = der::asn1::BitString::from_der(ext.extn_value.as_bytes()) {
        for (i, bit) in usage.bits().take(9).enumerate() {
            bits[i] = bit;
        }
    }
    bits
}

/// A certificate of `getCertificates`.
pub fn certificate(key: &Key) -> Result<JObject, Fail> {
    let der = key.certificate();
    let details = host::cert_details(der).map_err(|_| Fail::Generic)?;
    let info = host::cert_info(der).map_err(|_| Fail::Generic)?;
    let bits = key_usage(der);
    let mut usage = JObject::hash_map();
    usage.put("keyEncipherment", bits[2]);
    usage.put("crlSign", bits[6]);
    usage.put("nonRepudiation", bits[1]);
    usage.put("digitalSignature", bits[0]);
    usage.put("keyAgreement", bits[4]);
    usage.put("keyCertSign", bits[5]);
    let offset = host::local_offset(info.not_after).map_err(|_| Fail::Generic)?;
    let mut cert = JObject::hash_map();
    cert.put("keyUsage", usage);
    cert.put("issuerDN", details.issuer_dn);
    cert.put("alias", key.alias());
    cert.put("subjectDN", details.subject_dn);
    cert.put_opt(
        "algorithm",
        x509text::kalkan_key_alg_name(&info.spki_alg_oid),
    );
    cert.put(
        "validTo",
        oncl_port_kit::date::format_java(DATE, info.not_after, offset),
    );
    Ok(cert)
}

/// The page's key: of the store its `storageType`, `storagePath` and `password` name, the
/// one with `alias`, valid now.
pub fn signing_key(args: &Map<String, Value>) -> Result<Key, Fail> {
    let kind = crate::string(args, "storageType")?;
    let path = crate::string(args, "storagePath")?;
    let password = orgjson::opt_string(args, "password").unwrap_or_default();
    let alias = crate::string(args, "alias")?;
    let key = open(&kind, &path, &password)?
        .into_iter()
        .find(|key| key.alias() == alias)
        .ok_or(Fail::Generic)?;
    let info = host::cert_info(key.certificate()).map_err(|_| Fail::Generic)?;
    let now = host::now().map_err(|_| Fail::Generic)?;
    if now < info.not_before || now > info.not_after {
        return Err(Fail::Crypto("SIGN_CERT_EXPIRED"));
    }
    Ok(key)
}

/// `(SignatureMethod, DigestMethod)` by the certificate's signature algorithm. sha1RSA
/// certificates are refused: no RSA-SHA1 signatures are made.
fn uris(der: &[u8]) -> Result<(&'static str, &'static str), Fail> {
    let info = host::cert_info(der).map_err(|_| Fail::Generic)?;
    match x509text::kalkan_sig_alg_name(&info.signature_alg_oid) {
        Some("SHA256WithRSAEncryption") => Ok((
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )),
        Some("ECGOST34310") => Ok((
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        )),
        Some("ECGOST3410-2015-512") => Ok((
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        )),
        _ => Err(Fail::Generic),
    }
}

/// The `ds:Signature` elements already in `xml` (`//ds:Signature`), approximated by the
/// start tags whose local name is `Signature` when the document uses the XMLDSig
/// namespace.
fn signatures(xml: &str) -> usize {
    if !xml.contains("http://www.w3.org/2000/09/xmldsig#") {
        return 0;
    }
    xml.split('<')
        .skip(1)
        .filter(|tag| {
            let name = tag
                .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .next()
                .unwrap_or_default();
            name.rsplit(':').next() == Some("Signature")
        })
        .count()
}

/// The cabinet's signature of `xml`: in the document's first node, `Id` `"1"` and the
/// count of signatures already there, a signing-time property signed by a second
/// reference; written with `standalone="no"`.
pub fn sign_xml(key: &Key, xml: &str) -> Result<String, Fail> {
    let (signature_method, digest_method) = uris(key.certificate())?;
    let now = host::now().map_err(|_| Fail::Generic)?;
    let offset = host::local_offset(now).map_err(|_| Fail::Generic)?;
    let id = (1 + signatures(xml)).to_string();
    let signed = key
        .sign_xml_ex(SignXmlExArgs {
            handle: key.handle(),
            xml: xml.as_bytes().to_vec().into(),
            element: None,
            parent: None,
            namespaces: Vec::new(),
            other_prefix_uri: None,
            placement: Placement::FirstChildOfDocument,
            signature_method: Some(signature_method.to_owned()),
            digest_method: Some(digest_method.to_owned()),
            signed_info_c14n: Some(C14n::Inclusive),
            transforms: Some(vec![
                Transform::Enveloped,
                Transform::C14n(C14n::InclusiveWithComments),
            ]),
            signature_id: Some(id),
            signing_time_object: Some(SigningTimeObject {
                property_id: "signingTime".to_owned(),
                target_ref: true,
                text: oncl_port_kit::date::format_java(DATE, now, offset),
            }),
            strip_whitespace: false,
            base64_line_breaks: None,
            output: XmlOutput::Serialize {
                declaration: true,
                standalone_no: true,
                trim: false,
            },
        })
        .map_err(|_| Fail::Generic)?;
    String::from_utf8(signed).map_err(|_| Fail::Generic)
}

/// The certificates of `keys` as `getCertificates` lists them.
pub fn certificates(keys: &[Key]) -> Result<JValue, Fail> {
    Ok(JValue::Arr(
        keys.iter()
            .map(|key| certificate(key).map(JValue::Obj))
            .collect::<Result<_, _>>()?,
    ))
}
