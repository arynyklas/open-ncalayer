//! The module `kz.fhs.cabinet.FHSCabinetSigner` of First Heartland Securities: the class
//! `FHSSignClassV2` in the original's `CommonInvoker` dialect, with the V1 methods it
//! inherits. Every method takes `args`; the bodies are beans in the key order of Java's
//! `HashMap`, with `code` `"200"` or `"500"` as strings.
//!
//! - V2 (`getTradeCabBundleVersion`, `getCertificatePath`, `getCertificateInfo`,
//!   `signTextV2`, `signXmlV2`): the page names the key file and its password; failures are
//!   bodies (`code` `"500"`, `message` when the original had one).
//! - V1 (`signXml`, `signFile`, `signText`): the user picks the key; every failure is an
//!   error window first, then `{"code":"500"}`.
//!
//! CMS signatures are Kalkan's `createCAdES` (detached, co-signing a CMS with content) with a
//! time-stamp of Kalkan's default TSA profile.

mod texts;

use der::{Decode, Tagged};
use oncl_pdk::abi::{
    CmsCerts, CmsContent, CmsOutcome, CoSign, MessageKind, NetFailure, NetKind, SignCmsExArgs,
    SignedAttrs, SigningTime, TimeForm, TimeSource, TsaChoice,
};
use oncl_pdk::dialogs::{self, ChoiceArgs};
use oncl_pdk::files::{self, ChooseFileArgs, FileFilter, FileMode};
use oncl_pdk::http::{self, HttpExArgs, Method};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{
    BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
};
use oncl_pdk::keys::{self, Action, Filter, Key, KeySource, OpenArgs, Password, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64, javamap};
use oncl_port_kit::date::format_java;
use oncl_port_pki::x509text::kalkan_key_alg_name;
use texts::Texts;
use x509_cert::Certificate;

/// The bundle's version, as `getTradeCabBundleVersion` gives it.
const VERSION: &str = "2.0.0";

/// The date format of the certificate's validity.
const DATE: &str = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

/// The storages the V1 key dialog offers: the token storages, then the key files.
const V1_STORAGES: [&str; 7] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
];

fn handle(request: &Request) -> String {
    let options = InvokeOptions {
        bad_request: BadRequest::Drop,
    };
    let class = FhsSignClassV2 {
        texts: texts::of(request.locale),
    };
    match invoke_with(&request.text, &request.add_info(), &[&class], &options) {
        Reply::Text(text) => text,
        Reply::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

oncl_pdk::plugin!(handle);

/// The class `FHSSignClassV2`, with the texts of the request's language.
struct FhsSignClassV2 {
    texts: &'static Texts,
}

/// A method of one parameter without an annotation name.
const fn method(name: &'static str) -> NlMethod {
    NlMethod {
        name,
        annotation: None,
        params: 1,
    }
}

const METHODS: &[NlMethod] = &[
    method("getTradeCabBundleVersion"),
    method("getCertificatePath"),
    method("getCertificateInfo"),
    method("signTextV2"),
    method("signXmlV2"),
    method("signXml"),
    method("signFile"),
    method("signText"),
];

impl NlClass for FhsSignClassV2 {
    fn class_name(&self) -> &'static str {
        "FHSSignClassV2"
    }

    fn methods(&self) -> &'static [NlMethod] {
        METHODS
    }

    fn call(&self, m: &NlMethod, args: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
        let args = args.expect("every method has a parameter");
        let t = self.texts;
        match m.name {
            "getTradeCabBundleVersion" => Ok(version(args)),
            "getCertificatePath" => Ok(certificate_path(args, t)),
            "getCertificateInfo" => Ok(certificate_info(args)),
            "signTextV2" => Ok(sign_text_v2(args)),
            "signXmlV2" => sign_xml_v2(args),
            "signXml" => sign_xml(args, t),
            "signFile" => sign_file(args, t),
            "signText" => Ok(sign_text(args, t)),
            _ => unreachable!("only METHODS are called"),
        }
    }
}

/// org.json `optString(key)`: `""` when absent or `null`, the text of a non-string.
fn opt_string(args: &Map<String, Value>, key: &str) -> String {
    orgjson::opt_string(args, key).unwrap_or_default()
}

/// `getString(key)`; its exception, as the dispatcher reports it.
fn get_string<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    orgjson::get_string(args, key)
        .map_err(|e| Failure::Invocation(Some(format!("org.json.JSONException: {e}"))))
}

/// FHS's `CommonResponse`: `method`, `requestId`, `code` (the bean's other fields follow).
fn response(method: &str, request_id: &str, code: &str) -> JObject {
    let mut bean = JObject::hash_map();
    bean.put("method", method);
    bean.put("requestId", request_id);
    bean.put("code", code);
    bean
}

/// `getTradeCabBundleVersion{requestId?}`.
fn version(args: &Map<String, Value>) -> JValue {
    let mut bean = response(
        "getTradeCabBundleVersion",
        &opt_string(args, "requestId"),
        "200",
    );
    bean.put("message", "OK");
    bean.put("version", VERSION);
    bean.into()
}

/// `getCertificatePath{requestId?}`: the path of a key file the user picks, none if the
/// user cancels; `code` `"200"` either way.
fn certificate_path(args: &Map<String, Value>, t: &Texts) -> JValue {
    let mut bean = response("getCertificatePath", &opt_string(args, "requestId"), "200");
    let chosen = files::choose(&ChooseFileArgs {
        mode: FileMode::Open,
        title: Some(t.select_certificate.to_owned()),
        filters: vec![FileFilter {
            name: t.key_store.to_owned(),
            extensions: vec!["p12".to_owned()],
        }],
        initial_dir: None,
    });
    if let Ok(Some(chosen)) = chosen {
        bean.put("path", chosen.path);
    }
    bean.put("storage", "PKCS12");
    bean.put("message", "OK");
    bean.into()
}

/// The key of the PKCS#12 file `path` (V2): the first alias in the order of Java's
/// `HashMap`; `None` on any failure, as the original swallows them all.
// Unverified against the original: the order of the aliases of a store with several keys
// (the original's `HashMap` of entries).
fn entity(args: &Map<String, Value>) -> Option<Key> {
    let request = OpenArgs {
        storage: "PKCS12".to_owned(),
        source: KeySource::PagePath(opt_string(args, "path")),
        password: Password::Text(opt_string(args, "password")),
    };
    let keys = keys::open(&request).ok()?.ok()?;
    let aliases: Vec<&str> = keys.iter().map(Key::alias).collect();
    let first = *javamap::iteration_order(&aliases, javamap::DEFAULT_CAPACITY).first()?;
    keys.into_iter().nth(first)
}

/// `getCertificateInfo{requestId?, path, password}`.
fn certificate_info(args: &Map<String, Value>) -> JValue {
    let mut bean = response("getCertificateInfo", &opt_string(args, "requestId"), "500");
    let Some(key) = entity(args) else {
        return bean.into();
    };
    bean.put("code", "200");
    bean.put("message", "OK");
    match certificate(key.certificate()) {
        Ok(info) => {
            bean.put("certificateInfo", info);
        }
        Err(message) => {
            bean.put("message", message);
        }
    }
    bean.into()
}

/// `CertificateInfo` of `der`; an error is the reply's message.
fn certificate(der: &[u8]) -> Result<JObject, String> {
    let details = host::cert_details(der).map_err(|e| e.message)?;
    let info = host::cert_info(der).map_err(|e| e.message)?;
    if details.knca_types.is_empty() {
        let code = "UNKNOWN_KNCA_CERTIFICATE_TYPE";
        return Err(format!("error code:{code}, error message{code}"));
    }
    let date = |ms: i64| {
        let offset = host::local_offset(ms).unwrap_or(0);
        format_java(DATE, ms, offset)
    };
    let mut bean = JObject::hash_map();
    bean.put("serialNumber", details.serial_dec);
    bean.put("issuedDate", date(info.not_before));
    bean.put("expiryDate", date(info.not_after));
    bean.put(
        "algorithm",
        kalkan_key_alg_name(&info.spki_alg_oid).unwrap_or(&info.spki_alg_oid),
    );
    // Kalkan's order; the original's set had none.
    bean.put(
        "certificateType",
        JValue::from(
            details
                .knca_types
                .into_iter()
                .map(JValue::from)
                .collect::<Vec<_>>(),
        ),
    );
    let subject = subject(der);
    let first = |oid: &str| {
        subject
            .iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v.clone())
    };
    bean.put_opt("fullName", first("2.5.4.3"));
    bean.put_opt("orgName", first("2.5.4.10"));
    bean.put_opt("bin", first("2.5.4.11"));
    bean.put_opt("iin", first("2.5.4.5"));
    bean.put_opt("surname", first("2.5.4.4"));
    bean.put_opt("middleName", first("2.5.4.42"));
    Ok(bean)
}

/// The string attributes of the certificate's subject, in DER order: (OID, value).
fn subject(der: &[u8]) -> Vec<(String, String)> {
    let Ok(cert) = Certificate::from_der(der) else {
        return Vec::new();
    };
    cert.tbs_certificate()
        .subject()
        .iter_rdn()
        .flat_map(|rdn| rdn.iter())
        .filter_map(|ava| {
            let bytes = ava.value.value();
            let text = match ava.value.tag() {
                der::Tag::BmpString => char::decode_utf16(
                    bytes
                        .chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])),
                )
                .collect::<Result<String, _>>()
                .ok()?,
                _ => String::from_utf8(bytes.to_vec()).ok()?,
            };
            Some((ava.oid.to_string(), text))
        })
        .collect()
}

/// Why `createCAdES` and `applyCAdEST` failed.
enum SignError {
    /// The time-stamp failed: the cause's `toString()`.
    Tsp(String),
    /// The core refused: its message.
    Host(String),
}

/// Kalkan's `createCAdES` of `data` (detached; a CMS with content gets co-signed) with a
/// time-stamp of Kalkan's default TSA profile.
fn cades(key: &Key, data: &[u8]) -> Result<Vec<u8>, SignError> {
    let args = SignCmsExArgs {
        handle: key.handle(),
        content: CmsContent::Data(data.to_vec().into()),
        encapsulate: false,
        cosign: CoSign::Auto,
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
        timestamp: Some(TsaChoice::Kalkan),
        output: oncl_pdk::abi::CmsOutput::Der,
    };
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
        Ok(CmsOutcome::TspFailed(failure)) => Err(SignError::Tsp(tsp_cause(&failure))),
        Err(e) => Err(SignError::Host(e.message)),
    }
}

/// The `toString()` of the exception a failed time-stamp of Kalkan's has as its cause.
// Unverified against the original: the exception texts (JDK and Kalkan), built here from
// the core's failure.
fn tsp_cause(failure: &NetFailure) -> String {
    match failure.kind {
        NetKind::Http(status) => {
            format!("kz.gov.pki.kalkan.tsp.TSPException: HTTP error code: {status}")
        }
        NetKind::UnknownHost => format!("java.net.UnknownHostException: {}", failure.address),
        NetKind::Timeout => "java.net.SocketTimeoutException: Read timed out".to_owned(),
        NetKind::Connect => "java.net.ConnectException: Connection refused: connect".to_owned(),
        _ => format!("kz.gov.pki.kalkan.tsp.TSPException: {}", failure.detail),
    }
}

/// Standard base64, padded, on one line.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}

/// `signTextV2{requestId?, base64data, path, password}`.
fn sign_text_v2(args: &Map<String, Value>) -> JValue {
    let mut bean = response("signTextV2", &opt_string(args, "requestId"), "500");
    let Some(key) = entity(args) else {
        return bean.into();
    };
    let data = match javab64::decode_java(&opt_string(args, "base64data")) {
        Ok(data) => data,
        Err(message) => {
            bean.put("message", message);
            return bean.into();
        }
    };
    match cades(&key, &data) {
        Ok(cms) => {
            bean.put("code", "200");
            bean.put("message", base64(&cms));
        }
        Err(SignError::Tsp(cause)) => {
            let code = "TIMESTAMP_CREATION_FAILURE";
            bean.put(
                "message",
                format!("error code:{code}, error message{cause}"),
            );
        }
        // Unverified against the original: the provider's message (the core's here).
        Err(SignError::Host(message)) => {
            bean.put("message", message);
        }
    }
    bean.into()
}

/// `signXmlV2{requestId?, xml, path, password}`: `xml` is required before anything else.
fn sign_xml_v2(args: &Map<String, Value>) -> CallResult {
    let request_id = opt_string(args, "requestId");
    let xml = get_string(args, "xml")?;
    let mut bean = response("signXmlV2", &request_id, "500");
    let Some(key) = entity(args) else {
        return Ok(bean.into());
    };
    match key.sign_xml(xml.as_bytes(), None, None) {
        Ok(signed) => {
            bean.put("code", "200");
            bean.put("message", String::from_utf8_lossy(&signed).into_owned());
        }
        // Unverified against the original: the provider's message (the core's here).
        Err(e) => {
            bean.put("message", e.message);
        }
    }
    Ok(bean.into())
}

/// V1's `ResponseMessage` of a success.
fn v1_ok(message: String) -> JValue {
    let mut bean = JObject::hash_map();
    bean.put("code", "200");
    bean.put("message", message);
    bean.into()
}

/// V1's reply to every failure, after `text` in an error window when there is one.
fn v1_failed(text: Option<&str>, t: &Texts) -> JValue {
    if let Some(text) = text {
        let _ = dialogs::choice(&ChoiceArgs {
            kind: MessageKind::Error,
            title: Some(t.error.to_owned()),
            text: text.to_owned(),
            buttons: vec![t.close.to_owned()],
            default: 0,
            options: Vec::new(),
        });
    }
    let mut bean = JObject::hash_map();
    bean.put("code", "500");
    bean.into()
}

/// The V1 key: the user picks it among the key files and tokens, without checks.
fn v1_key() -> Option<Key> {
    let request = SelectArgs {
        action: Action::Sign,
        storages: V1_STORAGES.iter().map(|s| (*s).to_owned()).collect(),
        filter: Filter {
            chain: Some(Vec::new()),
            allow_expired: true,
            allow_revoked: true,
            ..Filter::default()
        },
        more: Default::default(),
        detail: None,
        initial_path: None,
        order: Default::default(),
    };
    keys::select(&request).ok().flatten()
}

/// `signXml{xml}`: the whole document with an enveloped signature.
fn sign_xml(args: &Map<String, Value>, t: &Texts) -> CallResult {
    let xml = get_string(args, "xml")?;
    let Some(key) = v1_key() else {
        return Ok(v1_failed(Some(t.key_not_selected), t));
    };
    Ok(match key.sign_xml(xml.as_bytes(), None, None) {
        Ok(signed) => v1_ok(String::from_utf8_lossy(&signed).into_owned()),
        // Unverified against the original: the provider's message (the core's here).
        Err(e) => v1_failed(Some(&e.message), t),
    })
}

/// `signFile{url}`: the file at `url` (the page's site only), then a CMS of it.
fn sign_file(args: &Map<String, Value>, t: &Texts) -> CallResult {
    let url = get_string(args, "url")?;
    let downloaded = http::request_ex(&HttpExArgs {
        method: Method::Get,
        url: url.to_owned(),
        relative_to_origin: false,
        headers: Vec::new(),
        content_type: None,
        body: Default::default(),
        timeout_ms: None,
    });
    let data = match downloaded {
        Ok(reply) if reply.status == 200 => reply.body.into_vec(),
        _ => return Ok(v1_failed(Some(t.download_failed), t)),
    };
    let Some(key) = v1_key() else {
        return Ok(v1_failed(Some(t.key_not_selected), t));
    };
    Ok(match cades(&key, &data) {
        Ok(cms) => v1_ok(base64(&cms)),
        // Unverified against the original: the provider's message (built here).
        Err(SignError::Tsp(cause)) => v1_failed(Some(&cause), t),
        Err(SignError::Host(message)) => v1_failed(Some(&message), t),
    })
}

/// `signText{base64data}`.
fn sign_text(args: &Map<String, Value>, t: &Texts) -> JValue {
    let data = opt_string(args, "base64data");
    let Some(key) = v1_key() else {
        return v1_failed(Some(t.key_not_selected), t);
    };
    let Ok(data) = javab64::decode_java(&data) else {
        return v1_failed(Some(t.sign_failed), t);
    };
    match cades(&key, &data) {
        Ok(cms) => v1_ok(base64(&cms)),
        Err(SignError::Tsp(_)) => v1_failed(Some(t.tsp_failed), t),
        // A provider failure other than a password or a time-stamp: no window.
        Err(SignError::Host(_)) => v1_failed(None, t),
    }
}
