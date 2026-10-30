//! The module `kz.devart.bundle.Devart`: the class `DevartNLClass` in the original's
//! `CommonInvoker` dialect, whose bodies are JSON **texts** (encoded twice on the page).
//!
//! - `getSignerInfo`: the user picks a signing key; the reply names its subject and a
//!   token for it.
//! - `signDevart{token, dataList}`: with that key and no dialog, ESF (raw signatures of the
//!   text), XML (enveloped XMLDSig) and CMS (attached, co-signing a CMS, every signer
//!   without a time-stamp stamped) items, each type in its group of a hand-built text.
//! - `extractFromCms{dataList}`: the content of attached CMSes.
//!
//! Failures of the plugin's own are bodies `{"errorCode":"Ошибка! <message>"}`; checked
//! exceptions of the certificate checks leave the method (`INVOCATION_ERROR`).

mod cas;

use der::{Decode, Encode};
use oncl_pdk::abi::{
    CertStatusAbi, CmsCerts, CmsContent, CmsOutcome, CoSign, HashAlg, IssuerSel, NetFailure,
    NetKind, Nonce, OcspArgs, OcspOutcome, PkiMethod, PkiUrl, SignCmsExArgs, SignedAttrs,
    SigningTime, TimeForm, TimeSource,
};
use oncl_pdk::invoker::Failure;
use oncl_pdk::invoker::java::{
    BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
};
use oncl_pdk::keys::{self, Action, Filter, FilterMore, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{
    self, SignerSel, StampArgs, StampMode, StampOutcome, TokenForm, TsaChoice, TsaSpec,
};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Reply, Request, host, javab64};
use oncl_port_kit::date::format_java;
use oncl_port_pki::{cms_read, x509text};
use std::sync::Mutex;
use x509_cert::Certificate;

/// The storages `getSignerInfo` knows.
const FILE_STORAGES: [&str; 2] = ["PKCS12", "JKS"];
const TOKEN_STORAGES: [&str; 7] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "ABCloudServiceStore",
];

/// The names of the NCA's extended key usages `certificateKeyUser` lists.
const KEY_USERS: [(&str, &str); 15] = [
    ("INDIVIDUAL", "1.2.398.3.3.4.1.1"),
    ("ORGANIZATION", "1.2.398.3.3.4.1.2"),
    ("CEO", "1.2.398.3.3.4.1.2.1"),
    ("CAN_SIGN", "1.2.398.3.3.4.1.2.2"),
    ("CAN_SIGN_FINANCIAL", "1.2.398.3.3.4.1.2.3"),
    ("HR", "1.2.398.3.3.4.1.2.4"),
    ("EMPLOYEE", "1.2.398.3.3.4.1.2.5"),
    ("NCA_PRIVILEGES", "1.2.398.3.3.4.2"),
    ("NCA_ADMIN", "1.2.398.3.3.4.2.1"),
    ("NCA_MANAGER", "1.2.398.3.3.4.2.2"),
    ("NCA_OPERATOR", "1.2.398.3.3.4.2.3"),
    ("IDENTIFICATION", "1.2.398.3.3.4.3"),
    ("IDENTIFICATION_CON", "1.2.398.3.3.4.3.1"),
    ("IDENTIFICATION_REMOTE", "1.2.398.3.3.4.3.2"),
    ("IDENTIFICATION_REMOTE_DIGITAL_ID", "1.2.398.3.3.4.3.2.1"),
];

/// The extKeyUsage extension.
const EXT_KEY_USAGE: &str = "2.5.29.37";

/// The DER of the id-aa-signatureTimeStampToken OID.
const TIME_STAMP_OID: [u8; 13] = [
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e,
];

/// What `getSignerInfo` keeps under a token.
struct Signer {
    key: Key,
    key_user: Option<String>,
    check_ocsp: bool,
}

/// The tokens of this instance, oldest first.
static SIGNERS: Mutex<Vec<(String, Signer)>> = Mutex::new(Vec::new());

/// Most tokens kept: each holds an open key and the core keeps at most 16 keys an
/// instance; the oldest goes first (the original keeps every token).
const MAX_SIGNERS: usize = 12;

fn handle(request: &Request) -> String {
    let options = InvokeOptions {
        bad_request: BadRequest::Drop,
    };
    match invoke_with(
        &request.text,
        &request.add_info(),
        &[&DevartNlClass],
        &options,
    ) {
        Reply::Text(text) => text,
        Reply::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

oncl_pdk::plugin!(handle);

/// The class `DevartNLClass`.
struct DevartNlClass;

const METHODS: &[NlMethod] = &[
    NlMethod {
        name: "getSignerInfo",
        annotation: None,
        params: 1,
    },
    NlMethod {
        name: "signDevart",
        annotation: None,
        params: 1,
    },
    NlMethod {
        name: "extractFromCms",
        annotation: None,
        params: 1,
    },
];

impl NlClass for DevartNlClass {
    fn class_name(&self) -> &'static str {
        "DevartNLClass"
    }

    fn methods(&self) -> &'static [NlMethod] {
        METHODS
    }

    fn call(&self, m: &NlMethod, args: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
        let args = args.expect("every method has a parameter");
        let outcome = match m.name {
            "getSignerInfo" => signer_info(args),
            "signDevart" => sign_devart(args),
            "extractFromCms" => extract(args),
            _ => unreachable!("only METHODS are called"),
        };
        match outcome {
            Ok(text) => Ok(JValue::Str(text)),
            Err(Exc {
                checked: false,
                escapes: false,
                message,
                ..
            }) => Ok(JValue::Str(error_body(
                message.as_deref().unwrap_or("null"),
            ))),
            Err(e) if e.escapes => Err(Failure::Invocation(Some(e.to_string()))),
            Err(e) => Err(Failure::Invocation(Some(format!(
                "java.lang.RuntimeException: {e}"
            )))),
        }
    }
}

/// A Java exception of the plugin.
#[derive(Debug)]
struct Exc {
    /// Its class.
    class: &'static str,
    /// `getMessage()`.
    message: Option<String>,
    /// A checked exception: the method wraps it in a `RuntimeException` that leaves it.
    checked: bool,
    /// It leaves the method as it is.
    escapes: bool,
}

impl Exc {
    /// A `RuntimeException` the method catches: its message becomes the body.
    fn runtime(message: impl Into<String>) -> Exc {
        Exc {
            class: "java.lang.RuntimeException",
            message: Some(message.into()),
            checked: false,
            escapes: false,
        }
    }

    /// A `NullPointerException`, caught: `Ошибка! null`.
    fn npe() -> Exc {
        Exc {
            class: "java.lang.NullPointerException",
            message: None,
            checked: false,
            escapes: false,
        }
    }

    /// A checked exception of `class`.
    fn checked(class: &'static str, message: impl Into<String>) -> Exc {
        Exc {
            class,
            message: Some(message.into()),
            checked: true,
            escapes: false,
        }
    }

    /// An exception that leaves the method as it is.
    fn escaping(class: &'static str, message: impl Into<String>) -> Exc {
        Exc {
            class,
            message: Some(message.into()),
            checked: false,
            escapes: true,
        }
    }

    /// The original's `createMessageFromException`: the texts of the key store and
    /// certificate errors it rewrites.
    fn rewritten(&self) -> String {
        let Some(message) = &self.message else {
            return "null".to_owned();
        };
        const EXPIRED: &str = "certificate expired on ";
        if let Some(at) = message.find(EXPIRED) {
            let date: String = message[at + EXPIRED.len()..].chars().take(8).collect();
            return format!("Ключ просрочен {date}");
        }
        match message.as_str() {
            "Malformed content." => "Не верный формат".to_owned(),
            "stream does not represent a PKCS12 key store" => {
                "Key reading error: Invalid format.".to_owned()
            }
            "PKCS12 key store mac invalid - wrong password or corrupted file." => {
                "Key reading error: Password incorrect.".to_owned()
            }
            "IOException reading content." => "Не удалось прочитать содержимое".to_owned(),
            _ => message.clone(),
        }
    }
}

impl std::fmt::Display for Exc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.message {
            Some(message) => write!(f, "{}: {message}", self.class),
            None => f.write_str(self.class),
        }
    }
}

/// An org.json reader's exception, caught by the method.
fn json(message: String) -> Exc {
    Exc {
        class: "org.json.JSONException",
        message: Some(message),
        checked: false,
        escapes: false,
    }
}

/// `{"errorCode":"Ошибка! <message>"}`.
fn error_body(message: &str) -> String {
    let mut body = JObject::hash_map();
    body.put("errorCode", format!("Ошибка! {message}"));
    body.to_json()
}

/// An item of `dataList`.
struct Item {
    data: String,
    file_name: String,
    data_type: String,
}

/// `dataList`, read strictly (`getJSONArray`, `getJSONObject`, `getString` of `data`,
/// `fileName`, `dataType`); `None` when absent.
fn data_list(args: &Map<String, Value>) -> Result<Option<Vec<Item>>, String> {
    if !args.contains_key("dataList") {
        return Ok(None);
    }
    let list = orgjson::get_array(args, "dataList")?;
    let mut items = Vec::new();
    for i in 0..list.len() {
        let item = orgjson::array_get_object(list, i)?;
        items.push(Item {
            data: orgjson::get_string(item, "data")?.to_owned(),
            file_name: orgjson::get_string(item, "fileName")?.to_owned(),
            data_type: orgjson::get_string(item, "dataType")?.to_owned(),
        });
    }
    Ok(Some(items))
}

/// `certificateKeyUser`, if present (`getString`).
fn key_user(args: &Map<String, Value>) -> Result<Option<String>, Exc> {
    if !args.contains_key("certificateKeyUser") {
        return Ok(None);
    }
    orgjson::get_string(args, "certificateKeyUser")
        .map(|s| Some(s.to_owned()))
        .map_err(json)
}

/// `getSignerInfo{dataList?, storageName, certificateKeyUser?, checkOcsp, checkCrl}`.
fn signer_info(args: &Map<String, Value>) -> Result<String, Exc> {
    data_list(args).map_err(json)?;
    let storage = orgjson::get_string(args, "storageName").map_err(json)?;
    let key_user = key_user(args)?;
    let check_ocsp = orgjson::get_boolean(args, "checkOcsp").map_err(json)?;
    orgjson::get_boolean(args, "checkCrl").map_err(json)?;
    if storage.trim().is_empty() {
        return Err(Exc::runtime("storageName.param.empty"));
    }
    if TOKEN_STORAGES.contains(&storage) {
        if keys::terminals(storage).unwrap_or_default().is_empty() {
            return Err(Exc::runtime("storage.empty"));
        }
    } else if !FILE_STORAGES.contains(&storage) {
        return Err(Exc::runtime("storage.unknown"));
    }
    let request = SelectArgs {
        action: Action::Sign,
        storages: vec![storage.to_owned()],
        // Signing keys only; expired ones listed but not signable; no checks before.
        filter: Filter {
            chain: Some(Vec::new()),
            allow_expired: false,
            allow_revoked: true,
            ..Filter::default()
        },
        more: FilterMore {
            knca_types: vec!["SIGNATURE".to_owned()],
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: Default::default(),
    };
    {
        // Room for the key the dialog opens.
        let mut signers = SIGNERS.lock().unwrap_or_else(|e| e.into_inner());
        let excess = (signers.len() + 1).saturating_sub(MAX_SIGNERS);
        signers.drain(..excess);
    }
    let key = keys::select(&request)
        .map_err(|e| Exc::runtime(e.message))?
        .ok_or_else(|| Exc::runtime("action.canceled"))?;
    let subject = Certificate::from_der(key.certificate())
        .ok()
        .and_then(|cert| cert.tbs_certificate().subject().to_der().ok())
        .ok_or_else(Exc::npe)?;
    let dn = x509text::sun_x500name(&subject).map_err(|_| Exc::npe())?;
    let now = host::now().unwrap_or_default();
    let token = base64(format!("{}{dn}", local_date_time(now)).as_bytes());

    let mut body = JObject::hash_map();
    body.put("userCertInfo", dn);
    body.put("token", token.clone());
    let mut signers = SIGNERS.lock().unwrap_or_else(|e| e.into_inner());
    signers.retain(|(t, _)| *t != token);
    signers.push((
        token,
        Signer {
            key,
            key_user,
            check_ocsp,
        },
    ));
    Ok(body.to_json())
}

/// Java's `LocalDateTime.now().toString()` at `unix_ms` in the system's zone:
/// `2026-10-29T12:03:04.512`, the seconds and milliseconds only when not zero.
fn local_date_time(unix_ms: i64) -> String {
    let offset = host::local_offset(unix_ms).unwrap_or(0);
    let mut text = format_java("yyyy-MM-dd'T'HH:mm", unix_ms, offset);
    let millis = unix_ms.rem_euclid(1000);
    let seconds = (unix_ms.div_euclid(1000) + i64::from(offset)).rem_euclid(60);
    if seconds != 0 || millis != 0 {
        text.push_str(&format!(":{seconds:02}"));
    }
    if millis != 0 {
        text.push_str(&format!(".{millis:03}"));
    }
    text
}

/// A certificate time as the provider's validity exceptions print it.
// Unverified against the original: the date text of Kalkan's validity exceptions.
fn provider_time(unix_ms: i64) -> String {
    let offset = host::local_offset(unix_ms).unwrap_or(0);
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.unsigned_abs();
    format!(
        "{}GMT{sign}{:02}:{:02}",
        format_java("yyyyMMddHHmmss", unix_ms, offset),
        abs / 3600,
        abs % 3600 / 60
    )
}

/// `checkValidity()` now.
fn check_validity(der: &[u8]) -> Result<(), Exc> {
    let info = host::cert_info(der).map_err(|_| Exc::npe())?;
    let now = host::now().unwrap_or_default();
    if now > info.not_after {
        return Err(Exc::checked(
            "java.security.cert.CertificateExpiredException",
            format!("certificate expired on {}", provider_time(info.not_after)),
        ));
    }
    if now < info.not_before {
        return Err(Exc::checked(
            "java.security.cert.CertificateNotYetValidException",
            format!(
                "certificate not valid till {}",
                provider_time(info.not_before)
            ),
        ));
    }
    Ok(())
}

/// The exception of a request to the OCSP responder that failed.
// Unverified against the original: the JDK's texts of network exceptions.
fn network_exception(failure: &NetFailure) -> Exc {
    match failure.kind {
        NetKind::UnknownHost => {
            Exc::checked("java.net.UnknownHostException", failure.address.clone())
        }
        NetKind::Timeout => Exc::checked("java.net.SocketTimeoutException", "Read timed out"),
        NetKind::Connect => {
            Exc::checked("java.net.ConnectException", "Connection refused: connect")
        }
        _ => Exc::checked("java.io.IOException", failure.detail.clone()),
    }
}

/// The original's OCSP check of `der`: SHA-1 `CertID` against the bundled CA of the same
/// signature algorithm, an 8-byte nonce, POST to the responder with the request in the path
/// and the body; the response's status only.
fn check_ocsp(der: &[u8]) -> Result<(), Exc> {
    let issuer = cas::issuer_for(der).ok_or_else(Exc::npe)?;
    let args = OcspArgs {
        cert: der.to_vec().into(),
        issuer: IssuerSel::Given(issuer.to_vec().into()),
        cert_id_hash: HashAlg::Sha1,
        nonce: Nonce::Random(8),
        url: PkiUrl::Default,
        method: PkiMethod::PostWithPath,
        timeout_ms: 60_000,
        check: false,
    };
    let outcome =
        pki::ocsp_fetch(&args).map_err(|e| Exc::checked("java.io.IOException", e.message))?;
    match outcome {
        OcspOutcome::Failed(failure) => Err(network_exception(&failure)),
        // Unverified against the original: the class of the responder-status exception.
        OcspOutcome::Ok {
            response_status, ..
        } if response_status != 0 => Err(Exc::checked(
            "kz.gov.pki.kalkan.ocsp.OCSPException",
            format!("Не удачный запрос на отозванность. Статус: {response_status}"),
        )),
        OcspOutcome::Ok {
            cert_status: Some(CertStatusAbi::Good),
            ..
        } => Ok(()),
        OcspOutcome::Ok {
            cert_status: Some(CertStatusAbi::Revoked { .. }),
            ..
        } => Err(Exc::checked(
            "kz.devart.bundle.exception.CertificateRevokationException",
            "Сертификат отозван",
        )),
        OcspOutcome::Ok { .. } => Err(Exc::runtime("Не опознанный ответ OCSP!")),
    }
}

/// The original's `validateCertificateKeyUser`: validity now, OCSP when asked, then the
/// key users.
fn validate(der: &[u8], check: bool, key_user: Option<&str>) -> Result<(), Exc> {
    check_validity(der)?;
    if check {
        check_ocsp(der)?;
    }
    let Some(list) = key_user.filter(|l| !l.is_empty()) else {
        return Ok(());
    };
    let cert = Certificate::from_der(der).map_err(|_| Exc::npe())?;
    let has_eku = cert
        .tbs_certificate()
        .extensions()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id.to_string() == EXT_KEY_USAGE));
    if !has_eku {
        return Err(Exc::npe());
    }
    let ekus = host::cert_info(der).map_err(|_| Exc::npe())?.ext_key_usages;
    let names: Vec<&str> = KEY_USERS
        .iter()
        .filter(|(_, oid)| ekus.iter().any(|e| e == oid))
        .map(|(name, _)| *name)
        .collect();
    let matched = list
        .split(',')
        .any(|wanted| names.iter().any(|name| name.eq_ignore_ascii_case(wanted)));
    if matched {
        Ok(())
    } else {
        Err(Exc::checked(
            "java.security.cert.CertificateException",
            format!("Не найден признак {list} в сертификате!"),
        ))
    }
}

/// `signDevart{token, dataList?, certificateKeyUser?}`.
fn sign_devart(args: &Map<String, Value>) -> Result<String, Exc> {
    let token = orgjson::get_string(args, "token").map_err(json)?;
    let items = data_list(args).map_err(json)?.unwrap_or_default();
    let signers = SIGNERS.lock().unwrap_or_else(|e| e.into_inner());
    let signer = signers
        .iter()
        .find(|(t, _)| t == token)
        .map(|(_, s)| s)
        .ok_or_else(Exc::npe)?;
    let key_user = match key_user(args)? {
        Some(list) => Some(list),
        None => signer.key_user.clone(),
    };
    let key = &signer.key;
    validate(key.certificate(), signer.check_ocsp, key_user.as_deref())?;

    let mut groups = Vec::new();
    for kind in ["ESF", "XML", "CMS"] {
        let of_kind: Vec<&Item> = items
            .iter()
            .filter(|item| item.data_type.to_uppercase() == kind)
            .collect();
        if of_kind.is_empty() {
            continue;
        }
        let group = match kind {
            "ESF" => esf(key, &of_kind),
            "XML" => xml(key, &of_kind),
            _ => cms_group(key, &of_kind, signer.check_ocsp),
        };
        let json = match group {
            Ok(array) => JValue::from(array).to_json(),
            Err(message) => error_body(&message),
        };
        groups.push(format!("\"{kind}\": {json}"));
    }
    Ok(format!(
        "{{ \"signedResult\" : {{{}}} }}",
        groups.join(", ")
    ))
}

/// The `\r`-less text of an item's base64 data.
fn item_text(item: &Item) -> Result<String, String> {
    let bytes = javab64::decode_java(&item.data)?;
    Ok(String::from_utf8_lossy(&bytes).replace('\r', ""))
}

/// A signed item: `fileName`, `signature`, `signedData`, `certificate`, `message`, `status`.
fn signed_item(item: &Item, signature: String, data: String, certificate: String) -> JValue {
    let mut bean = JObject::hash_map();
    bean.put("fileName", item.file_name.clone());
    bean.put("signature", signature);
    bean.put("signedData", data);
    bean.put("certificate", certificate);
    bean.put("message", "OK");
    bean.put("status", 200);
    bean.into()
}

/// The ESF group: a raw signature of each text, with the chosen key.
fn esf(key: &Key, items: &[&Item]) -> Result<Vec<JValue>, String> {
    // Unverified against the original: the text for a sha1RSA certificate, which the
    // core does not sign with.
    if host::cert_details(key.certificate())
        .is_ok_and(|d| d.signing_alg.as_deref() == Some("rsa_sha1"))
    {
        return Err("SHA1withRSA is not supported".to_owned());
    }
    items
        .iter()
        .map(|item| {
            let text = item_text(item)?;
            let signature = key.sign_raw(text.as_bytes()).map_err(|e| e.message)?;
            Ok(signed_item(
                item,
                base64(&signature),
                text,
                base64(key.certificate()),
            ))
        })
        .collect()
}

/// The XML group: each document with an enveloped signature, `signature` and `certificate`
/// the text `null`.
fn xml(key: &Key, items: &[&Item]) -> Result<Vec<JValue>, String> {
    items
        .iter()
        .map(|item| {
            let text = item_text(item)?;
            let signed = key
                .sign_xml(text.as_bytes(), None, None)
                .map_err(|e| e.message)?;
            Ok(signed_item(
                item,
                "null".to_owned(),
                String::from_utf8_lossy(&signed).into_owned(),
                "null".to_owned(),
            ))
        })
        .collect()
}

/// The signature algorithm OID of the certificate `der`.
fn sig_alg(der: &[u8]) -> Option<String> {
    Certificate::from_der(der)
        .ok()
        .map(|cert| cert.signature_algorithm().oid.to_string())
}

/// The TSA policy chosen by the first certificate's signature algorithm.
fn tsa_policy(alg: &str) -> &'static str {
    match alg {
        "1.2.840.113549.1.1.11" => "1.2.398.3.3.2.6.2",
        "1.2.398.3.10.1.1.1.2" => "1.2.398.3.3.2.6.1",
        a if a.starts_with("1.2.398.3.10.1.1.2.3") => "1.2.398.3.3.2.6.4",
        _ => "1.2.398.3.3.2.6.3",
    }
}

/// The imprint's hash by a signer certificate's signature algorithm.
fn imprint_hash(alg: Option<&str>) -> HashAlg {
    match alg {
        Some("1.2.840.113549.1.1.5") => HashAlg::Sha1,
        Some("1.2.840.113549.1.1.11") => HashAlg::Sha256,
        _ => HashAlg::Gost34311,
    }
}

/// The CMS group: each item signed (co-signed if it is a CMS), every signer without a
/// time-stamp stamped, then every signer certificate checked.
fn cms_group(key: &Key, items: &[&Item], check: bool) -> Result<Vec<JValue>, String> {
    let mut signed = Vec::new();
    for item in items {
        let data = javab64::decode_java(&item.data)?;
        let old = cms_read::signers(&data);
        let (content, cosign, first_cert) = if old.is_empty() {
            (data, CoSign::Never, key.certificate().to_vec())
        } else {
            let content = cms_read::content(&data).ok_or("null")?;
            let first = old[0]
                .sid_cert
                .clone()
                .unwrap_or_else(|| key.certificate().to_vec());
            (content, CoSign::Into(data.into()), first)
        };
        let args = SignCmsExArgs {
            handle: key.handle(),
            content: CmsContent::Data(content.into()),
            encapsulate: true,
            cosign,
            econtent_type: None,
            digest: None,
            attrs: SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: false,
                signing_time: Some(SigningTime {
                    at: TimeSource::Now,
                    form: TimeForm::Auto,
                }),
                extra: Vec::new(),
            },
            certificates: CmsCerts::Signer,
            timestamp: None,
        };
        let cms = match key.sign_cms_ex(args).map_err(|e| e.message)? {
            CmsOutcome::Signed(cms) => cms.into_vec(),
            CmsOutcome::TspFailed(failure) => return Err(failure.detail),
        };
        let policy = tsa_policy(&sig_alg(&first_cert).unwrap_or_default());
        signed.push((item, stamp_unstamped(cms, policy)?));
    }
    for (_, cms) in &signed {
        for signer in cms_read::signers(cms) {
            let cert = signer.sid_cert.ok_or("null")?;
            check_validity(&cert)
                .and_then(|()| if check { check_ocsp(&cert) } else { Ok(()) })
                .map_err(|e| e.rewritten())?;
        }
    }
    Ok(signed
        .into_iter()
        .map(|(item, cms)| {
            let mut bean = JObject::hash_map();
            bean.put("fileName", item.file_name.clone());
            bean.put("cms", base64(&cms));
            bean.put("message", "OK");
            bean.put("status", 200);
            bean.into()
        })
        .collect())
}

/// `cms` with a time-stamp on every signer that has none: POST to the default TSA,
/// `policy`, the imprint hashed by the signer's certificate, the time as the nonce, 10
/// attempts.
fn stamp_unstamped(mut cms: Vec<u8>, policy: &str) -> Result<Vec<u8>, String> {
    let signers = cms_read::signers(&cms);
    for (index, signer) in signers.iter().enumerate() {
        let stamped = signer.unsigned_attrs.as_ref().is_some_and(|attrs| {
            attrs
                .windows(TIME_STAMP_OID.len())
                .any(|w| w == TIME_STAMP_OID)
        });
        if stamped {
            continue;
        }
        let alg = signer.sid_cert.as_deref().and_then(sig_alg);
        let nonce = host::now().unwrap_or_default().to_be_bytes();
        let start = nonce.iter().take_while(|b| **b == 0).count();
        let tsa = TsaSpec {
            url: PkiUrl::Fixed("http://tsp.pki.gov.kz/".to_owned()),
            method: PkiMethod::Post {
                content_type: Some("application/timestamp-query".to_owned()),
            },
            hash: imprint_hash(alg.as_deref()),
            policy: Some(policy.to_owned()),
            nonce: Nonce::Value(nonce[start..].to_vec().into()),
            cert_req: true,
            retries: 9,
            timeout_ms: 60_000,
            check_skew_ms: None,
            require_tsa_eku: false,
        };
        let args = StampArgs {
            cms: cms.clone().into(),
            signers: SignerSel::Index(u32::try_from(index).unwrap_or(u32::MAX)),
            tsa: TsaChoice::Custom(tsa),
            mode: StampMode::Append,
            token: TokenForm::Token,
        };
        cms = match pki::stamp(&args) {
            Ok(StampOutcome::Stamped(stamped)) => stamped.into_vec(),
            _ => return Err("TSP creation failure".to_owned()),
        };
    }
    Ok(cms)
}

/// `extractFromCms{dataList}`: the content of each CMS.
fn extract(args: &Map<String, Value>) -> Result<String, Exc> {
    let escaping_json = |e: String| Exc::escaping("org.json.JSONException", e);
    let list = orgjson::get_array(args, "dataList").map_err(escaping_json)?;
    let mut out = Vec::new();
    for i in 0..list.len() {
        let item = orgjson::array_get_object(list, i).map_err(escaping_json)?;
        let data = orgjson::get_string(item, "data").map_err(escaping_json)?;
        let file_name = orgjson::get_string(item, "fileName").map_err(escaping_json)?;
        let data_type = orgjson::get_string(item, "dataType").map_err(escaping_json)?;
        let cms = javab64::decode_java(data)
            .map_err(|e| Exc::escaping("java.lang.IllegalArgumentException", e))?;
        if cms_read::signers(&cms).is_empty() {
            return Err(Exc::runtime("Не верный формат"));
        }
        let content = cms_read::content(&cms).ok_or_else(|| {
            Exc::escaping(
                "java.lang.RuntimeException",
                "CMS doesn't have signed content",
            )
        })?;
        let mut bean = JObject::hash_map();
        bean.put("fileName", file_name);
        bean.put("data", base64(&content));
        bean.put("dataType", data_type);
        out.push(JValue::from(bean));
    }
    Ok(JValue::from(out).to_json())
}

/// Standard base64, padded, on one line.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
