//! The OpenNCALayer port of `org.skf.osgi.SKFModule` 1.6.2, SK-Pharmacy's module for
//! portal.efis.kz: token and key file choosers, the key of a page-named key store checked
//! against the portal's CA list and the NCA's OCSP (`getKeys`), and XAdES-BASELINE-LT
//! signatures of the portal's documents (`signXades`).
//!
//! - Requests are `{"method", "args": [...]}`; `args` is required for every method, its
//!   elements read as their `toString()`. Replies are `new JSONObject(HashMap<String,
//!   String>)`: `null` values left out, keys in Java's `HashMap` order.
//! - Any failure is the message of the deepest cause of the original's exception, under
//!   `errorCode`, with its four translations (an expired certificate, a revoked one, a
//!   clock in the future); an exception without a message (`NullPointerException`) is `{}`.
//! - The key of `getKeys` stays in the session for `signXades` (the original's, in the
//!   process for every page); the portal's CA list is downloaded once per session.
//! - Not ported: the original's trust-all TLS for the whole JVM, its OCSP allowed-period
//!   system property, temporary files.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use oncl_pdk::abi::{
    ChooseFileArgs, FileFilter, FileMode, Header, HostError, HttpExArgs, MAX_PKI_TIMEOUT_MS,
    MessageKind, Method,
};
use oncl_pdk::dialogs::{self, ChoiceArgs};
use oncl_pdk::host::HashAlg;
use oncl_pdk::javaexc::Throwable;
use oncl_pdk::keys::{self, Key, KeySource, OpenArgs, OpenOutcome, Password, XadesArgs};
use oncl_pdk::keys::{XadesLevel, XadesOutcome};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{
    self, CertStatusAbi, IssuerSel, NetFailure, NetKind, Nonce, OcspArgs, OcspOutcome, PkiMethod,
    PkiUrl, Problem, TsaChoice, TsaSpec,
};
use oncl_pdk::{Request, files, host, http};
use oncl_port_kit::date::format_java;
use oncl_port_kit::url::resolve_like_java_url;
use oncl_port_pki::{jks, x509text};
use std::cell::RefCell;
use x509_cert::Certificate;

/// The original's version.
const VERSION: &str = "1.6.2";

/// The portal's CA list: a JKS of trusted certificates.
const CACERTS: &str = "https://portal.efis.kz/pub/cacerts_v2";
/// Its password.
const CACERTS_PASSWORD: &str = "changeit";
/// The portal's document template.
const TEMPLATE: &str = "https://portal.efis.kz/pub/template.xml";

/// Serial numbers (hex) of the NCA's CAs the original takes for OCSP issuers.
const OCSP_ISSUERS: [&str; 3] = [
    "3576f5b31b5a6821a16fefab1212c94d938dc7ee",
    "46170a97a64bbaf7643c87d90c0fe24071595a8d",
    "7e30be9fc890633f1fff5a3c0cb0c85f4c6d1708",
];

/// Extended key usages of the right to sign for an organisation: first head, authorised
/// signer, financial signer.
const SIGN_RIGHTS: [&str; 3] = [
    "1.2.398.3.3.4.1.2.1",
    "1.2.398.3.3.4.1.2.2",
    "1.2.398.3.3.4.1.2.3",
];

/// Kalkan's storages (`kz.gov.pki.kalkan.Storage`): the key files, then the tokens with the
/// names the original's token chooser shows.
const FILE_STORAGES: [&str; 2] = ["PKCS12", "JKS"];
const TOKEN_STORAGES: [(&str, &str); 6] = [
    ("AKKaztokenStore", "Kaztoken"),
    ("AKKZIDCardStore", "Удостоверение личности"),
    ("AKEToken72KStore", "eToken 72K (Java)"),
    ("AKEToken5110Store", "eToken 5110"),
    ("AKJaCartaStore", "JaCarta"),
    ("AKAKEYStore", "AKEY"),
];

/// The first line of a document the original signs as it is.
const XML_DECLARATION: &str = r#"<?xml version="1.0" encoding="UTF-8""#;

/// The module's state in a session.
struct Skf {
    /// The key of the last successful `getKeys`.
    key: RefCell<Option<Key>>,
    /// The portal's CA certificates (DER), once downloaded.
    cas: RefCell<Option<Vec<Vec<u8>>>>,
}

thread_local! {
    static STATE: Skf = const {
        Skf {
            key: RefCell::new(None),
            cas: RefCell::new(None),
        }
    };
}

/// Why a call fails.
enum Fail {
    /// An exception, its causes chained.
    Thrown(Throwable),
    /// The original's own `CertificateRevokationException`.
    Revoked,
}

impl From<Throwable> for Fail {
    fn from(thrown: Throwable) -> Fail {
        Fail::Thrown(thrown)
    }
}

/// The reply's entries, in the order the original puts them; `None` is a `null`.
type Entries = Vec<(&'static str, Option<String>)>;

fn handle(request: &Request) -> String {
    STATE.with(|state| match call(state, &request.text) {
        Ok(entries) => reply(&entries),
        Err(fail) => reply(&[("errorCode", error_code(fail))]),
    })
}

oncl_pdk::plugin!(handle);

/// `new JSONObject(map)` of a `HashMap` filled with `entries`: a map of as many buckets as
/// it has entries (`null` ones too), filled in the first map's order without the `null`s.
fn reply(entries: &[(&str, Option<String>)]) -> String {
    let mut map = JObject::hash_map();
    for (key, value) in entries {
        map.put(*key, value.clone().map_or(JValue::Null, JValue::Str));
    }
    let mut object = JObject::from_map(entries.len());
    for (key, value) in map.iter() {
        if *value != JValue::Null {
            object.put(key, value.clone());
        }
    }
    object.to_json()
}

/// The message of `fail`, as the original makes it of the deepest cause.
fn error_code(fail: Fail) -> Option<String> {
    let thrown = match fail {
        Fail::Revoked => return Some("Сертификат отозван".to_owned()),
        Fail::Thrown(thrown) => thrown,
    };
    let root = thrown.deepest();
    let text = root.to_string();
    if let Some(at) = text.find("certificate expired on ") {
        let date = &text[at + "certificate expired on ".len()..];
        return Some(match expiry(date) {
            Some(text) => format!("Сертификат просрочен в {text}"),
            None => format!("Ошибка {text}"),
        });
    }
    if text.contains("Revoked certificate detected") || text.contains("STATUS_REVOKED") {
        return Some("Сертификат отозван!".to_owned());
    }
    if text.contains("Validation time is in future") {
        return Some(
            "Пожалуйста, исправьте время на компьютере. Рекомендуется использовать \
             синхронизацию времени с сервера kz.pool.ntp.org."
                .to_owned(),
        );
    }
    root.message.clone()
}

/// `yyyyMMddHHmmss'GMT'z` of `text` (BouncyCastle's time of an expired certificate,
/// `20251231235959GMT+00:00`) as `dd.MM.yyyy HH:mm:ss` in the system's zone.
fn expiry(text: &str) -> Option<String> {
    let digits = text.get(..14)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let zone = text.get(14..)?.strip_prefix("GMT")?;
    let sign = match zone.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hours, minutes) = zone.get(1..)?.split_once(':')?;
    let offset =
        sign * (hours.parse::<i64>().ok()? * 3600 + minutes.get(..2)?.parse::<i64>().ok()? * 60);
    let field = |range: std::ops::Range<usize>| digits[range].parse::<i64>().ok();
    let days = days_from_civil(field(0..4)?, field(4..6)?, field(6..8)?);
    let seconds =
        days * 86_400 + field(8..10)? * 3600 + field(10..12)? * 60 + field(12..14)? - offset;
    let ms = seconds * 1000;
    Some(format_java(
        "dd.MM.yyyy HH:mm:ss",
        ms,
        host::local_offset(ms).unwrap_or(0),
    ))
}

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// BouncyCastle's `Time.getTime()` of `unix_ms`: `yyyyMMddHHmmssGMT+00:00`.
fn bc_time(unix_ms: i64) -> String {
    format!("{}GMT+00:00", format_java("yyyyMMddHHmmss", unix_ms, 0))
}

fn exception(class: &str, message: impl Into<String>) -> Fail {
    Fail::Thrown(Throwable::new(class, Some(message.into())))
}

fn npe() -> Fail {
    Fail::Thrown(Throwable::npe())
}

fn call(state: &Skf, text: &str) -> Result<Entries, Fail> {
    let JValue::Obj(request) = orgjson::parse(text).map_err(Throwable::json)? else {
        unreachable!("org.json reads an object");
    };
    let request = request.to_map();
    let method = orgjson::get_string(&request, "method")
        .map_err(Throwable::json)?
        .to_owned();
    let args = orgjson::get_array(&request, "args").map_err(Throwable::json)?;
    let arg = |i: usize| -> Result<String, Fail> {
        args.get(i)
            .map(orgjson::value_to_string)
            .ok_or_else(|| Throwable::json(format!("JSONArray[{i}] not found.")).into())
    };
    let none = || Some("NONE".to_owned());
    match method.as_str() {
        "getBundleVersion" => Ok(vec![
            ("errorCode", none()),
            ("version", Some(VERSION.to_owned())),
        ]),
        "myLoadSlotList" => {
            let terminal = load_slot_list(&arg(0)?)?;
            Ok(vec![("result", Some(terminal)), ("errorCode", none())])
        }
        "myBrowseKeyStore" => {
            let (storage, directory) = (arg(0)?, arg(2)?);
            let path = browse(&storage, &directory)?;
            Ok(vec![("result", path), ("errorCode", none())])
        }
        "getKeys" => {
            let (storage, path, password, can_sign) = (arg(0)?, arg(1)?, arg(2)?, arg(3)?);
            let line = get_keys(state, &storage, &path, &password, &can_sign)?;
            Ok(vec![("result", Some(line)), ("errorCode", none())])
        }
        "signXades" => {
            // `canSign` is read first, and not used.
            let (_, doc_number, url, mime, session) = (arg(0)?, arg(1)?, arg(2)?, arg(3)?, arg(4)?);
            let signed = sign_xades(state, &doc_number, &url, &mime, &session)?;
            Ok(vec![
                ("result", Some(signed)),
                ("docNum", Some(doc_number)),
                ("errorCode", none()),
            ])
        }
        other => Ok(vec![(
            "errorCode",
            Some(format!("метод {other} не найден. ")),
        )]),
    }
}

/// The applet's exception of `code` (its message is the code).
fn applet(code: &str) -> Fail {
    exception("kz.gov.pki.knca.applet.exception.AppletException", code)
}

/// The token chooser: a reader of the token storage `storage`.
fn load_slot_list(storage: &str) -> Result<String, Fail> {
    let shown = TOKEN_STORAGES
        .iter()
        .find(|(name, _)| *name == storage)
        .map_or(storage, |(_, shown)| shown);
    let title = Some("Выбор хранилища ключа".to_owned());
    loop {
        let mut readers =
            keys::terminals(storage).map_err(|_| applet("COMMON_CHOOSE_TOKEN_ERROR"))?;
        if readers.is_empty() {
            // Nothing found: «Обновить» looks again.
            let pressed = dialogs::choice(&ChoiceArgs {
                kind: MessageKind::Warning,
                title: title.clone(),
                text: format!(
                    "Тип хранилища: {shown}\nЗащищенный носитель не обнаружен. Убедитесь, что \
                     носитель подключен и нажмите кнопку \"Обновить\""
                ),
                buttons: vec!["Обновить".to_owned(), "Отмена".to_owned()],
                default: 0,
                options: Vec::new(),
            })
            .map_err(|_| applet("COMMON_CHOOSE_TOKEN_ERROR"))?;
            if pressed == Some(0) {
                continue;
            }
            return Err(applet("TOKEN_CHOOSE_CANCEL"));
        }
        readers.truncate(oncl_pdk::abi::MAX_CHOICE_OPTIONS);
        let picked = dialogs::choice(&ChoiceArgs {
            kind: MessageKind::Info,
            title,
            text: format!("Тип хранилища: {shown}\nПуть к хранилищу:"),
            buttons: vec!["Выбрать".to_owned(), "Отмена".to_owned()],
            default: 0,
            options: readers.clone(),
        })
        .map_err(|_| applet("COMMON_CHOOSE_TOKEN_ERROR"))?;
        return match picked {
            Some(i) => Ok(readers.swap_remove(usize::from(i))),
            None => Err(applet("TOKEN_CHOOSE_CANCEL")),
        };
    }
}

/// The file chooser «Открыть файл» from `directory`: the path of the file chosen.
fn browse(storage: &str, directory: &str) -> Result<Option<String>, Fail> {
    let known =
        FILE_STORAGES.contains(&storage) || TOKEN_STORAGES.iter().any(|(name, _)| *name == storage);
    if !known {
        return Err(exception(
            "java.lang.IllegalArgumentException",
            format!("No enum constant kz.gov.pki.kalkan.Storage.{storage}"),
        ));
    }
    let filter = |extension: &str| FileFilter {
        name: format!("*.{extension}"),
        extensions: vec![extension.to_owned()],
    };
    let filters = match storage {
        "PKCS12" => vec![filter("p12")],
        "JKS" => vec![filter("jks")],
        _ => Vec::new(),
    };
    let chosen = files::choose(&ChooseFileArgs {
        mode: FileMode::Open,
        title: Some("Открыть файл".to_owned()),
        filters,
        initial_dir: (!directory.is_empty()).then(|| directory.to_owned()),
    })
    .map_err(|e| host_failure(&e))?;
    Ok(chosen.map(|chosen| chosen.path))
}

/// A host function's refusal, as an exception of its message.
fn host_failure(error: &HostError) -> Fail {
    exception("java.lang.RuntimeException", error.message.clone())
}

/// The original's exception of a key store that does not open.
// Unverified against the original: the texts of a missing or unreadable file (Kalkan's
// exception chain); a file the user does not let the page open, and a token missing, have
// no original.
fn open_failure(outcome: OpenOutcome, path: &str) -> Fail {
    let provider = "kz.gov.pki.provider.exception.ProviderUtilException";
    match outcome {
        OpenOutcome::WrongPassword { .. } => exception(provider, "Неверный пароль."),
        OpenOutcome::Blocked => exception(provider, "Пароль заблокирован."),
        OpenOutcome::NotFound => exception(
            "java.io.FileNotFoundException",
            format!("{path} (No such file or directory)"),
        ),
        OpenOutcome::Corrupt => exception(provider, "Не удалось открыть хранилище ключей."),
        OpenOutcome::NoDevice => exception(provider, "Защищенный носитель не обнаружен."),
        OpenOutcome::Declined => exception(provider, "Открытие файла ключа не разрешено."),
        // No key with a certificate: the original's NullPointerException.
        OpenOutcome::NoKeys | OpenOutcome::Opened(_) => npe(),
    }
}

/// The certificates of the portal's CA list, downloaded once per session.
fn cas(state: &Skf) -> Result<Vec<Vec<u8>>, Fail> {
    if let Some(cas) = state.cas.borrow().as_ref() {
        return Ok(cas.clone());
    }
    let store = download(CACERTS, None)?;
    let cas = jks::jks_certs(&store, CACERTS_PASSWORD).map_err(|message| {
        // A store cut short: an EOFException, without a message.
        Fail::Thrown(Throwable::new(
            "java.io.IOException",
            (!message.is_empty()).then_some(message),
        ))
    })?;
    *state.cas.borrow_mut() = Some(cas.clone());
    Ok(cas)
}

/// BigInteger's `toString(16)` of a serial number's bytes.
fn serial_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    match hex.trim_start_matches('0') {
        "" => "0".to_owned(),
        trimmed => trimmed.to_owned(),
    }
}

/// The OCSP issuer of `cert` among `cas`: the first of the NCA CAs the original knows with
/// the certificate's signature algorithm.
fn ocsp_issuer<'c>(cert: &Certificate, cas: &'c [Vec<u8>]) -> Option<&'c [u8]> {
    cas.iter()
        .find(|der| {
            Certificate::from_der(der).is_ok_and(|ca| {
                ca.signature_algorithm().oid == cert.signature_algorithm().oid
                    && OCSP_ISSUERS.contains(
                        &serial_hex(ca.tbs_certificate().serial_number().as_bytes()).as_str(),
                    )
            })
        })
        .map(Vec::as_slice)
}

/// Java's exception of a request that failed.
fn net_exception(failure: &NetFailure) -> Fail {
    Fail::Thrown(match failure.kind {
        NetKind::UnknownHost => Throwable::unknown_host(failure.address.clone()),
        NetKind::Connect => Throwable::connect_refused(),
        NetKind::Timeout => Throwable::socket_timeout(true),
        NetKind::Http(status) => Throwable::new(
            "java.io.IOException",
            Some(format!(
                "Server returned HTTP response code: {status} for URL: {}",
                failure.address
            )),
        ),
        _ => Throwable::new("java.io.IOException", Some(failure.detail.clone())),
    })
}

/// The OCSP status of `cert` as the original asks it: SHA-1 CertID, an 8-byte nonce
/// (not compared), the request both in the URL and as the POST body.
fn ocsp(cert: &[u8], issuer: &[u8]) -> Result<(), Fail> {
    let outcome = pki::ocsp_fetch(&OcspArgs {
        cert: cert.to_vec().into(),
        issuer: IssuerSel::Given(issuer.to_vec().into()),
        cert_id_hash: HashAlg::Sha1,
        nonce: Nonce::Random(8),
        url: PkiUrl::FromCert(cert.to_vec().into()),
        method: PkiMethod::PostWithPath,
        timeout_ms: MAX_PKI_TIMEOUT_MS,
        check: false,
    })
    // No responder named in the certificate, or one off the PKI hosts.
    .map_err(|e| host_failure(&e))?;
    let verify = "org.skf.osgi.utils.OCSPVerifyException";
    match outcome {
        OcspOutcome::Failed(failure) => Err(net_exception(&failure)),
        OcspOutcome::Ok {
            response_status, ..
        } if response_status != 0 => Err(exception(
            verify,
            format!("Не удачный запрос на отозванность. Статус: {response_status}"),
        )),
        OcspOutcome::Ok { cert_status, .. } => match cert_status {
            Some(CertStatusAbi::Good) => Ok(()),
            Some(CertStatusAbi::Revoked {
                reason: Some(_), ..
            }) => Err(Fail::Revoked),
            // Unverified against the original: the text of a revocation without a reason.
            Some(CertStatusAbi::Revoked { reason: None, .. }) => Err(exception(
                verify,
                "Ошибка валидации OCSP. Сертификат отозван.",
            )),
            _ => Err(exception(verify, "Не опознанный ответ OCSP!")),
        },
    }
}

/// `dd.MM.YYYY` (the week year) of `unix_ms` in the system's zone.
fn week_date(unix_ms: i64) -> String {
    format_java(
        "dd.MM.YYYY",
        unix_ms,
        host::local_offset(unix_ms).unwrap_or(0),
    )
}

/// `getKeys`: the first key of the store, checked, kept for `signXades`; its line.
fn get_keys(
    state: &Skf,
    storage: &str,
    path: &str,
    password: &str,
    can_sign: &str,
) -> Result<String, Fail> {
    // Kalkan's `Storage.get` of an unknown name: a NullPointerException.
    let source = if FILE_STORAGES.contains(&storage) {
        KeySource::PagePath(path.to_owned())
    } else if TOKEN_STORAGES.iter().any(|(name, _)| *name == storage) {
        KeySource::Terminal(path.to_owned())
    } else {
        return Err(npe());
    };
    let opened = keys::open(&OpenArgs {
        storage: storage.to_owned(),
        source,
        password: Password::Text(password.to_owned()),
    })
    .map_err(|e| host_failure(&e))?;
    let key = opened
        .map_err(|outcome| open_failure(outcome, path))?
        .into_iter()
        .next()
        .ok_or_else(npe)?;
    let cas = cas(state)?;
    let der = key.certificate();
    let cert = Certificate::from_der(der).map_err(|_| npe())?;
    let tbs = cert.tbs_certificate();

    // (1) OCSP, then the path to the CA list.
    let issuer = ocsp_issuer(&cert, &cas).ok_or_else(npe)?;
    ocsp(der, issuer)?;
    // Unverified against the original: its PKIX check of the path to the CA list. The
    // OCSP issuer is one of the list's CAs and its responder knows the certificate; what
    // the path check adds is the validity, below.
    // (2) The validity now, in BouncyCastle's words.
    let now = host::now().map_err(|e| host_failure(&e))?;
    let ms = |t: &x509_cert::time::Time| t.to_unix_duration().as_millis() as i64;
    let (not_before, not_after) = (
        ms(&tbs.validity().not_before),
        ms(&tbs.validity().not_after),
    );
    let invalid = "java.security.cert.CertificateExpiredException";
    if now > not_after {
        return Err(exception(
            invalid,
            format!("certificate expired on {}", bc_time(not_after)),
        ));
    }
    if now < not_before {
        return Err(exception(
            "java.security.cert.CertificateNotYetValidException",
            format!("certificate not valid till {}", bc_time(not_before)),
        ));
    }
    // (3) A signing key.
    let details = host::cert_details(der).map_err(|e| host_failure(&e))?;
    let certificate = "org.skf.osgi.utils.SkfCertificateException";
    if !details.knca_types.iter().any(|t| t == "SIGNATURE") {
        return Err(exception(
            certificate,
            "Ошибка сертификата. ЭЦП не предназначена для подписи.",
        ));
    }
    // (4) `canSign` "0": the right to sign for an organisation.
    let ekus: Vec<String> = tbs
        .get_extension::<x509_cert::ext::pkix::ExtendedKeyUsage>()
        .ok()
        .flatten()
        .map(|(_, usages)| usages.0.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    if can_sign == "0" && !ekus.iter().any(|eku| SIGN_RIGHTS.contains(&eku.as_str())) {
        return Err(exception(
            certificate,
            "Ошибка сертификата. Признак \"Права подписи\" не найден.",
        ));
    }

    // The subject's properties, walking its RDNs as `LdapName` does.
    let dn = &details.subject_dn;
    let property = |kind: &str| x509text::ldap_first(dn, kind).unwrap_or_default();
    let algorithm = cert.signature_algorithm().oid.to_string();
    let line = [
        x509text::kalkan_sig_alg_name(&algorithm).map_or(algorithm.clone(), str::to_owned),
        // `CN`, a space and `G` (empty when absent): the original's FIO.
        format!("{} {}", property("CN"), property("G")),
        serial_hex(tbs.serial_number().as_bytes()),
        key.alias().to_owned(),
        property("SERIALNUMBER").replace("IIN", ""),
        property("E"),
        can_sign.to_owned(),
        week_date(not_before),
        week_date(not_after),
        property("OU").replace("BIN", ""),
        property("O"),
        property("S"),
        property("L"),
        property("C"),
    ]
    .join("|");
    // Unverified against the original: whether a key failing the checks still replaces
    // the one kept.
    *state.key.borrow_mut() = Some(key);
    Ok(line)
}

/// `url` downloaded (a session cookie if any).
fn download(url: &str, session: Option<&str>) -> Result<Vec<u8>, Fail> {
    let url = resolve_like_java_url(url, url)
        .map_err(|message| exception("java.net.MalformedURLException", message))?;
    let headers = session
        .map(|session| {
            vec![Header {
                name: "Cookie".to_owned(),
                value: format!("JSESSIONID={session}"),
            }]
        })
        .unwrap_or_default();
    let response = http::request_ex(&HttpExArgs {
        method: Method::Get,
        url: url.clone(),
        relative_to_origin: false,
        headers,
        content_type: None,
        body: Vec::new().into(),
        timeout_ms: None,
    })
    // Off the page's origin and the portal: not loaded.
    .map_err(|_| {
        exception(
            "java.io.IOException",
            format!("Загрузка с адреса не разрешена: {url}"),
        )
    })?;
    if response.status >= 400 {
        return Err(exception(
            "java.io.IOException",
            format!(
                "Server returned HTTP response code: {} for URL: {url}",
                response.status
            ),
        ));
    }
    Ok(response.body.into_vec())
}

/// Santuario's `Base64.encode`: lines of 76 characters joined by `\n`.
fn base64_lines(data: &[u8]) -> String {
    let text = STANDARD.encode(data);
    text.as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `SignatureMethod` and `DigestMethod` of a certificate's signature algorithm, as the
/// original's DSS chooses them; `None` for DSS's defaults (RSA, SHA-256).
fn xades_methods(algorithm: &str) -> (Option<String>, Option<String>) {
    let pair =
        |signature: &str, digest: &str| (Some(signature.to_owned()), Some(digest.to_owned()));
    if algorithm.contains("1.2.398.3.10.1.1.1.2") {
        pair(
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        )
    } else if algorithm.contains("1.2.398.3.10.1.1.2.3") {
        pair(
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        )
    } else {
        (None, None)
    }
}

/// `signXades`: the document of `url` (or the portal's template around it), signed
/// XAdES-BASELINE-LT enveloped with the key of `getKeys`, then checked.
fn sign_xades(
    state: &Skf,
    doc_number: &str,
    url: &str,
    mime: &str,
    session: &str,
) -> Result<String, Fail> {
    let key = state.key.borrow();
    let key = key.as_ref().ok_or_else(npe)?;
    let cas = cas(state)?;
    let document = download(url, Some(session))?;
    let first_line = document
        .split(|b| *b == b'\n' || *b == b'\r')
        .next()
        .unwrap_or_default();
    let xml = if String::from_utf8_lossy(first_line).contains(XML_DECLARATION) {
        // A document prepared (or signed) before: signed again as it is.
        document
    } else {
        let template = download(TEMPLATE, None)?;
        String::from_utf8_lossy(&template)
            .replace("[BUNDLE_VERSION]", VERSION)
            .replace("[DOC_NUMBER]", doc_number)
            // [P10] Santuario's line breaks in the content.
            .replace("[BASE64_CONTENT]", &base64_lines(&document))
            .replace("[MIMETYPE]", mime)
            .into_bytes()
    };
    let cert = Certificate::from_der(key.certificate()).map_err(|_| npe())?;
    let (signature_method, digest_method) =
        xades_methods(&cert.signature_algorithm().oid.to_string());
    let outcome = key
        .sign_xades(XadesArgs {
            handle: key.handle(),
            xml: xml.into(),
            level: XadesLevel::Lt,
            // DSS's online TSA: the NCA's, no policy asked, SHA-256.
            tsa: TsaChoice::Custom(TsaSpec {
                url: PkiUrl::Default,
                method: PkiMethod::Get,
                hash: HashAlg::Sha256,
                policy: None,
                nonce: Nonce::None,
                cert_req: true,
                retries: 0,
                timeout_ms: MAX_PKI_TIMEOUT_MS,
                check_skew_ms: None,
                require_tsa_eku: false,
            }),
            // The whole CA list, as the original's certificate chain.
            chain: cas.into_iter().map(Into::into).collect(),
            signature_method,
            digest_method,
        })
        // A document that is not XML.
        .map_err(|e| exception("org.xml.sax.SAXParseException", e.message))?;
    let validation = "eu.europa.esig.dss.model.DSSException";
    let signed = match outcome {
        XadesOutcome::Signed(signed) => signed.into_vec(),
        XadesOutcome::Failed(failure) => return Err(net_exception(&failure)),
        XadesOutcome::Invalid(Problem::Revoked { .. }) => {
            return Err(exception(
                validation,
                "Ошибка валидации. Сертификат отозван. REVOKED",
            ));
        }
        // Unverified against the original: DSS's sub-indication of a status unknown.
        XadesOutcome::Invalid(_) => {
            return Err(exception(validation, "Ошибка валидации. TRY_LATER"));
        }
    };
    // The signature made is checked again.
    let reports = pki::xml_verify(&signed).map_err(|e| host_failure(&e))?;
    if !reports.last().is_some_and(|report| report.valid) {
        return Err(exception(
            validation,
            "Ошибка валидации. Не удалось расшифровать подпись. SIG_CRYPTO_FAILURE",
        ));
    }
    Ok(String::from_utf8_lossy(&signed).into_owned())
}
