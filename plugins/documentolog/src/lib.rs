//! The Documentolog agent (`kz.documentolog.Agent`) as an OpenNCALayer plugin: its two
//! modules, `kz.documentolog.agent.SignService` and `kz.documentolog.agent.KalkanService`,
//! told apart by the request's `module`.
//!
//! A request is `{"method", "args": {…}}`; one org.json cannot read, or without an `args`
//! object, drops the connection, as the original's uncaught exception does. Replies are
//! written in order with a numeric `code`: `{"code":200,"message":"success",
//! "responseObject":{"result":…}}`, `{"code":500,"message":"unknown"}`.
//!
//! The page names key stores by path (and alias, `key_index`); their password is asked
//! once in the «Пароль для ЭЦП» window and kept by the core for the session. The server
//! flow ([`server`]) fetches the signing order from Documentolog's service of the page's
//! site and signs what it names.

mod server;

use oncl_pdk::abi::{
    ChooseFileArgs, FileFilter, FileMode, KeySource, MessageKind, Password, PasswordArgs,
};
use oncl_pdk::dialogs::{self, ChoiceArgs};
use oncl_pdk::http::{self, Header, HttpExArgs, Method};
use oncl_pdk::keys::{
    self, C14n, CmsCerts, CmsContent, CmsOutcome, CoSign, Key, OpenArgs, Placement, SignCmsExArgs,
    SignXmlExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource, Transform, XmlOutput,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, files, host, javab64};
use oncl_port_pki::esedo::{
    self, ContentMode, Description, Encapsulate, EsedoInput, FileNames, OcspAnswer, OcspForm,
    Profile, SignerDn, SigningTimeRule, StringKind, TimeFrom,
};
use std::cell::RefCell;

/// Documentolog's ESEDO CMS: the file names, the page's OCSP answer, the signer's DN,
/// contentType and `ESEDO\0`; the whole chain; attached as asked; over a digest in the SP
/// flow.
pub const DOCUMENTOLOG: Profile = Profile {
    econtent_type: None,
    content: ContentMode::AsAsked,
    digest: None,
    encapsulate: Encapsulate::AsAsked,
    cosign: CoSign::Never,
    certificates: CmsCerts::Chain,
    content_type: true,
    signing_certificate_v2: false,
    signing_time: Some(SigningTimeRule {
        from: TimeFrom::Now,
        form: TimeForm::Auto,
    }),
    file_names: Some(FileNames {
        separator: "<>",
        omit_blank: false,
    }),
    signer_dn: Some(SignerDn::Kalkan),
    description: Some(Description {
        text: "ESEDO\0",
        kind: StringKind::Printable,
    }),
    ocsp: Some(OcspForm::OctetResponse),
    ocsp_request: None,
};

/// What the instance keeps between calls.
#[derive(Default)]
struct State {
    /// The key stores' password: typed in the window (kept by the core) or sent by the
    /// server.
    password: Option<Password>,
    /// The browse guard: up while a browse runs, and after one that failed.
    browsing: bool,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// What a method answers.
enum Out {
    Reply(String),
    Drop,
}

fn result(result: &str) -> Out {
    let mut inner = JObject::stringer();
    inner.put("result", result);
    let mut reply = JObject::stringer();
    reply.put("code", 200);
    reply.put("message", "success");
    reply.put("responseObject", inner);
    Out::Reply(reply.to_json())
}

fn failure(message: Option<&str>) -> Out {
    let mut reply = JObject::stringer();
    reply.put("code", 500);
    reply.put("message", message.map_or(JValue::Null, JValue::from));
    Out::Reply(reply.to_json())
}

fn unknown() -> Out {
    failure(Some("unknown"))
}

fn handle(request: &Request) -> String {
    let out = read(&request.text).map_or(Out::Drop, |(module, method, args)| {
        if module == "kz.documentolog.agent.SignService" {
            sign_service(&method, &args)
        } else {
            kalkan_service(&method, &args)
        }
    });
    match out {
        Out::Reply(text) => text,
        Out::Drop => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

oncl_pdk::plugin!(handle);

/// `module`, `method` (`optString`) and `args` (`getJSONObject`); `None` where the original
/// throws.
fn read(text: &str) -> Option<(String, String, Map<String, Value>)> {
    let JValue::Obj(request) = orgjson::parse(text).ok()? else {
        return None;
    };
    let map = request.to_map();
    let module = orgjson::opt_string(&map, "module").unwrap_or_default();
    let method = orgjson::opt_string(&map, "method").unwrap_or_default();
    let args = orgjson::get_object(&map, "args").ok()?.clone();
    Some((module, method, args))
}

fn sign_service(method: &str, args: &Map<String, Value>) -> Out {
    match method {
        "browseKeyStore" => browse(args),
        "getKeys" => get_keys(args),
        "getSPAndSign" | "sign" => server_sign(args, Flow::Sp),
        "getSSAndSign" => server_sign(args, Flow::Ss),
        _ => failure(Some("unknown method")),
    }
}

fn kalkan_service(method: &str, args: &Map<String, Value>) -> Out {
    match method {
        "init" => result("init"),
        "browseKeyStore" => browse(args),
        "getKeys" => get_keys(args),
        "getCertInfo" => cert_info(args),
        "getSubjectDN" => subject_dn(args),
        // The original reads the standalone agent's `keys.json`; the port does not.
        "getCurrentUser" => result(""),
        "getCurrentStoragePath" => result("null"),
        "createCMSEsedoSignature" => result(&page_cms(args, true).unwrap_or_default()),
        "createCMSSimpleSignature" => result(&page_cms(args, false).unwrap_or_default()),
        _ => failure(Some("unknown method")),
    }
}

/// `optString`: `""` when absent.
fn arg(args: &Map<String, Value>, key: &str) -> String {
    orgjson::opt_string(args, key).unwrap_or_default()
}

fn clear_password() {
    STATE.with_borrow_mut(|state| state.password = None);
}

/// The kept password, else the «Пароль для ЭЦП» window's; `None` if it is closed.
fn password() -> Option<Password> {
    if let Some(password) = STATE.with_borrow(|state| state.password.clone()) {
        return Some(password);
    }
    let secret = dialogs::password(&PasswordArgs {
        title: "Пароль для ЭЦП".to_owned(),
        label: "Пароль для ЭЦП: ".to_owned(),
        ok: "OK".to_owned(),
        cancel: "Отмена".to_owned(),
        allow_empty: false,
    })
    .ok()
    .flatten()?;
    let password = Password::Secret(secret.id);
    STATE.with_borrow_mut(|state| state.password = Some(password.clone()));
    Some(password)
}

/// The token storages the original's old applet knows.
const TOKENS: [&str; 4] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKJaCartaStore",
];

/// The file storages it knows.
const FILES: [&str; 2] = ["PKCS12", "JKS"];

/// Whether `storage` is one the original knows.
fn known_storage(storage: &str) -> bool {
    FILES.contains(&storage) || TOKENS.contains(&storage)
}

/// `browseKeyStore`: a key store file or folder, or a token reader; its path.
fn browse(args: &Map<String, Value>) -> Out {
    let storage = arg(args, "storage_name");
    let extension = arg(args, "file_extension");
    if STATE.with_borrow(|state| state.browsing) {
        clear_password();
        return unknown();
    }
    STATE.with_borrow_mut(|state| state.browsing = true);
    // The window again if it gave no password; still none: an empty result, the guard left
    // up (as the original).
    if password().or_else(password).is_none() {
        return result("");
    }
    let done = |out: Out| {
        STATE.with_borrow_mut(|state| state.browsing = false);
        out
    };
    if !known_storage(&storage) {
        clear_password();
        return done(unknown());
    }
    if !FILES.contains(&storage.as_str()) {
        let terminals = keys::terminals(&storage).unwrap_or_default();
        let chosen = if terminals.is_empty() {
            None
        } else {
            dialogs::choice(&ChoiceArgs {
                kind: MessageKind::Info,
                title: Some("Выбор хранилища ключа".to_owned()),
                text: format!("Тип хранилища: {storage}\nПуть к хранилищу:"),
                buttons: vec!["Выбрать".to_owned(), "Отмена".to_owned()],
                default: 0,
                options: terminals
                    .iter()
                    .take(oncl_pdk::abi::MAX_CHOICE_OPTIONS)
                    .cloned()
                    .collect(),
            })
            .ok()
            .flatten()
        };
        return match chosen.and_then(|i| terminals.get(usize::from(i))) {
            Some(terminal) => done(result(terminal)),
            None => {
                clear_password();
                done(unknown())
            }
        };
    }
    let filter = |name: &str, extensions: &[&str]| {
        vec![FileFilter {
            name: name.to_owned(),
            extensions: extensions.iter().map(|e| (*e).to_owned()).collect(),
        }]
    };
    let (mode, filters) = match extension.as_str() {
        "" => (FileMode::Directory, Vec::new()),
        "P12" => (FileMode::Open, filter("PKCS#12", &["p12"])),
        "KEYSTORE" => (FileMode::Open, filter("KEYSTORE", &["pfx", "p12", "bin"])),
        "CER" => (FileMode::Open, filter("CER", &["der", "cer"])),
        "CRL" => (FileMode::Open, filter("CRL", &["crl"])),
        "ALL" => (FileMode::Open, Vec::new()),
        // `FileType.valueOf` throws: the connection drops, the guard stays up.
        _ => return Out::Drop,
    };
    let chosen = files::choose(&ChooseFileArgs {
        mode,
        title: Some("Открыть файл".to_owned()),
        filters,
        initial_dir: None,
    });
    match chosen {
        Ok(Some(chosen)) => done(result(&chosen.path)),
        // A cancelled chooser is a null path: the connection drops, the guard stays up.
        _ => Out::Drop,
    }
}

/// Every key of the store `storage` at `path`; `None` if it does not open.
fn open(storage: &str, path: &str, password: Password) -> Option<Vec<Key>> {
    let source = if TOKENS.contains(&storage) {
        KeySource::Terminal(path.to_owned())
    } else {
        KeySource::PagePath(path.to_owned())
    };
    keys::open(&OpenArgs {
        storage: storage.to_owned(),
        source,
        password,
    })
    .ok()?
    .ok()
}

/// The signature algorithm OID of GOST 34.310-2004.
const GOST2004_SIG_OID: &str = "1.2.398.3.10.1.1.1.2";

/// The clientAuth extended key usage: the original's `"SIGN"` list leaves those out.
const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// `getKeys`: `ALG|CN|serialHex|alias` of each signing key, one per line; `ALG` is «ГОСТ»
/// for a certificate signed with GOST 34.310-2004 and «RSA» for any other. No key left is
/// an error.
fn get_keys(args: &Map<String, Value>) -> Out {
    let storage = arg(args, "storage_name");
    let path = arg(args, "storage_path");
    let Some(keys) = password().and_then(|password| open(&storage, &path, password)) else {
        clear_password();
        return unknown();
    };
    let lines: Vec<String> = keys
        .iter()
        .filter_map(|key| {
            let info = host::cert_info(key.certificate()).ok()?;
            if info.ext_key_usages.iter().any(|eku| eku == EKU_CLIENT_AUTH) {
                return None;
            }
            let alg = if info.signature_alg_oid == GOST2004_SIG_OID {
                "ГОСТ"
            } else {
                "RSA"
            };
            let serial = info.serial_hex.trim_start_matches('0');
            let serial = if serial.is_empty() { "0" } else { serial };
            Some(format!(
                "{alg}|{}|{serial}|{}",
                info.subject_cn.unwrap_or_default(),
                key.alias()
            ))
        })
        .collect();
    if lines.is_empty() {
        clear_password();
        return unknown();
    }
    result(&lines.join("\n"))
}

/// The key `alias` of the store the page names, with the kept password.
fn page_key(storage: &str, path: &str, alias: &str) -> Option<Key> {
    open(storage, path, password()?)?
        .into_iter()
        .find(|key| key.alias() == alias)
}

/// `getCertInfo`: never a success, as the original's inverted check.
fn cert_info(args: &Map<String, Value>) -> Out {
    match page_key(
        &arg(args, "storage_alias"),
        &arg(args, "storage_path"),
        &arg(args, "alias"),
    ) {
        Some(_) => failure(Some("getX509Certificate is null")),
        None => failure(None),
    }
}

/// `getSubjectDN`: the subject as Kalkan writes it, `||`, the certificate's base64.
fn subject_dn(args: &Map<String, Value>) -> Out {
    let key = page_key(
        &arg(args, "storage_alias"),
        &arg(args, "storage_path"),
        &arg(args, "alias"),
    );
    let text = key
        .and_then(|key| {
            let details = host::cert_details(key.certificate()).ok()?;
            Some(format!(
                "{}||{}",
                details.subject_dn,
                javab64_encode(key.certificate())
            ))
        })
        .unwrap_or_default();
    result(&text)
}

fn javab64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The bytes at `url`: a GET of an `http(s)` URL the core allows (the page's own site).
fn download(url: &str) -> Option<Vec<u8>> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return None;
    }
    let response = http::request_ex(&HttpExArgs {
        method: Method::Get,
        url: url.to_owned(),
        relative_to_origin: false,
        headers: Vec::new(),
        content_type: None,
        body: Default::default(),
        timeout_ms: None,
    })
    .ok()?;
    (response.status == 200).then(|| response.body.into_vec())
}

/// The document at `url`: base64 text, of `size` characters unless `size` is negative.
fn document(url: &str, size: i64) -> Option<Vec<u8>> {
    let body = download(url)?;
    if size >= 0 && body.len() as i64 != size {
        return None;
    }
    javab64::decode_kalkan(std::str::from_utf8(&body).ok()?).ok()
}

/// Whether the original signs with the key's certificate: its digest follows the
/// certificate's signature algorithm (SHA-256 RSA, GOST 34.310-2004); others are
/// `UNKNOWN_SIG_ALG`, and SHA-1 RSA signatures are not made.
fn supported(key: &Key) -> bool {
    host::cert_info(key.certificate()).is_ok_and(|info| {
        matches!(
            info.signature_alg_oid.as_str(),
            "1.2.840.113549.1.1.11" | "1.2.398.3.10.1.1.1.2"
        )
    })
}

fn signed(outcome: Option<CmsOutcome>) -> Option<String> {
    match outcome? {
        CmsOutcome::Signed(cms) => Some(javab64_encode(&cms)),
        CmsOutcome::TspFailed(_) => None,
    }
}

/// The ESEDO CMS of `data` (or of its hash) with the file names and OCSP answer.
fn esedo_cms(
    key: &Key,
    data: &[u8],
    hashed: bool,
    attached: bool,
    names: &str,
    ocsp: Option<&[u8]>,
) -> Option<String> {
    if !supported(key) {
        return None;
    }
    let details = host::cert_details(key.certificate()).ok()?;
    let input = EsedoInput {
        cert: key.certificate(),
        kalkan_dn: Some(&details.subject_dn),
        file_names: &[names],
        ocsp: ocsp.map(|response| OcspAnswer {
            response,
            basic: None,
            produced_at_ms: None,
        }),
        tsp_gen_time_ms: None,
        data,
        hashed,
        attached,
    };
    let args = esedo::sign_args(&DOCUMENTOLOG, &input, key.handle()).ok()?;
    signed(key.sign_cms_ex(args).ok())
}

/// The old applet's CMS: the generator's attributes (contentType, signingTime,
/// messageDigest), the whole chain.
fn simple_cms(key: &Key, content: CmsContent, attached: bool) -> Option<String> {
    if !supported(key) {
        return None;
    }
    signed(
        key.sign_cms_ex(SignCmsExArgs {
            handle: key.handle(),
            content,
            encapsulate: attached,
            cosign: CoSign::Never,
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
            certificates: CmsCerts::Chain,
            timestamp: None,
            output: oncl_pdk::abi::CmsOutput::Der,
        })
        .ok(),
    )
}

/// `createCMSEsedoSignature` and `createCMSSimpleSignature` of the page: the password
/// first (the window if none is kept), then the data, then the key.
fn page_cms(args: &Map<String, Value>, esedo: bool) -> Option<String> {
    let password = password();
    let data = document(&arg(args, "sign_string_url"), -1)?;
    let attached = arg(args, "attached") == "true";
    let key = open(
        &arg(args, "storage_alias"),
        &arg(args, "storage_path"),
        password?,
    )?
    .into_iter()
    .find(|key| key.alias() == arg(args, "key_index"))?;
    if esedo {
        let ocsp = javab64::decode_kalkan(&arg(args, "ocsp_notification")).ok();
        esedo_cms(
            &key,
            &data,
            false,
            attached,
            &arg(args, "signed_files"),
            ocsp.as_deref(),
        )
    } else {
        // The original signs the base64 text of the data, not the data.
        let text = javab64_encode(&data);
        simple_cms(&key, CmsContent::Data(text.into_bytes().into()), attached)
    }
}

/// The two server flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// `getSPAndSign`, `sign`: the server sends the document's hash.
    Sp,
    /// `getSSAndSign`: the server sends the document's URL.
    Ss,
}

fn server_sign(args: &Map<String, Value>, flow: Flow) -> Out {
    result(&server_flow(args, flow).unwrap_or_default())
}

/// The server flow: the challenge, the order decrypted, the document signed; `None` on
/// any failure (the original's `""`).
fn server_flow(args: &Map<String, Value>, flow: Flow) -> Option<String> {
    let ca = arg(args, "ca");
    let store_type = arg(args, "store_type");
    let path = arg(args, "path");
    let (s_rand, code) = server::challenge()?;
    let url = format!("{path}&code={code}");
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return None;
    }
    let response = http::request_ex(&HttpExArgs {
        method: Method::Get,
        url,
        relative_to_origin: false,
        headers: vec![
            Header {
                name: "User-Agent".to_owned(),
                value: "Mozilla/5.0".to_owned(),
            },
            Header {
                name: "Accept-Language".to_owned(),
                value: "en-US,en;q=0.5".to_owned(),
            },
        ],
        content_type: None,
        body: Default::default(),
        timeout_ms: None,
    })
    .ok()?;
    if response.status != 200 {
        return None;
    }
    let JValue::Obj(order) = orgjson::parse(std::str::from_utf8(&response.body).ok()?).ok()? else {
        return None;
    };
    let order = order.to_map();
    if orgjson::opt_string(&order, "status").as_deref() != Some("1") {
        return None;
    }
    let field = |name: &str| server::decrypt(&s_rand, &arg(&order, name));
    let given = field("p").unwrap_or_default();
    let kind = field("et")?;
    let alias = field("a").unwrap_or_default();
    let mut store = field("f")?;
    if flow == Flow::Sp {
        store = server::redecode_1251(&store);
    }
    let names = field("fs").unwrap_or_default();
    let ss = field("ss")?;
    let ocsp = javab64::decode_kalkan(&arg(&order, "ocsp")).ok();
    match ca.as_str() {
        "НУЦ" => {}
        // The Tumar/Gamma branch of the original (УЦГО tokens) is not ported: its failure
        // answer.
        _ => return None,
    }
    let password = if given.is_empty() {
        password()?
    } else {
        let password = Password::Text(given.clone());
        STATE.with_borrow_mut(|state| state.password = Some(password.clone()));
        password
    };
    let keys = open(&store_type, &store, password);
    if given.is_empty() {
        clear_password();
    }
    let keys = keys?;
    let key = if alias.is_empty() {
        keys.into_iter().next()?
    } else {
        keys.into_iter().find(|key| key.alias() == alias)?
    };
    match flow {
        Flow::Sp => {
            let digest = javab64::decode_kalkan(&ss).ok()?;
            if kind == "esedo" {
                esedo_cms(&key, &digest, true, false, &names, ocsp.as_deref())
            } else {
                simple_cms(&key, CmsContent::Digest(digest.into()), false)
            }
        }
        Flow::Ss => {
            let size = field("sss").and_then(|s| s.trim().parse::<i64>().ok())?;
            let data = document(&ss, size)?;
            match kind.as_str() {
                "esedo" => esedo_cms(&key, &data, false, false, &names, ocsp.as_deref()),
                "xml_signer" => xml_signature(&key, &data),
                "ez_signer" => cades(&key, &data),
                _ => simple_cms(&key, CmsContent::Data(data.into()), false),
            }
        }
    }
}

/// `createCAdES` without a time-stamp, attached.
fn cades(key: &Key, data: &[u8]) -> Option<String> {
    signed(
        key.sign_cms_ex(SignCmsExArgs {
            handle: key.handle(),
            content: CmsContent::Data(data.to_vec().into()),
            encapsulate: true,
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
            timestamp: None,
            output: oncl_pdk::abi::CmsOutput::Der,
        })
        .ok(),
    )
}

/// The XML signature of the server flow: in the document's first node; RSA by the
/// certificate's SHA-256, everything else GOST 34.310-2004; the document's base64.
fn xml_signature(key: &Key, xml: &[u8]) -> Option<String> {
    let info = host::cert_info(key.certificate()).ok()?;
    let (signature_method, digest_method) = if info.signature_alg_oid == "1.2.840.113549.1.1.11" {
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )
    } else if info.signature_alg_oid == "1.2.840.113549.1.1.5" {
        // No RSA-SHA1 signatures.
        return None;
    } else {
        (
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        )
    };
    let signed = key
        .sign_xml_ex(SignXmlExArgs {
            handle: key.handle(),
            xml: xml.to_vec().into(),
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
            signature_id: None,
            signing_time_object: None,
            strip_whitespace: false,
            base64_line_breaks: None,
            output: XmlOutput::Serialize {
                declaration: true,
                standalone_no: true,
                trim: false,
            },
        })
        .ok()?;
    Some(javab64_encode(&signed))
}
