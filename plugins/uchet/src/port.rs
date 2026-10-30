//! The methods of `CommonUtils`, reached through the reflective dispatcher.

use crate::texts::{self, message};
use oncl_pdk::abi::{
    Check, FileMode, Header, HttpExArgs, Method, PageRead, PageWrite, Problem, SignerReport,
    VerifyArgs, VerifyAt,
};
use oncl_pdk::dialogs::{self, MessageKind, PasswordArgs};
use oncl_pdk::files::{self, ChooseFileArgs, FileFilter};
use oncl_pdk::keys::{self, Action, CoSign, Filter, Key, KeyOrder, KeySource, OpenArgs, Password};
use oncl_pdk::legacy::{
    self, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param,
};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{self, Revocation};
use oncl_pdk::{AddInfo, Request, host, http, javab64};
use oncl_port_kit::date::format_java;
use oncl_port_legacy::{
    ACTION_CANCELED, CertProblem, Select, Storage, base64, cades, cades_args, check_cert, fail,
    file_filters, file_info, into_text, knca_types, name_values, ok, response, select, sign_xml,
    split_path, storage, subject_and_issuer,
};

/// The module's state: none.
pub struct CommonUtils;

use LegacyBody::{Private, PrivateTakingObject, Public, Unconvertible};
use Param::Str;

const METHODS: &[LegacyMethod<CommonUtils>] = &[
    method("test", 1, Public(&[Str], test)),
    method("getVersion", 1, Public(&[Str], get_version)),
    method(
        "signXml",
        5,
        Public(&[Str, Str, Str, Str, Str], sign_xml_method),
    ),
    method("getFilePath", 2, Public(&[Str, Str], get_file_path)),
    method("checkCMS", 1, Public(&[Str], check_cms)),
    method("checkCMSFromWeb", 1, Public(&[Str], check_cms_from_web)),
    method("signXmlApi", 3, Public(&[Str, Str, Str], sign_xml_api)),
    method("signFile", 4, Public(&[Str, Str, Str, Str], sign_file)),
    method("signFilePath", 3, Public(&[Str, Str, Str], sign_file_path)),
    method(
        "signFileFromDiskAndSaveToDiskApi",
        6,
        Public(&[Str, Str, Str, Str, Str, Str], sign_to_disk_api),
    ),
    method(
        "signFileAndReturnBase64Api",
        5,
        Public(&[Str, Str, Str, Str, Str], sign_base64_api),
    ),
    method("getMessage", 1, Public(&[Str], get_message)),
    method("showKeyChooser", 1, Unconvertible),
    method("setKeyInfoServices", 1, Unconvertible),
    method("setKeyInfoSetterService", 1, Unconvertible),
    method("fillFromCert", 2, Private),
    method("verifyCMSResult", 1, Private),
    method("downloadUrl", 1, Private),
    method("signFileFromDiskAndSaveToDisk", 4, Private),
    method("sendGET", 1, Private),
    method("getStorageInfoApiWithPathAndPass", 3, Private),
    method("signFileFromBase64AndReturn", 4, Private),
    method("getFileFromBase64", 1, Private),
    method("signApi", 2, Private),
    method("getStorageInfoApi", 1, Private),
    method("getKeyStore", 1, Private),
    method("sign", 2, Private),
    method("createCAdES", 4, Private),
    method("saveFile", 3, Private),
    method("checkCert", 1, Private),
    method("getCaCertsMap", 0, Private),
    method("verifyCert", 3, Private),
    method("generateCert", 1, Private),
    method("getCaCertList", 0, Private),
    method("getStorageInfo", 1, Private),
    method("getFileFromPath", 1, Private),
    method("getFileFromPath", 2, Private),
    method("getBytes", 1, Private),
    method("saveKey", 2, Private),
    method("getJson", 1, PrivateTakingObject),
];

const fn method(
    name: &'static str,
    arity: usize,
    body: LegacyBody<CommonUtils>,
) -> LegacyMethod<CommonUtils> {
    LegacyMethod { name, arity, body }
}

const CLASS: LegacyClass<CommonUtils> = LegacyClass {
    dispatcher: "kz.uchet.signUtil.NCALayerCommonActivator",
    target: "kz.uchet.signUtil.CommonUtils",
    methods: METHODS,
    error_bean: ErrorBean::ResponseForJs,
    no_such_method: legacy::no_such_method_exception,
    before_invoke: None,
};

/// The plugin's handler.
pub fn handle(request: &Request) -> String {
    into_text(legacy::dispatch(
        &CommonUtils,
        &CLASS,
        &request.text,
        &request.add_info(),
    ))
}

fn failed(message: &str) -> Outcome {
    fail(Some(message))
}

/// The bean with `200`, `responseObject` and `message`.
fn signed(object: impl Into<JValue>, message: Option<&str>) -> Outcome {
    Outcome::Json(response(Some(object.into()), "200", message))
}

/// Java's `trim().isEmpty()`.
fn blank(s: &str) -> bool {
    s.trim_matches(|c| c <= ' ').is_empty()
}

/// `test(name)`: `"true" + name`, not JSON.
fn test(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Text(format!("true{}", args.str(0)))
}

/// `getVersion(name)`.
fn get_version(_: &CommonUtils, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Json(response(None, "200", Some("1.5")))
}

/// `getMessage(key)`: the text, not JSON; a key the bundle lacks throws.
fn get_message(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    match message(args.str(0)) {
        Some(text) => Outcome::Text(text.to_owned()),
        None => Outcome::Thrown,
    }
}

/// `signXml(storageName, keyType, xml, tbsXPath, parentXPath)`: the official method. The
/// original's file chooser did not stop the flow when cancelled; the core's one window
/// does, which is the key dialog's `action.canceled`.
fn sign_xml_method(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let key_type = args.str(1);
    let key = select(Select {
        storage: args.str(0),
        action: if key_type == "AUTHENTICATION" {
            Action::Authenticate
        } else {
            Action::Sign
        },
        knca_types: knca_types(key_type),
        order: KeyOrder::NewestFirst,
        filter: Filter {
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
    });
    let key = match key {
        Ok(Some(key)) => key,
        Ok(None) => return failed(ACTION_CANCELED),
        Err(message) => return failed(&message),
    };
    match sign_xml(&key, args.str(2), args.str(3), args.str(4)) {
        Ok(xml) => ok(xml),
        Err(message) => failed(&message),
    }
}

/// `getFilePath(fileExt, initialPath)`: the `FileInfo` of the chosen file, `{"size":0}` when
/// cancelled; an unknown `fileExt` throws.
fn get_file_path(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let Some(filters) = file_filters(args.str(0)) else {
        return Outcome::Thrown;
    };
    let initial = args.str(1);
    let chosen = files::choose(&ChooseFileArgs {
        mode: FileMode::Open,
        title: Some(texts::KEY_CHOOSE.to_owned()),
        filters,
        initial_dir: (!initial.is_empty()).then(|| initial.to_owned()),
    });
    match chosen {
        Ok(Some(file)) => ok(file_info(&file.path, file.size.unwrap_or_default())),
        Ok(None) => {
            let mut empty = JObject::hash_map();
            empty.put("size", JValue::Int(0));
            ok(empty)
        }
        Err(_) => failed(texts::INTERNAL_ERROR),
    }
}

/// A file the page names: blank is `404`, anything unreadable `file.ioException`.
fn read_page_file(path: &str) -> Result<Vec<u8>, String> {
    if blank(path) {
        return Err(texts::REQUIRED.to_owned());
    }
    match files::page_read(path) {
        Ok(PageRead::Ok(file)) => Ok(file.data.into_vec()),
        _ => Err(texts::FILE_IO.to_owned()),
    }
}

/// `checkCMS(filePath)`: the report of every signer of the CMS file.
fn check_cms(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    match read_page_file(args.str(0)).and_then(|cms| report(&cms)) {
        Ok(signers) => Outcome::Json(responses(signers)),
        Err(message) => failed(&message),
    }
}

/// `checkCMSFromWeb(url)`: the CMS at `url` — only the page's own origin, as the manifest
/// allows (the original read any URL, `file:` included); anything else is
/// `internalError`.
fn check_cms_from_web(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let url = args.str(0);
    let fetched = http::request_ex(&HttpExArgs {
        method: Method::Get,
        url: url.to_owned(),
        relative_to_origin: !url.contains("://"),
        headers: Vec::new(),
        content_type: None,
        body: Vec::new().into(),
        timeout_ms: None,
    });
    // Unverified against the original: its text for a URL it cannot read.
    let cms = match fetched {
        Ok(reply) if reply.status == 200 => reply.body.into_vec(),
        _ => return failed(texts::INTERNAL_ERROR),
    };
    match report(&cms) {
        Ok(signers) => Outcome::Json(responses(signers)),
        Err(message) => failed(&message),
    }
}

/// `{"responseObjects":[…],"code":"200"}`.
fn responses(signers: Vec<JValue>) -> JObject {
    let mut bean = response(None, "200", None);
    bean.put("responseObjects", JValue::Arr(signers));
    bean
}

/// The `SignerInfo` of each signer: judged at its time-stamp, with the core's CAs (for the
/// CA list the original downloaded) and the certificate's OCSP responder.
fn report(cms: &[u8]) -> Result<Vec<JValue>, String> {
    let report = pki::cms_verify(&VerifyArgs {
        cms: cms.to_vec().into(),
        data: None,
        at: VerifyAt::TspTime,
        chain: None,
        revocation: Revocation::LiveOcsp,
        first_signer_only: false,
        require_key_usage: Vec::new(),
    })
    // Unverified against the original: the text of a CMS that does not read.
    .map_err(|_| texts::INTERNAL_ERROR.to_owned())?;
    report
        .signers
        .iter()
        .map(|signer| signer_info(signer).map(JValue::Obj))
        .collect()
}

/// `{"valid":…,"message":…}`.
fn verification(valid: bool, message: Option<&str>) -> JObject {
    let mut result = JObject::hash_map();
    result.put("valid", valid);
    result.put_opt("message", message);
    result
}

/// `dd/MM/yyyy HH:mm:ss` in the system's time zone.
fn local_date(unix_ms: i64) -> Result<String, String> {
    let offset = host::local_offset(unix_ms).map_err(|e| e.message)?;
    Ok(format_java("dd/MM/yyyy HH:mm:ss", unix_ms, offset))
}

fn signer_info(signer: &SignerReport) -> Result<JObject, String> {
    let internal = || texts::INTERNAL_ERROR.to_owned();
    let cert = signer.certificate.as_ref().ok_or_else(internal)?;
    let info = host::cert_info(cert).map_err(|e| e.message)?;
    let details = host::cert_details(cert).map_err(|e| e.message)?;
    let (subject, _) = subject_and_issuer(cert)?;
    let first = |oid: &str| -> Result<Option<String>, String> {
        Ok(name_values(&subject, oid)?.into_iter().next())
    };
    let tsp = match &signer.tsp {
        None => verification(false, Some(texts::NO_TIMESTAMP)),
        Some(tsp) if tsp.check == Check::Ok => verification(true, None),
        Some(_) => verification(false, Some(texts::TIMESTAMP_INVALID)),
    };
    let certificate = certificate_result(signer, &details.knca_types, &info.ext_key_usages);
    let signature = match (&signer.signature, &signer.validity) {
        (_, Check::Fail(Problem::Expired | Problem::NotYetValid)) => {
            verification(false, Some(texts::SIGNER_VALIDITY))
        }
        (Check::Ok, _) => verification(true, None),
        _ => verification(false, None),
    };
    let valid = [&tsp, &certificate, &signature]
        .iter()
        .all(|r| r.get("valid") == Some(&JValue::Bool(true)));
    let person = info
        .ext_key_usages
        .iter()
        .any(|eku| eku == "1.2.398.3.3.4.1.1");
    let iin = first("2.5.4.5")?.map(|s| s.chars().skip(3).collect::<String>());
    // Unverified against the original: a missing GIVENNAME (left out here).
    let name = first("2.5.4.3")?.map(|cn| match first("2.5.4.42") {
        Ok(Some(given)) => format!("{cn} {given}"),
        _ => cn,
    });
    let bin = if person {
        None
    } else {
        name_values(&subject, "2.5.4.11")?
            .into_iter()
            .find(|ou| ou.chars().count() == 15 && (ou.contains("BIN") || ou.contains("bin")))
            .map(|ou| ou.chars().skip(3).collect::<String>())
    };
    let serial = info.serial_hex.trim_start_matches('0');
    let serial = if serial.is_empty() { "0" } else { serial };
    let period = format!(
        "{} - {}",
        local_date(info.not_before)?,
        local_date(info.not_after)?
    );
    let tsp_date = match signer.tsp.as_ref().and_then(|t| t.gen_time_ms) {
        Some(ms) => Some(local_date(ms)?),
        None => None,
    };
    // The bean's properties in the order its fields share HashMap buckets.
    let mut bean = JObject::hash_map();
    bean.put("personCertificate", person);
    bean.put("serialNumber", serial);
    bean.put("validSignature", valid);
    bean.put_opt("organizationName", first("2.5.4.10")?);
    bean.put("certificateValidityPeriod", period);
    bean.put_opt("tspDate", tsp_date);
    bean.put_opt("bin", bin);
    bean.put_opt("iin", iin);
    bean.put("tspVerificationResult", JValue::Obj(tsp));
    bean.put("number", 0);
    bean.put("certificateVerificationResult", JValue::Obj(certificate));
    bean.put_opt("name", name);
    bean.put("signatureVerificationResult", JValue::Obj(signature));
    Ok(bean)
}

/// The certificate's result: the type SIGNATURE, its validity and path at the time-stamp,
/// the refused extended key usages, then OCSP.
fn certificate_result(signer: &SignerReport, types: &[String], ekus: &[String]) -> JObject {
    let text = if !types.iter().any(|t| t == "SIGNATURE") {
        Some(texts::NOT_FOR_SIGNING)
    } else if signer.validity == Check::Fail(Problem::Expired) {
        Some(texts::CERT_EXPIRED)
    } else if signer.validity == Check::Fail(Problem::NotYetValid) {
        Some(texts::CERT_NOT_YET_VALID)
    } else if matches!(signer.path, Check::Fail(_)) {
        Some(texts::UNKNOWN_CA)
    } else if ekus
        .iter()
        .any(|e| e == "1.2.398.5.19.1.2.2.1" || e == "1.2.398.5.19.1.2.2.1.2")
    {
        Some(texts::NOT_VALIDATED)
    } else {
        match &signer.revocation {
            Check::Fail(Problem::Revoked { .. }) => Some(texts::REVOKED),
            Check::Fail(Problem::StatusUnknown) => Some(texts::OCSP_UNKNOWN),
            Check::Fail(Problem::ResponderUnverified | Problem::NonceMismatch) => {
                Some(texts::OCSP_NOT_VERIFIED)
            }
            // The original's checker has no update-window texts here: such answers pass.
            Check::Fail(Problem::OcspStale) => None,
            // Unverified against the original: a responder that cannot be reached.
            Check::Fail(_) => Some(texts::OCSP_EXCEPTION),
            Check::Ok | Check::Skipped => None,
        }
    };
    verification(text.is_none(), text)
}

/// `signXmlApi(keyPath, password, xmlBody)`: the key store the page names (the user allows
/// it once a session), the whole document signed; the signed XML in `message`.
fn sign_xml_api(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>{}",
        args.str(2)
    );
    let signed = page_key(args.str(0), args.str(1))
        .and_then(only_signing_key)
        .and_then(|key| sign_xml(&key, &xml, "", ""));
    match signed {
        Ok(xml) => Outcome::Json(response(None, "200", Some(&xml))),
        Err(message) => failed(&message),
    }
}

/// The keys of the PKCS#12 file the page names, opened with the page's password.
fn page_key(path: &str, password: &str) -> Result<Vec<Key>, String> {
    keys::open(&OpenArgs {
        storage: "PKCS12".to_owned(),
        source: KeySource::PagePath(path.to_owned()),
        password: Password::Text(password.to_owned()),
    })
    .map_err(|e| e.message)?
    // A wrong password too: the original printed the error and had no key store.
    .map_err(|_| texts::STORE_NOT_OPENED.to_owned())
}

/// The one signing key of `keys`: none is `keyNotFound`; several fail, as the original's
/// key chooser is a stub.
fn only_signing_key(keys: Vec<Key>) -> Result<Key, String> {
    let mut signing = Vec::new();
    for key in keys {
        let details = host::cert_details(key.certificate()).map_err(|e| e.message)?;
        if details.knca_types.iter().any(|t| t == "SIGNATURE") {
            signing.push(key);
        }
    }
    match signing.len() {
        0 => Err(texts::KEY_NOT_FOUND.to_owned()),
        1 => Ok(signing.remove(0)),
        _ => Err(texts::INTERNAL_ERROR.to_owned()),
    }
}

/// `signFile(filePath, fileUrl, fileDir, storageName)`: `signFilePath`, or `no no no !!!`
/// (not JSON) without a path.
fn sign_file(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    if args.str(0).is_empty() {
        return Outcome::Text("no no no !!!".to_owned());
    }
    sign_to_dir(args.str(0), args.str(2), args.str(3), None)
}

/// `signFilePath(filePath, fileDir, storageName)`.
fn sign_file_path(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    sign_to_dir(args.str(0), args.str(1), args.str(2), None)
}

/// The CAdES-T of the file `file_path`, written into `file_dir` as `<name>.cms`; the key
/// from the module's storage dialog, or from the page's key file and password.
fn sign_to_dir(
    file_path: &str,
    file_dir: &str,
    storage_name: &str,
    page: Option<(&str, &str)>,
) -> Outcome {
    let signed = (|| {
        if blank(storage_name) || blank(file_dir) {
            return Err(texts::REQUIRED.to_owned());
        }
        let data = read_page_file(file_path)?;
        let keys = match page {
            Some((path, password)) => page_store(storage_name, path, password)?,
            None => storage_dialog(storage_name)?,
        };
        let cms = sign_cms(keys, &data)?;
        let (name, _) = split_path(file_path);
        let name = if name.ends_with(".cms") {
            name.to_owned()
        } else {
            format!("{name}.cms")
        };
        let io = || texts::FILE_IO.to_owned();
        match files::page_write(file_dir, &name, &cms).map_err(|_| io())? {
            PageWrite::Written(path) => Ok(path),
            PageWrite::Invalid => match files::page_write(file_dir, "signedCMS.cms", &cms) {
                Ok(PageWrite::Written(path)) => Ok(path),
                _ => Err(io()),
            },
            PageWrite::Declined => Err(io()),
        }
    })();
    match signed {
        Ok(path) => signed_reply(path, Some(texts::CMS_SIGNED)),
        Err(message) => failed(&message),
    }
}

fn signed_reply(object: String, message: Option<&str>) -> Outcome {
    signed(object, message)
}

/// The storage the page names, checked as the module's 1-argument `StorageInfo`: an unknown
/// name is `internalError`, a token storage without a token `Носитель не обнаружен`.
fn checked_storage(storage_name: &str) -> Result<Storage, String> {
    let storage = storage(storage_name).map_err(|_| texts::INTERNAL_ERROR.to_owned())?;
    if let Storage::Token(name) = storage
        && keys::terminals(name).map_or(true, |readers| readers.is_empty())
    {
        return Err(texts::NO_MEDIUM.to_owned());
    }
    Ok(storage)
}

/// The module's storage dialog: the key store file and its password (the password asked
/// again while it is wrong); every key of the store. Closing it is
/// `Не удалось открыть хранилище`.
fn storage_dialog(storage_name: &str) -> Result<Vec<Key>, String> {
    let storage = checked_storage(storage_name)?;
    let not_opened = || texts::STORE_NOT_OPENED.to_owned();
    let source = match storage {
        Storage::File(_) => {
            let file = files::open_ex(&ChooseFileArgs {
                mode: FileMode::Open,
                title: Some(texts::KEY_CHOOSE.to_owned()),
                filters: vec![FileFilter {
                    name: "pkcs12 files (*.p12, *.pfx, *.jks)".to_owned(),
                    extensions: vec!["p12".to_owned(), "pfx".to_owned(), "jks".to_owned()],
                }],
                initial_dir: None,
            })
            .map_err(|_| not_opened())?
            .ok_or_else(not_opened)?;
            KeySource::Bytes(file.data)
        }
        // Unverified against the original: the first reader stands for its container list.
        Storage::Token(name) => KeySource::Terminal(
            keys::terminals(name)
                .ok()
                .and_then(|readers| readers.into_iter().next())
                .ok_or_else(|| texts::NO_MEDIUM.to_owned())?,
        ),
    };
    loop {
        let secret = dialogs::password(&PasswordArgs {
            title: "EzSigner".to_owned(),
            label: "Пароль".to_owned(),
            ok: "Открыть".to_owned(),
            cancel: "Отмена".to_owned(),
            allow_empty: false,
        })
        .map_err(|_| not_opened())?
        .ok_or_else(not_opened)?;
        let opened = keys::open(&OpenArgs {
            storage: storage.name().to_owned(),
            source: source.clone(),
            password: Password::Secret(secret.id),
        })
        .map_err(|_| not_opened())?;
        match opened {
            Ok(keys) => return Ok(keys),
            Err(keys::OpenOutcome::WrongPassword { tries_left }) => {
                let text = match tries_left {
                    Some(n) => format!("Неверный пароль Количество оставшихся попыток {n}"),
                    None => "Неверный пароль".to_owned(),
                };
                let _ = dialogs::message(MessageKind::Error, &text);
            }
            Err(keys::OpenOutcome::Blocked) => {
                let _ = dialogs::message(MessageKind::Error, "Пароль заблокирован");
                return Err(not_opened());
            }
            Err(_) => return Err(not_opened()),
        }
    }
}

/// The keys of the key file the page names, opened with the page's password.
fn page_store(storage_name: &str, path: &str, password: &str) -> Result<Vec<Key>, String> {
    checked_storage(storage_name)?;
    page_key(path, password)
}

/// The one signing key of `keys`, checked, then an attached CAdES of `data` time-stamped
/// by Kalkan's default TSA profile.
fn sign_cms(keys: Vec<Key>, data: &[u8]) -> Result<Vec<u8>, String> {
    let key = only_signing_key(keys)?;
    if let Some(problem) =
        check_cert(key.certificate()).map_err(|_| texts::INTERNAL_ERROR.to_owned())?
    {
        return Err(problem_text(problem).to_owned());
    }
    cades(
        &key,
        cades_args(key.handle(), data, true, CoSign::Auto, true),
    )
}

/// The module's text of a refused certificate.
fn problem_text(problem: CertProblem) -> &'static str {
    match problem {
        CertProblem::NotSigning => texts::NOT_FOR_SIGNING,
        CertProblem::Expired => texts::CERT_EXPIRED,
        CertProblem::NotYetValid => texts::CERT_NOT_YET_VALID,
        CertProblem::UnknownCa => texts::UNKNOWN_CA,
        CertProblem::Blocked => texts::NOT_VALIDATED,
        CertProblem::Revoked => texts::REVOKED,
        CertProblem::OcspUnknown => texts::OCSP_UNKNOWN,
        CertProblem::OcspNotVerified => texts::OCSP_NOT_VERIFIED,
        CertProblem::OcspStale => texts::OCSP_EXCEPTION,
    }
}

/// The license server's answer for `token`: `ok` lets the silent signing go on.
fn license(token: &str) -> String {
    // The original sent a token with `test` to a server on the user's own machine.
    if token.contains("test") {
        return texts::LICENSE_DOWN.to_owned();
    }
    let reply = http::request_ex(&HttpExArgs {
        method: Method::Post,
        url: "http://ncalayer.uchet.kz:8080/checkSignToken".to_owned(),
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
        content_type: Some("application/json".to_owned()),
        // Put together as text, without escaping, as the original did.
        body: format!("{{\"sign_token\":\"{token}\"}}")
            .into_bytes()
            .into(),
        timeout_ms: None,
    });
    let Ok(reply) = reply else {
        return texts::LICENSE_DOWN.to_owned();
    };
    if reply.status != 200 {
        return texts::LICENSE_DOWN.to_owned();
    }
    let answer = String::from_utf8_lossy(&reply.body).into_owned();
    let Ok(JValue::Obj(answer)) = orgjson::parse(&answer) else {
        return texts::LICENSE_DOWN.to_owned();
    };
    let answer = answer.to_map();
    let (Ok(error), Ok(result)) = (
        orgjson::get_string(&answer, "error"),
        orgjson::get_string(&answer, "result"),
    ) else {
        return texts::LICENSE_DOWN.to_owned();
    };
    // Unverified against the original: both texts present (none is taken here).
    let mut text = "";
    if error.is_empty() {
        text = result;
    }
    if result.is_empty() {
        text = error;
    }
    text.to_owned()
}

/// `signFileFromDiskAndSaveToDiskApi(signToken, filePath, fileDir, keyPath, keyPassword,
/// storageName)`.
fn sign_to_disk_api(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let verdict = license(args.str(0));
    if verdict != "ok" {
        return failed(&verdict);
    }
    sign_to_dir(
        args.str(1),
        args.str(2),
        args.str(5),
        Some((args.str(3), args.str(4))),
    )
}

/// `signFileAndReturnBase64Api(signToken, fileBase64, keyPath, keyPassword, storageName)`:
/// the CMS in `responseObject`.
fn sign_base64_api(_: &CommonUtils, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let verdict = license(args.str(0));
    if verdict != "ok" {
        return failed(&verdict);
    }
    let cms = (|| {
        // The original printed a decoding error and failed later on the missing bytes.
        let data =
            javab64::decode_java(args.str(1)).map_err(|_| texts::INTERNAL_ERROR.to_owned())?;
        let keys = page_store(args.str(4), args.str(2), args.str(3))?;
        sign_cms(keys, &data)
    })();
    match cms {
        // Unverified against the original: no `message` in this reply.
        Ok(cms) => signed(base64(&cms), None),
        Err(message) => failed(&message),
    }
}
