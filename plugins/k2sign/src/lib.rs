//! K2Sign (`kz.ecc.K2SignBundle` 1.1.5) as an OpenNCALayer plugin: `version`, `login` (the
//! session id signed and uploaded in a zip), `file` (a document from the site or a PDF the
//! user picks, signed or not, uploaded in a zip), `verify` and `verifyAll` (signatures from
//! the site checked, the results shown and sent back). Every URL is the page's own site:
//! relative ones are resolved against its origin, absolute ones elsewhere are refused.
//! Errors show the original's window and reply `{"errorCode":"<type>"}`; the site may name
//! the type in its reply (`error: <TYPE>`).
#![cfg(target_arch = "wasm32")]

mod texts;

use oncl_pdk::abi::{
    Action, Bytes, Check, ChooseArgs, ChooseFileArgs, CmsCerts, CmsContent, CmsOutcome, CoSign,
    ErrorCode, FileFilter, FileMode, Filter, Header, HttpExArgs, HttpResponse, KeyUsageBit,
    MessageKind, Method, Problem, Revocation, SignCmsExArgs, SignedAttrs, SigningTime, TimeForm,
    TimeSource, TsaChoice, VerifyArgs, VerifyAt,
};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{self, Map, Value};
use oncl_pdk::{Locale, Request, dialogs, files, host, http, javamap, pki};
use oncl_port_kit::http::{Multipart, Part};
use oncl_port_kit::reply::ecc;
use texts::Ui;

/// The storages the key dialog offers, in the original's order.
const STORAGES: [&str; 6] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKJaCartaStore",
    "AKEToken5110Store",
    "PKCS12",
];

/// The boundary of every upload, fixed in the original.
const BOUNDARY: &str = "---------------------------24464570528145";

/// The largest file uploaded: the original's default, 20 MiB.
const MAX_FILE_SIZE: usize = 20 * 1024 * 1024;

/// `verify`'s default URLs, as the original had them.
const DEFAULT_DATA_URL: &str = "fileDownloadServlet?fileId=4368";
const DEFAULT_SIGN_URL: &str = "fileDownloadServlet?signId=4357";

/// Why an operation did not give its result.
enum Failure {
    /// An error of the type `code`; the window shows the text of `message` (a type the site
    /// named that K2Sign does not have) or of `code`.
    K2 {
        code: &'static str,
        message: Option<String>,
    },
    /// No reply: the original's connection ended.
    Drop,
}

fn k2(code: &'static str) -> Failure {
    Failure::K2 {
        code,
        message: None,
    }
}

type Outcome = Result<String, Failure>;

fn handle(request: &Request) -> String {
    // The original read the origin before anything else, and ended the connection without
    // one.
    let Some(origin) = request.origin.as_deref() else {
        return drop_connection();
    };
    let Ok(Value::Object(req)) = serde_json::from_str::<Value>(&request.text) else {
        return drop_connection();
    };
    let locale = request.locale;
    let outcome = match orgjson::opt_string(&req, "type")
        .unwrap_or_default()
        .as_str()
    {
        "version" => {
            let mut version = JObject::hash_map();
            version.put("version", "1.0.0");
            return ecc(Some(JValue::Obj(version)), Some("NONE"));
        }
        "login" => login(&req),
        "file" => file(&req, locale),
        "verify" => verify(&req, locale),
        "verifyAll" => verify_all(&req, origin, locale),
        _ => Err(k2("TYPE_NOT_SUPPORTED")),
    };
    match outcome {
        Ok(result) => ecc(Some(result.into()), Some("NONE")),
        Err(Failure::Drop) => drop_connection(),
        Err(Failure::K2 { code, message }) => {
            let text = texts::text(message.as_deref().unwrap_or(code), locale);
            let _ = dialogs::message(MessageKind::Error, text);
            ecc(None, Some(code))
        }
    }
}

oncl_pdk::plugin!(handle);

/// `login`: `sessionId` signed, uploaded with the signature and the certificate.
fn login(req: &Map<String, Value>) -> Outcome {
    let session_id = orgjson::get_string(req, "sessionId").map_err(|_| Failure::Drop)?;
    let upload_url = orgjson::get_string(req, "uploadURL").map_err(|_| Failure::Drop)?;
    let attributes = orgjson::opt_string(req, "fileAttributes").unwrap_or_default();
    let timestamp = has_tsa(req);
    let key = choose()?;
    let cms = cades(&key, session_id.as_bytes(), timestamp)?;
    let cert = key.certificate().to_vec();
    drop(key);
    // `coockie`, sic: the page's name for it.
    let cookie = orgjson::get_string(req, "coockie").map_err(|_| k2("CREATE_REQUEST_ERROR"))?;
    upload(
        upload_url,
        "userdata",
        &[
            ("userdata", session_id.as_bytes()),
            ("userdata.p7s", &cms),
            ("public_key.cer", &cert),
        ],
        &[("fileAttributes", &attributes)],
        cookie,
    )
}

/// `file`: with `downloadURL`, that document signed and the signature uploaded; otherwise a
/// PDF the user picks, uploaded as it is (`uploadOnly`) or with its signature.
fn file(req: &Map<String, Value>, locale: Locale) -> Outcome {
    let attributes = orgjson::opt_string(req, "fileAttributes").unwrap_or_default();
    let user = orgjson::get_string(req, "userName").map_err(|_| Failure::Drop)?;
    let upload_url = orgjson::get_string(req, "uploadURL").map_err(|_| Failure::Drop)?;
    let timestamp = has_tsa(req);
    let cookie = orgjson::opt_string(req, "coockie").unwrap_or_default();
    let download_url = orgjson::opt_string(req, "downloadURL").unwrap_or_default();
    let upload_only =
        orgjson::opt_string(req, "uploadOnly").is_some_and(|value| value.eq_ignore_ascii_case("Y"));

    if !download_url.is_empty() {
        let data = download(&download_url, &cookie)?;
        let key = choose()?;
        let cms = cades(&key, &data, timestamp)?;
        let cert = key.certificate().to_vec();
        drop(key);
        return upload(
            upload_url,
            "eccserver",
            &[("eccserver.p7s", &cms), ("public_key.cer", &cert)],
            &[
                ("fileAttributes", &attributes),
                ("userName", user),
                ("SignatureOnly", "signedFileFromServer"),
            ],
            &cookie,
        );
    }

    let ui = Ui::of(locale);
    let chooser = ChooseFileArgs {
        mode: FileMode::Open,
        title: Some(ui.open_file.to_owned()),
        filters: vec![FileFilter {
            name: ui.file.to_owned(),
            extensions: vec!["pdf".to_owned()],
        }],
        initial_dir: None,
    };
    let chosen = match files::open_ex(&chooser) {
        Ok(Some(chosen)) => chosen,
        Ok(None) => return Err(k2("CANCEL")),
        Err(e) if e.code == ErrorCode::Limit => return Err(k2("MAX_FILE_SIZE_EXCEEDED")),
        Err(_) => return Err(k2("FILE_NOT_FOUND")),
    };
    if chosen.data.len() > MAX_FILE_SIZE {
        return Err(k2("MAX_FILE_SIZE_EXCEEDED"));
    }
    let name = chosen
        .path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&chosen.path);
    if upload_only {
        return upload(
            upload_url,
            name,
            &[(name, &chosen.data)],
            &[
                ("fileAttributes", &attributes),
                ("userName", user),
                ("NotSignedFile", "notSignedFile"),
            ],
            &cookie,
        );
    }
    let key = choose()?;
    let cms = cades(&key, &chosen.data, timestamp)?;
    let cert = key.certificate().to_vec();
    drop(key);
    let signature_name = format!("{name}.p7s");
    upload(
        upload_url,
        name,
        &[
            (name, &chosen.data),
            (&signature_name, &cms),
            ("public_key.cer", &cert),
        ],
        &[("fileAttributes", &attributes), ("userName", user)],
        &cookie,
    )
}

/// `verify`: the signature at `fileSignURL` of the document at `fileDataURL`.
fn verify(req: &Map<String, Value>, locale: Locale) -> Outcome {
    let data_url =
        orgjson::opt_string(req, "fileDataURL").unwrap_or_else(|| DEFAULT_DATA_URL.to_owned());
    let sign_url =
        orgjson::opt_string(req, "fileSignURL").unwrap_or_else(|| DEFAULT_SIGN_URL.to_owned());
    let signature = download(&sign_url, "")?;
    let data = download(&data_url, "")?;
    check(&signature, &data).map_err(k2)?;
    info("SIGN_VERIFICATION_SUCCESS", locale);
    Ok("OK".to_owned())
}

/// `verifyAll`: each signature of each item checked; the outcome is shown, and if all are
/// valid, sent to `signVerifyResURL`. The reply is `OK` either way.
fn verify_all(req: &Map<String, Value>, origin: &str, locale: Locale) -> Outcome {
    let data_url = orgjson::opt_string(req, "fileDataURL").unwrap_or_default();
    let sign_url = orgjson::opt_string(req, "fileSignURL").unwrap_or_default();
    let user = orgjson::opt_string(req, "userName").unwrap_or_default();
    let results_url = orgjson::opt_string(req, "signVerifyResURL").unwrap_or_default();
    let items = orgjson::get_array(req, "items").map_err(|_| Failure::Drop)?;

    // The original's `HashMap<Integer, String>`: a repeated id keeps its place.
    let mut results: Vec<(i32, bool)> = Vec::new();
    let mut count = 0usize;
    let failed = || k2("SIGN_VERIFICATION_FAILED");
    for i in 0..items.len() {
        let item = orgjson::array_get_object(items, i).map_err(|_| failed())?;
        let file_id = orgjson::get_int(item, "fileId").map_err(|_| failed())?;
        let ids = orgjson::get_array(item, "signaturesIds").map_err(|_| failed())?;
        let data = download(&format!("{data_url}{file_id}"), "")?;
        for id in ids {
            let id = id
                .as_i64()
                .and_then(|id| i32::try_from(id).ok())
                .ok_or_else(failed)?;
            let signature = download(&format!("{sign_url}{id}"), "")?;
            let valid = check(&signature, &data).is_ok();
            match results.iter_mut().find(|(seen, _)| *seen == id) {
                Some(result) => result.1 = valid,
                None => results.push((id, valid)),
            }
            count += 1;
        }
    }

    if results.iter().all(|(_, valid)| *valid) {
        info(
            if count == 1 {
                "SIGN_VERIFICATION_SUCCESS"
            } else {
                "ALL_SIGN_ARE_VALID"
            },
            locale,
        );
        send_results(origin, &results_url, &user, &results, locale);
    } else {
        let key = if count == 1 {
            "SIGN_VERIFICATION_FAILED"
        } else {
            "MANY_NOT_VALID_SIGN_FOUND"
        };
        let _ = dialogs::message(MessageKind::Error, texts::text(key, locale));
    }
    Ok("OK".to_owned())
}

/// `POST <origin>/<results_url>`: the user and each id's `Y`/`N`, in the order of Java's
/// `HashMap` of the ids. A failure is only shown.
fn send_results(
    origin: &str,
    results_url: &str,
    user: &str,
    results: &[(i32, bool)],
    locale: Locale,
) {
    let ids: Vec<i32> = results.iter().map(|(id, _)| *id).collect();
    let mut body = format!("userName={}&verifyRes=", url_encode(user));
    for i in integer_map_order(&ids) {
        let (id, valid) = results[i];
        body.push_str(&format!(
            "{}-{};",
            url_encode(&id.to_string()),
            yes_no(valid)
        ));
    }
    let args = HttpExArgs {
        method: Method::Post,
        // The original joined the strings.
        url: format!("{origin}/{results_url}"),
        relative_to_origin: true,
        headers: Vec::new(),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: body.into_bytes().into(),
        timeout_ms: None,
    };
    let text = match http::request_ex(&args) {
        Ok(reply) if reply.status == 200 => return,
        // Unverified against the original: the reason phrase is the server's; the standard
        // one stands in for it.
        Ok(reply) => reason_phrase(reply.status).to_owned(),
        Err(_) => texts::text("UPLOAD_SIGN_VERIFY_RESULT_ERROR", locale).to_owned(),
    };
    let _ = dialogs::message(MessageKind::Error, &text);
}

fn yes_no(valid: bool) -> &'static str {
    if valid { "Y" } else { "N" }
}

/// The information window with the text of `key`.
fn info(key: &str, locale: Locale) {
    let _ = dialogs::message(MessageKind::Info, texts::text(key, locale));
}

/// Kalkan's `verifySignOld`: the first signer, its certificate among the CMS's with
/// digitalSignature and nonRepudiation, valid at its signingTime; no chain, no revocation.
/// The error type otherwise.
fn check(signature: &[u8], data: &[u8]) -> Result<(), &'static str> {
    const FAILED: &str = "SIGN_VERIFICATION_FAILED";
    let args = VerifyArgs {
        cms: signature.to_vec().into(),
        data: Some(data.to_vec().into()),
        at: VerifyAt::SigningTime,
        chain: Some(Vec::new()),
        revocation: Revocation::None,
        first_signer_only: true,
        require_key_usage: vec![KeyUsageBit::DigitalSignature, KeyUsageBit::NonRepudiation],
    };
    let report = pki::cms_verify(&args).map_err(|_| FAILED)?;
    let signer = report.signers.first().ok_or(FAILED)?;
    match signer.validity {
        Check::Fail(Problem::Expired) => return Err("VALIDITY_EXPIRED"),
        Check::Fail(Problem::NotYetValid) => return Err("NOT_YET_VALID"),
        _ => {}
    }
    match signer.signature {
        Check::Ok => Ok(()),
        _ => Err(FAILED),
    }
}

/// A non-empty `tsaURL`: a time-stamp, always of Kalkan's default TSA (the URL itself was
/// never used).
fn has_tsa(req: &Map<String, Value>) -> bool {
    !orgjson::opt_string(req, "tsaURL")
        .unwrap_or_default()
        .is_empty()
}

/// `GET url` on the page's site, with `cookie` if not empty.
fn download(url: &str, cookie: &str) -> Result<Vec<u8>, Failure> {
    match request(Method::Get, url, cookie, None, Vec::new()) {
        Ok(reply) if (200..300).contains(&reply.status) => Ok(reply.body.into_vec()),
        _ => Err(k2("DOWNLOAD_FILE_EXCEPTION")),
    }
}

/// The zip of `entries` (each `file_<n>` with its name in `file_name_mappings.xml`) uploaded
/// to `url` with `fields` (put in this order): the site's reply, or the error it names.
fn upload(
    url: &str,
    base: &str,
    entries: &[(&str, &[u8])],
    fields: &[(&str, &str)],
    cookie: &str,
) -> Outcome {
    // The original's temporary file needed a name of three characters or more.
    if base.chars().count() < 3 {
        return Err(k2("CREATE_REQUEST_ERROR"));
    }
    let names: Vec<String> = (1..=entries.len()).map(|n| format!("file_{n}")).collect();
    let mapping: Vec<(&str, &str)> = names
        .iter()
        .zip(entries)
        .map(|(file, (name, _))| (file.as_str(), *name))
        .collect();
    let line_separator = host::platform()
        .map(|p| p.line_separator)
        .unwrap_or_else(|_| "\n".to_owned());
    let mapping_xml =
        oncl_port_kit::props::store_to_xml("file name mapping", &mapping, &line_separator);
    let mut files: Vec<(&str, &[u8])> = names
        .iter()
        .zip(entries)
        .map(|(file, (_, data))| (file.as_str(), *data))
        .collect();
    files.push(("file_name_mappings.xml", mapping_xml.as_bytes()));
    let zip = oncl_port_kit::zip::deflated(&files);

    // `File.createTempFile(base, "_Signed.zip")`: the base and a random number.
    let random = host::random(8).map_err(|_| k2("CREATE_REQUEST_ERROR"))?;
    let number = u64::from_le_bytes(random.try_into().map_err(|_| k2("CREATE_REQUEST_ERROR"))?);
    let zip_name = format!("{base}{number}_Signed.zip");

    let keys: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    let mut parts: Vec<Part> = javamap::iteration_order(&keys, javamap::DEFAULT_CAPACITY)
        .into_iter()
        .map(|i| Part::field(fields[i].0, fields[i].1))
        .collect();
    parts.push(Part {
        // No space after `form-data;`: as the original wrote it.
        disposition: format!("form-data;name=\"file\"; filename=\"{zip_name}\""),
        content_type: Some("application/zip".to_owned()),
        data: zip,
    });
    let body = Multipart {
        boundary: BOUNDARY.to_owned(),
        parts,
    };
    let reply = request(
        Method::Post,
        url,
        cookie,
        Some(body.content_type()),
        body.body(),
    )
    .map_err(|_| k2("UPLOAD_FILE_EXCEPTION"))?;
    if reply.status != 200 {
        return Err(k2("UPLOAD_FILE_EXCEPTION"));
    }
    server_reply(String::from_utf8_lossy(&reply.body).into_owned())
}

/// The site's reply to an upload: `error: <TYPE>[,…]` names an error, `ошибка` anywhere is
/// `OTHER`; anything else is the result, untrimmed.
fn server_reply(body: String) -> Outcome {
    let trimmed = body.trim_matches(|c: char| c <= ' ');
    if trimmed.to_lowercase().starts_with("error:") {
        // `substring(7)`: one character after the colon skipped.
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() < 7 {
            return Err(k2("CREATE_REQUEST_ERROR"));
        }
        let rest: String = chars[7..].iter().collect();
        let mut name = rest.trim_matches(|c: char| c <= ' ').to_uppercase();
        if let Some(comma) = name.find(',')
            && comma > 0
        {
            name.truncate(comma);
        }
        return Err(match texts::error_type(&name) {
            Some(code) => k2(code),
            None => Failure::K2 {
                code: "OTHER",
                message: Some(name),
            },
        });
    }
    if trimmed.contains("ошибка") {
        return Err(k2("OTHER"));
    }
    Ok(body)
}

/// A request to `url` on the page's site (relative to its origin, or absolute and of the
/// same origin), with `cookie` if not empty.
fn request(
    method: Method,
    url: &str,
    cookie: &str,
    content_type: Option<String>,
    body: Vec<u8>,
) -> Result<HttpResponse, oncl_pdk::abi::HostError> {
    let headers = if cookie.is_empty() {
        Vec::new()
    } else {
        vec![Header {
            name: "Cookie".to_owned(),
            value: cookie.to_owned(),
        }]
    };
    let args = HttpExArgs {
        method,
        url: url.to_owned(),
        relative_to_origin: true,
        headers,
        content_type,
        body: Bytes::from(body),
        timeout_ms: None,
    };
    http::request_ex(&args)
}

/// The key dialog with the original's storages and no condition on the key.
fn choose() -> Result<Key, Failure> {
    let args = ChooseArgs {
        action: Action::Sign,
        storages: STORAGES.map(str::to_owned).to_vec(),
        filter: Filter {
            chain: Some(Vec::new()),
            allow_expired: true,
            allow_revoked: true,
            ..Filter::default()
        },
        detail: None,
    };
    keys::choose(&args)
        .ok()
        .flatten()
        .ok_or_else(|| k2("CANCEL"))
}

/// Kalkan's `createCAdES`, detached: contentType, signingTime, messageDigest and
/// signingCertificateV2, the signer certificate; with `timestamp`, a time-stamp of Kalkan's
/// default TSA. Any failure, the time-stamp's too, is `CREATE_CMS_ERROR`.
// Unverified against the original: the signed attributes of its older `createCAdES`
// variant, taken to be those of the current one.
fn cades(key: &Key, data: &[u8], timestamp: bool) -> Result<Vec<u8>, Failure> {
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
        timestamp: timestamp.then_some(TsaChoice::Kalkan),
    };
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
        Ok(CmsOutcome::TspFailed(_)) | Err(_) => Err(k2("CREATE_CMS_ERROR")),
    }
}

/// The iteration order of Java's `HashMap<Integer, _>` (16 buckets, doubled past three
/// quarters full) into which the distinct `keys` were put in order: their indices. Resizing
/// keeps the order within a bucket, so it is the insertion order sorted by final bucket.
/// (A bucket of nine or more keys, which Java would turn into a tree, is not modelled.)
fn integer_map_order(keys: &[i32]) -> Vec<usize> {
    let mut capacity = javamap::DEFAULT_CAPACITY;
    while keys.len() > capacity / 4 * 3 {
        capacity *= 2;
    }
    let bucket = |key: i32| {
        let h = key as u32;
        ((h ^ (h >> 16)) as usize) & (capacity - 1)
    };
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|&i| bucket(keys[i]));
    order
}

/// `URLEncoder.encode(s, "UTF-8")`.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The standard reason phrase of an HTTP status.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => " ",
    }
}

/// No reply: the connection closes, as the original's did on an exception it did not catch.
fn drop_connection() -> String {
    let _ = host::reply_drop();
    String::new()
}
