//! NURSign (`kz.ecc.NurSignBundle` 5.1.2) as an OpenNCALayer plugin: `version`, `text` and
//! `multitext` (detached CAdES time-stamped by Kalkan's default TSA), `binary` (detached
//! CAdES of base64 data, from the page or downloaded), `xml` and `multixml` (enveloped
//! XMLDSig), and `file` (a file the user picks, signed, checked on the page's site by its
//! hashes and uploaded). Errors show a window and reply `500` with its text; a cancelled key
//! dialog replies `{}`. Downloads and uploads go only to hosts under `.gov.kz`, `.ecc.kz` and
//! `.minfin.kz`, as the original's default list.
#![cfg(target_arch = "wasm32")]

mod texts;

use oncl_pdk::abi::{
    Action, Bytes, ChooseArgs, ChooseFileArgs, CmsCerts, CmsContent, CmsOutcome, CoSign, ErrorCode,
    FileMode, Filter, HashAlg, HttpExArgs, HttpResponse, MessageKind, Method, NetFailure, NetKind,
    SignCmsExArgs, SignXmlExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource, TsaChoice,
    XmlOutput,
};
use oncl_pdk::javaexc::Throwable;
use oncl_pdk::keys::{self, Key};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{self, Map, Value};
use oncl_pdk::{Request, dialogs, files, host, http, javab64, javamap};
use oncl_port_kit::http::{Multipart, Part};
use oncl_port_kit::reply::{ecc, error_text};
use texts::Code;

/// The storages the key dialog offers: every token, then key files.
const STORAGES: [&str; 7] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
];

/// The hosts (and their subdomains) the plugin downloads from and uploads to.
const HOST_SUFFIXES: [&str; 3] = [".gov.kz", ".ecc.kz", ".minfin.kz"];

/// The largest file signed or downloaded: the original's default, 20 MiB.
const MAX_FILE_SIZE: usize = 20 * 1024 * 1024;

/// Why an operation did not give its reply.
enum Failure {
    /// The key dialog was cancelled: `{}`.
    Cancelled,
    /// No reply: the original's connection ended.
    Drop,
    /// An error with a text of the resource files.
    Code(Code),
    /// An error with a text of its own (the original showed the exception's).
    Message(String),
}

impl From<Code> for Failure {
    fn from(code: Code) -> Failure {
        Failure::Code(code)
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
    let outcome = match orgjson::opt_string(&req, "type")
        .unwrap_or_default()
        .as_str()
    {
        "version" => {
            let mut version = JObject::hash_map();
            version.put("version", "1.0.0");
            Ok(ecc(Some(JValue::Obj(version)), Some("NONE")))
        }
        "text" => sign_text(&req),
        "multitext" => sign_multitext(&request.text),
        "binary" => sign_binary(&req),
        "xml" => sign_xml(&req),
        "multixml" => sign_multixml(&req),
        "file" => sign_file(&req, origin),
        _ => return ecc(None, Some("500")),
    };
    match outcome {
        Ok(reply) => reply,
        Err(Failure::Cancelled) => ecc(None, None),
        Err(Failure::Drop) => drop_connection(),
        Err(Failure::Code(code)) => error(code.text(request.locale)),
        Err(Failure::Message(text)) => error(&text),
    }
}

oncl_pdk::plugin!(handle);

/// The error window, then the reply with its text.
fn error(text: &str) -> String {
    let _ = dialogs::message(MessageKind::Error, text);
    error_text(text, "500")
}

/// `text`: `data` (empty if absent) signed and time-stamped.
fn sign_text(req: &Map<String, Value>) -> Outcome {
    let data = orgjson::opt_string(req, "data").unwrap_or_default();
    let key = choose()?;
    let cms = cades(&key, data.as_bytes(), true)?;
    Ok(ecc(Some(base64(&cms).into()), Some("NONE")))
}

/// `multitext`: each value of the object `data`, in the order of Java's `HashMap` of its
/// keys, signed and time-stamped with one key; the first failure fails them all.
fn sign_multitext(text: &str) -> Outcome {
    let Ok(JValue::Obj(req)) = orgjson::parse(text) else {
        return Err(Failure::Drop);
    };
    let Some(JValue::Obj(data)) = req.get("data") else {
        return Err(Code::SignPlainDataFailed.into());
    };
    let key = choose()?;
    let mut items = JObject::hash_map();
    for (name, value) in data.iter() {
        let value = match value {
            JValue::Null => String::new(),
            other => other.java_string(),
        };
        let cms = cades(&key, value.as_bytes(), true)?;
        items.put(name, base64(&cms));
    }
    let mut result = JObject::hash_map();
    result.put("items", JValue::Obj(items));
    Ok(ecc(Some(JValue::Obj(result)), Some("NONE")))
}

/// `binary`: base64 `data`, or the file at `upload_url` (a download), signed without a
/// time-stamp; with any `need_hash`, the MD5 and SHA-256 of the base64 text.
fn sign_binary(req: &Map<String, Value>) -> Outcome {
    let data = if is_local(req) {
        orgjson::opt_string(req, "data").unwrap_or_default()
    } else {
        let url = orgjson::opt_string(req, "upload_url").unwrap_or_default();
        if url.is_empty() {
            return Err(Code::NotValidUrl.into());
        }
        let bytes = download(&url)?;
        if bytes.len() > MAX_FILE_SIZE {
            return Err(Code::MaxFileSizeExceeded.into());
        }
        base64(&bytes)
    };
    let key = choose()?;
    let content = javab64::decode_java(&data).map_err(|_| Code::SignPlainDataFailed)?;
    let cms = cades(&key, &content, false)?;
    let mut reply = JObject::hash_map();
    reply.put("result", base64(&cms));
    reply.put("errorCode", "NONE");
    if !orgjson::opt_string(req, "need_hash")
        .unwrap_or_default()
        .is_empty()
    {
        // Of the base64 text, not of the content, as the original.
        let (md5, sha256) = hashes(data.as_bytes())?;
        let mut hash = JObject::hash_map();
        hash.put("MD5", md5);
        hash.put("SHA256", sha256);
        reply.put("hash", JValue::Obj(hash));
    }
    Ok(reply.to_json())
}

/// `xml`: the document `data`, or the one at `upload_url`, signed.
fn sign_xml(req: &Map<String, Value>) -> Outcome {
    let xml = if is_local(req) {
        orgjson::get_string(req, "data")
            .map_err(|_| Code::SignPlainDataFailed)?
            .to_owned()
    } else {
        let url = orgjson::get_string(req, "upload_url").map_err(|_| Code::SignPlainDataFailed)?;
        download_xml(url)?
    };
    let key = choose()?;
    let signed = xmldsig(&key, &xml)?;
    Ok(ecc(Some(signed.into()), Some("NONE")))
}

/// `multixml`: each document of the array `data` (or the one at `upload_url`) signed, in
/// order. `data` that is not an array, or a cancelled key dialog, ended the original's
/// connection.
fn sign_multixml(req: &Map<String, Value>) -> Outcome {
    let docs = if is_local(req) {
        orgjson::opt_array(req, "data")
            .ok_or(Failure::Drop)?
            .to_vec()
    } else {
        let url = orgjson::opt_string(req, "upload_url").unwrap_or_default();
        vec![Value::String(download_xml(&url)?)]
    };
    let key = choose().map_err(|_| Failure::Drop)?;
    let mut signed = Vec::with_capacity(docs.len());
    for i in 0..docs.len() {
        let xml = orgjson::array_get_string(&docs, i).map_err(|_| Code::SignPlainDataFailed)?;
        signed.push(JValue::Str(xmldsig(&key, xml)?));
    }
    Ok(ecc(Some(JValue::Arr(signed)), Some("NONE")))
}

/// `file`: a file the user picks, signed; its hashes checked at the page's
/// `/ru/files/check_by_hash/`, then the signature (and the file, unless the site has it)
/// uploaded to `url_upload`; the reply is the site's object with `filePath` and `signature`.
fn sign_file(req: &Map<String, Value>, origin: &str) -> Outcome {
    let chooser = ChooseFileArgs {
        mode: FileMode::Open,
        title: Some("Открыть файл".to_owned()),
        filters: Vec::new(),
        initial_dir: None,
    };
    let file = match files::open_ex(&chooser) {
        Ok(Some(file)) => file,
        Ok(None) => return Err(Code::Cancel.into()),
        Err(e) if e.code == ErrorCode::Limit => return Err(Code::MaxFileSizeExceeded.into()),
        Err(_) => return Err(Code::FileNotFound.into()),
    };
    if file.data.len() > MAX_FILE_SIZE {
        return Err(Code::MaxFileSizeExceeded.into());
    }
    let data = base64(&file.data);
    let key = choose()?;
    let signature = base64(&cades(&key, &file.data, false)?);
    drop(key);
    let (md5, sha256) = hashes(data.as_bytes())?;

    if !host_allowed(origin) {
        return Err(Code::NotValidUrl.into());
    }
    let check = post(
        "/ru/files/check_by_hash/",
        true,
        "application/x-www-form-urlencoded; charset=UTF-8",
        format!("md5={md5}&sha256={sha256}").into_bytes(),
    );
    let have_file = match check {
        Ok(reply) if reply.status == 200 => reply.body.as_slice() != b"false",
        Ok(_) => return Err(Code::CheckFileExistError.into()),
        Err(e) => return Err(post_failure(&e)),
    };

    let token = orgjson::get_string(req, "token").map_err(|_| Code::SignPlainDataFailed)?;
    let url = orgjson::get_string(req, "url_upload").map_err(|_| Code::SignPlainDataFailed)?;
    if !host_allowed(url) {
        return Err(Code::NotValidUrl.into());
    }
    let name = file_name(&file.path);
    let fields: Vec<(&str, &str)> = if have_file {
        vec![
            ("SHA256", &sha256),
            ("signature", &signature),
            ("file_name", name),
            ("token", token),
            ("MD5", &md5),
        ]
    } else {
        vec![("signature", &signature), ("token", token)]
    };
    let keys: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    let mut parts: Vec<Part> = javamap::iteration_order(&keys, javamap::DEFAULT_CAPACITY)
        .into_iter()
        .map(|i| Part::field(fields[i].0, fields[i].1))
        .collect();
    parts.push(Part {
        // `fileName`, not `filename`: as the original wrote it.
        disposition: format!("form-data; name=\"userfile\"; fileName=\"{name}\""),
        content_type: Some("application/octet-stream".to_owned()),
        data: if have_file {
            Vec::new()
        } else {
            file.data.into_vec()
        },
    });
    let now = host::now().map_err(|_| Code::SignPlainDataFailed)?;
    let body = Multipart {
        boundary: format!("{now:x}"),
        parts,
    };
    let reply = match post(url, false, &body.content_type(), body.body()) {
        Ok(reply) => reply,
        Err(e) => return Err(post_failure(&e)),
    };
    match reply.status {
        200 => {}
        201..=299 => return Err(Code::UploadFileException.into()),
        _ => return Err(Code::SignPlainDataFailed.into()),
    }
    let text = String::from_utf8_lossy(&reply.body);
    let Ok(JValue::Obj(mut result)) = orgjson::parse(&text) else {
        return Err(Code::SignPlainDataFailed.into());
    };
    result.put("filePath", file.path.as_str());
    result.put("signature", signature.as_str());
    Ok(ecc(Some(JValue::Obj(result)), Some("NONE")))
}

/// `source` is absent, `null` or `"local"`.
fn is_local(req: &Map<String, Value>) -> bool {
    orgjson::opt_string(req, "source").is_none_or(|source| source == "local")
}

/// The base name of `path`.
fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Whether the URL's host ends with one of [`HOST_SUFFIXES`].
fn host_allowed(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|url| {
        url.host_str()
            .is_some_and(|host| HOST_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)))
    })
}

/// A download of `url`, a host under [`HOST_SUFFIXES`].
fn download(url: &str) -> Result<Vec<u8>, Failure> {
    // `new URL(url)` failing was another exception than the plugin's own: `OTHER`.
    if url::Url::parse(url).is_err() {
        return Err(Code::Other.into());
    }
    if !host_allowed(url) {
        return Err(Code::NotValidUrl.into());
    }
    let args = HttpExArgs {
        method: Method::Get,
        url: url.to_owned(),
        relative_to_origin: false,
        headers: Vec::new(),
        content_type: None,
        body: Bytes::new(),
        timeout_ms: None,
    };
    match http::request_ex(&args) {
        Ok(reply) if (200..300).contains(&reply.status) => Ok(reply.body.into_vec()),
        Ok(_) => Err(Code::DownloadFileException.into()),
        // Outside the manifest: `http://`, which the original allowed too.
        Err(e) if e.code == ErrorCode::Denied => Err(Code::NotValidUrl.into()),
        Err(e) if e.code == ErrorCode::Limit => Err(Code::MaxFileSizeExceeded.into()),
        Err(_) => Err(Code::DownloadFileException.into()),
    }
}

/// The text of the document at `url`: any failure is `DOWNLOAD_FILE_EXCEPTION`, an empty
/// URL `NOT_VALID_URL`.
fn download_xml(url: &str) -> Result<String, Failure> {
    if url.is_empty() {
        return Err(Code::NotValidUrl.into());
    }
    let bytes = download(url).map_err(|_| Code::DownloadFileException)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `POST url` (relative to the page's origin, or absolute).
fn post(
    url: &str,
    relative_to_origin: bool,
    content_type: &str,
    body: Vec<u8>,
) -> Result<HttpResponse, oncl_pdk::abi::HostError> {
    let args = HttpExArgs {
        method: Method::Post,
        url: url.to_owned(),
        relative_to_origin,
        headers: Vec::new(),
        content_type: Some(content_type.to_owned()),
        body: body.into(),
        timeout_ms: None,
    };
    http::request_ex(&args)
}

/// A failed request to the site: a host outside the manifest is `NOT_VALID_URL`; the rest
/// was the original's generic failure.
fn post_failure(error: &oncl_pdk::abi::HostError) -> Failure {
    if error.code == ErrorCode::Denied {
        Code::NotValidUrl.into()
    } else {
        // Unverified against the original: the text of a network failure of these requests.
        Code::SignPlainDataFailed.into()
    }
}

/// The MD5 and SHA-256 of `data`, lowercase hex.
fn hashes(data: &[u8]) -> Result<(String, String), Failure> {
    let sha256 = host::hash(HashAlg::Sha256, data).map_err(|_| Code::SignPlainDataFailed)?;
    let sha256 = sha256.iter().map(|b| format!("{b:02x}")).collect();
    Ok((oncl_port_kit::md5_hex(data), sha256))
}

/// The key dialog with every storage and no condition on the key: the original checked none.
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
    keys::choose(&args).ok().flatten().ok_or(Failure::Cancelled)
}

/// Kalkan's `createCAdES`, detached: contentType, signingTime, messageDigest and
/// signingCertificateV2, the signer certificate, an encapsulated CMS co-signed; with
/// `timestamp`, a time-stamp of Kalkan's default TSA, whose failure the original reported
/// as the network exception.
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
        output: oncl_pdk::abi::CmsOutput::Der,
    };
    match key.sign_cms_ex(args) {
        Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
        Ok(CmsOutcome::TspFailed(failure)) => Err(tsp_failure(&failure)),
        // Unverified against the original: the text of a failure to sign (a key the host
        // cannot use).
        Err(_) => Err(Code::SignPlainDataFailed.into()),
    }
}

/// The original's text of a failed time-stamp: the network exception's `toString()`.
fn tsp_failure(failure: &NetFailure) -> Failure {
    let exception = match failure.kind {
        NetKind::UnknownHost => Throwable::unknown_host(failure.address.as_str()),
        NetKind::Connect => Throwable::connect_refused(),
        NetKind::Timeout => Throwable::socket_timeout(false),
        // Unverified against the original: the texts of a TSA's HTTP error and of an invalid
        // or refused time-stamp.
        NetKind::Http(status) => Throwable::new(
            "java.io.IOException",
            Some(format!(
                "Server returned HTTP response code: {status} for URL: http://{}",
                failure.address
            )),
        ),
        _ => return Code::TimestampCreationFailure.into(),
    };
    Failure::Message(exception.to_string())
}

/// The whole document signed, without its XML declaration, as the original returned it.
fn xmldsig(key: &Key, xml: &str) -> Result<String, Failure> {
    let args = SignXmlExArgs {
        handle: key.handle(),
        xml: xml.as_bytes().to_vec().into(),
        element: None,
        parent: None,
        namespaces: Vec::new(),
        other_prefix_uri: None,
        placement: Default::default(),
        signature_method: None,
        digest_method: None,
        signed_info_c14n: None,
        transforms: None,
        signature_id: None,
        signing_time_object: None,
        strip_whitespace: true,
        base64_line_breaks: None,
        output: XmlOutput::Serialize {
            declaration: false,
            standalone_no: false,
            trim: true,
        },
    };
    // Unverified against the original: the parser's exception text of a malformed document.
    let signed = key
        .sign_xml_ex(args)
        .map_err(|_| Code::SignPlainDataFailed)?;
    Ok(String::from_utf8_lossy(&signed).into_owned())
}

/// No reply: the connection closes, as the original's did on an exception it did not catch.
fn drop_connection() -> String {
    let _ = host::reply_drop();
    String::new()
}

/// Base64 without line breaks.
fn base64(bytes: &[u8]) -> String {
    javab64::encode_mime(bytes).replace("\r\n", "")
}
