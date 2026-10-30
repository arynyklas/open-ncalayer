//! The Motiware module service (`ru.motiw.ModuleService`): without dialogs of its own, the
//! page names the storage, container and password. `getStoragesList`, `getContainerList`,
//! `getCertificateList` and `sign` work with tokens (key files have no containers, as in the
//! live original); `verify` checks a CMS; `showStorageKey` shows the key dialog.
//!
//! Replies are the original's `ResponseMessage` bean (`responseObject`, `code`, `message`,
//! `uuid`) as org.json writes it. Arguments are checked by count and Java type first.
#![cfg(target_arch = "wasm32")]

use der::{Decode, Encode};
use oncl_pdk::abi::{
    Action, Bytes, CmsCerts, CmsContent, CmsOutcome, CoSign, Filter, KeyOrder, KeySource, OpenArgs,
    OpenOutcome, Password, SignCmsExArgs, SignedAttrs, SigningTime, TimeForm, TimeSource,
    TsaChoice,
};
use oncl_pdk::keys::{self, Key, SelectArgs};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::pki::{self, Check, Problem, Revocation, VerifyArgs, VerifyAt};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host, javab64};
use oncl_port_pki::{cms_read, x509text};
use x509_cert::Certificate;

oncl_pdk::plugin!(handle);

/// Every Kalkan storage, in the iteration order of the original's `HashSet`.
const STORAGES: [&str; 9] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKJaCartaStore",
    "JKS",
    "ABCloudServiceStore",
    "PKCS12",
    "AKAKEYStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
];

/// The OID of the signatureTimeStampToken attribute.
const TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

/// A parameter type `validate` checks.
#[derive(Clone, Copy)]
enum Param {
    Str,
    Int,
    Bool,
}

impl Param {
    fn class(self) -> &'static str {
        match self {
            Param::Str => "String",
            Param::Int => "Integer",
            Param::Bool => "Boolean",
        }
    }

    fn accepts(self, value: &Value) -> bool {
        match self {
            Param::Str => value.is_string(),
            Param::Int => value.as_i64().is_some_and(|i| i32::try_from(i).is_ok()),
            Param::Bool => value.is_boolean(),
        }
    }
}

/// A reply: `responseObject`, `code`, `message` (`None` left out).
struct Reply {
    object: Option<JValue>,
    code: &'static str,
    message: Option<String>,
}

impl Reply {
    fn ok(object: JValue) -> Reply {
        Reply {
            object: Some(object),
            code: "200",
            message: Some(String::new()),
        }
    }

    /// An error with `responseObject` `""`, as the original's checks and lookups answer.
    fn failed(code: &'static str, message: String) -> Reply {
        Reply::caught(code, Some(message))
    }

    /// An exception `getCertificateList` or `sign` catches: `responseObject` `""`, `code`,
    /// the exception's message (`None`: a null message, left out).
    fn caught(code: &'static str, message: Option<String>) -> Reply {
        Reply {
            object: Some(JValue::Str(String::new())),
            code,
            message,
        }
    }

    /// An error of `verify`: without `responseObject`.
    fn error(message: Option<String>) -> Reply {
        Reply {
            object: None,
            code: "500",
            message,
        }
    }
}

fn handle(request: &Request) -> String {
    match answer(&request.text) {
        Some((reply, uuid)) => {
            let mut object = JObject::hash_map();
            object.put_opt("responseObject", reply.object);
            object.put("code", reply.code);
            object.put_opt("message", reply.message);
            object.put("uuid", uuid);
            object.to_json()
        }
        // The original has no `try` here: the exception drops the connection.
        None => {
            let _ = host::reply_drop();
            String::new()
        }
    }
}

/// The reply and the `uuid`; `None` to drop the connection.
fn answer(text: &str) -> Option<(Reply, String)> {
    let JValue::Obj(root) = orgjson::parse(text).ok()? else {
        return None;
    };
    let root = root.to_map();
    let method = orgjson::get_string(&root, "method").ok()?;
    let uuid = orgjson::opt_string(&root, "uuid").unwrap_or_default();
    let reply = match method {
        "getStoragesList" => storages(),
        "getContainerList" => match validate(&root, &[Param::Str])? {
            Ok(args) => containers(args[0].as_str()?)?,
            Err(reply) => reply,
        },
        "getCertificateList" => match validate(&root, &[Param::Str; 3])? {
            Ok(args) => certificate_list(str_at(args, 0)?, str_at(args, 1)?, str_at(args, 2)?),
            Err(reply) => reply,
        },
        "sign" => {
            let params = [
                Param::Str,
                Param::Str,
                Param::Str,
                Param::Str,
                Param::Str,
                Param::Int,
                Param::Bool,
            ];
            match validate(&root, &params)? {
                Ok(args) => sign(args)?,
                Err(reply) => reply,
            }
        }
        "verify" => match validate(&root, &[Param::Str; 2])? {
            Ok(args) => verify(str_at(args, 0)?, str_at(args, 1)?)?,
            Err(reply) => reply,
        },
        "showStorageKey" => {
            // The original shows commonUtils' key dialog and drops its result.
            let _ = keys::select(&SelectArgs {
                action: Action::KeyInfo,
                storages: vec!["PKCS12".to_owned()],
                filter: Filter {
                    allow_expired: true,
                    chain: Some(Vec::new()),
                    allow_revoked: true,
                    ..Filter::default()
                },
                more: Default::default(),
                detail: None,
                initial_path: None,
                order: KeyOrder::OldestFirst,
            });
            Reply {
                object: None,
                code: "200",
                message: None,
            }
        }
        _ => Reply {
            object: None,
            code: "404",
            message: Some("Method not found".to_owned()),
        },
    };
    Some((reply, uuid))
}

fn str_at(args: &[Value], i: usize) -> Option<&str> {
    args.get(i).and_then(Value::as_str)
}

/// `Class.toString()` of the value org.json holds.
fn java_class(value: &Value) -> &'static str {
    match value {
        Value::Null => "class org.json.JSONObject$Null",
        Value::Bool(_) => "class java.lang.Boolean",
        Value::Number(n) => match n.as_i64() {
            Some(i) if i32::try_from(i).is_ok() => "class java.lang.Integer",
            Some(_) => "class java.lang.Long",
            None if n.is_u64() => "class java.math.BigInteger",
            None => "class java.math.BigDecimal",
        },
        Value::String(_) => "class java.lang.String",
        Value::Array(_) => "class org.json.JSONArray",
        Value::Object(_) => "class org.json.JSONObject",
    }
}

/// The original's `validate`: `args` (absent: a NullPointerException, `None`), its length,
/// then the Java class of each argument.
fn validate<'a>(
    root: &'a Map<String, Value>,
    params: &[Param],
) -> Option<Result<&'a [Value], Reply>> {
    let args = orgjson::opt_array(root, "args")?;
    if args.len() < params.len() {
        return Some(Err(Reply::failed(
            "400",
            format!(
                "Error length params. Actual {}, expected: {}",
                args.len(),
                params.len()
            ),
        )));
    }
    for (i, (param, value)) in params.iter().zip(args).enumerate() {
        if !param.accepts(value) {
            // Unverified against the original: `Actual` as `Class.toString()`.
            return Some(Err(Reply::failed(
                "400",
                format!(
                    "Error type param[{i}]. Actual {}, expected: class java.lang.{}",
                    java_class(value),
                    param.class()
                ),
            )));
        }
    }
    Some(Ok(args))
}

/// Whether `storage` is a token (it has readers to name).
fn is_token(storage: &str) -> bool {
    STORAGES.contains(&storage) && !matches!(storage, "PKCS12" | "JKS")
}

/// `getStoragesList`: `PKCS12` and every token storage with a reader.
fn storages() -> Reply {
    let present = STORAGES
        .iter()
        .filter(|name| {
            **name == "PKCS12"
                || (is_token(name) && keys::terminals(name).is_ok_and(|r| !r.is_empty()))
        })
        .map(|name| JValue::Str((*name).to_owned()))
        .collect();
    Reply::ok(JValue::Arr(present))
}

/// `getContainerList(storage)`: a token's readers; key files have none (the original lists
/// the core's remembered keys, which its live core never had). `None` for an unknown
/// storage.
fn containers(storage: &str) -> Option<Reply> {
    if !STORAGES.contains(&storage) {
        return None;
    }
    if !is_token(storage) {
        return Some(Reply::ok(JValue::Arr(Vec::new())));
    }
    let readers = keys::terminals(storage).unwrap_or_default();
    Some(Reply::ok(JValue::Arr(
        readers
            .into_iter()
            .map(|reader| {
                let mut container = JObject::hash_map();
                container.put("path", reader);
                container.put("serial", storage);
                JValue::Obj(container)
            })
            .collect(),
    )))
}

/// The keys of the token `storage` in the reader `container` (none for an empty token), or
/// the reply why not.
fn open(storage: &str, container: &str, password: &str) -> Result<Vec<Key>, Reply> {
    if !is_token(storage) {
        if STORAGES.contains(&storage) {
            return Err(Reply::failed(
                "404",
                format!("Not found container by serial: {container}"),
            ));
        }
        // `Storage.get` of an unknown name is null: a NullPointerException, caught.
        return Err(Reply::caught("500", None));
    }
    let outcome = keys::open(&OpenArgs {
        storage: storage.to_owned(),
        source: KeySource::Terminal(container.to_owned()),
        password: Password::Text(password.to_owned()),
    })
    .map_err(|e| Reply::caught("500", Some(e.message)))?;
    // Unverified against the original: Kalkan's texts of a token that does not open.
    let message = match outcome {
        Ok(keys) => return Ok(keys),
        Err(OpenOutcome::NoKeys) => return Ok(Vec::new()),
        Err(OpenOutcome::WrongPassword { .. }) => "Wrong password",
        Err(OpenOutcome::Blocked) => "Token is blocked",
        Err(OpenOutcome::NoDevice | OpenOutcome::NotFound) => "Token not found",
        Err(OpenOutcome::Declined) => "Access denied",
        Err(OpenOutcome::Corrupt | OpenOutcome::Opened(_)) => "Token is not readable",
    };
    Err(Reply::caught("500", Some(message.to_owned())))
}

/// `getCertificateList(storage, container, password)`.
fn certificate_list(storage: &str, container: &str, password: &str) -> Reply {
    match open(storage, container, password) {
        Ok(keys) => Reply::ok(JValue::Arr(
            keys.iter()
                .filter_map(|key| certificate_info(key.certificate(), Some(key.alias()), None))
                .map(JValue::Obj)
                .collect(),
        )),
        Err(reply) => reply,
    }
}

/// `sign(storage, container, password, alias, data, format, attach)`: a CAdES, time-stamped
/// by Kalkan's default TSA for `format > 1`. `None` drops the connection.
fn sign(args: &[Value]) -> Option<Reply> {
    let (storage, container, password, alias, data) = (
        str_at(args, 0)?,
        str_at(args, 1)?,
        str_at(args, 2)?,
        str_at(args, 3)?,
        str_at(args, 4)?,
    );
    let format = args[5].as_i64()?;
    let attach = args[6].as_bool()?;
    let keys = match open(storage, container, password) {
        Ok(keys) => keys,
        Err(reply) => return Some(reply),
    };
    let Some(key) = keys.iter().find(|key| key.alias() == alias) else {
        return Some(Reply::caught("500", None));
    };
    let bytes = match javab64::decode_java(data) {
        Ok(bytes) => bytes,
        Err(e) => return Some(Reply::caught("500", Some(e))),
    };
    let signed = key.sign_cms_ex(SignCmsExArgs {
        handle: key.handle(),
        content: CmsContent::Data(Bytes::from(bytes)),
        encapsulate: attach,
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
        timestamp: (format > 1).then_some(TsaChoice::Kalkan),
    });
    let cms = match signed {
        Ok(CmsOutcome::Signed(cms)) => cms.into_vec(),
        Ok(CmsOutcome::TspFailed(failure)) => {
            return Some(Reply::caught("500", Some(failure.detail)));
        }
        Err(e) => return Some(Reply::caught("500", Some(e.message))),
    };
    let signers = cms_read::signers(&cms);
    let tst = last_time_stamp(&cms);
    let certificates = signers
        .iter()
        .filter_map(|signer| signer.sid_cert.as_deref())
        .filter_map(|cert| certificate_info(cert, None, tst.as_ref()))
        .map(JValue::Obj)
        .collect();
    let mut object = JObject::hash_map();
    object.put("certificates", JValue::Arr(certificates));
    object.put("signature", javab64::encode_mime(&cms).replace("\r\n", ""));
    Some(Reply::ok(JValue::Obj(object)))
}

/// The time-stamp of the last signer of `cms` that has one, which the original puts on
/// every certificate it lists.
fn last_time_stamp(cms: &[u8]) -> Option<TimeStamp> {
    cms_read::signers(cms)
        .iter()
        .rev()
        .find_map(|signer| signer.unsigned_attrs.as_deref().and_then(time_stamp))
}

/// `verify(cms, data)`: base64 errors drop the connection (`None`); provider_util's checks
/// as its codes.
fn verify(cms: &str, data: &str) -> Option<Reply> {
    let cms = javab64::decode_java(cms).ok()?;
    let tst = last_time_stamp(&cms);
    let data = javab64::decode_java(data).ok()?;
    let data = (!data.is_empty()).then(|| Bytes::from(data));
    let detached = data.is_none();
    let report = match pki::cms_verify(&VerifyArgs {
        cms: Bytes::from(cms),
        data,
        at: VerifyAt::Now,
        chain: Some(Vec::new()),
        revocation: Revocation::None,
        first_signer_only: false,
        require_key_usage: Vec::new(),
    }) {
        Ok(report) => report,
        Err(e) => return Some(Reply::error(Some(e.message))),
    };
    let code = |code: &str| Some(Reply::error(Some(code.to_owned())));
    if detached && report.content.is_none() {
        return code("CMS_NO_ENCAPSULATED_DATA");
    }
    if report.signers.is_empty() {
        return code("SIGNER_CERTIFICATE_NOT_FOUND");
    }
    let mut certificates = Vec::new();
    for signer in &report.signers {
        let Some(cert) = &signer.certificate else {
            return code("SIGNER_CERTIFICATE_NOT_FOUND");
        };
        if matches!(signer.validity, Check::Fail(_)) {
            return code("CERTIFICATE_DATE_NOT_VALID");
        }
        match &signer.signature {
            Check::Fail(Problem::NoContent) => return code("CMS_NO_ENCAPSULATED_DATA"),
            Check::Fail(_) => return code("CMS_SIGNATURE_NOT_VALID"),
            _ => {}
        }
        if matches!(signer.ess_cert_id, Check::Fail(_)) {
            return code("CMS_ESSCERTIDV2_DIFF_CERTHASH");
        }
        certificates.extend(certificate_info(cert, None, tst.as_ref()).map(JValue::Obj));
    }
    let mut object = JObject::hash_map();
    object.put("certificates", JValue::Arr(certificates));
    Some(Reply::ok(JValue::Obj(object)))
}

/// A signer's time-stamp: serial (hex), genTime (Unix milliseconds) and the TSA name.
struct TimeStamp {
    serial: String,
    gen_time_ms: Option<i64>,
    tsa: Option<String>,
}

/// The `CertificateInfo` bean of `cert` (a `HashMap` of 16 buckets, `null`s left out).
fn certificate_info(cert: &[u8], alias: Option<&str>, tst: Option<&TimeStamp>) -> Option<JObject> {
    let info = host::cert_info(cert).ok()?;
    let parsed = Certificate::from_der(cert).ok()?;
    let tbs = parsed.tbs_certificate();
    let subject = x509text::rfc2253(&tbs.subject().to_der().ok()?).ok()?;
    let issuer = x509text::rfc2253(&tbs.issuer().to_der().ok()?).ok()?;
    let mut object = JObject::hash_map();
    // Keys sharing a bucket go in the getter order assumed (serialNumber before tsa, issuer
    // before notBefore, algorithm before sigAlgName).
    object.put_opt("timeStampDate", tst.and_then(|t| t.gen_time_ms));
    object.put("notAfter", info.not_after);
    object.put("serialNumber", big_integer_hex(&info.serial_hex));
    object.put_opt("tsa", tst.and_then(|t| t.tsa.clone()));
    object.put("subject", subject);
    object.put_opt("timeStampSerialNumber", tst.map(|t| t.serial.clone()));
    object.put_opt("alias", alias);
    object.put("issuer", issuer);
    object.put("notBefore", info.not_before);
    object.put(
        "algorithm",
        x509text::kalkan_key_alg_name(&info.spki_alg_oid).unwrap_or(&info.spki_alg_oid),
    );
    object.put(
        "sigAlgName",
        x509text::kalkan_sig_alg_name(&info.signature_alg_oid).unwrap_or(&info.signature_alg_oid),
    );
    Some(object)
}

/// `BigInteger.toString(16)` of a positive integer given as the hex of its DER content.
fn big_integer_hex(hex: &str) -> String {
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// A DER TLV: its tag, the whole TLV, its content and what follows.
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// The first DER TLV of `input`.
fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        let len = input
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |len, b| (len << 8) | usize::from(*b));
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((
        tag,
        input.get(..end)?,
        input.get(head..end)?,
        input.get(end..)?,
    ))
}

/// The TLVs of `content`: tag, whole TLV, content.
fn children(mut content: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut out = Vec::new();
    while let Some((tag, whole, inner, rest)) = tlv(content) {
        out.push((tag, whole, inner));
        content = rest;
    }
    out
}

/// The time-stamp in the unsigned attributes `attrs` (a DER SET OF Attribute).
fn time_stamp(attrs: &[u8]) -> Option<TimeStamp> {
    let (_, _, set, _) = tlv(attrs)?;
    // The first value of the attribute's SET: the token, a ContentInfo.
    let token = children(set).into_iter().find_map(|(_, _, attr)| {
        let parts = children(attr);
        let oid = der::asn1::ObjectIdentifier::from_bytes(parts.first()?.2).ok()?;
        if oid.to_string() != TIME_STAMP_TOKEN {
            return None;
        }
        children(parts.get(1)?.2)
            .first()
            .map(|(_, whole, _)| *whole)
    })?;
    let tst_info = cms_read::content(token)?;
    let (_, _, fields, _) = tlv(&tst_info)?;
    let fields = children(fields);
    let serial: String = fields
        .get(3)?
        .2
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let gen_time_ms = fields
        .get(4)
        .and_then(|(_, _, time)| generalized_time_ms(std::str::from_utf8(time).ok()?));
    // tsa [0] EXPLICIT GeneralName; a directoryName [4] EXPLICIT Name: BC writes `4: ` and
    // the name in its encoded order.
    // Unverified against the original: BC's attribute symbols in the name.
    let tsa = fields
        .iter()
        .find(|(tag, _, _)| *tag == 0xa0)
        .and_then(|(_, _, general)| {
            let (tag, _, name, _) = tlv(general)?;
            if tag != 0xa4 {
                return None;
            }
            let (_, name, _, _) = tlv(name)?;
            let rfc = x509text::rfc2253(name).ok()?;
            Some(format!("4: {}", reverse_rdns(&rfc)))
        });
    Some(TimeStamp {
        serial: big_integer_hex(&serial),
        gen_time_ms,
        tsa,
    })
}

/// An RFC 2253 name with its RDNs in the other order.
fn reverse_rdns(rfc: &str) -> String {
    let mut parts = Vec::new();
    let (mut part, mut escaped) = (String::new(), false);
    for c in rfc.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ',' {
            parts.push(std::mem::take(&mut part));
            continue;
        }
        part.push(c);
    }
    parts.push(part);
    parts.reverse();
    parts.join(",")
}

/// Unix milliseconds of a GeneralizedTime `YYYYMMDDHHMMSS[.f]Z`.
fn generalized_time_ms(text: &str) -> Option<i64> {
    let digits = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (hour, minute, second) = (digits(8..10)?, digits(10..12)?, digits(12..14)?);
    let millis = match text.get(14..15) {
        Some(".") => {
            let fraction: String = text[15..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            format!("{fraction:0<3}")[..3].parse::<i64>().ok()?
        }
        _ => 0,
    };
    // Days from 1970-01-01 (proleptic Gregorian).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis)
}
