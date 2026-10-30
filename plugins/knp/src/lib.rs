//! The KNP module of the taxpayer's cabinet (ИС СОНО, `kz.inessoft.kgd.knp.ncalayer.
//! KNPModuleService`) as an OpenNCALayer plugin. No dialogs: the page sends the key store
//! (a PKCS#12 as a data URL, or a token reader), its password and the alias.
//!
//! A request is `{"command", "requestId", …}`. One org.json cannot read, without a string
//! `command`, without an origin or with an unknown command drops the connection, as the
//! original's uncaught exception does. Replies are the original's beans as org.json writes
//! them (Java `HashMap` order): `resultStatus`, `requestId` and the command's fields; any
//! failure is `{"resultStatus":{"resultCode":"ERROR"},"requestId":…}`.
//!
//! The SmartAuth commands call the service of the page's own host ([`smartauth`]).

mod keys;
mod smartauth;

use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host};
use smartauth::{Answer, Enum, P};

/// Why a command failed.
pub(crate) enum Fail {
    /// The general error.
    Generic,
    /// `error.cryptoError` with `resultStatus` `ERROR`.
    Crypto(&'static str),
    /// A reply of its own.
    Reply(String),
}

type Command = fn(&Ctx) -> Result<String, Fail>;

/// A command's request.
struct Ctx<'a> {
    args: &'a Map<String, Value>,
    request_id: &'a str,
    origin: &'a str,
}

const COMMANDS: &[(&str, Command)] = &[
    ("info", info),
    ("getAuthAccounts", accounts),
    ("getStorageType", storage_types),
    ("getStorageDevicesByType", storage_devices),
    ("hardwarePair", hardware_pair),
    ("attachDeviceToAccount", |_| Ok("null".to_owned())),
    ("getCertificates", certificates),
    ("signDocument", sign_document),
    ("accountStatus", account_status),
    ("getAgreementText", agreement_text),
    ("signAgreement", sign_agreement),
    ("cancelAgreement", cancel_agreement),
    ("changeAgreement", change_agreement),
    ("signUp", sign_up),
    ("confirmSignUp", confirm_sign_up),
    ("resetPassword", reset_password),
    ("confirmResetPassword", confirm_reset_password),
    ("changeConfirmationType", change_confirmation_type),
    (
        "confirmChangeConfirmationType",
        confirm_change_confirmation_type,
    ),
    ("changePassword", change_password),
    ("confirmChangePassword", confirm_change_password),
];

fn drop_connection() -> String {
    let _ = host::reply_drop();
    String::new()
}

fn handle(request: &Request) -> String {
    let Ok(JValue::Obj(object)) = orgjson::parse(&request.text) else {
        return drop_connection();
    };
    let args = object.to_map();
    let Ok(command) = orgjson::get_string(&args, "command") else {
        return drop_connection();
    };
    let Some(origin) = request.origin.as_deref() else {
        return drop_connection();
    };
    let Some((_, run)) = COMMANDS.iter().find(|(name, _)| *name == command) else {
        return drop_connection();
    };
    let Ok(request_id) = orgjson::get_string(&args, "requestId") else {
        return reply(Some("ERROR"), None).to_json();
    };
    let ctx = Ctx {
        args: &args,
        request_id,
        origin,
    };
    match run(&ctx) {
        Ok(text) | Err(Fail::Reply(text)) => text,
        Err(Fail::Generic) => reply(Some("ERROR"), Some(request_id)).to_json(),
        Err(Fail::Crypto(code)) => {
            let mut reply = reply(Some("ERROR"), Some(request_id));
            reply.put("error", error_of("cryptoError", code));
            reply.to_json()
        }
    }
}

oncl_pdk::plugin!(handle);

/// A reply with `resultStatus` (if any) and `requestId` (if read).
fn reply(code: Option<&str>, request_id: Option<&str>) -> JObject {
    let mut reply = JObject::hash_map();
    if let Some(code) = code {
        let mut status = JObject::hash_map();
        status.put("resultCode", code);
        reply.put("resultStatus", status);
    }
    reply.put_opt("requestId", request_id);
    reply
}

fn ok(ctx: &Ctx) -> JObject {
    reply(Some("OK"), Some(ctx.request_id))
}

fn error_of(key: &str, value: &str) -> JObject {
    let mut error = JObject::hash_map();
    error.put(key, value);
    error
}

/// A reply without `resultStatus`: `{"requestId":…,"error":{key: value}}`.
fn bare_error(ctx: &Ctx, key: &str, value: &str) -> Fail {
    let mut reply = reply(None, Some(ctx.request_id));
    reply.put("error", error_of(key, value));
    Fail::Reply(reply.to_json())
}

/// org.json `getString`: a missing or non-string field is the general error.
pub(crate) fn string(args: &Map<String, Value>, key: &str) -> Result<String, Fail> {
    orgjson::get_string(args, key)
        .map(str::to_owned)
        .map_err(|_| Fail::Generic)
}

/// A page enum field read with `valueOf`.
fn page_enum(args: &Map<String, Value>, key: &str, values: Enum) -> Result<i64, Fail> {
    smartauth::number(values, &string(args, key)?)
}

/// A `Long` field that may be absent or `null`.
fn opt_long(args: &Map<String, Value>, key: &str) -> Result<Option<i64>, Fail> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or(Fail::Generic),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|_| Fail::Generic),
        Some(_) => Err(Fail::Generic),
    }
}

// Local commands.

fn info(ctx: &Ctx) -> Result<String, Fail> {
    let mut reply = ok(ctx);
    reply.put("type", "personal");
    reply.put("version", "1.1.0");
    reply.put("status", "READY");
    Ok(reply.to_json())
}

fn accounts(ctx: &Ctx) -> Result<String, Fail> {
    let mut reply = ok(ctx);
    reply.put("accounts", JValue::Arr(Vec::new()));
    Ok(reply.to_json())
}

fn storage_types(ctx: &Ctx) -> Result<String, Fail> {
    let storages = [
        ("PKCS12", false),
        ("KAZTOKEN", true),
        ("KZIDCARD", true),
        ("ETOKEN_72K", true),
        ("JACARTA", true),
    ]
    .into_iter()
    .map(|(name, token)| {
        let mut storage = JObject::hash_map();
        storage.put("name", name);
        storage.put("token", token);
        JValue::Obj(storage)
    })
    .collect();
    let mut reply = ok(ctx);
    reply.put("storages", JValue::Arr(storages));
    Ok(reply.to_json())
}

/// The readers of a token type: every one for KAZTOKEN, the others without KAZTOKEN's.
fn storage_devices(ctx: &Ctx) -> Result<String, Fail> {
    let kind = string(ctx.args, "storage")?;
    let storage = keys::token_storage(&kind).ok_or(Fail::Generic)?;
    let terminals = oncl_pdk::keys::terminals(storage).map_err(|_| Fail::Generic)?;
    let terminals = terminals
        .into_iter()
        .filter(|name| kind == "KAZTOKEN" || !name.starts_with("DigiFlow LLP. KAZTOKEN"))
        .map(JValue::Str)
        .collect();
    let mut reply = ok(ctx);
    reply.put("tokenTerminals", JValue::Arr(terminals));
    Ok(reply.to_json())
}

fn hardware_pair(ctx: &Ctx) -> Result<String, Fail> {
    let mut token = JObject::hash_map();
    token.put("hardwareId", "hwtoken.hardwareId");
    token.put("id", "hwtoken.id");
    token.put("hash", "hwtoken.hash");
    token.put("parentId", "hwtoken.parentId");
    token.put("parentHash", "hwtoken.parentHash");
    let mut reply = ok(ctx);
    reply.put("hardwareKey", "hardwareKey");
    reply.put("token", token);
    Ok(reply.to_json())
}

fn certificates(ctx: &Ctx) -> Result<String, Fail> {
    let kind = string(ctx.args, "type")?;
    let path = string(ctx.args, "storagePath")?;
    let password = orgjson::opt_string(ctx.args, "password").unwrap_or_default();
    let keys = keys::open(&kind, &path, &password)?;
    let mut reply = ok(ctx);
    reply.put("certificates", keys::certificates(&keys)?);
    Ok(reply.to_json())
}

/// The XML of `signDocument` in its `inputFormat`.
fn input_xml(ctx: &Ctx) -> Result<String, Fail> {
    let xml = string(ctx.args, "xml")?;
    match string(ctx.args, "inputFormat")?.as_str() {
        "STRING" => Ok(xml),
        "BASE64" => oncl_pdk::javab64::decode_java(&xml)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or(Fail::Generic),
        _ => Err(Fail::Generic),
    }
}

fn sign_document(ctx: &Ctx) -> Result<String, Fail> {
    let key = keys::signing_key(ctx.args)?;
    let xml = input_xml(ctx)?;
    let signed = keys::sign_xml(&key, &xml)?;
    let signed = match string(ctx.args, "outputFormat")?.as_str() {
        "STRING" => signed,
        "BASE64" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(signed.as_bytes())
        }
        _ => return Err(Fail::Generic),
    };
    let mut reply = ok(ctx);
    reply.put("signedXml", signed);
    Ok(reply.to_json())
}

// SmartAuth commands.

/// `uinInfo` of the page's `uin` and `type`.
fn uin_info(ctx: &Ctx) -> Result<P, Fail> {
    let kind = page_enum(ctx.args, "type", smartauth::UIN_TYPE)?;
    Ok(smartauth::uin_info(kind, &string(ctx.args, "uin")?))
}

/// The reply to an `ERROR` result: its set error among `errors` (result field, reply key,
/// values), without `resultStatus`.
fn error_reply(ctx: &Ctx, result: &Map<String, Value>, errors: &[(&str, &str, Enum)]) -> Fail {
    for (field, key, values) in errors {
        if let Some(number) = result.get(*field).and_then(Value::as_i64) {
            return match smartauth::name(values, number) {
                Ok(name) => bare_error(ctx, key, name),
                Err(fail) => fail,
            };
        }
    }
    Fail::Reply(reply(None, Some(ctx.request_id)).to_json())
}

/// The success result of `call`, or the command's reply to an `ERROR`.
fn success(
    ctx: &Ctx,
    call: &str,
    action: &P,
    errors: &[(&str, &str, Enum)],
) -> Result<Map<String, Value>, Fail> {
    match smartauth::call(ctx.origin, call, action)? {
        Answer::Success(result) => Ok(result),
        Answer::Error(result) => Err(error_reply(ctx, &result, errors)),
    }
}

const UIN: (&str, &str, Enum) = (
    "uinValidationError",
    "uinValidationError",
    smartauth::UIN_VALIDATION_ERROR,
);
const USER_STATUS: (&str, &str, Enum) = (
    "userStatusError",
    "userStatusError",
    smartauth::USER_STATUS_ERROR,
);
const SIGNED_XML: (&str, &str, Enum) = (
    "signedXmlValidationError",
    "signedXmlValidationError",
    smartauth::SIGNED_XML_VALIDATION_ERROR,
);
const SENDING: (&str, &str, Enum) = (
    "sendingConfirmationError",
    "sendingConfirmationError",
    smartauth::SENDING_CONFIRMATION_ERROR,
);
const CHECK: (&str, &str, Enum) = (
    "checkConfirmationError",
    "checkConfirmationError",
    smartauth::CHECK_CONFIRMATION_ERROR,
);
const AUTH: (&str, &str, Enum) = ("authError", "authError", smartauth::AUTH_ERROR);
const AGREEMENT_STATUS: (&str, &str, Enum) = (
    "agreementStatusError",
    "agreementStatusError",
    smartauth::AGREEMENT_STATUS_ERROR,
);
const AUTH_AGREEMENT_STATUS: (&str, &str, Enum) = (
    "authAgreementStatusError",
    "agreementStatusError",
    smartauth::AGREEMENT_STATUS_ERROR,
);
const NEW_PASSWORD: (&str, &str, Enum) = (
    "newPasswordValidationError",
    "newPasswordValidationError",
    smartauth::NEW_PASSWORD_VALIDATION_ERROR,
);
const CREATE_XML: (&str, &str, Enum) = (
    "CreateAgreementXmlToSignError",
    "createAgreementXmlToSignError",
    smartauth::CREATE_AGREEMENT_XML_TO_SIGN_ERROR,
);

fn account_status(ctx: &Ctx) -> Result<String, Fail> {
    let action = P::Msg(vec![("uinInfo", uin_info(ctx)?)]);
    let result = success(ctx, "getUserStatus", &action, &[UIN])?;
    let mut reply = ok(ctx);
    reply.put(
        "userRegistrationStatus",
        smartauth::enum_field(
            &result,
            "userRegistrationStatus",
            smartauth::USER_REGISTRATION_STATUS,
        )?,
    );
    reply.put(
        "authAgreementStatus",
        smartauth::enum_field(&result, "authAgreementStatus", smartauth::AGREEMENT_STATUS)?,
    );
    reply.put(
        "signAgreementStatus",
        smartauth::enum_field(&result, "signAgreementStatus", smartauth::AGREEMENT_STATUS)?,
    );
    for field in [
        "authAgreementSignedFrom",
        "authAgreementSignedTo",
        "signAgreementSignedFrom",
        "signAgreementSignedTo",
    ] {
        reply.put_opt(field, result.get(field).and_then(Value::as_i64));
    }
    reply.put("rnn", smartauth::string_field(&result, "rnn"));
    reply.put("iinBin", smartauth::string_field(&result, "iinBin"));
    Ok(reply.to_json())
}

fn agreement_text(ctx: &Ctx) -> Result<String, Fail> {
    let types = orgjson::get_array(ctx.args, "agreementTypes").map_err(|_| Fail::Generic)?;
    let types = types
        .iter()
        .map(|t| {
            let name = t.as_str().ok_or(Fail::Generic)?;
            smartauth::number(smartauth::USER_AGREEMENT_TYPE, name).map(P::Int)
        })
        .collect::<Result<_, _>>()?;
    let action = P::Msg(vec![
        ("language", P::str(string(ctx.args, "lang")?)),
        ("agreementTypes", P::Arr(types)),
    ]);
    let result = match smartauth::call(ctx.origin, "getAgreementText", &action)? {
        Answer::Success(result) => result,
        // The base class's default error, typo included.
        Answer::Error(_) => return Err(bare_error(ctx, "errorCause", "Undefined sever error!")),
    };
    let infos = result
        .get("agreementTextInfos")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|info| {
            let info = info.as_object().ok_or(Fail::Generic)?;
            let mut out = JObject::hash_map();
            out.put("text", smartauth::string_field(info, "text"));
            out.put(
                "userAgreementTypeEnum",
                smartauth::enum_field(info, "agreementType", smartauth::USER_AGREEMENT_TYPE)?,
            );
            out.put("version", smartauth::string_field(info, "version"));
            Ok(JValue::Obj(out))
        })
        .collect::<Result<_, Fail>>()?;
    let mut reply = ok(ctx);
    reply.put("agreementTextInfos", JValue::Arr(infos));
    Ok(reply.to_json())
}

/// The checks of the agreement's period before any request.
fn check_period(ctx: &Ctx, kind: i64, from: Option<i64>, to: Option<i64>) -> Result<(), Fail> {
    let fail = |code: &str| {
        Err(bare_error(
            ctx,
            "createAgreementXmlToSignError",
            &format!("AGREEMENT_XML_GENERATION_{code}"),
        ))
    };
    let cancel = kind >= 100;
    if !cancel && from.is_none() {
        return fail("MUST_BE_WITH_PERIOD");
    }
    if cancel && (from.is_some() || to.is_some()) {
        return fail("MUST_BE_WITHOUT_PERIOD");
    }
    if let (Some(from), Some(to)) = (from, to) {
        let now = host::now().map_err(|_| Fail::Generic)? / 1000;
        if from > to {
            return fail("INVALID_PERIOD");
        }
        if from < now - 43_200 {
            return fail("FROM_IS_TOO_IN_PAST");
        }
        if to - from < 3_600 {
            return fail("TOO_SHORT_PERIOD");
        }
    }
    Ok(())
}

/// `createAgreementXmlToSign`, then the XML signed with the page's key.
fn signed_agreement(
    ctx: &Ctx,
    kind: i64,
    language: &str,
    period: (Option<i64>, Option<i64>),
) -> Result<String, Fail> {
    let mut fields = vec![
        ("uinInfo", uin_info(ctx)?),
        ("agreementType", P::Int(kind)),
        ("language", P::str(language)),
    ];
    if let Some(from) = period.0 {
        fields.push(("signFrom", P::Int(from)));
    }
    if let Some(to) = period.1 {
        fields.push(("signTo", P::Int(to)));
    }
    let result = success(
        ctx,
        "createAgreementXmlToSign",
        &P::Msg(fields),
        &[UIN, CREATE_XML],
    )?;
    let xml = smartauth::string_field(&result, "xmlToSign");
    let key = keys::signing_key(ctx.args)?;
    keys::sign_xml(&key, &xml)
}

fn sign_agreement(ctx: &Ctx) -> Result<String, Fail> {
    let kind = page_enum(
        ctx.args,
        "userAgreementType",
        smartauth::USER_AGREEMENT_TYPE,
    )?;
    let language = string(ctx.args, "lang")?;
    let from = opt_long(ctx.args, "signFrom")?;
    let to = opt_long(ctx.args, "signTo")?;
    check_period(ctx, kind, from, to)?;
    let signed = signed_agreement(ctx, kind, &language, (from, to))?;
    let mut reply = ok(ctx);
    reply.put("signedAgreement", signed);
    Ok(reply.to_json())
}

fn cancel_agreement(ctx: &Ctx) -> Result<String, Fail> {
    let kind = page_enum(
        ctx.args,
        "userAgreementType",
        smartauth::USER_AGREEMENT_TYPE,
    )?;
    let language = string(ctx.args, "language")?;
    let signed = signed_agreement(ctx, kind, &language, (None, None))?;
    let action = P::Msg(vec![
        ("uinInfo", uin_info(ctx)?),
        ("signedCancelAgreementXml", P::str(signed)),
    ]);
    success(
        ctx,
        "cancelAgreement",
        &action,
        &[SIGNED_XML, USER_STATUS, AGREEMENT_STATUS, UIN],
    )?;
    Ok(ok(ctx).to_json())
}

fn change_agreement(ctx: &Ctx) -> Result<String, Fail> {
    let auth = orgjson::opt_string(ctx.args, "signedAuthAgreementXml").unwrap_or_default();
    let sign = orgjson::opt_string(ctx.args, "signedSignAgreementXml").unwrap_or_default();
    if auth.is_empty() && sign.is_empty() {
        return Err(Fail::Generic);
    }
    let action = P::Msg(vec![
        ("uinInfo", uin_info(ctx)?),
        ("signedAuthAgreementXml", P::str(auth)),
        ("signedSignAgreementXml", P::str(sign)),
    ]);
    success(
        ctx,
        "updateUserAgreements",
        &action,
        &[USER_STATUS, UIN, SIGNED_XML, AGREEMENT_STATUS],
    )?;
    Ok(ok(ctx).to_json())
}

/// Whether `address` is an e-mail address by the original's pattern (`find` of
/// `^local@(ipv4(:port)?|(label.)+tld)$`, ASCII case-insensitive): the local part dot-separated
/// runs of `[A-Za-z0-9_'+*/^&=?~{}-]`; the domain an IPv4 literal with an optional port of up
/// to 3 digits, or labels of letters, digits and inner hyphens with a 2-6 letter top-level
/// label. `$` also matches before a final line terminator.
fn is_mail(address: &str) -> bool {
    let address = ["\r\n", "\n", "\r", "\u{85}", "\u{2028}", "\u{2029}"]
        .iter()
        .find_map(|end| address.strip_suffix(end))
        .unwrap_or(address);
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    let local_char = |c: char| c.is_ascii_alphanumeric() || "_'+*/^&=?~{}-".contains(c);
    let local_ok = local
        .split('.')
        .all(|run| !run.is_empty() && run.chars().all(local_char));
    local_ok && (is_ipv4_literal(domain) || is_host_name(domain))
}

/// `\d{1,3}(\.\d{1,3}){3}(:\d{1,3})?`.
fn is_ipv4_literal(domain: &str) -> bool {
    let digits = |s: &str| (1..=3).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    let (address, port) = match domain.split_once(':') {
        Some((address, port)) => (address, Some(port)),
        None => (domain, None),
    };
    let parts: Vec<&str> = address.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| digits(p)) && port.is_none_or(digits)
}

/// `(label\.)+[A-Za-z]{2,6}`, a label `[A-Za-z0-9][A-Za-z0-9-]+[A-Za-z0-9]` or
/// `[A-Za-z0-9]{1,2}`.
fn is_host_name(domain: &str) -> bool {
    let Some((labels, top)) = domain.rsplit_once('.') else {
        return false;
    };
    let label = |label: &str| {
        let bytes = label.as_bytes();
        match bytes.len() {
            1 | 2 => bytes.iter().all(u8::is_ascii_alphanumeric),
            n if n >= 3 => {
                bytes[0].is_ascii_alphanumeric()
                    && bytes[n - 1].is_ascii_alphanumeric()
                    && bytes
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            }
            _ => false,
        }
    };
    (2..=6).contains(&top.len())
        && top.bytes().all(|b| b.is_ascii_alphabetic())
        && labels.split('.').all(label)
}

/// `confirmationsSetting` of the page's `method` and `address`, the address checked.
fn confirmations(ctx: &Ctx, with_status: bool) -> Result<P, Fail> {
    let method = page_enum(ctx.args, "method", smartauth::CONFIRMATION_METHOD)?;
    let address = string(ctx.args, "address")?;
    let (valid, address, code) = if method == 0 {
        (
            is_mail(&address),
            address,
            "SENDING_CONFIRMATION_ILLEGAL_MAIL_FORMAT",
        )
    } else {
        let cleaned: String = address
            .chars()
            .filter(|c| !(c.is_whitespace() || "-()+_".contains(*c)))
            .collect();
        let valid =
            (3..=18).contains(&cleaned.len()) && cleaned.bytes().all(|b| b.is_ascii_digit());
        (valid, cleaned, "SENDING_CONFIRMATION_ILLEGAL_PHONE_FORMAT")
    };
    if !valid {
        if with_status {
            let mut reply = reply(Some("ERROR"), Some(ctx.request_id));
            reply.put("error", error_of("sendingConfirmationError", code));
            return Err(Fail::Reply(reply.to_json()));
        }
        return Err(bare_error(ctx, "sendingConfirmationError", code));
    }
    Ok(P::Msg(vec![
        ("method", P::Int(method)),
        ("address", P::str(address)),
    ]))
}

/// `sentConfirmationData` of a result.
fn sent_confirmation(result: &Map<String, Value>) -> Result<JObject, Fail> {
    let sent = result
        .get("sentConfirmationData")
        .and_then(Value::as_object)
        .ok_or(Fail::Generic)?;
    let mut out = JObject::hash_map();
    out.put(
        "usedMethod",
        smartauth::enum_field(sent, "usedMethod", smartauth::CONFIRMATION_METHOD)?,
    );
    out.put("operationId", smartauth::string_field(sent, "operationId"));
    Ok(out)
}

fn sent_reply(ctx: &Ctx, result: &Map<String, Value>) -> Result<String, Fail> {
    let mut reply = ok(ctx);
    reply.put("sentConfirmationData", sent_confirmation(result)?);
    Ok(reply.to_json())
}

fn sign_up(ctx: &Ctx) -> Result<String, Fail> {
    let uin = uin_info(ctx)?;
    let auth = string(ctx.args, "signedAuthAgreementXml")?;
    let sign = orgjson::opt_string(ctx.args, "signedSignAgreementXml");
    let language = string(ctx.args, "confirmationLanguage")?;
    let one_time =
        orgjson::get_boolean(ctx.args, "oneTimeHardwareTokenBlock").map_err(|_| Fail::Generic)?;
    let confirmations = confirmations(ctx, false)?;
    let mut fields = vec![
        ("uinInfo", uin),
        ("confirmationsSetting", confirmations),
        ("confirmationLanguage", P::str(language)),
        ("hardwareKey", P::str("HWKEY")),
        ("isOneTimeHardwareTokenBlock", P::Bool(one_time)),
        ("signedAuthAgreementXml", P::str(auth)),
    ];
    if let Some(sign) = sign {
        fields.push(("signedSignAgreementXml", P::str(sign)));
    }
    let result = success(
        ctx,
        "registerUser",
        &P::Msg(fields),
        &[USER_STATUS, UIN, SIGNED_XML, SENDING],
    )?;
    sent_reply(ctx, &result)
}

/// `confirmationData` of the page's `operationId` and `code`.
fn confirmation_data(ctx: &Ctx) -> Result<P, Fail> {
    Ok(P::Msg(vec![(
        "confirmationData",
        P::Msg(vec![
            ("operationId", P::str(string(ctx.args, "operationId")?)),
            ("code", P::str(string(ctx.args, "code")?)),
        ]),
    )]))
}

fn confirm_sign_up(ctx: &Ctx) -> Result<String, Fail> {
    let result = success(
        ctx,
        "registerUserConfirmation",
        &confirmation_data(ctx)?,
        &[USER_STATUS, CHECK],
    )?;
    let mut reply = ok(ctx);
    reply.put(
        "generatedPassword",
        smartauth::string_field(&result, "generatedPassword"),
    );
    reply.put("rnn", smartauth::string_field(&result, "rnn"));
    reply.put("iinBin", smartauth::string_field(&result, "iinBin"));
    Ok(reply.to_json())
}

fn reset_password(ctx: &Ctx) -> Result<String, Fail> {
    let action = P::Msg(vec![
        ("uinInfo", uin_info(ctx)?),
        (
            "confirmationLanguage",
            P::str(string(ctx.args, "confirmationLanguage")?),
        ),
    ]);
    let result = success(
        ctx,
        "resetPassword",
        &action,
        &[USER_STATUS, SENDING, AUTH_AGREEMENT_STATUS, UIN],
    )?;
    sent_reply(ctx, &result)
}

fn confirm_reset_password(ctx: &Ctx) -> Result<String, Fail> {
    let result = success(
        ctx,
        "resetPasswordConfirmation",
        &confirmation_data(ctx)?,
        &[USER_STATUS, CHECK],
    )?;
    let mut reply = ok(ctx);
    reply.put(
        "generatedPassword",
        smartauth::string_field(&result, "generatedPassword"),
    );
    Ok(reply.to_json())
}

/// `authInfo` of the page's `uin`, `type` and `password`, with the stub device.
fn auth_info(ctx: &Ctx) -> Result<P, Fail> {
    Ok(P::Msg(vec![
        ("uinInfo", uin_info(ctx)?),
        ("password", P::str(string(ctx.args, "password")?)),
        ("hardwareTokenBlock", smartauth::stub_token()),
        ("hardwareKey", P::str("hardwareKey")),
    ]))
}

fn change_confirmation_type(ctx: &Ctx) -> Result<String, Fail> {
    let auth = auth_info(ctx)?;
    let language = string(ctx.args, "confirmationLanguage")?;
    let confirmations = confirmations(ctx, true)?;
    let action = P::Msg(vec![
        ("authInfo", auth),
        ("confirmationsSetting", confirmations),
        ("confirmationLanguage", P::str(language)),
    ]);
    let result = success(
        ctx,
        "updateConfirmationsSetting",
        &action,
        &[AUTH, SENDING, USER_STATUS, AUTH_AGREEMENT_STATUS, UIN],
    )?;
    sent_reply(ctx, &result)
}

/// A confirmation whose `ERROR` the original fails to map: the general error.
fn confirm_without_errors(ctx: &Ctx, call: &str) -> Result<String, Fail> {
    match smartauth::call(ctx.origin, call, &confirmation_data(ctx)?)? {
        Answer::Success(_) => Ok(ok(ctx).to_json()),
        Answer::Error(_) => Err(Fail::Generic),
    }
}

fn confirm_change_confirmation_type(ctx: &Ctx) -> Result<String, Fail> {
    confirm_without_errors(ctx, "updateConfirmationsSettingConfirmation")
}

fn change_password(ctx: &Ctx) -> Result<String, Fail> {
    let action = P::Msg(vec![
        ("authInfo", auth_info(ctx)?),
        ("newPassword", P::str(string(ctx.args, "newPassword")?)),
        (
            "confirmationLanguage",
            P::str(string(ctx.args, "confirmationLanguage")?),
        ),
    ]);
    let result = success(
        ctx,
        "setPassword",
        &action,
        &[
            AUTH,
            NEW_PASSWORD,
            SENDING,
            USER_STATUS,
            AUTH_AGREEMENT_STATUS,
            UIN,
        ],
    )?;
    sent_reply(ctx, &result)
}

fn confirm_change_password(ctx: &Ctx) -> Result<String, Fail> {
    confirm_without_errors(ctx, "setPasswordConfirmation")
}
