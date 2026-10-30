//! The Alatau City Bank Business API module (`kz.acbank.business.api.ncalayer.module`) as an
//! OpenNCALayer plugin.
//!
//! Requests are `{"apiVersion"?, "method", "args"?}`; one org.json cannot read, or without a
//! string `method`, drops the connection as the original's uncaught exception does.
//! Replies: `{"code":"success","message":null,"body":{…},"status":true}` or
//! `{"code":"<code>","status":false}`.
//!
//! - `healthcheck {ping: true}`: `{"healthcheck":true}` while a signing window is open
//!   (in any session: the plugin's shared state, for 15 minutes from its opening).
//! - `signJsonWithJws` (compact JWS) and `multiSignJsonWithJws` (JWS JSON, `INITIAL` or
//!   `SUBSEQUENT`): the items are checked, shown, a PKCS#12 key of type SIGNATURE chosen,
//!   and each item signed with GOST 2015-512 (`jws`).

mod jws;
mod texts;

use jws::{Item, Mode, Operation};
use oncl_pdk::abi::{Action, Filter, FilterMore, MessageKind, SelectArgs};
use oncl_pdk::dialogs::{self, ChoiceArgs};
use oncl_pdk::keys::{self, Key};
use oncl_pdk::orgjson::{self, JObject, JValue};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{Request, host, shared};
use texts::Texts;

/// The shared key of the open signing window.
const WINDOW: &str = "window";

/// How long `healthcheck` sees a window as open: the original's 15-minute idle lock.
const WINDOW_TTL_MS: u64 = 15 * 60 * 1000;

/// The most bytes of a dialog text (the host takes 16 KiB).
const MAX_TEXT: usize = 15 << 10;

/// The most bytes of a dialog line (the host takes 1 KiB).
const MAX_LINE: usize = 1000;

/// The error codes of the original's `WindowClientException`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Code {
    MethodNotFound,
    LocaleIncorrect,
    AlreadyRunning,
    Empty,
    NoContent,
    NoContentType,
    IncorrectContentType,
    IncorrectContent,
    IncorrectOperation,
    WindowClosed,
    PingWhat,
    Inactive,
    Unexpected,
}

impl Code {
    fn text(self) -> &'static str {
        match self {
            Code::MethodNotFound => "ncalayer.module.method.not-found",
            Code::LocaleIncorrect => "ncalayer.module.settings.locale.incorrect",
            Code::AlreadyRunning => "ncalayer.module.session.already-running",
            Code::Empty => "ncalayer.module.sign.signable-data.empty",
            Code::NoContent => "ncalayer.module.sign.signable-data.has-no-content",
            Code::NoContentType => "ncalayer.module.sign.signable-data.has-no-content-type",
            Code::IncorrectContentType => {
                "ncalayer.module.sign.signable-data.has-incorrect-content-type"
            }
            Code::IncorrectContent => "ncalayer.module.sign.signable-data.has-incorrect-content",
            Code::IncorrectOperation => {
                "ncalayer.module.sign.signable-data.has-incorrect-signature-operation"
            }
            Code::WindowClosed => "ncalayer.module.window.closed",
            Code::PingWhat => "ncalayer.module.healthcheck.ping.what",
            Code::Inactive => "ncalayer.module.healthcheck.session.inactive",
            Code::Unexpected => "ncalayer.module.unexpected-error",
        }
    }
}

fn handle(request: &Request) -> String {
    let Some((method, args)) = read(&request.text) else {
        let _ = host::reply_drop();
        return String::new();
    };
    let result = match method.as_str() {
        "healthcheck" => healthcheck(args.as_ref()),
        "signJsonWithJws" => sign(args.as_ref(), Mode::Compact),
        "multiSignJsonWithJws" => sign(args.as_ref(), Mode::Json),
        _ => Err(Code::MethodNotFound),
    };
    let mut reply = JObject::hash_map();
    match result {
        Ok(body) => {
            reply.put("status", true);
            reply.put("code", "success");
            reply.put("message", JValue::Null);
            reply.put("body", body);
        }
        Err(code) => {
            reply.put("status", false);
            reply.put("code", code.text());
        }
    }
    reply.to_json()
}

oncl_pdk::plugin!(handle);

/// `method` and `args` (`optJSONObject`) of the request; `None` where the original throws.
fn read(text: &str) -> Option<(String, Option<Map<String, Value>>)> {
    let JValue::Obj(request) = orgjson::parse(text).ok()? else {
        return None;
    };
    let map = request.to_map();
    let method = orgjson::get_string(&map, "method").ok()?.to_owned();
    let args = orgjson::opt_object(&map, "args").cloned();
    Some((method, args))
}

/// `healthcheck`.
fn healthcheck(args: Option<&Map<String, Value>>) -> Result<JObject, Code> {
    let args = args.ok_or(Code::Unexpected)?;
    if !orgjson::opt_boolean(args, "ping", false) {
        return Err(Code::PingWhat);
    }
    if window_open() {
        let mut body = JObject::hash_map();
        body.put("healthcheck", true);
        Ok(body)
    } else {
        Err(Code::Inactive)
    }
}

fn window_open() -> bool {
    matches!(shared::get(WINDOW), Ok(Some(_)))
}

/// The window's mark in the shared state, removed when the flow ends.
struct WindowMark;

impl WindowMark {
    fn open() -> WindowMark {
        let _ = shared::put(WINDOW, Some(b"1"), Some(WINDOW_TTL_MS));
        WindowMark
    }
}

impl Drop for WindowMark {
    fn drop(&mut self) {
        let _ = shared::put(WINDOW, None, None);
    }
}

/// Whether `s` is empty or whitespace (`StringUtils.isBlank`).
fn is_blank(s: &str) -> bool {
    s.chars().all(char::is_whitespace)
}

/// The window's language: `settings.locale` (`kk`, `ru`, `en` in any case), Russian by
/// default.
fn locale(args: &Map<String, Value>) -> Result<Texts, Code> {
    let Some(locale) =
        orgjson::opt_object(args, "settings").and_then(|s| orgjson::opt_string(s, "locale"))
    else {
        return Ok(Texts::RU);
    };
    // Unverified against the original: an empty locale string is taken as an incorrect one.
    match locale.to_lowercase().as_str() {
        "ru" => Ok(Texts::RU),
        "kk" => Ok(Texts::KK),
        "en" => Ok(Texts::EN),
        _ => Err(Code::LocaleIncorrect),
    }
}

/// The request's items, as the original maps them.
fn items(args: &Map<String, Value>) -> Result<Vec<Item>, Code> {
    let Some(list) = orgjson::opt_array(args, "signableItems") else {
        return Ok(Vec::new());
    };
    list.iter()
        .map(|item| {
            let item = item.as_object().ok_or(Code::Unexpected)?;
            let get = |key| {
                orgjson::get_string(item, key)
                    .map(str::to_owned)
                    .map_err(|_| Code::Unexpected)
            };
            Ok(Item {
                id: get("id")?,
                name: get("name")?,
                content: get("content")?,
                content_type: orgjson::opt_string(item, "contentType"),
                span_id: orgjson::opt_string(item, "spanId").unwrap_or_default(),
            })
        })
        .collect()
}

/// `signatureOperation`: absent or empty is none; otherwise an exact name.
fn operation(args: &Map<String, Value>) -> Result<Option<Operation>, Code> {
    match orgjson::opt_string(args, "signatureOperation").as_deref() {
        None | Some("") => Ok(None),
        Some("INITIAL") => Ok(Some(Operation::Initial)),
        Some("SUBSEQUENT") => Ok(Some(Operation::Subsequent)),
        Some(_) => Err(Code::IncorrectOperation),
    }
}

/// The checks of the items, in the original's order.
fn validate(items: &[Item], mode: Mode) -> Result<(), Code> {
    if items.is_empty() {
        return Err(Code::Empty);
    }
    for item in items {
        if is_blank(&item.content) {
            return Err(Code::NoContent);
        }
        let content_type = item.content_type.as_deref().unwrap_or("");
        if is_blank(content_type) {
            return Err(Code::NoContentType);
        }
        if !content_type.eq_ignore_ascii_case("application/json")
            && !content_type.eq_ignore_ascii_case("json")
        {
            return Err(Code::IncorrectContentType);
        }
        if mode == Mode::Compact && !matches!(orgjson::parse(&item.content), Ok(JValue::Obj(_))) {
            return Err(Code::IncorrectContent);
        }
    }
    Ok(())
}

/// `signJsonWithJws` and `multiSignJsonWithJws`.
fn sign(args: Option<&Map<String, Value>>, mode: Mode) -> Result<JObject, Code> {
    let args = args.ok_or(Code::Unexpected)?;
    let texts = locale(args)?;
    let items = items(args)?;
    let operation = operation(args)?;
    if window_open() {
        return Err(Code::AlreadyRunning);
    }
    validate(&items, mode)?;
    let _window = WindowMark::open();
    let key = window(&texts, &items)?;
    // The original signs on a thread that never reports a failure, and its window waits
    // forever; here the failure is the reply.
    let signed = jws::sign_items(&key, &items, mode, operation).map_err(|_| Code::Unexpected)?;
    let mut body = JObject::hash_map();
    body.put(
        "signedItems",
        JValue::Arr(signed.into_iter().map(JValue::Obj).collect()),
    );
    Ok(body)
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The signing window: the items with «Sign», «View», «Cancel», then the key.
fn window(texts: &Texts, items: &[Item]) -> Result<Key, Code> {
    let names: Vec<&str> = items.iter().map(|item| item.name.as_str()).collect();
    let mut text = format!("{}\n", texts.documents);
    for name in &names {
        text.push_str("\n• ");
        text.push_str(name);
    }
    loop {
        let answer = dialogs::choice(&ChoiceArgs {
            kind: MessageKind::Info,
            title: Some(texts.title.to_owned()),
            text: cut(&text, MAX_TEXT).to_owned(),
            buttons: texts.main_buttons.iter().map(|b| (*b).to_owned()).collect(),
            default: 0,
            options: Vec::new(),
        })
        .map_err(|_| Code::Unexpected)?;
        match answer {
            Some(0) => break,
            Some(1) => preview(texts, items),
            _ => return Err(Code::WindowClosed),
        }
    }
    keys::select(&SelectArgs {
        action: Action::Sign,
        storages: vec!["PKCS12".to_owned()],
        // The original checks nothing beyond the certificate's KNCA type.
        filter: Filter {
            allow_expired: true,
            chain: Some(Vec::new()),
            allow_revoked: true,
            ..Filter::default()
        },
        more: FilterMore {
            knca_types: vec!["SIGNATURE".to_owned()],
            ..FilterMore::default()
        },
        detail: Some(cut(&names.join(", "), MAX_LINE).to_owned()),
        initial_path: None,
        order: Default::default(),
    })
    .map_err(|_| Code::Unexpected)?
    .ok_or(Code::WindowClosed)
}

/// «View»: the item (chosen from a list if there are several) pretty-printed.
fn preview(texts: &Texts, items: &[Item]) {
    let index = if items.len() == 1 {
        Some(0)
    } else {
        dialogs::choice(&ChoiceArgs {
            kind: MessageKind::Info,
            title: Some(texts.preview_title.to_owned()),
            text: texts.documents.to_owned(),
            buttons: texts
                .preview_buttons
                .iter()
                .map(|b| (*b).to_owned())
                .collect(),
            default: 0,
            options: items
                .iter()
                .take(oncl_pdk::abi::MAX_CHOICE_OPTIONS)
                .map(|item| cut(&item.name, MAX_LINE).to_owned())
                .collect(),
        })
        .ok()
        .flatten()
        .map(usize::from)
    };
    let Some(item) = index.and_then(|i| items.get(i)) else {
        return;
    };
    let text = match orgjson::parse(&item.content) {
        Ok(value) => format!("{}\n\n{}", texts.content, jws::pretty(&value)),
        Err(_) => format!("{}\n\n{}", texts.content_invalid, item.content),
    };
    let _ = dialogs::message(MessageKind::Info, cut(&text, MAX_TEXT));
}
