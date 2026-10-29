//! An example OpenNCALayer plugin: the module `io.github.arynyklas.openncalayer.Example`,
//! class `Example` in the CommonInvoker dialect of the basics module, with a method for each
//! capability, and a few that misbehave on purpose (`spin`, `grow`, `panic`) to show what the
//! core does with them.
//!
//! Build: `cargo build --release --target wasm32-unknown-unknown` here; the module is
//! `target/wasm32-unknown-unknown/release/oncl_plugin_example.wasm`, packed with `plugin.toml`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oncl_pdk::abi::{Bytes, ErrorCode, HostError, HostResult, Import, MessageKind, SignRawArgs};
use oncl_pdk::invoker::{self, CallResult, Failure, NlClass};
use oncl_pdk::keys::{Action, ChooseArgs, Filter, Key};
use oncl_pdk::serde_json::{Map, Value, json};
use oncl_pdk::{AddInfo, Request, call_host, dialogs, files, http, keys};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Calls of `count` in this instance.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// Keys `hold` keeps until `release`.
static HELD: Mutex<Vec<Key>> = Mutex::new(Vec::new());

fn handle(request: &Request) -> String {
    invoker::invoke(&request.text, &request.add_info(), &[&Example])
}

oncl_pdk::plugin!(handle);

/// The class `Example`.
struct Example;

impl NlClass for Example {
    fn class_name(&self) -> &'static str {
        "Example"
    }

    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        add_info: &AddInfo,
    ) -> Option<CallResult> {
        let empty = Map::new();
        let args = args.unwrap_or(&empty);
        Some(match method {
            "echo" => string(args, "text").map(Value::from),
            "count" => Ok(json!(COUNT.fetch_add(1, Ordering::Relaxed) + 1)),
            "origin" => Ok(json!(add_info.origin)),
            "confirm" => string(args, "text").and_then(|text| host(dialogs::confirm(&text))),
            "message" => string(args, "text").and_then(|text| {
                host(dialogs::message(MessageKind::Info, &text).map(|()| Value::Null))
            }),
            "sign" => sign(args),
            "signRaw" => sign_raw(args),
            "signXml" => sign_xml(args),
            "hold" => hold(args),
            "release" => release(args),
            "rawSign" => raw_sign(args),
            "open" => open(),
            "save" => save(args),
            "fetch" => fetch(args),
            "spin" => spin(),
            "grow" => grow(),
            "panic" => panic!("asked to panic"),
            _ => return None,
        })
    }
}

/// The string argument `key`.
fn string(args: &Map<String, Value>, key: &str) -> Result<String, Failure> {
    oncl_pdk::orgjson::get_string(args, key)
        .map(str::to_owned)
        .map_err(|e| Failure::Invocation(Some(e)))
}

/// The base64 argument `key`, decoded.
fn bytes(args: &Map<String, Value>, key: &str) -> Result<Vec<u8>, Failure> {
    STANDARD
        .decode(string(args, key)?)
        .map_err(|e| Failure::Invocation(Some(format!("{key}: {e}"))))
}

/// The boolean argument `key`, `default` if absent.
fn flag(args: &Map<String, Value>, key: &str, default: bool) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// A host function's result: its error as `HOST_<CODE>` with its message.
fn host<T: Into<Value>>(result: HostResult<T>) -> CallResult {
    result.map(Into::into).map_err(host_failure)
}

fn host_failure(e: HostError) -> Failure {
    let code = match e.code {
        ErrorCode::Denied => "HOST_DENIED",
        ErrorCode::Invalid => "HOST_INVALID",
        ErrorCode::Limit => "HOST_LIMIT",
        ErrorCode::Failed => "HOST_FAILED",
    };
    Failure::Custom {
        code: code.to_owned(),
        message: Some(e.message),
        details: None,
    }
}

/// The key the user chooses for signing: `chain` (base64 DER CA certificates; absent: the
/// NCA's) and `allowExpired` as the basics module's `signerParams`.
fn choose(args: &Map<String, Value>, detail: &str) -> Result<Option<Key>, Failure> {
    let chain = match args.get("chain") {
        Some(Value::Array(certs)) => Some(
            certs
                .iter()
                .map(|cert| {
                    let text = cert.as_str().unwrap_or_default();
                    STANDARD
                        .decode(text)
                        .map(Bytes::from)
                        .map_err(|e| Failure::Invocation(Some(format!("chain: {e}"))))
                })
                .collect::<Result<_, _>>()?,
        ),
        _ => None,
    };
    let request = ChooseArgs {
        action: Action::Sign,
        storages: Vec::new(),
        filter: Filter {
            chain,
            allow_expired: flag(args, "allowExpired", false),
            ..Filter::default()
        },
        detail: Some(detail.to_owned()),
    };
    keys::choose(&request).map_err(host_failure)
}

/// `sign{data_b64, attached, timestamp}`: a CMS as PEM; `null` if the user cancels.
fn sign(args: &Map<String, Value>) -> CallResult {
    let data = bytes(args, "data_b64")?;
    let Some(key) = choose(args, "CMS")? else {
        return Ok(Value::Null);
    };
    let cms = key
        .sign_cms(
            &data,
            flag(args, "attached", true),
            flag(args, "timestamp", false),
        )
        .map_err(host_failure)?;
    Ok(Value::from(pem("CMS", &cms)))
}

/// `signRaw{data_b64}`: the signature, base64.
fn sign_raw(args: &Map<String, Value>) -> CallResult {
    let data = bytes(args, "data_b64")?;
    let Some(key) = choose(args, "raw")? else {
        return Ok(Value::Null);
    };
    let signature = key.sign_raw(&data).map_err(host_failure)?;
    Ok(json!({
        "signature": STANDARD.encode(signature),
        "certificate": STANDARD.encode(key.certificate()),
    }))
}

/// `signXml{xml, element?, parent?}`: the signed document.
fn sign_xml(args: &Map<String, Value>) -> CallResult {
    let xml = string(args, "xml")?;
    let Some(key) = choose(args, "XML")? else {
        return Ok(Value::Null);
    };
    let element = oncl_pdk::orgjson::opt_string(args, "element");
    let parent = oncl_pdk::orgjson::opt_string(args, "parent");
    let signed = key
        .sign_xml(xml.as_bytes(), element.as_deref(), parent.as_deref())
        .map_err(host_failure)?;
    String::from_utf8(signed)
        .map(Value::from)
        .map_err(|e| Failure::Invocation(Some(e.to_string())))
}

/// `hold`: chooses a key and keeps it: its handle.
fn hold(args: &Map<String, Value>) -> CallResult {
    let Some(key) = choose(args, "hold")? else {
        return Ok(Value::Null);
    };
    let handle = key.handle();
    HELD.lock().unwrap_or_else(|e| e.into_inner()).push(key);
    Ok(json!(handle))
}

/// `release{handle}`: lets go of a key `hold` kept.
fn release(args: &Map<String, Value>) -> CallResult {
    let handle = args.get("handle").and_then(Value::as_u64);
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    let found = held
        .iter()
        .position(|key| Some(u64::from(key.handle())) == handle);
    Ok(json!(found.map(|i| drop(held.remove(i))).is_some()))
}

/// `rawSign{handle, data_b64}`: `keys_sign_raw` with any handle, through the bare ABI.
fn raw_sign(args: &Map<String, Value>) -> CallResult {
    let handle = args
        .get("handle")
        .and_then(Value::as_u64)
        .and_then(|h| u32::try_from(h).ok())
        .ok_or_else(|| Failure::Invocation(Some("handle".to_owned())))?;
    let data = bytes(args, "data_b64")?;
    let signature: Bytes = call_host(
        Import::KeysSignRaw,
        &SignRawArgs {
            handle,
            data: Bytes::from(data),
        },
    )
    .map_err(host_failure)?;
    Ok(Value::from(STANDARD.encode(signature)))
}

/// `open`: `{path, data_b64}` of a file the user chooses; `null` if cancelled.
fn open() -> CallResult {
    Ok(match files::open().map_err(host_failure)? {
        Some((path, data)) => json!({ "path": path, "data_b64": STANDARD.encode(data) }),
        None => Value::Null,
    })
}

/// `save{name, data_b64}`: the path written; `null` if cancelled.
fn save(args: &Map<String, Value>) -> CallResult {
    let name = string(args, "name")?;
    let data = bytes(args, "data_b64")?;
    host(files::save(&name, &data).map(|path| path.map_or(Value::Null, Value::from)))
}

/// `fetch{url, body_b64?, contentType?}`: a GET, or a POST with a body.
fn fetch(args: &Map<String, Value>) -> CallResult {
    let url = string(args, "url")?;
    let reply = if args.contains_key("body_b64") {
        let body = bytes(args, "body_b64")?;
        let content_type = oncl_pdk::orgjson::opt_string(args, "contentType")
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        http::post(&url, &content_type, &body)
    } else {
        http::get(&url)
    }
    .map_err(host_failure)?;
    Ok(json!({
        "status": reply.status,
        "contentType": reply.content_type,
        "location": reply.location,
        "body_b64": STANDARD.encode(&reply.body),
    }))
}

/// `spin`: never returns.
fn spin() -> CallResult {
    let mut n: u64 = 0;
    loop {
        n = std::hint::black_box(n.wrapping_add(1));
    }
}

/// `grow`: takes memory without end.
fn grow() -> CallResult {
    loop {
        let chunk: Vec<u8> = Vec::with_capacity(16 << 20);
        std::mem::forget(std::hint::black_box(chunk));
    }
}

/// `der` as PEM with `label`, 64 characters a line.
fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        // Base64 is ASCII.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
