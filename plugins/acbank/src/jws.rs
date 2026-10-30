//! The JWS of the items, as the original's nimbus-jose-jwt signers wrote them with
//! `ECGOST3410-2015-512`.
//!
//! - Protected header: `spanid`, `x5c` (the key's chain, standard base64), `cty`,
//!   `typ:"JOSE"`, `alg`, `ts` in Java `HashMap` order, written by Gson without HTML
//!   escaping. `ts` is the local wall time read as UTC, in milliseconds, as a string (the
//!   original's zone mix-up, kept). Without a `spanId` from the page, `spanid` is the hex
//!   SHA-256 of `<x> + ts`, where `<x>` is the content type for the compact form (the
//!   original passes it in the content's place), the content for JSON `INITIAL` and
//!   nothing for `SUBSEQUENT`.
//! - Compact: `b64url(header).b64url(content).b64url(signature)`.
//! - JSON `INITIAL`: the base64url of `{"payload","signatures":[{"protected","signature"}]}`
//!   (org.json); `SUBSEQUENT`: that JWS JSON from the content with one more signature over
//!   its `payload`, re-written by org.json, base64url again.

use crate::Code;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use oncl_pdk::host::{self, HashAlg};
use oncl_pdk::keys::Key;
use oncl_pdk::orgjson::{self, JObject, JValue};

/// An item to sign, as the page sent it.
pub(crate) struct Item {
    pub id: String,
    pub name: String,
    pub content: String,
    pub content_type: Option<String>,
    pub span_id: String,
}

/// The JWS serialization of the method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Compact,
    Json,
}

/// `signatureOperation` of the JWS JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Initial,
    Subsequent,
}

const ALG: &str = "ECGOST3410-2015-512";

/// Base64url read with or without padding.
const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Every item signed with `key`: the items of the reply body.
pub(crate) fn sign_items(
    key: &Key,
    items: &[Item],
    mode: Mode,
    operation: Option<Operation>,
) -> Result<Vec<JObject>, Code> {
    let details = host::cert_details(key.certificate()).map_err(|_| Code::Unexpected)?;
    if details.signing_alg.as_deref() != Some("gost2015_512") {
        return Err(Code::Unexpected);
    }
    let x5c: Vec<String> = key
        .chain()
        .map_err(|_| Code::Unexpected)?
        .iter()
        .map(|der| STANDARD.encode(der))
        .collect();
    items
        .iter()
        .map(|item| match mode {
            Mode::Compact => compact(key, &x5c, item),
            Mode::Json => json(key, &x5c, item, operation.ok_or(Code::Unexpected)?),
        })
        .collect()
}

/// `ts`: the local wall time read as UTC, milliseconds.
fn ts() -> Result<String, Code> {
    let now = host::now().map_err(|_| Code::Unexpected)?;
    let offset = host::local_offset(now).map_err(|_| Code::Unexpected)?;
    Ok((now + i64::from(offset) * 1000).to_string())
}

/// The lower-case hex SHA-256 of `text`.
fn sha256_hex(text: &str) -> Result<String, Code> {
    let digest = host::hash(HashAlg::Sha256, text.as_bytes()).map_err(|_| Code::Unexpected)?;
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// The protected header, as its JSON text.
fn header(x5c: &[String], content_type: &str, span_id: &str, hashed: &str) -> Result<String, Code> {
    let ts = ts()?;
    let span_id = if span_id.is_empty() {
        sha256_hex(&format!("{hashed}{ts}"))?
    } else {
        span_id.to_owned()
    };
    let mut header = JObject::hash_map();
    header.put("spanid", span_id);
    header.put(
        "x5c",
        JValue::Arr(x5c.iter().map(|c| JValue::Str(c.clone())).collect()),
    );
    header.put("cty", content_type);
    header.put("typ", "JOSE");
    header.put("alg", ALG);
    header.put("ts", ts);
    Ok(gson(&header))
}

/// The signature of the signing input, base64url.
fn signature(key: &Key, input: &str) -> Result<String, Code> {
    key.sign_raw(input.as_bytes())
        .map(|sig| b64url(&sig))
        .map_err(|_| Code::Unexpected)
}

fn compact(key: &Key, x5c: &[String], item: &Item) -> Result<JObject, Code> {
    let content_type = item.content_type.as_deref().unwrap_or("");
    // The original hashes the content type where the content was meant.
    let header = header(x5c, content_type, &item.span_id, content_type)?;
    let input = format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(item.content.as_bytes())
    );
    let jws = format!("{input}.{}", signature(key, &input)?);
    let mut signed = JObject::hash_map();
    signed.put("spanId", item.span_id.as_str());
    signed.put("signature", jws);
    signed.put("name", item.name.as_str());
    signed.put("id", item.id.as_str());
    signed.put("contentType", content_type);
    signed.put("content", item.content.as_str());
    Ok(signed)
}

fn json(key: &Key, x5c: &[String], item: &Item, operation: Operation) -> Result<JObject, Code> {
    let content_type = item.content_type.as_deref().unwrap_or("");
    let (mut jws, payload, hashed) = match operation {
        Operation::Initial => {
            let payload = b64url(item.content.as_bytes());
            let mut jws = JObject::hash_map();
            jws.put("payload", payload.as_str());
            jws.put("signatures", JValue::Arr(Vec::new()));
            (jws, payload, item.content.as_str())
        }
        Operation::Subsequent => {
            let text = URL_SAFE_LENIENT
                .decode(&item.content)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or(Code::Unexpected)?;
            let Ok(JValue::Obj(jws)) = orgjson::parse(&text) else {
                return Err(Code::Unexpected);
            };
            let Some(JValue::Str(payload)) = jws.get("payload") else {
                return Err(Code::Unexpected);
            };
            let payload = payload.clone();
            (jws, payload, "")
        }
    };
    let header = b64url(header(x5c, content_type, &item.span_id, hashed)?.as_bytes());
    let signature = signature(key, &format!("{header}.{payload}"))?;
    let mut entry = JObject::hash_map();
    entry.put("protected", header);
    entry.put("signature", signature);
    let mut signatures = match jws.get("signatures") {
        Some(JValue::Arr(signatures)) => signatures.clone(),
        // Unverified against the original: a JWS JSON without a `signatures` array.
        _ => return Err(Code::Unexpected),
    };
    signatures.push(JValue::Obj(entry));
    jws.put("signatures", JValue::Arr(signatures));
    let mut signed = JObject::hash_map();
    signed.put("spanId", item.span_id.as_str());
    // Unverified against the original: the base64url around the JWS JSON without padding
    // (nimbus's `Base64URL`).
    signed.put("jws", b64url(jws.to_json().as_bytes()));
    signed.put("id", item.id.as_str());
    Ok(signed)
}

/// The object as Gson writes it without HTML escaping, in its key order.
fn gson(object: &JObject) -> String {
    let mut out = String::from("{");
    for (i, (key, value)) in object.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        gson_quote(key, &mut out);
        out.push(':');
        match value {
            JValue::Str(s) => gson_quote(s, &mut out),
            JValue::Arr(items) => {
                out.push('[');
                for (j, item) in items.iter().enumerate() {
                    if j > 0 {
                        out.push(',');
                    }
                    if let JValue::Str(s) = item {
                        gson_quote(s, &mut out);
                    }
                }
                out.push(']');
            }
            other => out.push_str(&other.to_json()),
        }
    }
    out.push('}');
    out
}

/// A string as Gson writes it without HTML escaping.
fn gson_quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// org.json's `toString(2)`.
pub(crate) fn pretty(value: &JValue) -> String {
    let mut out = String::new();
    write_pretty(value, 0, &mut out);
    out
}

fn indent(out: &mut String, n: usize) {
    out.extend(std::iter::repeat_n(' ', n));
}

fn write_pretty(value: &JValue, at: usize, out: &mut String) {
    match value {
        JValue::Obj(object) => {
            out.push('{');
            let entries: Vec<_> = object.iter().collect();
            if let [(key, value)] = entries.as_slice() {
                orgjson::quote(key, out);
                out.push_str(": ");
                write_pretty(value, at, out);
            } else if !entries.is_empty() {
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('\n');
                    indent(out, at + 2);
                    orgjson::quote(key, out);
                    out.push_str(": ");
                    write_pretty(value, at + 2, out);
                }
                out.push('\n');
                indent(out, at);
            }
            out.push('}');
        }
        JValue::Arr(items) => {
            out.push('[');
            if let [item] = items.as_slice() {
                write_pretty(item, at, out);
            } else if !items.is_empty() {
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('\n');
                    indent(out, at + 2);
                    write_pretty(item, at + 2, out);
                }
                out.push('\n');
                indent(out, at);
            }
            out.push(']');
        }
        other => other.write_json(out),
    }
}
