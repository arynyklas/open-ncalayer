//! The JSON form of the RPC messages as protobuf-java's `JsonFormat` writes and reads it.
//!
//! The printer is `JsonFormat.printer()`: two spaces of indent, `\n`, `"name": value`, the
//! fields in field-number order, default values of fields without presence left out, an
//! empty message `{` `\n` `}`, repeated messages as `[{…}, {…}]`, strings escaped as Gson
//! escapes them by default (HTML-safe: `<`, `>`, `&`, `=`, `'` as `\u003c` and so on), bytes
//! in standard base64 with padding.
//!
//! The parser is `JsonFormat.parser().ignoringUnknownFields()`: a field by its JSON name or
//! its proto name (not both), `null` as an unset field, a string field from any JSON
//! primitive's text, `true`/`false` (or those strings) for a boolean, bytes in standard or
//! URL-safe base64, at most one member of a oneof; anything else is an invalid payload.

use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use oncl_pdk::serde_json::{Map, Value};

/// The payload cannot be read as the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

/// What reading a field gives.
pub type Read<T> = Result<T, Invalid>;

/// A message with a JSON form.
pub trait Json: Default {
    /// Writes the set fields, in field-number order.
    fn print(&self, p: &mut Printer);
    /// Reads the fields of `obj` into the message.
    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()>;
}

/// `JsonFormat.printer().print(message)`.
pub fn print<M: Json>(message: &M) -> String {
    let mut p = Printer {
        out: String::new(),
        indent: 0,
        at_start: false,
        first: true,
    };
    p.message(message);
    p.out
}

/// `JsonFormat.parser().ignoringUnknownFields().merge(text, builder)`.
pub fn parse<M: Json>(text: &str) -> Read<M> {
    let value: Value = oncl_pdk::serde_json::from_str(text).map_err(|_| Invalid)?;
    let obj = value.as_object().ok_or(Invalid)?;
    let mut message = M::default();
    message.merge(obj)?;
    Ok(message)
}

/// protobuf-java's `TextGenerator` under `JsonFormat`'s printer.
pub struct Printer {
    out: String,
    indent: usize,
    at_start: bool,
    /// No field of the message being written yet.
    first: bool,
}

impl Printer {
    /// `TextGenerator.print`: the indent goes before the first text of each line.
    fn text(&mut self, text: &str) {
        for piece in text.split_inclusive('\n') {
            if self.at_start {
                self.at_start = false;
                for _ in 0..self.indent {
                    self.out.push_str("  ");
                }
            }
            self.out.push_str(piece);
            if piece.ends_with('\n') {
                self.at_start = true;
            }
        }
    }

    fn message<M: Json>(&mut self, message: &M) {
        self.text("{\n");
        self.indent += 1;
        let outer = std::mem::replace(&mut self.first, true);
        message.print(self);
        if !self.first {
            self.text("\n");
        }
        self.indent -= 1;
        self.text("}");
        self.first = outer;
    }

    fn name(&mut self, name: &str) {
        if !self.first {
            self.text(",\n");
        }
        self.first = false;
        self.text(&format!("\"{name}\": "));
    }

    /// A string field.
    pub fn string(&mut self, name: &str, value: &str) {
        self.name(name);
        self.text(&gson_quote(value));
    }

    /// A bytes field.
    pub fn bytes(&mut self, name: &str, value: &[u8]) {
        self.name(name);
        self.text(&format!("\"{}\"", STANDARD.encode(value)));
    }

    /// A boolean field.
    pub fn boolean(&mut self, name: &str, value: bool) {
        self.name(name);
        self.text(if value { "true" } else { "false" });
    }

    /// A message field.
    pub fn message_field<M: Json>(&mut self, name: &str, value: &M) {
        self.name(name);
        self.message(value);
    }

    /// A repeated message field (non-empty).
    pub fn repeated<M: Json>(&mut self, name: &str, values: &[M]) {
        self.name(name);
        self.text("[");
        for (i, value) in values.iter().enumerate() {
            if i > 0 {
                self.text(", ");
            }
            self.message(value);
        }
        self.text("]");
    }
}

/// A string as Gson's default `toJson` writes it: HTML-safe.
fn gson_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
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
            '<' | '>' | '&' | '=' | '\'' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The value of the field named `json` (its JSON name) or `proto`; `None` if absent or
/// `null`. Both names at once are refused.
pub fn field<'a>(obj: &'a Map<String, Value>, json: &str, proto: &str) -> Read<Option<&'a Value>> {
    let by_json = obj.get(json).filter(|v| !v.is_null());
    let by_proto = (json != proto)
        .then(|| obj.get(proto).filter(|v| !v.is_null()))
        .flatten();
    match (by_json, by_proto) {
        (Some(_), Some(_)) => Err(Invalid),
        (one, other) => Ok(one.or(other)),
    }
}

/// A string field's value: any primitive's text.
pub fn string(value: &Value) -> Read<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(Invalid),
    }
}

/// A boolean field's value.
pub fn boolean(value: &Value) -> Read<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(Invalid),
    }
}

/// Base64 with or without its padding.
const fn lenient(alphabet: &base64::alphabet::Alphabet) -> GeneralPurpose {
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
}

const STANDARD_LENIENT: GeneralPurpose = lenient(&base64::alphabet::STANDARD);
const URL_SAFE_LENIENT: GeneralPurpose = lenient(&base64::alphabet::URL_SAFE);

/// A bytes field's value: standard base64, else URL-safe.
pub fn bytes(value: &Value) -> Read<Vec<u8>> {
    let Value::String(text) = value else {
        return Err(Invalid);
    };
    STANDARD_LENIENT
        .decode(text)
        .or_else(|_| URL_SAFE_LENIENT.decode(text))
        .map_err(|_| Invalid)
}

/// A message field's value.
pub fn message<M: Json>(value: &Value) -> Read<M> {
    let obj = value.as_object().ok_or(Invalid)?;
    let mut message = M::default();
    message.merge(obj)?;
    Ok(message)
}

/// A repeated message field's value.
pub fn repeated<M: Json>(value: &Value) -> Read<Vec<M>> {
    value
        .as_array()
        .ok_or(Invalid)?
        .iter()
        .map(message)
        .collect()
}

/// Base64 the original sends binary payloads in (standard, padded).
pub fn encode_binary(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
