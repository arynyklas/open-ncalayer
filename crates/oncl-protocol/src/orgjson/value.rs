//! org.json's values as its `toString()` writes them: [`JObject`] in the key order of the
//! map behind it, numbers as org.json prints them, strings through [`quote`].

use crate::javamap::{self, Table};
use serde_json::{Map, Number, Value};

/// A value of an org.json `JSONObject` or `JSONArray`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JValue {
    /// `JSONObject.NULL`: written as `null`. (A Java `null` is no value at all: see
    /// [`JObject::put_opt`].)
    Null,
    /// A `Boolean`.
    Bool(bool),
    /// An `Integer` or a `Long`.
    Int(i64),
    /// Any other number, as `toString()` gives it: a `BigDecimal` (`1.50`, `1E+3`), a
    /// `BigInteger` beyond 63 bits, a `Double` (`-0.0`). Written as org.json writes numbers:
    /// a plain decimal loses its trailing zeros (`1.50` → `1.5`, `1.0` → `1`).
    Dec(String),
    /// A `String`.
    Str(String),
    /// A nested `JSONObject`.
    Obj(JObject),
    /// A `JSONArray`.
    Arr(Vec<JValue>),
    /// A `JSONString`: this text is written as it is.
    Raw(String),
}

impl JValue {
    /// The value's `toString()`: a string as itself, a number as Java prints it (without
    /// org.json's trimming), `null`, `true`/`false`, an object or array as its JSON text.
    /// What org.json's `optString` and `JSONArray.get(i).toString()` give.
    pub fn java_string(&self) -> String {
        match self {
            JValue::Null => "null".to_owned(),
            JValue::Bool(b) => b.to_string(),
            JValue::Int(i) => i.to_string(),
            JValue::Dec(d) => d.clone(),
            JValue::Str(s) | JValue::Raw(s) => s.clone(),
            JValue::Obj(_) | JValue::Arr(_) => self.to_json(),
        }
    }

    /// The JSON text org.json writes for the value.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    /// Appends the JSON text of the value to `out`.
    pub fn write_json(&self, out: &mut String) {
        match self {
            JValue::Null => out.push_str("null"),
            JValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JValue::Int(i) => out.push_str(&i.to_string()),
            JValue::Dec(d) => {
                let text = number_to_string(d);
                if is_json_number(text) {
                    out.push_str(text);
                } else {
                    quote(text, out);
                }
            }
            JValue::Str(s) => quote(s, out),
            JValue::Obj(o) => o.write_json(out),
            JValue::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            JValue::Raw(s) => out.push_str(s),
        }
    }

    /// The value as a `serde_json` value: objects lose their key order, numbers that are not
    /// integers become the nearest `f64` (or their text where there is none), a
    /// [`JValue::Raw`] is parsed (else kept as a string).
    pub fn to_value(&self) -> Value {
        match self {
            JValue::Null => Value::Null,
            JValue::Bool(b) => Value::Bool(*b),
            JValue::Int(i) => Value::from(*i),
            JValue::Dec(d) => d
                .parse::<f64>()
                .ok()
                .and_then(Number::from_f64)
                .map_or_else(|| Value::String(d.clone()), Value::Number),
            JValue::Str(s) => Value::String(s.clone()),
            JValue::Obj(o) => Value::Object(o.to_map()),
            JValue::Arr(items) => Value::Array(items.iter().map(JValue::to_value).collect()),
            JValue::Raw(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
        }
    }
}

impl From<&str> for JValue {
    fn from(s: &str) -> Self {
        JValue::Str(s.to_owned())
    }
}

impl From<String> for JValue {
    fn from(s: String) -> Self {
        JValue::Str(s)
    }
}

impl From<bool> for JValue {
    fn from(b: bool) -> Self {
        JValue::Bool(b)
    }
}

impl From<i32> for JValue {
    fn from(i: i32) -> Self {
        JValue::Int(i64::from(i))
    }
}

impl From<i64> for JValue {
    fn from(i: i64) -> Self {
        JValue::Int(i)
    }
}

impl From<JObject> for JValue {
    fn from(o: JObject) -> Self {
        JValue::Obj(o)
    }
}

impl From<Vec<JValue>> for JValue {
    fn from(items: Vec<JValue>) -> Self {
        JValue::Arr(items)
    }
}

/// A `serde_json` value as org.json would hold it after parsing its text: an object becomes
/// a `new JSONObject()` filled in the order of its keys (sorted, as `serde_json` keeps
/// them), an integer an `Integer`/`Long` (beyond: its digits), another number its shortest
/// decimal text.
impl From<Value> for JValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => JValue::Null,
            Value::Bool(b) => JValue::Bool(b),
            Value::Number(n) => match (n.as_i64(), n.as_u64()) {
                (Some(i), _) => JValue::Int(i),
                (None, Some(u)) => JValue::Dec(u.to_string()),
                (None, None) => JValue::Dec(n.to_string()),
            },
            Value::String(s) => JValue::Str(s),
            Value::Array(items) => JValue::Arr(items.into_iter().map(JValue::from).collect()),
            Value::Object(map) => {
                let mut o = JObject::hash_map();
                for (k, v) in map {
                    o.put(k, JValue::from(v));
                }
                JValue::Obj(o)
            }
        }
    }
}

/// The map behind a [`JObject`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    /// A `HashMap`: keys in its iteration order.
    Hash(Table),
    /// What `JSONStringer` writes: keys in the order they were written.
    Written,
}

/// An org.json `JSONObject`, its keys in the order its `toString()` writes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JObject {
    kind: Kind,
    /// The entries in the order they went in.
    entries: Vec<(String, JValue)>,
}

impl JObject {
    /// `new JSONObject()`, or a bean wrapped by org.json: a `HashMap` of 16 buckets.
    pub fn hash_map() -> JObject {
        JObject {
            kind: Kind::Hash(Table::new(javamap::DEFAULT_CAPACITY)),
            entries: Vec::new(),
        }
    }

    /// `new JSONObject(map)` of a map of `len` entries: a `HashMap` of
    /// [`table_size_for`](javamap::table_size_for)`(len)` buckets, filled in the map's order.
    pub fn from_map(len: usize) -> JObject {
        JObject {
            kind: Kind::Hash(Table::new(javamap::table_size_for(len))),
            entries: Vec::new(),
        }
    }

    /// An object written by `JSONStringer` (or held in a `LinkedHashMap`): keys in the order
    /// they were put.
    pub fn stringer() -> JObject {
        JObject {
            kind: Kind::Written,
            entries: Vec::new(),
        }
    }

    /// `put(key, value)`: a key already present keeps its place and takes the new value.
    pub fn put(&mut self, key: impl Into<String>, value: impl Into<JValue>) -> &mut Self {
        let key = key.into();
        let value = value.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => {
                if let Kind::Hash(table) = &mut self.kind {
                    table.push(javamap::string_hash(&key));
                }
                self.entries.push((key, value));
            }
        }
        self
    }

    /// `put(key, value)` where `value` may be Java's `null`: `None` removes the key, as
    /// org.json does (and as a `null` bean property is left out).
    pub fn put_opt<V: Into<JValue>>(
        &mut self,
        key: impl Into<String>,
        value: Option<V>,
    ) -> &mut Self {
        match value {
            Some(value) => self.put(key, value),
            None => {
                self.remove(&key.into());
                self
            }
        }
    }

    /// Removes `key`, if present.
    pub fn remove(&mut self, key: &str) -> Option<JValue> {
        let at = self.entries.iter().position(|(k, _)| k == key)?;
        if let Kind::Hash(table) = &mut self.kind {
            table.remove(at);
        }
        Some(self.entries.remove(at).1)
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&JValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no keys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries in the order `toString()` writes them.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &JValue)> {
        let order = match &self.kind {
            Kind::Hash(table) => table.order(),
            Kind::Written => (0..self.entries.len()).collect(),
        };
        order.into_iter().map(|i| {
            let (k, v) = &self.entries[i];
            (k.as_str(), v)
        })
    }

    /// `toString()`.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    /// Appends `toString()` to `out`.
    pub fn write_json(&self, out: &mut String) {
        out.push('{');
        for (i, (k, v)) in self.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            quote(k, out);
            out.push(':');
            v.write_json(out);
        }
        out.push('}');
    }

    /// The object as a `serde_json` map (see [`JValue::to_value`]).
    pub fn to_map(&self) -> Map<String, Value> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.to_value()))
            .collect()
    }
}

/// `JSONObject.quote(s)` appended to `out`: `"` and `\` escaped, `/` only after `<`, the
/// short escapes of `\b \t \n \f \r`, every other character below U+0020, from U+0080 to
/// U+009F and from U+2000 to U+20FF as `\u` and four lower-case hex digits; the rest as it
/// is (Cyrillic is not escaped).
pub fn quote(s: &str, out: &mut String) {
    out.push('"');
    let mut previous = '\0';
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            '/' => {
                if previous == '<' {
                    out.push('\\');
                }
                out.push(c);
            }
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' '
                || ('\u{80}'..'\u{a0}').contains(&c)
                || ('\u{2000}'..'\u{2100}').contains(&c) =>
            {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
        previous = c;
    }
    out.push('"');
}

/// `JSONObject.quote(s)` as a new string.
pub fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    quote(s, &mut out);
    out
}

/// org.json's `numberToString`: a decimal without an exponent loses its trailing zeros and
/// then a trailing point.
fn number_to_string(text: &str) -> &str {
    if text.find('.').is_some_and(|at| at > 0) && !text.contains(['e', 'E']) {
        text.trim_end_matches('0').trim_end_matches('.')
    } else {
        text
    }
}

/// org.json's `NUMBER_PATTERN`: `-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?`. A number text
/// that does not match is written as a string.
fn is_json_number(text: &str) -> bool {
    let b = text.as_bytes();
    let mut i = 0;
    let digits = |i: &mut usize| {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - start
    };
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            digits(&mut i);
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        if digits(&mut i) == 0 {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}
