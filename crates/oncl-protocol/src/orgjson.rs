//! org.json 20211205 as the original's modules use it: the readers of request values (on
//! `serde_json` values, with org.json's conversions and `JSONException` messages), and, for
//! replies that must match the original byte for byte, its parser ([`parse`]) and writer
//! ([`JObject`], [`JValue`], [`quote`]) with the key order of Java's `HashMap`.
//!
//! The messages are `getMessage()`: without the `org.json.JSONException: ` prefix of
//! `toString()`.

mod parse;
mod value;

pub use parse::{parse, reserialize};
pub use value::{JObject, JValue, quote, quoted};

use serde_json::{Map, Value};

/// org.json `optString`: `None` when absent or `null`, a string as itself, any other value
/// as its JSON text. The original's `optString(key)` is the empty string for `None`.
pub fn opt_string(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

/// org.json `getString`: the string under `key`, else the `JSONException` message org.json
/// throws (`getMessage()`, without the `org.json.JSONException: ` prefix of `toString()`).
/// A JSON `null` is a value that is not a string, not a missing key.
pub fn get_string<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    match obj.get(key) {
        Some(Value::String(s)) => Ok(s),
        None => Err(format!("JSONObject[\"{key}\"] not found.")),
        Some(_) => Err(format!("JSONObject[\"{key}\"] is not a string.")),
    }
}

/// The `int` org.json `getInt` makes of `value`: a number narrowed with `intValue()` (an
/// integer keeps its low 32 bits, a fraction is cut toward zero and saturates), or a string
/// `Integer.parseInt` reads (an optional sign and ASCII digits within the `int` range; Java
/// also takes other Unicode decimal digits, which are not recognized here). `None` where
/// org.json throws.
pub fn int_value(value: &Value) -> Option<i32> {
    match value {
        Value::Number(n) => Some(match (n.as_i64(), n.as_u64()) {
            // `Long.intValue()`.
            (Some(i), _) => i as i32,
            // `BigInteger.intValue()`: the low 32 bits.
            (None, Some(u)) => u as i32,
            // `Double.intValue()`.
            (None, None) => n.as_f64().map_or(0, |f| f as i32),
        }),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// `JSONObject["key"]` as org.json names a key in its messages (the key through [`quote`]).
fn key_name(key: &str) -> String {
    format!("JSONObject[{}]", quoted(key))
}

/// org.json `get(key)`: the value, or `JSONObject["key"] not found.` (a JSON `null` is a
/// value).
fn get<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    obj.get(key)
        .ok_or_else(|| format!("{} not found.", key_name(key)))
}

/// Java's `word.equalsIgnoreCase(s)`: character by character, equal as they are, after
/// `toUpperCase`, or after `toLowerCase` of that (a character Java maps to one character).
fn java_equals_ignore_case(word: &str, s: &str) -> bool {
    fn one(mut chars: impl Iterator<Item = char>, c: char) -> char {
        match (chars.next(), chars.next()) {
            (Some(mapped), None) => mapped,
            _ => c,
        }
    }
    let upper = |c: char| one(c.to_uppercase(), c);
    let lower = |c: char| one(c.to_lowercase(), c);
    word.chars().count() == s.chars().count()
        && word
            .chars()
            .zip(s.chars())
            .all(|(a, b)| a == b || upper(a) == upper(b) || lower(upper(a)) == lower(upper(b)))
}

/// The `boolean` org.json makes of `value`: a boolean, or the string `true`/`false` in any
/// case.
fn boolean_value(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) if java_equals_ignore_case("true", s) => Some(true),
        Value::String(s) if java_equals_ignore_case("false", s) => Some(false),
        _ => None,
    }
}

/// org.json `optBoolean(key, default)`: a boolean, or the string `true`/`false` in any
/// case; anything else (absent, `null`, another value) is `default`.
pub fn opt_boolean(obj: &Map<String, Value>, key: &str, default: bool) -> bool {
    obj.get(key).and_then(boolean_value).unwrap_or(default)
}

/// org.json `getBoolean(key)`: as [`opt_boolean`], else `JSONObject["key"] not found.` or
/// `JSONObject["key"] is not a Boolean.`.
pub fn get_boolean(obj: &Map<String, Value>, key: &str) -> Result<bool, String> {
    boolean_value(get(obj, key)?).ok_or_else(|| format!("{} is not a Boolean.", key_name(key)))
}

/// org.json 20211205 `optInt(key, default)`: absent and `null` give `default`; a number is
/// used as is; anything else is `toString()`-ed and parsed by `stringToNumber`, falling back
/// to `default` on failure (so booleans, arrays, objects and non-numeric strings give
/// `default`). The number is then narrowed with `Number.intValue()`: fractions truncate
/// toward zero and integers keep their low 32 bits. Like org.json, strings are not trimmed
/// (`" 2"` is non-numeric).
pub fn opt_int(obj: &Map<String, Value>, key: &str, default: i32) -> i32 {
    match obj.get(key) {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i as i32
            } else if let Some(u) = n.as_u64() {
                u as i32
            } else {
                n.as_f64().map_or(default, truncate)
            }
        }
        Some(Value::String(s)) => string_to_int(s).unwrap_or(default),
        _ => default,
    }
}

/// org.json `stringToNumber` followed by `intValue()`; `None` where it throws. Its
/// `Double.valueOf` retry for strings `BigDecimal` rejects (hex floats, `d`/`f` suffixes)
/// is not emulated.
fn string_to_int(s: &str) -> Option<i32> {
    let initial = *s.as_bytes().first()?;
    if !(initial.is_ascii_digit() || initial == b'-') {
        return None;
    }
    if s.contains(['.', 'e', 'E']) || s == "-0" {
        // `new BigDecimal(s)`; without inf/nan its grammar is Rust's float grammar.
        let decimal = s
            .bytes()
            .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b));
        return decimal
            .then(|| s.parse::<f64>().ok())
            .flatten()
            .map(truncate);
    }
    // `new BigInteger(s)`; org.json first rejects octal-looking "01" and "-01".
    let digits = s.strip_prefix('-').unwrap_or(s);
    let octal = digits.len() > 1 && digits.starts_with('0');
    if octal || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let low = digits.bytes().fold(0u32, |acc, d| {
        acc.wrapping_mul(10).wrapping_add(u32::from(d - b'0'))
    });
    let low = if initial == b'-' {
        low.wrapping_neg()
    } else {
        low
    };
    Some(low as i32)
}

/// `BigDecimal.intValue()`/`Double.intValue()` for finite values: truncate toward zero, keep
/// the low 32 bits.
fn truncate(f: f64) -> i32 {
    f.trunc() as i128 as i32
}

/// org.json `getInt(key)`: [`int_value`] of the value, else `JSONObject["key"] not found.`
/// or `JSONObject["key"] is not a int.`.
pub fn get_int(obj: &Map<String, Value>, key: &str) -> Result<i32, String> {
    int_value(get(obj, key)?).ok_or_else(|| format!("{} is not a int.", key_name(key)))
}

/// org.json `getJSONObject(key)`: `not found.` or `is not a JSONObject.`.
pub fn get_object<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, String> {
    get(obj, key)?
        .as_object()
        .ok_or_else(|| format!("{} is not a JSONObject.", key_name(key)))
}

/// org.json `optJSONObject(key)`: the object, or `None` for anything else.
pub fn opt_object<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    obj.get(key).and_then(Value::as_object)
}

/// org.json `getJSONArray(key)`: `not found.` or `is not a JSONArray.`.
pub fn get_array<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], String> {
    get(obj, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{} is not a JSONArray.", key_name(key)))
}

/// org.json `optJSONArray(key)`: the array, or `None` for anything else.
pub fn opt_array<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a [Value]> {
    obj.get(key).and_then(Value::as_array).map(Vec::as_slice)
}

/// `JSONArray.get(i)`: the element, or `JSONArray[i] not found.` (a JSON `null` is an
/// element).
fn array_get(arr: &[Value], i: usize) -> Result<&Value, String> {
    arr.get(i)
        .ok_or_else(|| format!("JSONArray[{i}] not found."))
}

/// `JSONArray.getString(i)`: `JSONArray[i] not found.` or `JSONArray[i] is not a String.`.
pub fn array_get_string(arr: &[Value], i: usize) -> Result<&str, String> {
    array_get(arr, i)?
        .as_str()
        .ok_or_else(|| format!("JSONArray[{i}] is not a String."))
}

/// `JSONArray.getInt(i)`: [`int_value`], else `JSONArray[i] not found.` or
/// `JSONArray[i] is not a int.`.
pub fn array_get_int(arr: &[Value], i: usize) -> Result<i32, String> {
    int_value(array_get(arr, i)?).ok_or_else(|| format!("JSONArray[{i}] is not a int."))
}

/// `JSONArray.getJSONObject(i)`: `JSONArray[i] not found.` or
/// `JSONArray[i] is not a JSONObject.`.
pub fn array_get_object(arr: &[Value], i: usize) -> Result<&Map<String, Value>, String> {
    array_get(arr, i)?
        .as_object()
        .ok_or_else(|| format!("JSONArray[{i}] is not a JSONObject."))
}

/// `toString()` of a value org.json holds (`JSONArray.get(i).toString()`): a string as
/// itself, `null` as `"null"`, a number as Java prints it, an object or array as org.json
/// writes it (see [`JValue::from`]).
pub fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => JValue::from(other.clone()).java_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opt_strings() {
        let obj = json!({"s": "x", "n": 5, "b": true, "null": null});
        let obj = obj.as_object().unwrap();
        assert_eq!(opt_string(obj, "s").as_deref(), Some("x"));
        assert_eq!(opt_string(obj, "n").as_deref(), Some("5"));
        assert_eq!(opt_string(obj, "b").as_deref(), Some("true"));
        assert_eq!(opt_string(obj, "null"), None);
        assert_eq!(opt_string(obj, "missing"), None);
    }

    #[test]
    fn get_strings() {
        let obj = json!({"s": "x", "n": 5, "null": null});
        let obj = obj.as_object().unwrap();
        assert_eq!(get_string(obj, "s"), Ok("x"));
        assert_eq!(
            get_string(obj, "n"),
            Err("JSONObject[\"n\"] is not a string.".to_owned())
        );
        assert_eq!(
            get_string(obj, "null"),
            Err("JSONObject[\"null\"] is not a string.".to_owned())
        );
        assert_eq!(
            get_string(obj, "missing"),
            Err("JSONObject[\"missing\"] not found.".to_owned())
        );
    }

    #[test]
    fn int_values() {
        assert_eq!(int_value(&json!(7)), Some(7));
        assert_eq!(int_value(&json!(-7)), Some(-7));
        assert_eq!(int_value(&json!(4_294_967_298_i64)), Some(2));
        assert_eq!(int_value(&json!(u64::MAX)), Some(-1));
        assert_eq!(int_value(&json!(2.9)), Some(2));
        assert_eq!(int_value(&json!(-2.9)), Some(-2));
        assert_eq!(int_value(&json!(1e300)), Some(i32::MAX));
        assert_eq!(int_value(&json!("+12")), Some(12));
        assert_eq!(int_value(&json!("-12")), Some(-12));
        assert_eq!(int_value(&json!("2147483648")), None);
        assert_eq!(int_value(&json!("1.5")), None);
        assert_eq!(int_value(&json!("")), None);
        assert_eq!(int_value(&json!(" 1")), None);
        assert_eq!(int_value(&json!(true)), None);
        assert_eq!(int_value(&Value::Null), None);
    }
}
