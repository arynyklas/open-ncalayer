//! How the original's modules read request values with org.json, shared by every module's
//! dispatcher and argument parsing.

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
