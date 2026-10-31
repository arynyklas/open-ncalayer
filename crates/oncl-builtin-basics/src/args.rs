//! The arguments as the original reads them with org.json, and the texts it takes
//! certificates and data from.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pdk::Locale;
use oncl_pdk::invoker::Failure;
use oncl_pdk::orgjson::{int_value, opt_string};
use oncl_pdk::serde_json::{Map, Value};

/// Kalkan's `Storage` names in declaration order.
pub(crate) const STORAGES: [&str; 9] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
    "JKS",
    "ABCloudServiceStore",
];

/// `optString("locale", "kk")`: Kazakh without one, `kk` and `ru` in any case, anything
/// else English (Java's `new Locale(…)` lower-cases the language).
pub(crate) fn locale(args: &Map<String, Value>) -> Locale {
    match opt_string(args, "locale") {
        None => Locale::Kk,
        Some(v) if v.eq_ignore_ascii_case("kk") => Locale::Kk,
        Some(v) if v.eq_ignore_ascii_case("ru") => Locale::Ru,
        Some(_) => Locale::En,
    }
}

/// `allowedStorages` entries as the original maps them: `(String) e` on each entry, so a
/// non-string is a ClassCastException; null and unknown names are dropped (`Storage.get`
/// finds nothing); duplicates stay.
pub(crate) fn storage_list(names: &[Value]) -> Result<Vec<String>, Failure> {
    let mut storages = Vec::with_capacity(names.len());
    for name in names {
        match name {
            Value::String(name) if STORAGES.contains(&name.as_str()) => {
                storages.push(name.clone());
            }
            Value::String(_) | Value::Null => {}
            other => return Err(class_cast(other)),
        }
    }
    Ok(storages)
}

/// Java's `Base64.getDecoder()` as the original's basics module decodes `data` and
/// certificates: the message of its `IllegalArgumentException` on failure.
pub(crate) fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    oncl_pdk::javab64::decode_java(s)
}

/// `der` as base64, for the replies.
pub(crate) fn encode_base64(der: &[u8]) -> String {
    STANDARD.encode(der)
}

/// The DER a certificate written as PEM or as base64 of its DER would have, whitespace
/// allowed anywhere in the base64; whether it is a certificate is the core's to say.
pub(crate) fn pem_or_base64(text: &str) -> Option<Vec<u8>> {
    let base64: String = pem_body(text)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    decode_base64(&base64).ok()
}

/// What lies between the first `-----BEGIN …-----` and the next `-----END`; all of `text`
/// without a BEGIN; empty for a block that does not end.
fn pem_body(text: &str) -> &str {
    const BEGIN: &str = "-----BEGIN";
    const DASHES: &str = "-----";
    let Some(start) = text.find(BEGIN) else {
        return text;
    };
    let header = &text[start + BEGIN.len()..];
    let Some(close) = header.find(DASHES) else {
        return "";
    };
    let body = &header[close + DASHES.len()..];
    body.find("-----END").map_or("", |end| &body[..end])
}

/// `-----BEGIN <label>-----`, base64 of `der` in lines of 64 characters,
/// `-----END <label>-----`, each line ended by `nl`, as NCALayer's PEM writer writes them.
pub(crate) fn pem(label: &str, der: &[u8], nl: &str) -> String {
    const DASHES: &str = "-----";
    let body = encode_base64(der);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 * nl.len() + 64);
    for part in [DASHES, "BEGIN ", label, DASHES, nl] {
        pem.push_str(part);
    }
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push_str(nl);
    }
    for part in [DASHES, "END ", label, DASHES, nl] {
        pem.push_str(part);
    }
    pem
}

/// org.json `getString`.
pub(crate) fn get_string<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    match obj.get(key) {
        None => Err(not_found(key)),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(wrong_type(key, "a string")),
    }
}

/// org.json `getJSONObject`.
pub(crate) fn get_object<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    match obj.get(key) {
        None => Err(not_found(key)),
        Some(Value::Object(o)) => Ok(o),
        Some(_) => Err(wrong_type(key, "a JSONObject")),
    }
}

/// org.json `getJSONArray`.
pub(crate) fn get_array<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], Failure> {
    match obj.get(key) {
        None => Err(not_found(key)),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(wrong_type(key, "a JSONArray")),
    }
}

/// org.json `getInt` ([`int_value`]).
pub(crate) fn get_int(obj: &Map<String, Value>, key: &str) -> Result<i32, Failure> {
    let value = obj.get(key).ok_or_else(|| not_found(key))?;
    int_value(value).ok_or_else(|| wrong_type(key, "a int"))
}

/// org.json `optBoolean`: a boolean, or the string `true`/`false` in any case.
pub(crate) fn opt_bool(obj: &Map<String, Value>, key: &str, default: bool) -> bool {
    match obj.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => true,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") => false,
        _ => default,
    }
}

/// `value.toString()` of an org.json `toMap()`/`toList()` value; null is a
/// NullPointerException.
pub(crate) fn java_string(value: &Value) -> Result<String, Failure> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Null => Err(null_pointer()),
        other => Ok(other.to_string()),
    }
}

pub(crate) fn null_pointer() -> Failure {
    Failure::Invocation(Some("java.lang.NullPointerException".to_owned()))
}

pub(crate) fn not_found(key: &str) -> Failure {
    json_exception(format!("JSONObject[\"{key}\"] not found."))
}

pub(crate) fn wrong_type(key: &str, what: &str) -> Failure {
    json_exception(format!("JSONObject[\"{key}\"] is not {what}."))
}

/// An org.json error escaping the method: INVOCATION_ERROR with the exception as details.
pub(crate) fn json_exception(message: String) -> Failure {
    Failure::Invocation(Some(format!("org.json.JSONException: {message}")))
}

/// `(String) value` on a JSON value that is not a string.
pub(crate) fn class_cast(value: &Value) -> Failure {
    // JRE 8 (bundled with the original) words it without "class " or module details.
    Failure::Invocation(Some(format!(
        "java.lang.ClassCastException: {} cannot be cast to java.lang.String",
        java_class(value)
    )))
}

/// Java class of a value of org.json's `JSONArray.toList()` (org.json 20211205
/// `stringToNumber`): integers are the narrowest of Integer, Long, BigInteger; numbers in
/// decimal notation are BigDecimal, except negative zero (`-0`, `-0.0`, …), a Double.
fn java_class(value: &Value) -> &'static str {
    match value {
        Value::Null => "org.json.JSONObject$Null",
        Value::Bool(_) => "java.lang.Boolean",
        Value::Number(n) if n.as_i64().is_some_and(|n| i32::try_from(n).is_ok()) => {
            "java.lang.Integer"
        }
        Value::Number(n) if n.is_i64() => "java.lang.Long",
        Value::Number(n) if n.is_u64() => "java.math.BigInteger",
        // serde_json parses `-0` to the f64 −0.0 as well.
        Value::Number(n) if n.as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative()) => {
            "java.lang.Double"
        }
        Value::Number(_) => "java.math.BigDecimal",
        Value::String(_) => "java.lang.String",
        Value::Array(_) => "java.util.ArrayList",
        Value::Object(_) => "java.util.HashMap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pdk::serde_json::{self, json};

    #[test]
    fn org_json_accessors() {
        let obj = json!({"s": "v", "n": 5, "null": null, "b": "TRUE", "o": {}, "a": []});
        let obj = obj.as_object().unwrap();
        assert_eq!(get_string(obj, "s"), Ok("v"));
        assert_eq!(
            get_string(obj, "n"),
            Err(Failure::Invocation(Some(
                "org.json.JSONException: JSONObject[\"n\"] is not a string.".to_owned()
            )))
        );
        assert_eq!(
            get_string(obj, "x"),
            Err(Failure::Invocation(Some(
                "org.json.JSONException: JSONObject[\"x\"] not found.".to_owned()
            )))
        );
        assert!(get_object(obj, "o").is_ok());
        assert!(get_object(obj, "a").is_err());
        assert!(get_array(obj, "a").is_ok());
        assert!(get_array(obj, "null").is_err());
        assert!(opt_bool(obj, "b", false));
        assert!(!opt_bool(obj, "n", false));
        assert!(opt_bool(obj, "x", true));
    }

    #[test]
    fn get_int_reads_as_org_json() {
        let obj = json!({"n": 2048, "f": 2048.9, "s": "3072", "x": "abc", "b": true, "big": 4294969344_u64});
        let obj = obj.as_object().unwrap();
        assert_eq!(get_int(obj, "n"), Ok(2048));
        assert_eq!(get_int(obj, "f"), Ok(2048));
        assert_eq!(get_int(obj, "s"), Ok(3072));
        assert_eq!(get_int(obj, "big"), Ok(2048));
        let not_int = Err(Failure::Invocation(Some(
            "org.json.JSONException: JSONObject[\"x\"] is not a int.".to_owned(),
        )));
        assert_eq!(get_int(obj, "x"), not_int);
        assert!(get_int(obj, "b").is_err());
        assert_eq!(
            get_int(obj, "missing"),
            Err(Failure::Invocation(Some(
                "org.json.JSONException: JSONObject[\"missing\"] not found.".to_owned()
            )))
        );
    }

    #[test]
    fn java_classes() {
        let class = |v: Value| java_class(&v);
        assert_eq!(class(json!(5)), "java.lang.Integer");
        assert_eq!(class(json!(-2_147_483_648_i64)), "java.lang.Integer");
        assert_eq!(class(json!(2_147_483_648_i64)), "java.lang.Long");
        assert_eq!(class(json!(u64::MAX)), "java.math.BigInteger");
        assert_eq!(class(json!(1.5)), "java.math.BigDecimal");
        assert_eq!(class(json!(0.0)), "java.math.BigDecimal");
        assert_eq!(class(json!(-0.0)), "java.lang.Double");
        for text in ["-0", "-0.0", "-0e3", "1e2", "2.5"] {
            let v: Value = serde_json::from_str(text).unwrap();
            let expected = if text.starts_with("-0") {
                "java.lang.Double"
            } else {
                "java.math.BigDecimal"
            };
            assert_eq!(java_class(&v), expected, "{text}");
        }
        assert_eq!(class(json!(true)), "java.lang.Boolean");
        assert_eq!(class(json!([])), "java.util.ArrayList");
        assert_eq!(class(json!({})), "java.util.HashMap");
        assert_eq!(class(json!("s")), "java.lang.String");
        assert_eq!(class(Value::Null), "org.json.JSONObject$Null");
    }

    #[test]
    fn pem_as_the_core_writes_it() {
        for nl in ["\n", "\r\n"] {
            assert_eq!(
                pem("CERTIFICATE", &[0xfb, 0xff], nl),
                format!("-----BEGIN CERTIFICATE-----{nl}+/8={nl}-----END CERTIFICATE-----{nl}")
            );
        }
        let long = pem("CMS", &[0; 49], "\n");
        let lines: Vec<&str> = long.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2], "AA==");
    }

    #[test]
    fn certificate_texts() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let b64 = encode_base64(&der);
        assert_eq!(pem_or_base64(&b64), Some(der.to_vec()));
        assert_eq!(
            pem_or_base64(&format!(
                "-----BEGIN CERTIFICATE-----\r\n{b64}\r\n-----END CERTIFICATE-----"
            )),
            Some(der.to_vec())
        );
        assert_eq!(pem_body("-----BEGIN X-----abc"), "");
        assert_eq!(pem_body("-----BEGIN X"), "");
        assert_eq!(pem_or_base64("not base64!"), None);
    }
}
