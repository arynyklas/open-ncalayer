//! org.json 20211205: its writer, its parser and its readers' messages.

use oncl_protocol::orgjson::{
    JObject, JValue, MAX_DEPTH, array_get_int, array_get_object, array_get_string, get_array,
    get_boolean, get_int, get_object, opt_array, opt_boolean, opt_int, opt_object, parse, quoted,
    quoted_len, reserialize, scan, value_to_string,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[test]
fn quote_escapes_like_org_json() {
    assert_eq!(quoted("</a>"), r#""<\/a>""#);
    assert_eq!(quoted("/a"), r#""/a""#);
    assert_eq!(quoted("a/b</c"), r#""a/b<\/c""#);
    assert_eq!(quoted("\"\\"), r#""\"\\""#);
    assert_eq!(quoted("\u{8}\t\n\u{c}\r"), r#""\b\t\n\f\r""#);
    assert_eq!(quoted("\u{1f}\u{0}"), r#""\u001f\u0000""#);
    assert_eq!(quoted("\u{7f}"), "\"\u{7f}\"");
    assert_eq!(
        quoted("\u{80}\u{85}\u{9f}\u{a0}"),
        "\"\\u0080\\u0085\\u009f\u{a0}\""
    );
    assert_eq!(
        quoted("\u{2028}\u{2029}\u{20ac}\u{2100}"),
        "\"\\u2028\\u2029\\u20ac\u{2100}\""
    );
    assert_eq!(quoted("Сәлем"), "\"Сәлем\"");
    assert_eq!(quoted(""), r#""""#);
}

/// `JSONObject.quote` character by character, as org.json writes it.
fn quote_by_chars(s: &str) -> String {
    let mut out = String::from('"');
    let mut previous = '\0';
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            '/' if previous == '<' => out.push_str("\\/"),
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
    out
}

#[test]
fn quote_matches_org_json_char_by_char() {
    // Every character next to an edge of an escaped range, in UTF-8 of each length.
    const ALPHABET: &[char] = &[
        '\0',
        '\u{8}',
        '\t',
        '\n',
        '\u{c}',
        '\r',
        '\u{1f}',
        ' ',
        '"',
        '\\',
        '/',
        '<',
        'a',
        '\u{7f}',
        '\u{80}',
        '\u{9f}',
        '\u{a0}',
        '\u{bf}',
        '\u{c0}',
        'Ә',
        '\u{7ff}',
        '\u{800}',
        '\u{1fff}',
        '\u{2000}',
        '\u{2028}',
        '\u{20ac}',
        '\u{20ff}',
        '\u{2100}',
        '\u{2fff}',
        '\u{3000}',
        '\u{ffff}',
        '\u{10000}',
        '😀',
    ];
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let len = usize::try_from(next() % 12).unwrap();
        let s: String = (0..len)
            .map(|_| ALPHABET[usize::try_from(next()).unwrap() % ALPHABET.len()])
            .collect();
        let expected = quote_by_chars(&s);
        assert_eq!(quoted(&s), expected, "{s:?}");
        assert_eq!(quoted_len(&s), expected.len(), "{s:?}");
    }
    for c in '\0'..=char::MAX {
        let s = format!("<{c}/");
        assert_eq!(quoted(&s), quote_by_chars(&s), "{c:?}");
        assert_eq!(quoted_len(&s), quoted(&s).len(), "{c:?}");
    }
}

#[test]
fn decimal_normalizes() {
    let written = |text: &str| reserialize(&format!(r#"{{"n":{text}}}"#)).unwrap();
    assert_eq!(written("1.0"), r#"{"n":1}"#);
    assert_eq!(written("1.50"), r#"{"n":1.5}"#);
    assert_eq!(written("10.00"), r#"{"n":10}"#);
    assert_eq!(written("1e3"), r#"{"n":1E+3}"#);
    assert_eq!(written("1.5E-7"), r#"{"n":1.5E-7}"#);
    assert_eq!(written("0.000001"), r#"{"n":0.000001}"#);
    assert_eq!(written("-0"), r#"{"n":-0}"#);
    assert_eq!(written("-0.0"), r#"{"n":-0}"#);
    assert_eq!(written("7"), r#"{"n":7}"#);
    assert_eq!(
        written("-9223372036854775808"),
        r#"{"n":-9223372036854775808}"#
    );
    assert_eq!(
        written("123456789012345678901234567890"),
        r#"{"n":123456789012345678901234567890}"#
    );
    // Written as org.json writes a number put by a plugin.
    let mut o = JObject::hash_map();
    o.put("n", JValue::Dec("2.500".to_owned()));
    assert_eq!(o.to_json(), r#"{"n":2.5}"#);
}

#[test]
fn parse_keeps_org_json_forms() {
    // Single quotes, unquoted words, `;` between pairs, text after the object.
    assert_eq!(
        reserialize("{'a':x;\"b\":TRUE,} trailing").unwrap(),
        r#"{"a":"x","b":true}"#
    );
    // A leading zero is not a number.
    assert_eq!(reserialize(r#"{"a":01}"#).unwrap(), r#"{"a":"01"}"#);
    // A string with escapes, `/` and a supplementary character.
    assert_eq!(
        reserialize(r#"{"s":"<\/x>\u0041\ud83d\ude00"}"#).unwrap(),
        "{\"s\":\"<\\/x>A\u{1F600}\"}"
    );
    // Nested objects are `HashMap`s too.
    assert_eq!(
        reserialize(r#"{"o":{"errorCode":1,"errorMessage":2},"a":[1,null,"x"]}"#).unwrap(),
        r#"{"a":[1,null,"x"],"o":{"errorMessage":2,"errorCode":1}}"#
    );
}

#[test]
fn parse_rejects_duplicate_key() {
    assert_eq!(
        parse(r#"{"a":1,"a":2}"#),
        Err(r#"Duplicate key "a" at 11 [character 12 line 1]"#.to_owned())
    );
    assert_eq!(
        parse(r#"{"a":null,"a":2}"#),
        Err(r#"Duplicate key "a" at 14 [character 15 line 1]"#.to_owned())
    );
}

#[test]
fn scan_rejects_duplicate_key_wherever_it_is() {
    let repeated = |text: &str| scan(text, "module").unwrap_err();
    assert!(repeated(r#"{"module":"m","module":"n"}"#).starts_with(r#"Duplicate key "module""#));
    assert!(repeated(r#"{"module":"m","a":1,"a":2}"#).starts_with(r#"Duplicate key "a""#));
    assert!(
        repeated(r#"{"module":"m","args":[{"x":1,"x":{}}]}"#).starts_with(r#"Duplicate key "x""#)
    );
    let scanned = scan(r#"{"a":{"a":1},"module":"m","b":[{"a":2}]} x"#, "module").unwrap();
    assert_eq!(scanned.value, Some(JValue::from("m")));
    assert_eq!(scanned.len, 40);
}

/// The longest the reading of a text of 80 000 keys may take, in any build: in linear time
/// it takes well under a second even unoptimized; in quadratic time it took 17 s optimized.
const MANY_KEYS_BOUND: Duration = Duration::from_secs(10);

/// `n` pairs `"k<i>":<i>` joined by commas.
fn pairs(n: usize, from: usize) -> String {
    (from..from + n)
        .map(|i| format!("\"k{i}\":{i}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn many_keys_read_in_linear_time() {
    const KEYS: usize = 80_000;
    let top = format!(r#"{{{},"module":"m"}}"#, pairs(KEYS, 0));
    let nested = format!(r#"{{"module":"m","args":{{{}}}}}"#, pairs(KEYS, 0));
    assert!(top.len() > 1_000_000);
    for text in [&top, &nested] {
        let start = Instant::now();
        let scanned = scan(text, "module").unwrap();
        assert_eq!(scanned.value, Some(JValue::from("m")));
        assert_eq!(scanned.len, text.len());
        let JValue::Obj(object) = parse(text).unwrap() else {
            unreachable!()
        };
        assert_eq!(object.to_json().len(), text.len());
        assert!(object.into_map().len() <= KEYS + 1);
        assert!(start.elapsed() < MANY_KEYS_BOUND, "{:?}", start.elapsed());
    }
    // The last key repeats the first: found without comparing it with every other.
    let start = Instant::now();
    let repeated = format!(r#"{{"module":"m",{},"k0":0}}"#, pairs(KEYS, 0));
    assert!(
        scan(&repeated, "module")
            .unwrap_err()
            .starts_with(r#"Duplicate key "k0""#)
    );
    assert!(
        parse(&repeated)
            .unwrap_err()
            .starts_with(r#"Duplicate key "k0""#)
    );
    assert!(start.elapsed() < MANY_KEYS_BOUND, "{:?}", start.elapsed());
}

#[test]
fn deep_text_of_many_keys_reads_in_linear_time() {
    // `MAX_DEPTH` levels, each an object of 630 keys and the next level: 80 000 keys.
    const PER_LEVEL: usize = 630;
    let mut text = String::new();
    for level in 0..MAX_DEPTH {
        text.push('{');
        if level == 0 {
            text.push_str(r#""module":"m","#);
        }
        text.push_str(&pairs(PER_LEVEL, level * PER_LEVEL));
        if level + 1 < MAX_DEPTH {
            text.push_str(",\"next\":");
        }
    }
    text.push_str(&"}".repeat(MAX_DEPTH));
    let start = Instant::now();
    assert_eq!(scan(&text, "module").unwrap().len, text.len());
    assert!(parse(&text).is_ok());
    assert!(start.elapsed() < MANY_KEYS_BOUND, "{:?}", start.elapsed());
    // One level more is refused.
    let deeper = format!(r#"{{"a":{text}}}"#);
    assert!(
        scan(&deeper, "module")
            .unwrap_err()
            .starts_with("Nesting too deep")
    );
}

/// `scan` and `parse` against `serde_json` on texts of many keys, optimized:
/// `cargo test --release -p oncl-protocol --test orgjson -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn many_keys_against_serde_json() {
    let median = |f: &dyn Fn()| {
        let mut runs: Vec<Duration> = (0..7)
            .map(|_| {
                let start = Instant::now();
                f();
                start.elapsed()
            })
            .collect();
        runs.sort();
        runs[3]
    };
    for keys in [10_000, 80_000, 200_000] {
        let text = format!(r#"{{{},"module":"m"}}"#, pairs(keys, 0));
        let serde = median(&|| {
            serde_json::from_str::<serde::de::IgnoredAny>(&text).unwrap();
        });
        let serde_value = median(&|| {
            serde_json::from_str::<Value>(&text).unwrap();
        });
        let scanned = median(&|| {
            scan(&text, "module").unwrap();
        });
        let parsed = median(&|| {
            parse(&text).unwrap();
        });
        eprintln!(
            "{keys} keys, {} bytes: serde_json IgnoredAny {serde:?}, Value {serde_value:?}; \
             scan {scanned:?}, parse {parsed:?}",
            text.len()
        );
    }
}

#[test]
fn parse_errors_match_org_json() {
    let error = |text: &str| parse(text).unwrap_err();
    assert_eq!(
        error("[1]"),
        "A JSONObject text must begin with '{' at 1 [character 2 line 1]"
    );
    assert_eq!(
        error(""),
        "A JSONObject text must begin with '{' at 0 [character 1 line 1]"
    );
    assert_eq!(
        error(r#"{"a":1"#),
        "Expected a ',' or '}' at 6 [character 7 line 1]"
    );
    assert_eq!(
        error("{"),
        "A JSONObject text must end with '}' at 1 [character 2 line 1]"
    );
    // org.json steps back over the end of the text and reads the `,` again.
    assert_eq!(
        error(r#"{"a":1,"#),
        "Missing value at 6 [character 7 line 1]"
    );
    assert_eq!(
        error(r#"{"a" 1}"#),
        "Expected a ':' after a key at 6 [character 7 line 1]"
    );
    assert_eq!(
        error(r#"{"a":1 "b":2}"#),
        "Expected a ',' or '}' at 8 [character 9 line 1]"
    );
    assert_eq!(
        error("{\n\"a\":\"x\ny\"}"),
        "Unterminated string at 9 [character 0 line 3]"
    );
    assert_eq!(
        error(r#"{"a":"\x"}"#),
        "Illegal escape. at 8 [character 9 line 1]"
    );
    assert_eq!(
        error(r#"{"a":}"#),
        "Missing value at 5 [character 6 line 1]"
    );
    assert_eq!(
        error(r#"{"a":[1:2]}"#),
        "Expected a ',' or ']' at 8 [character 9 line 1]"
    );
    // An unquoted word runs up to a delimiter, spaces included.
    assert_eq!(reserialize(r#"{"a":[1 2]}"#).unwrap(), r#"{"a":["1 2"]}"#);
}

#[test]
fn readers_messages() {
    let obj = json!({
        "b": "TRUE", "f": false, "n": 5, "s": "12", "x": "x", "null": null,
        "o": {"k": 1}, "a": ["s", 2, {"k": 1}, null]
    });
    let obj = obj.as_object().unwrap();
    assert!(opt_boolean(obj, "b", false));
    assert!(!opt_boolean(obj, "f", true));
    assert!(opt_boolean(obj, "x", true));
    assert!(opt_boolean(obj, "missing", true));
    assert!(opt_boolean(obj, "null", true));
    assert_eq!(get_boolean(obj, "b"), Ok(true));
    assert_eq!(
        get_boolean(obj, "x"),
        Err(r#"JSONObject["x"] is not a Boolean."#.to_owned())
    );
    assert_eq!(
        get_boolean(obj, "missing"),
        Err(r#"JSONObject["missing"] not found."#.to_owned())
    );
    assert_eq!(get_int(obj, "n"), Ok(5));
    assert_eq!(get_int(obj, "s"), Ok(12));
    assert_eq!(
        get_int(obj, "x"),
        Err(r#"JSONObject["x"] is not a int."#.to_owned())
    );
    assert_eq!(
        get_int(obj, "null"),
        Err(r#"JSONObject["null"] is not a int."#.to_owned())
    );
    assert_eq!(opt_int(obj, "n", 2), 5);
    assert_eq!(opt_int(obj, "x", 2), 2);
    assert_eq!(get_object(obj, "o").unwrap().len(), 1);
    assert_eq!(
        get_object(obj, "a"),
        Err(r#"JSONObject["a"] is not a JSONObject."#.to_owned())
    );
    assert!(opt_object(obj, "a").is_none());
    assert_eq!(get_array(obj, "a").unwrap().len(), 4);
    assert_eq!(
        get_array(obj, "o"),
        Err(r#"JSONObject["o"] is not a JSONArray."#.to_owned())
    );
    assert!(opt_array(obj, "o").is_none());
    let arr = get_array(obj, "a").unwrap();
    assert_eq!(array_get_string(arr, 0), Ok("s"));
    assert_eq!(
        array_get_string(arr, 1),
        Err("JSONArray[1] is not a String.".to_owned())
    );
    assert_eq!(
        array_get_string(arr, 3),
        Err("JSONArray[3] is not a String.".to_owned())
    );
    assert_eq!(
        array_get_string(arr, 4),
        Err("JSONArray[4] not found.".to_owned())
    );
    assert_eq!(array_get_int(arr, 1), Ok(2));
    assert_eq!(
        array_get_int(arr, 0),
        Err("JSONArray[0] is not a int.".to_owned())
    );
    assert_eq!(array_get_object(arr, 2).unwrap().len(), 1);
    assert_eq!(
        array_get_object(arr, 0),
        Err("JSONArray[0] is not a JSONObject.".to_owned())
    );
    assert_eq!(value_to_string(&Value::Null), "null");
    assert_eq!(value_to_string(&json!("s")), "s");
    assert_eq!(value_to_string(&json!(2)), "2");
    assert_eq!(
        value_to_string(&json!({"errorCode": 1, "errorMessage": "</x>"})),
        r#"{"errorMessage":"<\/x>","errorCode":1}"#
    );
    // A key is named through `quote` in the messages.
    assert_eq!(
        get_int(obj, "a\"b"),
        Err(r#"JSONObject["a\"b"] not found."#.to_owned())
    );
}

#[test]
fn stringer_keeps_written_order() {
    let mut o = JObject::stringer();
    o.put("errorCode", "NONE")
        .put("errorMessage", "x")
        .put("result", 1);
    assert_eq!(
        o.to_json(),
        r#"{"errorCode":"NONE","errorMessage":"x","result":1}"#
    );
    let mut h = JObject::hash_map();
    h.put("errorCode", "NONE").put("errorMessage", "x");
    assert_eq!(h.to_json(), r#"{"errorMessage":"x","errorCode":"NONE"}"#);
}

#[test]
fn put_none_omits_key() {
    let mut o = JObject::hash_map();
    o.put("result", "r").put_opt::<&str>("errorCode", None);
    assert_eq!(o.to_json(), r#"{"result":"r"}"#);
    // `put(k, null)` removes a key already there; `JSONObject.NULL` is written.
    o.put("errorCode", "NONE");
    o.put_opt::<&str>("result", None);
    o.put("n", JValue::Null);
    assert_eq!(o.to_json(), r#"{"errorCode":"NONE","n":null}"#);
    // A key put again keeps its place.
    let mut o = JObject::hash_map();
    o.put("MD5", 1).put("SHA256", 2).put("MD5", 3);
    assert_eq!(o.to_json(), r#"{"SHA256":2,"MD5":3}"#);
}
