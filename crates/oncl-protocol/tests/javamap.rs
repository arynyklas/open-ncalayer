//! The key order of Java's `HashMap`, against orders the original's replies show.

use oncl_protocol::javamap::{DEFAULT_CAPACITY, iteration_order, string_hash, table_size_for};

/// `keys` in the order a `HashMap` of `capacity` buckets iterates them.
fn ordered<'a>(keys: &[&'a str], capacity: usize) -> Vec<&'a str> {
    iteration_order(keys, capacity)
        .into_iter()
        .map(|i| keys[i])
        .collect()
}

#[test]
fn string_hash_matches_java() {
    assert_eq!(string_hash(""), 0);
    assert_eq!(string_hash("result"), -934_426_595);
    assert_eq!(string_hash("errorCode"), 329_035_797);
    assert_eq!(string_hash("Әлем"), 38_016_074);
    // A supplementary character is two UTF-16 units.
    assert_eq!(string_hash("\u{1F600}"), 1_772_899);
}

#[test]
fn orders_from_the_specs() {
    let new_map = |keys: &[&'static str]| ordered(keys, DEFAULT_CAPACITY);
    assert_eq!(new_map(&["result", "errorCode"]), ["result", "errorCode"]);
    assert_eq!(
        new_map(&["errorCode", "errorMessage"]),
        ["errorMessage", "errorCode"]
    );
    assert_eq!(
        new_map(&["result", "errorCode", "hash"]),
        ["result", "errorCode", "hash"]
    );
    assert_eq!(new_map(&["MD5", "SHA256"]), ["SHA256", "MD5"]);
    assert_eq!(
        new_map(&["filePath", "signature"]),
        ["signature", "filePath"]
    );
    // ResponseMessage, with the uuid put last.
    assert_eq!(
        new_map(&["code", "message", "responseObject", "uuid"]),
        ["responseObject", "code", "message", "uuid"]
    );
    // ResponseForJS.
    assert_eq!(
        new_map(&["code", "message", "responseObject", "responseObjects"]),
        ["responseObjects", "responseObject", "code", "message"]
    );
    // The official KeyInfo bean, its properties put in declaration order.
    assert_eq!(
        new_map(&KEY_INFO),
        [
            "certNotBefore",
            "issuerCn",
            "authorityKeyIdentifier",
            "serialNumber",
            "certNotAfter",
            "issuerDn",
            "alias",
            "keyId",
            "pem",
            "subjectCn",
            "algorithm",
            "subjectDn",
        ]
    );
    // CommonResponse.
    assert_eq!(new_map(&["status", "body"]), ["body", "status"]);
    assert_eq!(
        new_map(&["status", "code", "message", "details"]),
        ["code", "details", "message", "status"]
    );
}

const KEY_INFO: [&str; 12] = [
    "alias",
    "keyId",
    "algorithm",
    "subjectCn",
    "subjectDn",
    "issuerCn",
    "issuerDn",
    "serialNumber",
    "certNotAfter",
    "certNotBefore",
    "authorityKeyIdentifier",
    "pem",
];

#[test]
fn resize_keeps_relative_order() {
    // The thirteenth key doubles the table: keys of one bucket of 16 split between two of
    // 32, each keeping the order they went in.
    let mut keys = KEY_INFO.to_vec();
    keys.push("uuid");
    assert_eq!(
        ordered(&keys, DEFAULT_CAPACITY),
        [
            "certNotBefore",
            "issuerCn",
            "authorityKeyIdentifier",
            "serialNumber",
            "certNotAfter",
            "issuerDn",
            "keyId",
            "uuid",
            "alias",
            "pem",
            "subjectCn",
            "algorithm",
            "subjectDn",
        ]
    );
}

#[test]
fn map_constructor_capacity() {
    assert_eq!(table_size_for(5), 8);
    assert_eq!(table_size_for(3), 4);
    assert_eq!(table_size_for(16), 16);
    assert_eq!(table_size_for(0), 1);
    // `new JSONObject(map)` of 5 entries: a `HashMap` of 8 buckets.
    assert_eq!(
        ordered(&["code", "message", "responseObject", "uuid", "x"], 8),
        ["x", "responseObject", "code", "message", "uuid"]
    );
}

#[test]
fn crowded_bucket_resizes_a_small_table() {
    // Nine keys of one bucket of 16 in a table of 16: the ninth doubles the table, as Java
    // does instead of making a tree of a bucket in a table under 64.
    let mut same: Vec<String> = Vec::new();
    let mut n = 0u32;
    while same.len() < 9 {
        let key = format!("k{n}");
        let h = string_hash(&key) as u32;
        if (h ^ (h >> 16)) & 15 == 0 {
            same.push(key);
        }
        n += 1;
    }
    let keys: Vec<&str> = same.iter().map(String::as_str).collect();
    let eight = ordered(&keys[..8], 16);
    assert_eq!(eight, &keys[..8], "one bucket: the order they went in");
    let bucket32 = |k: &str| {
        let h = string_hash(k) as u32;
        (h ^ (h >> 16)) & 31
    };
    let nine = ordered(&keys, 16);
    let mut expected = keys.clone();
    expected.sort_by_key(|k| bucket32(k));
    assert_eq!(nine, expected);
}
