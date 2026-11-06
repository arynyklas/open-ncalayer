//! Validation of a manifest against the pinned WinGet schemas 1.12.0 (draft 07), offline.
//!
//! The schemas (`xtask/assets/winget/schema-1.12.0/`, from `microsoft/winget-cli`) are embedded
//! and checked against their pinned SHA-256 before they are used. The validator implements
//! exactly the keywords those schemas use and **refuses any other keyword**, so a schema
//! update that needs more fails loudly instead of validating less. Properties a schema does not
//! list are errors here (the schemas themselves allow them; a misspelt key such as
//! `ElevationRequirment` would otherwise pass unnoticed). This is schema validation, not an
//! installer proof.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The manifest schema version.
pub const MANIFEST_VERSION: &str = "1.12.0";

/// What kind of manifest file a document is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `<id>.yaml`.
    Version,
    /// `<id>.locale.<locale>.yaml` of the default locale.
    DefaultLocale,
    /// `<id>.installer.yaml`.
    Installer,
}

impl Kind {
    /// `ManifestType` of the kind.
    pub fn manifest_type(self) -> &'static str {
        match self {
            Kind::Version => "version",
            Kind::DefaultLocale => "defaultLocale",
            Kind::Installer => "installer",
        }
    }

    /// The kind named by a `ManifestType`.
    pub fn of(manifest_type: &str) -> Option<Kind> {
        [Kind::Version, Kind::DefaultLocale, Kind::Installer]
            .into_iter()
            .find(|kind| kind.manifest_type() == manifest_type)
    }

    /// `(file text, pinned SHA-256)` of the schema.
    fn source(self) -> (&'static str, &'static str) {
        match self {
            Kind::Version => (
                include_str!("../../assets/winget/schema-1.12.0/manifest.version.1.12.0.json"),
                "0cdf9c17a0d19221a3612980c95a47d120c4ce532157177aa6af4368a8a78273",
            ),
            Kind::DefaultLocale => (
                include_str!(
                    "../../assets/winget/schema-1.12.0/manifest.defaultLocale.1.12.0.json"
                ),
                "b87eaa2252daf0bc9b2d495a3f7f5547b8b36236bdcc0543cf9f7403bd56707e",
            ),
            Kind::Installer => (
                include_str!("../../assets/winget/schema-1.12.0/manifest.installer.1.12.0.json"),
                "47de5aefdea4e7ccbc8ab4e32e8230671300054bd4f688cd7ca8bdebf459f006",
            ),
        }
    }
}

/// The schema of `kind`, parsed once, after its pinned hash is checked.
///
/// # Panics
///
/// The embedded schema file was changed from the pinned one (a build defect, not an input).
pub fn schema(kind: Kind) -> &'static Value {
    static CACHE: LazyLock<[Value; 3]> = LazyLock::new(|| {
        [Kind::Version, Kind::DefaultLocale, Kind::Installer].map(|kind| {
            let (text, pinned) = kind.source();
            let actual = crate::upstream::hex(&Sha256::digest(text.as_bytes()));
            assert_eq!(
                actual, pinned,
                "the embedded {kind:?} schema is not the pinned one"
            );
            let parsed: Value = serde_json::from_str(text).expect("the pinned schema is JSON");
            let unsupported = unsupported_keywords(&parsed);
            assert!(
                unsupported.is_empty(),
                "the pinned {kind:?} schema uses keywords the validator does not implement: {unsupported:?}"
            );
            parsed
        })
    });
    &CACHE[kind as usize]
}

const KEYWORDS: &[&str] = &[
    "$ref",
    "type",
    "enum",
    "const",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "format",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "properties",
    "required",
    "not",
    "oneOf",
];
const ANNOTATIONS: &[&str] = &[
    "$id",
    "$schema",
    "title",
    "description",
    "default",
    "definitions",
];

/// The keywords of `schema` and everything below it that this validator does not implement.
/// A schema that needs one is not validated at all.
pub fn unsupported_keywords(schema: &Value) -> Vec<String> {
    fn walk(schema: &Value, path: &str, found: &mut Vec<String>) {
        let Some(rules) = schema.as_object() else {
            return;
        };
        for (keyword, value) in rules {
            if !KEYWORDS.contains(&keyword.as_str()) && !ANNOTATIONS.contains(&keyword.as_str()) {
                found.push(format!("{path}/{keyword}"));
            }
            match keyword.as_str() {
                "properties" | "definitions" => {
                    for (name, member) in value.as_object().into_iter().flatten() {
                        walk(member, &format!("{path}/{keyword}/{name}"), found);
                    }
                }
                "items" | "not" => walk(value, &format!("{path}/{keyword}"), found),
                "oneOf" => {
                    for (index, member) in value.as_array().into_iter().flatten().enumerate() {
                        walk(member, &format!("{path}/oneOf/{index}"), found);
                    }
                }
                _ => {}
            }
        }
    }
    let mut found = Vec::new();
    walk(schema, "", &mut found);
    found
}

/// The errors of `instance` against the schema of `kind`; empty when it conforms.
pub fn validate(kind: Kind, instance: &Value) -> Vec<String> {
    let root = schema(kind);
    let mut errors = Vec::new();
    check(root, root, instance, "", &mut errors);
    errors
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "string" => value.is_string(),
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        _ => false,
    }
}

fn pointer(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

fn check(root: &Value, schema: &Value, value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(rules) = schema.as_object() else {
        errors.push(format!("{}: the schema is not an object", pointer(path)));
        return;
    };
    if let Some(reference) = rules.get("$ref") {
        let Some(name) = reference
            .as_str()
            .and_then(|r| r.strip_prefix("#/definitions/"))
        else {
            errors.push(format!(
                "{}: unsupported reference {reference}",
                pointer(path)
            ));
            return;
        };
        match root.pointer(&format!("/definitions/{name}")) {
            // Draft 07: nothing next to `$ref` counts.
            Some(target) => check(root, target, value, path, errors),
            None => errors.push(format!("{}: unknown definition {name}", pointer(path))),
        }
        return;
    }
    if let Some(types) = rules.get("type") {
        let names: Vec<&str> = match types {
            Value::String(name) => vec![name.as_str()],
            Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !names.iter().any(|name| type_matches(name, value)) {
            errors.push(format!(
                "{}: expected {}",
                pointer(path),
                names.join(" or ")
            ));
            return;
        }
    }
    if let Some(options) = rules.get("enum").and_then(Value::as_array)
        && !options.contains(value)
    {
        errors.push(format!(
            "{}: {value} is not one of the allowed values",
            pointer(path)
        ));
    }
    if let Some(constant) = rules.get("const")
        && constant != value
    {
        errors.push(format!("{}: must be {constant}", pointer(path)));
    }
    if let Some(not) = rules.get("not") {
        let mut inner = Vec::new();
        check(root, not, value, path, &mut inner);
        if inner.is_empty() {
            errors.push(format!("{}: {value} is forbidden here", pointer(path)));
        }
    }
    if let Some(options) = rules.get("oneOf").and_then(Value::as_array) {
        let matching = options
            .iter()
            .filter(|option| {
                let mut inner = Vec::new();
                check(root, option, value, path, &mut inner);
                inner.is_empty()
            })
            .count();
        if matching != 1 {
            errors.push(format!(
                "{}: matches {matching} of the alternatives, exactly one is required",
                pointer(path)
            ));
        }
    }
    match value {
        Value::String(text) => check_string(rules, text, path, errors),
        Value::Number(_) => check_number(rules, value, path, errors),
        Value::Array(items) => check_array(root, rules, items, path, errors),
        Value::Object(map) => check_object(root, rules, map, path, errors),
        _ => {}
    }
}

fn check_string(
    rules: &serde_json::Map<String, Value>,
    text: &str,
    path: &str,
    errors: &mut Vec<String>,
) {
    let length = text.chars().count() as u64;
    if let Some(min) = rules.get("minLength").and_then(Value::as_u64)
        && length < min
    {
        errors.push(format!("{}: shorter than {min}", pointer(path)));
    }
    if let Some(max) = rules.get("maxLength").and_then(Value::as_u64)
        && length > max
    {
        errors.push(format!("{}: longer than {max}", pointer(path)));
    }
    if let Some(pattern) = rules.get("pattern").and_then(Value::as_str) {
        match Regex::new(pattern) {
            Ok(re) if re.is_match(text) => {}
            Ok(_) => errors.push(format!(
                "{}: {text:?} does not match {pattern}",
                pointer(path)
            )),
            Err(e) => errors.push(format!(
                "{}: unusable pattern {pattern}: {e}",
                pointer(path)
            )),
        }
    }
    if let Some(format) = rules.get("format").and_then(Value::as_str) {
        match format {
            "date" => {
                if !is_date(text) {
                    errors.push(format!(
                        "{}: {text:?} is not a date (YYYY-MM-DD)",
                        pointer(path)
                    ));
                }
            }
            "long" => {}
            other => errors.push(format!("{}: unsupported format {other}", pointer(path))),
        }
    }
}

fn is_date(text: &str) -> bool {
    static DATE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(\d{4})-(\d{2})-(\d{2})$").expect("a date pattern"));
    let Some(parts) = DATE.captures(text) else {
        return false;
    };
    let number = |i: usize| parts[i].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (number(1) as i32, number(2) as u8, number(3) as u8);
    time::Month::try_from(month)
        .ok()
        .is_some_and(|month| time::Date::from_calendar_date(year, month, day).is_ok())
}

fn check_number(
    rules: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(number) = value.as_f64() else { return };
    if let Some(min) = rules.get("minimum").and_then(Value::as_f64)
        && number < min
    {
        errors.push(format!("{}: below {min}", pointer(path)));
    }
    if let Some(max) = rules.get("maximum").and_then(Value::as_f64)
        && number > max
    {
        errors.push(format!("{}: above {max}", pointer(path)));
    }
    if rules.get("format").and_then(Value::as_str) == Some("long")
        && !(value.is_i64() || value.is_u64())
    {
        errors.push(format!("{}: not an integer", pointer(path)));
    }
}

fn check_array(
    root: &Value,
    rules: &serde_json::Map<String, Value>,
    items: &[Value],
    path: &str,
    errors: &mut Vec<String>,
) {
    let length = items.len() as u64;
    if let Some(min) = rules.get("minItems").and_then(Value::as_u64)
        && length < min
    {
        errors.push(format!("{}: fewer than {min} items", pointer(path)));
    }
    if let Some(max) = rules.get("maxItems").and_then(Value::as_u64)
        && length > max
    {
        errors.push(format!("{}: more than {max} items", pointer(path)));
    }
    if rules.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
        for (index, item) in items.iter().enumerate() {
            if items[..index].contains(item) {
                errors.push(format!(
                    "{}: item {index} repeats an earlier one",
                    pointer(path)
                ));
            }
        }
    }
    if let Some(item_schema) = rules.get("items") {
        for (index, item) in items.iter().enumerate() {
            check(root, item_schema, item, &format!("{path}/{index}"), errors);
        }
    }
}

fn check_object(
    root: &Value,
    rules: &serde_json::Map<String, Value>,
    map: &serde_json::Map<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
) {
    if let Some(required) = rules.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !map.contains_key(name) {
                errors.push(format!("{}: {name} is required", pointer(path)));
            }
        }
    }
    if let Some(properties) = rules.get("properties").and_then(Value::as_object) {
        for (name, member) in map {
            match properties.get(name) {
                Some(member_schema) => {
                    check(
                        root,
                        member_schema,
                        member,
                        &format!("{path}/{name}"),
                        errors,
                    );
                }
                None => errors.push(format!(
                    "{}: {name} is not a property of this manifest",
                    pointer(path)
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_pinned_schemas_load_and_use_only_implemented_keywords() {
        for kind in [Kind::Version, Kind::DefaultLocale, Kind::Installer] {
            // `schema()` audits the whole tree; an empty instance only lacks what is required.
            assert!(unsupported_keywords(schema(kind)).is_empty());
            let errors = validate(kind, &json!({}));
            assert!(
                errors.iter().all(|e| e.contains("is required")),
                "{kind:?}: {errors:?}"
            );
        }
    }

    #[test]
    fn a_keyword_the_validator_lacks_is_found_anywhere_in_a_schema() {
        let schema = json!({
            "type": "object",
            "definitions": { "A": { "type": "string", "allOf": [] } },
            "properties": { "B": { "items": { "additionalProperties": false } } }
        });
        let found = unsupported_keywords(&schema);
        assert_eq!(
            found,
            [
                "/definitions/A/allOf",
                "/properties/B/items/additionalProperties"
            ]
        );
    }
}
