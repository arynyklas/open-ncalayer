//! The one YAML subset WinGet manifests are written in here, and nothing else.
//!
//! The generator writes block mappings, block sequences, plain and double-quoted scalars; the
//! checker reads back exactly that (plus single-quoted scalars, which a reviewer's editor may
//! produce) and refuses everything else: flow collections, anchors and aliases, tags, block
//! scalars, multiple documents, tabs, trailing comments. A manifest that needs a feature of YAML
//! this reader does not have is not one this tool wrote, and it fails loudly instead of being
//! half-read. The real parser of WinGet (`winget validate`) is the independent judge of the
//! files; this module only has to agree with the generator and be strict.

use std::fmt;

use serde_json::{Map, Number, Value};

/// A value of a manifest, in the order it is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Yaml {
    /// A string.
    Str(String),
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A mapping, keys in writing order.
    Map(Vec<(String, Yaml)>),
    /// A sequence.
    Seq(Vec<Yaml>),
}

impl Yaml {
    /// A string value.
    pub fn s(text: impl Into<String>) -> Yaml {
        Yaml::Str(text.into())
    }

    /// A mapping.
    pub fn map<'a>(items: impl IntoIterator<Item = (&'a str, Yaml)>) -> Yaml {
        Yaml::Map(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    /// A sequence of strings.
    pub fn strings<'a>(items: impl IntoIterator<Item = &'a str>) -> Yaml {
        Yaml::Seq(items.into_iter().map(Yaml::s).collect())
    }
}

/// Why a document was not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YamlError {
    /// The 1-based line, if the error belongs to one.
    pub line: Option<usize>,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for YamlError {}

fn error<T>(line: usize, message: impl Into<String>) -> Result<T, YamlError> {
    Err(YamlError {
        line: Some(line),
        message: message.into(),
    })
}

/// Whether `text` may stay unquoted: it cannot be read as another type, and it has none of the
/// characters that carry meaning in YAML.
fn plain_ok(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    if !text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | ':' | '@' | '+' | '-'))
    {
        return false;
    }
    if text.ends_with(':') || text.contains(": ") {
        return false;
    }
    !ambiguous(text)
}

/// Whether a plain scalar `text` would be read as a boolean, null or a number.
fn ambiguous(text: &str) -> bool {
    const WORDS: [&str; 11] = [
        "true", "false", "yes", "no", "on", "off", "y", "n", "null", "~", "nan",
    ];
    let lower = text.to_ascii_lowercase();
    if WORDS.contains(&lower.as_str()) || lower == "inf" || lower == ".inf" {
        return true;
    }
    // Digits with at most one dot and an optional exponent, hexadecimal and octal forms.
    let digits = lower.trim_start_matches(['+', '-']);
    if digits.starts_with("0x") || digits.starts_with("0o") || digits.starts_with("0b") {
        return true;
    }
    let (mantissa, exponent) = match digits.split_once('e') {
        Some((m, e)) => (m, Some(e)),
        None => (digits, None),
    };
    let number_like = !mantissa.is_empty()
        && mantissa.matches('.').count() <= 1
        && mantissa.chars().all(|c| c.is_ascii_digit() || c == '.')
        && mantissa.chars().any(|c| c.is_ascii_digit());
    match exponent {
        None => number_like,
        Some(e) => {
            number_like
                && !e.is_empty()
                && e.trim_start_matches(['+', '-'])
                    .chars()
                    .all(|c| c.is_ascii_digit())
        }
    }
}

fn scalar(text: &str) -> String {
    if plain_ok(text) {
        text.to_owned()
    } else {
        serde_json::to_string(text).expect("a string is JSON")
    }
}

fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn scalar_text(value: &Yaml) -> Option<String> {
    match value {
        Yaml::Str(text) => Some(scalar(text)),
        Yaml::Bool(true) => Some("true".to_owned()),
        Yaml::Bool(false) => Some("false".to_owned()),
        Yaml::Int(number) => Some(number.to_string()),
        Yaml::Map(_) | Yaml::Seq(_) => None,
    }
}

fn emit_map(items: &[(String, Yaml)], indent: usize, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    for (key, value) in items {
        assert!(valid_key(key), "{key:?} is not a manifest key");
        match value {
            Yaml::Map(inner) => {
                assert!(!inner.is_empty(), "{key} is an empty mapping");
                out.push(format!("{pad}{key}:"));
                emit_map(inner, indent + 2, out);
            }
            Yaml::Seq(inner) => {
                assert!(!inner.is_empty(), "{key} is an empty sequence");
                out.push(format!("{pad}{key}:"));
                emit_seq(inner, indent, out);
            }
            other => out.push(format!(
                "{pad}{key}: {}",
                scalar_text(other).expect("a scalar")
            )),
        }
    }
}

fn emit_seq(items: &[Yaml], indent: usize, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    for item in items {
        match item {
            Yaml::Map(inner) => {
                assert!(!inner.is_empty(), "an empty mapping in a sequence");
                let mut lines = Vec::new();
                emit_map(inner, indent + 2, &mut lines);
                let first = lines.remove(0);
                out.push(format!("{pad}- {}", &first[indent + 2..]));
                out.extend(lines);
            }
            Yaml::Seq(_) => panic!("a sequence in a sequence"),
            other => out.push(format!("{pad}- {}", scalar_text(other).expect("a scalar"))),
        }
    }
}

/// The text of a document: `header` as comment lines, a blank line, then `root`.
///
/// # Panics
///
/// `root` is not a mapping, a key is not a plain identifier, or a collection is empty:
/// the generator builds none of these.
pub fn emit(header: &[String], root: &Yaml) -> String {
    let Yaml::Map(items) = root else {
        panic!("a manifest is a mapping");
    };
    let mut lines: Vec<String> = header.iter().map(|line| format!("# {line}")).collect();
    lines.push(String::new());
    emit_map(items, 0, &mut lines);
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

struct Line {
    number: usize,
    indent: usize,
    text: String,
}

fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

/// `key` and the rest of `text` when it is `key: rest` or `key:`.
fn split_key(text: &str) -> Option<(&str, &str)> {
    let colon = text.find(':')?;
    let (key, rest) = (&text[..colon], &text[colon + 1..]);
    if !valid_key(key) {
        return None;
    }
    if rest.is_empty() {
        Some((key, ""))
    } else {
        rest.strip_prefix(' ')
            .map(|rest| (key, rest.trim_start_matches(' ')))
    }
}

fn read_scalar(line: usize, text: &str) -> Result<Value, YamlError> {
    let Some(first) = text.chars().next() else {
        return Ok(Value::Null);
    };
    match first {
        '"' => match serde_json::from_str::<String>(text) {
            Ok(string) => Ok(Value::String(string)),
            Err(_) => error(
                line,
                "a double-quoted scalar that is not a JSON-style string",
            ),
        },
        '\'' => {
            let Some(inner) = text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')) else {
                return error(
                    line,
                    "a single-quoted scalar that does not end at the line's end",
                );
            };
            let mut out = String::new();
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        out.push('\'');
                    } else {
                        return error(line, "a stray quote in a single-quoted scalar");
                    }
                } else {
                    out.push(c);
                }
            }
            Ok(Value::String(out))
        }
        '[' | '{' | '|' | '>' | '&' | '*' | '!' | '%' | '@' | '`' | '?' => error(
            line,
            format!("{first:?} starts a YAML feature this reader does not accept"),
        ),
        _ => {
            if text.contains(" #") || text.ends_with(':') || text.contains(": ") {
                return error(line, "an ambiguous plain scalar (comment or colon)");
            }
            Ok(match text {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                "null" | "~" => Value::Null,
                _ => {
                    let integer = text.strip_prefix('-').unwrap_or(text);
                    if !integer.is_empty()
                        && integer.chars().all(|c| c.is_ascii_digit())
                        && (integer == "0" || !integer.starts_with('0'))
                    {
                        text.parse::<i64>()
                            .map(|n| Value::Number(Number::from(n)))
                            .unwrap_or_else(|_| Value::String(text.to_owned()))
                    } else {
                        Value::String(text.to_owned())
                    }
                }
            })
        }
    }
}

struct Reader {
    lines: Vec<Line>,
    pos: usize,
}

impl Reader {
    fn block(&mut self, indent: usize) -> Result<Value, YamlError> {
        let line = &self.lines[self.pos];
        if is_item(&line.text) {
            self.sequence(indent)
        } else {
            self.mapping(indent)
        }
    }

    fn mapping(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut map = Map::new();
        while self.pos < self.lines.len() {
            let (number, line_indent, text) = {
                let line = &self.lines[self.pos];
                (line.number, line.indent, line.text.clone())
            };
            if line_indent < indent {
                break;
            }
            if line_indent > indent {
                return error(number, "unexpected indentation");
            }
            if is_item(&text) {
                return error(number, "a sequence item where a mapping key is expected");
            }
            let Some((key, rest)) = split_key(&text) else {
                return error(number, "not a `key: value` line");
            };
            if map.contains_key(key) {
                return error(number, format!("duplicate key {key}"));
            }
            self.pos += 1;
            let value = if rest.is_empty() {
                match self.lines.get(self.pos) {
                    Some(next) if next.indent > indent => {
                        let next_indent = next.indent;
                        self.block(next_indent)?
                    }
                    Some(next) if next.indent == indent && is_item(&next.text) => {
                        self.sequence(indent)?
                    }
                    _ => Value::Null,
                }
            } else {
                read_scalar(number, rest)?
            };
            map.insert(key.to_owned(), value);
        }
        Ok(Value::Object(map))
    }

    fn sequence(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut items = Vec::new();
        while self.pos < self.lines.len() {
            let (number, line_indent, text) = {
                let line = &self.lines[self.pos];
                (line.number, line.indent, line.text.clone())
            };
            if line_indent != indent || !is_item(&text) {
                break;
            }
            let content = text[1..].trim_start_matches(' ');
            let offset = text.len() - content.len();
            if content.is_empty() {
                return error(number, "a sequence item with nothing on its line");
            }
            if split_key(content).is_some() && !content.starts_with(['"', '\'']) {
                // A mapping starting on the dash's line: its keys line up with the first one.
                let item_indent = indent + offset;
                let line = &mut self.lines[self.pos];
                line.indent = item_indent;
                line.text = content.to_owned();
                items.push(self.mapping(item_indent)?);
            } else {
                self.pos += 1;
                items.push(read_scalar(number, content)?);
            }
        }
        Ok(Value::Array(items))
    }
}

/// Reads a document of the subset.
///
/// # Errors
///
/// The document uses anything outside the subset or is malformed.
pub fn parse(text: &str) -> Result<Value, YamlError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        if raw.contains('\t') {
            return error(number, "a tab");
        }
        let trimmed = raw.trim_end();
        let content = trimmed.trim_start_matches(' ');
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if content == "---" || content.starts_with("--- ") || content == "..." {
            return error(number, "document markers are not accepted");
        }
        lines.push(Line {
            number,
            indent: trimmed.len() - content.len(),
            text: content.to_owned(),
        });
    }
    if lines.is_empty() {
        return Err(YamlError {
            line: None,
            message: "the document is empty".to_owned(),
        });
    }
    let first = lines[0].indent;
    let mut reader = Reader { lines, pos: 0 };
    let value = reader.block(first)?;
    if reader.pos != reader.lines.len() {
        return error(reader.lines[reader.pos].number, "unexpected indentation");
    }
    if !value.is_object() {
        return Err(YamlError {
            line: None,
            message: "a manifest is a mapping".to_owned(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: &Yaml) -> Value {
        parse(&emit(&[], value)).expect("what is written reads back")
    }

    fn json(yaml: &Yaml) -> Value {
        match yaml {
            Yaml::Str(s) => Value::String(s.clone()),
            Yaml::Bool(b) => Value::Bool(*b),
            Yaml::Int(n) => Value::from(*n),
            Yaml::Seq(items) => Value::Array(items.iter().map(json).collect()),
            Yaml::Map(items) => {
                Value::Object(items.iter().map(|(k, v)| (k.clone(), json(v))).collect())
            }
        }
    }

    #[test]
    fn strings_that_look_like_other_types_stay_strings() {
        let tricky = [
            "true",
            "No",
            "null",
            "~",
            "12",
            "1.5",
            "1e3",
            "0x1F",
            "007",
            "12E34",
            "-5",
            "",
            "a: b",
            "x #y",
            "--silent",
            "1.12.0",
            "10.0.17763.0",
            "it's \"quoted\"",
            "日本語",
            "line\nbreak",
            "https://github.com/a/b/releases/download/v1.0.0/a-b.exe",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            "1234567890123456789012345678901234567890123456789012345678901234",
            "12345678901234567890123456789012345678901234567890123456789E1234",
        ];
        for text in tricky {
            let doc = Yaml::map([
                ("Key", Yaml::s(text)),
                ("List", Yaml::Seq(vec![Yaml::s(text)])),
            ]);
            assert_eq!(roundtrip(&doc), json(&doc), "{text:?}");
        }
    }

    #[test]
    fn nested_structures_and_scalar_types_round_trip() {
        let doc = Yaml::map([
            ("Top", Yaml::s("v")),
            ("Flag", Yaml::Bool(true)),
            ("Off", Yaml::Bool(false)),
            ("Code", Yaml::Int(-4)),
            (
                "Inner",
                Yaml::map([("A", Yaml::s("x")), ("B", Yaml::Int(2))]),
            ),
            (
                "Items",
                Yaml::Seq(vec![
                    Yaml::map([
                        ("Architecture", Yaml::s("x64")),
                        ("Nested", Yaml::map([("K", Yaml::s("v"))])),
                        ("Tail", Yaml::strings(["a", "b"])),
                    ]),
                    Yaml::map([("Architecture", Yaml::s("x86"))]),
                ]),
            ),
            ("Names", Yaml::strings(["p", "q"])),
        ]);
        assert_eq!(roundtrip(&doc), json(&doc));
    }

    #[test]
    fn features_outside_the_subset_are_refused() {
        for text in [
            "A: [1, 2]\n",
            "A: {b: 1}\n",
            "A: &x 1\nB: *x\n",
            "A: !!str 1\n",
            "A: |\n  text\n",
            "A: >\n  text\n",
            "A: 1 # comment\n",
            "---\nA: 1\n",
            "A: 1\nA: 2\n",
            "\tA: 1\n",
            "A: 1\n  B: 2\n",
            "- A\n",
            "A: 'unterminated\n",
        ] {
            assert!(parse(text).is_err(), "{text:?} was accepted");
        }
    }

    #[test]
    fn the_style_of_winget_pkgs_reads_with_an_indentless_sequence() {
        let value = parse(
            "# comment\nPackageIdentifier: a.B\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://x/y\n- Architecture: x86\n  InstallerUrl: https://x/z\nManifestType: installer\n",
        )
        .unwrap();
        assert_eq!(value["Installers"][1]["InstallerUrl"], "https://x/z");
        assert_eq!(value["ManifestType"], "installer");
    }
}
