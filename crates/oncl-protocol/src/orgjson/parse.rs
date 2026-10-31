//! `new JSONObject(text)` of org.json 20211205: its `JSONTokener`, its leniency (single
//! quotes, unquoted words, `;` between pairs, text after the object ignored), its number
//! forms and its error messages with their position.

use super::value::{JObject, JValue};

/// The deepest nesting of objects and arrays read. org.json has no limit of its own (a
/// deeper text ends its thread in a `StackOverflowError`); this one keeps the reader's
/// recursion within a thread's stack. A deeper text is an error.
const MAX_DEPTH: usize = 512;

/// `new JSONObject(text)`: the object, or org.json's `JSONException` message, such as
/// `A JSONObject text must begin with '{' at 1 [character 2 line 1]` or
/// `Duplicate key "a" at 13 [character 14 line 1]`. Keys go in as they come, into a
/// `new JSONObject()` (a `HashMap` of 16 buckets), nested objects too.
pub fn parse(text: &str) -> Result<JValue, String> {
    Tokener::new(text).object(Keep::All).map(JValue::Obj)
}

/// `new JSONObject(text).toString()`.
pub fn reserialize(text: &str) -> Result<String, String> {
    parse(text).map(|value| value.to_json())
}

/// What [`scan`] reads of an object's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scanned {
    /// The value of the key asked for, if the object has it.
    pub value: Option<JValue>,
    /// The length in bytes of the object's text, through its closing `}`. org.json does
    /// not read what follows.
    pub len: usize,
}

/// `new JSONObject(text)` as a check: [`parse`]'s errors (a key repeated in any object
/// among them), but only the value of the top-level `key` is kept. The other values are
/// read and dropped, so a request carrying a document of megabytes is not copied.
pub fn scan(text: &str, key: &str) -> Result<Scanned, String> {
    let mut tokener = Tokener::new(text);
    let mut object = tokener.object(Keep::Key(key))?;
    Ok(Scanned {
        value: object.remove(key),
        len: tokener.pos,
    })
}

/// Which values the reader keeps; the others are read, checked and dropped (their keys are
/// kept, with `null` in place of the value, for the duplicate-key check).
#[derive(Clone, Copy)]
enum Keep<'k> {
    All,
    Nothing,
    /// The value of this key of the object; nothing below the other keys.
    Key(&'k str),
}

impl Keep<'_> {
    /// Whether values are kept inside a value this one keeps.
    fn all(self) -> bool {
        matches!(self, Keep::All)
    }
}

/// org.json's `JSONTokener` over the UTF-16 code units of a text, decoded as it reads.
struct Tokener<'t> {
    text: &'t str,
    /// The byte offset of the next character in `text`.
    pos: usize,
    /// The low surrogate of the last character read, still to be returned.
    low: Option<u16>,
    eof: bool,
    use_previous: bool,
    previous: u16,
    /// What `toString()` reports: units read, the column and the line.
    index: usize,
    character: usize,
    line: usize,
    character_previous_line: usize,
    /// Objects and arrays open.
    depth: usize,
}

impl<'t> Tokener<'t> {
    fn new(text: &'t str) -> Tokener<'t> {
        Tokener {
            text,
            pos: 0,
            low: None,
            eof: false,
            use_previous: false,
            previous: 0,
            index: 0,
            character: 1,
            line: 1,
            character_previous_line: 0,
            depth: 0,
        }
    }

    /// The next UTF-16 unit of `text`, `0` at its end.
    fn unit(&mut self) -> u16 {
        if let Some(low) = self.low.take() {
            return low;
        }
        let Some(c) = self.text[self.pos..].chars().next() else {
            return 0;
        };
        self.pos += c.len_utf8();
        let mut units = [0; 2];
        let units = c.encode_utf16(&mut units);
        if let [_, low] = units {
            self.low = Some(*low);
        }
        units[0]
    }

    /// `next()`: the next unit, `0` at the end.
    fn next(&mut self) -> u16 {
        let c = if self.use_previous {
            self.use_previous = false;
            self.previous
        } else {
            self.unit()
        };
        if c == 0 {
            self.eof = true;
            return 0;
        }
        self.index += 1;
        if c == u16::from(b'\r') {
            self.line += 1;
            self.character_previous_line = self.character;
            self.character = 0;
        } else if c == u16::from(b'\n') {
            if self.previous != u16::from(b'\r') {
                self.line += 1;
                self.character_previous_line = self.character;
            }
            self.character = 0;
        } else {
            self.character += 1;
        }
        self.previous = c;
        c
    }

    /// `back()`: the last unit is read again.
    fn back(&mut self) {
        if self.use_previous || self.index == 0 {
            return;
        }
        self.index -= 1;
        if self.previous == u16::from(b'\r') || self.previous == u16::from(b'\n') {
            self.line -= 1;
            self.character = self.character_previous_line;
        } else if self.character > 0 {
            self.character -= 1;
        }
        self.use_previous = true;
        self.eof = false;
    }

    /// `nextClean()`: the next unit above U+0020, or `0`.
    fn next_clean(&mut self) -> u16 {
        loop {
            let c = self.next();
            if c == 0 || c > u16::from(b' ') {
                return c;
            }
        }
    }

    /// `syntaxError(message)`'s message.
    fn error(&self, message: &str) -> String {
        format!(
            "{message} at {} [character {} line {}]",
            self.index, self.character, self.line
        )
    }

    /// Enters an object or an array: an error beyond [`MAX_DEPTH`].
    fn enter(&mut self) -> Result<(), String> {
        if self.depth == MAX_DEPTH {
            return Err(self.error("Nesting too deep"));
        }
        self.depth += 1;
        Ok(())
    }

    /// `new JSONObject(tokener)`, with the values `keep` asks for.
    fn object(&mut self, keep: Keep<'_>) -> Result<JObject, String> {
        if self.next_clean() != u16::from(b'{') {
            return Err(self.error("A JSONObject text must begin with '{'"));
        }
        self.enter()?;
        let mut object = JObject::hash_map();
        loop {
            match self.next_clean() {
                0 => return Err(self.error("A JSONObject text must end with '}'")),
                c if c == u16::from(b'}') => break,
                _ => self.back(),
            }
            let key = self.value(Keep::All)?.java_string();
            if self.next_clean() != u16::from(b':') {
                return Err(self.error("Expected a ':' after a key"));
            }
            if object.get(&key).is_some() {
                return Err(self.error(&format!("Duplicate key \"{key}\"")));
            }
            let value = match keep {
                Keep::Key(wanted) if wanted == key => self.value(Keep::All)?,
                Keep::All => self.value(Keep::All)?,
                Keep::Key(_) | Keep::Nothing => self.value(Keep::Nothing)?,
            };
            object.put(key, value);
            match self.next_clean() {
                c if c == u16::from(b';') || c == u16::from(b',') => {
                    if self.next_clean() == u16::from(b'}') {
                        break;
                    }
                    self.back();
                }
                c if c == u16::from(b'}') => break,
                _ => return Err(self.error("Expected a ',' or '}'")),
            }
        }
        self.depth -= 1;
        Ok(object)
    }

    /// `new JSONArray(tokener)`; its elements only if `keep`.
    fn array(&mut self, keep: bool) -> Result<Vec<JValue>, String> {
        if self.next_clean() != u16::from(b'[') {
            return Err(self.error("A JSONArray text must start with '['"));
        }
        self.enter()?;
        let mut items = Vec::new();
        let c = self.next_clean();
        if c == 0 {
            return Err(self.error("Expected a ',' or ']'"));
        }
        if c != u16::from(b']') {
            self.back();
            loop {
                let item = if self.next_clean() == u16::from(b',') {
                    self.back();
                    JValue::Null
                } else {
                    self.back();
                    self.value(if keep { Keep::All } else { Keep::Nothing })?
                };
                if keep {
                    items.push(item);
                }
                match self.next_clean() {
                    0 => return Err(self.error("Expected a ',' or ']'")),
                    c if c == u16::from(b',') => {
                        let c = self.next_clean();
                        if c == 0 {
                            return Err(self.error("Expected a ',' or ']'"));
                        }
                        if c == u16::from(b']') {
                            break;
                        }
                        self.back();
                    }
                    c if c == u16::from(b']') => break,
                    _ => return Err(self.error("Expected a ',' or ']'")),
                }
            }
        }
        self.depth -= 1;
        Ok(items)
    }

    /// `nextValue()`; a value not kept is `null`.
    fn value(&mut self, keep: Keep<'_>) -> Result<JValue, String> {
        let keep = keep.all();
        let c = self.next_clean();
        if c == u16::from(b'"') || c == u16::from(b'\'') {
            let s = self.string(c, keep)?;
            return Ok(if keep { JValue::Str(s) } else { JValue::Null });
        }
        if c == u16::from(b'{') {
            self.back();
            let object = self.object(if keep { Keep::All } else { Keep::Nothing })?;
            return Ok(if keep {
                JValue::Obj(object)
            } else {
                JValue::Null
            });
        }
        if c == u16::from(b'[') {
            self.back();
            let items = self.array(keep)?;
            return Ok(if keep {
                JValue::Arr(items)
            } else {
                JValue::Null
            });
        }
        let mut word = Vec::new();
        // Whether a unit above U+0020 came: the word is not blank after `trim()`.
        let mut filled = false;
        let mut c = c;
        while c >= u16::from(b' ') && !",:]}/\\\"[{;=#".encode_utf16().any(|stop| stop == c) {
            filled |= c > u16::from(b' ');
            if keep {
                word.push(c);
            }
            c = self.next();
        }
        if !self.eof {
            self.back();
        }
        if !filled {
            return Err(self.error("Missing value"));
        }
        if !keep {
            return Ok(JValue::Null);
        }
        let word = String::from_utf16_lossy(&word);
        // `String.trim()`: units up to U+0020 at both ends.
        Ok(string_to_value(word.trim_matches(|c: char| c <= ' ')))
    }

    /// `nextString(quote)`; the string only if `keep` (else it is checked and dropped).
    fn string(&mut self, quote: u16, keep: bool) -> Result<String, String> {
        let mut out = Vec::new();
        let mut push = |unit: u16| {
            if keep {
                out.push(unit);
            }
        };
        loop {
            let c = self.next();
            match c {
                0 | 0x0a | 0x0d => return Err(self.error("Unterminated string")),
                0x5c => {
                    let escaped = self.next();
                    match escaped {
                        0x62 => push(0x08),
                        0x74 => push(0x09),
                        0x6e => push(0x0a),
                        0x66 => push(0x0c),
                        0x72 => push(0x0d),
                        0x75 => {
                            let mut hex = [0; 4];
                            for unit in &mut hex {
                                *unit = self.next();
                                if self.eof {
                                    return Err(self.error("Substring bounds error"));
                                }
                            }
                            let hex = String::from_utf16_lossy(&hex);
                            // `(char) Integer.parseInt(hex, 16)`: a sign is allowed, the
                            // low 16 bits are kept.
                            let unit = i32::from_str_radix(&hex, 16)
                                .map_err(|_| self.error("Illegal escape."))?
                                as u16;
                            push(unit);
                        }
                        0x22 | 0x27 | 0x5c | 0x2f => push(escaped),
                        _ => return Err(self.error("Illegal escape.")),
                    }
                }
                c if c == quote => return Ok(String::from_utf16_lossy(&out)),
                c => push(c),
            }
        }
    }
}

/// `JSONObject.stringToValue(word)` of an unquoted word.
fn string_to_value(word: &str) -> JValue {
    if word.eq_ignore_ascii_case("true") {
        return JValue::Bool(true);
    }
    if word.eq_ignore_ascii_case("false") {
        return JValue::Bool(false);
    }
    if word.eq_ignore_ascii_case("null") {
        return JValue::Null;
    }
    let initial = word.as_bytes()[0];
    if (initial.is_ascii_digit() || initial == b'-')
        && let Some(number) = string_to_number(word)
    {
        return number;
    }
    JValue::Str(word.to_owned())
}

/// `JSONObject.stringToNumber(word)`; `None` where it throws. Its retry of a decimal
/// `BigDecimal` rejects through `Double.valueOf` (hex floats, `d`/`f` suffixes) is not
/// emulated.
fn string_to_number(word: &str) -> Option<JValue> {
    if word.contains(['.', 'e', 'E']) || word == "-0" {
        let decimal = BigDecimal::parse(word)?;
        if word.starts_with('-') && decimal.is_zero() {
            // `Double.valueOf(-0.0)`.
            return Some(JValue::Dec("-0.0".to_owned()));
        }
        return Some(JValue::Dec(decimal.to_java_string()));
    }
    let digits = word.strip_prefix('-').unwrap_or(word);
    // Octal-looking `01` and `-01` are refused.
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // `BigInteger`: an `Integer` or a `Long` if it fits, else its digits.
    match word.parse::<i64>() {
        Ok(i) => Some(JValue::Int(i)),
        Err(_) => {
            let digits = digits.trim_start_matches('0');
            let sign = if word.starts_with('-') { "-" } else { "" };
            Some(JValue::Dec(format!("{sign}{digits}")))
        }
    }
}

/// A `java.math.BigDecimal` as `new BigDecimal(text)` reads it: its digits and its scale.
struct BigDecimal {
    negative: bool,
    /// The unscaled value's digits, without leading zeros (`"0"` for zero).
    digits: String,
    scale: i64,
}

impl BigDecimal {
    /// `new BigDecimal(text)`: a sign, digits with at most one point (at least one digit),
    /// an exponent `e`/`E` with an optional sign.
    fn parse(text: &str) -> Option<BigDecimal> {
        let (negative, rest) = match text.as_bytes().first()? {
            b'-' => (true, &text[1..]),
            b'+' => (false, &text[1..]),
            _ => (false, text),
        };
        let (mantissa, exponent) = match rest.find(['e', 'E']) {
            Some(at) => {
                let exponent = &rest[at + 1..];
                let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (&rest[..at], exponent.parse::<i64>().ok()?)
            }
            None => (rest, 0),
        };
        let (int, frac) = match mantissa.split_once('.') {
            Some((int, frac)) => (int, frac),
            None => (mantissa, ""),
        };
        if int.len() + frac.len() == 0
            || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let all: String = format!("{int}{frac}");
        let digits = all.trim_start_matches('0');
        let digits = if digits.is_empty() { "0" } else { digits };
        Some(BigDecimal {
            negative,
            digits: digits.to_owned(),
            scale: i64::try_from(frac.len()).ok()? - exponent,
        })
    }

    fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    /// `BigDecimal.toString()`: plain when the scale is not negative and the adjusted
    /// exponent is at least -6, else scientific (`1E+3`, `1.5E-7`).
    fn to_java_string(&self) -> String {
        let sign = if self.negative && !self.is_zero() {
            "-"
        } else {
            ""
        };
        let n = self.digits.len() as i64;
        let adjusted = -self.scale + (n - 1);
        if self.scale == 0 {
            return format!("{sign}{}", self.digits);
        }
        if self.scale > 0 && adjusted >= -6 {
            let point = n - self.scale;
            return if point > 0 {
                let (int, frac) = self.digits.split_at(point as usize);
                format!("{sign}{int}.{frac}")
            } else {
                let zeros = "0".repeat((-point) as usize);
                format!("{sign}0.{zeros}{}", self.digits)
            };
        }
        let (first, rest) = self.digits.split_at(1);
        let mut out = format!("{sign}{first}");
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('E');
        if adjusted >= 0 {
            out.push('+');
        }
        out.push_str(&adjusted.to_string());
        out
    }
}
