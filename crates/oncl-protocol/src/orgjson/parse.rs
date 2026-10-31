//! `new JSONObject(text)` of org.json 20211205: its `JSONTokener`, its leniency (single
//! quotes, unquoted words, `;` between pairs, text after the object ignored), its number
//! forms and its error messages with their position.

use super::keyed::KeyHasher;
use super::value::{JObject, JValue};
use std::borrow::Cow;
use std::collections::HashSet;

/// The deepest nesting of objects and arrays read, the outer object included. org.json has
/// no limit of its own (a deeper text ends its thread in a `StackOverflowError`); this one
/// is the depth `serde_json` reads (its recursion limit of 128 leaves 127 levels), so every
/// reader after the envelope reads what it routes: the built-in modules, the core's data
/// rewrite and plugins that read the request with `serde_json`. A deeper text is an error.
pub const MAX_DEPTH: usize = 127;

/// The most heap [`scan`] may hold at once to read a frame, 16 MiB on 32-bit targets (the
/// core's process has 2 GiB there for everything) and 256 MiB on 64-bit ones. It holds
/// the keys of the objects being read (a skipped object's too: that is how a repeated
/// key is found), the text of those not borrowed from the frame (unquoted or escaped), and
/// the wanted key's value if it is a string or a word. The frame itself is not counted. A
/// frame that needs more, a hundred thousand keys in one object and more, is an error:
/// the connection is dropped, as for any text org.json does not read.
#[cfg(target_pointer_width = "64")]
pub const SCAN_BUDGET: usize = 256 << 20;
/// The most heap [`scan`] may hold at once to read a frame (see [`SCAN_BUDGET_32_BIT`]).
#[cfg(not(target_pointer_width = "64"))]
pub const SCAN_BUDGET: usize = SCAN_BUDGET_32_BIT;

/// [`SCAN_BUDGET`] on 32-bit targets, for [`scan_within`] on any target.
pub const SCAN_BUDGET_32_BIT: usize = 16 << 20;

/// The heap charged for a key in a set while its object is read: the set's slot, with its
/// table growing (the old table and the new one coexist). Above the real cost on any target.
const SEEN_COST: usize = 96;
/// The heap charged for an entry of an object that is built, besides [`SEEN_COST`]: the
/// entry in a growing `Vec`, the index and the order.
const ENTRY_COST: usize = 128;
/// The heap charged for an element of an array that is built: a value in a growing `Vec`.
const ITEM_COST: usize = 64;
/// The heap charged for each UTF-16 unit of a string or word while it is decoded: the units
/// (the `Vec` growing), the `String` made of them (growing), and one more copy of it.
const DECODE_COST: usize = 16;
/// The units a decoding string is charged for at a time.
const CHARGE_BLOCK: usize = 4096;

/// `new JSONObject(text)`: the object, or org.json's `JSONException` message, such as
/// `A JSONObject text must begin with '{' at 1 [character 2 line 1]` or
/// `Duplicate key "a" at 13 [character 14 line 1]`. Keys go in as they come, into a
/// `new JSONObject()` (a `HashMap` of 16 buckets), nested objects too.
pub fn parse(text: &str) -> Result<JValue, String> {
    Tokener::new(text).kept_object(Keep::All).map(JValue::Obj)
}

/// `new JSONObject(text)` of which only the top-level `keys` are kept: [`parse`]'s errors
/// (a key repeated in any object among them), and the object holding those of `keys` the
/// text has, as `parse` reads them. The other values are read and dropped, so a request of
/// many keys or large values the reader does not ask for costs no copy of them.
pub fn parse_only(text: &str, keys: &[&str]) -> Result<JObject, String> {
    Tokener::new(text).kept_object(Keep::Keys(keys))
}

/// `new JSONObject(text).toString()`.
pub fn reserialize(text: &str) -> Result<String, String> {
    parse(text).map(|value| value.to_json())
}

/// What [`scan`] reads of an object's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scanned {
    /// The value of the key asked for, if the object has it: a string or a word as
    /// [`parse`] reads it; an object or an array is read and dropped, and an empty one
    /// stands for it.
    pub value: Option<JValue>,
    /// The length in bytes of the object's text, through its closing `}`. org.json does
    /// not read what follows.
    pub len: usize,
}

/// `new JSONObject(text)` as a check: [`parse`]'s errors (a key repeated in any object
/// among them), but only the value of the top-level `key` is kept, and a container not
/// even that (see [`Scanned::value`]). The other values are read and dropped, so a request
/// carrying a document of megabytes is not copied. Within [`SCAN_BUDGET`] of heap: a text
/// that needs more is an error.
pub fn scan(text: &str, key: &str) -> Result<Scanned, String> {
    scan_within(text, key, SCAN_BUDGET)
}

/// [`scan`] within `budget` bytes of heap.
pub fn scan_within(text: &str, key: &str, budget: usize) -> Result<Scanned, String> {
    let mut tokener = Tokener::with_budget(text, budget);
    let mut object = tokener.kept_object(Keep::Shallow(&[key]))?;
    Ok(Scanned {
        value: object.remove(key),
        len: tokener.pos,
    })
}

/// Which values the reader keeps; the others are read, checked and dropped (only their
/// keys are kept, in a set, for the duplicate-key check).
#[derive(Clone, Copy)]
enum Keep<'k> {
    /// Everything, containers built.
    All,
    /// Strings and words; a container is read and dropped, an empty one stands for it.
    Top,
    Nothing,
    /// The values of these keys of the object, as [`Keep::All`]; nothing below the other
    /// keys.
    Keys(&'k [&'k str]),
    /// The values of these keys of the object, as [`Keep::Top`]; nothing below the other
    /// keys.
    Shallow(&'k [&'k str]),
}

impl Keep<'_> {
    /// Whether strings and words are kept.
    fn scalars(self) -> bool {
        matches!(self, Keep::All | Keep::Top)
    }

    /// Whether containers are built.
    fn builds(self) -> bool {
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
    /// The heap left to the reader (see [`SCAN_BUDGET`]).
    left: usize,
}

impl<'t> Tokener<'t> {
    /// A reader of `text` that takes as much heap as it needs.
    fn new(text: &'t str) -> Tokener<'t> {
        Tokener::with_budget(text, usize::MAX)
    }

    /// A reader of `text` that takes at most `budget` bytes of heap at once.
    fn with_budget(text: &'t str, budget: usize) -> Tokener<'t> {
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
            left: budget,
        }
    }

    /// Takes `bytes` of the budget: an error if it has less.
    fn charge(&mut self, bytes: usize) -> Result<(), String> {
        match self.left.checked_sub(bytes) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => Err(self.error("Too much to read")),
        }
    }

    /// Gives back `bytes` that were let go.
    fn refund(&mut self, bytes: usize) {
        self.left = self.left.saturating_add(bytes);
    }

    /// `text` as an owned string; one borrowed from the frame is copied, and charged.
    fn own(&mut self, text: Cow<'t, str>) -> Result<String, String> {
        match text {
            Cow::Owned(text) => Ok(text),
            Cow::Borrowed(text) => {
                self.charge(text.len())?;
                Ok(text.to_owned())
            }
        }
    }

    /// The error of a key read twice.
    fn duplicate(&self, key: &str) -> String {
        self.error(&format!("Duplicate key \"{key}\""))
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

    /// [`object`](Tokener::object) of a `keep` that keeps an object.
    fn kept_object(&mut self, keep: Keep<'_>) -> Result<JObject, String> {
        Ok(self.object(keep)?.expect("a kept object"))
    }

    /// `new JSONObject(tokener)`, with the values `keep` asks for: the whole object for
    /// [`Keep::All`], only the wanted keys for [`Keep::Keys`] and [`Keep::Shallow`], and for
    /// [`Keep::Nothing`] no object at all (`None`: its keys only go into a set, for the
    /// duplicate-key check). A repeated key is found in constant time, whatever is kept.
    fn object(&mut self, keep: Keep<'_>) -> Result<Option<JObject>, String> {
        if self.next_clean() != u16::from(b'{') {
            return Err(self.error("A JSONObject text must begin with '{'"));
        }
        self.enter()?;
        let mut object = (!matches!(keep, Keep::Nothing)).then(JObject::hash_map);
        // The keys read, where the object does not hold them all.
        let mut seen = HashSet::with_hasher(KeyHasher::current());
        // What the keys cost, and of that what the object keeps of them.
        let (mut held, mut kept) = (0, 0);
        loop {
            match self.next_clean() {
                0 => return Err(self.error("A JSONObject text must end with '}'")),
                c if c == u16::from(b'}') => break,
                _ => self.back(),
            }
            let key = self.key()?;
            if self.next_clean() != u16::from(b':') {
                return Err(self.error("Expected a ':' after a key"));
            }
            // An owned key was charged when it was read; the set's slot is charged now.
            let cost = SEEN_COST
                + match &key {
                    Cow::Owned(key) => key.len(),
                    Cow::Borrowed(_) => 0,
                };
            self.charge(SEEN_COST)?;
            held += cost;
            let wanted = match keep {
                Keep::All => Some(Keep::All),
                Keep::Keys(keys) if keys.contains(&&*key) => Some(Keep::All),
                Keep::Shallow(keys) if keys.contains(&&*key) => Some(Keep::Top),
                _ => None,
            };
            let Some(wanted) = wanted else {
                // The key goes into the set; its value is read and dropped.
                if let Some(old) = seen.replace(key) {
                    return Err(self.duplicate(&old));
                }
                self.value(Keep::Nothing)?;
                if self.object_goes_on()? {
                    continue;
                }
                break;
            };
            let repeated = match (keep, &object) {
                (Keep::All, Some(object)) => object.get(&key).is_some(),
                _ => seen.replace(key.clone()).is_some(),
            };
            if repeated {
                return Err(self.duplicate(&key));
            }
            let value = self.value(wanted)?;
            let copied = match &key {
                Cow::Borrowed(text) => text.len(),
                Cow::Owned(_) => 0,
            };
            let key = self.own(key)?;
            held += copied;
            kept += cost + copied;
            if let Some(object) = &mut object {
                self.charge(ENTRY_COST)?;
                held += ENTRY_COST;
                kept += ENTRY_COST;
                object.put(key, value);
            }
            if self.object_goes_on()? {
                continue;
            }
            break;
        }
        self.depth -= 1;
        if !matches!(keep, Keep::All) {
            self.refund(held - kept);
        }
        Ok(object)
    }

    /// After a pair of an object: whether another follows (`false` at the closing `}`).
    fn object_goes_on(&mut self) -> Result<bool, String> {
        match self.next_clean() {
            c if c == u16::from(b';') || c == u16::from(b',') => {
                if self.next_clean() == u16::from(b'}') {
                    return Ok(false);
                }
                self.back();
                Ok(true)
            }
            c if c == u16::from(b'}') => Ok(false),
            _ => Err(self.error("Expected a ',' or '}'")),
        }
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
                    self.charge(ITEM_COST)?;
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

    /// `nextValue()`, as much of it as `keep` keeps; the rest is `null`, or an empty
    /// container for [`Keep::Top`].
    fn value(&mut self, keep: Keep<'_>) -> Result<JValue, String> {
        let kept = keep.scalars();
        let c = self.next_clean();
        if c == u16::from(b'"') || c == u16::from(b'\'') {
            let s = self.string(c, kept)?;
            return Ok(if kept {
                JValue::Str(self.own(s)?)
            } else {
                JValue::Null
            });
        }
        if c == u16::from(b'{') {
            self.back();
            let object = self.object(if keep.builds() {
                Keep::All
            } else {
                Keep::Nothing
            })?;
            return Ok(match (object, keep) {
                (Some(object), _) => JValue::Obj(object),
                (None, Keep::Top) => JValue::Obj(JObject::hash_map()),
                (None, _) => JValue::Null,
            });
        }
        if c == u16::from(b'[') {
            self.back();
            let items = self.array(keep.builds())?;
            return Ok(match keep {
                Keep::All => JValue::Arr(items),
                Keep::Top => JValue::Arr(Vec::new()),
                _ => JValue::Null,
            });
        }
        let mut word = Vec::new();
        // The heap charged for `word`, at [`DECODE_COST`] a unit.
        let mut charged = 0;
        // Whether a unit above U+0020 came: the word is not blank after `trim()`.
        let mut filled = false;
        let mut c = c;
        while c >= u16::from(b' ') && !is_word_stop(c) {
            filled |= c > u16::from(b' ');
            let run = self.run(|b| b < b' ' || is_word_stop(u16::from(b)));
            filled |= run.bytes().any(|b| b > b' ');
            if kept {
                let cost = (1 + run.len()) * DECODE_COST;
                self.charge(cost)?;
                charged += cost;
                word.push(c);
                word.extend(run.encode_utf16());
            }
            c = self.next();
        }
        if !self.eof {
            self.back();
        }
        if !filled {
            return Err(self.error("Missing value"));
        }
        if !kept {
            return Ok(JValue::Null);
        }
        let text = String::from_utf16_lossy(&word);
        drop(word);
        self.refund(charged);
        // The text and the value made of it, then the value alone.
        self.charge(2 * text.len())?;
        // `String.trim()`: units up to U+0020 at both ends.
        let value = string_to_value(text.trim_matches(|c: char| c <= ' '));
        self.refund(text.len());
        Ok(value)
    }

    /// An object's key: `nextValue().toString()`, borrowed from the text when it is a quoted
    /// string without escapes. What an owned key takes of the budget stays charged.
    fn key(&mut self) -> Result<Cow<'t, str>, String> {
        let c = self.next_clean();
        if c == u16::from(b'"') || c == u16::from(b'\'') {
            return self.string(c, true);
        }
        self.back();
        let (start, mark) = (self.pos, self.left);
        Ok(Cow::Owned(match self.value(Keep::All)? {
            JValue::Str(s) => s,
            value => {
                // `toString()` of the value: its JSON text is at most six times the
                // text it was read from, and written into a growing `String`.
                let transient = 16 * (self.pos - start) + 64;
                self.charge(transient)?;
                let text = value.java_string();
                drop(value);
                self.refund(transient);
                // What the value took, let go; the key's text stays.
                self.refund(mark - self.left);
                self.charge(text.len())?;
                text
            }
        }))
    }

    /// `nextString(quote)`; the string only if `keep` (else it is checked and dropped),
    /// borrowed from the text when it has no escapes. An owned string stays charged.
    fn string(&mut self, quote: u16, keep: bool) -> Result<Cow<'t, str>, String> {
        let stop = |b: u8| matches!(b, 0 | b'\n' | b'\r' | b'\\') || u16::from(b) == quote;
        let plain = self.run(stop);
        if self.peek_byte() == Some(quote as u8) {
            self.next();
            return Ok(Cow::Borrowed(plain));
        }
        let mut out = Vec::new();
        // The units charged for (at [`DECODE_COST`] each): `out` holds no more.
        let mut room = 0;
        if keep {
            room = plain.len();
            self.charge(room * DECODE_COST)?;
            out.extend(plain.encode_utf16());
        }
        loop {
            let c = self.next();
            let unit = match c {
                0 | 0x0a | 0x0d => return Err(self.error("Unterminated string")),
                0x5c => {
                    let escaped = self.next();
                    match escaped {
                        0x62 => 0x08,
                        0x74 => 0x09,
                        0x6e => 0x0a,
                        0x66 => 0x0c,
                        0x72 => 0x0d,
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
                            i32::from_str_radix(&hex, 16)
                                .map_err(|_| self.error("Illegal escape."))?
                                as u16
                        }
                        0x22 | 0x27 | 0x5c | 0x2f => escaped,
                        _ => return Err(self.error("Illegal escape.")),
                    }
                }
                c if c == quote => {
                    let text = String::from_utf16_lossy(&out);
                    drop(out);
                    self.refund(room * DECODE_COST);
                    self.charge(text.len())?;
                    return Ok(Cow::Owned(text));
                }
                c => c,
            };
            if keep {
                if out.len() == room {
                    self.charge(CHARGE_BLOCK * DECODE_COST)?;
                    room += CHARGE_BLOCK;
                }
                out.push(unit);
            }
        }
    }

    /// The next byte of `text` if the next unit comes from it unread.
    fn peek_byte(&self) -> Option<u8> {
        if self.use_previous || self.low.is_some() {
            return None;
        }
        self.text.as_bytes().get(self.pos).copied()
    }

    /// Reads at once, as `next()` reads them one by one, the characters from the position up
    /// to the first byte `stop` takes, or the end. `stop` must take NUL, CR and LF (which
    /// `next()` reads otherwise); it is asked of ASCII bytes only, so a run never ends inside
    /// a character. Nothing is read while a unit is still to be returned.
    fn run(&mut self, stop: impl Fn(u8) -> bool) -> &'t str {
        if self.use_previous || self.low.is_some() {
            return "";
        }
        let text: &'t str = self.text;
        let rest = &text[self.pos..];
        let len = rest
            .bytes()
            .position(|b| b.is_ascii() && stop(b))
            .unwrap_or(rest.len());
        let run = &rest[..len];
        let Some(last) = run.chars().next_back() else {
            return run;
        };
        let units: usize = run.chars().map(char::len_utf16).sum();
        self.pos += len;
        self.index += units;
        self.character += units;
        let mut buf = [0; 2];
        self.previous = *last.encode_utf16(&mut buf).last().expect("a unit");
        run
    }
}

/// The units that end an unquoted word besides those below U+0020.
fn is_word_stop(c: u16) -> bool {
    matches!(
        u8::try_from(c),
        Ok(b',' | b':' | b']' | b'}' | b'/' | b'\\' | b'"' | b'[' | b'{' | b';' | b'=' | b'#')
    )
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
