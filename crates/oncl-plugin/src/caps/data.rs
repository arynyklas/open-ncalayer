//! Data the core keeps for a built-in module during one call (capability `builtin`): the
//! long string values of the request, and what the `data_*` functions make of them, so the
//! module's code never copies documents through its interpreter.
//!
//! - Before the call, the request's string values of at least [`DATA_KEPT_STRING_MIN`]
//!   bytes, or of at least [`DATA_KEPT_SHORT_MIN`] bytes in a request longer than
//!   [`DATA_KEPT_LARGE`] (object keys never), are kept, once they add up to at least
//!   [`DATA_KEPT_MIN`] bytes, and replaced by markers: the call's prefix, random and
//!   unknown to the page, followed by a number. A string's length is that of its JSON text
//!   between the quotes, escapes as written. Only a request that is valid JSON is rewritten
//!   (every escape is checked, a lone surrogate is not valid); anything else reaches the
//!   module as the page sent it. Only a module that imports a `data_*` function has its
//!   requests rewritten.
//! - The `data_*` functions take a marker of this call wherever they take data, or the data
//!   itself; what they make is kept and returned as a marker.
//! - After the call, every JSON string of the reply that is exactly a marker of this call
//!   gets the kept data in its place, written as org.json's `JSONObject.quote` writes a
//!   string, as the modules write their replies (`<\/`; the data must be UTF-8), into a
//!   reply allocated once at its length, at most
//!   [`BUILTIN_MAX_REPLY`](crate::BUILTIN_MAX_REPLY) bytes.
//! - All of it goes when the call returns ([`CallData`] lives in the call's context), and
//!   at most `max` bytes are kept at once for a call, and
//!   [`BUILTIN_KEPT_BUDGET`](crate::BUILTIN_KEPT_BUDGET) for all calls of the process: more
//!   is `limit`, and the call's connection is dropped whatever the module answers.

use super::{invalid, limit};
use crate::host::HostState;
use oncl_pdk::abi::{
    Bytes, CmsContent, CmsOutcome, DATA_KEPT_LARGE, DATA_KEPT_MIN, DATA_KEPT_SHORT_MIN,
    DATA_KEPT_STRING_MIN, DataDecodeArgs, DataDecoded, DataDecoding, DataEncodeArgs, DataEncoding,
    DataRef, HostResult, PagePathArgs, PageRead, SignCmsExArgs, SignRawArgs, SignXmlArgs,
    StampArgs, StampOutcome,
};
use oncl_pki::cms::Content;
use oncl_protocol::orgjson::{quote, quoted_len};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The bytes all calls keep now.
static KEPT: AtomicUsize = AtomicUsize::new(0);

/// The data of one call of a built-in module.
pub(crate) struct CallData {
    /// `oncl-data:<32 hex digits>:`, the digits random for each call.
    prefix: String,
    /// By number; `None` once let go.
    kept: Vec<Option<Vec<u8>>>,
    /// The bytes kept now.
    bytes: usize,
    /// The most bytes kept at once.
    max: usize,
}

impl CallData {
    /// No data yet, at most `max` bytes, with a fresh random prefix.
    ///
    /// # Panics
    ///
    /// If the system has no random bytes.
    pub(crate) fn new(max: usize) -> Self {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("random bytes for the data markers");
        let mut prefix = String::from("oncl-data:");
        for b in nonce {
            prefix.push_str(&format!("{b:02x}"));
        }
        prefix.push(':');
        CallData {
            prefix,
            kept: Vec::new(),
            bytes: 0,
            max,
        }
    }

    /// The prefix of this call's markers.
    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Keeps `data`: its marker.
    pub(crate) fn keep(&mut self, data: Vec<u8>) -> HostResult<String> {
        let bytes = self.bytes.saturating_add(data.len());
        if bytes > self.max {
            return Err(limit(format!(
                "the data of a call is at most {} bytes",
                self.max
            )));
        }
        KEPT.try_update(Ordering::AcqRel, Ordering::Acquire, |kept| {
            kept.checked_add(data.len())
                .filter(|total| *total <= crate::BUILTIN_KEPT_BUDGET)
        })
        .map_err(|_| {
            limit(format!(
                "the built-in modules keep at most {} bytes at once",
                crate::BUILTIN_KEPT_BUDGET
            ))
        })?;
        self.bytes = bytes;
        self.kept.push(Some(data));
        Ok(format!("{}{}", self.prefix, self.kept.len() - 1))
    }

    /// The number of `marker`, if it is one of this call's.
    fn number(&self, marker: &[u8]) -> Option<usize> {
        let digits = marker.strip_prefix(self.prefix.as_bytes())?;
        if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    }

    /// The data `marker` stands for.
    pub(crate) fn get(&self, marker: &[u8]) -> HostResult<&[u8]> {
        self.number(marker)
            .and_then(|n| self.kept.get(n))
            .and_then(Option::as_deref)
            .ok_or_else(|| invalid("not a marker of the call's data"))
    }

    /// `bytes` itself, or the data it stands for if it is a marker of this call.
    pub(crate) fn resolve<'a>(&'a self, bytes: &'a [u8]) -> HostResult<&'a [u8]> {
        if bytes.starts_with(self.prefix.as_bytes()) {
            self.get(bytes)
        } else {
            Ok(bytes)
        }
    }

    /// `request` with its long string values kept and replaced by their markers (see the
    /// module's documentation); as it is if it is not valid JSON or they add up to less
    /// than [`DATA_KEPT_MIN`].
    pub(crate) fn keep_request(&mut self, request: &str) -> HostResult<String> {
        if request.len() < DATA_KEPT_MIN || serde_json::from_str::<Strict>(request).is_err() {
            return Ok(request.to_owned());
        }
        let bytes = request.as_bytes();
        // A large request may be a batch of many short documents: they are kept too.
        let shortest = if request.len() > DATA_KEPT_LARGE {
            DATA_KEPT_SHORT_MIN
        } else {
            DATA_KEPT_STRING_MIN
        };
        // The long string values: where they start and end, quotes included.
        let mut long = Vec::new();
        let mut total = 0usize;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'"' {
                i += 1;
                continue;
            }
            let end = string_end(bytes, i);
            if end - i - 2 >= shortest && !is_key(bytes, end) {
                long.push((i, end));
                total += end - i - 2;
            }
            i = end;
        }
        if total < DATA_KEPT_MIN {
            return Ok(request.to_owned());
        }
        // Each marker is the prefix, at most 10 digits and its quotes.
        let replaced: usize = long.iter().map(|(start, end)| end - start).sum();
        let mut out =
            String::with_capacity(request.len() - replaced + long.len() * (self.prefix.len() + 12));
        let mut copied = 0;
        for (start, end) in long {
            let text: String = serde_json::from_str(&request[start..end])
                .map_err(|e| invalid(format!("a request string: {e}")))?;
            let marker = self.keep(text.into_bytes())?;
            out.push_str(&request[copied..start]);
            out.push('"');
            out.push_str(&marker);
            out.push('"');
            copied = end;
        }
        out.push_str(&request[copied..]);
        Ok(out)
    }

    /// `reply` with every JSON string that is exactly a marker of this call replaced by
    /// its data, as org.json's `JSONObject.quote` writes it, allocated once at its length.
    ///
    /// # Errors
    ///
    /// Data a marker of the reply stands for is gone or not UTF-8, or the reply would be
    /// over `max` bytes.
    pub(crate) fn splice(&self, reply: String, max: usize) -> Result<String, String> {
        let quoted = format!("\"{}", self.prefix);
        if !reply.contains(&quoted) {
            return Ok(reply);
        }
        let bytes = reply.as_bytes();
        // The markers: where they start and end, quotes included, and their data.
        let mut markers = Vec::new();
        let mut len = reply.len();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'"' {
                i += 1;
                continue;
            }
            let end = string_end(bytes, i);
            let inner = &bytes[i + 1..end.saturating_sub(1).max(i + 1)];
            if let Some(n) = self.number(inner) {
                let data = self
                    .kept
                    .get(n)
                    .and_then(Option::as_deref)
                    .ok_or("the reply names data the call let go of")?;
                let text = std::str::from_utf8(data)
                    .map_err(|_| "the reply names data that is not text")?;
                len = len - (end - i) + quoted_len(text);
                markers.push((i, end, text));
            }
            i = end;
        }
        if len > max {
            return Err(format!("the reply would be {len} bytes, over {max}"));
        }
        let mut out = String::with_capacity(len);
        let mut copied = 0;
        for (start, end, text) in markers {
            out.push_str(&reply[copied..start]);
            quote(text, &mut out);
            copied = end;
        }
        out.push_str(&reply[copied..]);
        debug_assert_eq!(out.len(), len);
        Ok(out)
    }
}

/// A JSON value checked as `serde_json` reads it into a `Value` (every escape, a lone
/// surrogate refused) without keeping it: unescaped strings are not even copied.
struct Strict;

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Strict)
    }
}

impl<'de> serde::de::Visitor<'de> for Strict {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Strict, E> {
        Ok(Strict)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Strict, E> {
        Ok(Strict)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Strict, E> {
        Ok(Strict)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Strict, E> {
        Ok(Strict)
    }

    fn visit_str<E>(self, _: &str) -> Result<Strict, E> {
        Ok(Strict)
    }

    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        while seq.next_element::<Strict>()?.is_some() {}
        Ok(Strict)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        while map.next_entry::<Strict, Strict>()?.is_some() {}
        Ok(Strict)
    }
}

impl Drop for CallData {
    fn drop(&mut self) {
        KEPT.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// The index just past the JSON string starting at `start` (a `"`), or the end of `bytes`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Whether the string ending before `end` is an object key: a `:` follows it.
fn is_key(bytes: &[u8], end: usize) -> bool {
    bytes[end..]
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b':')
}

/// The call's data: built-in modules only.
fn call_data(state: &mut HostState) -> HostResult<&mut CallData> {
    state
        .call
        .data
        .as_mut()
        .ok_or_else(|| invalid("the call keeps no data"))
}

/// `kept`, the result of keeping data during a call: over a limit, the call's connection is
/// dropped whatever the module answers, as for the request's own data.
fn over_limit_drops<T>(state: &mut HostState, kept: HostResult<T>) -> HostResult<T> {
    if let Err(e) = &kept {
        tracing::error!(
            error = %e,
            "a built-in module's call keeps more data than it may; its connection is dropped"
        );
        state.call.drop = true;
    }
    kept
}

/// [`CallData::keep`] for the call of `state`, through [`over_limit_drops`].
fn keep(state: &mut HostState, bytes: Vec<u8>) -> HostResult<String> {
    let kept = call_data(state)?.keep(bytes);
    over_limit_drops(state, kept)
}

/// `data_read`: a copy of the data.
pub(crate) fn data_read(state: &mut HostState, args: DataRef) -> HostResult<Bytes> {
    let data = call_data(state)?;
    Ok(Bytes::from(data.get(args.data.as_bytes())?.to_vec()))
}

/// `data_decode`: kept text decoded as `args.form` says, and kept.
pub(crate) fn data_decode(state: &mut HostState, args: DataDecodeArgs) -> HostResult<DataDecoded> {
    let data = call_data(state)?;
    let text = std::str::from_utf8(data.get(args.data.as_bytes())?)
        .map_err(|_| invalid("the data is not text"))?;
    let decoded = match args.form {
        DataDecoding::JavaBase64 => oncl_protocol::javab64::decode_java(text),
    };
    match decoded {
        Ok(bytes) => keep(state, bytes).map(DataDecoded::Data),
        Err(message) => Ok(DataDecoded::Invalid(message)),
    }
}

/// `data_encode`: kept data encoded as `args.form` says, and kept.
pub(crate) fn data_encode(state: &mut HostState, args: DataEncodeArgs) -> HostResult<String> {
    use base64::Engine;
    let data = call_data(state)?;
    let encoded = match args.form {
        DataEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .encode(data.get(args.data.as_bytes())?)
            .into_bytes(),
    };
    keep(state, encoded)
}

/// `data_sign_cms`: `keys_sign_cms_ex` of the content (and the CMS co-signed into) a
/// marker names, the CMS in `args.output`'s form kept.
pub(crate) fn data_sign_cms(state: &mut HostState, args: SignCmsExArgs) -> HostResult<CmsOutcome> {
    let mut data = state
        .call
        .data
        .take()
        .ok_or_else(|| invalid("the call keeps no data"))?;
    let signed = (|| {
        let content = match &args.content {
            CmsContent::Data(bytes) => Content::Data(data.resolve(bytes)?),
            CmsContent::Digest(bytes) => Content::Digest(data.resolve(bytes)?),
        };
        let into = match &args.cosign {
            oncl_pdk::abi::CoSign::Into(cms) => Some(data.resolve(cms)?),
            oncl_pdk::abi::CoSign::Auto | oncl_pdk::abi::CoSign::Never => None,
        };
        super::keys::sign_cms_ex(state, &args, content, into)
    })();
    let outcome = match signed {
        Ok(Ok(der)) => {
            let kept = data.keep(super::keys::cms_output(der, args.output).into_vec());
            over_limit_drops(state, kept)
                .map(|marker| CmsOutcome::Signed(Bytes::from(marker.into_bytes())))
        }
        Ok(Err(failure)) => Ok(CmsOutcome::TspFailed(failure)),
        Err(e) => Err(e),
    };
    state.call.data = Some(data);
    outcome
}

/// `data_sign_xml`: `keys_sign_xml` of the document a marker names, the signed document
/// kept.
pub(crate) fn data_sign_xml(state: &mut HostState, args: SignXmlArgs) -> HostResult<String> {
    let mut data = state
        .call
        .data
        .take()
        .ok_or_else(|| invalid("the call keeps no data"))?;
    let signed = data
        .resolve(&args.xml)
        .and_then(|xml| super::keys::sign_xml(state, &args, xml));
    let outcome = match signed {
        Ok(signed) => {
            let kept = data.keep(signed);
            over_limit_drops(state, kept)
        }
        Err(e) => Err(e),
    };
    state.call.data = Some(data);
    outcome
}

/// `data_sign_raw`: `keys_sign_raw` of the data a marker names (or of `args.data` itself):
/// the signature.
pub(crate) fn data_sign_raw(state: &mut HostState, args: SignRawArgs) -> HostResult<Bytes> {
    let data = state
        .call
        .data
        .as_ref()
        .ok_or_else(|| invalid("the call keeps no data"))?;
    let bytes = data.resolve(&args.data)?;
    super::keys::sign_raw(state, args.handle, bytes).map(Bytes::from)
}

/// `data_stamp`: `tsp_stamp` of the CMS a marker names, the stamped CMS kept.
pub(crate) fn data_stamp(state: &mut HostState, args: StampArgs) -> HostResult<StampOutcome> {
    let mut data = state
        .call
        .data
        .take()
        .ok_or_else(|| invalid("the call keeps no data"))?;
    let stamped = data
        .resolve(&args.cms)
        .and_then(|cms| super::crypto::stamp(state, &args, cms));
    let outcome = match stamped {
        Ok(StampOutcome::Stamped(cms)) => {
            let kept = data.keep(cms.into_vec());
            over_limit_drops(state, kept)
                .map(|marker| StampOutcome::Stamped(Bytes::from(marker.into_bytes())))
        }
        other => other,
    };
    state.call.data = Some(data);
    outcome
}

/// `data_page_read`: `page_file_read`, the contents kept.
pub(crate) fn data_page_read(state: &mut HostState, args: PagePathArgs) -> HostResult<PageRead> {
    call_data(state)?;
    match super::files::page_file_read(state, args)? {
        PageRead::Ok(mut file) => {
            let contents = std::mem::take(&mut file.data).into_vec();
            file.data = Bytes::from(keep(state, contents)?.into_bytes());
            Ok(PageRead::Ok(file))
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(c: char) -> String {
        std::iter::repeat_n(c, DATA_KEPT_MIN).collect()
    }

    #[test]
    fn long_values_are_kept_keys_and_short_values_not() {
        let mut data = CallData::new(usize::MAX);
        let value = long('a');
        let key = long('k');
        let request = format!(
            r#"{{"short":"x","data":"{value}","list":["{value}",1],"{key}":true, "esc":"\u0041{value}"}}"#
        );
        let kept = data.keep_request(&request).unwrap();
        let p = data.prefix().to_owned();
        assert_eq!(
            kept,
            format!(
                r#"{{"short":"x","data":"{p}0","list":["{p}1",1],"{key}":true, "esc":"{p}2"}}"#
            )
        );
        assert_eq!(
            data.get(format!("{p}0").as_bytes()).unwrap(),
            value.as_bytes()
        );
        assert_eq!(
            data.get(format!("{p}2").as_bytes()).unwrap(),
            format!("A{value}").as_bytes()
        );
        // Invalid JSON and short requests stay as they are.
        let mut data = CallData::new(usize::MAX);
        let broken = format!(r#"{{"data":"{value}""#);
        assert_eq!(data.keep_request(&broken).unwrap(), broken);
        assert_eq!(data.keep_request(r#"{"a":"b"}"#).unwrap(), r#"{"a":"b"}"#);
        assert!(data.kept.is_empty());
    }

    #[test]
    fn markers_of_another_call_or_unknown_are_refused() {
        let mut one = CallData::new(usize::MAX);
        let two = CallData::new(usize::MAX);
        assert_ne!(one.prefix(), two.prefix());
        let marker = one.keep(b"doc".to_vec()).unwrap();
        assert_eq!(one.resolve(marker.as_bytes()).unwrap(), b"doc");
        assert!(two.get(marker.as_bytes()).is_err());
        // Not a marker of `two`: the bytes themselves.
        assert_eq!(two.resolve(marker.as_bytes()).unwrap(), marker.as_bytes());
        for bad in ["", "x", "1x", "99"] {
            assert!(
                one.get(format!("{}{bad}", one.prefix()).as_bytes())
                    .is_err()
            );
            assert!(
                one.resolve(format!("{}{bad}", one.prefix()).as_bytes())
                    .is_err()
            );
        }
    }

    #[test]
    fn at_most_max_bytes_are_kept() {
        let mut data = CallData::new(10);
        data.keep(vec![0; 6]).unwrap();
        let e = data.keep(vec![0; 5]).unwrap_err();
        assert_eq!(e.code, oncl_pdk::abi::ErrorCode::Limit);
        data.keep(vec![0; 4]).unwrap();
    }

    #[test]
    fn replies_get_the_data_as_org_json_quotes_it() {
        let mut data = CallData::new(usize::MAX);
        let text = "<a x=\"1\">\r\n</a>\u{1}\u{2028}é\\/\u{8}\u{c}\t\u{1f}\u{7f}\u{0}😀\u{85}";
        let quoted = concat!(
            r#""<a x=\"1\">\r\n<\/a>\u0001\u2028é\\/\b\f\t\u001f"#,
            "\u{7f}",
            r#"\u0000😀\u0085""#
        );
        let marker = data.keep(text.as_bytes().to_vec()).unwrap();
        let other = CallData::new(usize::MAX).keep(b"x".to_vec()).unwrap();
        let reply = format!(r#"{{"result":["{marker}","kept","{other}","{marker} and more"]}}"#);
        let spliced = data.splice(reply, usize::MAX).unwrap();
        assert_eq!(
            spliced,
            format!(r#"{{"result":[{quoted},"kept","{other}","{marker} and more"]}}"#)
        );
        // Allocated once, at its length.
        assert_eq!(spliced.capacity(), spliced.len());
        let gone = format!("\"{}7\"", data.prefix());
        assert!(data.splice(gone, usize::MAX).is_err());
        // A reply over the limit is refused.
        let reply = format!("[\"{marker}\"]");
        let fits = quoted.len() + 2;
        assert!(data.splice(reply.clone(), fits - 1).is_err());
        assert_eq!(data.splice(reply, fits).unwrap(), format!("[{quoted}]"));
    }

    #[test]
    fn many_shorter_values_are_kept_once_they_add_up() {
        let value = "a".repeat(DATA_KEPT_STRING_MIN);
        let shorter = "b".repeat(DATA_KEPT_STRING_MIN - 1);
        let count = DATA_KEPT_MIN / DATA_KEPT_STRING_MIN;
        // `count` values of the shortest kept length add up to the threshold.
        let mut data = CallData::new(usize::MAX);
        let request = serde_json::json!({
            "data": vec![value.clone(); count],
            "short": shorter,
        })
        .to_string();
        let kept = data.keep_request(&request).unwrap();
        let p = data.prefix().to_owned();
        let markers: Vec<String> = (0..count).map(|n| format!("{p}{n}")).collect();
        assert_eq!(
            kept,
            serde_json::json!({"data": markers, "short": shorter}).to_string()
        );
        assert_eq!(data.kept.len(), count);
        // One fewer does not add up: nothing is kept.
        let mut data = CallData::new(usize::MAX);
        let request = serde_json::json!({
            "data": vec![value.clone(); count - 1],
            "short": vec![shorter.clone(); count],
        })
        .to_string();
        assert_eq!(data.keep_request(&request).unwrap(), request);
        assert!(data.kept.is_empty());
    }

    #[test]
    fn the_length_is_the_json_text_between_the_quotes() {
        // Exactly the shortest length, escapes counted as written: kept; a byte less: not.
        let escaped = format!("\\u0041{}", "a".repeat(DATA_KEPT_STRING_MIN - 6));
        let request = format!(
            r#"{{"a":"{escaped}","b":"{}","c":"{}"}}"#,
            "b".repeat(DATA_KEPT_STRING_MIN - 1),
            "c".repeat(DATA_KEPT_MIN),
        );
        let mut data = CallData::new(usize::MAX);
        let kept = data.keep_request(&request).unwrap();
        let p = data.prefix().to_owned();
        assert_eq!(
            kept,
            format!(
                r#"{{"a":"{p}0","b":"{}","c":"{p}1"}}"#,
                "b".repeat(DATA_KEPT_STRING_MIN - 1)
            )
        );
        assert_eq!(
            data.get(format!("{p}0").as_bytes()).unwrap(),
            format!("A{}", "a".repeat(DATA_KEPT_STRING_MIN - 6)).as_bytes()
        );
    }

    #[test]
    fn a_large_request_keeps_its_short_values_too() {
        // Over `DATA_KEPT_LARGE` bytes, values from `DATA_KEPT_SHORT_MIN` bytes are kept;
        // shorter ones and keys stay.
        let short = "s".repeat(DATA_KEPT_SHORT_MIN);
        let shorter = "t".repeat(DATA_KEPT_SHORT_MIN - 1);
        let key = "k".repeat(DATA_KEPT_SHORT_MIN);
        let count = DATA_KEPT_LARGE / DATA_KEPT_SHORT_MIN;
        let request = serde_json::json!({
            "data": vec![short.clone(); count],
            "shorter": shorter,
            key.clone(): 1,
        })
        .to_string();
        assert!(request.len() > DATA_KEPT_LARGE);
        let mut data = CallData::new(usize::MAX);
        let kept = data.keep_request(&request).unwrap();
        let p = data.prefix().to_owned();
        let markers: Vec<String> = (0..count).map(|n| format!("{p}{n}")).collect();
        assert_eq!(
            kept,
            serde_json::json!({"data": markers, "shorter": shorter, key: 1}).to_string()
        );
        assert_eq!(
            data.get(format!("{p}0").as_bytes()).unwrap(),
            short.as_bytes()
        );
        // Within `DATA_KEPT_LARGE` bytes, the same values stay.
        let request = serde_json::json!({"data": vec![short; count / 2]}).to_string();
        assert!(request.len() <= DATA_KEPT_LARGE);
        let mut data = CallData::new(usize::MAX);
        assert_eq!(data.keep_request(&request).unwrap(), request);
    }

    #[test]
    fn a_lone_surrogate_leaves_the_request_as_it_is() {
        let value = long('a');
        for escape in [r"\ud800", r"\udc00", r"\ud800\u0041"] {
            let mut data = CallData::new(usize::MAX);
            let request = format!(r#"{{"data":"{value}{escape}","more":"{value}"}}"#);
            assert_eq!(data.keep_request(&request).unwrap(), request);
            assert!(data.kept.is_empty());
            // In a key too.
            let request = format!(r#"{{"k{escape}":"{value}"}}"#);
            assert_eq!(data.keep_request(&request).unwrap(), request);
        }
        // A pair is text.
        let mut data = CallData::new(usize::MAX);
        let request = format!(r#"{{"data":"{value}\ud83d\ude00"}}"#);
        assert_ne!(data.keep_request(&request).unwrap(), request);
        assert_eq!(data.kept.len(), 1);
    }
}
