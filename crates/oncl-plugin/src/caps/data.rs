//! Data the core keeps for a built-in module during one call (capability `builtin`): the
//! long string values of the request, and what the `data_*` functions make of them, so the
//! module's code never copies documents through its interpreter.
//!
//! - Before the call, every string value of the request of at least [`DATA_KEPT_MIN`]
//!   bytes (object keys never) is kept and replaced by a marker: the call's prefix, random
//!   and unknown to the page, followed by a number. Only a request that is valid JSON is
//!   rewritten; anything else reaches the module as the page sent it.
//! - The `data_*` functions take a marker of this call wherever they take data, or the data
//!   itself; what they make is kept and returned as a marker.
//! - After the call, every JSON string of the reply that is exactly a marker of this call
//!   gets the kept data in its place, written as `serde_json` writes a string (the data
//!   must be UTF-8).
//! - All of it goes when the call returns ([`CallData`] lives in the call's context), and
//!   at most `max` bytes are kept at once: more is `limit`.

use super::{invalid, limit};
use crate::host::HostState;
use oncl_pdk::abi::{
    Bytes, CmsContent, CmsOutcome, DATA_KEPT_MIN, DataDecodeArgs, DataDecoded, DataDecoding,
    DataEncodeArgs, DataEncoding, DataRef, HostResult, PagePathArgs, PageRead, SignCmsExArgs,
    SignXmlArgs, StampArgs, StampOutcome,
};
use oncl_pki::cms::Content;

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

    /// `request` with its string values of at least [`DATA_KEPT_MIN`] bytes kept and
    /// replaced by their markers; as it is if it is not valid JSON or has none.
    pub(crate) fn keep_request(&mut self, request: &str) -> HostResult<String> {
        if request.len() < DATA_KEPT_MIN
            || serde_json::from_str::<serde::de::IgnoredAny>(request).is_err()
        {
            return Ok(request.to_owned());
        }
        let bytes = request.as_bytes();
        let mut out = String::with_capacity(request.len().min(1 << 20));
        let mut copied = 0;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'"' {
                i += 1;
                continue;
            }
            let end = string_end(bytes, i);
            if end - i >= DATA_KEPT_MIN && !is_key(bytes, end) {
                let text: String = serde_json::from_str(&request[i..end])
                    .map_err(|e| invalid(format!("a request string: {e}")))?;
                let marker = self.keep(text.into_bytes())?;
                out.push_str(&request[copied..i]);
                out.push('"');
                out.push_str(&marker);
                out.push('"');
                copied = end;
            }
            i = end;
        }
        if copied == 0 {
            return Ok(request.to_owned());
        }
        out.push_str(&request[copied..]);
        Ok(out)
    }

    /// `reply` with every JSON string that is exactly a marker of this call replaced by
    /// its data, as `serde_json` writes a string.
    ///
    /// # Errors
    ///
    /// Data a marker of the reply stands for is gone or not UTF-8.
    pub(crate) fn splice(&self, reply: String) -> Result<String, String> {
        let quoted = format!("\"{}", self.prefix);
        if !reply.contains(&quoted) {
            return Ok(reply);
        }
        let bytes = reply.as_bytes();
        let mut out = String::with_capacity(reply.len());
        let mut copied = 0;
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
                out.push_str(&reply[copied..i]);
                out.push_str(&serde_json::to_string(text).expect("a string serializes"));
                copied = end;
            }
            i = end;
        }
        out.push_str(&reply[copied..]);
        Ok(out)
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
        DataDecoding::BasicsBase64 => {
            oncl_protocol::javab64::decode_basics(text).map_err(|e| e.to_string())
        }
    };
    Ok(match decoded {
        Ok(bytes) => DataDecoded::Data(data.keep(bytes)?),
        Err(message) => DataDecoded::Invalid(message),
    })
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
    data.keep(encoded)
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
        Ok(Ok(der)) => data
            .keep(super::keys::cms_output(der, args.output).into_vec())
            .map(|marker| CmsOutcome::Signed(Bytes::from(marker.into_bytes()))),
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
    let outcome = signed.and_then(|signed| data.keep(signed));
    state.call.data = Some(data);
    outcome
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
        Ok(StampOutcome::Stamped(cms)) => data
            .keep(cms.into_vec())
            .map(|marker| StampOutcome::Stamped(Bytes::from(marker.into_bytes()))),
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
            let marker = call_data(state)?.keep(contents)?;
            file.data = Bytes::from(marker.into_bytes());
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
    fn replies_get_the_data_as_serde_json_writes_it() {
        let mut data = CallData::new(usize::MAX);
        let text = "<a x=\"1\">\r\n</a>\u{1}\u{2028}é\\/";
        let marker = data.keep(text.as_bytes().to_vec()).unwrap();
        let other = CallData::new(usize::MAX).keep(b"x".to_vec()).unwrap();
        let reply = serde_json::json!({
            "result": [marker, "kept", other, format!("{marker} and more")],
        })
        .to_string();
        let expected = serde_json::json!({
            "result": [text, "kept", other, format!("{marker} and more")],
        })
        .to_string();
        assert_eq!(data.splice(reply).unwrap(), expected);
        let gone = format!("\"{}7\"", data.prefix());
        assert!(data.splice(gone).is_err());
    }
}
