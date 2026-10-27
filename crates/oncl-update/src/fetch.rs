//! Downloading the index of a channel and its signature through an [`HttpTransport`] (the
//! caller's, with its proxy); nothing is checked here but the transport: see
//! [`crate::verify()`].

use oncl_pki::http::{GetOptions, HttpTransport};

use crate::UpdateError;
use crate::index::Channel;
use crate::verify::MAX_INDEX_LEN;

/// The largest signature file read; a minisign signature is about 300 bytes.
const MAX_SIGNATURE_LEN: u64 = 4096;

/// The index and its signature, as downloaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// `<channel>.json`.
    pub index: Vec<u8>,
    /// `<channel>.json.minisig`.
    pub signature: Vec<u8>,
}

/// `<base>/<channel>.json`: the URL of the index of `channel` under `base`, the
/// `updates/v1` directory (with or without a trailing `/`).
pub fn index_url(base: &str, channel: Channel) -> String {
    format!("{}/{channel}.json", base.trim_end_matches('/'))
}

/// Downloads the index of `channel` under `base` ([`index_url`]) and its signature
/// (`.minisig` appended), over HTTPS only (redirects included: [`GetOptions::https_only`]),
/// the index up to [`MAX_INDEX_LEN`] bytes.
///
/// # Errors
///
/// [`UpdateError::Fetch`] if `base` is not `https://`, a request gets no response (a body
/// over its limit or a redirect to plain HTTP included), or a response is not `200`.
pub fn fetch(
    transport: &dyn HttpTransport,
    base: &str,
    channel: Channel,
) -> Result<Fetched, UpdateError> {
    if !base.starts_with("https://") {
        return Err(UpdateError::Fetch(format!("{base} is not an https URL")));
    }
    let url = index_url(base, channel);
    let index = get(transport, &url, MAX_INDEX_LEN)?;
    let signature = get(transport, &format!("{url}.minisig"), MAX_SIGNATURE_LEN)?;
    Ok(Fetched { index, signature })
}

fn get(transport: &dyn HttpTransport, url: &str, max_len: u64) -> Result<Vec<u8>, UpdateError> {
    let opts = GetOptions {
        max_len,
        https_only: true,
        ..GetOptions::default()
    };
    let reply = transport
        .get_with(url, opts)
        .map_err(|e| UpdateError::Fetch(format!("{url}: {e}")))?;
    if reply.status != 200 {
        return Err(UpdateError::Fetch(format!("{url}: HTTP {}", reply.status)));
    }
    // A transport that ignores `max_len` still does not hand over more.
    if reply.body.len() as u64 > max_len {
        return Err(UpdateError::Fetch(format!("{url}: over {max_len} bytes")));
    }
    Ok(reply.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::http::{HttpError, HttpReply};
    use std::sync::Mutex;

    /// Replies from a table by URL and records the limit and `https_only` asked for.
    struct Table {
        replies: Vec<(&'static str, u16, Vec<u8>)>,
        asked: Mutex<Vec<(String, u64, bool)>>,
    }

    impl HttpTransport for Table {
        fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
            self.get_with(url, GetOptions::default())
        }

        fn get_with(&self, url: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
            self.asked
                .lock()
                .unwrap()
                .push((url.to_owned(), opts.max_len, opts.https_only));
            let (_, status, body) = self
                .replies
                .iter()
                .find(|(u, _, _)| *u == url)
                .ok_or_else(|| HttpError("connection refused".to_owned()))?;
            Ok(HttpReply {
                status: *status,
                content_type: None,
                body: body.clone(),
            })
        }

        fn post(&self, _: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
            unreachable!()
        }
    }

    fn table(replies: Vec<(&'static str, u16, Vec<u8>)>) -> Table {
        Table {
            replies,
            asked: Mutex::new(Vec::new()),
        }
    }

    const BASE: &str = "https://example.org/updates/v1";

    #[test]
    fn fetches_index_and_signature_with_limits() {
        let t = table(vec![
            (
                "https://example.org/updates/v1/beta.json",
                200,
                b"{}".to_vec(),
            ),
            (
                "https://example.org/updates/v1/beta.json.minisig",
                200,
                b"sig".to_vec(),
            ),
        ]);
        let fetched = fetch(&t, &format!("{BASE}/"), Channel::Beta).unwrap();
        assert_eq!(fetched.index, b"{}");
        assert_eq!(fetched.signature, b"sig");
        assert_eq!(
            *t.asked.lock().unwrap(),
            [
                (
                    "https://example.org/updates/v1/beta.json".to_owned(),
                    1 << 20,
                    true
                ),
                (
                    "https://example.org/updates/v1/beta.json.minisig".to_owned(),
                    4096,
                    true
                ),
            ]
        );
        assert_eq!(
            index_url(BASE, Channel::Stable),
            format!("{BASE}/stable.json")
        );
    }

    #[test]
    fn failures_are_fetch_errors() {
        let no_sig = table(vec![(
            "https://example.org/updates/v1/beta.json",
            200,
            Vec::new(),
        )]);
        let not_found = table(vec![(
            "https://example.org/updates/v1/beta.json",
            404,
            Vec::new(),
        )]);
        let too_big = table(vec![(
            "https://example.org/updates/v1/beta.json",
            200,
            vec![b' '; (MAX_INDEX_LEN + 1) as usize],
        )]);
        for (t, base, expected) in [
            (&no_sig, BASE, "connection refused"),
            (&not_found, BASE, "HTTP 404"),
            (&too_big, BASE, "over 1048576 bytes"),
            (
                &not_found,
                "http://example.org/updates/v1",
                "not an https URL",
            ),
        ] {
            match fetch(t, base, Channel::Beta) {
                Err(UpdateError::Fetch(m)) => assert!(m.contains(expected), "{m}"),
                other => panic!("{other:?}"),
            }
        }
        assert!(
            not_found.asked.lock().unwrap().len() == 1,
            "http base not requested"
        );
    }
}
