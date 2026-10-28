//! Downloading the index of a channel and its signature through an [`HttpTransport`] (the
//! caller's, with its proxy); nothing is checked here but the transport: see
//! [`crate::verify()`].

use std::time::{Duration, Instant};

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
/// the index up to [`MAX_INDEX_LEN`] bytes, both requests within `timeout` together.
///
/// # Errors
///
/// [`UpdateError::NotPublished`] if the index answers 404: the channel has no index yet.
/// [`UpdateError::Fetch`] if `base` is not `https://`, a request gets no response in time
/// (a body over its limit or a redirect to plain HTTP included), or a response is not
/// `200` (the signature's 404 included: a half-published index is not "not published").
pub fn fetch(
    transport: &dyn HttpTransport,
    base: &str,
    channel: Channel,
    timeout: Duration,
) -> Result<Fetched, UpdateError> {
    if !base.starts_with("https://") {
        return Err(UpdateError::Fetch(format!("{base} is not an https URL")));
    }
    let deadline = Instant::now() + timeout;
    let url = index_url(base, channel);
    let index = match get(transport, &url, MAX_INDEX_LEN, deadline)? {
        Got::NotFound => return Err(UpdateError::NotPublished(channel)),
        Got::Body(body) => body,
    };
    let sig_url = format!("{url}.minisig");
    let signature = match get(transport, &sig_url, MAX_SIGNATURE_LEN, deadline)? {
        Got::NotFound => return Err(UpdateError::Fetch(format!("{sig_url}: HTTP 404"))),
        Got::Body(body) => body,
    };
    Ok(Fetched { index, signature })
}

enum Got {
    Body(Vec<u8>),
    NotFound,
}

/// The body of `url` (status 200), or that it answered 404; any other status is an error.
fn get(
    transport: &dyn HttpTransport,
    url: &str,
    max_len: u64,
    deadline: Instant,
) -> Result<Got, UpdateError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(UpdateError::Fetch(format!("{url}: no time left")));
    }
    let opts = GetOptions {
        timeout: left,
        connect_timeout: GetOptions::default().connect_timeout.min(left),
        max_len,
        https_only: true,
    };
    let reply = transport
        .get_with(url, opts)
        .map_err(|e| UpdateError::Fetch(format!("{url}: {e}")))?;
    match reply.status {
        200 => {}
        404 => return Ok(Got::NotFound),
        status => return Err(UpdateError::Fetch(format!("{url}: HTTP {status}"))),
    }
    // A transport that ignores `max_len` still does not hand over more.
    if reply.body.len() as u64 > max_len {
        return Err(UpdateError::Fetch(format!("{url}: over {max_len} bytes")));
    }
    Ok(Got::Body(reply.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::http::{HttpError, HttpReply};
    use std::sync::Mutex;

    /// Replies from a table by URL and records the limit, `https_only` and timeout asked
    /// for.
    struct Table {
        replies: Vec<(&'static str, u16, Vec<u8>)>,
        asked: Mutex<Vec<(String, u64, bool)>>,
        timeouts: Mutex<Vec<Duration>>,
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
            self.timeouts.lock().unwrap().push(opts.timeout);
            assert!(opts.connect_timeout <= opts.timeout);
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
            timeouts: Mutex::new(Vec::new()),
        }
    }

    const BUDGET: Duration = Duration::from_secs(15);

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
        let fetched = fetch(&t, &format!("{BASE}/"), Channel::Beta, BUDGET).unwrap();
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
        // Both requests within the one budget.
        let timeouts = t.timeouts.lock().unwrap();
        assert!(timeouts.iter().all(|t| *t <= BUDGET), "{timeouts:?}");
    }

    #[test]
    fn failures_are_fetch_errors() {
        let no_sig = table(vec![(
            "https://example.org/updates/v1/beta.json",
            200,
            Vec::new(),
        )]);
        let sig_not_found = table(vec![
            ("https://example.org/updates/v1/beta.json", 200, Vec::new()),
            (
                "https://example.org/updates/v1/beta.json.minisig",
                404,
                Vec::new(),
            ),
        ]);
        let server_error = table(vec![(
            "https://example.org/updates/v1/beta.json",
            503,
            Vec::new(),
        )]);
        let too_big = table(vec![(
            "https://example.org/updates/v1/beta.json",
            200,
            vec![b' '; (MAX_INDEX_LEN + 1) as usize],
        )]);
        let http = table(Vec::new());
        for (t, base, expected) in [
            (&no_sig, BASE, "connection refused"),
            (&sig_not_found, BASE, "minisig: HTTP 404"),
            (&server_error, BASE, "HTTP 503"),
            (&too_big, BASE, "over 1048576 bytes"),
            (&http, "http://example.org/updates/v1", "not an https URL"),
        ] {
            match fetch(t, base, Channel::Beta, BUDGET) {
                Err(UpdateError::Fetch(m)) => assert!(m.contains(expected), "{m}"),
                other => panic!("{other:?}"),
            }
        }
        assert!(
            http.asked.lock().unwrap().is_empty(),
            "http base not requested"
        );

        // No time left: nothing is asked.
        match fetch(&no_sig, BASE, Channel::Beta, Duration::ZERO) {
            Err(UpdateError::Fetch(m)) => assert!(m.contains("no time left"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            no_sig.asked.lock().unwrap().len(),
            2,
            "index and signature, once"
        );
    }

    #[test]
    fn an_index_that_is_not_there_is_not_published() {
        let t = table(vec![(
            "https://example.org/updates/v1/stable.json",
            404,
            Vec::new(),
        )]);
        assert!(matches!(
            fetch(&t, BASE, Channel::Stable, BUDGET),
            Err(UpdateError::NotPublished(Channel::Stable))
        ));
        assert_eq!(t.asked.lock().unwrap().len(), 1, "no signature asked for");
    }
}
