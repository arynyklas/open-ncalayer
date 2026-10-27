//! The signature of an index: minisign (Ed25519 over the BLAKE2b-512 hash of the file, the
//! "prehashed" mode), in `<channel>.json.minisig` beside the index. The signed trusted
//! comment is `channel=<channel>;seq=<seq>` ([`trusted_comment`]) and must name the
//! index's own channel and `seq`.

use minisign_verify::{PublicKey, Signature};
use time::{Duration, OffsetDateTime};

use crate::UpdateError;
use crate::index::{Channel, Index};

/// The largest index read: 1 MiB.
pub const MAX_INDEX_LEN: u64 = 1 << 20;

/// The oldest an index may be, from its `generated`, whatever its `expires` says: an index
/// not signed again within this is refused.
pub const MAX_AGE: Duration = Duration::days(30);

/// The trusted comment a signature of an index of `channel` and `seq` carries.
pub fn trusted_comment(channel: Channel, seq: u64) -> String {
    format!("channel={channel};seq={seq}")
}

/// Verifies an index of `channel` and reads it.
///
/// The index is accepted only if all of these hold:
/// - it is at most [`MAX_INDEX_LEN`] bytes;
/// - `sig_bytes` is a prehashed minisign signature of `index_bytes` by one of `keys` (the
///   current key and the next one, for rotation), its trusted comment included;
/// - the trusted comment names the channel and `seq` of the index, and the index is of
///   `channel`;
/// - the index is valid ([`Index::from_json`]);
/// - its `seq` is not below `last_seq`, the highest `seq` of `channel` accepted before.
///   An equal `seq` is the same index fetched again (every published index of a channel
///   has a new `seq`), so an update that failed to download can be retried with it;
/// - `now` is before its `expires` and less than [`MAX_AGE`] after its `generated`.
///
/// The JSON is parsed only after the signature holds.
///
/// # Errors
///
/// The first rule broken, as [`UpdateError::TooLarge`], [`UpdateError::MalformedSignature`],
/// [`UpdateError::BadSignature`], [`UpdateError::BadTrustedComment`], the errors of
/// [`Index::from_json`], [`UpdateError::CommentMismatch`], [`UpdateError::WrongChannel`],
/// [`UpdateError::Rollback`] or [`UpdateError::Expired`].
pub fn verify(
    index_bytes: &[u8],
    sig_bytes: &[u8],
    keys: &[PublicKey],
    channel: Channel,
    last_seq: Option<u64>,
    now: OffsetDateTime,
) -> Result<Index, UpdateError> {
    if index_bytes.len() as u64 > MAX_INDEX_LEN {
        return Err(UpdateError::TooLarge);
    }
    let signature = std::str::from_utf8(sig_bytes)
        .ok()
        .and_then(|text| Signature::decode(text).ok())
        .ok_or(UpdateError::MalformedSignature)?;
    // `allow_legacy = false`: a signature of the raw file (minisign's legacy mode) fails.
    if !keys
        .iter()
        .any(|key| key.verify(index_bytes, &signature, false).is_ok())
    {
        return Err(UpdateError::BadSignature);
    }
    let (signed_channel, signed_seq) = parse_trusted_comment(signature.trusted_comment())?;
    let index = Index::from_json(index_bytes)?;
    if (signed_channel, signed_seq) != (index.channel, index.seq) {
        return Err(UpdateError::CommentMismatch {
            comment: trusted_comment(signed_channel, signed_seq),
            index: trusted_comment(index.channel, index.seq),
        });
    }
    if index.channel != channel {
        return Err(UpdateError::WrongChannel {
            expected: channel,
            found: index.channel,
        });
    }
    if let Some(last) = last_seq
        && index.seq < last
    {
        return Err(UpdateError::Rollback {
            seq: index.seq,
            last,
        });
    }
    let deadline = match index.generated.checked_add(MAX_AGE) {
        Some(aged) => aged.min(index.expires),
        None => index.expires,
    };
    if now >= deadline {
        return Err(UpdateError::Expired(deadline));
    }
    Ok(index)
}

/// `channel=<channel>;seq=<seq>`, in any order; other `key=value` pairs are ignored, a key
/// given twice is refused.
fn parse_trusted_comment(comment: &str) -> Result<(Channel, u64), UpdateError> {
    let bad = |why: &str| UpdateError::BadTrustedComment(format!("{why} in {comment:?}"));
    let mut channel = None;
    let mut seq = None;
    for pair in comment.split(';') {
        let (key, value) = pair.split_once('=').ok_or_else(|| bad("no key=value"))?;
        match key {
            "channel" => {
                let c = Channel::ALL
                    .into_iter()
                    .find(|c| c.as_str() == value)
                    .ok_or_else(|| bad("unknown channel"))?;
                if channel.replace(c).is_some() {
                    return Err(bad("channel given twice"));
                }
            }
            "seq" => {
                let s = Some(value)
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or_else(|| bad("bad seq"))?;
                if seq.replace(s).is_some() {
                    return Err(bad("seq given twice"));
                }
            }
            _ => {}
        }
    }
    Ok((
        channel.ok_or_else(|| bad("no channel"))?,
        seq.ok_or_else(|| bad("no seq"))?,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::index::tests::index_json;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use minisign::KeyPair;
    use std::io::Cursor;
    use time::macros::datetime;

    /// A key pair made for the test, and its public key as the client reads it.
    pub(crate) struct TestKey {
        pair: KeyPair,
        pub(crate) public: PublicKey,
    }

    impl TestKey {
        pub(crate) fn new() -> TestKey {
            let pair = KeyPair::generate_unencrypted_keypair().unwrap();
            let public = PublicKey::decode(&pair.pk.to_box().unwrap().into_string()).unwrap();
            TestKey { pair, public }
        }

        /// A `.minisig` of `data` with `comment` as its trusted comment.
        pub(crate) fn sign(&self, data: &[u8], comment: &str) -> Vec<u8> {
            minisign::sign(None, &self.pair.sk, Cursor::new(data), Some(comment), None)
                .unwrap()
                .into_string()
                .into_bytes()
        }
    }

    const NOW: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

    fn body(channel: &str, seq: u64) -> Vec<u8> {
        serde_json::to_vec_pretty(&index_json(channel, seq)).unwrap()
    }

    fn signed(key: &TestKey, channel: &str, seq: u64) -> (Vec<u8>, Vec<u8>) {
        let index = body(channel, seq);
        let sig = key.sign(&index, &format!("channel={channel};seq={seq}"));
        (index, sig)
    }

    fn check(index: &[u8], sig: &[u8], keys: &[&TestKey]) -> Result<Index, UpdateError> {
        let keys: Vec<_> = keys.iter().map(|k| k.public.clone()).collect();
        verify(index, sig, &keys, Channel::Beta, Some(40), NOW)
    }

    #[test]
    fn either_trusted_key_verifies() {
        let (current, next) = (TestKey::new(), TestKey::new());
        let (index, sig) = signed(&current, "beta", 42);
        let read = check(&index, &sig, &[&current, &next]).unwrap();
        assert_eq!((read.channel, read.seq), (Channel::Beta, 42));
        let (index, sig) = signed(&next, "beta", 42);
        check(&index, &sig, &[&current, &next]).unwrap();
    }

    #[test]
    fn another_key_is_refused() {
        let (trusted, other) = (TestKey::new(), TestKey::new());
        let (index, sig) = signed(&other, "beta", 42);
        assert!(matches!(
            check(&index, &sig, &[&trusted]),
            Err(UpdateError::BadSignature)
        ));
        assert!(matches!(
            check(&index, &sig, &[]),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn changed_index_or_signature_is_refused() {
        let key = TestKey::new();
        let (index, sig) = signed(&key, "beta", 42);

        let mut changed = index.clone();
        let at = changed.len() / 2;
        changed[at] ^= 1;
        assert!(matches!(
            check(&changed, &sig, &[&key]),
            Err(UpdateError::BadSignature)
        ));

        // The trusted comment is covered by the global signature.
        let text = String::from_utf8(sig.clone()).unwrap();
        let forged = text.replace("seq=42", "seq=99");
        assert_ne!(forged, text);
        assert!(matches!(
            check(&index, forged.as_bytes(), &[&key]),
            Err(UpdateError::BadSignature)
        ));

        // A flipped bit of the signature itself (inside the base64 of line 2).
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let sig_line = &mut lines[1];
        let replacement = if sig_line.as_bytes()[20] == b'A' {
            "B"
        } else {
            "A"
        };
        sig_line.replace_range(20..21, replacement);
        assert!(matches!(
            check(&index, lines.join("\n").as_bytes(), &[&key]),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn legacy_unhashed_signatures_are_refused() {
        let key = TestKey::new();
        let (index, sig) = signed(&key, "beta", 42);
        let text = String::from_utf8(sig).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        // The algorithm is the first two bytes, "ED" (prehashed); "Ed" is the legacy mode.
        let mut raw = STANDARD.decode(lines[1]).unwrap();
        assert_eq!(&raw[..2], b"ED");
        raw[1] = b'd';
        let legacy = STANDARD.encode(&raw);
        lines[1] = &legacy;
        assert!(matches!(
            check(&index, lines.join("\n").as_bytes(), &[&key]),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn malformed_signature_files() {
        let key = TestKey::new();
        let index = body("beta", 42);
        for sig in [&b""[..], b"untrusted comment: x\nnot base64\n", b"\xff\xfe"] {
            assert!(
                matches!(
                    check(&index, sig, &[&key]),
                    Err(UpdateError::MalformedSignature)
                ),
                "{sig:?}"
            );
        }
    }

    #[test]
    fn trusted_comment_must_match_the_index() {
        let key = TestKey::new();
        let index = body("beta", 42);
        for comment in ["channel=beta;seq=41", "channel=stable;seq=42"] {
            let sig = key.sign(&index, comment);
            assert!(
                matches!(
                    check(&index, &sig, &[&key]),
                    Err(UpdateError::CommentMismatch { .. })
                ),
                "{comment}"
            );
        }
        for comment in [
            "timestamp:1700000000\tfile:beta.json",
            "channel=beta",
            "seq=42",
            "channel=beta;seq=42;seq=42",
            "channel=beta;channel=beta;seq=42",
            "channel=nightly;seq=42",
            "channel=beta;seq=+42",
            "channel=beta;seq=",
            "channel=beta;seq=18446744073709551616",
        ] {
            let sig = key.sign(&index, comment);
            assert!(
                matches!(
                    check(&index, &sig, &[&key]),
                    Err(UpdateError::BadTrustedComment(_))
                ),
                "{comment}"
            );
        }
        // Order and other pairs do not matter.
        let sig = key.sign(&index, "seq=42;timestamp=1700000000;channel=beta");
        check(&index, &sig, &[&key]).unwrap();
        assert_eq!(trusted_comment(Channel::Beta, 42), "channel=beta;seq=42");
    }

    #[test]
    fn index_of_another_channel_is_refused() {
        let key = TestKey::new();
        let (index, sig) = signed(&key, "stable", 42);
        assert!(matches!(
            check(&index, &sig, &[&key]),
            Err(UpdateError::WrongChannel {
                expected: Channel::Beta,
                found: Channel::Stable
            })
        ));
    }

    #[test]
    fn seq_must_not_go_back() {
        let key = TestKey::new();
        let (index, sig) = signed(&key, "beta", 39);
        assert!(matches!(
            check(&index, &sig, &[&key]),
            Err(UpdateError::Rollback { seq: 39, last: 40 })
        ));
        let keys = [key.public.clone()];
        verify(&index, &sig, &keys, Channel::Beta, None, NOW).unwrap();
        verify(&index, &sig, &keys, Channel::Beta, Some(39), NOW).unwrap();
        verify(&index, &sig, &keys, Channel::Beta, Some(38), NOW).unwrap();
    }

    #[test]
    fn stale_index_is_refused() {
        let key = TestKey::new();
        let keys = [key.public.clone()];
        let at = |value: serde_json::Value| {
            let index = serde_json::to_vec(&value).unwrap();
            let sig = key.sign(&index, "channel=beta;seq=42");
            (index, sig)
        };

        // Past `expires` (2026-10-31).
        let (index, sig) = at(index_json("beta", 42));
        let expires = datetime!(2026-10-31 0:00 UTC);
        verify(
            &index,
            &sig,
            &keys,
            Channel::Beta,
            None,
            expires - Duration::SECOND,
        )
        .unwrap();
        assert!(matches!(
            verify(&index, &sig, &keys, Channel::Beta, None, expires),
            Err(UpdateError::Expired(t)) if t == expires
        ));

        // A far `expires` does not stretch the index past 30 days from `generated`.
        let mut far = index_json("beta", 42);
        far["expires"] = serde_json::json!("2027-12-31T00:00:00Z");
        let (index, sig) = at(far);
        let aged = datetime!(2026-10-31 0:00 UTC);
        verify(
            &index,
            &sig,
            &keys,
            Channel::Beta,
            None,
            aged - Duration::SECOND,
        )
        .unwrap();
        assert!(matches!(
            verify(&index, &sig, &keys, Channel::Beta, None, aged + Duration::days(60)),
            Err(UpdateError::Expired(t)) if t == aged
        ));
    }

    #[test]
    fn oversized_index_is_refused_before_anything_else() {
        let index = vec![b' '; MAX_INDEX_LEN as usize + 1];
        assert!(matches!(
            verify(&index, b"", &[], Channel::Beta, None, NOW),
            Err(UpdateError::TooLarge)
        ));
    }

    #[test]
    fn signed_but_invalid_index_is_refused() {
        let key = TestKey::new();
        let mut v = index_json("beta", 42);
        v["core"][0]["rollout"] = serde_json::json!(200);
        let index = serde_json::to_vec(&v).unwrap();
        let sig = key.sign(&index, "channel=beta;seq=42");
        assert!(matches!(
            check(&index, &sig, &[&key]),
            Err(UpdateError::Malformed(_))
        ));
    }
}
