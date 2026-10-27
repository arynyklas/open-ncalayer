//! What the OCSP checks of the key dialogs remember between requests, in memory only:
//! responders that did not answer, and verified answers.

use oncl_pki::cert::Certificate;
use oncl_pki::http::HttpTransport;
use oncl_pki::ocsp::{self, CertStatus, OcspAnswer, OcspError};
use oncl_pki::pkix::CaSet;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;

/// How long a responder host that did not answer is not asked again.
pub const UNREACHABLE_FOR: Duration = Duration::from_secs(600);

/// How long a verified answer is used at most; less if the responder vouches for less.
pub const ANSWER_FOR: Duration = Duration::from_secs(600);

/// The OCSP memory of the module. The daemon registers one module, so it is shared by
/// every request of the process.
///
/// - A responder host without a response (connection failure, timeout, any transport
///   error: [`OcspError::Http`]) is not asked for [`UNREACHABLE_FOR`]: its keys stay
///   unchecked at once.
/// - A `good` or `revoked` answer that passed [`ocsp::check_answer`] is used for its
///   certificate (issuer key hash and serial number) until its nextUpdate, or without one
///   until thisUpdate + [`ocsp::ALLOWED_PERIOD`], and never longer than [`ANSWER_FOR`];
///   only for requests trusting the same CA set it was verified with.
#[derive(Default)]
pub struct OcspCache {
    unreachable: Mutex<HashMap<String, OffsetDateTime>>,
    answers: Mutex<HashMap<AnswerKey, Cached>>,
}

/// The certificate an answer is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AnswerKey {
    issuer_key_hash: [u8; 20],
    serial: Vec<u8>,
}

/// A verified answer, the CAs that verified it, and until when it is used.
struct Cached {
    status: CertStatus,
    cas: Arc<CaSet>,
    until: OffsetDateTime,
}

impl OcspCache {
    /// An empty memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// The status of `cert` (issued by `issuer`, serial `serial` in hex for the log) at
    /// `now`: remembered, or asked through `http` within [`ocsp::TIMEOUT`] with the
    /// responder trusted through `cas`. `None` when it stays unchecked; why is logged.
    pub(crate) fn status(
        &self,
        serial: &str,
        cert: &Certificate,
        issuer: &Certificate,
        cas: &Arc<CaSet>,
        http: &dyn HttpTransport,
        now: OffsetDateTime,
    ) -> Option<CertStatus> {
        let key = AnswerKey {
            issuer_key_hash: ocsp::key_hash(issuer),
            serial: cert.tbs_certificate().serial_number().as_bytes().to_vec(),
        };
        if let Some(status) = self.answer(&key, cas, now) {
            tracing::debug!(%serial, ?status, "OCSP: remembered answer");
            return Some(status);
        }
        let host = ocsp::ocsp_url(cert).map(|url| host(&url));
        if let Some(host) = &host
            && self.is_unreachable(host, now)
        {
            tracing::debug!(%serial, %host, "OCSP responder did not answer recently: the key stays available unchecked");
            return None;
        }
        match ocsp::check_answer(cert, issuer, cas, http, now, ocsp::TIMEOUT) {
            Ok(answer) => {
                self.remember(key, &answer, cas, now);
                Some(answer.status)
            }
            Err(e @ OcspError::Http(_)) => {
                match host {
                    Some(host) if self.mark_unreachable(&host, now) => {
                        tracing::warn!(%serial, %host, error = %e, "OCSP responder does not answer: the key stays available; the host is not asked again for {} min", UNREACHABLE_FOR.as_secs() / 60);
                    }
                    _ => {
                        tracing::debug!(%serial, error = %e, "OCSP check failed: the key stays available");
                    }
                }
                None
            }
            Err(e) => {
                tracing::warn!(%serial, error = %e, "OCSP check failed: the key stays available");
                None
            }
        }
    }

    /// The remembered status for `key` if it is still used at `now` and was verified with
    /// the same CAs as `cas`.
    fn answer(&self, key: &AnswerKey, cas: &Arc<CaSet>, now: OffsetDateTime) -> Option<CertStatus> {
        let answers = lock(&self.answers);
        let cached = answers.get(key)?;
        (now < cached.until && (Arc::ptr_eq(&cached.cas, cas) || cached.cas == *cas))
            .then_some(cached.status)
    }

    /// Remembers a `good` or `revoked` `answer` checked with `cas` at `now`.
    fn remember(&self, key: AnswerKey, answer: &OcspAnswer, cas: &Arc<CaSet>, now: OffsetDateTime) {
        if answer.status == CertStatus::Unknown {
            return;
        }
        let vouched = answer
            .next_update
            .unwrap_or(answer.this_update + ocsp::ALLOWED_PERIOD);
        let until = vouched.min(now + ANSWER_FOR);
        if until <= now {
            return;
        }
        let mut answers = lock(&self.answers);
        answers.retain(|_, cached| now < cached.until);
        answers.insert(
            key,
            Cached {
                status: answer.status,
                cas: Arc::clone(cas),
                until,
            },
        );
    }

    /// Whether `host` did not answer within [`UNREACHABLE_FOR`] before `now`.
    fn is_unreachable(&self, host: &str, now: OffsetDateTime) -> bool {
        lock(&self.unreachable)
            .get(host)
            .is_some_and(|until| now < *until)
    }

    /// Remembers that `host` did not answer at `now`; `false` if it was already known.
    fn mark_unreachable(&self, host: &str, now: OffsetDateTime) -> bool {
        let mut unreachable = lock(&self.unreachable);
        unreachable.retain(|_, until| now < *until);
        if unreachable.contains_key(host) {
            return false;
        }
        unreachable.insert(host.to_owned(), now + UNREACHABLE_FOR);
        true
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The host (and port) of `url`, lowercase: what lies between `scheme://` (and a user
/// name) and the path.
fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-10-27 12:00 UTC);

    fn key(serial: u8) -> AnswerKey {
        AnswerKey {
            issuer_key_hash: [7; 20],
            serial: vec![serial],
        }
    }

    fn answer(
        status: CertStatus,
        this_update: OffsetDateTime,
        next_update: Option<OffsetDateTime>,
    ) -> OcspAnswer {
        OcspAnswer {
            status,
            this_update,
            next_update,
        }
    }

    #[test]
    fn hosts_of_responder_urls() {
        assert_eq!(host("http://ocsp.pki.gov.kz"), "ocsp.pki.gov.kz");
        assert_eq!(
            host("http://OCSP.pki.gov.kz:8080/path?q#f"),
            "ocsp.pki.gov.kz:8080"
        );
        assert_eq!(
            host("http://user@ocsp.synthetic.test/"),
            "ocsp.synthetic.test"
        );
        assert_eq!(host("ocsp.example/x"), "ocsp.example");
    }

    #[test]
    fn answers_last_until_next_update_at_most_ten_minutes() {
        let cache = OcspCache::new();
        let cas = Arc::new(CaSet::default());
        let minute = time::Duration::MINUTE;
        // nextUpdate in 3 min.
        cache.remember(
            key(1),
            &answer(CertStatus::Good, NOW - minute, Some(NOW + 3 * minute)),
            &cas,
            NOW,
        );
        assert_eq!(
            cache.answer(&key(1), &cas, NOW + 2 * minute),
            Some(CertStatus::Good)
        );
        assert_eq!(cache.answer(&key(1), &cas, NOW + 3 * minute), None);
        // nextUpdate in an hour: 10 min.
        let revoked = CertStatus::Revoked {
            time: datetime!(2026-02-03 04:05:06 UTC),
            reason: None,
        };
        cache.remember(
            key(2),
            &answer(revoked, NOW - minute, Some(NOW + 60 * minute)),
            &cas,
            NOW,
        );
        assert_eq!(cache.answer(&key(2), &cas, NOW + 9 * minute), Some(revoked));
        assert_eq!(cache.answer(&key(2), &cas, NOW + 10 * minute), None);
        // No nextUpdate: thisUpdate + 300 s.
        cache.remember(
            key(3),
            &answer(CertStatus::Good, NOW - minute, None),
            &cas,
            NOW,
        );
        assert_eq!(
            cache.answer(&key(3), &cas, NOW + 3 * minute),
            Some(CertStatus::Good)
        );
        assert_eq!(cache.answer(&key(3), &cas, NOW + 4 * minute), None);
        // `unknown` and answers no longer vouched for are not remembered.
        cache.remember(
            key(4),
            &answer(CertStatus::Unknown, NOW, Some(NOW + minute)),
            &cas,
            NOW,
        );
        assert_eq!(cache.answer(&key(4), &cas, NOW), None);
        cache.remember(
            key(5),
            &answer(CertStatus::Good, NOW - 10 * minute, None),
            &cas,
            NOW,
        );
        assert_eq!(cache.answer(&key(5), &cas, NOW), None);
        // Another certificate, or other CAs: not this answer.
        assert_eq!(cache.answer(&key(9), &cas, NOW), None);
        let other = Arc::new(CaSet::new(vec![
            oncl_pki::roots::nca_production()[0].clone(),
        ]));
        assert_eq!(cache.answer(&key(1), &other, NOW), None);
        // Equal CAs from another request: the same trust.
        assert_eq!(
            cache.answer(&key(1), &Arc::new(CaSet::default()), NOW),
            Some(CertStatus::Good)
        );
    }

    #[test]
    fn unreachable_hosts_expire() {
        let cache = OcspCache::new();
        assert!(!cache.is_unreachable("ocsp.pki.gov.kz", NOW));
        assert!(cache.mark_unreachable("ocsp.pki.gov.kz", NOW));
        assert!(!cache.mark_unreachable("ocsp.pki.gov.kz", NOW + time::Duration::MINUTE));
        assert!(cache.is_unreachable("ocsp.pki.gov.kz", NOW + time::Duration::minutes(9)));
        assert!(!cache.is_unreachable("tsp.pki.gov.kz", NOW));
        assert!(!cache.is_unreachable("ocsp.pki.gov.kz", NOW + time::Duration::minutes(10)));
        assert!(cache.mark_unreachable("ocsp.pki.gov.kz", NOW + time::Duration::minutes(10)));
    }
}
