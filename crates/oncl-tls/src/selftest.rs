//! The browsers that opened the self-test page: the server records the `navigator.userAgent`
//! the page reports, the TLS wizard shows them.

use std::sync::{Mutex, PoisonError};

use time::OffsetDateTime;

/// One browser that loaded the self-test page over TLS and ran its script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelftestReport {
    /// `navigator.userAgent`, as the page sent it.
    pub user_agent: String,
    /// When it reported last.
    pub at: OffsetDateTime,
}

/// The last [`SelftestReports::MAX`] distinct user agents, newest first; in memory only,
/// shared by the server and the TLS wizard.
#[derive(Debug, Default)]
pub struct SelftestReports {
    reports: Mutex<Vec<SelftestReport>>,
}

impl SelftestReports {
    /// How many distinct user agents are kept.
    pub const MAX: usize = 16;
    /// The longest user agent kept, in bytes; a longer one is cut at a character boundary.
    pub const MAX_USER_AGENT: usize = 512;

    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `user_agent` reported at `at`: it moves to the front (a repeated report
    /// replaces the earlier one), and the oldest beyond [`Self::MAX`] is dropped. Blank
    /// user agents are ignored.
    pub fn record(&self, user_agent: &str, at: OffsetDateTime) {
        let user_agent = user_agent.trim();
        if user_agent.is_empty() {
            return;
        }
        let mut end = user_agent.len().min(Self::MAX_USER_AGENT);
        while !user_agent.is_char_boundary(end) {
            end -= 1;
        }
        let user_agent = &user_agent[..end];
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        reports.retain(|r| r.user_agent != user_agent);
        reports.insert(
            0,
            SelftestReport {
                user_agent: user_agent.to_owned(),
                at,
            },
        );
        reports.truncate(Self::MAX);
    }

    /// The reports, newest first.
    pub fn latest(&self) -> Vec<SelftestReport> {
        self.reports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn newest_first_distinct_and_bounded() {
        let reports = SelftestReports::new();
        let t0 = OffsetDateTime::UNIX_EPOCH;
        reports.record("Firefox", t0);
        reports.record("  ", t0);
        reports.record("Chrome", t0 + Duration::seconds(1));
        reports.record(" Firefox ", t0 + Duration::seconds(2));
        let latest = reports.latest();
        assert_eq!(
            latest
                .iter()
                .map(|r| (r.user_agent.as_str(), r.at))
                .collect::<Vec<_>>(),
            [
                ("Firefox", t0 + Duration::seconds(2)),
                ("Chrome", t0 + Duration::seconds(1))
            ]
        );

        for i in 0..40 {
            reports.record(&format!("ua {i}"), t0);
        }
        let latest = reports.latest();
        assert_eq!(latest.len(), SelftestReports::MAX);
        assert_eq!(latest[0].user_agent, "ua 39");

        reports.record(&"ж".repeat(400), t0);
        let long = &reports.latest()[0].user_agent;
        assert!(long.len() <= SelftestReports::MAX_USER_AGENT);
        assert!(long.chars().all(|c| c == 'ж'));
    }
}
