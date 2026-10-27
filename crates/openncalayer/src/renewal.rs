//! The server certificate's renewal, checked at start and once a day: a certificate due
//! within 60 days is reminded of; one issued with mkcert's CA (with the user's consent) is
//! re-issued 30 days before it expires, without asking, and served at once.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use oncl_tls::{
    MkcertRenewal, RenewError, Renewal, TlsError, TlsFiles, load_info, needs_renewal,
    renew_with_mkcert, server_config,
};
use oncl_ui::tls_wizard::Applied;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

use crate::server::LiveTls;

/// How often the certificate is checked after the start (by the wall clock).
pub const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// How often the renewal thread wakes to compare the wall clock with the last check: a
/// computer that sleeps through the night still checks soon after it wakes.
pub const WAKE_EVERY: Duration = Duration::from_secs(60 * 60);

/// What a check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewalCheck {
    /// Not set up, unreadable, or not due.
    Nothing,
    /// The user should re-issue: the certificate expires in `days` whole days; `expired`
    /// once its end has passed.
    Due { days: i64, expired: bool },
    /// Re-issued with mkcert's CA, saved and taken by the server (or by its next start, if
    /// wss is off); valid until `not_after` (RFC 3339).
    Renewed { not_after: String },
    /// The mkcert re-issue failed; the certificate in use expires in `days`.
    RenewFailed { days: i64, failure: RenewFailure },
}

/// Why an mkcert re-issue failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewFailure {
    /// mkcert's CA cannot be used (its key unreadable or not matching, the CA expired):
    /// nothing was written.
    Mkcert(String),
    /// mkcert's `rootCA.pem` is another CA than the one that issued the certificate in use
    /// (regenerated or replaced): its key was not read, nothing was written. The user is to
    /// run the TLS wizard again.
    CaChanged(String),
    /// The new certificate could not be saved; the files may be half written, and the
    /// server keeps the certificate it has loaded.
    Save(String),
    /// The new certificate was saved, but the server cannot load it and keeps the old one.
    Reload(String),
}

impl RenewFailure {
    pub fn detail(&self) -> &str {
        match self {
            RenewFailure::Mkcert(e)
            | RenewFailure::CaChanged(e)
            | RenewFailure::Save(e)
            | RenewFailure::Reload(e) => e,
        }
    }
}

/// Checks the certificate in `files` at `now`. A due mkcert certificate with the consent is
/// re-issued with the CA that issued it and saved, keeping the recorded consent
/// ([`renew_with_mkcert`]: a consent withdrawn meanwhile wins), then handed to the server by
/// `reload`, which says whether the server took it.
pub fn check(
    files: &TlsFiles,
    now: OffsetDateTime,
    reload: impl FnOnce() -> Applied,
) -> RenewalCheck {
    let Ok(Some(info)) = load_info(files) else {
        return RenewalCheck::Nothing;
    };
    match needs_renewal(&info, now) {
        Renewal::None => RenewalCheck::Nothing,
        Renewal::Remind { days } => due(&info.leaf_not_after, days, now),
        Renewal::AutoRenew => {
            let failed = |failure| RenewalCheck::RenewFailed {
                days: days_left(&info.leaf_not_after, now),
                failure,
            };
            let renewed = match renew_with_mkcert(files, now) {
                Ok(MkcertRenewal::Renewed(renewed)) => renewed,
                // The consent was withdrawn (or the certificate replaced) since `info`.
                Ok(MkcertRenewal::NotDue) => return state(files, now),
                Err(RenewError::Issue(TlsError::MkcertCaChanged(e))) => {
                    return failed(RenewFailure::CaChanged(e));
                }
                Err(RenewError::Issue(e)) => return failed(RenewFailure::Mkcert(e.to_string())),
                Err(RenewError::Save(e)) => {
                    return failed(RenewFailure::Save(format!("{}: {e}", files.dir.display())));
                }
            };
            match reload() {
                Applied::Serving | Applied::WhenPortFree | Applied::AfterRestart => {
                    RenewalCheck::Renewed {
                        not_after: renewed.leaf_not_after,
                    }
                }
                Applied::Failed(e) => failed(RenewFailure::Reload(e)),
            }
        }
    }
}

/// What the tray should warn about for the certificate in `files` at `now`, without
/// re-issuing anything (after the TLS wizard has saved a certificate).
pub fn state(files: &TlsFiles, now: OffsetDateTime) -> RenewalCheck {
    match load_info(files) {
        Ok(Some(info)) => match needs_renewal(&info, now) {
            Renewal::Remind { days } => due(&info.leaf_not_after, days, now),
            Renewal::None | Renewal::AutoRenew => RenewalCheck::Nothing,
        },
        _ => RenewalCheck::Nothing,
    }
}

/// [`RenewalCheck::Due`]: expired once `not_after` (RFC 3339) has passed at `now`.
fn due(not_after: &str, days: i64, now: OffsetDateTime) -> RenewalCheck {
    let expired = OffsetDateTime::parse(not_after, &Rfc3339).is_ok_and(|end| end <= now);
    RenewalCheck::Due { days, expired }
}

/// Whole days from `now` to the RFC 3339 `not_after`; 0 if it cannot be read.
fn days_left(not_after: &str, now: OffsetDateTime) -> i64 {
    OffsetDateTime::parse(not_after, &Rfc3339).map_or(0, |t| (t - now).whole_days())
}

/// Has the server take the certificate saved in `files`: [`Applied::AfterRestart`] when the
/// wss server is off (`live` is `None`); a certificate the server cannot load leaves the
/// previous one in use.
pub fn reload(files: &TlsFiles, live: Option<&LiveTls>) -> Applied {
    let Some(live) = live else {
        return Applied::AfterRestart;
    };
    match server_config(files) {
        Ok(config) => {
            live.replace(Arc::new(config));
            info!("the server takes the new certificate");
            Applied::Serving
        }
        Err(e) => {
            warn!(error = %e, "the new certificate cannot be served; the previous one stays");
            Applied::Failed(e.to_string())
        }
    }
}

/// Whether a check is due at `now` after the last one at `last`: [`CHECK_EVERY`] has passed
/// by the wall clock (sleep included), or the clock went back.
pub fn check_due(last: SystemTime, now: SystemTime) -> bool {
    now.duration_since(last)
        .map_or(true, |since| since >= CHECK_EVERY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_tls::{issue_with_mkcert, save};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use time::Duration;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-10-27 10:00 UTC);

    /// A CAROOT with a fresh mkcert-like CA valid for ten years from a year before `NOW`.
    fn caroot() -> tempfile::TempDir {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "mkcert test");
        params.not_before = NOW - Duration::days(365);
        params.not_after = NOW + Duration::days(9 * 365);
        let ca = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rootCA.pem"), ca.pem()).unwrap();
        std::fs::write(dir.path().join("rootCA-key.pem"), key.serialize_pem()).unwrap();
        dir
    }

    fn files(dir: &std::path::Path) -> TlsFiles {
        TlsFiles {
            dir: dir.join("tls"),
        }
    }

    fn serving() -> Applied {
        Applied::Serving
    }

    #[test]
    fn nothing_without_a_certificate_and_reminders_for_others() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        assert_eq!(check(&files, NOW, serving), RenewalCheck::Nothing);
        save(&files, &oncl_tls::generate(NOW, "t@h").unwrap()).unwrap();
        assert_eq!(check(&files, NOW, serving), RenewalCheck::Nothing);
        let late = NOW + Duration::days(800 - 45);
        let due = RenewalCheck::Due {
            days: 44,
            expired: false,
        };
        assert_eq!(check(&files, late, serving), due);
        assert_eq!(state(&files, late), due);
        // Less than a day left is not expired yet; past the end is.
        let end = NOW - Duration::hours(1) + Duration::days(800);
        assert_eq!(
            state(&files, end - Duration::hours(2)),
            RenewalCheck::Due {
                days: 0,
                expired: false
            }
        );
        assert_eq!(
            state(&files, end),
            RenewalCheck::Due {
                days: 0,
                expired: true
            }
        );
    }

    #[test]
    fn mkcert_certificates_renew_themselves_and_keep_the_consent() {
        let caroot = caroot();
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        let first = issue_with_mkcert(caroot.path(), NOW).unwrap();
        save(&files, &first).unwrap();
        let late = NOW + Duration::days(780);
        // Reminded of never; renewed within 30 days.
        assert_eq!(state(&files, late), RenewalCheck::Nothing);
        let RenewalCheck::Renewed { not_after } = check(&files, late, serving) else {
            panic!("not renewed");
        };
        let info = load_info(&files).unwrap().unwrap();
        assert_eq!(info.leaf_not_after, not_after);
        assert_ne!(info.leaf_sha256, first.info.leaf_sha256);
        assert_eq!(info.source, first.info.source);
        assert_eq!(check(&files, late, serving), RenewalCheck::Nothing);
    }

    #[test]
    fn a_withdrawn_consent_reminds_instead() {
        let caroot = caroot();
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        save(&files, &issue_with_mkcert(caroot.path(), NOW).unwrap()).unwrap();
        oncl_tls::set_mkcert_consent(&files, None).unwrap();
        // The key is not read any more: even a broken one does not matter.
        std::fs::write(caroot.path().join("rootCA-key.pem"), "broken").unwrap();
        let late = NOW + Duration::days(780);
        assert!(matches!(
            check(&files, late, || unreachable!("nothing is re-issued")),
            RenewalCheck::Due { days: 19, .. }
        ));
    }

    #[test]
    fn a_broken_mkcert_key_keeps_the_certificate_in_use() {
        let caroot = caroot();
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        let first = issue_with_mkcert(caroot.path(), NOW).unwrap();
        save(&files, &first).unwrap();
        let live = LiveTls::new(Arc::new(server_config(&files).unwrap()));
        std::fs::write(caroot.path().join("rootCA-key.pem"), "broken").unwrap();

        let late = NOW + Duration::days(780);
        let RenewalCheck::RenewFailed {
            days,
            failure: RenewFailure::Mkcert(error),
        } = check(&files, late, || unreachable!("nothing to reload"))
        else {
            panic!("renewed with a broken key");
        };
        assert_eq!(days, 19);
        assert!(error.contains("rootCA-key.pem"), "{error}");
        assert_eq!(load_info(&files).unwrap().unwrap(), first.info);
        // The server keeps serving what it has.
        assert_eq!(reload(&files, Some(&live)), Applied::Serving);
        assert_eq!(reload(&files, None), Applied::AfterRestart);
    }

    #[test]
    fn a_regenerated_mkcert_ca_is_not_used() {
        let caroot = caroot();
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        let first = issue_with_mkcert(caroot.path(), NOW).unwrap();
        save(&files, &first).unwrap();
        // mkcert made a new CA; its key would not even parse, were it read.
        let other = self::caroot();
        std::fs::copy(
            other.path().join("rootCA.pem"),
            caroot.path().join("rootCA.pem"),
        )
        .unwrap();
        std::fs::write(caroot.path().join("rootCA-key.pem"), "broken").unwrap();

        let late = NOW + Duration::days(780);
        let RenewalCheck::RenewFailed {
            days: 19,
            failure: RenewFailure::CaChanged(error),
        } = check(&files, late, || unreachable!("nothing to reload"))
        else {
            panic!("renewed with another CA");
        };
        assert!(error.contains("rootCA.pem"), "{error}");
        assert_eq!(load_info(&files).unwrap().unwrap(), first.info);
    }

    #[test]
    fn a_renewal_the_server_cannot_take_is_a_failure() {
        let caroot = caroot();
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        save(&files, &issue_with_mkcert(caroot.path(), NOW).unwrap()).unwrap();
        let late = NOW + Duration::days(780);
        assert_eq!(
            check(&files, late, || Applied::Failed("key mismatch".to_owned())),
            RenewalCheck::RenewFailed {
                days: 19,
                failure: RenewFailure::Reload("key mismatch".to_owned())
            }
        );
    }

    #[test]
    fn daily_checks_follow_the_wall_clock() {
        let last = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let hour = std::time::Duration::from_secs(3600);
        assert!(!check_due(last, last + hour));
        assert!(check_due(last, last + CHECK_EVERY));
        // Asleep for two days: due at the first wake.
        assert!(check_due(last, last + 2 * CHECK_EVERY + hour));
        // The clock went back.
        assert!(check_due(last, last - hour));
    }
}
