//! The server certificate's renewal, checked at start and once a day: a certificate due
//! within 60 days is reminded of; one issued with mkcert's CA (with the user's consent) is
//! re-issued 30 days before it expires, without asking.

use std::sync::Arc;
use std::time::Duration;

use oncl_tls::{
    Renewal, TlsError, TlsFiles, TlsSource, issue_with_mkcert, load_info, needs_renewal, save,
    server_config,
};
use oncl_ui::tls_wizard::Applied;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

use crate::server::LiveTls;

/// How often the certificate is checked after the start.
pub const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// What a check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewalCheck {
    /// Not set up, unreadable, or not due.
    Nothing,
    /// The user should re-issue: the certificate expires in `days` (0 or less: expired).
    Due { days: i64 },
    /// Re-issued with mkcert's CA and saved; valid until `not_after` (RFC 3339).
    Renewed { not_after: String },
    /// The mkcert re-issue failed (`error`); the certificate in use expires in `days`.
    RenewFailed { days: i64, error: String },
}

/// Checks the certificate in `files` at `now`. A due mkcert certificate is re-issued and
/// saved, keeping the recorded consent; the caller has the server take it. A failed re-issue
/// changes no file: the certificate in use stays.
pub fn check(files: &TlsFiles, now: OffsetDateTime) -> RenewalCheck {
    let Ok(Some(info)) = load_info(files) else {
        return RenewalCheck::Nothing;
    };
    match needs_renewal(&info, now) {
        Renewal::None => RenewalCheck::Nothing,
        Renewal::Remind { days } => RenewalCheck::Due { days },
        Renewal::AutoRenew => {
            let TlsSource::Mkcert { caroot, .. } = &info.source else {
                return RenewalCheck::Nothing;
            };
            let renewed = issue_with_mkcert(caroot, now).and_then(|mut material| {
                // The consent was given once, for every renewal.
                material.info.source = info.source.clone();
                save(files, &material)
                    .map(|()| material.info.leaf_not_after.clone())
                    .map_err(|e| TlsError::Mkcert(format!("{}: {e}", files.dir.display())))
            });
            match renewed {
                Ok(not_after) => RenewalCheck::Renewed { not_after },
                Err(e) => RenewalCheck::RenewFailed {
                    days: days_left(&info.leaf_not_after, now),
                    error: e.to_string(),
                },
            }
        }
    }
}

/// What the tray should warn about for the certificate in `files` at `now`, without
/// re-issuing anything (after the TLS wizard has saved a certificate).
pub fn state(files: &TlsFiles, now: OffsetDateTime) -> RenewalCheck {
    match load_info(files) {
        Ok(Some(info)) => match needs_renewal(&info, now) {
            Renewal::Remind { days } => RenewalCheck::Due { days },
            Renewal::None | Renewal::AutoRenew => RenewalCheck::Nothing,
        },
        _ => RenewalCheck::Nothing,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn nothing_without_a_certificate_and_reminders_for_others() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        assert_eq!(check(&files, NOW), RenewalCheck::Nothing);
        save(&files, &oncl_tls::generate(NOW, "t@h").unwrap()).unwrap();
        assert_eq!(check(&files, NOW), RenewalCheck::Nothing);
        let late = NOW + Duration::days(800 - 45);
        assert!(matches!(
            check(&files, late),
            RenewalCheck::Due { days: 44 }
        ));
        assert!(matches!(
            state(&files, late),
            RenewalCheck::Due { days: 44 }
        ));
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
        let RenewalCheck::Renewed { not_after } = check(&files, late) else {
            panic!("not renewed");
        };
        let info = load_info(&files).unwrap().unwrap();
        assert_eq!(info.leaf_not_after, not_after);
        assert_ne!(info.leaf_sha256, first.info.leaf_sha256);
        assert_eq!(info.source, first.info.source);
        assert_eq!(check(&files, late), RenewalCheck::Nothing);
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
        let RenewalCheck::RenewFailed { days, error } = check(&files, late) else {
            panic!("renewed with a broken key");
        };
        assert_eq!(days, 19);
        assert!(error.contains("rootCA-key.pem"), "{error}");
        assert_eq!(load_info(&files).unwrap().unwrap(), first.info);
        // The server keeps serving what it has.
        assert_eq!(reload(&files, Some(&live)), Applied::Serving);
        assert_eq!(reload(&files, None), Applied::AfterRestart);
    }
}
