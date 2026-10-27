//! macOS: the login keychain with per-user SSL trust through `security`, read-only checks
//! through Security.framework (`SecTrust`, trust settings).
//!
//! Only the user trust domain is written (`security add-trusted-cert` without `-d`); macOS
//! asks for the login password itself, which the user may cancel.

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::Command;

use security_framework::certificate::SecCertificate;
use security_framework::policy::SecPolicy;
use security_framework::secure_transport::SslProtocolSide;
use security_framework::trust::SecTrust;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

use crate::{
    Cancelled, Certificate, InstallOutcome, StoreState, TrustReport, TrustStore, hex,
    pem_certificates,
};

/// The name the SSL policy checks the leaf against.
const SERVER_NAME: &str = "127.0.0.1";

const SECURITY: &str = "/usr/bin/security";

/// The user's login keychain (`~/Library/Keychains/login.keychain-db`) with an SSL "Always
/// Trust" setting in the user domain.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacLoginKeychain;

impl MacLoginKeychain {
    fn keychain() -> io::Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        Ok(PathBuf::from(home).join("Library/Keychains/login.keychain-db"))
    }
}

impl TrustStore for MacLoginKeychain {
    fn contains(&self, ca: &Certificate) -> io::Result<bool> {
        let pem = security(
            Command::new(SECURITY)
                .args(["find-certificate", "-a", "-p"])
                .arg(Self::keychain()?),
        )?;
        for cert in pem_certificates(&pem) {
            if cert? == *ca {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
        if self.contains(ca)? && user_trust(ca).is_ok_and(|t| t == StoreState::User) {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        let mut file = tempfile::Builder::new().suffix(".cer").tempfile()?;
        file.write_all(ca.der())?;
        file.flush()?;
        match security(
            Command::new(SECURITY)
                .args(["add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k"])
                .arg(Self::keychain()?)
                .arg(file.path()),
        ) {
            Ok(_) => Ok(InstallOutcome::Installed),
            Err(e) if is_cancelled(&e) => Ok(InstallOutcome::CancelledByUser),
            Err(e) => Err(e),
        }
    }

    fn remove(&self, ca: &Certificate) -> io::Result<bool> {
        if !self.contains(ca)? {
            return Ok(false);
        }
        // `-Z` selects by SHA-1 (the exact certificate); `-t` also drops its user trust
        // settings.
        let sha1 = hex(&ca.sha1()).to_uppercase();
        match security(
            Command::new(SECURITY)
                .args(["delete-certificate", "-Z", &sha1, "-t"])
                .arg(Self::keychain()?),
        ) {
            Ok(_) => Ok(true),
            Err(e) if is_cancelled(&e) => Err(io::Error::other(Cancelled)),
            Err(e) => Err(e),
        }
    }
}

/// Runs a `security` command; its stdout on success, its stderr in the error otherwise.
fn security(command: &mut Command) -> io::Result<String> {
    let output = command.output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let operation = command
            .get_args()
            .next()
            .unwrap_or_default()
            .to_string_lossy();
        Err(io::Error::other(format!(
            "security {operation}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// The authorization dialog was cancelled (`errAuthorizationCanceled`, -60006).
fn is_cancelled(e: &io::Error) -> bool {
    let message = e.to_string();
    message.contains("canceled") || message.contains("cancelled") || message.contains("-60006")
}

/// [`StoreState::User`] if the user domain trusts the CA for TLS, [`StoreState::Managed`] if
/// only the admin domain does, [`StoreState::Absent`] otherwise.
fn user_trust(ca: &Certificate) -> io::Result<StoreState> {
    let cert = SecCertificate::from_der(ca.der()).map_err(io::Error::other)?;
    let trusted = |domain| {
        matches!(
            TrustSettings::new(domain).tls_trust_settings_for_certificate(&cert),
            Ok(Some(
                TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot
            ))
        )
    };
    Ok(if trusted(Domain::User) {
        StoreState::User
    } else if trusted(Domain::Admin) {
        StoreState::Managed
    } else {
        StoreState::Absent
    })
}

/// Whether `SecTrust` accepts [leaf, CA] for a TLS server `127.0.0.1`, without network.
fn chain_ok(ca: &Certificate, leaf: &Certificate) -> Result<bool, security_framework::base::Error> {
    let certs = [
        SecCertificate::from_der(leaf.der())?,
        SecCertificate::from_der(ca.der())?,
    ];
    let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, Some(SERVER_NAME));
    let mut trust = SecTrust::create_with_certificates(&certs, &[policy])?;
    trust.set_network_fetch_allowed(false)?;
    Ok(trust.evaluate_with_error().is_ok())
}

/// Read-only check: trust settings, `SecTrust` and the Firefox profiles.
pub(crate) fn check(ca: &Certificate, leaf: &Certificate) -> TrustReport {
    let firefox_roots: Vec<PathBuf> = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support/Firefox"))
        .into_iter()
        .collect();
    TrustReport {
        os_store: user_trust(ca).unwrap_or(StoreState::Unknown),
        os_chain_ok: chain_ok(ca, leaf).ok(),
        nss: Vec::new(),
        firefox_enterprise_roots: crate::firefox_enterprise_roots_report(&firefox_roots),
    }
}
