//! Trust stores of OpenNCALayer's local CA.
//!
//! - [`check`] finds out, read-only, whether the browsers of this computer can trust the CA:
//!   the OS store and the OS chain verdict for `127.0.0.1` (Windows, macOS), the NSS
//!   databases of Chrome and Firefox (Linux) and Firefox's `security.enterprise_roots.enabled`
//!   (Windows, macOS).
//! - [`TrustStore`] installs the CA into the user's own store or removes it from there. It is
//!   called only on an explicit user action confirmed in a window: OpenNCALayer never writes
//!   to a trust store on its own. Implementations: `WindowsUserRoot` (`CurrentUser\Root`),
//!   `MacLoginKeychain` (the login keychain with SSL trust) and `NssDb` (one NSS database).
//!
//! Certificates are identified by their exact encoding: installing twice does not duplicate
//! a certificate, and removing deletes exactly the given certificate, never another one with
//! the same name.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(windows)]
use windows as imp;

#[cfg(target_os = "linux")]
pub use linux::{CertutilMissing, NssDb, nss_databases};
#[cfg(target_os = "macos")]
pub use macos::MacLoginKeychain;
#[cfg(windows)]
pub use windows::WindowsUserRoot;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use sha1::Digest as _;
use x509_cert::der::Decode as _;

/// A DER-encoded X.509 certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    /// Takes a DER-encoded certificate; fails with [`io::ErrorKind::InvalidData`] if it does
    /// not parse as an X.509 certificate.
    pub fn from_der(der: impl Into<Vec<u8>>) -> io::Result<Self> {
        let der = der.into();
        x509_cert::Certificate::from_der(&der).map_err(invalid_data)?;
        Ok(Self { der })
    }

    /// Takes a PEM `CERTIFICATE` block (surrounding text is ignored; only the first block
    /// is taken).
    pub fn from_pem(pem: &str) -> io::Result<Self> {
        pem_certificates(pem)
            .next()
            .ok_or_else(|| invalid_data("no PEM CERTIFICATE block"))?
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// SHA-1 thumbprint: how Windows and macOS identify a certificate.
    pub fn sha1(&self) -> [u8; 20] {
        sha1::Sha1::digest(&self.der).into()
    }

    pub fn sha256(&self) -> [u8; 32] {
        sha2::Sha256::digest(&self.der).into()
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("sha256", &hex(&self.sha256()))
            .finish()
    }
}

/// Where an OS trust store has the CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreState {
    /// In the user's own store (Windows `CurrentUser\Root`, macOS user trust settings): what
    /// [`TrustStore::install`] adds and [`TrustStore::remove`] deletes.
    User,
    /// Only in machine-wide or policy stores (Windows `LocalMachine\Root`, group policy and
    /// enterprise stores; macOS admin trust settings), which need an administrator to change.
    Managed,
    Absent,
    /// The user's store could not be read.
    Unknown,
    /// There is no OS store the browsers use (Linux: they use NSS databases, see
    /// [`TrustReport::nss`]).
    NotApplicable,
}

/// The CA in one NSS database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssDbState {
    /// The database directory (holding `cert9.db`).
    pub path: PathBuf,
    /// Whether the database has the CA; `None` if it could not be read. Presence only: the
    /// trust flags are not interpreted, the live browser check decides.
    pub ca_present: Option<bool>,
}

/// Result of [`check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustReport {
    pub os_store: StoreState,
    /// Whether the OS accepts the leaf for a TLS server `127.0.0.1` (Windows chain engine
    /// with the SSL policy, macOS `SecTrust`); `None` where not applicable (Linux) or when
    /// the evaluation itself failed.
    pub os_chain_ok: Option<bool>,
    /// NSS databases of Chrome and Firefox (Linux only, empty elsewhere).
    pub nss: Vec<NssDbState>,
    /// Firefox profiles with whether Firefox imports the OS roots
    /// (`security.enterprise_roots.enabled`: the pref from `prefs.js`, else the default of
    /// the profile's last Firefox version, `None` if neither is known). Windows and macOS
    /// only: Firefox on Linux does not import OS roots.
    pub firefox_enterprise_roots: Vec<(PathBuf, Option<bool>)>,
}

/// What [`TrustStore::install`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    Installed,
    /// The store already had the certificate; nothing was written.
    AlreadyPresent,
    /// The user declined the system confirmation (Windows security warning, macOS
    /// authorization); nothing was written.
    CancelledByUser,
}

/// The user declined the system confirmation of a removal: the error inside the
/// [`io::Error`] of [`TrustStore::remove`] (`error.get_ref()` downcasts to it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the operation was cancelled in the system confirmation")]
pub struct Cancelled;

/// One trust store the user can install the CA into. Only called on an explicit user action
/// confirmed in a window.
pub trait TrustStore {
    /// Whether the store has exactly this certificate.
    fn contains(&self, ca: &Certificate) -> io::Result<bool>;
    /// Adds the certificate as a trusted root for TLS servers, unless it is already there.
    fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome>;
    /// Deletes exactly this certificate (matched by its encoding, never by name); `false` if
    /// the store did not have it. A declined system confirmation is an error with
    /// [`Cancelled`] inside.
    fn remove(&self, ca: &Certificate) -> io::Result<bool>;
}

/// Read-only trust check of the CA `ca` and the server leaf `leaf` it issued. Never writes
/// to any store and never prompts.
pub fn check(ca: &Certificate, leaf: &Certificate) -> TrustReport {
    imp::check(ca, leaf)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod imp {
    use super::{Certificate, StoreState, TrustReport};

    pub(crate) fn check(_ca: &Certificate, _leaf: &Certificate) -> TrustReport {
        TrustReport {
            os_store: StoreState::NotApplicable,
            os_chain_ok: None,
            nss: Vec::new(),
            firefox_enterprise_roots: Vec::new(),
        }
    }
}

fn invalid_data(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The `CERTIFICATE` blocks of a PEM text, in order.
fn pem_certificates(text: &str) -> impl Iterator<Item = io::Result<Certificate>> + '_ {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut rest = text;
    std::iter::from_fn(move || {
        let start = rest.find(BEGIN)?;
        let Some(len) = rest[start..].find(END) else {
            rest = "";
            return Some(Err(invalid_data("unterminated PEM CERTIFICATE block")));
        };
        let block = &rest[start..start + len + END.len()];
        rest = &rest[start + len + END.len()..];
        Some(
            x509_cert::der::pem::decode_vec(block.as_bytes())
                .map_err(|e| invalid_data(e.to_string()))
                .and_then(|(_, der)| Certificate::from_der(der)),
        )
    })
}

/// Sections of an INI file (`profiles.ini`, `compatibility.ini`): `(name, key/value pairs)`.
fn ini_sections(text: &str) -> Vec<(&str, Vec<(&str, &str)>)> {
    let mut sections: Vec<(&str, Vec<(&str, &str)>)> = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push((name, Vec::new()));
        } else if let (Some((_, entries)), Some((key, value))) =
            (sections.last_mut(), line.split_once('='))
        {
            entries.push((key.trim(), value.trim()));
        }
    }
    sections
}

/// Profile directories listed in `profiles.ini` under a Firefox profile root, in file order,
/// without duplicates. A missing or unreadable `profiles.ini` gives none.
fn firefox_profiles(root: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(root.join("profiles.ini")) else {
        return Vec::new();
    };
    let mut profiles = Vec::new();
    for (name, entries) in ini_sections(&text) {
        if !name.starts_with("Profile") {
            continue;
        }
        let value = |key: &str| entries.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let Some(path) = value("Path").filter(|p| !p.is_empty()) else {
            continue;
        };
        let dir = if value("IsRelative") == Some("0") {
            PathBuf::from(path)
        } else {
            root.join(path)
        };
        if !profiles.contains(&dir) {
            profiles.push(dir);
        }
    }
    profiles
}

/// `security.enterprise_roots.enabled` of a Firefox profile: the last `user_pref` in
/// `prefs.js`, else the default of the Firefox version that last ran the profile
/// (`compatibility.ini`: on since 120, off before), else unknown.
#[cfg(any(windows, target_os = "macos", test))]
fn firefox_enterprise_roots(profile: &Path) -> Option<bool> {
    const PREF: &str = "user_pref(\"security.enterprise_roots.enabled\",";
    if let Ok(prefs) = std::fs::read_to_string(profile.join("prefs.js")) {
        let explicit = prefs.lines().rev().find_map(|line| {
            let value = line.trim().strip_prefix(PREF)?.trim().strip_suffix(");")?;
            match value.trim() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            }
        });
        if explicit.is_some() {
            return explicit;
        }
    }
    let compatibility = std::fs::read_to_string(profile.join("compatibility.ini")).ok()?;
    let sections = ini_sections(&compatibility);
    let (_, entries) = sections.iter().find(|(name, _)| *name == "Compatibility")?;
    let (_, version) = entries.iter().find(|(key, _)| *key == "LastVersion")?;
    let major: u32 = version.split('.').next()?.parse().ok()?;
    Some(major >= 120)
}

/// [`TrustReport::firefox_enterprise_roots`] for the profiles under the given roots.
#[cfg(any(windows, target_os = "macos", test))]
fn firefox_enterprise_roots_report(roots: &[PathBuf]) -> Vec<(PathBuf, Option<bool>)> {
    roots
        .iter()
        .flat_map(|root| firefox_profiles(root))
        .map(|profile| {
            let enabled = firefox_enterprise_roots(&profile);
            (profile, enabled)
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fresh local CA (DER) and its server leaf for `127.0.0.1`, from `oncl-tls`.
    pub(crate) fn ca_and_leaf(label: &str) -> (Certificate, Certificate) {
        let material = oncl_tls::generate(time::OffsetDateTime::now_utc(), label).unwrap();
        let ca = Certificate::from_der(material.ca_der.unwrap()).unwrap();
        let leaf = Certificate::from_pem(&material.chain_pem).unwrap();
        (ca, leaf)
    }

    #[test]
    fn certificate_from_pem_and_der_agree() {
        let material = oncl_tls::generate(time::OffsetDateTime::now_utc(), "t@h").unwrap();
        let from_pem = Certificate::from_pem(material.ca_pem.as_deref().unwrap()).unwrap();
        let from_der = Certificate::from_der(material.ca_der.clone().unwrap()).unwrap();
        assert_eq!(from_pem, from_der);
        assert_eq!(
            hex(&from_der.sha1()),
            material.info.ca_sha1.as_deref().unwrap()
        );
        assert_eq!(
            hex(&from_der.sha256()),
            material.info.ca_sha256.as_deref().unwrap()
        );
    }

    #[test]
    fn certificate_rejects_garbage() {
        let err = Certificate::from_der(b"not a certificate".to_vec()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = Certificate::from_pem("no pem here").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = Certificate::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn pem_certificates_reads_every_block() {
        let (ca, _) = ca_and_leaf("a@h");
        let (other, _) = ca_and_leaf("b@h");
        let pem = |c: &Certificate| {
            x509_cert::der::pem::encode_string(
                "CERTIFICATE",
                x509_cert::der::pem::LineEnding::LF,
                c.der(),
            )
            .unwrap()
        };
        let text = format!("noise\n{}between\n{}", pem(&ca), pem(&other));
        let certs: Vec<_> = pem_certificates(&text).map(Result::unwrap).collect();
        assert_eq!(certs, [ca, other]);
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn firefox_profiles_from_profiles_ini() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("firefox");
        let absolute = dir.path().join("elsewhere").join("abs.profile");
        write(
            &root.join("profiles.ini"),
            &format!(
                "[Install4F96D1932A9F858E]\nDefault=Profiles/x.default-release\nLocked=1\n\n\
                 [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/y.default\n\n\
                 [Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/x.default-release\nDefault=1\n\n\
                 [Profile2]\nName=abs\nIsRelative=0\nPath={}\n\n\
                 [Profile3]\nName=dup\nIsRelative=1\nPath=Profiles/y.default\n\n\
                 [General]\nStartWithLastProfile=1\nVersion=2\n",
                absolute.display()
            ),
        );
        assert_eq!(
            firefox_profiles(&root),
            [
                root.join("Profiles/y.default"),
                root.join("Profiles/x.default-release"),
                absolute
            ]
        );
        assert!(firefox_profiles(&dir.path().join("missing")).is_empty());
    }

    #[test]
    fn firefox_enterprise_roots_pref_then_version_default() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        assert_eq!(firefox_enterprise_roots(profile), None);

        write(
            &profile.join("compatibility.ini"),
            "[Compatibility]\nLastVersion=115.9.1_20240312172836/20240312172836\nLastOSABI=WINNT_x86_64-msvc\n",
        );
        assert_eq!(firefox_enterprise_roots(profile), Some(false));
        write(
            &profile.join("compatibility.ini"),
            "[Compatibility]\nLastVersion=147.0_20260113000000/20260113000000\n",
        );
        assert_eq!(firefox_enterprise_roots(profile), Some(true));

        write(
            &profile.join("prefs.js"),
            "// Mozilla User Preferences\n\
             user_pref(\"security.enterprise_roots.enabled\", true);\n\
             user_pref(\"security.enterprise_roots.enabledX\", true);\n\
             user_pref(\"security.enterprise_roots.enabled\", false);\n\
             user_pref(\"browser.startup.page\", 3);\n",
        );
        assert_eq!(firefox_enterprise_roots(profile), Some(false));
        write(
            &profile.join("prefs.js"),
            "user_pref(\"browser.startup.page\", 3);\n",
        );
        assert_eq!(firefox_enterprise_roots(profile), Some(true));
    }

    #[test]
    fn firefox_enterprise_roots_report_lists_every_profile() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Firefox");
        write(
            &root.join("profiles.ini"),
            "[Profile0]\nIsRelative=1\nPath=Profiles/a\n\n[Profile1]\nIsRelative=1\nPath=Profiles/b\n",
        );
        write(
            &root.join("Profiles/a/prefs.js"),
            "user_pref(\"security.enterprise_roots.enabled\", false);\n",
        );
        assert_eq!(
            firefox_enterprise_roots_report(&[root.clone(), dir.path().join("missing")]),
            [
                (root.join("Profiles/a"), Some(false)),
                (root.join("Profiles/b"), None)
            ]
        );
    }
}
