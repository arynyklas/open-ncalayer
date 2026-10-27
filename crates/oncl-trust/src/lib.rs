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
//! Certificates are identified by their exact encoding, compared byte for byte (the other
//! certificates of a store are never parsed): installing twice does not duplicate a
//! certificate, and removing deletes exactly the given certificate, never another one with
//! the same name. Where a store can only address certificates by name and another
//! certificate shares the name (NSS, the same subject), the change is refused.

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
        let block = pem_blocks(pem)
            .next()
            .ok_or_else(|| invalid_data("no PEM CERTIFICATE block"))?;
        Self::from_der(block.ok_or_else(|| invalid_data("malformed PEM CERTIFICATE block"))?)
    }

    /// Whether `der` is exactly this certificate's encoding.
    fn is(&self, der: Option<&[u8]>) -> bool {
        der == Some(self.der.as_slice())
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

    /// The last common name of the subject, if it is a UTF-8, Printable or IA5 string.
    pub fn subject_common_name(&self) -> Option<String> {
        use x509_cert::der::{Tag, Tagged as _};
        const COMMON_NAME: x509_cert::der::asn1::ObjectIdentifier =
            x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
        let cert = x509_cert::Certificate::from_der(&self.der).ok()?;
        let value = cert
            .tbs_certificate()
            .subject()
            .iter()
            .filter(|attribute| attribute.oid == COMMON_NAME)
            .last()?
            .value
            .clone();
        match value.tag() {
            Tag::Utf8String | Tag::PrintableString | Tag::Ia5String => {
                String::from_utf8(value.value().to_vec()).ok()
            }
            _ => None,
        }
    }

    /// Whether the certificate names itself as its issuer (a root CA, not an intermediate).
    pub fn is_self_issued(&self) -> bool {
        x509_cert::Certificate::from_der(&self.der).is_ok_and(|cert| {
            let tbs = cert.tbs_certificate();
            tbs.subject() == tbs.issuer()
        })
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
    /// Whether the database has the CA; `None` if it could not be read.
    pub ca_present: Option<bool>,
    /// Whether the database trusts the CA for TLS servers (the SSL `C` flag of `certutil`);
    /// `None` without `certutil`, when `certutil` cannot read the database, or when another
    /// certificate with the same subject makes the flags ambiguous. The live browser check
    /// stays the final word.
    pub ca_ssl_trusted: Option<bool>,
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
    /// Adds the certificate as a trusted CA for TLS servers, unless it is already there. On
    /// macOS only a self-signed root becomes a trust root; an issuing CA is added as an
    /// intermediate that chains to its root.
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

/// The DER of each `CERTIFICATE` block of a PEM text, in order; `None` for a block that does
/// not decode (and the text ends at an unterminated one).
///
/// The blocks are not parsed as X.509: the certificates of a store are compared by their
/// bytes only, so one that this crate could not parse is still just "another certificate".
fn pem_blocks(text: &str) -> impl Iterator<Item = Option<Vec<u8>>> + '_ {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut rest = text;
    std::iter::from_fn(move || {
        let start = rest.find(BEGIN)?;
        let Some(len) = rest[start..].find(END) else {
            rest = "";
            return Some(None);
        };
        let block = &rest[start..start + len + END.len()];
        rest = &rest[start + len + END.len()..];
        Some(
            x509_cert::der::pem::decode_vec(block.as_bytes())
                .ok()
                .map(|(_, der)| der),
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
        ca_and_leaf_at(label, time::OffsetDateTime::now_utc())
    }

    /// [`ca_and_leaf`] issued at `now`: the same label and `now` give two CAs with the same
    /// subject.
    pub(crate) fn ca_and_leaf_at(
        label: &str,
        now: time::OffsetDateTime,
    ) -> (Certificate, Certificate) {
        let material = oncl_tls::generate(now, label).unwrap();
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
        let err = Certificate::from_pem(&pem(b"not a certificate")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The NCA's RSA root and issuing CA (the pinned ones the wizard installs).
    pub(crate) fn nca_rsa() -> (Certificate, Certificate) {
        let root = include_bytes!("../../../fixtures/nca/prod/rcarsa20.der");
        let issuing = include_bytes!("../../../fixtures/nca/prod/ncarsa22.der");
        (
            Certificate::from_der(root.to_vec()).unwrap(),
            Certificate::from_der(issuing.to_vec()).unwrap(),
        )
    }

    #[test]
    fn names_and_roots_of_certificates() {
        let (root, issuing) = nca_rsa();
        assert_eq!(
            root.subject_common_name().as_deref(),
            Some("НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA)")
        );
        assert_eq!(
            issuing.subject_common_name().as_deref(),
            Some("ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) 2022")
        );
        assert!(root.is_self_issued());
        assert!(!issuing.is_self_issued());
        let (ca, leaf) = ca_and_leaf("a@h");
        assert!(ca.is_self_issued());
        assert!(!leaf.is_self_issued());
        assert!(
            ca.subject_common_name()
                .is_some_and(|cn| cn.starts_with("OpenNCALayer Local CA (a@h ")),
            "{ca:?}"
        );
    }

    pub(crate) fn pem(der: &[u8]) -> String {
        x509_cert::der::pem::encode_string("CERTIFICATE", x509_cert::der::pem::LineEnding::LF, der)
            .unwrap()
    }

    #[test]
    fn pem_blocks_compares_bytes_without_parsing() {
        let (ca, _) = ca_and_leaf("a@h");
        let (other, _) = ca_and_leaf("b@h");
        let odd = noncanonical(&other);
        assert!(
            Certificate::from_der(odd.clone()).is_err(),
            "x509-cert rejects it"
        );
        let text = format!(
            "noise\n{}between\n{}{}-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n{}\
             -----BEGIN CERTIFICATE-----\nAAAA\n",
            pem(ca.der()),
            pem(&odd),
            pem(other.der()),
            pem(ca.der()),
        );
        let blocks: Vec<_> = pem_blocks(&text).collect();
        assert_eq!(
            blocks,
            [
                Some(ca.der().to_vec()),
                Some(odd),
                Some(other.der().to_vec()),
                None,
                Some(ca.der().to_vec()),
                None
            ]
        );
        assert!(ca.is(blocks[0].as_deref()));
        assert!(!ca.is(blocks[1].as_deref()));
        assert!(!ca.is(blocks[3].as_deref()));
    }

    /// `ca` with the critical flag of its basicConstraints encoded as BOOLEAN `01` instead of
    /// DER's `FF`: valid BER that NSS stores and x509-cert refuses. The signature no longer
    /// matches, which NSS does not check on import.
    pub(crate) fn noncanonical(ca: &Certificate) -> Vec<u8> {
        const BASIC_CONSTRAINTS_CRITICAL: [u8; 8] =
            [0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff];
        let mut der = ca.der().to_vec();
        let at = der
            .windows(BASIC_CONSTRAINTS_CRITICAL.len())
            .position(|w| w == BASIC_CONSTRAINTS_CRITICAL)
            .expect("the CA has a critical basicConstraints");
        der[at + BASIC_CONSTRAINTS_CRITICAL.len() - 1] = 0x01;
        der
    }

    pub(crate) fn write(path: &Path, text: &str) {
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
