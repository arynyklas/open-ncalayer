//! The TLS wizard («Сертификат для браузера…»):
//!
//! 1. the state: the server certificate, its dates and fingerprints, and the read-only trust
//!    check of its CA ([`TrustTargets::check`]);
//! 2. the source: OpenNCALayer's own CA, mkcert's CA (with the user's consent to have its
//!    key read at every renewal) or an imported certificate;
//! 3. installing and removing the own CA, the NCA's RSA roots and replaced own CAs in the
//!    user's trust stores, each only after a confirmation in the window;
//! 4. the check in the browser: the self-test page and the browsers that reported from it.
//!
//! The logic without a window is public: [`TlsWizardServices`] (loading and the actions, on
//! memory or temporary stores in tests) and the texts ([`status_text`], [`trust_text`],
//! [`browser_name`]). The window itself is in `window`, its texts in `texts`; the actions run
//! on a worker thread while the window waits for them.

mod texts;
mod window;

pub(crate) use window::{is_open, open};
#[cfg(test)]
pub(crate) use window::{open_loaded, preview_install_question};

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oncl_flows::Locale;
use oncl_tls::{
    AUTO_RENEW_BEFORE, RENEW_BEFORE, SelftestReport, SelftestReports, TlsError, TlsFiles, TlsInfo,
    TlsMaterial, TlsSource, TlsWarning, sha1_grouped,
};
use oncl_trust::{Cancelled, Certificate, InstallOutcome, StoreState, TrustReport, TrustStore};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use zeroize::Zeroizing;

use texts::{Texts, fill};

/// The trust stores of this user that the wizard checks and acts on.
pub trait TrustTargets: Send + Sync {
    /// Read-only: whether the browsers can trust `ca` and its leaf `leaf`.
    fn check(&self, ca: &Certificate, leaf: &Certificate) -> TrustReport;
    /// The stores the install buttons act on, made on the calling (worker) thread.
    fn stores(&self) -> Vec<NamedStore>;
}

/// A trust store with what the window calls it.
pub struct NamedStore {
    pub label: String,
    pub store: Box<dyn TrustStore>,
}

/// The trust stores of this user: Windows `CurrentUser\Root`, the macOS login keychain, the
/// NSS databases of Chrome and Firefox under `$HOME` (Linux). Only an explicit, confirmed
/// action of the wizard writes to them; [`TrustTargets::check`] only reads.
#[derive(Debug, Default)]
pub struct SystemTrust;

impl TrustTargets for SystemTrust {
    fn check(&self, ca: &Certificate, leaf: &Certificate) -> TrustReport {
        oncl_trust::check(ca, leaf)
    }

    #[cfg(windows)]
    fn stores(&self) -> Vec<NamedStore> {
        vec![NamedStore {
            label: "Windows: CurrentUser\\Root".to_owned(),
            store: Box::new(oncl_trust::WindowsUserRoot::current_user()),
        }]
    }

    #[cfg(target_os = "macos")]
    fn stores(&self) -> Vec<NamedStore> {
        vec![NamedStore {
            label: "macOS: login.keychain-db".to_owned(),
            store: Box::new(oncl_trust::MacLoginKeychain),
        }]
    }

    #[cfg(target_os = "linux")]
    fn stores(&self) -> Vec<NamedStore> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Vec::new();
        };
        oncl_trust::nss_databases(&home)
            .into_iter()
            .map(|db| NamedStore {
                label: nss_label(&home, &db.0),
                store: Box::new(db),
            })
            .collect()
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    fn stores(&self) -> Vec<NamedStore> {
        Vec::new()
    }
}

/// What the wizard calls the NSS database `db` under `home`: the browser and the path.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nss_label(home: &Path, db: &Path) -> String {
    let shown = match db.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => db.display().to_string(),
    };
    if shown.to_lowercase().contains("firefox") {
        format!("Firefox: {shown}")
    } else {
        format!("Chrome/Chromium: {shown}")
    }
}

/// What became of a certificate the wizard saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The server takes it for the next connections.
    Serving,
    /// The wss server is off because another program holds its port: it starts with it as
    /// soon as the port is free (e.g. the original NCALayer stopped from the tray).
    WhenPortFree,
    /// The wss server is off: it takes it at the next start.
    AfterRestart,
    /// The server could not load it (and keeps the previous one).
    Failed(String),
}

/// What the TLS wizard works with.
pub struct TlsWizardServices {
    pub files: TlsFiles,
    /// The server's port (the self-test page's address).
    pub port: u16,
    /// `user@host` for the name of a new own CA.
    pub label: String,
    pub reports: Arc<SelftestReports>,
    pub trust: Box<dyn TrustTargets>,
    /// mkcert's CA directory, if there is one ([`oncl_tls::mkcert_caroot`]).
    pub mkcert: Box<dyn Fn() -> Option<PathBuf> + Send + Sync>,
    /// Makes the server take the certificate just saved (on a worker thread).
    pub apply: Box<dyn Fn() -> Applied + Send + Sync>,
}

/// Where the next certificate comes from, in the order of the window's list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Own,
    Mkcert,
    Import,
}

impl Source {
    const ALL: [Source; 3] = [Source::Own, Source::Mkcert, Source::Import];

    fn of(source: &TlsSource) -> Source {
        match source {
            TlsSource::Own => Source::Own,
            TlsSource::Mkcert { .. } => Source::Mkcert,
            TlsSource::Imported => Source::Import,
        }
    }
}

/// What the «Источник» tab holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueForm {
    pub source: Source,
    /// The consent to have mkcert's CA key read at every renewal.
    pub mkcert_consent: bool,
    /// The chain and key files of an import.
    pub chain: String,
    pub key: String,
}

/// A trust store as the window lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRow {
    pub label: String,
    /// Whether it has the current CA; `None` without a CA.
    pub has_ca: Option<Result<bool, String>>,
}

/// A replaced own CA still waiting to be removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacedCa {
    pub ca: Certificate,
    pub name: Option<String>,
}

/// What the wizard shows.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// `tls.json`; `Ok(None)` when TLS is not set up.
    pub info: Result<Option<TlsInfo>, String>,
    /// The CA of the saved material (own or mkcert's) and its name.
    pub ca: Option<(Certificate, Option<String>)>,
    pub leaf: Option<Certificate>,
    /// The read-only check of `ca` and `leaf`.
    pub trust: Option<TrustReport>,
    pub stores: Vec<StoreRow>,
    pub replaced: Vec<ReplacedCa>,
    pub mkcert: Option<PathBuf>,
}

impl Snapshot {
    /// The saved material's source.
    pub fn source(&self) -> Option<&TlsSource> {
        self.info.as_ref().ok()?.as_ref().map(|info| &info.source)
    }

    /// The own CA, which the install buttons act on.
    pub fn own_ca(&self) -> Option<&Certificate> {
        match self.source() {
            Some(TlsSource::Own) => self.ca.as_ref().map(|(ca, _)| ca),
            _ => None,
        }
    }
}

/// Why a certificate was not issued.
#[derive(Debug)]
pub enum IssueError {
    NoConsent,
    NoMkcert,
    Read(PathBuf, io::Error),
    Tls(TlsError),
    Save(io::Error),
}

/// A certificate the wizard saved.
#[derive(Debug)]
pub struct Issued {
    pub info: TlsInfo,
    pub warnings: Vec<TlsWarning>,
    pub applied: Applied,
}

/// One store's outcome of an action.
#[derive(Debug)]
pub enum StoreOutcome {
    Installed(InstallOutcome),
    Removed(bool),
    Failed(io::Error),
}

/// Why a confirmed action on the trust stores did nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// There is no own CA (any more).
    NoOwnCa,
    /// The CA is not the one the user confirmed: it was replaced meanwhile.
    Changed,
    /// The embedded NCA roots do not match their pins.
    Roots(String),
}

/// The per-store outcomes of a confirmed action, or why it did nothing.
pub type Outcomes = Result<Vec<(String, StoreOutcome)>, Refused>;

impl TlsWizardServices {
    /// The self-test page.
    pub fn selftest_url(&self) -> String {
        format!("https://127.0.0.1:{}/openncalayer/selftest", self.port)
    }

    /// Everything the wizard shows (read only, on a worker thread).
    pub fn load(&self) -> Snapshot {
        let info = oncl_tls::load_info(&self.files).map_err(|e| e.to_string());
        let configured = matches!(info, Ok(Some(_)));
        let ca = configured
            .then(|| std::fs::read(self.files.ca_der()).ok())
            .flatten()
            .and_then(|der| Certificate::from_der(der).ok())
            .map(|ca| {
                let name = oncl_tls::subject_common_name(ca.der());
                (ca, name)
            });
        let leaf = configured
            .then(|| std::fs::read_to_string(self.files.chain_pem()).ok())
            .flatten()
            .and_then(|pem| Certificate::from_pem(&pem).ok());
        let trust = match (&ca, &leaf) {
            (Some((ca, _)), Some(leaf)) => Some(self.trust.check(ca, leaf)),
            _ => None,
        };
        let stores = self
            .trust
            .stores()
            .into_iter()
            .map(|named| StoreRow {
                has_ca: ca
                    .as_ref()
                    .map(|(ca, _)| named.store.contains(ca).map_err(|e| e.to_string())),
                label: named.label,
            })
            .collect();
        let replaced = oncl_tls::replaced_cas(&self.files)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cannot read the replaced CAs");
                Vec::new()
            })
            .into_iter()
            .filter_map(|der| Certificate::from_der(der).ok())
            .map(|ca| ReplacedCa {
                name: oncl_tls::subject_common_name(ca.der()),
                ca,
            })
            .collect();
        Snapshot {
            info,
            ca,
            leaf,
            trust,
            stores,
            replaced,
            mkcert: (self.mkcert)(),
        }
    }

    /// Issues (or imports) the certificate of `form` at `now`, saves it and has the server
    /// take it. Nothing is saved on an error.
    ///
    /// # Errors
    ///
    /// No consent or no mkcert for mkcert, an unreadable import file, unusable material, or
    /// the files cannot be written.
    pub fn issue(&self, form: &IssueForm, now: OffsetDateTime) -> Result<Issued, IssueError> {
        let material = match form.source {
            Source::Own => oncl_tls::generate(now, &self.label).map_err(IssueError::Tls)?,
            Source::Mkcert => {
                if !form.mkcert_consent {
                    return Err(IssueError::NoConsent);
                }
                let caroot = (self.mkcert)().ok_or(IssueError::NoMkcert)?;
                oncl_tls::issue_with_mkcert(&caroot, now).map_err(IssueError::Tls)?
            }
            Source::Import => {
                let read = |path: &str| {
                    let path = Path::new(path.trim());
                    std::fs::read_to_string(path).map_err(|e| IssueError::Read(path.into(), e))
                };
                let chain = read(&form.chain)?;
                let key = Zeroizing::new(read(&form.key)?);
                oncl_tls::import(&chain, &key, now).map_err(IssueError::Tls)?
            }
        };
        self.save(material)
    }

    fn save(&self, material: TlsMaterial) -> Result<Issued, IssueError> {
        oncl_tls::save(&self.files, &material).map_err(IssueError::Save)?;
        Ok(Issued {
            applied: (self.apply)(),
            info: material.info,
            warnings: material.warnings,
        })
    }

    /// The stores named `labels`, in the order of [`TrustTargets::stores`].
    fn selected(&self, labels: &[String]) -> Vec<NamedStore> {
        self.trust
            .stores()
            .into_iter()
            .filter(|named| labels.contains(&named.label))
            .collect()
    }

    /// Installs the own CA into the stores named `labels`, if it still is `confirmed`.
    ///
    /// # Errors
    ///
    /// There is no own CA, or it is not `confirmed`.
    pub fn install_ca(&self, labels: &[String], confirmed: &Certificate) -> Outcomes {
        let ca = self.confirmed_own_ca(confirmed)?;
        Ok(self.each(labels, |store| {
            store.install(&ca).map(StoreOutcome::Installed)
        }))
    }

    /// Removes exactly the own CA from the stores named `labels`, if it still is
    /// `confirmed`.
    ///
    /// # Errors
    ///
    /// There is no own CA, or it is not `confirmed`.
    pub fn remove_ca(&self, labels: &[String], confirmed: &Certificate) -> Outcomes {
        let ca = self.confirmed_own_ca(confirmed)?;
        Ok(self.each(labels, |store| store.remove(&ca).map(StoreOutcome::Removed)))
    }

    /// Installs the NCA's RSA CAs ([`oncl_pki::roots::nca_tls_roots`], checked against
    /// their pinned SHA-256) into the stores named `labels`: one outcome per store and CA.
    ///
    /// # Errors
    ///
    /// An embedded root does not match its pin: nothing is installed.
    pub fn install_nca_roots(&self, labels: &[String]) -> Outcomes {
        self.each_nca_root(labels, |store, root| {
            store.install(root).map(StoreOutcome::Installed)
        })
    }

    /// Removes exactly the NCA's RSA CAs that [`install_nca_roots`](Self::install_nca_roots)
    /// installs (the same pinned encodings, never another certificate of the same name) from
    /// the stores named `labels`: one outcome per store and CA.
    ///
    /// # Errors
    ///
    /// An embedded root does not match its pin: nothing is removed.
    pub fn remove_nca_roots(&self, labels: &[String]) -> Outcomes {
        self.each_nca_root(labels, |store, root| {
            store.remove(root).map(StoreOutcome::Removed)
        })
    }

    /// `act` on each pinned NCA RSA CA in each store named `labels`, outcomes labelled
    /// `<store> (<alias>)`.
    fn each_nca_root(
        &self,
        labels: &[String],
        act: impl Fn(&dyn TrustStore, &Certificate) -> io::Result<StoreOutcome>,
    ) -> Outcomes {
        let roots = oncl_pki::roots::nca_tls_roots()
            .map_err(Refused::Roots)?
            .into_iter()
            .map(|(alias, der)| {
                Certificate::from_der(der)
                    .map(|root| (alias, root))
                    .map_err(|e| Refused::Roots(format!("{alias}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut outcomes = Vec::new();
        for named in self.selected(labels) {
            for (alias, root) in &roots {
                let label = format!("{} ({alias})", named.label);
                let outcome = act(&*named.store, root).unwrap_or_else(StoreOutcome::Failed);
                outcomes.push((label, outcome));
            }
        }
        Ok(outcomes)
    }

    /// Removes the replaced own CAs that are among `confirmed` from the stores named
    /// `labels`; a CA removed (or absent) everywhere ticked is forgotten
    /// ([`oncl_tls::forget_replaced_ca`]). Replaced CAs the user was not asked about stay.
    pub fn remove_replaced(&self, labels: &[String], confirmed: &[Certificate]) -> Outcomes {
        let stores = self.selected(labels);
        let mut outcomes = Vec::new();
        let replaced = oncl_tls::replaced_cas(&self.files).unwrap_or_default();
        for der in replaced {
            let Ok(ca) = Certificate::from_der(der) else {
                continue;
            };
            if !confirmed.contains(&ca) {
                continue;
            }
            let name = oncl_tls::subject_common_name(ca.der()).unwrap_or_default();
            let mut all_done = !stores.is_empty();
            for named in &stores {
                let outcome = named.store.remove(&ca);
                all_done &= outcome.is_ok();
                let label = format!("{} ({name})", named.label);
                outcomes.push((
                    label,
                    outcome.map_or_else(StoreOutcome::Failed, StoreOutcome::Removed),
                ));
            }
            if all_done && let Err(e) = oncl_tls::forget_replaced_ca(&self.files, ca.der()) {
                outcomes.push((name, StoreOutcome::Failed(e)));
            }
        }
        Ok(outcomes)
    }

    /// Records the mkcert consent given (`true`, at `now`) or withdrawn in `tls.json`; whether
    /// the saved certificate is mkcert's and so has the consent at all.
    ///
    /// # Errors
    ///
    /// `tls.json` cannot be read or written.
    pub fn set_mkcert_consent(&self, consent: bool, now: OffsetDateTime) -> io::Result<bool> {
        let consented_at = consent
            .then(|| now.to_offset(UtcOffset::UTC).format(&Rfc3339))
            .transpose()
            .map_err(io::Error::other)?;
        oncl_tls::set_mkcert_consent(&self.files, consented_at)
    }

    /// The own CA of the saved material, if it is `confirmed`.
    fn confirmed_own_ca(&self, confirmed: &Certificate) -> Result<Certificate, Refused> {
        let ca = self.own_ca().ok_or(Refused::NoOwnCa)?;
        if ca == *confirmed {
            Ok(ca)
        } else {
            Err(Refused::Changed)
        }
    }

    /// The own CA of the saved material.
    fn own_ca(&self) -> Option<Certificate> {
        match oncl_tls::load_info(&self.files) {
            Ok(Some(TlsInfo {
                source: TlsSource::Own,
                ..
            })) => {}
            _ => return None,
        }
        std::fs::read(self.files.ca_der())
            .ok()
            .and_then(|der| Certificate::from_der(der).ok())
    }

    fn each(
        &self,
        labels: &[String],
        act: impl Fn(&dyn TrustStore) -> io::Result<StoreOutcome>,
    ) -> Vec<(String, StoreOutcome)> {
        self.selected(labels)
            .into_iter()
            .map(|named| {
                let outcome = act(&*named.store).unwrap_or_else(StoreOutcome::Failed);
                (named.label, outcome)
            })
            .collect()
    }
}

/// `dd.MM.yyyy` in UTC.
fn date(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!("{:02}.{:02}.{:04}", t.day(), u8::from(t.month()), t.year())
}

/// `dd.MM.yyyy HH:MM UTC`.
fn date_time(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!("{} {:02}:{:02} UTC", date(t), t.hour(), t.minute())
}

/// The «Состояние» tab's certificate part at `now` in `l`.
pub fn status_text(snapshot: &Snapshot, now: OffsetDateTime, l: Locale) -> String {
    let t = Texts::of(l);
    let info = match &snapshot.info {
        Err(e) => return fill(t.unreadable, &[e]),
        Ok(None) => return t.not_configured.to_owned(),
        Ok(Some(info)) => info,
    };
    let mut s = String::new();
    let line = |s: &mut String, text: String| {
        let _ = writeln!(s, "{text}");
    };
    match &info.source {
        TlsSource::Own => line(&mut s, t.source_own.to_owned()),
        TlsSource::Mkcert { caroot, .. } => {
            line(
                &mut s,
                fill(t.source_mkcert, &[&caroot.display().to_string()]),
            );
        }
        TlsSource::Imported => line(&mut s, t.source_imported.to_owned()),
    }
    if let Some((_, Some(name))) = &snapshot.ca {
        line(&mut s, fill(t.ca_name, &[name]));
    }
    if let Ok(not_after) = OffsetDateTime::parse(&info.leaf_not_after, &Rfc3339) {
        let left = (not_after - now).whole_days();
        if not_after <= now {
            line(&mut s, fill(t.leaf_expired, &[&date(not_after)]));
        } else {
            line(
                &mut s,
                fill(t.leaf_valid, &[&date(not_after), &left.to_string()]),
            );
        }
        if info.source.renews_itself() {
            line(
                &mut s,
                fill(t.auto_renew, &[&date(not_after - AUTO_RENEW_BEFORE)]),
            );
        } else {
            line(&mut s, fill(t.renew_by, &[&date(not_after - RENEW_BEFORE)]));
        }
    }
    if let Some(sha1) = &info.ca_sha1 {
        line(&mut s, fill(t.ca_sha1, &[&sha1_grouped(sha1)]));
    }
    if let Some(sha256) = &info.ca_sha256 {
        line(&mut s, fill(t.ca_sha256, &[&sha256.to_ascii_uppercase()]));
    }
    line(
        &mut s,
        fill(t.leaf_sha256, &[&info.leaf_sha256.to_ascii_uppercase()]),
    );
    s.trim_end().to_owned()
}

/// The «Состояние» tab's trust part in `l`.
pub fn trust_text(snapshot: &Snapshot, l: Locale) -> String {
    let t = Texts::of(l);
    let Some(report) = &snapshot.trust else {
        return match snapshot.source() {
            Some(TlsSource::Imported) => t.trust_imported,
            _ => t.trust_nothing,
        }
        .to_owned();
    };
    let mut lines = Vec::new();
    let os = match report.os_store {
        StoreState::User => Some(t.os_user),
        StoreState::Managed => Some(t.os_managed),
        StoreState::Absent => Some(t.os_absent),
        StoreState::Unknown => Some(t.os_unknown),
        StoreState::NotApplicable => None,
    };
    if let Some(os) = os {
        lines.push(fill(t.os_store, &[os]));
        let chain = match report.os_chain_ok {
            Some(true) => t.yes,
            Some(false) => t.no,
            None => t.unknown,
        };
        lines.push(fill(t.os_chain, &[chain]));
    }
    for db in &report.nss {
        let state = match (db.ca_present, db.ca_ssl_trusted) {
            (None, _) => t.nss_unreadable,
            (Some(false), _) => t.nss_absent,
            (Some(true), Some(true)) => t.nss_trusted,
            (Some(true), Some(false)) => t.nss_untrusted,
            (Some(true), None) => t.nss_present,
        };
        lines.push(fill(t.nss_db, &[&db.path.display().to_string(), state]));
    }
    if report.nss.is_empty() && report.os_store == StoreState::NotApplicable {
        lines.push(t.no_nss.to_owned());
    }
    for (profile, enterprise_roots) in &report.firefox_enterprise_roots {
        let state = match enterprise_roots {
            Some(true) => t.firefox_on,
            Some(false) => t.firefox_off,
            None => t.unknown,
        };
        let name = profile.file_name().map_or_else(
            || profile.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        lines.push(fill(t.firefox, &[&name, state]));
    }
    lines.join("\n")
}

/// The «Источник» tab's mkcert text.
fn mkcert_text(caroot: Option<&Path>, l: Locale) -> String {
    let t = Texts::of(l);
    match caroot {
        Some(caroot) => fill(t.mkcert_found, &[&caroot.display().to_string()]),
        None => t.mkcert_missing.to_owned(),
    }
}

/// The «Установка» tab's text about the current CA.
fn install_text(snapshot: &Snapshot, l: Locale) -> String {
    let t = Texts::of(l);
    let text = match (snapshot.source(), snapshot.own_ca()) {
        (Some(TlsSource::Own), Some(ca)) => {
            let name = snapshot
                .ca
                .as_ref()
                .and_then(|(_, name)| name.clone())
                .unwrap_or_default();
            fill(t.install_own, &[&name, &sha1_grouped(&hex(&ca.sha1()))])
        }
        (Some(TlsSource::Mkcert { .. }), _) => t.install_mkcert.to_owned(),
        (Some(TlsSource::Imported), _) => t.install_imported.to_owned(),
        _ => t.install_none.to_owned(),
    };
    if snapshot.stores.is_empty() {
        format!("{text}\n{}", t.no_stores)
    } else {
        text
    }
}

/// A store's state in the list.
fn store_state(row: &StoreRow, l: Locale) -> String {
    let t = Texts::of(l);
    match &row.has_ca {
        None => String::new(),
        Some(Ok(true)) => t.store_has_ca.to_owned(),
        Some(Ok(false)) => t.store_lacks_ca.to_owned(),
        Some(Err(e)) => fill(t.store_unreadable, &[e]),
    }
}

/// The replaced CAs: `«name», SHA-1 …` each.
fn replaced_text(replaced: &[ReplacedCa], l: Locale) -> String {
    let list: Vec<String> = replaced.iter().map(ca_line).collect();
    fill(Texts::of(l).replaced, &[&list.join("\n")])
}

fn ca_line(replaced: &ReplacedCa) -> String {
    format!(
        "«{}», SHA-1 {}",
        replaced.name.as_deref().unwrap_or_default(),
        sha1_grouped(&hex(&replaced.ca.sha1()))
    )
}

/// The browser and its version in a `navigator.userAgent`, e.g. `Firefox 140.0`,
/// `Chrome 141.0.0.0`, `Edge 141.0.0.0`; the whole string if no browser is recognised.
pub fn browser_name(user_agent: &str) -> String {
    // Checked in this order: Edge, Opera and Yandex also name Chrome and Safari.
    const BROWSERS: [(&str, &str); 7] = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("YaBrowser/", "Yandex"),
        ("Firefox/", "Firefox"),
        ("Chromium/", "Chromium"),
        ("Chrome/", "Chrome"),
        ("Version/", "Safari"),
    ];
    for (token, name) in BROWSERS {
        if let Some(at) = user_agent.find(token) {
            let version: String = user_agent[at + token.len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            return format!("{name} {version}").trim_end().to_owned();
        }
    }
    user_agent.to_owned()
}

/// `(browser, when)` rows of `reports`.
fn browser_rows(reports: &[SelftestReport]) -> Vec<(String, String)> {
    reports
        .iter()
        .map(|r| (browser_name(&r.user_agent), date_time(r.at)))
        .collect()
}

/// The message of an issued certificate.
fn issued_text(issued: &Issued, l: Locale) -> String {
    let t = Texts::of(l);
    let mut text = match &issued.applied {
        Applied::Serving => t.issued_serving.to_owned(),
        Applied::AfterRestart => t.issued_after_restart.to_owned(),
        Applied::WhenPortFree => t.issued_when_port_free.to_owned(),
        Applied::Failed(e) => fill(t.issued_not_served, &[e]),
    };
    for warning in &issued.warnings {
        match warning {
            TlsWarning::ValidityOver825Days => {
                text.push('\n');
                text.push_str(t.over_825_days);
            }
        }
    }
    text
}

fn issue_error_text(e: &IssueError, l: Locale) -> String {
    let t = Texts::of(l);
    match e {
        IssueError::NoConsent => t.no_consent.to_owned(),
        IssueError::NoMkcert => t.no_mkcert.to_owned(),
        IssueError::Read(path, e) => fill(
            t.cannot_read,
            &[&path.display().to_string(), &e.to_string()],
        ),
        IssueError::Tls(e) => fill(t.cannot_use, &[&e.to_string()]),
        IssueError::Save(e) => fill(t.cannot_save, &[&e.to_string()]),
    }
}

/// The message of a confirmed action: its outcomes, one line per store, or why it did
/// nothing; whether it failed.
fn action_text(outcomes: &Outcomes, l: Locale) -> (String, bool) {
    let t = Texts::of(l);
    match outcomes {
        Ok(outcomes) => outcomes_text(outcomes, l),
        Err(Refused::NoOwnCa) => (t.no_ca.to_owned(), true),
        Err(Refused::Changed) => (t.ca_changed.to_owned(), true),
        Err(Refused::Roots(e)) => (fill(t.roots_broken, &[e]), true),
    }
}

/// The outcomes of an action, one line per store; whether any failed.
fn outcomes_text(outcomes: &[(String, StoreOutcome)], l: Locale) -> (String, bool) {
    let t = Texts::of(l);
    if outcomes.is_empty() {
        return (t.stores_unknown.to_owned(), true);
    }
    let mut failed = false;
    let lines: Vec<String> = outcomes
        .iter()
        .map(|(label, outcome)| match outcome {
            StoreOutcome::Installed(InstallOutcome::Installed) => fill(t.installed, &[label]),
            StoreOutcome::Installed(InstallOutcome::AlreadyPresent) => {
                fill(t.already_present, &[label])
            }
            StoreOutcome::Installed(InstallOutcome::CancelledByUser) => {
                fill(t.install_cancelled, &[label])
            }
            StoreOutcome::Removed(true) => fill(t.removed, &[label]),
            StoreOutcome::Removed(false) => fill(t.not_there, &[label]),
            StoreOutcome::Failed(e) if is_cancelled(e) => fill(t.remove_cancelled, &[label]),
            StoreOutcome::Failed(e) => {
                failed = true;
                fill(t.failed, &[label, &e.to_string()])
            }
        })
        .collect();
    (lines.join("\n"), failed)
}

/// Whether `e` is a declined system confirmation ([`Cancelled`]).
fn is_cancelled(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Cancelled>())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
pub(crate) mod fakes {
    //! Trust stores in memory: what the tests install into and remove from.

    use std::sync::{Arc, Mutex, PoisonError};

    use super::*;

    /// Certificates (DER) in memory, shared by the clones of one store.
    #[derive(Clone, Default)]
    pub(crate) struct MemoryStore(pub(crate) Arc<Mutex<Vec<Vec<u8>>>>);

    impl MemoryStore {
        pub(crate) fn certificates(&self) -> Vec<Vec<u8>> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl TrustStore for MemoryStore {
        fn contains(&self, ca: &Certificate) -> io::Result<bool> {
            Ok(self.certificates().iter().any(|der| der == ca.der()))
        }

        fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
            let mut certs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if certs.iter().any(|der| der == ca.der()) {
                return Ok(InstallOutcome::AlreadyPresent);
            }
            certs.push(ca.der().to_vec());
            Ok(InstallOutcome::Installed)
        }

        fn remove(&self, ca: &Certificate) -> io::Result<bool> {
            let mut certs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let before = certs.len();
            certs.retain(|der| der != ca.der());
            Ok(certs.len() != before)
        }
    }

    /// Memory stores, by label; `check` reports from the first.
    pub(crate) struct MemoryTargets(pub(crate) Vec<(String, MemoryStore)>);

    impl TrustTargets for MemoryTargets {
        fn check(&self, ca: &Certificate, _leaf: &Certificate) -> TrustReport {
            let present = self
                .0
                .first()
                .is_some_and(|(_, store)| store.contains(ca).unwrap_or(false));
            TrustReport {
                os_store: if present {
                    StoreState::User
                } else {
                    StoreState::Absent
                },
                os_chain_ok: Some(present),
                nss: Vec::new(),
                firefox_enterprise_roots: Vec::new(),
            }
        }

        fn stores(&self) -> Vec<NamedStore> {
            self.0
                .iter()
                .map(|(label, store)| NamedStore {
                    label: label.clone(),
                    store: Box::new(store.clone()),
                })
                .collect()
        }
    }

    /// The wizard on `dir` with the memory stores `stores`, mkcert in `mkcert`, a server
    /// that always takes the certificate.
    pub(crate) fn services(
        dir: &Path,
        stores: Vec<(String, MemoryStore)>,
        mkcert: Option<PathBuf>,
    ) -> TlsWizardServices {
        TlsWizardServices {
            files: TlsFiles {
                dir: dir.join("tls"),
            },
            port: 13579,
            label: "user@host".to_owned(),
            reports: Arc::new(SelftestReports::new()),
            trust: Box::new(MemoryTargets(stores)),
            mkcert: Box::new(move || mkcert.clone()),
            apply: Box::new(|| Applied::Serving),
        }
    }

    /// An mkcert-like CA `mkcert user@host` (valid 2000–2099) in the CAROOT `dir`; its
    /// certificate.
    pub(crate) fn fake_mkcert(dir: &Path) -> Certificate {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mkcert user@host");
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let ca = params.self_signed(&key).unwrap();
        std::fs::write(dir.join("rootCA.pem"), ca.pem()).unwrap();
        std::fs::write(dir.join("rootCA-key.pem"), key.serialize_pem()).unwrap();
        Certificate::from_der(ca.der().to_vec()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fakes::{self, MemoryStore, services};
    use super::*;
    use time::Duration;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-10-27 10:00 UTC);

    fn own() -> IssueForm {
        IssueForm {
            source: Source::Own,
            mkcert_consent: false,
            chain: String::new(),
            key: String::new(),
        }
    }

    fn labels(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    #[test]
    fn own_ca_installs_into_ticked_stores_only_and_is_removed_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let user = MemoryStore::default();
        let other = MemoryStore::default();
        // Someone else's certificate stays untouched.
        let foreign = oncl_tls::generate(NOW, "other").unwrap().ca_der.unwrap();
        other.0.lock().unwrap().push(foreign.clone());
        let s = services(
            dir.path(),
            vec![
                ("User".to_owned(), user.clone()),
                ("Other".to_owned(), other.clone()),
            ],
            None,
        );
        let stranger = Certificate::from_der(foreign.clone()).unwrap();
        assert_eq!(
            s.install_ca(&labels(&["User"]), &stranger).unwrap_err(),
            Refused::NoOwnCa
        );

        let issued = s.issue(&own(), NOW).unwrap();
        assert_eq!(issued.applied, Applied::Serving);
        let snapshot = s.load();
        let ca = snapshot.own_ca().unwrap().clone();
        assert_eq!(
            snapshot
                .stores
                .iter()
                .map(|r| r.has_ca.clone())
                .collect::<Vec<_>>(),
            [Some(Ok(false)), Some(Ok(false))]
        );

        // Only the CA the user confirmed is acted on.
        assert_eq!(
            s.install_ca(&labels(&["User"]), &stranger).unwrap_err(),
            Refused::Changed
        );
        assert!(user.certificates().is_empty());
        let outcomes = s.install_ca(&labels(&["User"]), &ca).unwrap();
        assert!(matches!(
            &outcomes[..],
            [(l, StoreOutcome::Installed(InstallOutcome::Installed))] if l == "User"
        ));
        assert_eq!(user.certificates(), [ca.der().to_vec()]);
        assert_eq!(other.certificates(), std::slice::from_ref(&foreign));
        // A second click duplicates nothing.
        let again = s.install_ca(&labels(&["User"]), &ca).unwrap();
        assert!(matches!(
            again[..],
            [(_, StoreOutcome::Installed(InstallOutcome::AlreadyPresent))]
        ));
        assert_eq!(user.certificates().len(), 1);
        assert_eq!(s.load().trust.unwrap().os_store, StoreState::User);

        let removed = s.remove_ca(&labels(&["User", "Other"]), &ca).unwrap();
        assert!(matches!(
            removed[..],
            [
                (_, StoreOutcome::Removed(true)),
                (_, StoreOutcome::Removed(false))
            ]
        ));
        assert!(user.certificates().is_empty());
        assert_eq!(other.certificates(), [foreign]);
        let (text, failed) = outcomes_text(&removed, Locale::Ru);
        assert_eq!(text, "User: удалён\nOther: его там не было");
        assert!(!failed);
        assert!(outcomes_text(&[], Locale::Ru).1);
    }

    #[test]
    fn a_reissue_offers_the_old_ca_for_removal() {
        let dir = tempfile::tempdir().unwrap();
        let user = MemoryStore::default();
        let s = services(dir.path(), vec![("User".to_owned(), user.clone())], None);
        s.issue(&own(), NOW).unwrap();
        let first = s.load().own_ca().unwrap().clone();
        s.install_ca(&labels(&["User"]), &first).unwrap();

        s.issue(&own(), NOW + Duration::days(1)).unwrap();
        let snapshot = s.load();
        assert_eq!(snapshot.replaced.len(), 1);
        assert_eq!(snapshot.replaced[0].ca, first);
        let text = replaced_text(&snapshot.replaced, Locale::Ru);
        assert!(
            text.contains("OpenNCALayer Local CA (user@host 2026-10-27)"),
            "{text}"
        );
        assert!(text.contains(&sha1_grouped(&hex(&first.sha1()))), "{text}");

        // Only the CAs the user was asked about.
        let outcomes = s.remove_replaced(&labels(&["User"]), &[]).unwrap();
        assert!(outcomes.is_empty());
        assert_eq!(s.load().replaced.len(), 1);
        let outcomes = s
            .remove_replaced(&labels(&["User"]), std::slice::from_ref(&first))
            .unwrap();
        assert!(matches!(outcomes[..], [(_, StoreOutcome::Removed(true))]));
        assert!(user.certificates().is_empty());
        assert!(s.load().replaced.is_empty());
    }

    #[test]
    fn mkcert_needs_consent_and_its_ca_is_not_installed_by_us() {
        let dir = tempfile::tempdir().unwrap();
        let caroot = tempfile::tempdir().unwrap();
        let ca = fakes::fake_mkcert(caroot.path());

        let none = services(dir.path(), Vec::new(), None);
        let mut form = IssueForm {
            source: Source::Mkcert,
            mkcert_consent: true,
            ..own()
        };
        assert!(matches!(none.issue(&form, NOW), Err(IssueError::NoMkcert)));
        let s = services(
            dir.path(),
            vec![("User".to_owned(), MemoryStore::default())],
            Some(caroot.path().to_path_buf()),
        );
        form.mkcert_consent = false;
        assert!(matches!(s.issue(&form, NOW), Err(IssueError::NoConsent)));
        assert_eq!(s.load().info.unwrap(), None);
        form.mkcert_consent = true;
        s.issue(&form, NOW).unwrap();
        let snapshot = s.load();
        assert!(matches!(snapshot.source(), Some(TlsSource::Mkcert { .. })));
        assert_eq!(
            snapshot.ca.as_ref().unwrap().1.as_deref(),
            Some("mkcert user@host")
        );
        assert!(snapshot.own_ca().is_none());
        assert_eq!(
            s.install_ca(&labels(&["User"]), &ca).unwrap_err(),
            Refused::NoOwnCa
        );
        assert!(install_text(&snapshot, Locale::Ru).contains("mkcert -install"));
        let status = status_text(&snapshot, NOW, Locale::Ru);
        assert!(status.contains("перевыпустит его сам"), "{status}");
    }

    #[test]
    fn nca_roots_are_installed_as_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let user = MemoryStore::default();
        let s = services(dir.path(), vec![("User".to_owned(), user.clone())], None);
        let outcomes = s.install_nca_roots(&labels(&["User"])).unwrap();
        let names: Vec<&str> = outcomes.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(names, ["User (rcarsa20)", "User (ncarsa22)"]);
        let expected: Vec<Vec<u8>> = oncl_pki::roots::nca_tls_roots()
            .unwrap()
            .into_iter()
            .map(|(_, der)| der.to_vec())
            .collect();
        assert_eq!(user.certificates(), expected);
        assert!(
            s.install_nca_roots(&labels(&["Missing"]))
                .unwrap()
                .is_empty()
        );
        let (text, failed) = action_text(&Err(Refused::Roots("rcarsa20".to_owned())), Locale::En);
        assert!(failed);
        assert!(text.ends_with("nothing was changed: rcarsa20"), "{text}");

        // Removal takes exactly the pinned encodings and leaves anything else.
        let other =
            Certificate::from_der(include_bytes!("../../../fixtures/nca/prod/ncarsa.der").to_vec())
                .unwrap();
        user.install(&other).unwrap();
        let outcomes = s.remove_nca_roots(&labels(&["User"])).unwrap();
        let names: Vec<&str> = outcomes.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(names, ["User (rcarsa20)", "User (ncarsa22)"]);
        assert!(
            outcomes
                .iter()
                .all(|(_, o)| matches!(o, StoreOutcome::Removed(true))),
            "{outcomes:?}"
        );
        assert_eq!(user.certificates(), [other.der().to_vec()]);
        let again = s.remove_nca_roots(&labels(&["User"])).unwrap();
        assert!(
            again
                .iter()
                .all(|(_, o)| matches!(o, StoreOutcome::Removed(false)))
        );
    }

    #[test]
    fn an_import_reads_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = services(dir.path(), Vec::new(), None);
        let form = IssueForm {
            source: Source::Import,
            chain: dir.path().join("missing.pem").display().to_string(),
            key: String::new(),
            ..own()
        };
        let e = s.issue(&form, NOW).unwrap_err();
        assert!(matches!(e, IssueError::Read(..)));
        assert!(issue_error_text(&e, Locale::En).starts_with("Cannot read "));
        assert_eq!(s.load().info.unwrap(), None);
    }

    #[test]
    fn status_and_trust_texts() {
        let dir = tempfile::tempdir().unwrap();
        let s = services(
            dir.path(),
            vec![("User".to_owned(), MemoryStore::default())],
            None,
        );
        let empty = s.load();
        assert_eq!(
            status_text(&empty, NOW, Locale::Ru),
            Texts::of(Locale::Ru).not_configured
        );
        assert!(install_text(&empty, Locale::En).starts_with("Issue a certificate"));

        s.issue(&own(), NOW).unwrap();
        let snapshot = s.load();
        let info = snapshot.info.as_ref().unwrap().as_ref().unwrap();
        let status = status_text(&snapshot, NOW, Locale::Ru);
        assert!(status.starts_with("Источник: собственный"), "{status}");
        assert!(
            status.contains("OpenNCALayer Local CA (user@host 2026-10-27)"),
            "{status}"
        );
        assert!(status.contains("(осталось дней: 799)"), "{status}");
        assert!(
            status.contains(&sha1_grouped(info.ca_sha1.as_deref().unwrap())),
            "{status}"
        );
        let later = status_text(&snapshot, NOW + Duration::days(900), Locale::En);
        assert!(later.contains("expired"), "{later}");

        let trust = trust_text(&snapshot, Locale::Ru);
        assert_eq!(
            trust,
            "Хранилище системы: центра сертификации нет\n\
             Система принимает сертификат сервера для 127.0.0.1: нет"
        );
        for l in [Locale::Ru, Locale::Kk, Locale::En] {
            assert!(!trust_text(&snapshot, l).is_empty());
            assert!(!status_text(&snapshot, NOW, l).is_empty());
            assert!(!mkcert_text(None, l).is_empty());
        }
        assert_eq!(
            store_state(&snapshot.stores[0], Locale::En),
            "the current certification authority is not there"
        );
    }

    /// What the wizard says of the server after a save: the port busy is not "after a
    /// restart" (wss takes it once free), and each outcome reads differently.
    #[test]
    fn issued_texts_tell_what_the_server_does() {
        let dir = tempfile::tempdir().unwrap();
        let s = services(dir.path(), Vec::new(), None);
        let info = s.issue(&own(), NOW).unwrap().info;
        for l in [Locale::Ru, Locale::Kk, Locale::En] {
            let text = |applied| {
                issued_text(
                    &Issued {
                        info: info.clone(),
                        warnings: Vec::new(),
                        applied,
                    },
                    l,
                )
            };
            let texts = [
                text(Applied::Serving),
                text(Applied::WhenPortFree),
                text(Applied::AfterRestart),
                text(Applied::Failed("boom".to_owned())),
            ];
            for (i, t) in texts.iter().enumerate() {
                assert!(!texts[..i].contains(t), "{l:?}: {t}");
            }
        }
        let free = text_ru(&info, Applied::WhenPortFree);
        assert!(free.contains("когда порт освободится"), "{free}");
    }

    fn text_ru(info: &TlsInfo, applied: Applied) -> String {
        issued_text(
            &Issued {
                info: info.clone(),
                warnings: Vec::new(),
                applied,
            },
            Locale::Ru,
        )
    }

    #[test]
    fn nss_databases_are_named_by_browser() {
        let home = Path::new("/home/tester");
        assert_eq!(
            nss_label(home, &home.join(".pki/nssdb")),
            format!("Chrome/Chromium: ~/{}", Path::new(".pki/nssdb").display())
        );
        assert!(
            nss_label(home, &home.join(".mozilla/firefox/abc.default")).starts_with("Firefox: ~/")
        );
        assert!(
            nss_label(home, Path::new("/elsewhere/db")).starts_with("Chrome/Chromium: /elsewhere")
        );
    }

    #[test]
    fn browsers_are_named_from_their_user_agents() {
        let cases = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
                "Firefox 140.0",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "Chrome 141.0.0.0",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.3537.57",
                "Edge 141.0.3537.57",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
                "Safari 18.6",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 YaBrowser/25.8.0.0 Safari/537.36",
                "Yandex 25.8.0.0",
            ),
            ("curl/8.0", "curl/8.0"),
        ];
        for (ua, name) in cases {
            assert_eq!(browser_name(ua), name);
        }
        let reports = SelftestReports::new();
        reports.record(cases[0].0, NOW);
        assert_eq!(
            browser_rows(&reports.latest()),
            [(
                "Firefox 140.0".to_owned(),
                "27.10.2026 10:00 UTC".to_owned()
            )]
        );
    }
}
