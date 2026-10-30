//! Which keys of an opened store may sign: the request's `signerParams` against each
//! certificate, as the original's `KeystoreStage` disables entries — the conditions on the
//! certificate, its certification path through `signerParams.chain` and its OCSP status.

use crate::live::LiveAvailability;
use crate::ocsp_cache::OcspCache;
use oncl_pki::cert::Certificate;
use oncl_pki::http::HttpTransport;
use oncl_pki::info::{CertInfo, KeyUsageBits, KncaCertType, kcert_types};
use oncl_pki::key::SigAlg;
use oncl_pki::ocsp::{self, CertStatus};
use oncl_pki::pkix::{self, CaSet};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use x509_cert::ext::pkix::BasicConstraints;

/// How long the OCSP checks of a key list may take together: the request timeout and a
/// second more. Keys whose check has not finished by then become available.
pub const OCSP_DEADLINE: Duration = ocsp::TIMEOUT.saturating_add(Duration::from_secs(1));

/// The embedded NCA production CAs, shared by every request without `chain`.
static NCA_PRODUCTION: LazyLock<Arc<CaSet>> = LazyLock::new(|| Arc::new(CaSet::nca_production()));

/// A `signerParams` condition the certificate does not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledReason {
    /// It lacks a requested extended key usage.
    ExtKeyUsage,
    /// Its IIN differs from `iin`.
    Iin,
    /// Its BIN differs from `bin`.
    Bin,
    /// Its serial number differs from `serialNumber`.
    SerialNumber,
    /// It has none of the extended key usages of which one is required
    /// ([`FilterMore::any_ext_key_usages`]).
    AnyExtKeyUsage,
    /// It has an extended key usage that is excluded ([`FilterMore::exclude_ext_key_usages`]).
    ExcludedExtKeyUsage,
    /// It is of none of the required Kalkan types ([`FilterMore::knca_types`]).
    KncaType,
    /// Its BIN, or without one its IIN, differs from [`FilterMore::tin`].
    Tin,
    /// It lacks a required key usage bit ([`FilterMore::key_usage`]).
    KeyUsage,
    /// No certification path leads from it through the CAs of `chain` to an anchor.
    Chain,
}

/// Whether a key may be picked. When several apply, `Disabled` wins over `Revoked`, which
/// wins over `Expired`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// It may.
    Enabled,
    /// It may once its OCSP check, still running, does not find it revoked: not yet.
    Pending,
    /// The certificate is outside its validity period.
    Expired,
    /// Its OCSP responder reports the certificate revoked at `time`.
    Revoked {
        /// Revocation time.
        time: OffsetDateTime,
    },
    /// It fails these conditions, in [`DisabledReason`] order.
    Disabled(Vec<DisabledReason>),
}

/// The CA certificates of `signerParams.chain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainPolicy {
    /// No `chain` (or `null`): the embedded NCA production CAs.
    Default,
    /// `chain: []`: neither path building nor OCSP.
    Empty,
    /// The CAs of a non-empty `chain`, in its order (shared with the OCSP checks).
    Custom(Arc<CaSet>),
}

impl ChainPolicy {
    /// The CAs to build paths through; `None` for [`ChainPolicy::Empty`].
    fn ca_set(&self) -> Option<Arc<CaSet>> {
        match self {
            ChainPolicy::Default => Some(Arc::clone(&NCA_PRODUCTION)),
            ChainPolicy::Empty => None,
            ChainPolicy::Custom(cas) => Some(Arc::clone(cas)),
        }
    }
}

/// Conditions of `signerParams` and `signingParams`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFilter {
    /// Extended key usages the certificate must all have.
    pub ext_key_usages: BTreeSet<String>,
    /// Required IIN; empty: any.
    pub iin: String,
    /// Required BIN; empty: any.
    pub bin: String,
    /// Required serial number in hex, any case; empty: any.
    pub serial_number: String,
    /// Whether a certificate outside its validity period may sign.
    pub allow_expired: bool,
    /// CAs the certificate must chain through.
    pub chain: ChainPolicy,
    /// Whether to skip the OCSP check (`signingParams.allowRevoked`).
    pub allow_revoked: bool,
    /// The conditions plugins add.
    pub more: FilterMore,
}

/// Conditions of plugins beyond those of `signerParams`; the default adds none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterMore {
    /// Extended key usages of which the certificate must have at least one; empty: no
    /// condition.
    pub any_ext_key_usages: BTreeSet<String>,
    /// Extended key usages the certificate must not have.
    pub exclude_ext_key_usages: BTreeSet<String>,
    /// Kalkan types of which the certificate must be at least one; empty: no condition.
    pub knca_types: BTreeSet<KncaCertType>,
    /// The required BIN (the first OU without `BIN`), or for a certificate without one its
    /// IIN (SERIALNUMBER without `IIN`); empty: any.
    pub tin: String,
    /// Key usage bits the certificate must all have.
    pub key_usage: KeyUsageBits,
    /// A requested clientAuth also accepts every GOST 2015-512 certificate and sha256RSA
    /// certificates with keyEncipherment (the obsolete authentication keys some plugins
    /// accept).
    pub obsolete_auth: bool,
}

impl FilterMore {
    /// The conditions `info` fails, in [`DisabledReason`] order.
    fn failed(&self, info: &CertInfo, ekus: &BTreeSet<String>, out: &mut Vec<DisabledReason>) {
        if !self.any_ext_key_usages.is_empty() && self.any_ext_key_usages.is_disjoint(ekus) {
            out.push(DisabledReason::AnyExtKeyUsage);
        }
        if !self
            .exclude_ext_key_usages
            .is_disjoint(&info.ext_key_usages)
        {
            out.push(DisabledReason::ExcludedExtKeyUsage);
        }
        if !self.knca_types.is_empty() && self.knca_types.is_disjoint(&kcert_types(info)) {
            out.push(DisabledReason::KncaType);
        }
        if !self.tin.is_empty() {
            let tin = info
                .bin
                .as_deref()
                .filter(|bin| !bin.is_empty())
                .or(info.iin.as_deref());
            if tin != Some(self.tin.as_str()) {
                out.push(DisabledReason::Tin);
            }
        }
        let (want, has) = (&self.key_usage, &info.key_usage);
        let lacks = (want.digital_signature && !has.digital_signature)
            || (want.non_repudiation && !has.non_repudiation)
            || (want.key_encipherment && !has.key_encipherment)
            || (want.key_agreement && !has.key_agreement);
        if lacks {
            out.push(DisabledReason::KeyUsage);
        }
    }

    /// `ekus` with clientAuth added under the obsolete-auth rule, if it applies.
    fn with_obsolete_auth(
        &self,
        info: &CertInfo,
        requested: &BTreeSet<String>,
        mut ekus: BTreeSet<String>,
    ) -> BTreeSet<String> {
        let client_auth = oncl_pki::oid::CLIENT_AUTH.to_string();
        if self.obsolete_auth && requested.contains(&client_auth) {
            let obsolete = match info.signing_alg() {
                Ok(SigAlg::Gost2015_512) => true,
                Ok(SigAlg::RsaSha256) => info.key_usage.key_encipherment,
                Ok(SigAlg::Gost2004 | SigAlg::RsaSha1) | Err(_) => false,
            };
            if obsolete {
                ekus.insert(client_auth);
            }
        }
        ekus
    }
}

impl KeyFilter {
    /// The conditions on the certificate alone: `Disabled` with every failed condition;
    /// else `Expired` if the certificate is not valid at `now` and expired keys are not
    /// allowed; else `Enabled`. Extended key usages include the obsolete-auth clientAuth
    /// ([`CertInfo::effective_ekus`]).
    fn own_availability(&self, info: &CertInfo, now: OffsetDateTime) -> Availability {
        let mut reasons = Vec::new();
        let ekus = self.more.with_obsolete_auth(
            info,
            &self.ext_key_usages,
            info.effective_ekus(&self.ext_key_usages),
        );
        if !self.ext_key_usages.is_subset(&ekus) {
            reasons.push(DisabledReason::ExtKeyUsage);
        }
        if !matches_required(&self.iin, info.iin.as_deref()) {
            reasons.push(DisabledReason::Iin);
        }
        if !matches_required(&self.bin, info.bin.as_deref()) {
            reasons.push(DisabledReason::Bin);
        }
        if !self.serial_number.is_empty()
            && !self.serial_number.eq_ignore_ascii_case(&info.serial_hex)
        {
            reasons.push(DisabledReason::SerialNumber);
        }
        self.more.failed(info, &ekus, &mut reasons);
        if !reasons.is_empty() {
            Availability::Disabled(reasons)
        } else if !self.allow_expired && !info.is_within_validity(now) {
            Availability::Expired
        } else {
            Availability::Enabled
        }
    }
}

/// The availability of each key of `keys` (its certificate and that certificate's details),
/// in order, at `now`:
///
/// - the conditions on the certificate itself;
/// - unless `chain` is empty, a certification path through its CAs, validated at `now` or,
///   for an expired certificate, at its notAfter ([`pkix::validation_time`]); without one
///   the key is disabled for [`DisabledReason::Chain`];
/// - unless `chain` is empty or revoked keys are allowed, the OCSP status of every key not
///   disabled whose certificate is an end entity with a responder URL
///   ([`ocsp::ocsp_url`]), all at once on a thread each, through `http` and `cache`. Only
///   a `revoked` answer counts; failures, `unknown` and checks still running after
///   [`OCSP_DEADLINE`] leave the key as it is and are logged.
///
/// Returns once the paths are built: the OCSP checks go on in the background. Until its
/// check ends, a key that would be enabled is [`Availability::Pending`]; an expired one
/// stays expired (and may turn revoked). The result settles when every check has ended,
/// at the latest at the deadline, which counts from this call. Checks still running then
/// are abandoned, not waited for: their threads end with the transport's own timeout.
pub fn availabilities(
    filter: &KeyFilter,
    keys: &[(Certificate, CertInfo)],
    http: &Arc<dyn HttpTransport>,
    cache: &Arc<OcspCache>,
    now: OffsetDateTime,
) -> LiveAvailability {
    let deadline = Instant::now() + OCSP_DEADLINE;
    let cas = filter.chain.ca_set();
    let (sender, receiver) = mpsc::channel();
    // The keys being checked, with their availability unless revoked.
    let mut checking = BTreeMap::new();
    let mut initial = Vec::with_capacity(keys.len());
    for (index, (cert, info)) in keys.iter().enumerate() {
        let mut availability = filter.own_availability(info, now);
        if let Some(cas) = &cas {
            match pkix::build_path(cert, cas, pkix::validation_time(cert, now)) {
                Err(e) => {
                    tracing::info!(serial = %info.serial_hex, error = %e, "no certification path: the key is disabled");
                    availability = with_reason(availability, DisabledReason::Chain);
                }
                Ok(path) => {
                    let checked = !filter.allow_revoked
                        && !matches!(availability, Availability::Disabled(_))
                        && is_end_entity(cert)
                        && ocsp::ocsp_url(cert).is_some();
                    if checked && let Some(issuer) = path.get(1) {
                        let check = OcspCheck {
                            index,
                            serial: info.serial_hex.clone(),
                            cert: cert.clone(),
                            issuer: issuer.clone(),
                            cas: Arc::clone(cas),
                            http: Arc::clone(http),
                            cache: Arc::clone(cache),
                            now,
                        };
                        if check.spawn(sender.clone()) {
                            checking.insert(index, availability.clone());
                            if availability == Availability::Enabled {
                                availability = Availability::Pending;
                            }
                        }
                    }
                }
            }
        }
        initial.push(availability);
    }
    drop(sender);
    if checking.is_empty() {
        return LiveAvailability::settled(initial);
    }
    let live = LiveAvailability::changing(initial);
    let results = Results {
        live: live.clone(),
        receiver,
        checking,
        deadline,
    };
    // Without a thread to collect them, the dropped `results` settle at once.
    let spawned = thread::Builder::new()
        .name("ocsp-results".to_owned())
        .spawn(move || results.collect());
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "cannot wait for the OCSP checks: the keys stay available");
    }
    live
}

/// Where the OCSP checks of a key list report, and what becomes of their keys. Dropped, it
/// leaves the keys still being checked as they are unless revoked, and settles.
struct Results {
    live: LiveAvailability,
    receiver: mpsc::Receiver<(usize, Option<OffsetDateTime>)>,
    /// The keys still being checked, with their availability unless revoked.
    checking: BTreeMap<usize, Availability>,
    deadline: Instant,
}

impl Results {
    /// Sets each key's availability as its check ends, until the deadline.
    fn collect(mut self) {
        while !self.checking.is_empty() {
            let Ok((index, revoked)) = self
                .receiver
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            else {
                break;
            };
            if let Some(unrevoked) = self.checking.remove(&index) {
                let availability = match revoked {
                    Some(time) => Availability::Revoked { time },
                    None => unrevoked,
                };
                self.live.set(index, availability);
            }
        }
    }
}

impl Drop for Results {
    fn drop(&mut self) {
        let unchecked = std::mem::take(&mut self.checking);
        if !unchecked.is_empty() {
            let pending = unchecked.len();
            if Instant::now() >= self.deadline {
                tracing::warn!(
                    pending,
                    "OCSP checks did not finish within {} s: those keys stay available",
                    OCSP_DEADLINE.as_secs()
                );
            } else {
                // The collector could not start, or a check thread ended without a result.
                tracing::warn!(
                    pending,
                    "OCSP checks ended without a result: those keys stay available"
                );
            }
        }
        for (index, unrevoked) in unchecked {
            self.live.set(index, unrevoked);
        }
        self.live.settle();
    }
}

/// The OCSP check of the key at `index`.
struct OcspCheck {
    index: usize,
    /// Serial number in hex, for the log.
    serial: String,
    cert: Certificate,
    issuer: Certificate,
    cas: Arc<CaSet>,
    http: Arc<dyn HttpTransport>,
    cache: Arc<OcspCache>,
    now: OffsetDateTime,
}

impl OcspCheck {
    /// Runs the check on a thread of its own, which sends `(index, revocation time if
    /// revoked)` to `sender`. `false` if the thread could not start.
    fn spawn(self, sender: mpsc::Sender<(usize, Option<OffsetDateTime>)>) -> bool {
        let serial = self.serial.clone();
        let spawned = thread::Builder::new()
            .name("ocsp".to_owned())
            .spawn(move || {
                let revoked = self.run();
                // The receiver is gone once the deadline has passed.
                let _ = sender.send((self.index, revoked));
            });
        match spawned {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(%serial, error = %e, "cannot start the OCSP check: the key stays available");
                false
            }
        }
    }

    /// The revocation time if the responder reports the certificate revoked.
    fn run(&self) -> Option<OffsetDateTime> {
        let serial = &self.serial;
        let status = self.cache.status(
            serial,
            &self.cert,
            &self.issuer,
            &self.cas,
            self.http.as_ref(),
            self.now,
        );
        match status? {
            CertStatus::Revoked { time, reason } => {
                tracing::info!(%serial, %time, ?reason, "OCSP: the certificate is revoked");
                Some(time)
            }
            CertStatus::Good => None,
            CertStatus::Unknown => {
                tracing::warn!(%serial, "OCSP: the responder does not know the certificate; the key stays available");
                None
            }
        }
    }
}

/// `availability` with `reason` added: disabled for it alone unless already disabled.
fn with_reason(availability: Availability, reason: DisabledReason) -> Availability {
    match availability {
        Availability::Disabled(mut reasons) => {
            reasons.push(reason);
            Availability::Disabled(reasons)
        }
        _ => Availability::Disabled(vec![reason]),
    }
}

/// Whether `cert` is an end entity: no basicConstraints, or one without cA.
fn is_end_entity(cert: &Certificate) -> bool {
    !matches!(
        cert.tbs_certificate().get_extension::<BasicConstraints>(),
        Ok(Some((_, bc))) if bc.ca
    )
}

/// An empty requirement matches anything; otherwise the value must be present and equal.
fn matches_required(required: &str, actual: Option<&str>) -> bool {
    required.is_empty() || actual == Some(required)
}
