//! Which keys of an opened store may sign: the request's `signerParams` against each
//! certificate, as the original's `KeystoreStage` disables entries — the conditions on the
//! certificate, its certification path through `signerParams.chain` and its OCSP status.

use oncl_pki::cert::Certificate;
use oncl_pki::http::HttpTransport;
use oncl_pki::info::CertInfo;
use oncl_pki::ocsp::{self, CertStatus};
use oncl_pki::pkix::{self, CaSet};
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use x509_cert::ext::pkix::BasicConstraints;

/// How long the OCSP checks of a key list may take together: the request timeout and a
/// second more. Keys whose check has not finished by then stay available.
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
    /// No certification path leads from it through the CAs of `chain` to an anchor.
    Chain,
}

/// Whether a key may be picked. When several apply, `Disabled` wins over `Revoked`, which
/// wins over `Expired`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// It may.
    Enabled,
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
    /// The CAs of a non-empty `chain`, in its order.
    Custom(CaSet),
}

impl ChainPolicy {
    /// The CAs to build paths through; `None` for [`ChainPolicy::Empty`].
    fn ca_set(&self) -> Option<Arc<CaSet>> {
        match self {
            ChainPolicy::Default => Some(Arc::clone(&NCA_PRODUCTION)),
            ChainPolicy::Empty => None,
            ChainPolicy::Custom(cas) => Some(Arc::new(cas.clone())),
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
}

impl KeyFilter {
    /// The conditions on the certificate alone: `Disabled` with every failed condition;
    /// else `Expired` if the certificate is not valid at `now` and expired keys are not
    /// allowed; else `Enabled`. Extended key usages include the obsolete-auth clientAuth
    /// ([`CertInfo::effective_ekus`]).
    fn own_availability(&self, info: &CertInfo, now: OffsetDateTime) -> Availability {
        let mut reasons = Vec::new();
        if !self
            .ext_key_usages
            .is_subset(&info.effective_ekus(&self.ext_key_usages))
        {
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
///   ([`ocsp::ocsp_url`]), all at once on a thread each, through `http`. Only a `revoked`
///   answer counts; failures, `unknown` and checks still running after [`OCSP_DEADLINE`]
///   leave the key as it is and are logged as warnings.
///
/// Checks still running at the deadline are abandoned, not waited for: their threads end
/// with the transport's own timeout.
pub fn availabilities(
    filter: &KeyFilter,
    keys: &[(Certificate, CertInfo)],
    http: &Arc<dyn HttpTransport>,
    now: OffsetDateTime,
) -> Vec<Availability> {
    let deadline = Instant::now() + OCSP_DEADLINE;
    let cas = filter.chain.ca_set();
    let (sender, receiver) = mpsc::channel();
    let mut pending = 0_usize;
    let mut result = Vec::with_capacity(keys.len());
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
                            now,
                        };
                        if check.spawn(sender.clone()) {
                            pending += 1;
                        }
                    }
                }
            }
        }
        result.push(availability);
    }
    drop(sender);
    while pending > 0 {
        let Ok((index, revoked)) =
            receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        else {
            break;
        };
        pending -= 1;
        if let Some(time) = revoked {
            result[index] = Availability::Revoked { time };
        }
    }
    if pending > 0 {
        tracing::warn!(
            pending,
            "OCSP checks did not finish within {} s: those keys stay available",
            OCSP_DEADLINE.as_secs()
        );
    }
    result
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
        match ocsp::check(
            &self.cert,
            &self.issuer,
            &self.cas,
            self.http.as_ref(),
            self.now,
            ocsp::TIMEOUT,
        ) {
            Ok(CertStatus::Revoked { time, reason }) => {
                tracing::info!(%serial, %time, ?reason, "OCSP: the certificate is revoked");
                Some(time)
            }
            Ok(CertStatus::Good) => None,
            Ok(CertStatus::Unknown) => {
                tracing::warn!(%serial, "OCSP: the responder does not know the certificate; the key stays available");
                None
            }
            Err(e) => {
                tracing::warn!(%serial, error = %e, "OCSP check failed: the key stays available");
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
