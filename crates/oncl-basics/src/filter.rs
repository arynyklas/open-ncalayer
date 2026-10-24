//! Which keys of an opened store may sign: the request's `signerParams` against each
//! certificate, as the original's `KeystoreStage` disables entries.

use oncl_pki::info::CertInfo;
use std::collections::BTreeSet;
use time::OffsetDateTime;

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
}

/// Whether a key may be picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// It may.
    Enabled,
    /// The certificate is outside its validity period.
    Expired,
    /// It fails these conditions, in [`DisabledReason`] order.
    Disabled(Vec<DisabledReason>),
}

/// Conditions of `signerParams` (and `allowExpired`).
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
}

impl KeyFilter {
    /// `Disabled` with every failed condition; else `Expired` if the certificate is not
    /// valid at `now` and expired keys are not allowed; else `Enabled`. Extended key usages
    /// include the obsolete-auth clientAuth ([`CertInfo::effective_ekus`]).
    pub fn availability(&self, info: &CertInfo, now: OffsetDateTime) -> Availability {
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

/// An empty requirement matches anything; otherwise the value must be present and equal.
fn matches_required(required: &str, actual: Option<&str>) -> bool {
    required.is_empty() || actual == Some(required)
}
