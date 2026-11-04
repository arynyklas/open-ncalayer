//! JSON reports of remote results. Field names and values follow the local reports
//! (`crate::reports`) wherever the wire carries the fact; a fact the wire does not carry
//! (for example the PDF/XML structure details or the top-level AdES level of a
//! verification) is omitted, never invented.
use oncl_api::client::wire;
use serde::Serialize;

pub fn applied(state: oncl_api::error::AppliedState) -> &'static str {
    match state {
        oncl_api::error::AppliedState::NotApplied => "NotApplied",
        oncl_api::error::AppliedState::Applied => "Applied",
        oncl_api::error::AppliedState::Unknown => "Unknown",
    }
}

/// `(label, exit)` of a verdict the service reported; anything else is not a verdict.
pub fn verdict(text: &str) -> Option<(&'static str, i32)> {
    match text {
        "Valid" => Some(("Valid", 0)),
        "Invalid" => Some(("Invalid", 2)),
        "Indeterminate" => Some(("Indeterminate", 3)),
        _ => None,
    }
}

/// The AdES level label of the wire as the local report prints it (`Debug` of the level).
fn level(label: &str) -> String {
    match label {
        "LT" => "Lt".into(),
        "LTA" => "Lta".into(),
        other => other.into(),
    }
}

#[derive(Serialize)]
pub struct Hash<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub digest: &'a str,
    pub bytes_in: u64,
}

#[derive(Serialize)]
pub struct Written<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub profile: &'a str,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub signer_count: usize,
}

#[derive(Serialize)]
pub struct Extracted {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub bytes_out: u64,
    pub verified: bool,
}

#[derive(Serialize)]
pub struct DecodedJwt {
    pub operation_id: u64,
    pub code: &'static str,
    pub verified: bool,
    pub bytes_out: usize,
}

#[derive(Serialize)]
pub struct Signer {
    pub signature: String,
    pub chain: String,
    pub validity: String,
    pub revocation: String,
    pub timestamp: String,
    pub key_usage: String,
    /// The variant of the basis (the wire does not print the instant in this field).
    pub time_basis: String,
    pub time_basis_unix: i64,
    pub claimed_signing_time: Option<i64>,
    pub ades_level: Option<String>,
    /// The service's diagnostic strings, printed as the local report prints its list.
    pub reasons: String,
}
impl From<&wire::SignerChecks> for Signer {
    fn from(s: &wire::SignerChecks) -> Self {
        Self {
            signature: s.signature.clone(),
            chain: s.chain.clone(),
            validity: s.validity.clone(),
            revocation: s.revocation.clone(),
            timestamp: s.timestamp.clone(),
            key_usage: s.key_usage.clone(),
            time_basis: s.time_basis.clone(),
            time_basis_unix: s.time_basis_unix,
            claimed_signing_time: s.claimed_signing_time_unix,
            ades_level: s.ades_level.as_deref().map(level),
            reasons: format!("[{}]", s.reasons.join(", ")),
        }
    }
}

#[derive(Serialize)]
pub struct Verification<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub verdict: &'a str,
    pub policy: &'a str,
    pub checked_at: i64,
    pub signers: Vec<Signer>,
}

#[derive(Serialize)]
pub struct JwsSigner {
    pub algorithm: String,
    pub crypto: String,
    pub trust: Signer,
}
impl From<&wire::JwsSignerFacts> for JwsSigner {
    fn from(s: &wire::JwsSignerFacts) -> Self {
        Self {
            algorithm: s.algorithm.clone(),
            crypto: s.crypto.clone(),
            trust: Signer::from(&s.trust),
        }
    }
}

#[derive(Serialize)]
pub struct JwsVerification<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub verdict: &'a str,
    pub policy: &'a str,
    pub checked_at: i64,
    pub signers: Vec<JwsSigner>,
}

#[derive(Serialize)]
pub struct JwtClaims<'a> {
    pub verdict: &'a str,
    pub checked_at: i64,
    pub failures: &'a [String],
}
#[derive(Serialize)]
pub struct JwtJws<'a> {
    pub verdict: &'a str,
    pub checked_at: i64,
    pub signers: Vec<JwsSigner>,
}
#[derive(Serialize)]
pub struct JwtVerification<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub verdict: &'a str,
    pub jws: JwtJws<'a>,
    pub claims: JwtClaims<'a>,
}

#[derive(Serialize)]
pub struct Entry<'a> {
    pub alias: Option<&'a str>,
    pub certificate_sha256: Option<&'a str>,
    pub subject_cn: Option<&'a str>,
    pub serial_hex: Option<&'a str>,
    pub signature_algorithm_oid: Option<&'a str>,
    pub public_key_algorithm_oid: Option<&'a str>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}
#[derive(Serialize)]
pub struct Cms {
    pub detached: bool,
    pub content_len: u64,
    pub signer_count: usize,
}
#[derive(Serialize)]
pub struct Inspection<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub kind: &'a str,
    pub container_integrity: Option<&'a str>,
    pub entries: Vec<Entry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cms: Option<Cms>,
}
impl<'a> Inspection<'a> {
    pub fn new(
        operation_id: u64,
        applied_state: &'static str,
        target: &'a str,
        integrity: Option<&'a str>,
        entries: &'a [wire::InspectedEntry],
        cms: Option<&wire::InspectedCms>,
    ) -> Self {
        Self {
            operation_id,
            code: "Completed",
            applied: applied_state,
            kind: target,
            container_integrity: integrity,
            entries: entries
                .iter()
                .map(|e| Entry {
                    alias: e.alias.as_deref(),
                    certificate_sha256: e.sha256.as_deref(),
                    subject_cn: e.subject_cn.as_deref(),
                    serial_hex: e.serial_hex.as_deref(),
                    signature_algorithm_oid: e.signature_algorithm_oid.as_deref(),
                    public_key_algorithm_oid: e.public_key_algorithm_oid.as_deref(),
                    not_before: e.not_before_unix,
                    not_after: e.not_after_unix,
                })
                .collect(),
            cms: cms.map(|c| Cms {
                detached: c.detached,
                content_len: c.content_len,
                signer_count: c.signer_count,
            }),
        }
    }
}

#[derive(Serialize)]
pub struct TimestampFacts<'a> {
    pub gen_time: i64,
    pub checked_at: i64,
    pub algorithm: Option<&'a str>,
    pub imprint: &'a str,
    pub signature: &'a str,
    pub eku: &'a str,
    pub chain: &'a str,
    pub validity: &'a str,
    pub revocation: &'a str,
    pub expectations: &'a str,
}
#[derive(Serialize)]
pub struct Timestamp<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub verdict: &'a str,
    pub policy: &'a str,
    pub facts: TimestampFacts<'a>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
impl<'a> Timestamp<'a> {
    pub fn new(
        operation_id: u64,
        facts: &'a wire::TimestampFacts,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Self {
        Self {
            operation_id,
            code: "Completed",
            applied: "NotApplied",
            verdict: &facts.verdict,
            policy: &facts.policy,
            facts: TimestampFacts {
                gen_time: facts.gen_time_unix,
                checked_at: facts.checked_at_unix,
                algorithm: facts.algorithm.as_deref(),
                imprint: &facts.imprint,
                signature: &facts.signature,
                eku: &facts.eku,
                chain: &facts.chain,
                validity: &facts.validity,
                revocation: &facts.revocation,
                expectations: &facts.expectations,
            },
            bytes_in,
            bytes_out,
        }
    }
}
