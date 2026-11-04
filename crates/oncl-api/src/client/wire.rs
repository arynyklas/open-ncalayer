//! Owned, deserializable view of the terminal records the service writes.
//!
//! The server serializes borrowed `&'static str` labels (`dto::OperationResult`), which
//! cannot be deserialized. This module is the client's mirror of exactly that wire shape;
//! `tests/client.rs` parses every published OpenAPI example and every real response with it,
//! so a field added to the service DTOs cannot silently drift away from the client.
//! Unknown *fields* are ignored (a newer service may add facts); an unknown `kind`/`type`,
//! status or missing required field is a decode error, never a guessed success.
use crate::{
    dto::{
        BatchItemOutcome, BatchStatus, BatchStopKind, ExtendKind, FinalStatus, HashAlgorithm,
        JwsFormat, SignKind, VerifyProfile,
    },
    error::{ApiError, AppliedState, ErrorCode},
};
use serde::Deserialize;

/// The mandatory terminal record (JSON body or multipart part `final`).
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FinalRecord {
    /// `/v1/operations`
    Final {
        operation_id: u64,
        status: FinalStatus,
        results: Vec<ItemResult>,
        #[serde(default)]
        error: Option<ApiError>,
    },
    /// `/v1/batch`
    BatchFinal {
        operation_id: u64,
        status: BatchStatus,
        attempted: usize,
        completed: usize,
        total: usize,
        #[serde(default)]
        stop: Option<BatchStop>,
        items: Vec<BatchItem>,
        #[serde(default)]
        error: Option<ApiError>,
    },
}

impl FinalRecord {
    pub fn operation_id(&self) -> u64 {
        match self {
            Self::Final { operation_id, .. } | Self::BatchFinal { operation_id, .. } => {
                *operation_id
            }
        }
    }
    /// Artifact Content-IDs the record names, in record order.
    pub fn artifact_ids(&self) -> Vec<&str> {
        match self {
            Self::Final { results, .. } => results
                .iter()
                .filter_map(|item| item.result.artifact())
                .collect(),
            Self::BatchFinal { items, .. } => items
                .iter()
                .filter_map(|item| item.result.as_ref().and_then(ResultRecord::artifact))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ItemResult {
    pub item_id: String,
    pub applied: AppliedState,
    pub result: ResultRecord,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BatchStop {
    pub kind: BatchStopKind,
    pub code: ErrorCode,
    #[serde(default)]
    pub item_index: Option<usize>,
    pub applied: AppliedState,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SourceIdentity {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BatchItem {
    pub item_id: String,
    pub index: usize,
    pub outcome: BatchItemOutcome,
    pub applied: AppliedState,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub error: Option<ApiError>,
    #[serde(default)]
    pub result: Option<ResultRecord>,
    pub sources: Vec<SourceIdentity>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignerChecks {
    pub signature: String,
    pub chain: String,
    pub validity: String,
    pub revocation: String,
    pub timestamp: String,
    pub key_usage: String,
    pub time_basis: String,
    pub time_basis_unix: i64,
    #[serde(default)]
    pub claimed_signing_time_unix: Option<i64>,
    #[serde(default)]
    pub ades_level: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct JwsSignerFacts {
    pub algorithm: String,
    pub crypto: String,
    pub verdict: String,
    pub trust: SignerChecks,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InspectedEntry {
    pub alias: Option<String>,
    pub subject_cn: Option<String>,
    pub serial_hex: Option<String>,
    pub sha256: Option<String>,
    pub signature_algorithm_oid: Option<String>,
    pub public_key_algorithm_oid: Option<String>,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InspectedCms {
    pub detached: bool,
    pub content_len: u64,
    pub signer_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TimestampFacts {
    pub verdict: String,
    pub gen_time_unix: i64,
    pub checked_at_unix: i64,
    pub policy: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    pub imprint: String,
    pub signature: String,
    pub eku: String,
    pub chain: String,
    pub validity: String,
    pub revocation: String,
    pub expectations: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResultRecord {
    Hash {
        algorithm: HashAlgorithm,
        digest: String,
        bytes_in: u64,
    },
    Verification {
        profile: VerifyProfile,
        verdict: String,
        policy: String,
        checked_at_unix: i64,
        signers: Vec<SignerChecks>,
    },
    Extraction {
        #[serde(default)]
        artifact: Option<String>,
        bytes_written: u64,
    },
    Signing {
        profile: SignKind,
        #[serde(default)]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        signers: Vec<AppliedState>,
    },
    Jws {
        serialization: JwsFormat,
        #[serde(default)]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        signers: Vec<AppliedState>,
    },
    JwsVerification {
        verdict: String,
        policy: String,
        checked_at_unix: i64,
        signers: Vec<JwsSignerFacts>,
    },
    JwtDecoded {
        verified: bool,
        issuer: Option<String>,
        audience: Vec<String>,
        expiration_unix: Option<i64>,
        claims: String,
    },
    JwtVerification {
        verdict: String,
        signature_verdict: String,
        claims_verdict: String,
        claim_failures: Vec<String>,
        checked_at_unix: i64,
        signers: Vec<JwsSignerFacts>,
        claims: String,
    },
    Plugin {
        response: String,
        applied: AppliedState,
    },
    Inspection {
        target: String,
        bytes_in: u64,
        #[serde(default)]
        integrity: Option<String>,
        entries: Vec<InspectedEntry>,
        #[serde(default)]
        cms: Option<InspectedCms>,
    },
    Stamping {
        #[serde(default)]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        timestamp: TimestampFacts,
    },
    StampVerification {
        bytes_in: u64,
        timestamp: TimestampFacts,
    },
    Extension {
        profile: ExtendKind,
        #[serde(default)]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        verdicts: Vec<String>,
    },
}

impl ResultRecord {
    /// Content-ID of the finished output this result names, if any.
    pub fn artifact(&self) -> Option<&str> {
        match self {
            Self::Extraction { artifact, .. }
            | Self::Signing { artifact, .. }
            | Self::Jws { artifact, .. }
            | Self::Stamping { artifact, .. }
            | Self::Extension { artifact, .. } => artifact.as_deref(),
            _ => None,
        }
    }
    /// Verdict of a verification-type result.
    pub fn verdict(&self) -> Option<&str> {
        match self {
            Self::Verification { verdict, .. }
            | Self::JwsVerification { verdict, .. }
            | Self::JwtVerification { verdict, .. } => Some(verdict),
            Self::StampVerification { timestamp, .. } => Some(&timestamp.verdict),
            _ => None,
        }
    }
}

impl ResultRecord {
    /// The exact byte length of the artifact this result states, where the contract has one:
    /// extraction `bytes_written` and the timestamp token length (`bytes_out` of a stamp is
    /// documented as the token length). Signing, JWS and extension `bytes_out` are resource
    /// scope counters, not artifact sizes (measured: they differ from the artifact), so they
    /// are never compared.
    pub fn artifact_len(&self) -> Option<u64> {
        match self {
            Self::Extraction { bytes_written, .. } => Some(*bytes_written),
            Self::Stamping { bytes_out, .. } => Some(*bytes_out),
            _ => None,
        }
    }
}

impl FinalRecord {
    /// `(Content-ID, stated exact length)` of every artifact the record names.
    pub fn artifact_expectations(&self) -> Vec<(&str, Option<u64>)> {
        fn of(result: &ResultRecord) -> Option<(&str, Option<u64>)> {
            result.artifact().map(|id| (id, result.artifact_len()))
        }
        match self {
            Self::Final { results, .. } => results.iter().filter_map(|r| of(&r.result)).collect(),
            Self::BatchFinal { items, .. } => items
                .iter()
                .filter_map(|i| i.result.as_ref().and_then(|r| of(r)))
                .collect(),
        }
    }
}
