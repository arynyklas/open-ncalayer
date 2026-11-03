use serde::{Deserialize, Serialize};

/// Raw request bytes are streamed, not deserialized into a document allocation.
/// Algorithm and operation are fixed by this implemented route (SHA-256/hash).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashResponse {
    pub operation_id: u64,
    pub algorithm: String,
    pub digest: String,
    pub bytes_in: u64,
}

/// Authority-free wire metadata. The trusted host resolves every operation and
/// part role before consuming any document or secret field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationMetadata {
    pub items: Vec<ItemMetadata>,
    pub parts: Vec<PartMetadata>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemMetadata {
    pub id: String,
    pub operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Hash {
        algorithm: HashAlgorithm,
        input: String,
    },
    Verify {
        profile: VerifyProfile,
        input: String,
        #[serde(default)]
        detached: Option<String>,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Gost34311,
    Streebog256,
    Streebog512,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyProfile {
    Cms,
    CadesB,
    CadesT,
    CadesLt,
    CadesLta,
    Pdf,
    PadesB,
    PadesT,
    PadesLt,
    PadesLta,
    Xml,
    XmlKalkan,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartMetadata {
    pub name: String,
    pub item_id: String,
    pub role: PartRole,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartRole {
    Document,
    Secret,
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseEvent {
    Final {
        operation_id: u64,
        status: FinalStatus,
        results: Vec<ItemResult>,
    },
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalStatus {
    Completed,
}
#[derive(Serialize)]
pub struct ItemResult {
    pub item_id: String,
    pub applied: crate::error::AppliedState,
    pub result: OperationResult,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationResult {
    Hash {
        algorithm: HashAlgorithm,
        digest: String,
        bytes_in: u64,
    },
    Verification {
        profile: VerifyProfile,
        verdict: &'static str,
        policy: &'static str,
        checked_at_unix: i64,
        signers: Vec<SignerChecks>,
    },
}

#[derive(Serialize)]
pub struct SignerChecks {
    pub signature: &'static str,
    pub chain: &'static str,
    pub validity: &'static str,
    pub revocation: &'static str,
    pub timestamp: &'static str,
    pub key_usage: &'static str,
    pub time_basis: &'static str,
    pub time_basis_unix: i64,
    pub claimed_signing_time_unix: Option<i64>,
    pub ades_level: Option<&'static str>,
    pub reasons: Vec<String>,
}
