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
        /// `wsse` only.
        #[serde(default)]
        soap: Option<SoapKind>,
    },
    Extract {
        input: String,
    },
    /// Private signing. Keys are operator-named or inline secret-role containers.
    Sign {
        profile: SignKind,
        input: String,
        /// Detached content for `mode = add` over an existing detached container.
        #[serde(default)]
        detached: Option<String>,
        #[serde(default)]
        mode: SignWriteMode,
        /// Attached (encapsulated) CMS/CAdES content when creating.
        #[serde(default)]
        attached: bool,
        /// XML/XAdES only: unique ID of the element to sign.
        #[serde(default)]
        target: Option<String>,
        /// XML/XAdES only: unique ID of the element that receives the signature.
        #[serde(default)]
        parent: Option<String>,
        #[serde(default)]
        signature_id: Option<String>,
        /// `wsse` only.
        #[serde(default)]
        soap: Option<SoapKind>,
        /// `wsse` only: Body ID used when the Body has none.
        #[serde(default)]
        body_id: Option<String>,
        /// `xml_legacy`/`xades_legacy_*` only: XPath of the element to sign.
        #[serde(default)]
        element: Option<String>,
        /// `xml_legacy`/`xades_legacy_*` only: XPath of the element receiving the signature.
        #[serde(default)]
        xpath_parent: Option<String>,
        /// Legacy profiles only: SignatureMethod URI (known and key-compatible).
        #[serde(default)]
        signature_method: Option<String>,
        /// Legacy profiles only: DigestMethod URI.
        #[serde(default)]
        digest_method: Option<String>,
        /// Public evidence for LT/LTA levels: acquired by the caller, never trust anchors.
        #[serde(default)]
        evidence: Vec<EvidenceRef>,
        keys: Vec<KeyRef>,
    },
    /// Keyless public-evidence extension (never opens a private key).
    Extend {
        profile: ExtendKind,
        input: String,
        #[serde(default)]
        detached: Option<String>,
        #[serde(default)]
        evidence: Vec<EvidenceRef>,
    },
    /// Create a JWS over the input payload bytes.
    JwsSign {
        serialization: JwsFormat,
        #[serde(default)]
        detached: bool,
        input: String,
        keys: Vec<KeyRef>,
    },
    /// Add signers to an existing JWS after verifying every existing signature.
    JwsAdd {
        serialization: JwsFormat,
        input: String,
        #[serde(default)]
        detached: Option<String>,
        #[serde(default)]
        certificate: Option<String>,
        keys: Vec<KeyRef>,
    },
    JwsVerify {
        serialization: JwsFormat,
        input: String,
        #[serde(default)]
        detached: Option<String>,
        #[serde(default)]
        certificate: Option<String>,
    },
    /// Encode the input claims JSON as a compact JWT signed with one key.
    JwtEncode {
        input: String,
        key: KeyRef,
    },
    /// Structural decode only: never a verification result.
    JwtDecode {
        input: String,
    },
    /// Verify signature, host trust and host-configured claims separately.
    JwtVerify {
        input: String,
        #[serde(default)]
        certificate: Option<String>,
    },
    /// Invoke an operator-installed plugin operation. The caller identity, the
    /// permitted host imports and key names come from operator grants, not here.
    Plugin {
        plugin: String,
        operation: String,
        /// Plugin arguments (JSON text, bounded by the plugin's transfer limit).
        args: String,
        /// Invocation-local handles bound to operator-named keys.
        #[serde(default)]
        keys: Vec<PluginKeyRef>,
    },
    /// Public structural inspection; never signs and never exports a key.
    Inspect {
        target: InspectTarget,
    },
    /// Request a timestamp token over `input` from the operator-configured TSA.
    Stamp {
        input: String,
    },
    /// Verify a standalone timestamp token, optionally against its data.
    VerifyStamp {
        token: String,
        #[serde(default)]
        data: Option<String>,
        #[serde(default)]
        algorithm: Option<HashAlgorithm>,
        #[serde(default)]
        max_age_seconds: Option<u64>,
    },
}
/// Inspection inputs. `container`/`password` name `secret` parts (memory only);
/// certificate and CMS inputs are ordinary public documents.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum InspectTarget {
    Certificate {
        input: String,
    },
    Cms {
        input: String,
    },
    Container {
        container: String,
        #[serde(default)]
        password: Option<String>,
    },
    /// Public metadata of an operator-named key slot (token needs that key right).
    Named {
        name: String,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignKind {
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
    XadesB,
    XadesT,
    XadesLt,
    XadesLta,
    /// SOAP WS-Security Body signature with the host verification profile.
    Wsse,
    /// Kalkan-compatible XMLDSig (XPath element/parent; NCALayer wire layout).
    XmlLegacy,
    XadesLegacyB,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoapKind {
    Soap11,
    Soap12,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwsFormat {
    Compact,
    Flattened,
    General,
}
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignWriteMode {
    #[default]
    Create,
    Add,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginKeyRef {
    pub handle: u32,
    pub name: String,
}
/// A public `document` part carrying DER evidence.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub input: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Certificate,
    Ocsp,
    Crl,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendKind {
    CadesT,
    CadesLt,
    CadesLta,
    PadesT,
    PadesLt,
    PadesLta,
}
/// Key reference. `container`/`password` name `secret` parts of the same item;
/// no client path, token reader or certificate fingerprint is accepted.
#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyRef {
    Named {
        name: String,
    },
    Inline {
        container: String,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        alias: Option<String>,
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
    XadesB,
    XadesT,
    XadesLt,
    XadesLta,
    Wsse,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<crate::error::ApiError>,
    },
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalStatus {
    Completed,
    Failed,
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
    Extraction {
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact: Option<String>,
        bytes_written: u64,
    },
    Signing {
        profile: SignKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        signers: Vec<crate::error::AppliedState>,
    },
    Jws {
        serialization: JwsFormat,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        signers: Vec<crate::error::AppliedState>,
    },
    JwsVerification {
        verdict: &'static str,
        policy: &'static str,
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
        verdict: &'static str,
        signature_verdict: &'static str,
        claims_verdict: &'static str,
        claim_failures: Vec<String>,
        checked_at_unix: i64,
        signers: Vec<JwsSignerFacts>,
        claims: String,
    },
    Plugin {
        response: String,
        applied: crate::error::AppliedState,
    },
    Inspection {
        target: &'static str,
        bytes_in: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        integrity: Option<String>,
        entries: Vec<InspectedEntry>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cms: Option<InspectedCms>,
    },
    Stamping {
        #[serde(skip_serializing_if = "Option::is_none")]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        verdicts: Vec<&'static str>,
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

#[derive(Serialize)]
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
#[derive(Serialize)]
pub struct InspectedCms {
    pub detached: bool,
    pub content_len: u64,
    pub signer_count: usize,
}
/// Separate token facts: a valid-looking token is not a document proof unless
/// `imprint` is `Matched` and every check passed.
#[derive(Serialize)]
pub struct TimestampFacts {
    pub verdict: &'static str,
    pub gen_time_unix: i64,
    pub checked_at_unix: i64,
    pub policy: &'static str,
    pub algorithm: Option<String>,
    pub imprint: String,
    pub signature: &'static str,
    pub eku: &'static str,
    pub chain: &'static str,
    pub validity: &'static str,
    pub revocation: &'static str,
    pub expectations: &'static str,
}

#[derive(Serialize)]
pub struct JwsSignerFacts {
    pub algorithm: &'static str,
    pub crypto: &'static str,
    pub verdict: &'static str,
    pub trust: SignerChecks,
}

impl OperationResult {
    /// A failed terminal record withholds every artifact: no Content-ID of
    /// undelivered output may remain in the results.
    pub fn withhold_artifact(&mut self) {
        match self {
            Self::Extraction { artifact, .. }
            | Self::Signing { artifact, .. }
            | Self::Extension { artifact, .. }
            | Self::Stamping { artifact, .. }
            | Self::Jws { artifact, .. } => *artifact = None,
            _ => {}
        }
    }
}
