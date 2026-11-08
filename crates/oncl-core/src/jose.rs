//! Bounded, strict RFC 7515 JWS and RFC 7519 JWT operations.
//!
//! This profile implements RS256 and the pinned AcBank algorithm identifier
//! `ECGOST3410-2015-512` using existing PKI primitives (not an ES512 alias).
//! Compact, flattened and general JSON support attached or detached **base64url**
//! payloads. RFC 7797 unencoded payloads, unprotected headers, key URLs, `kid`,
//! JWK, and critical extensions are deliberately not supported. Legacy plugin
//! serialization is independent and unchanged. Add emits general JSON and checks
//! every old signature AND host trust before opening any new private key.
//!
//! Inputs are borrowed bounded byte slices: no stream is secretly materialized.
//! Payload <= 256 KiB, claims <= 64 KiB, protected header <= 16 KiB, encoded
//! container <= 1 MiB. Signature and x5c sequences reject the ninth entry before
//! parsing/copying it or growing their collection. Leaf/x5c/host-intermediate
//! certificates are <= 8 KiB DER; host intermediates are <= 8 candidates.
//! The host root store is NOT capped at eight roots or 8-KiB root certificates:
//! it remains borrowed by the accepted admitted PKIX builder, with public-key
//! scratch/selected-path copies under original global memory/metadata/deadline.
//! Container/header sizes are checked before decoding/JSON allocation. Workspace,
//! parsed data, certificate facts and output reports retain the original root
//! admission and memory/metadata reservations; only borrowed views escape.
//! Caller-owned input/output storage and explicit caller copies are not sandboxed.
//! No 1-GiB document/RSS claim is made by this bounded token API.
use crate::output::ProducerOutput;
use crate::{Action, Engine, OperationContext, OperationError, keys::KeyRequest};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use der::{Decode, Encode};
use oncl_pki::{
    cert::Certificate,
    digest::{DigestValue, HashState},
    http::deadline::DeadlineTransport,
    key::{AppliedState, PublicKey, SigAlg},
    resource::{ProcessingError, ResourceReservation, ResourceScope},
    validation::{self, CheckStatus, SignerValidation, ValidationContext, Verdict},
};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt, io::Write, sync::Arc};

pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_CLAIMS_BYTES: usize = 64 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_CONTAINER_BYTES: usize = 1024 * 1024;
pub const MAX_SIGNERS: usize = 8;
const MAX_CERT_BYTES: usize = 8192;
const MAX_SIGNATURE_BYTES: usize = 1024;

fn invalid(message: &'static str) -> OperationError {
    ProcessingError::InvalidInput(message).into()
}
fn check_certificate_size(cert: &Certificate) -> Result<(), OperationError> {
    let length = cert
        .encoded_len()
        .map_err(|_| invalid("invalid JOSE certificate"))?;
    if usize::try_from(length).map_err(|_| invalid("certificate length overflow"))? > MAX_CERT_BYTES
    {
        return Err(invalid("certificate exceeds JOSE profile"));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoseAlgorithm {
    Rs256,
    EcGost3410_2015_512,
}
impl JoseAlgorithm {
    pub fn from_name(name: &str) -> Result<Self, OperationError> {
        match name {
            "RS256" => Ok(Self::Rs256),
            "ECGOST3410-2015-512" => Ok(Self::EcGost3410_2015_512),
            _ => Err(invalid("unsupported JOSE algorithm")),
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::EcGost3410_2015_512 => "ECGOST3410-2015-512",
        }
    }
    fn signature(self) -> SigAlg {
        match self {
            Self::Rs256 => SigAlg::RsaSha256,
            Self::EcGost3410_2015_512 => SigAlg::Gost2015_512,
        }
    }
    fn from_signature(algorithm: SigAlg) -> Result<Self, OperationError> {
        match algorithm {
            SigAlg::RsaSha256 => Ok(Self::Rs256),
            SigAlg::Gost2015_512 => Ok(Self::EcGost3410_2015_512),
            _ => Err(invalid("private key has no supported JOSE profile")),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwsSerialization {
    Compact,
    Flattened,
    General,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoseProfile {
    serialization: JwsSerialization,
    detached: bool,
}
impl JoseProfile {
    pub const fn new(serialization: JwsSerialization, detached: bool) -> Self {
        Self {
            serialization,
            detached,
        }
    }
    pub const fn serialization(self) -> JwsSerialization {
        self.serialization
    }
    pub const fn detached(self) -> bool {
        self.detached
    }
}
/// Host-selected public certificate, when the standard JWS has no x5c. If x5c
/// is present, its leaf must match this pin. It never becomes a trust anchor.
#[derive(Clone, Copy)]
pub struct JwsVerifyRequest<'a> {
    pub profile: JoseProfile,
    pub certificate: Option<&'a Certificate>,
}
impl JwsVerifyRequest<'_> {
    pub const fn new(profile: JoseProfile) -> Self {
        Self {
            profile,
            certificate: None,
        }
    }
}
struct Admission {
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Admission(scoped)")
    }
}
impl Admission {
    fn new(scope: &ResourceScope, bytes: usize) -> Result<Self, OperationError> {
        // Bound transient JSON strings/trees, parser stacks, DER/PKI candidates,
        // old/new Vec capacities and encoded output, including validation reports.
        let bytes = (bytes as u64)
            .checked_mul(16)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .ok_or(ProcessingError::MemoryLimit)?;
        Ok(Self {
            _memory: scope.reserve_memory(bytes)?,
            _metadata: scope.reserve_metadata(bytes)?,
        })
    }
}
#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "bounded_sequence"
    )]
    x5c: Vec<String>,
}
#[derive(Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct WireSignature {
    protected: String,
    signature: String,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct General {
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    signatures: Vec<WireSignature>,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Flattened {
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    protected: String,
    signature: String,
}
// RawValue borrows the JSON lexeme without materializing header/payload strings.
// Bound each serialized lexeme before serde allocates its decoded String.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInput<'a> {
    #[serde(borrow)]
    protected: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    signature: &'a serde_json::value::RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneralInput<'a> {
    #[serde(borrow, default, deserialize_with = "present_payload")]
    payload: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow, deserialize_with = "bounded_sequence")]
    signatures: Vec<WireInput<'a>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlattenedInput<'a> {
    #[serde(borrow, default, deserialize_with = "present_payload")]
    payload: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    protected: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    signature: &'a serde_json::value::RawValue,
}
/// Collection admission precedes even the ninth element's deserializer. Using
/// IgnoredAny here would still traverse an arbitrarily costly excess entry.
fn bounded_sequence<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T>(std::marker::PhantomData<T>);
    struct RejectExcess<T>(std::marker::PhantomData<T>);
    impl<'de, T> DeserializeSeed<'de> for RejectExcess<T> {
        type Value = T;
        fn deserialize<D: de::Deserializer<'de>>(self, _: D) -> Result<T, D::Error> {
            Err(de::Error::custom("JOSE sequence exceeds eight entries"))
        }
    }
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JOSE sequence of at most eight entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::new();
            while values.len() < MAX_SIGNERS {
                match sequence.next_element()? {
                    Some(value) => values.push(value),
                    None => return Ok(values),
                }
            }
            // SeqAccess checks for ']' first. A present ninth item fails before
            // parsing/copying that item or growing the eight-element Vec.
            sequence.next_element_seed(RejectExcess::<T>(std::marker::PhantomData))?;
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T>(std::marker::PhantomData))
}
fn present_payload<'de, D: de::Deserializer<'de>>(
    d: D,
) -> Result<Option<&'de serde_json::value::RawValue>, D::Error> {
    <&serde_json::value::RawValue>::deserialize(d).map(Some)
}
fn bounded_string(
    raw: &serde_json::value::RawValue,
    limit: usize,
) -> Result<String, OperationError> {
    if raw.get().len() > limit.div_ceil(3) * 4 + 2 {
        return Err(invalid("encoded JOSE JSON field exceeds profile"));
    }
    serde_json::from_str(raw.get()).map_err(|_| invalid("JWS member must be a string"))
}
fn own_wire(wire: WireInput<'_>) -> Result<WireSignature, OperationError> {
    Ok(WireSignature {
        protected: bounded_string(wire.protected, MAX_HEADER_BYTES)?,
        signature: bounded_string(wire.signature, MAX_SIGNATURE_BYTES)?,
    })
}
#[derive(Debug)]
struct Parsed {
    payload: Vec<u8>,
    encoded_payload: String,
    signatures: Vec<WireSignature>,
    _admission: Admission,
}
fn decode_b64(input: &str, limit: usize) -> Result<Vec<u8>, OperationError> {
    if input.len() > limit.div_ceil(3) * 4 {
        return Err(invalid("JOSE base64url field exceeds limit"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| invalid("noncanonical JOSE base64url"))?;
    if decoded.len() > limit {
        return Err(invalid("decoded JOSE field exceeds limit"));
    }
    Ok(decoded)
}
fn parse(
    input: &[u8],
    profile: JoseProfile,
    detached: Option<&[u8]>,
    payload_limit: usize,
    ctx: &OperationContext,
) -> Result<Parsed, OperationError> {
    let scope = &ctx.scope;
    if input.len() > MAX_CONTAINER_BYTES || detached.is_some_and(|v| v.len() > payload_limit) {
        return Err(invalid("JOSE input exceeds bounded profile"));
    }
    if profile.detached != detached.is_some() {
        return Err(invalid("detached source/profile mismatch"));
    }
    let admission = Admission::new(scope, input.len() + detached.map_or(0, <[u8]>::len))?;
    ctx.account_borrowed(input, detached)?;
    scope.account_container(input.len() as u64)?;
    let (encoded, signatures) = match profile.serialization {
        JwsSerialization::Compact => {
            let s = std::str::from_utf8(input).map_err(|_| invalid("JWS compact is not ASCII"))?;
            let mut parts = s.split('.');
            let h = parts.next().ok_or_else(|| invalid("missing JWS header"))?;
            let p = parts.next().ok_or_else(|| invalid("missing JWS payload"))?;
            let sig = parts
                .next()
                .ok_or_else(|| invalid("missing JWS signature"))?;
            if parts.next().is_some() {
                return Err(invalid("extra compact JWS part"));
            }
            if profile.detached && !p.is_empty() {
                return Err(invalid("detached compact has attached payload"));
            }
            if h.len() > MAX_HEADER_BYTES.div_ceil(3) * 4
                || p.len() > payload_limit.div_ceil(3) * 4
                || sig.len() > MAX_SIGNATURE_BYTES.div_ceil(3) * 4
            {
                return Err(invalid("compact JWS field exceeds profile"));
            }
            (
                (!profile.detached).then(|| p.to_owned()),
                vec![WireSignature {
                    protected: h.to_owned(),
                    signature: sig.to_owned(),
                }],
            )
        }
        JwsSerialization::Flattened => {
            let f: FlattenedInput<'_> =
                serde_json::from_slice(input).map_err(|_| invalid("invalid flattened JWS JSON"))?;
            (
                f.payload
                    .map(|v| bounded_string(v, payload_limit))
                    .transpose()?,
                vec![own_wire(WireInput {
                    protected: f.protected,
                    signature: f.signature,
                })?],
            )
        }
        JwsSerialization::General => {
            let g: GeneralInput<'_> =
                serde_json::from_slice(input).map_err(|_| invalid("invalid general JWS JSON"))?;
            if g.signatures.is_empty() {
                return Err(invalid("JWS signer count outside profile"));
            }
            (
                g.payload
                    .map(|v| bounded_string(v, payload_limit))
                    .transpose()?,
                g.signatures
                    .into_iter()
                    .map(own_wire)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
    };
    let (payload, encoded_payload) = if let Some(detached) = detached {
        if encoded.is_some() {
            return Err(invalid("detached JSON must omit payload"));
        }
        (detached.to_vec(), URL_SAFE_NO_PAD.encode(detached))
    } else {
        let encoded = encoded.ok_or_else(|| invalid("missing attached JWS payload"))?;
        (decode_b64(&encoded, payload_limit)?, encoded)
    };
    for signature in &signatures {
        // Reject unsafe headers/oversized signatures before any key provider use.
        header(signature)?;
        decode_b64(&signature.signature, MAX_SIGNATURE_BYTES)?;
    }
    scope.checkpoint()?;
    Ok(Parsed {
        payload,
        encoded_payload,
        signatures,
        _admission: admission,
    })
}
fn header(wire: &WireSignature) -> Result<(Header, JoseAlgorithm), OperationError> {
    let bytes = decode_b64(&wire.protected, MAX_HEADER_BYTES)?;
    let header: Header = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("unsupported, duplicate or malformed protected header"))?;
    let algorithm = JoseAlgorithm::from_name(&header.alg)?;
    Ok((header, algorithm))
}
fn digest(algorithm: JoseAlgorithm, protected: &str, payload: &str) -> DigestValue {
    let mut hash = HashState::new(algorithm.signature().hash_alg());
    hash.update(protected.as_bytes());
    hash.update(b".");
    hash.update(payload.as_bytes());
    hash.finish()
}
fn combine(a: Verdict, b: Verdict) -> Verdict {
    if a == Verdict::Invalid || b == Verdict::Invalid {
        Verdict::Invalid
    } else if a == Verdict::Indeterminate || b == Verdict::Indeterminate {
        Verdict::Indeterminate
    } else {
        Verdict::Valid
    }
}
#[derive(Debug)]
pub struct JoseSignerReport {
    algorithm: JoseAlgorithm,
    crypto: CheckStatus,
    trust: SignerValidation,
}
impl JoseSignerReport {
    pub const fn algorithm(&self) -> JoseAlgorithm {
        self.algorithm
    }
    pub const fn crypto(&self) -> CheckStatus {
        self.crypto
    }
    pub fn trust(&self) -> &SignerValidation {
        &self.trust
    }
    pub fn verdict(&self) -> Verdict {
        combine(
            if self.crypto == CheckStatus::Passed {
                Verdict::Valid
            } else {
                Verdict::Invalid
            },
            self.trust.verdict(),
        )
    }
}
/// Parsed buffers and signer facts cannot be moved out or cloned independently
/// of the report's original reservations and admission lifetime.
/// ```compile_fail
/// fn detach(report: oncl_core::jose::JwsVerificationReport) {
///     let payload = report.parsed.payload;
/// }
/// ```
/// ```compile_fail
/// fn copy(report: &oncl_core::jose::JwsVerificationReport) {
///     let _: oncl_core::jose::JoseSignerReport = report.signers()[0].clone();
/// }
/// ```
#[derive(Debug)]
pub struct JwsVerificationReport {
    parsed: Parsed,
    signers: Vec<JoseSignerReport>,
    verdict: Verdict,
    checked_at: time::OffsetDateTime,
    policy: validation::ValidationPolicy,
}
impl JwsVerificationReport {
    pub fn payload(&self) -> &[u8] {
        &self.parsed.payload
    }
    pub fn signers(&self) -> &[JoseSignerReport] {
        &self.signers
    }
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }
    pub const fn checked_at(&self) -> time::OffsetDateTime {
        self.checked_at
    }
    pub const fn policy(&self) -> validation::ValidationPolicy {
        self.policy
    }
}
#[derive(Debug)]
pub struct JoseWriteReport {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub applied: AppliedState,
    pub signer_count: usize,
    _admission: Admission,
}
impl Engine {
    fn jose_authority(&self, ctx: &OperationContext, action: Action) -> Result<(), OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if !ctx.grant().allows(action) {
            return Err(OperationError::PermissionDenied);
        }
        ctx.scope.checkpoint()?;
        Ok(())
    }
    /// Create signatures over the exact borrowed payload (not a supplied digest).
    pub fn jws_create(
        &self,
        profile: JoseProfile,
        keys: Vec<KeyRequest<'_>>,
        payload: &[u8],
        output: &mut dyn Write,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.jose_create(
            profile,
            keys,
            payload,
            false,
            ProducerOutput::Writer(output),
            ctx,
        )
    }
    pub fn jws_create_staged(
        &self,
        profile: JoseProfile,
        keys: Vec<KeyRequest<'_>>,
        payload: &[u8],
        output: &mut oncl_pki::io::StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.check_sign_requests(&keys, ctx, Action::Sign)?;
        let output = ProducerOutput::staged(output, &ctx.scope)?;
        self.jose_create(profile, keys, payload, false, output, ctx)
    }
    fn jose_create(
        &self,
        profile: JoseProfile,
        keys: Vec<KeyRequest<'_>>,
        payload: &[u8],
        jwt: bool,
        mut output: ProducerOutput<'_>,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.jose_authority(ctx, Action::Sign)?;
        if jwt && payload.len() > MAX_CLAIMS_BYTES {
            return Err(invalid("JWT claims exceed profile"));
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid("JWS payload exceeds profile"));
        }
        validate_count(profile, keys.len())?;
        let admission = Admission::new(&ctx.scope, payload.len() + MAX_HEADER_BYTES * keys.len())?;
        ctx.account_borrowed(payload, None)?;
        if jwt {
            parse_claims(payload)?;
        }
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let mut signatures = Vec::with_capacity(keys.len());
        let mut applied = AppliedState::NotApplied;
        let result = (|| {
            self.jose_signatures(&keys, &encoded, jwt, &mut signatures, &mut applied, ctx)?;
            let length = emit(profile, &encoded, signatures, &mut output, &ctx.scope)?;
            output.finish(&ctx.scope)?;
            Ok(length)
        })();
        let bytes_out = after_use(result, applied)?;
        Ok(JoseWriteReport {
            bytes_in: payload.len() as u64,
            bytes_out,
            applied,
            signer_count: keys.len(),
            _admission: admission,
        })
    }
    fn jose_signatures(
        &self,
        keys: &[KeyRequest<'_>],
        encoded: &str,
        jwt: bool,
        signatures: &mut Vec<WireSignature>,
        applied: &mut AppliedState,
        ctx: &mut OperationContext,
    ) -> Result<(), OperationError> {
        let indices = self.prepare_sign_keys(keys, ctx, Action::Sign)?;
        // Validate the whole requested algorithm matrix before the first guard.
        for &index in &indices {
            JoseAlgorithm::from_signature(
                self.operation_signer(index, ctx, Action::Sign)?.algorithm(),
            )?;
        }
        for index in indices {
            let mut signer = self.operation_signer(index, ctx, Action::Sign)?;
            let algorithm = JoseAlgorithm::from_signature(signer.algorithm())?;
            check_certificate_size(signer.certificate())?;
            let cert = signer
                .certificate()
                .to_der()
                .map_err(|_| invalid("cannot encode signer certificate"))?;
            let header = Header {
                alg: algorithm.name().into(),
                typ: jwt.then(|| "JWT".into()),
                cty: None,
                x5c: vec![STANDARD.encode(cert)],
            };
            let header =
                serde_json::to_vec(&header).map_err(|_| invalid("cannot serialize JWS header"))?;
            if header.len() > MAX_HEADER_BYTES {
                return Err(invalid("signer header exceeds profile"));
            }
            let protected = URL_SAFE_NO_PAD.encode(header);
            let signature = signer.sign_digest(&digest(algorithm, &protected, encoded));
            match signature {
                Ok(signature) => {
                    *applied = applied.combine(AppliedState::Applied);
                    if signature.len() > MAX_SIGNATURE_BYTES {
                        return Err(invalid("signature exceeds JOSE profile"));
                    }
                    signatures.push(WireSignature {
                        protected,
                        signature: URL_SAFE_NO_PAD.encode(signature),
                    });
                }
                Err(error) => {
                    *applied = applied.combine(error.applied_state());
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    /// Verify every existing signature/trust fact before opening any new key.
    /// Existing protected/payload/signature strings are preserved byte-for-byte.
    /// Add's output is always standard general JSON, with the same detachment.
    pub fn jws_add(
        &self,
        request: JwsVerifyRequest<'_>,
        keys: Vec<KeyRequest<'_>>,
        input: &[u8],
        detached: Option<&[u8]>,
        output: &mut dyn Write,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.jws_add_output(
            request,
            keys,
            input,
            detached,
            ProducerOutput::Writer(output),
            ctx,
        )
    }
    pub fn jws_add_staged(
        &self,
        request: JwsVerifyRequest<'_>,
        keys: Vec<KeyRequest<'_>>,
        input: &[u8],
        detached: Option<&[u8]>,
        output: &mut oncl_pki::io::StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.check_sign_requests(&keys, ctx, Action::Sign)?;
        let output = ProducerOutput::staged(output, &ctx.scope)?;
        self.jws_add_output(request, keys, input, detached, output, ctx)
    }
    fn jws_add_output(
        &self,
        request: JwsVerifyRequest<'_>,
        keys: Vec<KeyRequest<'_>>,
        input: &[u8],
        detached: Option<&[u8]>,
        mut output: ProducerOutput<'_>,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.jose_authority(ctx, Action::Sign)?;
        let parsed = parse(input, request.profile, detached, MAX_PAYLOAD_BYTES, ctx)?;
        let mut report = self.jose_verify_parsed(request, parsed, ctx)?;
        if report.verdict != Verdict::Valid {
            return Err(OperationError::ValidationRequired);
        }
        let count = report
            .parsed
            .signatures
            .len()
            .checked_add(keys.len())
            .ok_or_else(|| invalid("signer count overflow"))?;
        let profile = JoseProfile::new(JwsSerialization::General, request.profile.detached);
        validate_count(profile, count)?;
        if keys.is_empty() {
            return Err(invalid("Add requires new signer"));
        }
        let admission = Admission::new(&ctx.scope, input.len() + MAX_HEADER_BYTES * keys.len())?;
        let mut applied = AppliedState::NotApplied;
        let result = (|| {
            self.jose_signatures(
                &keys,
                &report.parsed.encoded_payload,
                false,
                &mut report.parsed.signatures,
                &mut applied,
                ctx,
            )?;
            let length = emit(
                profile,
                &report.parsed.encoded_payload,
                report.parsed.signatures,
                &mut output,
                &ctx.scope,
            )?;
            output.finish(&ctx.scope)?;
            Ok(length)
        })();
        let bytes_out = after_use(result, applied)?;
        Ok(JoseWriteReport {
            bytes_in: (input.len() + detached.map_or(0, <[u8]>::len)) as u64,
            bytes_out,
            applied,
            signer_count: count,
            _admission: admission,
        })
    }
    pub fn jws_verify(
        &self,
        request: JwsVerifyRequest<'_>,
        input: &[u8],
        detached: Option<&[u8]>,
        ctx: &mut OperationContext,
    ) -> Result<JwsVerificationReport, OperationError> {
        self.jose_authority(ctx, Action::Verify)?;
        let parsed = parse(input, request.profile, detached, MAX_PAYLOAD_BYTES, ctx)?;
        self.jose_verify_parsed(request, parsed, ctx)
    }
    fn jose_verify_parsed(
        &self,
        request: JwsVerifyRequest<'_>,
        parsed: Parsed,
        ctx: &OperationContext,
    ) -> Result<JwsVerificationReport, OperationError> {
        let services = self
            .validation
            .as_deref()
            .ok_or(OperationError::MissingValidationServices)?;
        let now = (services.clock)();
        let scoped_http = ctx.http(services.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &services.network, &ctx.scope);
        let _http_memory = ctx
            .scope
            .reserve_memory(4 * oncl_pki::http::MAX_RESPONSE_LEN)?;
        let _http_metadata = ctx
            .scope
            .reserve_metadata(oncl_pki::http::MAX_RESPONSE_LEN)?;
        let validation = ValidationContext {
            policy: ctx.policy().validation,
            now,
            anchors: &services.anchors,
            intermediates: &services.intermediates,
            http: &transport,
        };
        if services.intermediates.len() > MAX_SIGNERS {
            return Err(invalid("host intermediate set exceeds JOSE profile"));
        }
        for cert in &services.intermediates {
            check_certificate_size(cert)?;
        }
        if let Some(cert) = request.certificate {
            check_certificate_size(cert)?;
        }
        let mut signers = Vec::with_capacity(parsed.signatures.len());
        let mut verdict = Verdict::Valid;
        for wire in &parsed.signatures {
            ctx.scope.checkpoint()?;
            let (header, algorithm) = header(wire)?;
            if !ctx
                .policy()
                .allowed_signature_algorithms
                .contains(&algorithm.signature())
            {
                return Err(OperationError::PermissionDenied);
            }
            let mut candidates =
                Vec::with_capacity(header.x5c.len() + services.intermediates.len());
            for encoded in &header.x5c {
                if encoded.len() > MAX_CERT_BYTES.div_ceil(3) * 4 {
                    return Err(invalid("x5c certificate exceeds profile"));
                }
                let der = STANDARD
                    .decode(encoded)
                    .map_err(|_| invalid("invalid x5c base64"))?;
                if der.len() > MAX_CERT_BYTES {
                    return Err(invalid("x5c certificate exceeds profile"));
                }
                candidates.push(
                    Certificate::from_der(&der).map_err(|_| invalid("invalid x5c certificate"))?,
                );
            }
            let has_leaf = !candidates.is_empty();
            candidates.extend(services.intermediates.iter().cloned());
            let cert = match (request.certificate, has_leaf.then(|| &candidates[0])) {
                (Some(pin), Some(leaf)) if pin != leaf => {
                    return Err(invalid("x5c does not match host certificate"));
                }
                (Some(pin), _) => pin,
                (None, Some(leaf)) => leaf,
                _ => return Err(invalid("JWS requires host certificate or protected x5c")),
            };
            let key = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())?;
            let signature = decode_b64(&wire.signature, MAX_SIGNATURE_BYTES)?;
            let crypto = if key
                .verify_digest(
                    algorithm.signature(),
                    &digest(algorithm, &wire.protected, &parsed.encoded_payload),
                    &signature,
                )
                .is_ok()
            {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            };
            let trust = validation::validate_certificate(cert, now, &validation, &candidates);
            transport.finish()?;
            let signer = JoseSignerReport {
                algorithm,
                crypto,
                trust,
            };
            verdict = combine(verdict, signer.verdict());
            signers.push(signer);
        }
        ctx.scope.checkpoint()?;
        Ok(JwsVerificationReport {
            parsed,
            signers,
            verdict,
            checked_at: now,
            policy: ctx.policy().validation,
        })
    }
}
fn validate_count(profile: JoseProfile, count: usize) -> Result<(), OperationError> {
    if count == 0
        || count > MAX_SIGNERS
        || (profile.serialization != JwsSerialization::General && count != 1)
    {
        return Err(invalid("signer count incompatible with serialization"));
    }
    Ok(())
}
fn after_use<T>(
    result: Result<T, OperationError>,
    applied: AppliedState,
) -> Result<T, OperationError> {
    result.map_err(|error| {
        let applied = applied.combine(error.applied_state());
        if applied == AppliedState::NotApplied {
            error
        } else {
            OperationError::AfterKeyUse {
                source: Box::new(error),
                applied,
            }
        }
    })
}
fn emit(
    profile: JoseProfile,
    payload: &str,
    mut signatures: Vec<WireSignature>,
    output: &mut ProducerOutput<'_>,
    scope: &ResourceScope,
) -> Result<u64, OperationError> {
    let bytes = match profile.serialization {
        JwsSerialization::Compact => {
            let signature = signatures.remove(0);
            format!(
                "{}.{}.{}",
                signature.protected,
                if profile.detached { "" } else { payload },
                signature.signature
            )
            .into_bytes()
        }
        JwsSerialization::Flattened => {
            let signature = signatures.remove(0);
            serde_json::to_vec(&Flattened {
                payload: (!profile.detached).then(|| payload.to_owned()),
                protected: signature.protected,
                signature: signature.signature,
            })
            .map_err(|_| invalid("cannot serialize flattened JWS"))?
        }
        JwsSerialization::General => serde_json::to_vec(&General {
            payload: (!profile.detached).then(|| payload.to_owned()),
            signatures,
        })
        .map_err(|_| invalid("cannot serialize general JWS"))?,
    };
    if bytes.len() > MAX_CONTAINER_BYTES {
        return Err(invalid("JWS output exceeds profile"));
    }
    scope.account_container(bytes.len() as u64)?;
    output.write(&bytes, scope)?;
    scope.checkpoint()?;
    Ok(bytes.len() as u64)
}

/// Trusted host-owned policy, never deserialized from a token. `new` fixes the
/// clock explicitly; default rules require exp and grant zero seconds leeway.
/// NumericDates in this bounded profile are integral RFC 3339-representable UTC
/// seconds, INCLUDING negative epochs. Fractional, overflowing, nonnumeric and
/// null dates fail claims, not crypto. Negative exp/nbf and negative trusted now
/// follow the same host expiration/not-before boundaries as positive epochs.
/// `iat` must be a representable integer but does not imply freshness/max-age
/// checks: no such host policy is inferred from the token.
#[derive(Debug)]
pub struct JwtValidationPolicy {
    now: i64,
    pub expected_issuer: Option<String>,
    pub expected_audience: Option<String>,
    pub require_exp: bool,
    pub leeway_seconds: u64,
}
impl JwtValidationPolicy {
    pub fn new(now: i64) -> Self {
        Self {
            now,
            expected_issuer: None,
            expected_audience: None,
            require_exp: true,
            leeway_seconds: 0,
        }
    }
    pub const fn now(&self) -> i64 {
        self.now
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimsFailure {
    MissingExpiration,
    InvalidNumericDate,
    Expired,
    NotYetValid,
    Issuer,
    Audience,
}
#[derive(Debug)]
pub struct JwtClaimsReport {
    verdict: Verdict,
    failures: Vec<ClaimsFailure>,
    now: i64,
}
impl JwtClaimsReport {
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }
    pub fn failures(&self) -> &[ClaimsFailure] {
        &self.failures
    }
    pub const fn checked_at(&self) -> i64 {
        self.now
    }
}
#[derive(Debug)]
struct Claims {
    issuer: Option<String>,
    audience: Vec<String>,
    exp: Option<i64>,
    nbf: Option<i64>,
    invalid_date: bool,
    invalid_issuer: bool,
    invalid_audience: bool,
}
/// A structural decode owns the admitted raw/parsed claims but does not expose
/// an owned Vec/Value or a mutable buffer from which the guards can be detached.
/// ```compile_fail
/// fn detach(mut decoded: oncl_core::jose::DecodedJwt) {
///     let _: Vec<u8> = std::mem::take(decoded.payload());
/// }
/// ```
#[derive(Debug)]
pub struct DecodedJwt {
    parsed: Parsed,
    claims: Claims,
}
impl DecodedJwt {
    /// Structural decode only. This type has no crypto/claims success verdict.
    pub const fn is_verified(&self) -> bool {
        false
    }
    pub fn payload(&self) -> &[u8] {
        &self.parsed.payload
    }
    pub fn issuer(&self) -> Option<&str> {
        self.claims.issuer.as_deref()
    }
    pub fn audience(&self) -> impl Iterator<Item = &str> {
        self.claims.audience.iter().map(String::as_str)
    }
    pub const fn expiration(&self) -> Option<i64> {
        self.claims.exp
    }
}
#[derive(Debug)]
pub struct JwtVerificationReport {
    jws: JwsVerificationReport,
    claims: JwtClaimsReport,
    verdict: Verdict,
}
impl JwtVerificationReport {
    pub fn jws(&self) -> &JwsVerificationReport {
        &self.jws
    }
    pub fn claims(&self) -> &JwtClaimsReport {
        &self.claims
    }
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }
}
impl Engine {
    pub fn jwt_encode(
        &self,
        key: KeyRequest<'_>,
        claims: &[u8],
        output: &mut dyn Write,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        if claims.len() > MAX_CLAIMS_BYTES {
            return Err(invalid("JWT claims exceed profile"));
        }
        self.jose_create(
            JoseProfile::new(JwsSerialization::Compact, false),
            vec![key],
            claims,
            true,
            ProducerOutput::Writer(output),
            ctx,
        )
    }
    pub fn jwt_encode_staged(
        &self,
        key: KeyRequest<'_>,
        claims: &[u8],
        output: &mut oncl_pki::io::StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<JoseWriteReport, OperationError> {
        self.check_sign_requests(std::slice::from_ref(&key), ctx, Action::Sign)?;
        let output = ProducerOutput::staged(output, &ctx.scope)?;
        self.jose_create(
            JoseProfile::new(JwsSerialization::Compact, false),
            vec![key],
            claims,
            true,
            output,
            ctx,
        )
    }
    pub fn jwt_decode_unverified(
        &self,
        input: &[u8],
        ctx: &mut OperationContext,
    ) -> Result<DecodedJwt, OperationError> {
        self.jose_authority(ctx, Action::Extract)?;
        let parsed = parse(
            input,
            JoseProfile::new(JwsSerialization::Compact, false),
            None,
            MAX_CLAIMS_BYTES,
            ctx,
        )?;
        jwt_header(&parsed)?;
        let claims = parse_claims(&parsed.payload)?;
        Ok(DecodedJwt { parsed, claims })
    }
    pub fn jwt_verify(
        &self,
        certificate: Option<&Certificate>,
        input: &[u8],
        policy: &JwtValidationPolicy,
        ctx: &mut OperationContext,
    ) -> Result<JwtVerificationReport, OperationError> {
        self.jose_authority(ctx, Action::Verify)?;
        if time::OffsetDateTime::from_unix_timestamp(policy.now).is_err() {
            return Err(invalid("invalid trusted JWT clock"));
        }
        let profile = JoseProfile::new(JwsSerialization::Compact, false);
        let parsed = parse(input, profile, None, MAX_CLAIMS_BYTES, ctx)?;
        jwt_header(&parsed)?;
        let claims = parse_claims(&parsed.payload)?;
        let claims_report = validate_claims(&claims, policy);
        let jws = self.jose_verify_parsed(
            JwsVerifyRequest {
                profile,
                certificate,
            },
            parsed,
            ctx,
        )?;
        let verdict = combine(jws.verdict, claims_report.verdict);
        Ok(JwtVerificationReport {
            jws,
            claims: claims_report,
            verdict,
        })
    }
}
fn jwt_header(parsed: &Parsed) -> Result<(), OperationError> {
    let (header, _) = header(&parsed.signatures[0])?;
    if header.typ.as_deref().is_some_and(|typ| typ != "JWT") || header.cty.is_some() {
        return Err(invalid("unsupported JWT type/nested token"));
    }
    Ok(())
}
fn parse_claims(bytes: &[u8]) -> Result<Claims, OperationError> {
    if bytes.len() > MAX_CLAIMS_BYTES {
        return Err(invalid("JWT claims exceed profile"));
    }
    let raw: &RawValue =
        serde_json::from_slice(bytes).map_err(|_| invalid("malformed JWT claims"))?;
    let object = unique_members(raw, 0)?.0;
    let mut invalid_date = false;
    let mut date = |name| match object.get(name) {
        None => None,
        Some(value) => match serde_json::from_str::<i64>(value.get())
            .ok()
            .filter(|v| time::OffsetDateTime::from_unix_timestamp(*v).is_ok())
        {
            Some(value) => Some(value),
            None => {
                invalid_date = true;
                None
            }
        },
    };
    let exp = date("exp");
    let nbf = date("nbf");
    // iat is also a NumericDate, even though it does not establish a proof time.
    let _iat = date("iat");
    let issuer = object
        .get("iss")
        .and_then(|v| serde_json::from_str::<String>(v.get()).ok());
    let invalid_issuer = object.contains_key("iss") && issuer.is_none();
    let (audience, invalid_audience) = match object.get("aud") {
        None => (Vec::new(), false),
        Some(value) => {
            if let Ok(audience) = serde_json::from_str::<String>(value.get()) {
                (vec![audience], false)
            } else if let Ok(audiences) = serde_json::from_str::<Vec<String>>(value.get()) {
                (audiences, false)
            } else {
                (Vec::new(), true)
            }
        }
    };
    Ok(Claims {
        issuer,
        audience,
        exp,
        nbf,
        invalid_date,
        invalid_issuer,
        invalid_audience,
    })
}
fn validate_claims(claims: &Claims, policy: &JwtValidationPolicy) -> JwtClaimsReport {
    let mut failures = Vec::with_capacity(6);
    if claims.invalid_date {
        failures.push(ClaimsFailure::InvalidNumericDate);
    }
    if policy.require_exp && claims.exp.is_none() {
        failures.push(ClaimsFailure::MissingExpiration);
    }
    let now = i128::from(policy.now);
    let leeway = i128::from(policy.leeway_seconds);
    if claims
        .exp
        .is_some_and(|exp| now >= i128::from(exp) + leeway)
    {
        failures.push(ClaimsFailure::Expired);
    }
    if claims.nbf.is_some_and(|nbf| now + leeway < i128::from(nbf)) {
        failures.push(ClaimsFailure::NotYetValid);
    }
    if claims.invalid_issuer
        || policy
            .expected_issuer
            .as_ref()
            .is_some_and(|iss| claims.issuer.as_ref() != Some(iss))
    {
        failures.push(ClaimsFailure::Issuer);
    }
    if claims.invalid_audience
        || policy
            .expected_audience
            .as_ref()
            .is_some_and(|aud| !claims.audience.contains(aud))
    {
        failures.push(ClaimsFailure::Audience);
    }
    JwtClaimsReport {
        verdict: if failures.is_empty() {
            Verdict::Valid
        } else {
            Verdict::Invalid
        },
        failures,
        now: policy.now,
    }
}
// Borrow JSON values as raw lexemes: an overflowing NumericDate such as 1e400
// becomes a claims failure, not a fictitious cryptographic or JSON failure.
// No application-claim tree is materialized. All object keys (including nested
// application objects) are unique; depth and original byte limits bound work.
struct UniqueMembers<'a>(BTreeMap<String, &'a RawValue>);
impl<'de> Deserialize<'de> for UniqueMembers<'de> {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MembersVisitor;
        impl<'de> Visitor<'de> for MembersVisitor {
            type Value = UniqueMembers<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object with unique members")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    values.insert(key, map.next_value::<&RawValue>()?);
                }
                Ok(UniqueMembers(values))
            }
        }
        deserializer.deserialize_map(MembersVisitor)
    }
}
fn unique_members<'a>(raw: &'a RawValue, depth: u8) -> Result<UniqueMembers<'a>, OperationError> {
    if depth > 16 {
        return Err(invalid("JWT claim nesting exceeds profile"));
    }
    let members: UniqueMembers<'_> = serde_json::from_str(raw.get())
        .map_err(|_| invalid("JWT claims must be unique JSON objects"))?;
    for value in members.0.values() {
        unique_nested(value, depth + 1)?;
    }
    Ok(members)
}
fn unique_nested(raw: &RawValue, depth: u8) -> Result<(), OperationError> {
    if depth > 16 {
        return Err(invalid("JWT claim nesting exceeds profile"));
    }
    match raw.get().as_bytes().first() {
        Some(b'{') => {
            unique_members(raw, depth)?;
        }
        Some(b'[') => {
            let values: Vec<&RawValue> = serde_json::from_str(raw.get())
                .map_err(|_| invalid("malformed JWT application array"))?;
            for value in values {
                unique_nested(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod sequence_admission_tests {
    use super::{GeneralInput, Header};
    use serde_json::error::Category;

    #[test]
    fn signature_sequence_rejects_ninth_before_parsing_its_representation() {
        let entry = r#"{"protected":"","signature":""}"#;
        let eight = std::iter::repeat_n(entry, 8).collect::<Vec<_>>().join(",");
        let valid = format!(r#"{{"payload":"","signatures":[{eight}]}}"#);
        assert_eq!(
            serde_json::from_str::<GeneralInput<'_>>(&valid)
                .unwrap()
                .signatures
                .len(),
            8
        );
        for suffix in [
            format!("{entry}]}}"),
            std::iter::repeat_n(entry, 10_000)
                .collect::<Vec<_>>()
                .join(","),
            format!(r#"{{"protected":"{}"#, "A".repeat(20_000)),
        ] {
            let prefix = format!(r#"{{"payload":"","signatures":[{eight},"#);
            let input = format!("{prefix}{suffix}");
            let error = serde_json::from_str::<GeneralInput<'_>>(&input)
                .err()
                .expect("ninth entry must be refused");
            assert_eq!(error.classify(), Category::Data);
            assert!(
                error.column() <= prefix.len() + 1,
                "parsed excess signature at column {}",
                error.column()
            );
        }
    }

    #[test]
    fn x5c_sequence_rejects_ninth_before_string_allocation_or_parse() {
        let eight = std::iter::repeat_n(r#""""#, 8)
            .collect::<Vec<_>>()
            .join(",");
        let valid = format!(r#"{{"alg":"RS256","x5c":[{eight}]}}"#);
        assert_eq!(serde_json::from_str::<Header>(&valid).unwrap().x5c.len(), 8);
        for suffix in [
            r#"""]}"#.to_owned(),
            std::iter::repeat_n(r#""""#, 1000)
                .collect::<Vec<_>>()
                .join(","),
            format!("\"{}", "A".repeat(8192)),
        ] {
            let prefix = format!(r#"{{"alg":"RS256","x5c":[{eight},"#);
            let input = format!("{prefix}{suffix}");
            let error = serde_json::from_str::<Header>(&input)
                .expect_err("ninth certificate must be refused");
            assert_eq!(error.classify(), Category::Data);
            assert!(
                error.column() <= prefix.len() + 1,
                "parsed excess certificate at column {}",
                error.column()
            );
        }
    }
}
