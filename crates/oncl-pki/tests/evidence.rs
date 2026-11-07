//! F04 initial TESTS/API gate. No implementation stubs. Controller owns RED/GREEN.
//! Raw coverage streams here are mechanism fixtures, NOT standardized AdES containers.
#![cfg(feature = "testing")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::asn1::{AnyRef, OctetString, UtcTime};
use der::{Decode, Encode, Reader, SliceReader};
use oncl_pki::cert::Certificate;
use oncl_pki::crl::MockCrl;
use oncl_pki::digest::{DigestValue, HashState, hash_source};
use oncl_pki::evidence::{
    AdesLevel, CoverageEncoding, CoveragePart, EvidenceBundle, EvidenceError, EvidenceId,
    EvidenceKind, EvidenceLimits, EvidenceOrigin, EvidenceStore, ProofKind, SignerEvidence,
    TimestampBinding, validate_evidence,
};
use oncl_pki::http::{
    GetOptions, HttpError, HttpErrorKind, HttpReply, HttpRequest, HttpTransport, MAX_RESPONSE_LEN,
};
use oncl_pki::io::{Region, Source, TemporaryStore};
use oncl_pki::key::{HashAlg, SigAlg};
use oncl_pki::ocsp::{self, CertStatus, MockOcsp, OcspTamper};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::resource::{
    IO_CHUNK_BYTES, OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope,
    SharedBudget,
};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::{self, MockTsa, TsaMethod, TsaProfile, TsaSpec};
use oncl_pki::validation::{
    CheckStatus, NetworkPolicy, TimeBasis, ValidationContext, ValidationPolicy, ValidationReason,
    ValidationReport, Verdict,
};
use oncl_testkit::{read, synthetic};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use time::{OffsetDateTime, macros::datetime};
use x509_cert::ext::Extension;
use x509_cert::time::Time;

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const CLAIM: OffsetDateTime = datetime!(2025-06-01 10:00 UTC);
const PROVEN: OffsetDateTime = datetime!(2025-06-01 10:05 UTC);
const ARCHIVE: OffsetDateTime = datetime!(2026-11-02 11:00 UTC);
const REVOKED: OffsetDateTime = datetime!(2026-01-15 08:00 UTC);
const DATA: &[u8] = b"F04 independently signed public synthetic content";
const TSA_URL: &str = "http://tsa.synthetic.test";
const TSA_STATUS: &str = "http://tsa-status.synthetic.test";
const TSA_CRL: &str = "http://tsa-crl.synthetic.test/inter.crl";

fn entry(name: &str) -> KeyEntry {
    let fixture = synthetic(name);
    load(&read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}
fn digest(algorithm: HashAlg, bytes: &[u8]) -> DigestValue {
    let mut state = HashState::new(algorithm);
    state.update(bytes);
    state.finish()
}
fn x509_time(at: OffsetDateTime) -> Time {
    Time::UtcTime(
        UtcTime::from_unix_duration(Duration::from_secs(at.unix_timestamp() as u64)).unwrap(),
    )
}
fn limits() -> ResourceLimits {
    ResourceLimits {
        memory_bytes: 32 * 1024 * 1024,
        temp_bytes: 32 * 1024 * 1024,
        metadata_bytes: 4 * 1024 * 1024,
        operation_timeout: Duration::from_secs(30),
        ..ResourceLimits::default()
    }
}
fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 64,
        max_bytes: 4 * 1024 * 1024,
        max_item_bytes: 1024 * 1024,
        max_crl_bytes: 4 * 1024 * 1024,
        max_crl_item_bytes: 1024 * 1024,
        max_total_bytes: 4 * 1024 * 1024,
        max_chain_len: 8,
        max_proofs: 4,
        max_coverage_parts: 128,
        max_coverage_bytes: 10_737_418_240,
    }
}
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope() -> ResourceScope {
    Arc::new(SharedBudget::new(limits()).unwrap())
        .begin(limits(), Arc::new(Control))
        .unwrap()
}
struct Offline(AtomicUsize);
impl Offline {
    fn new() -> Self {
        Self(AtomicUsize::new(0))
    }
}
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(HttpError::new(
            HttpErrorKind::Connect,
            "synthetic endpoint unavailable",
        ))
    }
}

// Test-only DER navigation preserves real certificate/OCSP/token signatures.
fn children(input: &[u8]) -> Vec<Vec<u8>> {
    let any = AnyRef::from_der(input).unwrap();
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut values = Vec::new();
    while !reader.is_finished() {
        values.push(reader.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
    }
    values
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if bytes.len() < 128 {
        result.push(bytes.len() as u8);
    } else {
        let length: Vec<_> = bytes
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        result.push(0x80 | length.len() as u8);
        result.extend(length);
    }
    result.extend_from_slice(bytes);
    result
}
fn rewrite_uris(input: &[u8], uri: &[u8]) -> Vec<u8> {
    let any = AnyRef::from_der(input).unwrap();
    if input[0] == 0x86 {
        return tlv(0x86, uri);
    }
    if input[0] & 0x20 != 0 {
        let body: Vec<_> = children(input)
            .iter()
            .flat_map(|part| rewrite_uris(part, uri))
            .collect();
        return tlv(input[0], &body);
    }
    tlv(input[0], any.value())
}
fn serial(cert: &Certificate) -> String {
    cert.tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Fixture {
    doc: KeyEntry,
    tsa: KeyEntry,
    intermediate: KeyEntry,
    root: KeyEntry,
    responder: KeyEntry,
    anchors: CaSet,
    candidates: Vec<Certificate>,
    signature: Vec<u8>,
    signed_digest: DigestValue,
    algorithm: SigAlg,
}
impl Fixture {
    fn new() -> Self {
        Self::algorithm("inter-user-gost2015-sign", SigAlg::Gost2015_512, false)
    }
    fn algorithm(name: &str, algorithm: SigAlg, expired: bool) -> Self {
        let intermediate = entry("inter-gost2015.key");
        let root = entry("root-gost2015.key");
        let mut doc = entry(name);
        let mut spec = TestCertSpec::from_cert(&doc.cert);
        if expired {
            spec.validity.not_after = x509_time(datetime!(2026-01-01 00:00 UTC));
        }
        doc.cert = issue_cert(&intermediate, spec);
        let mut tsa = entry("tsa-gost2015");
        let mut tsa_spec = TestCertSpec::from_cert(&tsa.cert);
        tsa_spec.serial = vec![0x74, 0x04];
        tsa_spec.extensions.retain(|ext| {
            !matches!(
                ext.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        });
        let leaf = TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert);
        for mut extension in leaf.extensions {
            let uri = match extension.extn_id.to_string().as_str() {
                "1.3.6.1.5.5.7.1.1" => Some(TSA_STATUS),
                "2.5.29.31" => Some(TSA_CRL),
                _ => None,
            };
            if let Some(uri) = uri {
                extension.extn_value = OctetString::new(rewrite_uris(
                    extension.extn_value.as_bytes(),
                    uri.as_bytes(),
                ))
                .unwrap();
                tsa_spec.extensions.push(extension);
            }
        }
        tsa.cert = issue_cert(&intermediate, tsa_spec);
        let mut responder = entry("ocsp-gost2015");
        responder.cert = issue_cert(&intermediate, TestCertSpec::from_cert(&responder.cert));
        let signature = doc.key.sign(algorithm, DATA).unwrap();
        Self {
            anchors: CaSet::new(vec![root.cert.clone()]),
            candidates: vec![intermediate.cert.clone()],
            signed_digest: digest(algorithm.hash_alg(), DATA),
            algorithm,
            signature,
            doc,
            tsa,
            intermediate,
            root,
            responder,
        }
    }
    fn signer(&self) -> SignerEvidence<'_> {
        SignerEvidence {
            certificate: &self.doc.cert,
            algorithm: self.algorithm,
            signed_digest: self.signed_digest,
            signature: &self.signature,
            claimed_time: Some(CLAIM),
        }
    }
    fn context<'a>(
        &'a self,
        http: &'a dyn HttpTransport,
        policy: ValidationPolicy,
    ) -> ValidationContext<'a> {
        ValidationContext {
            policy,
            now: NOW,
            anchors: &self.anchors,
            intermediates: &self.candidates,
            http,
        }
    }
    fn ocsp(&self, certificate: &Certificate, status: Status) -> Option<Vec<u8>> {
        if matches!(status, Status::Missing) {
            return None;
        }
        let answer = match status {
            Status::Revoked(at) => CertStatus::Revoked {
                time: at,
                reason: Some(1),
            },
            _ => CertStatus::Good,
        };
        let tamper = match status {
            Status::WrongKey => OcspTamper::WrongKey,
            Status::OtherCert => OcspTamper::OtherCertId,
            _ => OcspTamper::None,
        };
        // Embedded status is judged at the proof time: stale means issued before it
        // (two hours before PROVEN), not old relative to NOW.
        let issued = if matches!(status, Status::Stale) {
            PROVEN - time::Duration::hours(2)
        } else {
            NOW
        };
        let responder = MockOcsp::new(self.responder.clone())
            .with_now(issued)
            .status(&serial(certificate), answer)
            .tamper(tamper);
        let body = ocsp::request_der(certificate, &self.intermediate.cert);
        Some(
            responder
                .send(&HttpRequest::post(
                    TSA_STATUS,
                    Some("application/ocsp-request"),
                    &body,
                    GetOptions::default(),
                ))
                .unwrap()
                .body,
        )
    }
    fn payloads(&self, doc: Status, tsa: Status) -> Vec<(EvidenceKind, Vec<u8>)> {
        let mut result = vec![
            (EvidenceKind::Certificate, self.root.cert.to_der().unwrap()),
            (
                EvidenceKind::Certificate,
                self.intermediate.cert.to_der().unwrap(),
            ),
            (EvidenceKind::Certificate, self.tsa.cert.to_der().unwrap()),
        ];
        if let Some(bytes) = self.ocsp(&self.doc.cert, doc) {
            result.push((EvidenceKind::Ocsp, bytes));
        }
        if let Some(bytes) = self.ocsp(&self.tsa.cert, tsa) {
            result.push((EvidenceKind::Ocsp, bytes));
        }
        result.push((
            EvidenceKind::Crl,
            MockCrl::new(self.root.clone())
                .with_this_update(NOW - time::Duration::MINUTE)
                .next_update(Some(NOW + time::Duration::HOUR))
                .der(),
        ));
        result
    }
    // Independent producer: real signed RFC3161 response from a fixed request/clock.
    // Extract without verifying so deliberately bad EKU/key tokens can reach the consumer.
    fn token_with(&self, key: KeyEntry, covered: &[u8], at: OffsetDateTime) -> Vec<u8> {
        let mut profile = TsaProfile::kalkan_default();
        profile.url = TSA_URL.into();
        profile.method = TsaMethod::Post;
        let imprint = Sha256::digest(covered);
        let request = tsp::request_der(&profile, &imprint, &[0x04, 0x01]);
        let response = MockTsa::new(key)
            .with_gen_time(at)
            .send(&HttpRequest::post(
                TSA_URL,
                Some("application/timestamp-query"),
                &request,
                GetOptions::default(),
            ))
            .unwrap();
        assert_eq!(
            response.status,
            200,
            "synthetic TSA failed before DER extraction: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(
            response.content_type.as_deref(),
            Some("application/timestamp-reply")
        );
        children(&response.body)[1].clone()
    }
    fn token(&self, covered: &[u8], at: OffsetDateTime) -> Vec<u8> {
        self.token_with(self.tsa.clone(), covered, at)
    }
}
#[derive(Clone, Copy)]
enum Status {
    Good,
    Missing,
    Stale,
    WrongKey,
    OtherCert,
    Revoked(OffsetDateTime),
}

fn collect(store: &mut EvidenceStore, kind: EvidenceKind, bytes: &[u8]) -> EvidenceId {
    store
        .collect(
            kind,
            Source::sequential(&mut &*bytes, Some(bytes.len() as u64)),
            EvidenceOrigin::Embedded {
                label: "synthetic public DER",
            },
        )
        .unwrap()
}
struct Case {
    bundle: EvidenceBundle,
    ids: Vec<EvidenceId>,
    signature_token: EvidenceId,
    archive_token: Option<EvidenceId>,
    archive_coverage: Vec<CoveragePart<'static>>,
}
fn prepare(
    scope: &mut ResourceScope,
    parent: &std::path::Path,
    payloads: &[(EvidenceKind, Vec<u8>)],
    token: &[u8],
    archive: Option<&[u8]>,
) -> Case {
    prepare_limited(scope, parent, payloads, token, archive, evidence_limits())
}
fn prepare_limited(
    scope: &mut ResourceScope,
    parent: &std::path::Path,
    payloads: &[(EvidenceKind, Vec<u8>)],
    token: &[u8],
    archive: Option<&[u8]>,
    evidence: EvidenceLimits,
) -> Case {
    let mut store =
        EvidenceStore::new(TemporaryStore::new(parent).unwrap(), evidence, scope).unwrap();
    let mut ids = Vec::new();
    for (kind, bytes) in payloads {
        ids.push(collect(&mut store, *kind, bytes));
    }
    let signature_token = collect(&mut store, EvidenceKind::Timestamp, token);
    let mut archive_coverage = vec![CoveragePart::Signature];
    archive_coverage.extend(
        ids.iter()
            .chain(std::iter::once(&signature_token))
            .map(|id| CoveragePart::Evidence {
                id: *id,
                encoding: CoverageEncoding::Raw,
            }),
    );
    let archive_token = archive.map(|bytes| collect(&mut store, EvidenceKind::Timestamp, bytes));
    Case {
        bundle: store.finish(),
        ids,
        signature_token,
        archive_token,
        archive_coverage,
    }
}
fn archive_bytes(signature: &[u8], payloads: &[(EvidenceKind, Vec<u8>)], token: &[u8]) -> Vec<u8> {
    let mut covered = signature.to_vec();
    for (_, bytes) in payloads {
        covered.extend_from_slice(bytes);
    }
    covered.extend_from_slice(token);
    covered
}
fn validate(
    fixture: &Fixture,
    case: &mut Case,
    level: AdesLevel,
    resources: &ResourceScope,
    http: &dyn HttpTransport,
) -> ValidationReport {
    let signature_coverage = [CoveragePart::Signature];
    let mut proofs = vec![TimestampBinding {
        token: case.signature_token,
        kind: ProofKind::Signature,
        coverage: &signature_coverage,
    }];
    if let Some(token) = case.archive_token {
        proofs.push(TimestampBinding {
            token,
            kind: ProofKind::Archive,
            coverage: &case.archive_coverage,
        });
    }
    validate_evidence(
        &fixture.signer(),
        &mut case.bundle,
        &proofs,
        level,
        &fixture.context(http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        resources,
    )
    .unwrap()
}
fn assert_proven(report: &ValidationReport, token: EvidenceId) {
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.checked_at, NOW);
    assert_eq!(report.signers.len(), 1);
    let signer = &report.signers[0];
    assert_eq!(signer.signature, CheckStatus::Passed);
    assert_eq!(signer.timestamp, CheckStatus::Passed);
    assert_eq!(signer.time_basis, TimeBasis::VerifiedTimestamp(PROVEN));
    let proof = signer
        .proof_time
        .as_ref()
        .expect("only a fully verified proof is published");
    assert_eq!(proof.at(), PROVEN);
    assert_eq!(proof.token(), token);
}

#[test]
fn claimed_time_is_not_poe() {
    // Bug: use a caller's historical claim to rescue an expired certificate.
    let fixture = Fixture::algorithm("inter-user-gost2015-sign", SigAlg::Gost2015_512, true);
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    for (kind, bytes) in fixture.payloads(Status::Good, Status::Good) {
        collect(&mut store, kind, &bytes);
    }
    let mut bundle = store.finish();
    let http = Offline::new();
    let report = validate_evidence(
        &fixture.signer(),
        &mut bundle,
        &[],
        AdesLevel::B,
        &fixture.context(&http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        &resources,
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].validity, CheckStatus::Failed);
    assert_eq!(report.signers[0].claimed_signing_time, Some(CLAIM));
    assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
    assert!(report.signers[0].proof_time.is_none());
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
}

#[test]
fn revoked_after_proven_time() {
    // Bug: either accept claimed time, or reject genuine proof solely for later revocation.
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Revoked(REVOKED), Status::Good),
        &token,
        None,
    );
    let http = Offline::new();
    let report = validate(&fixture, &mut case, AdesLevel::Lt, &resources, &http);
    assert_proven(&report, case.signature_token);
    assert!(
        report.signers[0]
            .reasons
            .contains(&ValidationReason::RevokedAfterProvenTime { at: REVOKED })
    );
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
}

#[test]
fn document_revoked_before_or_at_proof_is_invalid() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    for at in [PROVEN - time::Duration::SECOND, PROVEN] {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &fixture.payloads(Status::Revoked(at), Status::Good),
            &token,
            None,
        );
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::T,
            &resources,
            &Offline::new(),
        );
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.signers[0].revocation, CheckStatus::Failed);
        assert!(
            report.signers[0]
                .reasons
                .contains(&ValidationReason::Revoked { at })
        );
    }
}

#[test]
fn archive_timestamp_covers_prior_evidence() {
    // Bug: archive token field/enum presence is accepted without replaying protected bytes.
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let archive = fixture.token(
        &archive_bytes(&fixture.signature, &payloads, &token),
        ARCHIVE,
    );
    for changed in [false, true] {
        let mut actual = payloads.clone();
        if changed {
            // A DIFFERENT valid signed CRL, not random parser damage.
            actual.last_mut().unwrap().1 = MockCrl::new(fixture.root.clone())
                .with_this_update(NOW - time::Duration::minutes(2))
                .next_update(Some(NOW + time::Duration::HOUR))
                .der();
        }
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &actual,
            &token,
            Some(&archive),
        );
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::Lta,
            &resources,
            &Offline::new(),
        );
        if changed {
            assert_eq!(report.verdict, Verdict::Invalid);
            assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
        } else {
            assert_proven(&report, case.signature_token);
        }
    }
}

#[test]
fn archive_rejects_changed_order_and_changed_earlier_proof() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let archive = fixture.token(
        &archive_bytes(&fixture.signature, &payloads, &token),
        ARCHIVE,
    );
    for mutation in [0, 1] {
        let mut actual = payloads.clone();
        let changed_token = fixture.token(&fixture.signature, PROVEN + time::Duration::SECOND);
        if mutation == 0 {
            actual.swap(0, 1);
        }
        let imported = if mutation == 1 {
            &changed_token
        } else {
            &token
        };
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &actual,
            imported,
            Some(&archive),
        );
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::Lta,
            &resources,
            &Offline::new(),
        );
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    }
}

#[test]
fn archive_binding_cannot_omit_duplicate_reorder_or_self_reference() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let archive = fixture.token(
        &archive_bytes(&fixture.signature, &payloads, &token),
        ARCHIVE,
    );
    for mutation in 0..4 {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &payloads,
            &token,
            Some(&archive),
        );
        match mutation {
            0 => {
                case.archive_coverage.pop();
            }
            1 => {
                case.archive_coverage.push(CoveragePart::Evidence {
                    id: case.ids[0],
                    encoding: CoverageEncoding::Raw,
                });
            }
            2 => {
                case.archive_coverage.swap(1, 2);
            }
            _ => {
                case.archive_coverage.push(CoveragePart::Evidence {
                    id: case.archive_token.unwrap(),
                    encoding: CoverageEncoding::Raw,
                });
            }
        }
        let signature = [CoveragePart::Signature];
        let proofs = [
            TimestampBinding {
                token: case.signature_token,
                kind: ProofKind::Signature,
                coverage: &signature,
            },
            TimestampBinding {
                token: case.archive_token.unwrap(),
                kind: ProofKind::Archive,
                coverage: &case.archive_coverage,
            },
        ];
        let http = Offline::new();
        assert!(matches!(
            validate_evidence(
                &fixture.signer(),
                &mut case.bundle,
                &proofs,
                AdesLevel::Lta,
                &fixture.context(&http, ValidationPolicy::OfflineReport),
                &NetworkPolicy::deny_all(),
                &resources
            ),
            Err(EvidenceError::InvalidBinding)
        ));
    }
}

#[test]
fn archive_cannot_backdate_an_earlier_proof() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let archive = fixture.token(
        &archive_bytes(&fixture.signature, &payloads, &token),
        PROVEN - time::Duration::SECOND,
    );
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &payloads,
        &token,
        Some(&archive),
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::Lta,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
}

#[test]
fn wrong_imprint_is_not_proof_even_with_a_real_trusted_tsa_signature() {
    let fixture = Fixture::new();
    let token = fixture.token(b"different signature", PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Good, Status::Good),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    assert!(report.signers[0].proof_time.is_none());
    assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
}

#[test]
fn invalid_signature_and_missing_eku_tsa_tokens_are_not_proof() {
    let fixture = Fixture::new();
    let mut wrong_key = fixture.tsa.clone();
    wrong_key.key = entry("user-gost2015-sign").key;
    for tsa in [wrong_key, fixture.doc.clone()] {
        let token = fixture.token_with(tsa, &fixture.signature, PROVEN);
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &fixture.payloads(Status::Good, Status::Good),
            &token,
            None,
        );
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::T,
            &resources,
            &Offline::new(),
        );
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
        assert!(report.signers[0].proof_time.is_none());
    }
}

#[test]
fn carried_chain_never_becomes_tsa_or_document_anchor() {
    let mut fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let payloads = fixture.payloads(Status::Good, Status::Good);
    fixture.anchors = CaSet::new(vec![]);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(&mut resources, parent.path(), &payloads, &token, None);
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].chain, CheckStatus::Failed);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    assert!(report.signers[0].proof_time.is_none());
}

#[test]
fn tsa_revocation_at_proof_is_invalid_but_later_revocation_allows_proof() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    for at in [
        PROVEN - time::Duration::SECOND,
        PROVEN,
        PROVEN + time::Duration::SECOND,
    ] {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &fixture.payloads(Status::Good, Status::Revoked(at)),
            &token,
            None,
        );
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::T,
            &resources,
            &Offline::new(),
        );
        if at > PROVEN {
            assert_proven(&report, case.signature_token);
            assert!(
                report.signers[0]
                    .reasons
                    .contains(&ValidationReason::TimestampRevokedAfterProof { at })
            );
        } else {
            assert_eq!(report.verdict, Verdict::Invalid);
            assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
            assert!(
                report.signers[0]
                    .reasons
                    .contains(&ValidationReason::TimestampRevoked { at })
            );
            assert!(report.signers[0].proof_time.is_none());
        }
    }
}

#[test]
fn missing_stale_wrong_key_or_unrelated_tsa_status_never_promotes_time() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    for tsa in [
        Status::Missing,
        Status::Stale,
        Status::WrongKey,
        Status::OtherCert,
    ] {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &fixture.payloads(Status::Good, tsa),
            &token,
            None,
        );
        let http = Offline::new();
        let report = validate(&fixture, &mut case, AdesLevel::Lt, &resources, &http);
        assert_eq!(report.verdict, Verdict::Indeterminate);
        assert_eq!(report.signers[0].timestamp, CheckStatus::Unavailable);
        assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
        assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
        assert!(report.signers[0].proof_time.is_none());
        assert!(
            report.signers[0]
                .reasons
                .contains(&ValidationReason::TimestampRevocationUnavailable)
        );
        assert_eq!(
            http.0.load(Ordering::SeqCst),
            0,
            "offline never fills embedded evidence from network"
        );
    }
}

#[test]
fn stale_tsa_status_does_not_excuse_current_document_revocation() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Revoked(REVOKED), Status::Stale),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::Lt,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Unavailable);
    assert_eq!(report.signers[0].revocation, CheckStatus::Failed);
    assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
}

#[test]
fn missing_archive_token_does_not_satisfy_lta() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Good, Status::Good),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::Lta,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Unavailable);
}

#[test]
fn bad_signer_signature_cannot_be_rescued_by_a_valid_timestamp() {
    let mut fixture = Fixture::new();
    fixture.signature[0] ^= 1;
    let token = fixture.token(&fixture.signature, PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Good, Status::Good),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].signature, CheckStatus::Failed);
}

#[test]
fn proof_is_bound_to_each_supported_signer_algorithm() {
    for (name, algorithm) in [
        ("user-gost2004-sign", SigAlg::Gost2004),
        ("inter-user-gost2015-sign", SigAlg::Gost2015_512),
        ("user-rsa-sign", SigAlg::RsaSha256),
    ] {
        let fixture = Fixture::algorithm(name, algorithm, false);
        let token = fixture.token(&fixture.signature, PROVEN);
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &fixture.payloads(Status::Good, Status::Good),
            &token,
            None,
        );
        assert_proven(
            &validate(
                &fixture,
                &mut case,
                AdesLevel::T,
                &resources,
                &Offline::new(),
            ),
            case.signature_token,
        );
    }
}

struct BoundedTsa {
    inner: MockTsa,
    requests: AtomicUsize,
}
impl HttpTransport for BoundedTsa {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        // Assert an actual consumer boundary, not a mock echo: no document enters HTTP.
        assert_eq!(request.content_type, Some("application/timestamp-query"));
        assert!(request.body.len() < 1024);
        assert!(request.opts.max_len <= MAX_RESPONSE_LEN);
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.inner.send(request)
    }
}
fn request_spec() -> TsaSpec {
    let mut profile = TsaProfile::kalkan_default();
    profile.url = TSA_URL.into();
    profile.method = TsaMethod::Post;
    let mut spec = TsaSpec::from(profile);
    spec.nonce = oncl_pki::http::NonceSpec::Value(vec![0x04, 0x02]);
    spec
}

#[test]
fn only_correct_bounded_imprint_reaches_tsa_after_incremental_document_hash() {
    // Bug: send the original document or hash an already-computed imprint again.
    let fixture = Fixture::new();
    let mut resources = scope();
    let mut input = RecordSource {
        position: 0,
        len: 3 * IO_CHUNK_BYTES as u64 + 37,
        largest_read: 0,
    };
    let len = input.len;
    let document_digest = hash_source(
        Source::sequential(&mut input, Some(len)),
        fixture.algorithm.hash_alg(),
        &mut resources,
    )
    .unwrap();
    assert_eq!(input.position, len);
    assert!(input.largest_read <= IO_CHUNK_BYTES);
    let mut signing_key = fixture.doc.clone();
    let signature =
        oncl_pki::key::DigestSigner::sign_digest(&mut signing_key, &document_digest).unwrap();
    let signer = SignerEvidence {
        certificate: &fixture.doc.cert,
        algorithm: fixture.algorithm,
        signed_digest: document_digest,
        signature: &signature,
        claimed_time: None,
    };
    let tsa = BoundedTsa {
        inner: MockTsa::new(fixture.tsa.clone()).with_gen_time(PROVEN),
        requests: AtomicUsize::new(0),
    };
    let ctx = fixture.context(&tsa, ValidationPolicy::StrictOnline);
    let network = NetworkPolicy::only_endpoints([TSA_URL]).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let id = store
        .request_timestamp(
            &signer,
            &[CoveragePart::Signature],
            &request_spec(),
            &ctx,
            &network,
        )
        .unwrap();
    let mut bundle = store.finish();
    let mut token = Vec::new();
    bundle.copy_entry(id, &mut token).unwrap();
    let (info, _) = tsp::verify_token_for(&token, &signature).unwrap();
    assert_eq!(info.imprint_alg, HashAlg::Sha256.oid());
    assert_eq!(info.imprint, Sha256::digest(&signature).as_slice());
    assert_eq!(tsa.requests.load(Ordering::SeqCst), 1);
    assert_eq!(bundle.entry(id).unwrap().source(), TSA_URL);
    assert_eq!(bundle.entry(id).unwrap().obtained_at(), Some(NOW));
}

#[test]
fn archive_request_uses_exact_base64_and_literal_coverage_without_hidden_manifest() {
    let fixture = Fixture::new();
    let payload = fixture.root.cert.to_der().unwrap();
    let tsa = BoundedTsa {
        inner: MockTsa::new(fixture.tsa.clone()).with_gen_time(ARCHIVE),
        requests: AtomicUsize::new(0),
    };
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let cert = collect(&mut store, EvidenceKind::Certificate, &payload);
    let parts = [
        CoveragePart::Bytes(b"<proof>"),
        CoveragePart::Signature,
        CoveragePart::Bytes(b"<certificate>"),
        CoveragePart::Evidence {
            id: cert,
            encoding: CoverageEncoding::Base64,
        },
        CoveragePart::Bytes(b"</certificate></proof>"),
    ];
    let token = store
        .request_timestamp(
            &fixture.signer(),
            &parts,
            &request_spec(),
            &fixture.context(&tsa, ValidationPolicy::StrictOnline),
            &NetworkPolicy::only_endpoints([TSA_URL]).unwrap(),
        )
        .unwrap();
    let mut bundle = store.finish();
    let mut bytes = Vec::new();
    bundle.copy_entry(token, &mut bytes).unwrap();
    let info = tsp::verify_token(&bytes).unwrap();
    let mut exact = b"<proof>".to_vec();
    exact.extend_from_slice(&fixture.signature);
    exact.extend_from_slice(b"<certificate>");
    exact.extend_from_slice(STANDARD.encode(&payload).as_bytes());
    exact.extend_from_slice(b"</certificate></proof>");
    assert_eq!(info.imprint, Sha256::digest(&exact).as_slice());
}

struct PanicRead;
impl Read for PanicRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("quota admission must precede source read")
    }
}
#[test]
fn count_item_byte_and_total_quotas_reject_before_reading_known_length() {
    let fixture = Fixture::new();
    let certificate = fixture.root.cert.to_der().unwrap();
    for quota in 0..3 {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut cap = evidence_limits();
        match quota {
            0 => cap.max_items = 1,
            1 => cap.max_item_bytes = certificate.len() as u64,
            _ => cap.max_bytes = certificate.len() as u64,
        }
        let mut store = EvidenceStore::new(
            TemporaryStore::new(parent.path()).unwrap(),
            cap,
            &mut resources,
        )
        .unwrap();
        collect(&mut store, EvidenceKind::Certificate, &certificate);
        let declared = if quota == 1 {
            certificate.len() as u64 + 1
        } else {
            certificate.len() as u64
        };
        assert!(matches!(
            store.collect(
                EvidenceKind::Certificate,
                Source::sequential(&mut PanicRead, Some(declared)),
                EvidenceOrigin::Embedded { label: "oversize" }
            ),
            Err(EvidenceError::Limit)
        ));
    }
}

#[test]
fn unknown_length_evidence_cannot_evade_item_quota() {
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut cap = evidence_limits();
    cap.max_item_bytes = 100;
    cap.max_crl_item_bytes = 100;
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        cap,
        &mut resources,
    )
    .unwrap();
    let mut reader = RecordSource {
        position: 0,
        len: 10_000,
        largest_read: 0,
    };
    assert!(matches!(
        store.collect(
            EvidenceKind::Crl,
            Source::sequential(&mut reader, None),
            EvidenceOrigin::Embedded {
                label: "untrusted length"
            }
        ),
        Err(EvidenceError::Limit)
    ));
    assert!(
        reader.position <= 101,
        "at most one byte probes the exact cap"
    );
    assert!(reader.largest_read <= 101);
}

#[test]
fn chain_proof_and_coverage_work_limits_fail_closed() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    for quota in 0..4 {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut cap = evidence_limits();
        match quota {
            0 => cap.max_chain_len = 1,
            1 => cap.max_proofs = 1,
            2 => cap.max_coverage_parts = 1,
            _ => cap.max_coverage_bytes = 1,
        }
        let mut store = EvidenceStore::new(
            TemporaryStore::new(parent.path()).unwrap(),
            cap,
            &mut resources,
        )
        .unwrap();
        for (kind, bytes) in &payloads {
            collect(&mut store, *kind, bytes);
        }
        let id = collect(&mut store, EvidenceKind::Timestamp, &token);
        let second = if quota == 1 {
            Some(collect(&mut store, EvidenceKind::Timestamp, &token))
        } else {
            None
        };
        let mut bundle = store.finish();
        let signature = [CoveragePart::Signature];
        let too_many = [CoveragePart::Signature, CoveragePart::Bytes(b"excess")];
        let mut proofs = vec![TimestampBinding {
            token: id,
            kind: ProofKind::Signature,
            coverage: if quota == 2 { &too_many } else { &signature },
        }];
        if let Some(id) = second {
            proofs.push(TimestampBinding {
                token: id,
                kind: ProofKind::Signature,
                coverage: &signature,
            });
        }
        let http = Offline::new();
        assert!(matches!(
            validate_evidence(
                &fixture.signer(),
                &mut bundle,
                &proofs,
                AdesLevel::T,
                &fixture.context(&http, ValidationPolicy::OfflineReport),
                &NetworkPolicy::deny_all(),
                &resources
            ),
            Err(EvidenceError::Limit)
        ));
        assert_eq!(http.0.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn foreign_evidence_id_cannot_bind_another_bundle_with_same_index() {
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut first = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let foreign = collect(
        &mut first,
        EvidenceKind::Certificate,
        &fixture.root.cert.to_der().unwrap(),
    );
    let _first = first.finish();
    let mut second = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    collect(
        &mut second,
        EvidenceKind::Certificate,
        &fixture.root.cert.to_der().unwrap(),
    );
    let token = fixture.token(&fixture.signature, PROVEN);
    let id = collect(&mut second, EvidenceKind::Timestamp, &token);
    let mut bundle = second.finish();
    assert!(bundle.entry(foreign).is_none());
    let parts = [
        CoveragePart::Signature,
        CoveragePart::Evidence {
            id: foreign,
            encoding: CoverageEncoding::Raw,
        },
    ];
    let bindings = [TimestampBinding {
        token: id,
        kind: ProofKind::Archive,
        coverage: &parts,
    }];
    let http = Offline::new();
    assert!(matches!(
        validate_evidence(
            &fixture.signer(),
            &mut bundle,
            &bindings,
            AdesLevel::Lta,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources
        ),
        Err(EvidenceError::InvalidBinding)
    ));
}

#[test]
fn bundle_and_moved_signers_retain_original_admission_until_actual_drop() {
    let fixture = Fixture::new();
    let budget = Arc::new(SharedBudget::new(limits()).unwrap());
    let mut resources = budget.begin(limits(), Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Good, Status::Good),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::Lt,
        &resources,
        &Offline::new(),
    );
    let signers = report.signers;
    drop(resources);
    assert!(matches!(
        budget.begin(limits(), Arc::new(Control)),
        Err(ProcessingError::CapacityExceeded)
    ));
    drop(case);
    assert!(
        matches!(
            budget.begin(limits(), Arc::new(Control)),
            Err(ProcessingError::CapacityExceeded)
        ),
        "a real result consumer still owns verified facts"
    );
    assert_eq!(signers[0].proof_time.as_ref().unwrap().at(), PROVEN);
    drop(signers);
    assert!(budget.begin(limits(), Arc::new(Control)).is_ok());
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn bundle_holds_scratch_budget_and_cleanup_never_removes_unrelated_files() {
    let fixture = Fixture::new();
    let bytes = fixture.root.cert.to_der().unwrap();
    let mut cap = limits();
    cap.max_in_flight = 2;
    cap.temp_bytes = bytes.len() as u64;
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut first = budget.begin(cap.clone(), Arc::new(Control)).unwrap();
    let second = budget.begin(cap.clone(), Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let sentinel = parent.path().join("unrelated");
    std::fs::write(&sentinel, b"preserve me").unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut first,
    )
    .unwrap();
    collect(&mut store, EvidenceKind::Certificate, &bytes);
    let bundle = store.finish();
    drop(first);
    assert!(matches!(
        second.reserve_temp(1),
        Err(ProcessingError::TempLimit)
    ));
    drop(bundle);
    assert!(second.reserve_temp(bytes.len() as u64).is_ok());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve me");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
}

struct Interrupt(AtomicUsize);
impl OperationControl for Interrupt {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        match self.0.load(Ordering::SeqCst) {
            1 => Err(ProcessingError::Cancelled),
            2 => Err(ProcessingError::DeadlineExceeded),
            _ => Ok(()),
        }
    }
}
#[test]
fn original_cancel_or_deadline_remains_typed_after_scope_drop() {
    let fixture = Fixture::new();
    for interruption in [1, 2] {
        let control = Arc::new(Interrupt(AtomicUsize::new(0)));
        let budget = Arc::new(SharedBudget::new(limits()).unwrap());
        let mut resources = budget.begin(limits(), control.clone()).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut store = EvidenceStore::new(
            TemporaryStore::new(parent.path()).unwrap(),
            evidence_limits(),
            &mut resources,
        )
        .unwrap();
        let id = collect(
            &mut store,
            EvidenceKind::Certificate,
            &fixture.root.cert.to_der().unwrap(),
        );
        let mut bundle = store.finish();
        drop(resources);
        control.0.store(interruption, Ordering::SeqCst);
        let result = bundle.copy_entry(id, &mut io::sink());
        assert!(matches!(
            (interruption, result),
            (
                1,
                Err(EvidenceError::Processing(ProcessingError::Cancelled))
            ) | (
                2,
                Err(EvidenceError::Processing(ProcessingError::DeadlineExceeded))
            )
        ));
        drop(bundle);
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

struct InterruptingNetwork {
    control: Arc<Interrupt>,
    ordinary: bool,
}
impl HttpTransport for InterruptingNetwork {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        if !self.ordinary {
            self.control.0.store(1, Ordering::SeqCst);
        }
        Err(HttpError::new(
            HttpErrorKind::Timeout,
            "synthetic request timeout",
        ))
    }
}
#[test]
fn network_timeout_is_not_global_cancel_and_global_cancel_is_not_unavailable() {
    let fixture = Fixture::new();
    for ordinary in [false, true] {
        let control = Arc::new(Interrupt(AtomicUsize::new(0)));
        let budget = Arc::new(SharedBudget::new(limits()).unwrap());
        let mut resources = budget.begin(limits(), control.clone()).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut store = EvidenceStore::new(
            TemporaryStore::new(parent.path()).unwrap(),
            evidence_limits(),
            &mut resources,
        )
        .unwrap();
        let http = InterruptingNetwork { control, ordinary };
        let result = store.request_timestamp(
            &fixture.signer(),
            &[CoveragePart::Signature],
            &request_spec(),
            &fixture.context(&http, ValidationPolicy::StrictOnline),
            &NetworkPolicy::only_endpoints([TSA_URL]).unwrap(),
        );
        if ordinary {
            assert!(matches!(result, Err(EvidenceError::Timestamp(_))));
        } else {
            assert!(matches!(
                result,
                Err(EvidenceError::Processing(ProcessingError::Cancelled))
            ));
        }
    }
}

#[test]
fn unauthorized_tsa_endpoint_never_reaches_transport() {
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let http = Offline::new();
    assert!(
        store
            .request_timestamp(
                &fixture.signer(),
                &[CoveragePart::Signature],
                &request_spec(),
                &fixture.context(&http, ValidationPolicy::StrictOnline),
                &NetworkPolicy::deny_all()
            )
            .is_err()
    );
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
}

#[test]
fn large_real_signed_crl_is_region_backed_and_replayed_after_context_drop() {
    let fixture = Fixture::new();
    // Public noncritical extension makes a real signed CRL span >2 I/O chunks.
    let extension = Extension {
        extn_id: "1.3.6.1.4.1.55555.4".parse().unwrap(),
        critical: false,
        extn_value: OctetString::new(vec![0x5a; 2 * IO_CHUNK_BYTES + 13]).unwrap(),
    };
    let crl = MockCrl::new(fixture.root.clone())
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .extension(extension)
        .der();
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let id = collect(&mut store, EvidenceKind::Crl, &crl);
    let mut bundle = store.finish();
    let item = bundle.entry(id).unwrap();
    assert_eq!(item.kind(), EvidenceKind::Crl);
    assert_eq!(item.region().len, crl.len() as u64);
    drop(resources);
    struct Compare<'a> {
        remaining: &'a [u8],
        largest_write: usize,
    }
    impl Write for Compare<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            assert!(bytes.len() <= IO_CHUNK_BYTES);
            assert!(self.remaining.starts_with(bytes));
            self.largest_write = self.largest_write.max(bytes.len());
            self.remaining = &self.remaining[bytes.len()..];
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut compare = Compare {
        remaining: &crl,
        largest_write: 0,
    };
    assert_eq!(
        bundle.copy_entry(id, &mut compare).unwrap(),
        crl.len() as u64
    );
    assert!(compare.remaining.is_empty());
    assert!(compare.largest_write > 0);
    drop(bundle);
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

struct RecordSource {
    position: u64,
    len: u64,
    largest_read: usize,
}
impl Read for RecordSource {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.largest_read = self.largest_read.max(output.len());
        let n = (self.len - self.position).min(output.len() as u64) as usize;
        for (index, byte) in output[..n].iter_mut().enumerate() {
            let offset = self.position + index as u64;
            *byte = (offset / 8).to_le_bytes()[(offset % 8) as usize];
        }
        self.position += n as u64;
        Ok(n)
    }
}
#[test]
fn common_region_replay_bounds_and_append_position_are_checked() {
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(&mut resources).unwrap();
    artifact.write_chunk(b"0123456789").unwrap();
    let mut bytes = [0; 3];
    assert_eq!(
        artifact
            .read_region(Region { offset: 2, len: 3 }, &mut bytes)
            .unwrap(),
        3
    );
    assert_eq!(&bytes, b"234");
    artifact.write_chunk(b"ABC").unwrap();
    assert_eq!(artifact.len(), 13);
    let mut all = [0; 13];
    assert_eq!(
        artifact
            .read_region(Region { offset: 0, len: 13 }, &mut all)
            .unwrap(),
        13
    );
    assert_eq!(&all, b"0123456789ABC");
    for region in [
        Region { offset: 13, len: 1 },
        Region {
            offset: u64::MAX,
            len: 2,
        },
    ] {
        assert!(matches!(
            artifact.read_region(region, &mut bytes),
            Err(ProcessingError::InvalidInput(_))
        ));
        assert!(matches!(
            artifact.read_region(region, &mut []),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
    assert_eq!(
        artifact
            .read_region(Region { offset: 13, len: 0 }, &mut bytes)
            .unwrap(),
        0
    );
}

#[test]
#[ignore = "writes 4_294_967_328 real record bytes; controller opts into disk boundary run"]
fn common_region_replay_crosses_four_gib_without_u32_truncation() {
    let cap = ResourceLimits {
        input_bytes: 4_294_967_328,
        temp_bytes: 4_294_967_328,
        output_bytes: 4_294_967_328,
        operation_timeout: Duration::from_secs(1800),
        ..limits()
    };
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap, Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(&mut resources).unwrap();
    let _memory = resources.reserve_memory(IO_CHUNK_BYTES as u64).unwrap();
    let mut buffer = vec![0; IO_CHUNK_BYTES];
    let mut source = RecordSource {
        position: 0,
        len: 4_294_967_328,
        largest_read: 0,
    };
    loop {
        let n = source.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        artifact.write_chunk(&buffer[..n]).unwrap();
    }
    assert_eq!(artifact.len(), 4_294_967_328);
    let mut boundary = [0; 40];
    assert_eq!(
        artifact
            .read_region(
                Region {
                    offset: 4_294_967_288,
                    len: 40
                },
                &mut boundary
            )
            .unwrap(),
        40
    );
    let expected = [
        0xff, 0xff, 0xff, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 1, 0, 0, 0x20, 0, 0, 0, 0,
        2, 0, 0, 0x20, 0, 0, 0, 0, 3, 0, 0, 0x20, 0, 0, 0, 0,
    ];
    assert_eq!(boundary, expected);
}

#[test]
fn genuine_proof_rescues_expiry_but_future_timestamp_does_not() {
    let fixture = Fixture::algorithm("inter-user-gost2015-sign", SigAlg::Gost2015_512, true);
    for at in [PROVEN, NOW + time::Duration::SECOND] {
        let token = fixture.token(&fixture.signature, at);
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &fixture.payloads(Status::Good, Status::Good),
            &token,
            None,
        );
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::T,
            &resources,
            &Offline::new(),
        );
        if at == PROVEN {
            assert_proven(&report, case.signature_token);
            assert_eq!(report.signers[0].validity, CheckStatus::Passed);
        } else {
            assert_eq!(report.verdict, Verdict::Invalid);
            assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
            assert_eq!(report.signers[0].validity, CheckStatus::Failed);
            assert!(report.signers[0].proof_time.is_none());
        }
    }
}

#[test]
fn untrusted_tsa_path_does_not_invalidate_otherwise_trusted_document_chain() {
    let mut fixture = Fixture::new();
    // MockTsa uses legacy CMS signing, whose algorithm follows the issuing
    // certificate's signature algorithm; keep this trust test within its
    // same-algorithm fixture profile, with an actually distinct foreign CA.
    let mut foreign = entry("user-gost2015-sign");
    let public = TestCertSpec::from_cert(&foreign.cert);
    let mut ca = TestCertSpec::from_cert(&fixture.root.cert);
    ca.subject = public.subject;
    ca.public_key = public.public_key;
    ca.serial = vec![0x66, 0x04];
    foreign.cert = issue_cert(&foreign, ca);
    fixture.tsa.cert = issue_cert(&foreign, TestCertSpec::from_cert(&fixture.tsa.cert));
    oncl_pki::cert::verify_signature(&foreign.cert, &foreign.cert).unwrap();
    oncl_pki::cert::verify_signature(&fixture.tsa.cert, &foreign.cert).unwrap();
    assert!(!fixture.anchors.certs().contains(&foreign.cert));
    fixture.candidates.push(foreign.cert.clone());
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut payloads = fixture.payloads(Status::Good, Status::Good);
    payloads.push((EvidenceKind::Certificate, foreign.cert.to_der().unwrap()));
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(&mut resources, parent.path(), &payloads, &token, None);
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].chain, CheckStatus::Passed);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    assert!(report.signers[0].proof_time.is_none());
}

#[test]
fn tsa_certificate_outside_validity_at_gentime_is_not_proof() {
    let mut fixture = Fixture::new();
    let mut spec = TestCertSpec::from_cert(&fixture.tsa.cert);
    spec.validity.not_after = x509_time(PROVEN - time::Duration::SECOND);
    fixture.tsa.cert = issue_cert(&fixture.intermediate, spec);
    let token = fixture.token(&fixture.signature, PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Good, Status::Good),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].chain, CheckStatus::Passed);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    assert!(report.signers[0].proof_time.is_none());
}

#[test]
fn revoked_tsa_intermediate_is_checked_not_only_timestamp_leaf() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut payloads = fixture.payloads(Status::Good, Status::Good);
    payloads.last_mut().unwrap().1 = MockCrl::new(fixture.root.clone())
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .revoke(
            fixture
                .intermediate
                .cert
                .tbs_certificate()
                .serial_number()
                .as_bytes(),
            PROVEN,
        )
        .der();
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(&mut resources, parent.path(), &payloads, &token, None);
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    assert!(report.signers[0].proof_time.is_none());
}

#[test]
fn missing_embedded_document_status_is_not_lt_even_with_valid_tsa_status() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Missing, Status::Good),
        &token,
        None,
    );
    let http = Offline::new();
    let report = validate(&fixture, &mut case, AdesLevel::Lt, &resources, &http);
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
}

#[test]
fn missing_signature_proof_does_not_satisfy_t() {
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    for (kind, bytes) in fixture.payloads(Status::Good, Status::Good) {
        collect(&mut store, kind, &bytes);
    }
    let mut bundle = store.finish();
    let http = Offline::new();
    let report = validate_evidence(
        &fixture.signer(),
        &mut bundle,
        &[],
        AdesLevel::T,
        &fixture.context(&http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        &resources,
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Unavailable);
    assert!(report.signers[0].proof_time.is_none());
}

#[test]
fn moved_report_facts_keep_live_memory_and_metadata_charges() {
    let fixture = Fixture::new();
    let mut cap = limits();
    cap.max_in_flight = 2;
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap.clone(), Arc::new(Control)).unwrap();
    let consumer = budget.begin(cap.clone(), Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Good, Status::Good),
        &token,
        None,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::Lt,
        &resources,
        &Offline::new(),
    );
    let signers = report.signers;
    drop(case);
    drop(resources);
    assert!(matches!(
        consumer.reserve_memory(cap.memory_bytes),
        Err(ProcessingError::MemoryLimit)
    ));
    assert!(matches!(
        consumer.reserve_metadata(cap.metadata_bytes),
        Err(ProcessingError::MetadataLimit)
    ));
    assert_eq!(signers[0].proof_time.as_ref().unwrap().at(), PROVEN);
    drop(signers);
    assert!(consumer.reserve_memory(cap.memory_bytes).is_ok());
    assert!(consumer.reserve_metadata(cap.metadata_bytes).is_ok());
}

#[test]
fn evidence_spool_enforces_shared_memory_metadata_and_temp_limits() {
    let fixture = Fixture::new();
    let bytes = fixture.root.cert.to_der().unwrap();
    for resource in 0..3 {
        let mut cap = limits();
        match resource {
            0 => cap.memory_bytes = 0,
            1 => cap.metadata_bytes = 0,
            _ => cap.temp_bytes = 0,
        }
        let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
        let mut resources = budget.begin(cap, Arc::new(Control)).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let result = (|| -> Result<(), EvidenceError> {
            let mut store = EvidenceStore::new(
                TemporaryStore::new(parent.path()).unwrap(),
                evidence_limits(),
                &mut resources,
            )?;
            store.collect(
                EvidenceKind::Certificate,
                Source::sequential(&mut &bytes[..], Some(bytes.len() as u64)),
                EvidenceOrigin::Embedded { label: "public" },
            )?;
            Ok(())
        })();
        assert!(matches!(
            (resource, result),
            (
                0,
                Err(EvidenceError::Processing(ProcessingError::MemoryLimit))
            ) | (
                1,
                Err(EvidenceError::Processing(ProcessingError::MetadataLimit))
            ) | (
                2,
                Err(EvidenceError::Processing(ProcessingError::TempLimit))
            )
        ));
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[test]
fn cancellation_during_online_status_validation_is_fatal_not_a_report() {
    let fixture = Fixture::new();
    let control = Arc::new(Interrupt(AtomicUsize::new(0)));
    let budget = Arc::new(SharedBudget::new(limits()).unwrap());
    let mut resources = budget.begin(limits(), control.clone()).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &fixture.payloads(Status::Missing, Status::Missing),
        &token,
        None,
    );
    let http = InterruptingNetwork {
        control,
        ordinary: false,
    };
    let parts = [CoveragePart::Signature];
    let bindings = [TimestampBinding {
        token: case.signature_token,
        kind: ProofKind::Signature,
        coverage: &parts,
    }];
    let network = NetworkPolicy::only_endpoints([
        "http://ocsp.synthetic.test",
        "http://crl.synthetic.test",
        TSA_STATUS,
        TSA_CRL,
    ])
    .unwrap();
    assert!(matches!(
        validate_evidence(
            &fixture.signer(),
            &mut case.bundle,
            &bindings,
            AdesLevel::T,
            &fixture.context(&http, ValidationPolicy::StrictOnline),
            &network,
            &resources
        ),
        Err(EvidenceError::Processing(ProcessingError::Cancelled))
    ));
}

#[test]
fn request_response_cap_does_not_expand_with_coverage_size() {
    struct Oversized;
    impl HttpTransport for Oversized {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            assert!(request.opts.max_len <= MAX_RESPONSE_LEN);
            Ok(HttpReply {
                status: 200,
                content_type: Some("application/timestamp-reply".into()),
                location: None,
                body: vec![0; MAX_RESPONSE_LEN as usize + 1],
            })
        }
    }
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    assert!(
        store
            .request_timestamp(
                &fixture.signer(),
                &[CoveragePart::Signature],
                &request_spec(),
                &fixture.context(&Oversized, ValidationPolicy::StrictOnline),
                &NetworkPolicy::only_endpoints([TSA_URL]).unwrap()
            )
            .is_err()
    );
}

#[test]
fn archive_validation_reconstructs_explicit_base64_and_literal_parts() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut exact = b"<archive>".to_vec();
    exact.extend_from_slice(&fixture.signature);
    for bytes in payloads
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .chain(std::iter::once(token.as_slice()))
    {
        exact.extend_from_slice(b"<e>");
        exact.extend_from_slice(STANDARD.encode(bytes).as_bytes());
        exact.extend_from_slice(b"</e>");
    }
    exact.extend_from_slice(b"</archive>");
    let archive = fixture.token(&exact, ARCHIVE);
    for changed_wrapper in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &payloads,
            &token,
            Some(&archive),
        );
        case.archive_coverage = vec![CoveragePart::Bytes(b"<archive>"), CoveragePart::Signature];
        for id in case
            .ids
            .iter()
            .chain(std::iter::once(&case.signature_token))
        {
            case.archive_coverage.push(CoveragePart::Bytes(b"<e>"));
            case.archive_coverage.push(CoveragePart::Evidence {
                id: *id,
                encoding: CoverageEncoding::Base64,
            });
            case.archive_coverage.push(CoveragePart::Bytes(b"</e>"));
        }
        case.archive_coverage
            .push(CoveragePart::Bytes(if changed_wrapper {
                b"</changed>"
            } else {
                b"</archive>"
            }));
        let report = validate(
            &fixture,
            &mut case,
            AdesLevel::Lta,
            &resources,
            &Offline::new(),
        );
        if changed_wrapper {
            assert_eq!(report.verdict, Verdict::Invalid);
            assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
        } else {
            assert_proven(&report, case.signature_token);
        }
    }
}

#[test]
fn archive_covering_an_unverified_earlier_token_does_not_create_historical_proof() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(b"not this signature", PROVEN);
    let archive = fixture.token(
        &archive_bytes(&fixture.signature, &payloads, &token),
        ARCHIVE,
    );
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &payloads,
        &token,
        Some(&archive),
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::Lta,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
    assert!(report.signers[0].proof_time.is_none());
    assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
}

#[test]
fn archive_graph_requires_earlier_token_validation_not_only_covered_bytes() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let archive = fixture.token(
        &archive_bytes(&fixture.signature, &payloads, &token),
        ARCHIVE,
    );
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &payloads,
        &token,
        Some(&archive),
    );
    let bindings = [TimestampBinding {
        token: case.archive_token.unwrap(),
        kind: ProofKind::Archive,
        coverage: &case.archive_coverage,
    }];
    let http = Offline::new();
    assert!(matches!(
        validate_evidence(
            &fixture.signer(),
            &mut case.bundle,
            &bindings,
            AdesLevel::Lta,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources
        ),
        Err(EvidenceError::InvalidBinding)
    ));
}

#[test]
fn repeated_external_evidence_delivery_cannot_bypass_output_quota() {
    let fixture = Fixture::new();
    let bytes = fixture.root.cert.to_der().unwrap();
    let mut cap = limits();
    // Intake is internal; exactly two external deliveries fit.
    cap.output_bytes = 2 * bytes.len() as u64;
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap, Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let id = collect(&mut store, EvidenceKind::Certificate, &bytes);
    let mut bundle = store.finish();
    assert_eq!(resources.progress().bytes_out, 0);
    assert_eq!(
        bundle.copy_entry(id, &mut io::sink()).unwrap(),
        bytes.len() as u64
    );
    assert_eq!(resources.progress().bytes_out, bytes.len() as u64);
    assert_eq!(
        bundle.copy_entry(id, &mut io::sink()).unwrap(),
        bytes.len() as u64
    );
    assert_eq!(resources.progress().bytes_out, 2 * bytes.len() as u64);
    struct RejectWrite;
    impl Write for RejectWrite {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("output quota must precede another delivery");
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        bundle.copy_entry(id, &mut RejectWrite),
        Err(EvidenceError::Processing(ProcessingError::OutputLimit))
    ));
}

#[test]
fn failed_partial_intake_stays_poisoned_across_infallible_finish() {
    let fixture = Fixture::new();
    let bytes = fixture.root.cert.to_der().unwrap();
    let mut cap = evidence_limits();
    cap.max_item_bytes = bytes.len() as u64;
    cap.max_crl_item_bytes = bytes.len() as u64;
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        cap,
        &mut resources,
    )
    .unwrap();
    let id = collect(&mut store, EvidenceKind::Certificate, &bytes);
    let mut over = RecordSource {
        position: 0,
        len: bytes.len() as u64 + 1,
        largest_read: 0,
    };
    assert!(matches!(
        store.collect(
            EvidenceKind::Crl,
            Source::sequential(&mut over, None),
            EvidenceOrigin::Embedded {
                label: "partial untrusted DER"
            }
        ),
        Err(EvidenceError::Limit)
    ));
    assert_eq!(over.position, bytes.len() as u64 + 1);
    let mut bundle = store.finish();
    assert!(bundle.entry(id).is_none());
    assert!(matches!(
        bundle.copy_entry(id, &mut io::sink()),
        Err(EvidenceError::Processing(ProcessingError::InvalidInput(_)))
    ));
    let http = Offline::new();
    assert!(matches!(
        validate_evidence(
            &fixture.signer(),
            &mut bundle,
            &[],
            AdesLevel::B,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources
        ),
        Err(EvidenceError::Processing(ProcessingError::InvalidInput(_)))
    ));
    drop(bundle);
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn staged_profile_coverage_replays_multichunk_bytes_and_rejects_changed_region_or_bytes() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut record = RecordSource {
        position: 0,
        len: 3 * IO_CHUNK_BYTES as u64 + 37,
        largest_read: 0,
    };
    let mut document = Vec::new();
    record.read_to_end(&mut document).unwrap();
    let mut exact = document.clone();
    exact.extend(archive_bytes(&fixture.signature, &payloads, &token));
    let archive = fixture.token(&exact, ARCHIVE);
    for mutation in 0..3 {
        let parent = tempfile::tempdir().unwrap();
        let mut resources = scope();
        let source_store = TemporaryStore::new(parent.path()).unwrap();
        let mut source = source_store.stage(&mut resources).unwrap();
        for bytes in document.chunks(IO_CHUNK_BYTES) {
            source.write_chunk(bytes).unwrap();
        }
        if mutation == 2 {
            source.write_chunk(b"!").unwrap();
        }
        let source = std::sync::Mutex::new(source);
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &payloads,
            &token,
            Some(&archive),
        );
        let region = match mutation {
            1 => Region {
                offset: 1,
                len: document.len() as u64 - 1,
            },
            2 => Region {
                offset: 0,
                len: document.len() as u64 + 1,
            },
            _ => Region {
                offset: 0,
                len: document.len() as u64,
            },
        };
        let signature = [CoveragePart::Signature];
        let mut coverage = vec![
            CoveragePart::Staged {
                artifact: &source,
                region,
            },
            CoveragePart::Signature,
        ];
        coverage.extend(
            case.ids
                .iter()
                .chain(std::iter::once(&case.signature_token))
                .map(|id| CoveragePart::Evidence {
                    id: *id,
                    encoding: CoverageEncoding::Raw,
                }),
        );
        let proofs = [
            TimestampBinding {
                token: case.signature_token,
                kind: ProofKind::Signature,
                coverage: &signature,
            },
            TimestampBinding {
                token: case.archive_token.unwrap(),
                kind: ProofKind::Archive,
                coverage: &coverage,
            },
        ];
        let http = Offline::new();
        let report = validate_evidence(
            &fixture.signer(),
            &mut case.bundle,
            &proofs,
            AdesLevel::Lta,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources,
        )
        .unwrap();
        if mutation == 0 {
            assert_proven(&report, case.signature_token);
        } else {
            assert_eq!(report.verdict, Verdict::Invalid);
            assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
        }
    }
}

#[test]
fn staged_profile_coverage_preserves_original_source_control_and_never_waits_on_busy_lock() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut covered = b"profile bytes".to_vec();
    covered.extend(archive_bytes(&fixture.signature, &payloads, &token));
    let archive = fixture.token(&covered, ARCHIVE);
    for busy in [false, true] {
        let control = Arc::new(Interrupt(AtomicUsize::new(0)));
        let mut source_scope = Arc::new(SharedBudget::new(limits()).unwrap())
            .begin(limits(), control.clone())
            .unwrap();
        let mut resources = scope();
        let parent = tempfile::tempdir().unwrap();
        let mut source = TemporaryStore::new(parent.path())
            .unwrap()
            .stage(&mut source_scope)
            .unwrap();
        source.write_chunk(b"profile bytes").unwrap();
        let source = std::sync::Mutex::new(source);
        drop(source_scope);
        let mut case = prepare(
            &mut resources,
            parent.path(),
            &payloads,
            &token,
            Some(&archive),
        );
        let _busy = if busy {
            Some(source.lock().unwrap())
        } else {
            control.0.store(1, Ordering::SeqCst);
            None
        };
        let signature = [CoveragePart::Signature];
        let mut coverage = vec![
            CoveragePart::Staged {
                artifact: &source,
                region: Region { offset: 0, len: 13 },
            },
            CoveragePart::Signature,
        ];
        coverage.extend(
            case.ids
                .iter()
                .chain(std::iter::once(&case.signature_token))
                .map(|id| CoveragePart::Evidence {
                    id: *id,
                    encoding: CoverageEncoding::Raw,
                }),
        );
        let proofs = [
            TimestampBinding {
                token: case.signature_token,
                kind: ProofKind::Signature,
                coverage: &signature,
            },
            TimestampBinding {
                token: case.archive_token.unwrap(),
                kind: ProofKind::Archive,
                coverage: &coverage,
            },
        ];
        let http = Offline::new();
        let result = validate_evidence(
            &fixture.signer(),
            &mut case.bundle,
            &proofs,
            AdesLevel::Lta,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources,
        );
        if busy {
            assert!(matches!(
                result,
                Err(EvidenceError::Processing(ProcessingError::CapacityExceeded))
            ));
        } else {
            assert!(matches!(
                result,
                Err(EvidenceError::Processing(ProcessingError::Cancelled))
            ));
        }
    }
}

// Review I1: A owns the bundle; B is an independently controlled validation.
// Signed status remains real; only the interruption is injected at the HTTP boundary.
struct CrossScopeStatus {
    ocsp: MockOcsp,
    crl: MockCrl,
    interrupt: Arc<Interrupt>,
    calls: AtomicUsize,
}
impl HttpTransport for CrossScopeStatus {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = if request.url.ends_with("root-gost2015.crl") {
            self.crl.send(request)
        } else {
            self.ocsp.send(request)
        };
        if count == 0 {
            self.interrupt.0.store(1, Ordering::SeqCst);
        }
        answer
    }
}

#[test]
fn distinct_validation_scope_cancellation_stops_online_pki_after_first_response() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    for cancel_owner in [false, true] {
        let owner = Arc::new(Interrupt(AtomicUsize::new(0)));
        let current = Arc::new(Interrupt(AtomicUsize::new(0)));
        let mut scope_a = Arc::new(SharedBudget::new(limits()).unwrap())
            .begin(limits(), owner.clone())
            .unwrap();
        let scope_b = Arc::new(SharedBudget::new(limits()).unwrap())
            .begin(limits(), current.clone())
            .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut case = prepare(
            &mut scope_a,
            parent.path(),
            &fixture.payloads(Status::Missing, Status::Missing),
            &token,
            None,
        );
        let http = CrossScopeStatus {
            ocsp: MockOcsp::new(fixture.responder.clone()).with_now(NOW),
            crl: MockCrl::new(fixture.root.clone())
                .with_this_update(NOW - time::Duration::MINUTE)
                .next_update(Some(NOW + time::Duration::HOUR)),
            interrupt: if cancel_owner {
                owner.clone()
            } else {
                current.clone()
            },
            calls: AtomicUsize::new(0),
        };
        let parts = [CoveragePart::Signature];
        let proofs = [TimestampBinding {
            token: case.signature_token,
            kind: ProofKind::Signature,
            coverage: &parts,
        }];
        let network = NetworkPolicy::only_endpoints([
            TSA_STATUS,
            TSA_CRL,
            "http://ocsp.synthetic.test",
            "http://crl.synthetic.test",
        ])
        .unwrap();
        let result = validate_evidence(
            &fixture.signer(),
            &mut case.bundle,
            &proofs,
            AdesLevel::T,
            &fixture.context(&http, ValidationPolicy::StrictOnline),
            &network,
            &scope_b,
        );
        assert!(matches!(
            result,
            Err(EvidenceError::Processing(ProcessingError::Cancelled))
        ));
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            1,
            "neither scope's cancellation may permit another actual status exchange"
        );
        if cancel_owner {
            assert!(scope_b.checkpoint().is_ok(), "B remains independently live");
        } else {
            assert!(scope_a.checkpoint().is_ok(), "A remains independently live");
        }
    }
}

fn reissue_local_status_urls(fixture: &mut Fixture, origin: &str) {
    let update = |key: &KeyEntry, issuer: &KeyEntry, root: bool| {
        let mut spec = TestCertSpec::from_cert(&key.cert);
        for extension in &mut spec.extensions {
            let path = match extension.extn_id.to_string().as_str() {
                "1.3.6.1.5.5.7.1.1" => Some("/ocsp"),
                "2.5.29.31" => Some(if root { "/root.crl" } else { "/leaf.crl" }),
                _ => None,
            };
            if let Some(path) = path {
                extension.extn_value = OctetString::new(rewrite_uris(
                    extension.extn_value.as_bytes(),
                    format!("{origin}{path}").as_bytes(),
                ))
                .unwrap();
            }
        }
        issue_cert(issuer, spec)
    };
    fixture.intermediate.cert = update(&fixture.intermediate, &fixture.root, true);
    fixture.doc.cert = update(&fixture.doc, &fixture.intermediate, false);
    fixture.tsa.cert = update(&fixture.tsa, &fixture.intermediate, false);
    fixture.candidates = vec![fixture.intermediate.cert.clone()];
}

struct CountPinnedUreq {
    inner: oncl_pki::http::UreqTransport,
    calls: Arc<AtomicUsize>,
}
impl HttpTransport for CountPinnedUreq {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.send(request)
    }
    fn send_pinned(
        &self,
        request: &HttpRequest<'_>,
        pins: &[std::net::SocketAddr],
    ) -> Result<HttpReply, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.send_pinned(request, pins)
    }
}

#[test]
fn distinct_shorter_validation_deadline_finishes_real_ureq_before_response_release() {
    use std::sync::mpsc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut fixture = Fixture::new();
    reissue_local_status_urls(&mut fixture, &origin);
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut scope_a = scope();
    let parent = tempfile::tempdir().unwrap();
    let mut case = prepare(
        &mut scope_a,
        parent.path(),
        &fixture.payloads(Status::Missing, Status::Missing),
        &token,
        None,
    );
    let responder = MockOcsp::new(fixture.responder.clone()).with_now(NOW);
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_origin = origin.clone();
    let server = std::thread::spawn(move || {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                other => panic!("synthetic OCSP accept failed: {other:?}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        let header_end = loop {
            let n = socket.read(&mut chunk).unwrap();
            assert!(n != 0 && request.len() + n <= 65_536);
            request.extend_from_slice(&chunk[..n]);
            if let Some(at) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = std::str::from_utf8(&request[..header_end])
            .unwrap()
            .to_owned();
        let length: usize = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse().unwrap())
            .unwrap_or(0);
        assert!(length <= 65_536 - header_end);
        while request.len() - header_end < length {
            let n = socket.read(&mut chunk).unwrap();
            assert!(n != 0 && request.len() + n <= 65_536);
            request.extend_from_slice(&chunk[..n]);
        }
        let mut first = head.lines().next().unwrap().split_whitespace();
        let method = first.next().unwrap();
        let url = format!("{origin}{}", first.next().unwrap());
        let received = if method == "POST" {
            HttpRequest::post(
                &url,
                Some("application/ocsp-request"),
                &request[header_end..header_end + length],
                GetOptions::default(),
            )
        } else {
            HttpRequest::get(&url, GetOptions::default())
        };
        let response = responder.send(&received).unwrap();
        assert_eq!(
            response.status, 200,
            "barrier must hold a genuine signed OCSP response"
        );
        accepted_tx.send(()).unwrap();
        // Response stays unavailable until the assertion has observed completion.
        // Failure paths still release/join both bounded threads before panicking.
        let _ = release_rx.recv_timeout(Duration::from_secs(6));
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.body.len()
        );
        let _ = socket
            .write_all(header.as_bytes())
            .and_then(|()| socket.write_all(&response.body));
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let worker_calls = calls.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        // Start B's shorter deadline only after all fixture/staging setup.
        let cap = ResourceLimits {
            operation_timeout: Duration::from_millis(1500),
            ..limits()
        };
        let scope_b = Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap();
        let http = CountPinnedUreq {
            inner: oncl_pki::http::UreqTransport::with_proxy(oncl_pki::http::ProxySetting::None),
            calls: worker_calls,
        };
        let parts = [CoveragePart::Signature];
        let proofs = [TimestampBinding {
            token: case.signature_token,
            kind: ProofKind::Signature,
            coverage: &parts,
        }];
        let network = NetworkPolicy::only_endpoints([worker_origin.as_str()]).unwrap();
        let result = validate_evidence(
            &fixture.signer(),
            &mut case.bundle,
            &proofs,
            AdesLevel::T,
            &fixture.context(&http, ValidationPolicy::StrictOnline),
            &network,
            &scope_b,
        );
        let result = match result {
            Err(EvidenceError::Processing(ProcessingError::DeadlineExceeded)) => Ok(()),
            other => Err(format!("expected exact B deadline, got {other:?}")),
        };
        done_tx.send(result).unwrap();
    });
    let accepted = accepted_rx.recv_timeout(Duration::from_secs(8));
    let before_release = if accepted.is_ok() {
        done_rx.recv_timeout(Duration::from_secs(3)).ok()
    } else {
        None
    };
    let owner_still_live = scope_a.checkpoint().is_ok();
    let calls_before_release = calls.load(Ordering::SeqCst);
    let _ = release_tx.send(());
    worker.join().unwrap();
    server.join().unwrap();
    assert!(
        accepted.is_ok(),
        "a genuine local request must reach the held-response boundary"
    );
    assert!(owner_still_live, "A is not the source of deadline failure");
    assert!(
        matches!(before_release, Some(Ok(()))),
        "B must finish with DeadlineExceeded BEFORE response release: {before_release:?}"
    );
    assert_eq!(calls_before_release, 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no later actual status request after B expires"
    );
}

struct ParserOwnerControl {
    armed: std::sync::atomic::AtomicBool,
    checkpoints: AtomicUsize,
    after_cancel: AtomicUsize,
    current: Arc<Interrupt>,
}
impl OperationControl for ParserOwnerControl {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.armed.load(Ordering::SeqCst) {
            if self.current.0.load(Ordering::SeqCst) != 0 {
                self.after_cancel.fetch_add(1, Ordering::SeqCst);
            }
            if self.checkpoints.fetch_add(1, Ordering::SeqCst) == 7 {
                self.current.0.store(1, Ordering::SeqCst);
            }
        }
        // A remains live; only B has been cancelled.
        Ok(())
    }
}

#[test]
fn distinct_validation_cancel_stops_multichunk_parser_replay_while_owner_lives() {
    let fixture = Fixture::new();
    let current = Arc::new(Interrupt(AtomicUsize::new(0)));
    let owner = Arc::new(ParserOwnerControl {
        armed: std::sync::atomic::AtomicBool::new(false),
        checkpoints: AtomicUsize::new(0),
        after_cancel: AtomicUsize::new(0),
        current: current.clone(),
    });
    let mut scope_a = Arc::new(SharedBudget::new(limits()).unwrap())
        .begin(limits(), owner.clone())
        .unwrap();
    let scope_b = Arc::new(SharedBudget::new(limits()).unwrap())
        .begin(limits(), current.clone())
        .unwrap();
    let extension = Extension {
        extn_id: "1.3.6.1.4.1.55555.41".parse().unwrap(),
        critical: false,
        extn_value: OctetString::new(vec![0x41; 3 * IO_CHUNK_BYTES + 13]).unwrap(),
    };
    let crl = MockCrl::new(fixture.root.clone())
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .extension(extension)
        .der();
    assert!(crl.len() > 3 * IO_CHUNK_BYTES);
    oncl_pki::crl::verify_crl(&crl, &fixture.root.cert, NOW).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut scope_a,
    )
    .unwrap();
    collect(&mut store, EvidenceKind::Crl, &crl);
    let mut bundle = store.finish();
    owner.armed.store(true, Ordering::SeqCst);
    let http = Offline::new();
    let result = validate_evidence(
        &fixture.signer(),
        &mut bundle,
        &[],
        AdesLevel::B,
        &fixture.context(&http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        &scope_b,
    );
    assert!(matches!(
        result,
        Err(EvidenceError::Processing(ProcessingError::Cancelled))
    ));
    assert_eq!(
        current.0.load(Ordering::SeqCst),
        1,
        "interruption was armed inside actual parser replay"
    );
    // Permit completion of one bounded low-level read's owner checkpoints, not
    // replaying/decoding the remainder of a >3-chunk signed evidence object.
    assert!(
        owner.after_cancel.load(Ordering::SeqCst) <= 8,
        "parser continued under A after independent B cancellation"
    );
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
    assert!(scope_a.checkpoint().is_ok());
}

#[test]
fn multichunk_base64_archive_matches_full_encoding_for_all_remainders_and_small_work_buffer() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    for remainder in 0..3 {
        let crl = (0..3)
            .map(|extra| {
                let extension = Extension {
                    extn_id: "1.3.6.1.4.1.55555.42".parse().unwrap(),
                    critical: false,
                    extn_value: OctetString::new(vec![0x42; 2 * IO_CHUNK_BYTES + 64 + extra])
                        .unwrap(),
                };
                MockCrl::new(fixture.root.clone())
                    .with_this_update(NOW - time::Duration::MINUTE)
                    .next_update(Some(NOW + time::Duration::HOUR))
                    .extension(extension)
                    .der()
            })
            .find(|bytes| bytes.len() % 3 == remainder)
            .expect("three consecutive DER lengths cover all remainders");
        assert!(crl.len() > 2 * IO_CHUNK_BYTES);
        oncl_pki::crl::verify_crl(&crl, &fixture.root.cert, NOW).unwrap();
        let mut payloads = fixture.payloads(Status::Good, Status::Good);
        payloads.push((EvidenceKind::Crl, crl));
        let mut exact = b"<archive>".to_vec();
        exact.extend_from_slice(&fixture.signature);
        for bytes in payloads
            .iter()
            .map(|(_, bytes)| bytes.as_slice())
            .chain(std::iter::once(token.as_slice()))
        {
            exact.extend_from_slice(b"<e>");
            exact.extend_from_slice(STANDARD.encode(bytes).as_bytes());
            exact.extend_from_slice(b"</e>");
        }
        exact.extend_from_slice(b"</archive>");
        let archive = fixture.token(&exact, ARCHIVE);
        for work_memory in [32 * 1024 * 1024, 64 * 1024] {
            let mut scope_a = scope();
            let cap = ResourceLimits {
                memory_bytes: work_memory,
                ..limits()
            };
            let scope_b = Arc::new(SharedBudget::new(cap.clone()).unwrap())
                .begin(cap, Arc::new(Control))
                .unwrap();
            let parent = tempfile::tempdir().unwrap();
            let mut case = prepare(
                &mut scope_a,
                parent.path(),
                &payloads,
                &token,
                Some(&archive),
            );
            let signature = [CoveragePart::Signature];
            let mut coverage = vec![CoveragePart::Bytes(b"<archive>"), CoveragePart::Signature];
            for id in case
                .ids
                .iter()
                .chain(std::iter::once(&case.signature_token))
            {
                coverage.push(CoveragePart::Bytes(b"<e>"));
                coverage.push(CoveragePart::Evidence {
                    id: *id,
                    encoding: CoverageEncoding::Base64,
                });
                coverage.push(CoveragePart::Bytes(b"</e>"));
            }
            coverage.push(CoveragePart::Bytes(b"</archive>"));
            let proofs = [
                TimestampBinding {
                    token: case.signature_token,
                    kind: ProofKind::Signature,
                    coverage: &signature,
                },
                TimestampBinding {
                    token: case.archive_token.unwrap(),
                    kind: ProofKind::Archive,
                    coverage: &coverage,
                },
            ];
            let http = Offline::new();
            let report = validate_evidence(
                &fixture.signer(),
                &mut case.bundle,
                &proofs,
                AdesLevel::Lta,
                &fixture.context(&http, ValidationPolicy::OfflineReport),
                &NetworkPolicy::deny_all(),
                &scope_b,
            )
            .unwrap();
            assert_proven(&report, case.signature_token);
            assert_eq!(http.0.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn nested_standard_hash_index_reuses_one_scoped_work_buffer() {
    let fixture = Fixture::new();
    let payloads = fixture.payloads(Status::Good, Status::Good);
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut transformed = payloads[0].1.clone();
    for _ in 0..8 {
        transformed = Sha256::digest(&transformed).to_vec();
    }
    let mut covered = fixture.signature.clone();
    covered.extend_from_slice(&transformed);
    for (_, value) in &payloads[1..] {
        covered.extend_from_slice(value);
    }
    covered.extend_from_slice(&token);
    let archive = fixture.token(&covered, ARCHIVE);
    let parent = tempfile::tempdir().unwrap();
    let mut quota = limits();
    quota.memory_bytes = 1024 * 1024;
    let mut resources = Arc::new(SharedBudget::new(quota.clone()).unwrap())
        .begin(quota, Arc::new(Control))
        .unwrap();
    let mut case = prepare(
        &mut resources,
        parent.path(),
        &payloads,
        &token,
        Some(&archive),
    );
    let leaf = [CoveragePart::Evidence {
        id: case.ids[0],
        encoding: CoverageEncoding::Raw,
    }];
    let one = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &leaf,
    }];
    let two = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &one,
    }];
    let three = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &two,
    }];
    let four = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &three,
    }];
    let five = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &four,
    }];
    let six = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &five,
    }];
    let seven = [CoveragePart::Hashed {
        algorithm: HashAlg::Sha256,
        parts: &six,
    }];
    let mut coverage = vec![
        CoveragePart::Signature,
        CoveragePart::Hashed {
            algorithm: HashAlg::Sha256,
            parts: &seven,
        },
    ];
    coverage.extend(
        case.ids[1..]
            .iter()
            .chain(std::iter::once(&case.signature_token))
            .map(|id| CoveragePart::Evidence {
                id: *id,
                encoding: CoverageEncoding::Raw,
            }),
    );
    let signature = [CoveragePart::Signature];
    let proofs = [
        TimestampBinding {
            token: case.signature_token,
            kind: ProofKind::Signature,
            coverage: &signature,
        },
        TimestampBinding {
            token: case.archive_token.unwrap(),
            kind: ProofKind::Archive,
            coverage: &coverage,
        },
    ];
    let http = Offline::new();
    let report = validate_evidence(
        &fixture.signer(),
        &mut case.bundle,
        &proofs,
        AdesLevel::Lta,
        &fixture.context(&http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        &resources,
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Valid);
    assert_proven(&report, case.signature_token);
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
}

#[test]
fn format_failure_is_monotonic_and_original_scope_bound() {
    let fixture = Fixture::new();
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let mut bundle = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap()
    .finish();
    let http = Offline::new();
    let mut report = validate_evidence(
        &fixture.signer(),
        &mut bundle,
        &[],
        AdesLevel::B,
        &fixture.context(&http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        &resources,
    )
    .unwrap();
    let before = report.signers[0].reasons.len();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    let foreign = scope();
    assert!(
        report
            .invalidate_signer(
                0,
                oncl_pki::validation::FormatFailure::ReferenceDigestMismatch,
                &foreign,
            )
            .is_err()
    );
    assert_eq!(report.signers[0].reasons.len(), before);
    report
        .invalidate_signer(
            0,
            oncl_pki::validation::FormatFailure::ReferenceDigestMismatch,
            &resources,
        )
        .unwrap();
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].signature, CheckStatus::Failed);
    assert_eq!(report.signers[0].reasons.len(), before + 1);
    assert!(
        report
            .invalidate_signer(
                1,
                oncl_pki::validation::FormatFailure::ReferenceDigestMismatch,
                &resources,
            )
            .is_err()
    );
    assert_eq!(report.signers[0].signature, CheckStatus::Failed);
}

#[test]
fn closed_signature_representation_checks_source_scope_projection_and_raw_value() {
    use oncl_pki::evidence::BoundSignatureRepresentation;
    let fixture = Fixture::new();
    let encoded = STANDARD.encode(&fixture.signature);
    let bytes = format!("<v>{encoded}</v>").into_bytes();
    let region = Region {
        offset: 0,
        len: bytes.len() as u64,
    };
    let spans = [Region {
        offset: 3,
        len: encoded.len() as u64,
    }];
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    for case in 0..4 {
        let mut artifact = if case == 0 {
            store.stage(&mut resources).unwrap()
        } else {
            store.stage_source(&mut resources).unwrap()
        };
        artifact.write_chunk(&bytes).unwrap();
        let foreign = scope();
        let mut wrong = fixture.signature.clone();
        wrong[0] ^= 1;
        let mut signer = fixture.signer();
        if case == 2 {
            signer.signature = &wrong;
        }
        let projection = if case == 3 {
            &[Region {
                offset: 2,
                len: encoded.len() as u64,
            }][..]
        } else {
            &spans
        };
        assert!(
            BoundSignatureRepresentation::from_base64_projection(
                artifact,
                region,
                projection,
                &signer,
                &evidence_limits(),
                if case == 1 { &foreign } else { &resources },
            )
            .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn bound_signature_representation_timestamp_checks_whole_layout_and_current_signature() {
    use oncl_pki::evidence::BoundSignatureRepresentation;
    let fixture = Fixture::new();
    let encoded = STANDARD.encode(&fixture.signature);
    let split = encoded.len() / 2;
    let prefix = "<v>";
    let middle = "<!--layout-->";
    let whitespace = "&#xD;\n";
    let bytes = format!(
        "{prefix}{}{middle}{whitespace}{}</v>",
        &encoded[..split],
        &encoded[split..]
    )
    .into_bytes();
    let spans = [
        Region {
            offset: prefix.len() as u64,
            len: split as u64,
        },
        Region {
            offset: (prefix.len() + split + middle.len()) as u64,
            len: (whitespace.len() + encoded.len() - split) as u64,
        },
    ];
    for correct in [false, true] {
        let mut resources = scope();
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let mut artifact = store.stage_source(&mut resources).unwrap();
        artifact.write_chunk(&bytes).unwrap();
        let bound = BoundSignatureRepresentation::from_base64_projection(
            artifact,
            Region {
                offset: 0,
                len: bytes.len() as u64,
            },
            &spans,
            &fixture.signer(),
            &evidence_limits(),
            &resources,
        )
        .unwrap();
        let mut evidence = EvidenceStore::new(store, evidence_limits(), &mut resources).unwrap();
        for (kind, bytes) in fixture.payloads(Status::Good, Status::Good) {
            collect(&mut evidence, kind, &bytes);
        }
        let token = fixture.token(if correct { &bytes } else { &fixture.signature }, PROVEN);
        let token = collect(&mut evidence, EvidenceKind::Timestamp, &token);
        let mut bundle = evidence.finish();
        let coverage = [CoveragePart::BoundSignature(&bound)];
        let proofs = [TimestampBinding {
            token,
            kind: ProofKind::Signature,
            coverage: &coverage,
        }];
        let http = Offline::new();
        let report = validate_evidence(
            &fixture.signer(),
            &mut bundle,
            &proofs,
            AdesLevel::T,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources,
        )
        .unwrap();
        if correct {
            assert_proven(&report, token);
        } else {
            assert!(report.signers[0].proof_time.is_none());
            assert_eq!(report.signers[0].timestamp, CheckStatus::Failed);
        }
        let mut wrong = fixture.signature.clone();
        wrong[0] ^= 1;
        let mut signer = fixture.signer();
        signer.signature = &wrong;
        assert!(matches!(
            validate_evidence(
                &signer,
                &mut bundle,
                &proofs,
                AdesLevel::T,
                &fixture.context(&http, ValidationPolicy::OfflineReport),
                &NetworkPolicy::deny_all(),
                &resources
            ),
            Err(EvidenceError::InvalidBinding)
        ));
    }
}

#[test]
fn evidence_intake_zero_output_and_external_delivery_admission() {
    let mut cap = limits();
    cap.output_bytes = 0;
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap, Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let mut store = EvidenceStore::new(
        TemporaryStore::new(parent.path()).unwrap(),
        evidence_limits(),
        &mut resources,
    )
    .unwrap();
    let id = collect(
        &mut store,
        EvidenceKind::Certificate,
        b"internal public evidence",
    );
    assert_eq!(resources.progress().bytes_out, 0);
    let mut bundle = store.finish();
    struct MustNotWrite;
    impl Write for MustNotWrite {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("external evidence output not admitted")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        bundle.copy_entry(id, &mut MustNotWrite),
        Err(EvidenceError::Processing(ProcessingError::OutputLimit))
    ));
    assert_eq!(resources.progress().bytes_out, 0);
}

#[test]
fn bound_signature_representation_retains_admission_and_rejects_foreign_bundle() {
    use oncl_pki::evidence::BoundSignatureRepresentation;
    let fixture = Fixture::new();
    let encoded = STANDARD.encode(&fixture.signature);
    let bytes = format!("<v>{encoded}</v>").into_bytes();
    let cap = limits();
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap.clone(), Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage_source(&mut resources).unwrap();
    artifact.write_chunk(&bytes).unwrap();
    let bound = BoundSignatureRepresentation::from_base64_projection(
        artifact,
        Region {
            offset: 0,
            len: bytes.len() as u64,
        },
        &[Region {
            offset: 3,
            len: encoded.len() as u64,
        }],
        &fixture.signer(),
        &evidence_limits(),
        &resources,
    )
    .unwrap();
    drop(resources);
    assert!(budget.begin(cap.clone(), Arc::new(Control)).is_err());
    let mut foreign = scope();
    let mut evidence = EvidenceStore::new(store, evidence_limits(), &mut foreign).unwrap();
    let token = collect(
        &mut evidence,
        EvidenceKind::Timestamp,
        &fixture.token(&bytes, PROVEN),
    );
    let mut bundle = evidence.finish();
    let coverage = [CoveragePart::BoundSignature(&bound)];
    let proofs = [TimestampBinding {
        token,
        kind: ProofKind::Signature,
        coverage: &coverage,
    }];
    let http = Offline::new();
    assert!(matches!(
        validate_evidence(
            &fixture.signer(),
            &mut bundle,
            &proofs,
            AdesLevel::T,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &foreign,
        ),
        Err(EvidenceError::Processing(ProcessingError::InvalidInput(_)))
    ));
    drop(bound);
    assert!(budget.begin(cap, Arc::new(Control)).is_ok());
}

#[test]
fn bound_archive_representation_covers_exact_current_value_and_prior_evidence() {
    use oncl_pki::evidence::{BoundArchiveRepresentation, BoundSignatureRepresentation};
    let fixture = Fixture::new();
    let mut resources = scope();
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let value = format!("<v>{}</v>", STANDARD.encode(&fixture.signature)).into_bytes();
    let mut stage = store.stage_source(&mut resources).unwrap();
    stage.write_chunk(&value).unwrap();
    let bound = BoundSignatureRepresentation::from_base64_projection(
        stage,
        Region {
            offset: 0,
            len: value.len() as u64,
        },
        &[Region {
            offset: 3,
            len: (value.len() - 7) as u64,
        }],
        &fixture.signer(),
        &evidence_limits(),
        &resources,
    )
    .unwrap();
    let mut evidence =
        EvidenceStore::new(store.clone(), evidence_limits(), &mut resources).unwrap();
    let signature_token = fixture.token(&value, PROVEN);
    let mut prior = vec![(
        collect(&mut evidence, EvidenceKind::Timestamp, &signature_token),
        signature_token,
    )];
    for (kind, bytes) in fixture.payloads(Status::Good, Status::Good) {
        prior.push((collect(&mut evidence, kind, &bytes), bytes));
    }
    let mut canonical = b"<data>actual transformed reference</data><SignedInfo/>".to_vec();
    let signature_region = Region {
        offset: canonical.len() as u64,
        len: value.len() as u64,
    };
    canonical.extend_from_slice(&value);
    let mut projections = Vec::new();
    for (id, bytes) in &prior {
        canonical.extend_from_slice(b"<e>");
        let encoded = STANDARD.encode(bytes);
        let span = Region {
            offset: canonical.len() as u64,
            len: encoded.len() as u64,
        };
        canonical.extend_from_slice(encoded.as_bytes());
        canonical.extend_from_slice(b"</e>");
        projections.push((*id, vec![span]));
    }
    let archive_token = fixture.token(&canonical, ARCHIVE);
    let archive_id = collect(&mut evidence, EvidenceKind::Timestamp, &archive_token);
    let mut bundle = evidence.finish();
    let mut stage = store.stage_source(&mut resources).unwrap();
    stage.write_chunk(&canonical).unwrap();
    let groups: Vec<_> = projections
        .iter()
        .map(|(id, spans)| (*id, spans.as_slice()))
        .collect();
    let archive = BoundArchiveRepresentation::from_base64_projections(
        stage,
        &bound,
        signature_region,
        &groups,
        &fixture.signer(),
        &mut bundle,
        Some(archive_id),
        &resources,
    )
    .unwrap();
    let signature_coverage = [CoveragePart::BoundSignature(&bound)];
    let archive_coverage = [CoveragePart::BoundArchive(&archive)];
    let proofs = [
        TimestampBinding {
            token: prior[0].0,
            kind: ProofKind::Signature,
            coverage: &signature_coverage,
        },
        TimestampBinding {
            token: archive_id,
            kind: ProofKind::Archive,
            coverage: &archive_coverage,
        },
    ];
    let http = Offline::new();
    let report = validate_evidence(
        &fixture.signer(),
        &mut bundle,
        &proofs,
        AdesLevel::Lta,
        &fixture.context(&http, ValidationPolicy::OfflineReport),
        &NetworkPolicy::deny_all(),
        &resources,
    )
    .unwrap();
    assert_eq!(report.signers[0].timestamp, CheckStatus::Passed);
    let mut wrong = fixture.signature.clone();
    wrong[0] ^= 1;
    let mut signer = fixture.signer();
    signer.signature = &wrong;
    assert!(
        validate_evidence(
            &signer,
            &mut bundle,
            &proofs,
            AdesLevel::Lta,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources
        )
        .is_err()
    );
    let mut resumed = EvidenceStore::resume(bundle);
    assert!(
        matches!(
            resumed.request_timestamp(
                &fixture.signer(),
                &archive_coverage,
                &request_spec(),
                &fixture.context(&http, ValidationPolicy::StrictOnline),
                &NetworkPolicy::only_endpoints([TSA_URL]).unwrap(),
            ),
            Err(EvidenceError::InvalidBinding)
        ),
        "a stale prefix must not omit the already appended archive token"
    );
    assert_eq!(http.0.load(Ordering::SeqCst), 0);
    let mut bundle = resumed.finish();
    for failure in 0..5 {
        let mut stage = store.stage_source(&mut resources).unwrap();
        let mut bytes = canonical.clone();
        if failure == 0 {
            bytes[signature_region.offset as usize] = b'!';
        }
        stage.write_chunk(&bytes).unwrap();
        let mut bad = projections.clone();
        match failure {
            1 => {
                bad.pop();
            }
            2 => {
                bad[0].0 = archive_id;
            }
            3 => {
                bad[1].1 = bad[0].1.clone();
            }
            4 => {
                bad.push(bad[0].clone());
            }
            _ => {}
        }
        let groups: Vec<_> = bad
            .iter()
            .map(|(id, spans)| (*id, spans.as_slice()))
            .collect();
        assert!(
            BoundArchiveRepresentation::from_base64_projections(
                stage,
                &bound,
                signature_region,
                &groups,
                &fixture.signer(),
                &mut bundle,
                Some(archive_id),
                &resources,
            )
            .is_err(),
            "failure {failure} accepted"
        );
    }
}

#[test]
fn internal_evidence_read_preserves_bounds_and_external_delivery_accounting() {
    let mut cap = limits();
    cap.output_bytes = 0;
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap, Arc::new(Control)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut evidence = EvidenceStore::new(store, evidence_limits(), &mut resources).unwrap();
    let id = collect(&mut evidence, EvidenceKind::Crl, b"actual DER replay bytes");
    let mut bundle = evidence.finish();
    let mut bytes = [0; 6];
    assert_eq!(bundle.read_entry(id, 7, &mut bytes).unwrap(), 6);
    assert_eq!(&bytes, b"DER re");
    assert!(bundle.read_entry(id, 100, &mut bytes).is_err());
    assert!(bundle.copy_entry(id, &mut Vec::new()).is_err());
    assert_eq!(resources.progress().bytes_out, 0);
}

#[test]
fn evidence_resume_preserves_consumption_owner_and_terminal_poison() {
    struct Broken(bool);
    impl Read for Broken {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                Err(io::Error::other("actual intake failure"))
            } else {
                self.0 = true;
                out[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }
    }
    let mut resources = scope();
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut cap = evidence_limits();
    cap.max_bytes = 6;
    cap.max_item_bytes = 6;
    cap.max_crl_bytes = 6;
    cap.max_crl_item_bytes = 6;
    cap.max_total_bytes = 6;
    let mut evidence = EvidenceStore::new(store.clone(), cap, &mut resources).unwrap();
    let id = collect(&mut evidence, EvidenceKind::Crl, b"abc");
    let mut resumed = EvidenceStore::resume(evidence.finish());
    collect(&mut resumed, EvidenceKind::Crl, b"def");
    assert!(matches!(
        resumed.collect(
            EvidenceKind::Crl,
            Source::sequential(&mut &b"g"[..], Some(1)),
            EvidenceOrigin::Embedded { label: "over cap" }
        ),
        Err(EvidenceError::Limit)
    ));
    let mut bundle = resumed.finish();
    let mut bytes = [0; 3];
    assert_eq!(bundle.read_entry(id, 0, &mut bytes).unwrap(), 3);
    assert_eq!(&bytes, b"abc");
    let mut evidence = EvidenceStore::new(store, evidence_limits(), &mut resources).unwrap();
    assert!(
        evidence
            .collect(
                EvidenceKind::Crl,
                Source::sequential(&mut Broken(false), None),
                EvidenceOrigin::Embedded { label: "fault" }
            )
            .is_err()
    );
    let mut resumed = EvidenceStore::resume(evidence.finish());
    assert!(
        resumed
            .collect(
                EvidenceKind::Crl,
                Source::sequential(&mut &b"valid"[..], Some(5)),
                EvidenceOrigin::Embedded {
                    label: "must remain poisoned"
                }
            )
            .is_err()
    );
}

#[test]
fn bound_archive_trailing_material_is_current_tsa_only_and_cannot_repair_prior_lt() {
    use oncl_pki::evidence::{BoundArchiveRepresentation, BoundSignatureRepresentation};
    let fixture = Fixture::new();
    let mut current = fixture.tsa.clone();
    let mut spec = TestCertSpec::from_cert(&current.cert);
    spec.serial = vec![0x74, 0x05];
    current.cert = issue_cert(&fixture.intermediate, spec);
    for case in 0..4 {
        let mut resources = scope();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let value = format!("<v>{}</v>", STANDARD.encode(&fixture.signature)).into_bytes();
        let mut stage = store.stage_source(&mut resources).unwrap();
        stage.write_chunk(&value).unwrap();
        let bound = BoundSignatureRepresentation::from_base64_projection(
            stage,
            Region {
                offset: 0,
                len: value.len() as u64,
            },
            &[Region {
                offset: 3,
                len: (value.len() - 7) as u64,
            }],
            &fixture.signer(),
            &evidence_limits(),
            &resources,
        )
        .unwrap();
        let mut evidence =
            EvidenceStore::new(store.clone(), evidence_limits(), &mut resources).unwrap();
        let signature_token = fixture.token(&value, PROVEN);
        let signature_id = collect(&mut evidence, EvidenceKind::Timestamp, &signature_token);
        let mut prior = vec![(signature_id, signature_token)];
        for (kind, bytes) in fixture.payloads(
            if case == 2 {
                Status::Missing
            } else {
                Status::Good
            },
            Status::Good,
        ) {
            prior.push((collect(&mut evidence, kind, &bytes), bytes));
        }
        let mut canonical = b"<ReferenceData/><SignedInfo/>".to_vec();
        let value_region = Region {
            offset: canonical.len() as u64,
            len: value.len() as u64,
        };
        canonical.extend_from_slice(&value);
        let mut groups = Vec::new();
        for (id, bytes) in &prior {
            canonical.extend_from_slice(b"<e>");
            let encoded = STANDARD.encode(bytes);
            let span = Region {
                offset: canonical.len() as u64,
                len: encoded.len() as u64,
            };
            canonical.extend_from_slice(encoded.as_bytes());
            canonical.extend_from_slice(b"</e>");
            groups.push((*id, vec![span]));
        }
        let archive = fixture.token_with(current.clone(), &canonical, ARCHIVE);
        let archive_id = collect(&mut evidence, EvidenceKind::Timestamp, &archive);
        if case != 1 {
            collect(
                &mut evidence,
                EvidenceKind::Ocsp,
                &fixture.ocsp(&current.cert, Status::Good).unwrap(),
            );
        }
        if matches!(case, 1 | 2) {
            collect(
                &mut evidence,
                EvidenceKind::Ocsp,
                &fixture.ocsp(&fixture.doc.cert, Status::Good).unwrap(),
            );
        }
        if case == 3 {
            collect(
                &mut evidence,
                EvidenceKind::Certificate,
                &fixture.doc.cert.to_der().unwrap(),
            );
        }
        let mut bundle = evidence.finish();
        let mut stage = store.stage_source(&mut resources).unwrap();
        stage.write_chunk(&canonical).unwrap();
        let projections: Vec<_> = groups
            .iter()
            .map(|(id, spans)| (*id, spans.as_slice()))
            .collect();
        let bound_archive = BoundArchiveRepresentation::from_base64_projections(
            stage,
            &bound,
            value_region,
            &projections,
            &fixture.signer(),
            &mut bundle,
            Some(archive_id),
            &resources,
        )
        .unwrap();
        let signature_coverage = [CoveragePart::BoundSignature(&bound)];
        let archive_coverage = [CoveragePart::BoundArchive(&bound_archive)];
        let proofs = [
            TimestampBinding {
                token: signature_id,
                kind: ProofKind::Signature,
                coverage: &signature_coverage,
            },
            TimestampBinding {
                token: archive_id,
                kind: ProofKind::Archive,
                coverage: &archive_coverage,
            },
        ];
        let http = Offline::new();
        let report = validate_evidence(
            &fixture.signer(),
            &mut bundle,
            &proofs,
            AdesLevel::Lta,
            &fixture.context(&http, ValidationPolicy::OfflineReport),
            &NetworkPolicy::deny_all(),
            &resources,
        );
        if case == 0 {
            assert_eq!(
                report.unwrap().verdict,
                Verdict::Valid,
                "rotated current TSA status may follow its noncyclic archive"
            );
        } else {
            assert!(
                report.is_err() || report.unwrap().verdict != Verdict::Valid,
                "case {case} promoted unrelated or missing prior validation data"
            );
        }
    }
}

#[test]
fn timestamp_configuration_preflight_is_the_issuance_gate_without_private_or_http_work() {
    use oncl_pki::evidence::validate_timestamp_configuration;
    let valid = request_spec();
    validate_timestamp_configuration(&valid, ValidationPolicy::StrictOnline).unwrap();
    for case in 0..11 {
        let mut spec = valid.clone();
        match case {
            0 => spec.cert_req = false,
            1 => spec.policy = None,
            2 => spec.nonce = oncl_pki::http::NonceSpec::None,
            3 => spec.retries = 3,
            4 => spec.hash = HashAlg::Sha1,
            5 => spec.require_tsa_eku = false,
            6 => spec.timeout = Duration::ZERO,
            7 => spec.url = "x".repeat(4097),
            8 => spec.nonce = oncl_pki::http::NonceSpec::Random(0),
            9 => spec.nonce = oncl_pki::http::NonceSpec::Value(vec![]),
            _ => spec.nonce = oncl_pki::http::NonceSpec::Value(vec![1; 65]),
        }
        assert!(
            matches!(
                validate_timestamp_configuration(&spec, ValidationPolicy::StrictOnline),
                Err(EvidenceError::InvalidBinding)
            ),
            "case {case}"
        );
    }
    assert!(matches!(
        validate_timestamp_configuration(&valid, ValidationPolicy::OfflineReport),
        Err(EvidenceError::InvalidBinding)
    ));
}

#[test]
fn trusted_host_clock_samples_after_genuine_reply_without_relaxing_as_of_or_future_rules() {
    use std::sync::atomic::AtomicI64;
    struct Advance {
        tsa: MockTsa,
        clock: Arc<AtomicI64>,
        after: OffsetDateTime,
    }
    impl HttpTransport for Advance {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            let reply = self.tsa.send(request)?;
            self.clock
                .store(self.after.unix_timestamp(), Ordering::SeqCst);
            Ok(reply)
        }
    }
    let fixture = Fixture::new();
    for case in 0..5 {
        let clock = Arc::new(AtomicI64::new(
            (NOW + time::Duration::seconds(if case == 4 { 5 } else { 0 })).unix_timestamp(),
        ));
        let generated = NOW + time::Duration::seconds(if case == 1 { 4 } else { 2 });
        let after = NOW + time::Duration::seconds(if case == 2 { -1 } else { 3 });
        let http = Advance {
            tsa: MockTsa::new(fixture.tsa.clone()).with_gen_time(generated),
            clock: clock.clone(),
            after,
        };
        let context = fixture.context(&http, ValidationPolicy::StrictOnline);
        let network = NetworkPolicy::only_endpoints([TSA_URL]).unwrap();
        let mut resources = scope();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let mut evidence = EvidenceStore::new(store, evidence_limits(), &mut resources).unwrap();
        let host_clock =
            || OffsetDateTime::from_unix_timestamp(clock.load(Ordering::SeqCst)).unwrap();
        let monotonic_remaining = resources.deadline().remaining();
        let result = if case == 3 {
            evidence.request_timestamp(
                &fixture.signer(),
                &[CoveragePart::Signature],
                &request_spec(),
                &context,
                &network,
            )
        } else {
            evidence.request_timestamp_with_clock(
                &fixture.signer(),
                &[CoveragePart::Signature],
                &request_spec(),
                &context,
                &network,
                &host_clock,
            )
        };
        if case == 0 {
            let id = result.unwrap();
            let bundle = evidence.finish();
            assert_eq!(bundle.entry(id).unwrap().obtained_at(), Some(after));
            assert!(
                resources.deadline().remaining() <= monotonic_remaining,
                "wall-clock advancement cannot refresh the original monotonic deadline"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(EvidenceError::Timestamp(oncl_pki::tsp::TspError::ClockSkew))
                ),
                "case {case}"
            );
        }
    }
}

fn collect_len(
    store: &mut EvidenceStore,
    kind: EvidenceKind,
    len: usize,
) -> Result<(), EvidenceError> {
    let bytes = vec![0u8; len];
    store
        .collect(
            kind,
            Source::sequential(&mut bytes.as_slice(), Some(len as u64)),
            EvidenceOrigin::Embedded { label: "boundary" },
        )
        .map(|_| ())
}
fn crl_store(limits: EvidenceLimits) -> (EvidenceStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut scope = scope();
    (EvidenceStore::new(store, limits, &mut scope).unwrap(), dir)
}
fn split_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_bytes: 1000,
        max_item_bytes: 600,
        max_crl_bytes: 5000,
        max_crl_item_bytes: 4000,
        max_total_bytes: 5500,
        ..evidence_limits()
    }
}

#[test]
fn crl_spool_quota_is_separate_but_total_and_other_categories_stay_bounded() {
    // A CRL over the certificate/OCSP item cap is admitted up to its own item cap.
    let (mut store, _dir) = crl_store(split_limits());
    collect_len(&mut store, EvidenceKind::Crl, 4000).unwrap();
    // The aggregate over all categories still applies: 4000 + 600 + 600 > 5500 is refused
    // at the second non-CRL item, though each category is inside its own quota.
    collect_len(&mut store, EvidenceKind::Certificate, 600).unwrap();
    assert!(matches!(
        collect_len(&mut store, EvidenceKind::Ocsp, 600),
        Err(EvidenceError::Limit)
    ));
}

#[test]
fn crl_item_cap_and_non_crl_item_cap_are_enforced_exactly() {
    let (mut store, _dir) = crl_store(split_limits());
    collect_len(&mut store, EvidenceKind::Certificate, 600).unwrap();
    // One byte over the non-CRL item cap fails; the CRL item cap does not relax it.
    let (mut other, _dir2) = crl_store(split_limits());
    assert!(matches!(
        collect_len(&mut other, EvidenceKind::Certificate, 601),
        Err(EvidenceError::Limit)
    ));
    let (mut crl, _dir3) = crl_store(split_limits());
    collect_len(&mut crl, EvidenceKind::Crl, 4000).unwrap();
    let (mut over, _dir4) = crl_store(split_limits());
    assert!(matches!(
        collect_len(&mut over, EvidenceKind::Crl, 4001),
        Err(EvidenceError::Limit)
    ));
}

#[test]
fn crl_item_cap_never_exceeds_the_library_maximum_and_a_lying_length_is_stopped() {
    let limits = EvidenceLimits {
        max_crl_bytes: u64::MAX / 2,
        max_crl_item_bytes: u64::MAX / 2,
        max_total_bytes: u64::MAX / 2,
        ..evidence_limits()
    };
    let (mut store, _dir) = crl_store(limits);
    // Declared far above MAX_CRL_LEN: refused before any byte is read.
    struct Never;
    impl Read for Never {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read before admission")
        }
    }
    let declared = oncl_pki::crl::MAX_CRL_LEN + 1;
    assert!(matches!(
        store.collect(
            EvidenceKind::Crl,
            Source::sequential(&mut Never, Some(declared)),
            EvidenceOrigin::Embedded { label: "hostile" },
        ),
        Err(EvidenceError::Limit)
    ));
}

fn collect_text(store: &mut EvidenceStore, text: &[u8]) -> Result<EvidenceId, EvidenceError> {
    store.collect_base64(
        EvidenceKind::Crl,
        Source::sequential(&mut &text[..], Some(text.len() as u64)),
        EvidenceOrigin::Embedded {
            label: "base64 boundary",
        },
    )
}
#[test]
fn base64_crl_is_decoded_as_streamed_text_and_quota_counts_decoded_bytes() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let payload: Vec<u8> = (0..3001u32).map(|n| (n * 7 % 251) as u8).collect();
    let mut text = STANDARD.encode(&payload).into_bytes();
    // Line breaks and spaces of a wrapped XML text node are ignored.
    let wrapped: Vec<u8> = text
        .chunks(76)
        .flat_map(|line| line.iter().copied().chain(*b"\r\n "))
        .collect();
    text = wrapped;
    let (mut store, _dir) = crl_store(split_limits());
    let id = collect_text(&mut store, &text).unwrap();
    let bundle = store.finish();
    assert_eq!(bundle.entry(id).unwrap().region().len, payload.len() as u64);
    // The item cap applies to the decoded size: one byte more is refused.
    let (mut over, _dir2) = crl_store(EvidenceLimits {
        max_crl_item_bytes: 3000,
        ..split_limits()
    });
    assert!(matches!(
        collect_text(&mut over, &text),
        Err(EvidenceError::Limit)
    ));
}

#[test]
fn malformed_base64_is_invalid_input_not_a_partial_item() {
    for bad in [
        &b"AAA"[..],
        b"AA=A",
        b"A",
        b"AAAA=",
        b"AA==AAAA",
        b"AA!A",
        b"A===",
    ] {
        let (mut store, _dir) = crl_store(split_limits());
        assert!(
            matches!(
                collect_text(&mut store, bad),
                Err(EvidenceError::Processing(ProcessingError::InvalidInput(_)))
            ),
            "{:?}",
            std::str::from_utf8(bad)
        );
    }
}

/// The readback of a scanned CRL (DER over 1 MiB) is raw memory, charged as such: it is
/// not also retained metadata, so it fits a metadata budget smaller than the CRL.
#[test]
fn a_scanned_crl_over_one_mib_is_charged_as_memory_not_as_metadata() {
    let fixture = Fixture::new();
    let token = fixture.token(&fixture.signature, PROVEN);
    let mut payloads = fixture.payloads(Status::Good, Status::Good);
    let mut crl = MockCrl::new(fixture.root.clone())
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR));
    for index in 0..100_000u32 {
        crl = crl.revoke(&(0x0100_0000_u32 + index).to_be_bytes(), PROVEN);
    }
    payloads.last_mut().unwrap().1 = crl.der();
    let crl_len = payloads.last().unwrap().1.len() as u64;
    assert!(crl_len > 2 << 20 && crl_len < 4 << 20, "{crl_len}");
    let mut cap = limits();
    cap.metadata_bytes = 2 << 20;
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut resources = budget.begin(cap, Arc::new(Control)).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let evidence = EvidenceLimits {
        max_crl_item_bytes: 4 << 20,
        ..evidence_limits()
    };
    let mut case = prepare_limited(
        &mut resources,
        parent.path(),
        &payloads,
        &token,
        None,
        evidence,
    );
    let report = validate(
        &fixture,
        &mut case,
        AdesLevel::T,
        &resources,
        &Offline::new(),
    );
    assert_eq!(report.signers[0].chain, CheckStatus::Passed);
}

fn invalid_limits(limits: EvidenceLimits) -> bool {
    matches!(limits.validate(), Err(EvidenceError::InvalidLimits(_)))
}

#[test]
fn crl_and_total_quotas_are_validated() {
    assert!(evidence_limits().validate().is_ok());
    // A zero quota admits nothing: as for `max_bytes`, a configuration error, not "no CRLs".
    for broken in [
        EvidenceLimits {
            max_crl_bytes: 0,
            ..evidence_limits()
        },
        EvidenceLimits {
            max_crl_item_bytes: 0,
            ..evidence_limits()
        },
        EvidenceLimits {
            max_total_bytes: 0,
            ..evidence_limits()
        },
    ] {
        assert!(invalid_limits(broken), "{broken:?}");
    }
    // No ordering is imposed: intake takes the minimum, so an item cap above the aggregate (or
    // an aggregate above the total) is merely not the binding one.
    assert!(
        EvidenceLimits {
            max_crl_item_bytes: (4 << 20) + 1,
            max_crl_bytes: 1 << 20,
            max_total_bytes: 512 << 10,
            ..evidence_limits()
        }
        .validate()
        .is_ok()
    );
    // A CRL item cap above the library maximum (clamped at intake) stays valid.
    assert!(
        EvidenceLimits {
            max_crl_bytes: u64::MAX / 2,
            max_crl_item_bytes: u64::MAX / 2,
            max_total_bytes: u64::MAX / 2,
            ..evidence_limits()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn a_store_refuses_invalid_crl_quotas_before_staging() {
    let parent = tempfile::tempdir().unwrap();
    let mut resources = scope();
    let broken = EvidenceLimits {
        max_crl_item_bytes: 0,
        ..evidence_limits()
    };
    assert!(matches!(
        EvidenceStore::new(
            TemporaryStore::new(parent.path()).unwrap(),
            broken,
            &mut resources
        ),
        Err(EvidenceError::InvalidLimits(_))
    ));
}

#[test]
fn limits_intersect_field_by_field() {
    let a = evidence_limits();
    let b = EvidenceLimits {
        max_items: 8,
        max_crl_bytes: 1 << 20,
        max_crl_item_bytes: 1 << 19,
        max_total_bytes: 2 << 20,
        ..evidence_limits()
    };
    let both = a.intersect(b);
    assert_eq!(both, b);
    assert_eq!(b.intersect(a), both);
    assert!(both.validate().is_ok());
}
