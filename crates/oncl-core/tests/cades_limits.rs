//! D9: the CAdES verify of a document of exactly `input_bytes` (attached: the signed result is
//! document + signature; detached: the signature is read next to the document) is the
//! engine's accounting, not a refusal. The signature structure is container, the document
//! (embedded eContent or the detached content) is `input_bytes`; one document byte more is
//! `InputLimit`, a signature structure past `container_bytes` is refused as well.
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationError, OperationPolicy,
    ValidationServices, VerifyRequest,
};
use oncl_pki::{
    cert,
    cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec},
    evidence::{AdesLevel, EvidenceLimits},
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{Source, TemporaryStore},
    pkcs12::{KeyEntry, load},
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    validation::NetworkPolicy,
};
use oncl_testkit::{read, synthetic, synthetic_cert};
use std::{io::Cursor, sync::Arc};
use time::{OffsetDateTime, macros::datetime};

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const DATA: &[u8] = b"document of exactly the configured input allowance";

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct NoNetwork;
impl HttpTransport for NoNetwork {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline fixture must not fetch"))
    }
}
fn entry(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
/// A CAdES-B signature of `DATA` by the intermediate's user, with the chain embedded.
fn signed(attached: bool) -> Vec<u8> {
    let spec = SignSpec {
        content: Content::Data(DATA),
        encapsulate: attached,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs: AttrSpec::cades(NOW),
        certificates: CertSpec::Extra(vec![
            entry("inter-gost2015.key").cert,
            entry("root-gost2015.key").cert,
        ]),
    };
    cms::sign_spec(&entry("inter-user-gost2015-sign"), &[], &spec).unwrap()
}
fn limits(input_bytes: u64, container_bytes: u64) -> ResourceLimits {
    ResourceLimits {
        input_bytes,
        container_bytes,
        ..ResourceLimits::default()
    }
}
fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 64,
        max_bytes: 8 << 20,
        max_item_bytes: 1 << 20,
        max_crl_bytes: 8 << 20,
        max_crl_item_bytes: 1 << 20,
        max_total_bytes: 8 << 20,
        max_chain_len: 8,
        max_proofs: 8,
        max_coverage_parts: 1024,
        max_coverage_bytes: 1 << 30,
    }
}
fn verify(
    wire: &[u8],
    detached: Option<&[u8]>,
    limits: ResourceLimits,
    known_length: bool,
) -> Result<oncl_core::VerificationReport, OperationError> {
    let dir = tempfile::tempdir().unwrap();
    let services = ValidationServices::new(
        CaSet::new(vec![cert::parse(&synthetic_cert("root-gost2015")).unwrap()]),
        vec![entry("inter-gost2015.key").cert],
        Arc::new(NoNetwork),
        NetworkPolicy::only_endpoints(Vec::<String>::new()).unwrap(),
        Arc::new(|| NOW),
    );
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_validation(services)
            .with_temporary_store(TemporaryStore::new(dir.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let mut wire = Cursor::new(wire);
    let mut content = detached.map(Cursor::new);
    let length = |len: usize| known_length.then_some(len as u64);
    let detached = content
        .as_mut()
        .map(|cursor| Source::sequential(cursor, length(DATA.len())));
    let wire_len = wire.get_ref().len();
    engine.verify(
        &VerifyRequest::cades(AdesLevel::B, evidence_limits()),
        Source::sequential(&mut wire, length(wire_len)),
        detached,
        &mut ctx,
    )
}

#[test]
fn a_cades_document_of_exactly_input_bytes_verifies_attached_and_detached() {
    for attached in [true, false] {
        let wire = signed(attached);
        let detached = (!attached).then_some(DATA);
        assert!(
            wire.len() > DATA.len(),
            "the signature structure alone is larger than the document allowance"
        );
        for known in [true, false] {
            let report = verify(&wire, detached, limits(DATA.len() as u64, 1 << 20), known)
                .unwrap_or_else(|e| panic!("attached={attached} known={known}: {e:?}"));
            assert_eq!(report.signers.len(), 1);
        }
    }
}

#[test]
fn a_cades_document_one_byte_past_input_bytes_is_input_limit() {
    for attached in [true, false] {
        let wire = signed(attached);
        let detached = (!attached).then_some(DATA);
        for known in [true, false] {
            let error = verify(
                &wire,
                detached,
                limits(DATA.len() as u64 - 1, 1 << 20),
                known,
            )
            .unwrap_err();
            assert_eq!(
                error.code(),
                ErrorCode::InputLimit,
                "attached={attached} known={known}"
            );
        }
    }
}

#[test]
fn a_cades_signature_structure_past_container_bytes_is_refused() {
    for attached in [true, false] {
        let wire = signed(attached);
        let detached = (!attached).then_some(DATA);
        let structure = (wire.len() - if attached { DATA.len() } else { 0 }) as u64;
        for known in [true, false] {
            let error = verify(
                &wire,
                detached,
                limits(DATA.len() as u64, structure / 2),
                known,
            )
            .unwrap_err();
            assert!(
                matches!(
                    error.code(),
                    ErrorCode::ContainerLimit | ErrorCode::InputLimit
                ),
                "attached={attached} known={known}: {error:?}"
            );
        }
    }
}
