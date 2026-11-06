use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, ExtendRequest, OperationPolicy,
};
use oncl_pki::{
    evidence::AdesLevel,
    io::Source,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct Count(Arc<AtomicUsize>);
impl Read for Count {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}
#[test]
fn evidence_extension_requires_its_own_non_private_grant_before_intake() {
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut context = engine
        .begin(
            ExecutionGrant::new([Action::Sign]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut source = Count(calls.clone());
    let error = engine
        .extend(
            &ExtendRequest::cms(AdesLevel::Lta),
            Source::sequential(&mut source, None),
            &mut Vec::new(),
            &mut context,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

fn evidence_limits() -> oncl_pki::evidence::EvidenceLimits {
    oncl_pki::evidence::EvidenceLimits {
        max_items: 64,
        max_bytes: 8 << 20,
        max_item_bytes: 1 << 20,
        max_crl_bytes: 8 << 20,
        max_crl_item_bytes: 1 << 20,
        max_total_bytes: 8 << 20,
        max_chain_len: 8,
        max_proofs: 8,
        max_coverage_parts: 1024,
        max_coverage_bytes: 10_737_418_240,
    }
}
#[test]
fn cades_acquisition_and_grant_preflight_do_not_consume_input_or_open_keys() {
    use oncl_core::{
        SignRequest,
        keys::{KeyRequest, KeySelector},
    };
    use oncl_pki::cms::ades::ValidationMaterial;
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let selector = KeySelector::inline(vec![], None);
    for granted in [Action::Sign, Action::SignDigest] {
        let mut context = engine
            .begin(
                ExecutionGrant::new([granted]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut source = Count(calls.clone());
        let error = engine
            .sign(
                SignRequest::cades_create(
                    vec![KeyRequest::new(&selector, None)],
                    true,
                    AdesLevel::T,
                    ValidationMaterial {
                        certificates: &[],
                        ocsp: &[],
                        crls: &[],
                    },
                    evidence_limits(),
                ),
                Source::sequential(&mut source, None),
                &mut Vec::new(),
                &mut context,
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            if granted == Action::Sign {
                ErrorCode::MissingCadesConfiguration
            } else {
                ErrorCode::PermissionDenied
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            error.applied_state(),
            oncl_pki::key::AppliedState::NotApplied
        );
    }
}
#[test]
fn missing_cades_configuration_survives_the_real_key_error_bridge() {
    use oncl_core::OperationError;
    use oncl_pki::key::{AppliedState, KeyError};
    for applied in [
        AppliedState::NotApplied,
        AppliedState::Applied,
        AppliedState::Unknown,
    ] {
        let error = if applied == AppliedState::NotApplied {
            OperationError::MissingCadesConfiguration
        } else {
            OperationError::AfterKeyUse {
                source: Box::new(OperationError::MissingCadesConfiguration),
                applied,
            }
        };
        let key_error: KeyError = error.into();
        let restored = OperationError::from(key_error);
        assert_eq!(restored.code(), ErrorCode::MissingCadesConfiguration);
        assert_eq!(restored.applied_state(), applied);
    }
}
