//! One legacy ABI profile translator and one shared bounded CMS builder; no raw key access.
use super::*;
use crate::{Action, keys::AuthorizedSigner};
use oncl_pki::{
    cms,
    digest::DigestValue,
    key::{DigestSigner, KeyError, SigAlg},
    validation::{self, ValidationContext, Verdict},
};
use std::cell::{Cell, RefCell};

struct RecordedSigner<'ctx, 'state> {
    signer: AuthorizedSigner<'ctx>,
    applied: &'state Cell<AppliedState>,
    failure: &'state RefCell<Option<OperationError>>,
}
pub(super) fn aggregate(old: AppliedState, new: AppliedState) -> AppliedState {
    match (old, new) {
        (AppliedState::Unknown, _) | (_, AppliedState::Unknown) => AppliedState::Unknown,
        (AppliedState::Applied, _) | (_, AppliedState::Applied) => AppliedState::Applied,
        _ => AppliedState::NotApplied,
    }
}
impl DigestSigner for RecordedSigner<'_, '_> {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        self.signer.certificate()
    }
    fn algorithm(&self) -> SigAlg {
        self.signer.algorithm()
    }
    fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
        match self.signer.sign_digest(digest) {
            Ok(signature) => {
                self.applied
                    .set(aggregate(self.applied.get(), AppliedState::Applied));
                Ok(signature)
            }
            Err(error) => {
                let applied = error.applied_state();
                self.applied.set(aggregate(self.applied.get(), applied));
                *self.failure.borrow_mut() = Some(error);
                Err(KeyError::BackendFailure.with_applied_state(applied))
            }
        }
    }
}
fn abi_error(error: abi::HostError) -> OperationError {
    match error.code {
        abi::ErrorCode::Denied => OperationError::PermissionDenied,
        abi::ErrorCode::Limit => ProcessingError::ContainerLimit.into(),
        _ => ProcessingError::InvalidInput("invalid CMS capability profile").into(),
    }
}
fn cms_error(error: cms::CmsError) -> OperationError {
    match error {
        cms::CmsError::Key(error) => error.into(),
        _ => ProcessingError::InvalidInput("invalid CMS capability profile or container").into(),
    }
}
impl Backend<'_, '_> {
    pub(super) fn sign_cms(
        &mut self,
        import: Import,
        bytes: &[u8],
    ) -> Result<Vec<u8>, OperationError> {
        let args = if import == Import::KeysSignCms {
            let args: abi::SignCmsArgs = decode(bytes)?;
            abi::SignCmsExArgs {
                handle: args.handle,
                content: abi::CmsContent::Data(args.data),
                encapsulate: args.attached,
                cosign: abi::CoSign::Auto,
                econtent_type: None,
                digest: None,
                attrs: abi::SignedAttrs {
                    content_type: true,
                    message_digest: true,
                    signing_certificate_v2: true,
                    signing_time: Some(abi::SigningTime {
                        at: abi::TimeSource::Now,
                        form: abi::TimeForm::Auto,
                    }),
                    extra: Vec::new(),
                },
                certificates: abi::CmsCerts::Signer,
                timestamp: args.timestamp.then_some(abi::TsaChoice::Basics),
                output: abi::CmsOutput::Der,
            }
        } else {
            decode::<abi::SignCmsExArgs>(bytes)?
        };
        let binding = self
            .bindings
            .keys
            .iter()
            .find(|key| key.handle == args.handle)
            .ok_or(OperationError::PermissionDenied)?;
        self.authorize(import, Some(&binding.key.selector().key_id()))?;
        if self.state.released.contains(&args.handle) {
            return Err(OperationError::PermissionDenied);
        }
        let action = if matches!(args.content, abi::CmsContent::Digest(_)) {
            Action::SignDigest
        } else {
            Action::Sign
        };
        if !self.ctx.grant.allows(action)
            || (action == Action::SignDigest && !self.ctx.policy.allow_prehashed)
        {
            return Err(OperationError::PermissionDenied);
        }
        if action == Action::SignDigest && (args.encapsulate || !args.attrs.message_digest) {
            return Err(ProcessingError::InvalidInput(
                "prehashed CMS requires detached signed messageDigest",
            )
            .into());
        }
        let host = self
            .engine
            .validation
            .as_ref()
            .ok_or(OperationError::MissingValidationServices)?;
        let spec = oncl_plugin::headless::cms_spec(&args, (host.clock)()).map_err(abi_error)?;
        let chain = if matches!(args.certificates, abi::CmsCerts::Chain) {
            binding
                .metadata
                .as_ref()
                .ok_or(OperationError::PermissionDenied)?
                .chain
        } else {
            &[]
        };
        if matches!(args.certificates, abi::CmsCerts::Chain) {
            let metadata = binding
                .metadata
                .as_ref()
                .ok_or(OperationError::PermissionDenied)?;
            super::metadata::admit_bound_metadata(
                self.state,
                &self.ctx.scope,
                metadata.certificate,
                chain,
                "",
            )?;
        }
        // Decode/normalization/attributes/certificates are admitted before the shared
        // bounded builder allocates, independently of the guest's linear memory.
        let content = match &args.content {
            abi::CmsContent::Data(data) | abi::CmsContent::Digest(data) => data.as_ref(),
        };
        self.ctx.scope.account_input(content.len() as u64)?;
        self.preflight_cosign(&args)?;
        let tsa = args
            .timestamp
            .as_ref()
            .map(|choice| {
                self.with_pki(import, |services| {
                    services
                        .resolve_tsa(choice)
                        .map_err(abi_error)?
                        .map_err(|_| OperationError::ValidationRequired)
                })
            })
            .transpose()?;
        let indices = self.engine.prepare_sign_keys(
            &[KeyRequest::new(
                binding.key.selector(),
                binding.key.secret(),
            )],
            self.ctx,
            action,
        )?;
        let signer = self.engine.operation_signer(indices[0], self.ctx, action)?;
        if let abi::CmsContent::Digest(digest) = &args.content {
            DigestValue::from_bytes(signer.algorithm().hash_alg(), digest)?;
        }
        let applied = Cell::new(self.state.applied);
        let failure = RefCell::new(None);
        let mut signer = RecordedSigner {
            signer,
            applied: &applied,
            failure: &failure,
        };
        let admission = self
            .state
            .admission
            .as_mut()
            .ok_or(OperationError::InvalidContext)?;
        let admission_failure = RefCell::new(None);
        let scope = &self.ctx.scope;
        let transfer = self.transfer;
        let mut admit = |plan: cms::CmsAdmission| {
            let result = super::metadata::admit_cms_output(
                admission,
                scope,
                transfer,
                import,
                args.output,
                plan,
            );
            if let Err(error) = result {
                *admission_failure.borrow_mut() = Some(error);
                return Err(cms::CmsError::Key(KeyError::BackendFailure));
            }
            Ok(())
        };
        let signed = cms::sign_spec_with_signer(&mut signer, chain, &spec, &mut admit);
        drop(signer);
        self.state.applied = applied.get();
        if let Some(error) = failure.into_inner() {
            return Err(error);
        }
        if let Some(error) = admission_failure.into_inner() {
            return Err(error);
        }
        let mut der = signed.map_err(cms_error)?;
        self.ctx.scope.checkpoint()?;
        if let Some(tsa) = tsa {
            match self.with_pki(import, |services| Ok(services.timestamp(&der, &tsa)))? {
                Ok(stamped) => der = stamped,
                Err(failure) => {
                    return Ok(abi::encode(&Ok::<_, abi::HostError>(
                        abi::CmsOutcome::TspFailed(failure),
                    )));
                }
            }
        }
        let output = oncl_plugin::headless::format_cms(der, args.output);
        self.ctx.scope.account_output(output.len() as u64)?;
        if import == Import::KeysSignCms {
            Ok(abi::encode(&Ok::<_, abi::HostError>(output)))
        } else {
            Ok(abi::encode(&Ok::<_, abi::HostError>(
                abi::CmsOutcome::Signed(output),
            )))
        }
    }
    fn preflight_cosign(&self, args: &abi::SignCmsExArgs) -> Result<(), OperationError> {
        let (existing, detached) = match (&args.cosign, &args.content) {
            (abi::CoSign::Into(cms), abi::CmsContent::Data(data)) => {
                (Some(cms.as_ref()), Some(data.as_ref()))
            }
            (abi::CoSign::Into(cms), abi::CmsContent::Digest(_)) => (Some(cms.as_ref()), None),
            (abi::CoSign::Auto, abi::CmsContent::Data(data)) if cms::signer_count(data).is_ok() => {
                (Some(data.as_ref()), None)
            }
            _ => (None, None),
        };
        let Some(existing) = existing else {
            return Ok(());
        };
        let host = self
            .engine
            .validation
            .as_ref()
            .ok_or(OperationError::MissingValidationServices)?;
        let counted = self.ctx.http(host.http.as_ref());
        let transport = oncl_pki::http::deadline::DeadlineTransport::new(
            &counted,
            &host.network,
            &self.ctx.scope,
        );
        let result = validation::validate_cms(
            existing,
            detached,
            &ValidationContext {
                policy: self.ctx.policy.validation,
                now: (host.clock)(),
                anchors: &host.anchors,
                intermediates: &host.intermediates,
                http: &transport,
            },
            &self.ctx.scope,
        );
        transport.finish()?;
        self.ctx.network_status()?;
        let report = result.map_err(|error| match error {
            validation::ValidationError::Processing(e) => OperationError::from(e),
            _ => OperationError::ValidationRequired,
        })?;
        if report.verdict == Verdict::Valid {
            Ok(())
        } else {
            Err(OperationError::ValidationRequired)
        }
    }
}

impl Backend<'_, '_> {
    pub(super) fn verify_cms(&mut self, bytes: &[u8]) -> Result<Vec<u8>, OperationError> {
        use oncl_pki::validation::CheckStatus;
        let args: abi::VerifyArgs = decode(bytes)?;
        let host = self.engine.validation_context(self.ctx, Action::Validate)?;
        self.ctx
            .account_borrowed(&args.cms, args.data.as_deref().map(|b| b.as_ref()))?;
        self.ctx.scope.account_container(args.cms.len() as u64)?;
        // Guest certificates may help build paths, but cannot become trust anchors.
        let mut candidates = host.intermediates.clone();
        if let Some(chain) = &args.chain {
            for cert in chain {
                candidates.push(
                    oncl_pki::cert::parse(cert).map_err(|_| {
                        ProcessingError::InvalidInput("invalid candidate certificate")
                    })?,
                );
            }
        }
        let counted = self.ctx.http(host.http.as_ref());
        let transport = oncl_pki::http::deadline::DeadlineTransport::new(
            &counted,
            &host.network,
            &self.ctx.scope,
        );
        let report = validation::validate_cms(
            &args.cms,
            args.data.as_deref().map(|b| b.as_ref()),
            &ValidationContext {
                policy: self.ctx.policy.validation,
                now: (host.clock)(),
                anchors: &host.anchors,
                intermediates: &candidates,
                http: &transport,
            },
            &self.ctx.scope,
        );
        transport.finish()?;
        self.ctx.network_status()?;
        let report = report.map_err(|error| match error {
            validation::ValidationError::Processing(e) => OperationError::from(e),
            _ => ProcessingError::InvalidInput("malformed CMS verification input").into(),
        })?;
        let mut projected = self.with_pki(Import::CmsVerify, |services| {
            services
                .cms_metadata(&args.cms, args.data.as_deref().map(|b| b.as_ref()))
                .map_err(abi_error)
        })?;
        if projected.signers.len() != report.signers.len() {
            return Err(OperationError::InvalidContext);
        }
        fn checked(status: CheckStatus, detail: abi::Check, fallback: abi::Problem) -> abi::Check {
            match status {
                CheckStatus::Passed => abi::Check::Ok,
                CheckStatus::NotApplicable => abi::Check::Skipped,
                CheckStatus::Failed => match detail {
                    abi::Check::Fail(_) => detail,
                    _ => abi::Check::Fail(fallback),
                },
                CheckStatus::Unavailable => abi::Check::Fail(abi::Problem::StatusUnknown),
            }
        }
        for (target, source) in projected.signers.iter_mut().zip(report.signers.iter()) {
            target.signature = checked(
                source.signature,
                target.signature.clone(),
                abi::Problem::BadSignature,
            );
            target.path = checked(source.chain, target.path.clone(), abi::Problem::PathInvalid);
            target.validity = checked(
                source.validity,
                target.validity.clone(),
                abi::Problem::Expired,
            );
            target.revocation = checked(
                source.revocation,
                target.revocation.clone(),
                abi::Problem::StatusUnknown,
            );
            if source.key_usage == CheckStatus::Failed {
                target.path = abi::Check::Fail(abi::Problem::PathInvalid);
            }
            if let Some(tsp) = &mut target.tsp {
                tsp.check = checked(
                    source.timestamp,
                    tsp.check.clone(),
                    abi::Problem::TspInvalid,
                );
            }
        }
        if args.first_signer_only {
            projected.signers.truncate(1);
        }
        Ok(abi::encode(&Ok::<_, abi::HostError>(projected)))
    }
}
