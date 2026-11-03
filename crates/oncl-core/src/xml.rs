//! Real source XML signing and proof-only extension, sharing host authority and PKI.
use crate::{
    Action, Engine, OperationContext, OperationError, OperationReport, SignProfile, SignProvenance,
    keys::KeyRequest, sign::Output,
};
use oncl_pki::{
    cms::ades::ValidationMaterial,
    evidence::{AdesLevel, EvidenceError},
    http::deadline::DeadlineTransport,
    io::{Source, StagedArtifact, XmlSignatureOutput},
    key::{AppliedState, DigestSigner, KeyError, SigAlg},
    resource::ProcessingError,
    validation::{ValidationContext, ValidationPolicy},
};
use oncl_xml::{XmlSignProfile, XmlSourceError, XmlVerifyProfile};
use std::io::Write;
pub(crate) fn error(error: XmlSourceError) -> OperationError {
    match error {
        XmlSourceError::Processing(error)
        | XmlSourceError::Evidence(EvidenceError::Processing(error)) => error.into(),
        XmlSourceError::Evidence(EvidenceError::Limit) => ProcessingError::MetadataLimit.into(),
        XmlSourceError::Xml(oncl_xml::XmlError::Key(error)) => OperationError::Key(error),
        XmlSourceError::AlgorithmDenied => OperationError::Key(KeyError::UnsupportedAlgorithm),
        XmlSourceError::Acquisition(_) | XmlSourceError::Evidence(EvidenceError::Timestamp(_)) => {
            OperationError::ValidationRequired
        }
        _ => {
            ProcessingError::InvalidInput("unsupported or malformed XML signature/evidence").into()
        }
    }
}
fn intersect(a: &[SigAlg], b: &[SigAlg]) -> &'static [SigAlg] {
    let mut mask = 0;
    for (i, alg) in [SigAlg::Gost2004, SigAlg::Gost2015_512, SigAlg::RsaSha256]
        .iter()
        .enumerate()
    {
        if a.contains(alg) && b.contains(alg) {
            mask |= 1 << i;
        }
    }
    const SETS: [&[SigAlg]; 8] = [
        &[],
        &[SigAlg::Gost2004],
        &[SigAlg::Gost2015_512],
        &[SigAlg::Gost2004, SigAlg::Gost2015_512],
        &[SigAlg::RsaSha256],
        &[SigAlg::Gost2004, SigAlg::RsaSha256],
        &[SigAlg::Gost2015_512, SigAlg::RsaSha256],
        &[SigAlg::Gost2004, SigAlg::Gost2015_512, SigAlg::RsaSha256],
    ];
    SETS[mask]
}
struct TrackedSigner<'a> {
    signer: &'a mut dyn DigestSigner,
    applied: AppliedState,
}
impl DigestSigner for TrackedSigner<'_> {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        self.signer.certificate()
    }
    fn algorithm(&self) -> SigAlg {
        self.signer.algorithm()
    }
    fn sign_digest(&mut self, digest: &oncl_pki::digest::DigestValue) -> Result<Vec<u8>, KeyError> {
        self.applied = AppliedState::Unknown;
        let result = self.signer.sign_digest(digest);
        self.applied = match &result {
            Ok(_) => AppliedState::Applied,
            Err(error) => error.applied_state(),
        };
        result
    }
}
fn after(error: OperationError, applied: AppliedState) -> OperationError {
    if applied == AppliedState::NotApplied {
        error
    } else {
        OperationError::AfterKeyUse {
            source: Box::new(error),
            applied,
        }
    }
}
pub(crate) enum LegacySpec<'a> {
    Xml(oncl_xml::XmlSignSpec<'a>),
    Xades(oncl_xml::xades::XadesSpec<'a>),
}
enum LegacyPrepared<'a> {
    Xml(oncl_xml::PreparedLegacySign<'a>),
    Xades(oncl_xml::xades::PreparedXadesSpec<'a>),
}
impl Engine {
    pub(crate) fn sign_xml_legacy_operation(
        &self,
        key: KeyRequest<'_>,
        spec: LegacySpec<'_>,
        input: Source<'_>,
        output: Output<'_>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        match output {
            Output::Staged(stage) => self.sign_xml_legacy_staged(key, spec, input, stage, ctx),
            Output::Writer(writer) => {
                let store = self
                    .temporary
                    .as_ref()
                    .ok_or(OperationError::MissingTemporaryStore)?;
                let mut stage = store.stage(&mut ctx.scope)?;
                let report = self.sign_xml_legacy_staged(key, spec, input, &mut stage, ctx)?;
                stage
                    .copy_to(writer)
                    .map_err(|e| after(e.into(), report.applied))?;
                Ok(report)
            }
        }
    }
    fn sign_xml_legacy_staged(
        &self,
        key: KeyRequest<'_>,
        spec: LegacySpec<'_>,
        input: Source<'_>,
        stage: &mut StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        let mut output = XmlSignatureOutput::new(stage, &ctx.scope)?;
        let validation = self.validation_context(ctx, Action::Sign)?;
        let store = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let transport =
            DeadlineTransport::new(validation.http.as_ref(), &validation.network, &ctx.scope);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (validation.clock)(),
            anchors: &validation.anchors,
            intermediates: &validation.intermediates,
            http: &transport,
        };
        let services = oncl_xml::xades::XadesServices {
            validation: &context,
            network: &validation.network,
            temporary: store,
            tsa: self.cades.as_ref().map(|c| &c.tsa),
            material: ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            evidence_limits: self.cades.as_ref().map(|c| c.evidence_limits),
            host_clock: Some(validation.clock.as_ref()),
        };
        let (prepared, report_profile) = match spec {
            LegacySpec::Xml(spec) => (
                LegacyPrepared::Xml(
                    oncl_xml::prepare_legacy_source(input, &spec, store, &mut ctx.scope)
                        .map_err(error)?,
                ),
                SignProfile::Xml,
            ),
            LegacySpec::Xades(spec) => {
                let level = match spec.level {
                    oncl_xml::xades::XadesLevel::B => AdesLevel::B,
                    oncl_xml::xades::XadesLevel::T => AdesLevel::T,
                    oncl_xml::xades::XadesLevel::Lt => AdesLevel::Lt,
                };
                if level > AdesLevel::B && self.cades.is_none() {
                    return Err(OperationError::MissingCadesConfiguration);
                }
                (
                    LegacyPrepared::Xades(
                        oncl_xml::xades::prepare_spec_source(
                            input,
                            &spec,
                            context.now,
                            &services,
                            &mut ctx.scope,
                        )
                        .map_err(error)?,
                    ),
                    SignProfile::Xades(level),
                )
            }
        };
        let index = self.prepare_sign_keys(std::slice::from_ref(&key), ctx, Action::Sign)?[0];
        let mut signer = self.operation_signer(index, ctx, Action::Sign)?;
        let mut tracked = TrackedSigner {
            signer: &mut signer,
            applied: AppliedState::NotApplied,
        };
        let mut resources = ctx.scope.shared_view();
        let result = match prepared {
            LegacyPrepared::Xades(prepared) => {
                prepared.sign_transaction(&mut tracked, &services, &mut output, &mut resources)
            }
            LegacyPrepared::Xml(prepared) => (|| {
                let summary =
                    prepared.sign_transaction(&mut tracked, &mut output, &mut resources)?;
                let profile = XmlVerifyProfile {
                    canonicalization: oncl_xml::C14nProfile::KalkanLegacy,
                    allowed_signature_algorithms: ctx.policy.allowed_signature_algorithms,
                    evidence_limits: self.cades.as_ref().map(|c| c.evidence_limits),
                    ..Default::default()
                };
                let verification = oncl_xml::verify_source_with_clock(
                    output.source()?,
                    &profile,
                    store,
                    &context,
                    &validation.network,
                    validation.clock.as_ref(),
                    &mut resources,
                )?;
                Ok(oncl_xml::xades::XadesReport {
                    summary,
                    verification,
                })
            })(),
        };
        let applied = tracked.applied;
        let report = result.map_err(|e| after(error(e), applied))?;
        transport.finish().map_err(|e| after(e.into(), applied))?;
        if report.verification.validation.verdict != oncl_pki::validation::Verdict::Valid {
            return Err(after(OperationError::ValidationRequired, applied));
        }
        output
            .finish(&resources)
            .map_err(|e| after(e.into(), applied))?;
        Ok(OperationReport::xml_operation(
            ctx.id,
            report_profile,
            SignProvenance::Document,
            applied,
            report,
        ))
    }
    pub(crate) fn sign_xml_operation(
        &self,
        key: KeyRequest<'_>,
        profile: XmlSignProfile<'_>,
        level: Option<AdesLevel>,
        input: Source<'_>,
        output: Output<'_>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        match output {
            Output::Staged(stage) => self.sign_xml_staged(key, profile, level, input, stage, ctx),
            Output::Writer(writer) => {
                let store = self
                    .temporary
                    .as_ref()
                    .ok_or(OperationError::MissingTemporaryStore)?;
                let mut stage = store.stage(&mut ctx.scope)?;
                let report = self.sign_xml_staged(key, profile, level, input, &mut stage, ctx)?;
                stage
                    .copy_to(writer)
                    .map_err(|e| after(e.into(), report.applied))?;
                Ok(report)
            }
        }
    }
    fn sign_xml_staged(
        &self,
        key: KeyRequest<'_>,
        mut profile: XmlSignProfile<'_>,
        level: Option<AdesLevel>,
        input: Source<'_>,
        stage: &mut StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        let mut output = XmlSignatureOutput::new(stage, &ctx.scope)?;
        let validation = self.validation_context(ctx, Action::Sign)?;
        let store = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        if level.is_some_and(|l| l > AdesLevel::B) && self.cades.is_none() {
            return Err(OperationError::MissingCadesConfiguration);
        }
        if level.is_some_and(|l| l > AdesLevel::B) {
            oncl_pki::evidence::validate_timestamp_configuration(
                &self
                    .cades
                    .as_ref()
                    .ok_or(OperationError::MissingCadesConfiguration)?
                    .tsa,
                ValidationPolicy::StrictOnline,
            )
            .map_err(|e| error(XmlSourceError::Evidence(e)))?;
        }
        profile.allowed_signature_algorithms = intersect(
            profile.allowed_signature_algorithms,
            ctx.policy.allowed_signature_algorithms,
        );
        let transport =
            DeadlineTransport::new(validation.http.as_ref(), &validation.network, &ctx.scope);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (validation.clock)(),
            anchors: &validation.anchors,
            intermediates: &validation.intermediates,
            http: &transport,
        };
        let xml_services = oncl_xml::xades::XadesServices {
            validation: &context,
            network: &validation.network,
            temporary: store,
            tsa: self.cades.as_ref().map(|c| &c.tsa),
            material: ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            evidence_limits: self.cades.as_ref().map(|c| c.evidence_limits),
            host_clock: Some(validation.clock.as_ref()),
        };
        if let Some(level) = level {
            xml_services.preflight(level, &profile).map_err(error)?;
            profile.evidence_limits = Some(xml_services.bounded_limits(&profile).map_err(error)?);
        }
        // Parse unique IDs/placement/transforms and every existing signer BEFORE
        // opening a key. The opaque prepared source owns the exact frozen bytes.
        let mut prepared = if let Some(level) = level {
            oncl_xml::xades::prepare_source(
                input,
                &oncl_xml::xades::XadesSourceSpec {
                    xml: profile,
                    level,
                    signing_time: context.now,
                },
                store,
                &mut ctx.scope,
            )
        } else {
            oncl_xml::prepare_source(input, &profile, store, &mut ctx.scope)
        }
        .map_err(error)?;
        prepared
            .verify_existing_with_clock(
                &context,
                &validation.network,
                validation.clock.as_ref(),
                &mut ctx.scope,
            )
            .map_err(error)?;
        transport.finish()?;
        let index = self.prepare_sign_keys(std::slice::from_ref(&key), ctx, Action::Sign)?[0];
        let mut signer = self.operation_signer(index, ctx, Action::Sign)?;
        let mut tracked = TrackedSigner {
            signer: &mut signer,
            applied: AppliedState::NotApplied,
        };
        let mut resources = ctx.scope.shared_view();
        let result = if let Some(level) = level {
            oncl_xml::xades::sign_prepared(
                prepared,
                level,
                context.now,
                &mut tracked,
                &xml_services,
                &mut output,
                &mut resources,
            )
        } else {
            oncl_xml::sign_prepared_with_clock(
                prepared,
                &mut tracked,
                &context,
                &validation.network,
                validation.clock.as_ref(),
                &mut output,
                &mut resources,
            )
        };
        let applied = tracked.applied;
        transport.finish().map_err(|e| after(e.into(), applied))?;
        resources
            .checkpoint()
            .map_err(|e| after(e.into(), applied))?;
        let report = result.map_err(|e| after(error(e), applied))?;
        output
            .finish(&resources)
            .map_err(|e| after(e.into(), applied))?;
        Ok(OperationReport::xml_operation(
            ctx.id,
            level.map_or(SignProfile::Xml, SignProfile::Xades),
            SignProvenance::Document,
            applied,
            report,
        ))
    }
    pub(crate) fn extend_xml_operation(
        &self,
        request: &crate::ExtendRequest<'_>,
        profile: &XmlVerifyProfile,
        input: Source<'_>,
        output: Option<&mut dyn Write>,
        staged: Option<&mut StagedArtifact>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        match (output, staged) {
            (None, Some(stage)) => self.extend_xml_staged(request, profile, input, stage, ctx),
            (Some(writer), None) => {
                self.validation_context(ctx, Action::Extend)?;
                let store = self
                    .temporary
                    .as_ref()
                    .ok_or(OperationError::MissingTemporaryStore)?;
                let mut stage = store.stage(&mut ctx.scope)?;
                let report = self.extend_xml_staged(request, profile, input, &mut stage, ctx)?;
                stage.copy_to(writer)?;
                Ok(report)
            }
            _ => Err(ProcessingError::InvalidInput("exactly one XML output required").into()),
        }
    }
    fn extend_xml_staged(
        &self,
        request: &crate::ExtendRequest<'_>,
        profile: &XmlVerifyProfile,
        input: Source<'_>,
        stage: &mut StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        let level = request.level;
        let mut output = XmlSignatureOutput::new(stage, &ctx.scope)?;
        let validation = self.validation_context(ctx, Action::Extend)?;
        let store = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        if level > AdesLevel::B && self.cades.is_none() {
            return Err(OperationError::MissingCadesConfiguration);
        }
        let transport =
            DeadlineTransport::new(validation.http.as_ref(), &validation.network, &ctx.scope);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (validation.clock)(),
            anchors: &validation.anchors,
            intermediates: &validation.intermediates,
            http: &transport,
        };
        let services = oncl_xml::xades::XadesServices {
            validation: &context,
            network: &validation.network,
            temporary: store,
            tsa: self.cades.as_ref().map(|c| &c.tsa),
            material: crate::cades::material(&request.material),
            evidence_limits: self.cades.as_ref().map(|c| c.evidence_limits),
            host_clock: Some(validation.clock.as_ref()),
        };
        let mut profile = profile.clone();
        profile.evidence_limits =
            intersect_evidence_limits(request.limits, profile.evidence_limits);
        profile.allowed_signature_algorithms = intersect(
            profile.allowed_signature_algorithms,
            ctx.policy.allowed_signature_algorithms,
        );
        let generation = XmlSignProfile {
            max_metadata_bytes: profile.max_metadata_bytes,
            max_work: profile.max_work,
            evidence_limits: profile.evidence_limits,
            ..Default::default()
        };
        services.preflight(level, &generation).map_err(error)?;
        profile.evidence_limits = Some(services.bounded_limits(&generation).map_err(error)?);
        let result = oncl_xml::xades::extend_transaction(
            input,
            level,
            &profile,
            &services,
            &mut output,
            &mut ctx.scope,
        );
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(error)?;
        output.finish(&ctx.scope)?;
        let achieved = report
            .verification
            .minimum_level()
            .ok_or(OperationError::ValidationRequired)?;
        Ok(OperationReport::xml_operation(
            ctx.id,
            SignProfile::Xades(achieved),
            SignProvenance::EvidenceExtension,
            AppliedState::NotApplied,
            report,
        ))
    }
}

pub(crate) fn intersect_evidence_limits(
    a: Option<oncl_pki::evidence::EvidenceLimits>,
    b: Option<oncl_pki::evidence::EvidenceLimits>,
) -> Option<oncl_pki::evidence::EvidenceLimits> {
    match (a, b) {
        (Some(a), Some(b)) => Some(oncl_pki::evidence::EvidenceLimits {
            max_items: a.max_items.min(b.max_items),
            max_bytes: a.max_bytes.min(b.max_bytes),
            max_item_bytes: a.max_item_bytes.min(b.max_item_bytes),
            max_chain_len: a.max_chain_len.min(b.max_chain_len),
            max_proofs: a.max_proofs.min(b.max_proofs),
            max_coverage_parts: a.max_coverage_parts.min(b.max_coverage_parts),
            max_coverage_bytes: a.max_coverage_bytes.min(b.max_coverage_bytes),
        }),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}
