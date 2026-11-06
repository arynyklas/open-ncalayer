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
        // Keep the exact static reason: a post-key failure of a multi-hour operation must say
        // which format/evidence check rejected, not collapse into one opaque message.
        XmlSourceError::Malformed(reason) | XmlSourceError::Unsupported(reason) => {
            ProcessingError::InvalidInput(reason).into()
        }
        XmlSourceError::Xml(oncl_xml::XmlError::TooLarge) => {
            ProcessingError::InvalidInput("XML input exceeds the XML processing limits").into()
        }
        XmlSourceError::Evidence(EvidenceError::InvalidBinding) => ProcessingError::InvalidInput(
            "invalid evidence owner, coverage graph or timestamp configuration",
        )
        .into(),
        _ => {
            ProcessingError::InvalidInput("unsupported or malformed XML signature/evidence").into()
        }
    }
}
pub(crate) fn intersect(a: &[SigAlg], b: &[SigAlg]) -> &'static [SigAlg] {
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
pub(crate) fn intersect_verification(a: &[SigAlg], b: &[SigAlg]) -> &'static [SigAlg] {
    use SigAlg::{Gost2004 as G04, Gost2015_512 as G15, RsaSha1 as R1, RsaSha256 as R256};
    const SETS: [&[SigAlg]; 16] = [
        &[],
        &[G04],
        &[G15],
        &[G04, G15],
        &[R256],
        &[G04, R256],
        &[G15, R256],
        &[G04, G15, R256],
        &[R1],
        &[G04, R1],
        &[G15, R1],
        &[G04, G15, R1],
        &[R256, R1],
        &[G04, R256, R1],
        &[G15, R256, R1],
        &[G04, G15, R256, R1],
    ];
    let mut mask = 0;
    for (i, algorithm) in [G04, G15, R256, R1].iter().enumerate() {
        if a.contains(algorithm) && b.contains(algorithm) {
            mask |= 1 << i;
        }
    }
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
fn check_legacy_output(ctx: &OperationContext, length: u64) -> Result<(), ProcessingError> {
    ctx.scope.check_output_capacity(length)?;
    #[cfg(feature = "plugins")]
    if ctx
        .plugin_xml_output_limit
        .is_some_and(|limit| length > limit)
    {
        return Err(ProcessingError::ContainerLimit);
    }
    Ok(())
}

enum LegacySpecRef<'spec, 'data> {
    Xml(&'spec oncl_xml::XmlSignSpec<'data>),
    Xades(&'spec oncl_xml::xades::XadesSpec<'data>),
}
enum LegacyPrepared<'a> {
    Xml(oncl_xml::PreparedLegacySign<'a>),
    Xades(oncl_xml::xades::PreparedXadesSpec<'a>),
}
// Direct signing and batch admission share actual opaque preparation. Batch
// drops transient indexes instead of retaining a workspace for every item.
fn prepare_xml<'a>(
    input: Source<'_>,
    mut profile: XmlSignProfile<'a>,
    level: Option<AdesLevel>,
    services: &oncl_xml::xades::XadesServices<'_>,
    scope: &mut oncl_pki::resource::ResourceScope,
) -> Result<oncl_xml::PreparedXmlSign<'a>, OperationError> {
    if let Some(level) = level {
        services.preflight(level, &profile).map_err(error)?;
        profile.evidence_limits = Some(services.bounded_limits(&profile).map_err(error)?);
    }
    let mut prepared = if let Some(level) = level {
        oncl_xml::xades::prepare_source(
            input,
            &oncl_xml::xades::XadesSourceSpec {
                xml: profile,
                level,
                signing_time: services.validation.now,
            },
            services.temporary,
            scope,
        )
    } else {
        oncl_xml::prepare_source(input, &profile, services.temporary, scope)
    }
    .map_err(error)?;
    if let Some(clock) = services.host_clock {
        prepared.verify_existing_with_clock(services.validation, services.network, clock, scope)
    } else {
        prepared.verify_existing(services.validation, services.network, scope)
    }
    .map_err(error)?;
    Ok(prepared)
}
fn prepare_legacy<'a>(
    input: Source<'_>,
    spec: LegacySpecRef<'_, 'a>,
    services: &oncl_xml::xades::XadesServices<'_>,
    scope: &mut oncl_pki::resource::ResourceScope,
) -> Result<(LegacyPrepared<'a>, SignProfile), OperationError> {
    match spec {
        LegacySpecRef::Xml(spec) => Ok((
            LegacyPrepared::Xml(
                oncl_xml::prepare_legacy_source(input, spec, services.temporary, scope)
                    .map_err(error)?,
            ),
            SignProfile::Xml,
        )),
        LegacySpecRef::Xades(spec) => {
            let level = match spec.level {
                oncl_xml::xades::XadesLevel::B => AdesLevel::B,
                oncl_xml::xades::XadesLevel::T => AdesLevel::T,
                oncl_xml::xades::XadesLevel::Lt => AdesLevel::Lt,
            };
            if level > AdesLevel::B && services.tsa.is_none() {
                return Err(OperationError::MissingCadesConfiguration);
            }
            Ok((
                LegacyPrepared::Xades(
                    oncl_xml::xades::prepare_spec_source(
                        input,
                        spec,
                        services.validation.now,
                        services,
                        scope,
                    )
                    .map_err(error)?,
                ),
                SignProfile::Xades(level),
            ))
        }
    }
}
impl Engine {
    /// Admit actual captured XML before provider resolution. No prepared index,
    /// cached verdict, signing authority or output escapes this extra pass.
    pub(crate) fn preflight_batch_xml(
        &self,
        request: &crate::SignRequest<'_>,
        input: Source<'_>,
        ctx: &mut OperationContext,
    ) -> Result<(), OperationError> {
        let validation = self.validation_context(ctx, Action::Sign)?;
        let store = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let scoped_http = ctx.http(validation.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &validation.network, &ctx.scope);
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
        use crate::request::SignMode;
        let result = match &request.mode {
            SignMode::Wsse(_, profile) => {
                let _profile_admission = profile.preflight(&ctx.scope).map_err(error)?;
                let mut profile = profile.clone();
                profile.verification.xml.allowed_signature_algorithms = intersect(
                    profile.verification.xml.allowed_signature_algorithms,
                    ctx.policy.allowed_signature_algorithms,
                );
                let mut prepared =
                    oncl_xml::wsse::prepare_source(input, &profile, store, &mut ctx.scope)
                        .map_err(error)?;
                prepared
                    .verify_existing(
                        &context,
                        &validation.network,
                        &mut ctx.scope,
                        Some(validation.clock.as_ref()),
                    )
                    .map_err(error)
            }
            SignMode::Xml(_, profile, level) => {
                let mut profile = profile.clone();
                profile.allowed_signature_algorithms = intersect(
                    profile.allowed_signature_algorithms,
                    ctx.policy.allowed_signature_algorithms,
                );
                prepare_xml(input, profile, *level, &services, &mut ctx.scope).map(drop)
            }
            SignMode::XmlLegacy(_, spec) => {
                prepare_legacy(input, LegacySpecRef::Xml(spec), &services, &mut ctx.scope).map(drop)
            }
            SignMode::XadesLegacy(_, spec) => {
                prepare_legacy(input, LegacySpecRef::Xades(spec), &services, &mut ctx.scope)
                    .map(drop)
            }
            _ => Err(ProcessingError::InvalidInput("XML batch preparation mode").into()),
        };
        transport.finish()?;
        ctx.scope.checkpoint()?;
        result
    }
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
        // A signed document necessarily contains these structural element tags,
        // even before a leaf certificate/algorithm is available for exact sizing.
        check_legacy_output(ctx, b"<Signature></Signature>".len() as u64)?;
        let store = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let scoped_http = ctx.http(validation.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &validation.network, &ctx.scope);
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
        let borrowed = match &spec {
            LegacySpec::Xml(spec) => LegacySpecRef::Xml(spec),
            LegacySpec::Xades(spec) => LegacySpecRef::Xades(spec),
        };
        let (prepared, report_profile) =
            prepare_legacy(input, borrowed, &services, &mut ctx.scope)?;
        let index = self.prepare_sign_keys(std::slice::from_ref(&key), ctx, Action::Sign)?[0];
        let mut signer = self.operation_signer(index, ctx, Action::Sign)?;
        let mut tracked = TrackedSigner {
            signer: &mut signer,
            applied: AppliedState::NotApplied,
        };
        let mut resources = ctx.scope.shared_view();
        let mut admit = |length| check_legacy_output(ctx, length);
        let result = match prepared {
            LegacyPrepared::Xades(prepared) => prepared.sign_transaction(
                &mut tracked,
                &services,
                &mut output,
                &mut resources,
                &mut admit,
            ),
            LegacyPrepared::Xml(prepared) => (|| {
                let summary = prepared.sign_transaction(
                    &mut tracked,
                    &mut output,
                    &mut resources,
                    &mut admit,
                )?;
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
        let scoped_http = ctx.http(validation.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &validation.network, &ctx.scope);
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
        // The same actual preparation admits batch sources before provider
        // resolution. Dispatch deliberately repeats it without a verdict cache.
        let prepared = prepare_xml(input, profile, level, &xml_services, &mut ctx.scope)?;
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
    pub(crate) fn sign_wsse_operation(
        &self,
        key: KeyRequest<'_>,
        profile: oncl_xml::wsse::SourceWsseSignProfile,
        input: Source<'_>,
        output: Output<'_>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        match output {
            Output::Staged(stage) => self.sign_wsse_staged(key, profile, input, stage, ctx),
            Output::Writer(writer) => {
                let store = self
                    .temporary
                    .as_ref()
                    .ok_or(OperationError::MissingTemporaryStore)?;
                let mut stage = store.stage(&mut ctx.scope)?;
                let report = self.sign_wsse_staged(key, profile, input, &mut stage, ctx)?;
                stage
                    .copy_to(writer)
                    .map_err(|e| after(e.into(), report.applied))?;
                Ok(report)
            }
        }
    }
    fn sign_wsse_staged(
        &self,
        key: KeyRequest<'_>,
        mut profile: oncl_xml::wsse::SourceWsseSignProfile,
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
        profile.verification.xml.allowed_signature_algorithms = intersect(
            profile.verification.xml.allowed_signature_algorithms,
            ctx.policy.allowed_signature_algorithms,
        );
        profile.verification.xml.evidence_limits = intersect_evidence_limits(
            self.cades.as_ref().map(|c| c.evidence_limits),
            profile.verification.xml.evidence_limits,
        );
        let scoped_http = ctx.http(validation.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &validation.network, &ctx.scope);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (validation.clock)(),
            anchors: &validation.anchors,
            intermediates: &validation.intermediates,
            http: &transport,
        };
        let mut prepared = oncl_xml::wsse::prepare_source(input, &profile, store, &mut ctx.scope)
            .map_err(error)?;
        prepared
            .verify_existing(
                &context,
                &validation.network,
                &mut ctx.scope,
                Some(validation.clock.as_ref()),
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
        let result = oncl_xml::wsse::sign_prepared(
            prepared,
            &mut tracked,
            &context,
            &validation.network,
            Some(validation.clock.as_ref()),
            &mut output,
            &mut resources,
        );
        let applied = tracked.applied;
        transport.finish().map_err(|e| after(e.into(), applied))?;
        resources
            .checkpoint()
            .map_err(|e| after(e.into(), applied))?;
        let (summary, verification) = result.map_err(|e| after(error(e), applied))?;
        output
            .finish(&resources)
            .map_err(|e| after(e.into(), applied))?;
        Ok(OperationReport::xml_operation(
            ctx.id,
            SignProfile::Wsse,
            SignProvenance::Document,
            applied,
            oncl_xml::xades::XadesReport {
                summary,
                verification: verification.xml,
            },
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
        let scoped_http = ctx.http(validation.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &validation.network, &ctx.scope);
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
            max_crl_bytes: a.max_crl_bytes.min(b.max_crl_bytes),
            max_crl_item_bytes: a.max_crl_item_bytes.min(b.max_crl_item_bytes),
            max_total_bytes: a.max_total_bytes.min(b.max_total_bytes),
            max_chain_len: a.max_chain_len.min(b.max_chain_len),
            max_proofs: a.max_proofs.min(b.max_proofs),
            max_coverage_parts: a.max_coverage_parts.min(b.max_coverage_parts),
            max_coverage_bytes: a.max_coverage_bytes.min(b.max_coverage_bytes),
        }),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}
