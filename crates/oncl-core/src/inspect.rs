//! Public structural inspection, independent of signing authority and trust.
use crate::{Action, Engine, OperationContext, OperationError, OperationId};
use oncl_pki::{
    info::{PublicEntry, PublicMetadata},
    io::{MetadataInput, Source},
};
use std::sync::Arc;
/// Secret-bearing requests are borrowed, not Debug/Clone/Serialize.
pub struct InspectRequest<'a> {
    mode: InspectMode<'a>,
}
enum InspectMode<'a> {
    Certificate,
    Container(Option<&'a str>),
    Named(&'a crate::keys::KeyRequest<'a>),
    Cms,
}
impl<'a> InspectRequest<'a> {
    pub fn certificate() -> Self {
        Self {
            mode: InspectMode::Certificate,
        }
    }
    pub fn container(password: Option<&'a str>) -> Self {
        Self {
            mode: InspectMode::Container(password),
        }
    }
    pub fn named_key(request: &'a crate::keys::KeyRequest<'a>) -> Self {
        Self {
            mode: InspectMode::Named(request),
        }
    }
    pub fn cms_metadata() -> Self {
        Self {
            mode: InspectMode::Cms,
        }
    }
}
/// Read-only providers never expose a KeyLease, signer or unlocked secret.
pub trait ReadMetadataProvider: Send + Sync {
    fn inspect(
        &self,
        request: &crate::keys::KeyRequest<'_>,
        limits: &oncl_pki::info::InspectionLimits,
        ctx: &mut OperationContext,
    ) -> Result<PublicMetadata, OperationError>;
}
impl std::fmt::Debug for dyn ReadMetadataProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadMetadataProvider { host-configured }")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionKind {
    Certificate,
    Container,
    NamedKey,
    SignatureMetadata,
}
/// Structural signature-container facts, not cryptographic/trust validation.
#[derive(Debug)]
pub struct SignatureMetadata {
    facts: oncl_pki::cms::stream::Inspection,
}
impl SignatureMetadata {
    pub fn detached(&self) -> bool {
        self.facts.detached
    }
    pub fn content_len(&self) -> u64 {
        self.facts.content_len
    }
    pub fn signer_count(&self) -> usize {
        self.facts.signer_count
    }
    pub fn content_region(&self) -> Option<oncl_pki::io::Region> {
        self.facts.content_region
    }
}
/// Public allocations cannot be detached from their admitted owner.
/// ```compile_fail
/// fn detach(report: oncl_core::InspectionReport) -> Vec<oncl_pki::info::PublicEntry> {
///     report.entries().to_vec()
/// }
/// ```
#[derive(Debug)]
pub struct InspectionReport {
    id: OperationId,
    metadata: Option<PublicMetadata>,
    cms: Option<SignatureMetadata>,
    bytes_in: u64,
    kind: InspectionKind,
}
impl InspectionReport {
    pub fn id(&self) -> OperationId {
        self.id
    }
    pub fn kind(&self) -> InspectionKind {
        self.kind
    }
    pub fn container_integrity(&self) -> Option<oncl_pki::info::MetadataIntegrity> {
        self.metadata.as_ref().map(PublicMetadata::integrity)
    }
    pub fn entries(&self) -> &[PublicEntry] {
        self.metadata.as_ref().map_or(&[], PublicMetadata::entries)
    }
    /// Structural only: these facts do not assert a valid signature or trust.
    pub fn cms(&self) -> Option<&SignatureMetadata> {
        self.cms.as_ref()
    }
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }
}
pub(crate) fn container(
    input: Source<'_>,
    password: &str,
    aliases: &[String],
    limits: &oncl_pki::info::InspectionLimits,
    scope: &mut oncl_pki::resource::ResourceScope,
) -> Result<PublicMetadata, OperationError> {
    let input = MetadataInput::read(input, scope, oncl_pki::keystore::MAX_KEY_FILE)?;
    let result = if oncl_pki::jks::is_jks(input.as_bytes()) {
        oncl_pki::jks::inspect_metadata(input.as_bytes(), password, aliases, scope, limits)
    } else {
        oncl_pki::pkcs12::inspect_metadata(input.as_bytes(), password, aliases, scope, limits)
    };
    result.map_err(Into::into)
}
impl Engine {
    pub fn inspect(
        &self,
        request: &InspectRequest<'_>,
        input: Option<Source<'_>>,
        ctx: &mut OperationContext,
    ) -> Result<InspectionReport, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if !ctx.grant.allows(Action::Inspect) {
            return Err(OperationError::PermissionDenied);
        }
        ctx.scope.checkpoint()?;
        let before = ctx.scope.progress().bytes_in;
        let kind = match request.mode {
            InspectMode::Certificate => InspectionKind::Certificate,
            InspectMode::Container(_) => InspectionKind::Container,
            InspectMode::Named(_) => InspectionKind::NamedKey,
            InspectMode::Cms => InspectionKind::SignatureMetadata,
        };
        let mut report = InspectionReport {
            id: ctx.id,
            metadata: None,
            cms: None,
            bytes_in: 0,
            kind,
        };
        match request.mode {
            InspectMode::Certificate => {
                let input = input.ok_or(OperationError::InvalidKeySource)?;
                let bytes =
                    MetadataInput::read(input, &mut ctx.scope, oncl_pki::keystore::MAX_KEY_FILE)?;
                report.metadata = Some(PublicMetadata::certificate(bytes.as_bytes(), &ctx.scope)?);
            }
            InspectMode::Container(password) => {
                if ctx.grant.metadata_aliases().is_empty() {
                    return Err(OperationError::PermissionDenied);
                }
                if ctx.grant.metadata_aliases().len() > self.inspection_limits.max_entries {
                    return Err(oncl_pki::resource::ProcessingError::MetadataLimit.into());
                }
                let password = password.ok_or(OperationError::SecretRequired)?;
                let input = input.ok_or(OperationError::InvalidKeySource)?;
                let bytes =
                    MetadataInput::read(input, &mut ctx.scope, oncl_pki::keystore::MAX_KEY_FILE)?;
                report.metadata = Some(if oncl_pki::jks::is_jks(bytes.as_bytes()) {
                    oncl_pki::jks::inspect_metadata(
                        bytes.as_bytes(),
                        password,
                        ctx.grant.metadata_aliases(),
                        &ctx.scope,
                        &self.inspection_limits,
                    )?
                } else {
                    oncl_pki::pkcs12::inspect_metadata(
                        bytes.as_bytes(),
                        password,
                        ctx.grant.metadata_aliases(),
                        &ctx.scope,
                        &self.inspection_limits,
                    )?
                });
            }
            InspectMode::Named(request) => {
                if !ctx.grant.allows_key(&request.selector().key_id()) {
                    return Err(OperationError::PermissionDenied);
                }
                if input.is_some() {
                    return Err(OperationError::InvalidKeySource);
                }
                let provider = self
                    .metadata
                    .as_deref()
                    .ok_or(OperationError::MissingMetadataProvider)?;
                let metadata = provider.inspect(request, &self.inspection_limits, ctx)?;
                metadata.check_scope(&ctx.scope)?;
                report.metadata = Some(metadata);
            }
            InspectMode::Cms => {
                let facts = oncl_pki::cms::stream::inspect(
                    input.ok_or(OperationError::InvalidKeySource)?,
                    &mut ctx.scope,
                )
                .map_err(crate::report::stream_error)?;
                report.cms = Some(SignatureMetadata { facts });
            }
        }
        ctx.scope.checkpoint()?;
        report.bytes_in = ctx
            .scope
            .progress()
            .bytes_in
            .checked_sub(before)
            .ok_or(oncl_pki::resource::ProcessingError::InputLimit)?;
        Ok(report)
    }
}
