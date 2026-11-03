use crate::{
    Action, ExecutionGrant, OperationContext, OperationError, OperationId, OperationPolicy,
};
use oncl_pki::digest::{DigestValue, hash_source};
use oncl_pki::io::Source;
use oncl_pki::key::HashAlg;
use oncl_pki::resource::{OperationControl, ResourceLimits, SharedBudget};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Only dependencies used by implemented methods are configured. Hash needs no
/// keys, temporary store, network, GUI, or async runtime. Reuse one engine, or
/// attach the application's one shared budget to every engine with the builder.
#[derive(Debug)]
pub struct EngineServices {
    limits: ResourceLimits,
    shared: Option<Arc<SharedBudget>>,
    keys: Option<crate::keys::KeyServices>,
    validation: Option<Arc<crate::ValidationServices>>,
    temporary: Option<oncl_pki::io::TemporaryStore>,
    cades: Option<crate::CadesConfiguration>,
    metadata: Option<Arc<dyn crate::ReadMetadataProvider>>,
    inspection_limits: oncl_pki::info::InspectionLimits,
    #[cfg(feature = "plugins")]
    plugins: Option<crate::plugins::PluginRegistry>,
}
impl EngineServices {
    pub fn hash_only(limits: ResourceLimits) -> Self {
        Self {
            limits,
            shared: None,
            keys: None,
            validation: None,
            temporary: None,
            cades: None,
            metadata: None,
            inspection_limits: oncl_pki::info::InspectionLimits::default(),
            #[cfg(feature = "plugins")]
            plugins: None,
        }
    }
    pub fn with_shared_budget(mut self, budget: Arc<SharedBudget>) -> Self {
        self.shared = Some(budget);
        self
    }
    /// Configure real source resolution and an explicit host authority/audit guard.
    pub fn with_keys(
        mut self,
        provider: Arc<dyn crate::keys::KeyProvider>,
        guard: Arc<dyn crate::keys::KeyUseGuard>,
    ) -> Self {
        self.keys = Some(crate::keys::KeyServices { provider, guard });
        self
    }
    pub fn with_validation(mut self, services: crate::ValidationServices) -> Self {
        self.validation = Some(Arc::new(services));
        self
    }
    /// Explicit host document scratch namespace; never an implicit filesystem default.
    pub fn with_temporary_store(mut self, store: oncl_pki::io::TemporaryStore) -> Self {
        self.temporary = Some(store);
        self
    }
    pub fn with_cades(mut self, configuration: crate::CadesConfiguration) -> Self {
        self.cades = Some(configuration);
        self
    }
    pub fn with_metadata_provider(
        mut self,
        provider: Arc<dyn crate::ReadMetadataProvider>,
    ) -> Self {
        self.metadata = Some(provider);
        self
    }
    /// Trusted host resource profile, never selected by a container/request.
    pub fn with_inspection_limits(mut self, limits: oncl_pki::info::InspectionLimits) -> Self {
        self.inspection_limits = limits;
        self
    }
    #[cfg(feature = "plugins")]
    pub fn with_plugins(mut self, plugins: crate::plugins::PluginRegistry) -> Self {
        self.plugins = Some(plugins);
        self
    }
}

#[derive(Debug)]
pub struct Engine {
    limits: ResourceLimits,
    budget: Arc<SharedBudget>,
    pub(crate) identity: Arc<()>,
    pub(crate) keys: Option<crate::keys::KeyServices>,
    pub(crate) validation: Option<Arc<crate::ValidationServices>>,
    pub(crate) temporary: Option<oncl_pki::io::TemporaryStore>,
    pub(crate) cades: Option<crate::CadesConfiguration>,
    pub(crate) metadata: Option<Arc<dyn crate::ReadMetadataProvider>>,
    pub(crate) inspection_limits: oncl_pki::info::InspectionLimits,
    #[cfg(feature = "plugins")]
    pub(crate) plugins: Option<crate::plugins::PluginRegistry>,
}

/// One original invocation root admitted for bounded metadata intake, without
/// any cryptographic/key authority. Consuming it is the only context transition.
pub struct OperationAdmission {
    id: OperationId,
    owner: Arc<()>,
    scope: oncl_pki::resource::ResourceScope,
    original_scope: oncl_pki::resource::ResourceScope,
}
impl OperationAdmission {
    pub fn id(&self) -> OperationId {
        self.id
    }
    pub fn resources(&mut self) -> &mut oncl_pki::resource::ResourceScope {
        &mut self.scope
    }
}
impl Engine {
    pub fn new(services: EngineServices) -> Result<Self, OperationError> {
        services.limits.validate()?;
        services.inspection_limits.validate()?;
        if let Some(configuration) = &services.cades {
            configuration.evidence_limits.validate().map_err(|error| {
                crate::cades::error(oncl_pki::cms::ades::AdesError::Evidence(error))
            })?;
            if configuration.tsa.hash != HashAlg::Sha256 || !configuration.tsa.require_tsa_eku {
                return Err(oncl_pki::resource::ProcessingError::InvalidInput(
                    "CAdES acquisition requires SHA-256 and TSA EKU",
                )
                .into());
            }
        }
        let budget = match services.shared {
            Some(shared) => shared,
            None => Arc::new(SharedBudget::new(services.limits.clone())?),
        };
        Ok(Self {
            limits: services.limits,
            budget,
            identity: Arc::new(()),
            keys: services.keys,
            validation: services.validation,
            temporary: services.temporary,
            cades: services.cades,
            metadata: services.metadata,
            inspection_limits: services.inspection_limits,
            #[cfg(feature = "plugins")]
            plugins: services.plugins,
        })
    }
    pub fn begin(
        &self,
        grant: ExecutionGrant,
        policy: OperationPolicy,
        control: Arc<dyn OperationControl>,
    ) -> Result<OperationContext, OperationError> {
        if grant.is_empty() {
            return Err(OperationError::PermissionDenied);
        }
        Ok(Self::admitted_context(self.admit(control)?, grant, policy))
    }
    /// Admit bounded intake before the trusted host has resolved wire metadata
    /// into authority. This does not permit any SDK operation or key opening.
    pub fn admit(
        &self,
        control: Arc<dyn OperationControl>,
    ) -> Result<OperationAdmission, OperationError> {
        let scope = self.budget.begin(self.limits.clone(), control)?;
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| OperationError::IdExhausted)?;
        Ok(OperationAdmission {
            id: OperationId(id),
            owner: self.identity.clone(),
            original_scope: scope.shared_view(),
            scope,
        })
    }
    /// Consume the original intake state only after host authorization. Scope
    /// replacement through the public mutable resource handle cannot rebound
    /// this admission onto another operation, even within the same Engine.
    pub fn begin_admitted(
        &self,
        admission: OperationAdmission,
        grant: ExecutionGrant,
        policy: OperationPolicy,
    ) -> Result<OperationContext, OperationError> {
        if !Arc::ptr_eq(&admission.owner, &self.identity)
            || !admission.scope.same_operation(&admission.original_scope)
        {
            return Err(OperationError::InvalidContext);
        }
        if grant.is_empty() {
            return Err(OperationError::PermissionDenied);
        }
        admission.scope.checkpoint()?;
        Ok(Self::admitted_context(admission, grant, policy))
    }
    fn admitted_context(
        admission: OperationAdmission,
        grant: ExecutionGrant,
        policy: OperationPolicy,
    ) -> OperationContext {
        OperationContext {
            id: admission.id,
            owner: admission.owner,
            grant,
            policy,
            scope: admission.scope,
            leases: Vec::new(),
            private_use_stopped: std::sync::atomic::AtomicBool::new(false),
            batch_item: None,
            borrowed_replay: None,
            #[cfg(feature = "plugins")]
            plugin_network: None,
            #[cfg(feature = "plugins")]
            plugin_network_budget: None,
            #[cfg(feature = "plugins")]
            plugin_pki: None,
            #[cfg(feature = "plugins")]
            plugin_xml_output_limit: None,
        }
    }
    pub fn hash(
        &self,
        algorithm: HashAlg,
        input: Source<'_>,
        ctx: &mut OperationContext,
    ) -> Result<HashReport, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if !ctx.grant.allows(Action::Hash) {
            return Err(OperationError::PermissionDenied);
        }
        let before = ctx.scope.progress().bytes_in;
        let digest = hash_source(input, algorithm, &mut ctx.scope)?;
        let bytes_in = ctx
            .scope
            .progress()
            .bytes_in
            .checked_sub(before)
            .ok_or(oncl_pki::resource::ProcessingError::InputLimit)?;
        Ok(HashReport {
            id: ctx.id,
            digest,
            bytes_in,
        })
    }
}

/// A successfully completed hash, not a signature or validation assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashReport {
    pub id: OperationId,
    pub digest: DigestValue,
    pub bytes_in: u64,
}
