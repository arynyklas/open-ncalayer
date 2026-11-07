//! What the Plugins page is offered and the engine its operations run on.
//!
//! The host (the daemon) knows which plugins are installed; this crate shows them. The host
//! implements [`ManualPluginSource`]: it builds the [`PluginRegistry`] of what the manual
//! window may run and the [`ManualListing`] (operations by plugin, installed plugins that
//! offer none, plugins that could not be read), and [`plugin_offer`] turns them into the
//! engine the page runs on.
//!
//! The engine is NOT the engine of the documents ([`crate::signing::runner::desktop_engine`]):
//! its only key guard is the [`PluginConsentGuard`], which refuses every key use that is not for
//! an approval Core issued after the user's confirmation, and the documents' own guard refuses a
//! plugin's key use in turn (`docs/dev/sdk.md`, "Manual window").

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oncl_core::keys::KeySources;
use oncl_core::plugins::{CallerContext, PluginConsentGuard, PluginRegistry};
use oncl_core::{Engine, EngineServices, OperationError};
use oncl_pki::http::{HttpMethod, HttpTransport};
use oncl_pki::io::TemporaryStore;
use oncl_pki::resource::ResourceLimits;
use oncl_pki::validation::NetworkPolicy;
use oncl_plugin::Localized;
use oncl_plugin::manual::OcspCache;
use oncl_plugin::operations::Param;
use time::OffsetDateTime;

use crate::signing::runner::{ExtraTrust, validation_services};

/// How long a plugin call may run once the user confirmed: the SDK's default operation timeout
/// (`ResourceLimits::default().operation_timeout`; the settings have no other). The worker
/// enforces it from the confirmation on ([`crate::workspace::JobControl::set_deadline`]).
pub(crate) const RUN_LIMIT: Duration = Duration::from_secs(300);

/// How long the confirmation page may stay open before it is closed (and the key store's
/// password the worker holds is dropped).
pub(crate) const CONSENT_IDLE: Duration = Duration::from_secs(300);

/// Room for opening the key and preparing the confirmation, which count against the engine's
/// deadline of the run too: the approval is bound to the operation's context, so the context
/// lives from the preparation to the end of the call.
const PREPARE_ALLOWANCE: Duration = Duration::from_secs(60);

/// One operation of an installed plugin that the page may offer.
///
/// `plugin_name` and `label` are the plugin's own text: untrusted, shown in a frame and never
/// as the host's words. `plugin_id`, `plugin_version` and `operation` were checked at parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedOperation {
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_name: Localized,
    pub operation: String,
    pub label: Localized,
    /// The parameters the form asks for, in the manifest's order.
    pub params: Vec<Param>,
    /// Whether it uses the user's key: the page runs only operations that do (what is
    /// approved is the use of the key).
    pub uses_key: bool,
    /// The exact PKI endpoints the registry granted the operation (empty without network);
    /// the call's own grant must name the same.
    pub pki_endpoints: Vec<(HttpMethod, String)>,
}

/// An installed plugin that offers no operation to the manual window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithoutOperations {
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_name: Localized,
}

/// An installed plugin whose package could not be read. The reason stays in the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnusablePlugin {
    pub plugin_id: String,
}

/// What the page lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManualListing {
    /// By plugin, each plugin's in its manifest's order.
    pub operations: Vec<OfferedOperation>,
    /// Installed plugins with no operation for this window.
    pub without_operations: Vec<WithoutOperations>,
    pub unusable: Vec<UnusablePlugin>,
}

/// What the host's plugins are, as the page needs them.
pub struct PluginOffer {
    pub(crate) engine: Arc<Engine>,
    /// The engine's guard (its `applications()` counts the keys applied).
    pub guard: Arc<PluginConsentGuard>,
    pub(crate) host: HostParts,
    /// Who the operations are registered for: the local operator of this window.
    pub(crate) caller: CallerContext,
    pub listing: ManualListing,
}

/// The host's own network for the plugins' PKI requests and the key choice's revocation check.
#[derive(Clone)]
pub(crate) struct HostParts {
    pub(crate) transport: Arc<dyn HttpTransport>,
    pub(crate) network: NetworkPolicy,
    pub(crate) ocsp_cache: Arc<OcspCache>,
}

/// Why the page has no plugins to offer.
#[derive(Debug)]
pub enum OfferError {
    /// This run of the program has no plugin service.
    Unavailable,
    /// The engine could not be made.
    Engine(OperationError),
}

/// Where the page gets its plugins from; called on a worker thread each time the list is read.
pub trait ManualPluginSource: Send + Sync {
    /// The plugins installed now.
    fn offer(&self) -> Result<PluginOffer, OfferError>;
}

/// No plugins: a program without a plugin service.
pub struct NoManualPlugins;

impl ManualPluginSource for NoManualPlugins {
    fn offer(&self) -> Result<PluginOffer, OfferError> {
        Err(OfferError::Unavailable)
    }
}

/// What the host gives to make the plugins' engine: the same authority as the documents' engine
/// has (the national PKI and what the host adds), the clock the certificates are judged by, and
/// the program's activity gate.
#[derive(Clone)]
pub struct PluginEngineKit {
    pub http: Arc<dyn HttpTransport>,
    pub extra: ExtraTrust,
    pub clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    pub activity: Option<Arc<oncl_core::activity::ActivityGate>>,
    /// A directory this program owns for temporary files (the plugins' staged outputs).
    pub spool: PathBuf,
}

/// The offer for `registry` (the host's, with `caller` registered for each listed operation).
///
/// The engine's operation deadline covers preparing, the user's reading time
/// ([`CONSENT_IDLE`]) and the call ([`RUN_LIMIT`]): one context carries them all.
///
/// # Errors
///
/// [`OfferError::Engine`] if the engine cannot be made.
pub fn plugin_offer(
    registry: PluginRegistry,
    caller: CallerContext,
    listing: ManualListing,
    kit: &PluginEngineKit,
) -> Result<PluginOffer, OfferError> {
    let guard = Arc::new(PluginConsentGuard::new());
    let (validation, network) =
        validation_services(&kit.extra, Arc::clone(&kit.http), Arc::clone(&kit.clock))
            .map_err(OfferError::Engine)?;
    let store = TemporaryStore::new(&kit.spool)
        .map_err(OperationError::from)
        .map_err(OfferError::Engine)?;
    let limits = ResourceLimits {
        operation_timeout: PREPARE_ALLOWANCE + CONSENT_IDLE + RUN_LIMIT,
        ..ResourceLimits::default()
    };
    let services = EngineServices::hash_only(limits)
        .with_plugin_keys(Arc::new(KeySources::new()), Arc::clone(&guard))
        .with_validation(validation)
        .with_temporary_store(store)
        .with_plugins(registry);
    let mut engine = Engine::new(services).map_err(OfferError::Engine)?;
    if let Some(gate) = &kit.activity {
        engine = engine.with_activity(Arc::clone(gate));
    }
    Ok(PluginOffer {
        engine: Arc::new(engine),
        guard,
        host: HostParts {
            transport: Arc::clone(&kit.http),
            network,
            ocsp_cache: Arc::new(OcspCache::new()),
        },
        caller,
        listing,
    })
}
