//! `kz.gov.pki.ncalayerservices.accessory`.

use crate::{Available, Backend, Lazy, resolve};
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_plugin::HostServices;
use oncl_plugin::core::CoreHooks;
use oncl_protocol::{AddInfo, Module, Reply};
use std::sync::Arc;

pub use oncl_builtin_accessory::{MODULE_NAME, SYMNAME, bundles};
pub use oncl_plugin::core::{Bundles, UiCallback, UiRequest};

const AVAILABLE: Available = Available {
    native: true,
    wasm: true,
};

struct Settings {
    services: Vec<String>,
    bundles: Arc<dyn Bundles>,
    ui: UiCallback,
    backend: Option<Backend>,
}

/// The `kz.gov.pki.ncalayerservices.accessory` module, as `oncl_accessory::Accessory` is
/// configured.
pub struct Accessory(Lazy<Settings>);

impl Accessory {
    /// The module, reporting `services` as the built-in modules, with the plugins of
    /// `bundles`, and asking `ui` to open windows.
    pub fn new(services: Vec<String>, bundles: Arc<dyn Bundles>, ui: UiCallback) -> Self {
        Accessory(Lazy::new(Settings {
            services,
            bundles,
            ui,
            backend: None,
        }))
    }

    /// The same module built as `backend`.
    #[must_use]
    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.0.settings().backend = Some(backend);
        self
    }
}

/// No network: the module needs none.
struct Offline;

impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline"))
    }
}

/// [`Bundles`] and [`UiCallback`] of the facade, for the native module.
struct NativeBundles(Arc<dyn Bundles>);

impl oncl_accessory::Bundles for NativeBundles {
    fn services(&self) -> Vec<String> {
        self.0.services()
    }

    fn bundles(&self) -> Vec<(String, String)> {
        self.0.bundles()
    }

    fn request_install(&self, symname: &str, origin: &str) -> bool {
        self.0.request_install(symname, origin)
    }
}

/// The native module's window request as the core's.
fn ui_request(request: oncl_accessory::UiRequest) -> UiRequest {
    match request {
        oncl_accessory::UiRequest::Settings => UiRequest::Settings,
        oncl_accessory::UiRequest::BundleManager => UiRequest::BundleManager,
        oncl_accessory::UiRequest::KeystoreExplorer => UiRequest::KeystoreExplorer,
        oncl_accessory::UiRequest::AdesSigning => UiRequest::AdesSigning,
        oncl_accessory::UiRequest::InstallBundle { symname, origin } => {
            UiRequest::InstallBundle { symname, origin }
        }
        oncl_accessory::UiRequest::AdesValidation => UiRequest::AdesValidation,
    }
}

fn build(s: Settings) -> Box<dyn Module> {
    match resolve(MODULE_NAME, s.backend, AVAILABLE) {
        Backend::Native => {
            let ui = s.ui;
            Box::new(oncl_accessory::Accessory::new(
                s.services,
                Arc::new(NativeBundles(s.bundles)),
                Arc::new(move |r| ui(ui_request(r))),
            ))
        }
        Backend::Wasm => {
            let services = HostServices::new(
                Arc::new(ScriptedPrompter::new(Vec::<Step>::new())),
                Arc::new(MemoryRecentPath::new(None)),
                Arc::new(Offline),
                oncl_token::Tokens::disabled(),
            );
            let hooks = CoreHooks {
                builtin_modules: s.services,
                bundles: s.bundles,
                ui: s.ui,
                core_version: env!("CARGO_PKG_VERSION").to_owned(),
            };
            crate::guest(MODULE_NAME, services, Some(Arc::new(hooks)))
        }
    }
}

impl Module for Accessory {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
