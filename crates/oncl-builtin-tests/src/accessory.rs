//! `kz.gov.pki.ncalayerservices.accessory`.

use crate::Lazy;
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_plugin::HostServices;
use oncl_plugin::core::CoreHooks;
use oncl_protocol::{AddInfo, Module, Reply};
use std::sync::Arc;

pub use oncl_builtin_accessory::{MODULE_NAME, SYMNAME, bundles};
pub use oncl_plugin::core::{Bundles, UiCallback, UiRequest};

struct Settings {
    services: Vec<String>,
    bundles: Arc<dyn Bundles>,
    ui: UiCallback,
}

/// The `kz.gov.pki.ncalayerservices.accessory` module, configured as the daemon configures
/// it.
pub struct Accessory(Lazy<Settings>);

impl Accessory {
    /// The module, reporting `services` as the built-in modules, with the plugins of
    /// `bundles`, and asking `ui` to open windows.
    pub fn new(services: Vec<String>, bundles: Arc<dyn Bundles>, ui: UiCallback) -> Self {
        Accessory(Lazy::new(Settings {
            services,
            bundles,
            ui,
        }))
    }
}

/// No network: the module needs none.
struct Offline;

impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline"))
    }
}

fn build(s: Settings) -> Box<dyn Module> {
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

impl Module for Accessory {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
