//! `kz.gov.pki.ncalayerservices.accessory`.

use crate::{Available, Backend, Lazy, resolve};
use oncl_protocol::{AddInfo, Module, Reply};
use std::sync::Arc;

pub use oncl_accessory::{Bundles, MODULE_NAME, SYMNAME, UiCallback, UiRequest, bundles};

const AVAILABLE: Available = Available {
    native: true,
    wasm: false,
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

fn build(s: Settings) -> Box<dyn Module> {
    match resolve(MODULE_NAME, s.backend, AVAILABLE) {
        Backend::Native => Box::new(oncl_accessory::Accessory::new(s.services, s.bundles, s.ui)),
        Backend::Wasm => unreachable!("resolved to an available backend"),
    }
}

impl Module for Accessory {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
