//! `kz.gov.pki.knca.applet.Applet`.

use crate::{Available, Backend, Lazy, resolve};
use oncl_basics::Prompter;
use oncl_basics::testing::MemoryRecentPath;
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_plugin::HostServices;
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_token::Tokens;
use std::sync::Arc;

pub use oncl_builtin_applet::MODULE_NAME;

const AVAILABLE: Available = Available {
    native: true,
    wasm: true,
};

struct Settings {
    prompter: Arc<dyn Prompter>,
    tokens: Option<Arc<Tokens>>,
    backend: Option<Backend>,
}

/// The `kz.gov.pki.knca.applet.Applet` module, configured as the daemon configures it.
pub struct Applet(Lazy<Settings>);

impl Applet {
    /// The module, showing its dialogs with `prompter`, without tokens.
    pub fn new(prompter: Arc<dyn Prompter>) -> Self {
        Applet(Lazy::new(Settings {
            prompter,
            tokens: None,
            backend: None,
        }))
    }

    /// The same module with the hardware tokens of `tokens`.
    #[must_use]
    pub fn with_tokens(mut self, tokens: Arc<Tokens>) -> Self {
        self.0.settings().tokens = Some(tokens);
        self
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

fn build(s: Settings) -> Box<dyn Module> {
    match resolve(MODULE_NAME, s.backend, AVAILABLE) {
        Backend::Native => {
            let mut m = oncl_applet::Applet::new(s.prompter);
            if let Some(t) = s.tokens {
                m = m.with_tokens(t);
            }
            Box::new(m)
        }
        Backend::Wasm => {
            let services = HostServices::new(
                s.prompter,
                Arc::new(MemoryRecentPath::new(None)),
                Arc::new(Offline),
                s.tokens.unwrap_or_else(Tokens::disabled),
            );
            crate::guest(MODULE_NAME, services, None)
        }
    }
}

impl Module for Applet {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
