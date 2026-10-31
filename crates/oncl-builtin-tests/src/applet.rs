//! `kz.gov.pki.knca.applet.Applet`.

use crate::{Available, Backend, Lazy, resolve};
use oncl_basics::Prompter;
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_token::Tokens;
use std::sync::Arc;

pub use oncl_applet::MODULE_NAME;

const AVAILABLE: Available = Available {
    native: true,
    wasm: false,
};

struct Settings {
    prompter: Arc<dyn Prompter>,
    tokens: Option<Arc<Tokens>>,
    backend: Option<Backend>,
}

/// The `kz.gov.pki.knca.applet.Applet` module, as `oncl_applet::Applet` is configured.
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

fn build(s: Settings) -> Box<dyn Module> {
    match resolve(MODULE_NAME, s.backend, AVAILABLE) {
        Backend::Native => {
            let mut m = oncl_applet::Applet::new(s.prompter);
            if let Some(t) = s.tokens {
                m = m.with_tokens(t);
            }
            Box::new(m)
        }
        Backend::Wasm => unreachable!("resolved to an available backend"),
    }
}

impl Module for Applet {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
