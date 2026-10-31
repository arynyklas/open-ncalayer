//! `kz.gov.pki.knca.basics`.

use crate::{Available, Backend, Lazy, resolve};
use oncl_basics::{OcspCache, Prompter, RecentPathStore};
use oncl_pki::http::HttpTransport;
use oncl_pki::tsp::TsaProfile;
use oncl_plugin::HostServices;
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_token::Tokens;
use std::sync::Arc;
use time::OffsetDateTime;

pub use oncl_builtin_basics::MODULE_NAME;

const AVAILABLE: Available = Available {
    native: true,
    wasm: true,
};

struct Settings {
    prompter: Arc<dyn Prompter>,
    recent: Arc<dyn RecentPathStore>,
    http: Arc<dyn HttpTransport>,
    tsa: Option<TsaProfile>,
    clock: Option<fn() -> OffsetDateTime>,
    ocsp_cache: Option<Arc<OcspCache>>,
    tokens: Option<Arc<Tokens>>,
    backend: Option<Backend>,
}

/// The `kz.gov.pki.knca.basics` module, as `oncl_basics::Basics` is configured.
pub struct Basics(Lazy<Settings>);

impl Basics {
    /// The module with the basics TSA profile, the system clock, an empty OCSP memory and no
    /// tokens.
    pub fn new(
        prompter: Arc<dyn Prompter>,
        recent: Arc<dyn RecentPathStore>,
        http: Arc<dyn HttpTransport>,
    ) -> Self {
        Basics(Lazy::new(Settings {
            prompter,
            recent,
            http,
            tsa: None,
            clock: None,
            ocsp_cache: None,
            tokens: None,
            backend: None,
        }))
    }

    /// The same module time-stamping with `p`.
    #[must_use]
    pub fn with_tsa(mut self, p: TsaProfile) -> Self {
        self.0.settings().tsa = Some(p);
        self
    }

    /// The same module reading the time from `f`.
    #[must_use]
    pub fn with_clock(mut self, f: fn() -> OffsetDateTime) -> Self {
        self.0.settings().clock = Some(f);
        self
    }

    /// The same module keeping its OCSP answers in `cache`.
    #[must_use]
    pub fn with_ocsp_cache(mut self, cache: Arc<OcspCache>) -> Self {
        self.0.settings().ocsp_cache = Some(cache);
        self
    }

    /// The same module offering the hardware tokens of `tokens`.
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
            let mut m = oncl_basics::Basics::new(s.prompter, s.recent, s.http);
            if let Some(p) = s.tsa {
                m = m.with_tsa(p);
            }
            if let Some(f) = s.clock {
                m = m.with_clock(f);
            }
            if let Some(c) = s.ocsp_cache {
                m = m.with_ocsp_cache(c);
            }
            if let Some(t) = s.tokens {
                m = m.with_tokens(t);
            }
            Box::new(m)
        }
        Backend::Wasm => {
            let mut services = HostServices::new(
                s.prompter,
                s.recent,
                s.http,
                s.tokens.unwrap_or_else(Tokens::disabled),
            );
            if let Some(p) = s.tsa {
                services.tsa = p;
            }
            if let Some(f) = s.clock {
                services.clock = f;
            }
            if let Some(c) = s.ocsp_cache {
                services.ocsp_cache = c;
            }
            crate::guest(MODULE_NAME, services, None)
        }
    }
}

impl Module for Basics {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
