//! `kz.gov.pki.knca.commonUtils`.

use crate::{Available, Backend, Lazy, resolve};
use oncl_basics::Prompter;
use oncl_basics::testing::MemoryRecentPath;
use oncl_pki::http::HttpTransport;
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::TsaProfile;
use oncl_plugin::HostServices;
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_token::Tokens;
use std::sync::Arc;
use time::OffsetDateTime;

pub use oncl_builtin_commonutils::MODULE_NAME;

const AVAILABLE: Available = Available {
    native: true,
    wasm: true,
};

struct Settings {
    prompter: Arc<dyn Prompter>,
    http: Arc<dyn HttpTransport>,
    tsa: Option<TsaProfile>,
    cas: Option<CaSet>,
    clock: Option<fn() -> OffsetDateTime>,
    tokens: Option<Arc<Tokens>>,
    backend: Option<Backend>,
}

/// The `kz.gov.pki.knca.commonUtils` module, as `oncl_commonutils::CommonUtils` is
/// configured.
pub struct CommonUtils(Lazy<Settings>);

impl CommonUtils {
    /// The module with the commonUtils TSA profile, the production CAs, the system clock and
    /// no tokens.
    pub fn new(prompter: Arc<dyn Prompter>, http: Arc<dyn HttpTransport>) -> Self {
        CommonUtils(Lazy::new(Settings {
            prompter,
            http,
            tsa: None,
            cas: None,
            clock: None,
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

    /// The same module building certificate paths to `cas`.
    #[must_use]
    pub fn with_cas(mut self, cas: CaSet) -> Self {
        self.0.settings().cas = Some(cas);
        self
    }

    /// The same module reading the time from `f`.
    #[must_use]
    pub fn with_clock(mut self, f: fn() -> OffsetDateTime) -> Self {
        self.0.settings().clock = Some(f);
        self
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
            let mut m = oncl_commonutils::CommonUtils::new(s.prompter, s.http);
            if let Some(p) = s.tsa {
                m = m.with_tsa(p);
            }
            if let Some(c) = s.cas {
                m = m.with_cas(c);
            }
            if let Some(f) = s.clock {
                m = m.with_clock(f);
            }
            if let Some(t) = s.tokens {
                m = m.with_tokens(t);
            }
            Box::new(m)
        }
        Backend::Wasm => {
            assert!(
                s.tsa.is_none(),
                "the built-in commonUtils time-stamps with Kalkan's profile only"
            );
            let mut services = HostServices::new(
                s.prompter,
                Arc::new(MemoryRecentPath::new(None)),
                s.http,
                s.tokens.unwrap_or_else(Tokens::disabled),
            );
            if let Some(c) = s.cas {
                services.cas = Arc::new(c);
            }
            if let Some(f) = s.clock {
                services.clock = f;
            }
            crate::guest(MODULE_NAME, services, None)
        }
    }
}

impl Module for CommonUtils {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
