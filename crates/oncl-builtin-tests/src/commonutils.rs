//! `kz.gov.pki.knca.commonUtils`.

use crate::Lazy;
use oncl_flows::Prompter;
use oncl_flows::testing::MemoryRecentPath;
use oncl_pki::http::HttpTransport;
use oncl_pki::pkix::CaSet;
use oncl_plugin::HostServices;
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_token::Tokens;
use std::sync::Arc;
use time::OffsetDateTime;

pub use oncl_builtin_commonutils::MODULE_NAME;

struct Settings {
    prompter: Arc<dyn Prompter>,
    http: Arc<dyn HttpTransport>,
    cas: Option<CaSet>,
    clock: Option<fn() -> OffsetDateTime>,
    tokens: Option<Arc<Tokens>>,
}

/// The `kz.gov.pki.knca.commonUtils` module, configured as the daemon configures it.
pub struct CommonUtils(Lazy<Settings>);

impl CommonUtils {
    /// The module with Kalkan's TSA profile, the production CAs, the system clock and
    /// no tokens.
    pub fn new(prompter: Arc<dyn Prompter>, http: Arc<dyn HttpTransport>) -> Self {
        CommonUtils(Lazy::new(Settings {
            prompter,
            http,
            cas: None,
            clock: None,
            tokens: None,
        }))
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
}

fn build(s: Settings) -> Box<dyn Module> {
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

impl Module for CommonUtils {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info, build)
    }
}
