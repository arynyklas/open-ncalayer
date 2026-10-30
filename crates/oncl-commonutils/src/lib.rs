//! The `kz.gov.pki.knca.commonUtils` module (the original's `NCALayerCommonBundle`).
//!
//! A request is `{"method", "args"?: [positional], "uuid"?}`; the original finds the method
//! by reflection over its `CommonUtils` class, and so does this module's dispatcher. The
//! reply is `{"code":"200"|"500","message"?,"responseObject"?,"uuid"?}`.
//!
//! Signing methods name a storage: `PKCS12` and `JKS` (read only) open the storage dialog
//! for the key file and its password, then the key dialog lists the keys of the requested
//! `keyType`. With token support off, hardware tokens answer as if none were connected; with
//! it on, `getActiveTokens` lists the storages of the tokens plugged in and a token storage
//! opens the storage dialog for the PIN of the first reader holding such a token.
//! Dialog flows take [`oncl_basics::lock_dialog_flow`], so they never interleave with
//! another module's. The dialog language is process-wide, Russian until `changeLocale`.

mod dispatch;
mod methods;

use oncl_basics::{Locale, Prompter};
use oncl_pki::http::HttpTransport;
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::TsaProfile;
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_token::Tokens;
use std::sync::{Arc, Mutex, PoisonError};
use time::OffsetDateTime;

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.knca.commonUtils";

/// The `kz.gov.pki.knca.commonUtils` module.
pub struct CommonUtils {
    prompter: Arc<dyn Prompter>,
    http: Arc<dyn HttpTransport>,
    tsa: TsaProfile,
    cas: Arc<CaSet>,
    clock: fn() -> OffsetDateTime,
    locale: Mutex<Locale>,
    tokens: Arc<Tokens>,
}

impl CommonUtils {
    /// The module with Kalkan's default TSA profile ([`TsaProfile::kalkan_default`]),
    /// the embedded NCA production CAs for the signer chains the CAdES methods check, the
    /// system clock, Russian dialogs and no tokens.
    pub fn new(prompter: Arc<dyn Prompter>, http: Arc<dyn HttpTransport>) -> Self {
        CommonUtils {
            prompter,
            http,
            tsa: TsaProfile::kalkan_default(),
            cas: Arc::new(CaSet::nca_production()),
            clock: OffsetDateTime::now_utc,
            locale: Mutex::new(Locale::Ru),
            tokens: Tokens::disabled(),
        }
    }

    /// The same module time-stamping with `p`.
    #[must_use]
    pub fn with_tsa(self, p: TsaProfile) -> Self {
        CommonUtils { tsa: p, ..self }
    }

    /// The same module checking the signer chains of the CAdES methods against `cas`
    /// instead of the NCA production CAs (the original's bundled `cacerts.jks`).
    #[must_use]
    pub fn with_cas(self, cas: CaSet) -> Self {
        CommonUtils {
            cas: Arc::new(cas),
            ..self
        }
    }

    /// The same module reading the time (signingTime, certificate chains) from `f`.
    #[must_use]
    pub fn with_clock(self, f: fn() -> OffsetDateTime) -> Self {
        CommonUtils { clock: f, ..self }
    }

    /// The same module signing with the hardware tokens of `tokens` too, while their
    /// support is on.
    #[must_use]
    pub fn with_tokens(self, tokens: Arc<Tokens>) -> Self {
        CommonUtils { tokens, ..self }
    }

    /// The current dialog language.
    fn locale(&self) -> Locale {
        *self.locale.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_locale(&self, l: Locale) {
        *self.locale.lock().unwrap_or_else(PoisonError::into_inner) = l;
    }
}

impl Module for CommonUtils {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        dispatch::process(self, request, add_info).into()
    }
}
