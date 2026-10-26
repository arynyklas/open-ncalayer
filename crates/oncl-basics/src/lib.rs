//! The `kz.gov.pki.knca.basics` module: `CommonInvoker` over the classes `PKIExtras`
//! (`sign`: cms with NCA time-stamps, raw, and enveloped XMLDSig) and `PKIEssentials`
//! (`generateCsr`: new keys in PKCS#12 key files and their requests; `importCertificate`:
//! certificates installed next to those keys).
//!
//! Dialogs go through a [`Prompter`]; dialog flows run one at a time process-wide, so a
//! second request waits for the first one's dialogs to finish. The keys offered are checked
//! against `signerParams.chain` and, through the same [`HttpTransport`] as time-stamping,
//! their OCSP responders.
//!
//! The crate also holds what the other modules share with it: the [`Prompter`] dialogs, the
//! dialog-flow turn ([`lock_dialog_flow`]) and the rules for paths a page names
//! ([`PageFile`], [`local_page_path`]).

mod essentials;
mod filter;
mod page_file;
mod prompt;
mod sign;
#[cfg(feature = "testing")]
pub mod testing;

pub use filter::{
    Availability, ChainPolicy, DisabledReason, KeyFilter, OCSP_DEADLINE, availabilities,
};
pub use page_file::{
    MAX_PAGE_FILE, PageFile, PageFileError, is_device_path, is_network_path, local_page_path,
};
pub use prompt::{
    Action, CsrAnswer, CsrPrompt, FileKind, FilePrompt, ImportAnswer, ImportPrompt, KeyCandidate,
    KeyPrompt, Locale, OpenError, PasswordPrompt, Prompt, Prompter, RecentPathStore, StorageAnswer,
    StorageKind, StoragePrompt,
};

use oncl_pki::http::HttpTransport;
use oncl_pki::tsp::TsaProfile;
use oncl_protocol::invoker::{self, CallResult, Failure, NlClass};
use oncl_protocol::{AddInfo, Module};
use serde_json::{Map, Value};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use time::OffsetDateTime;

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.knca.basics";

/// Serializes the module's dialog flows process-wide: the dialogs of two requests never
/// interleave, and a second request waits for the first instead of failing as busy.
static DIALOG_FLOW: Mutex<()> = Mutex::new(());

/// Takes the process-wide dialog-flow turn the module's own flows take: another module
/// showing the same dialogs holds it for its whole flow, so flows of different modules do
/// not interleave either.
pub fn lock_dialog_flow() -> MutexGuard<'static, ()> {
    DIALOG_FLOW.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The `kz.gov.pki.knca.basics` module.
pub struct Basics {
    prompter: Arc<dyn Prompter>,
    recent: Arc<dyn RecentPathStore>,
    http: Arc<dyn HttpTransport>,
    tsa: TsaProfile,
    clock: fn() -> OffsetDateTime,
}

impl Basics {
    /// The module with the basics TSA profile ([`TsaProfile::basics_default`]) and the
    /// system clock.
    pub fn new(
        prompter: Arc<dyn Prompter>,
        recent: Arc<dyn RecentPathStore>,
        http: Arc<dyn HttpTransport>,
    ) -> Self {
        Basics {
            prompter,
            recent,
            http,
            tsa: TsaProfile::basics_default(),
            clock: OffsetDateTime::now_utc,
        }
    }

    /// The same module time-stamping with `p`.
    #[must_use]
    pub fn with_tsa(self, p: TsaProfile) -> Self {
        Basics { tsa: p, ..self }
    }

    /// The same module reading the time (signingTime, certificate validity, path validation
    /// and OCSP) from `f`.
    #[must_use]
    pub fn with_clock(self, f: fn() -> OffsetDateTime) -> Self {
        Basics { clock: f, ..self }
    }
}

impl Module for Basics {
    fn process(&self, request: &str, add_info: &AddInfo) -> String {
        invoker::invoke(request, add_info, &[&PkiExtras(self), &PkiEssentials(self)])
    }
}

/// `PKIExtras`, the default class.
struct PkiExtras<'a>(&'a Basics);

impl NlClass for PkiExtras<'_> {
    fn class_name(&self) -> &'static str {
        "PKIExtras"
    }

    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        add_info: &AddInfo,
    ) -> Option<CallResult> {
        match method {
            "sign" => Some(match args {
                Some(args) => sign::sign(self.0, args, add_info),
                None => Err(demands_arguments(method)),
            }),
            _ => None,
        }
    }
}

/// `PKIEssentials`, reachable only by name.
struct PkiEssentials<'a>(&'a Basics);

impl NlClass for PkiEssentials<'_> {
    fn class_name(&self) -> &'static str {
        "PKIEssentials"
    }

    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        add_info: &AddInfo,
    ) -> Option<CallResult> {
        let call = match method {
            "generateCsr" => essentials::generate_csr,
            "importCertificate" => essentials::import_certificate,
            _ => return None,
        };
        Some(match args {
            Some(args) => call(self.0, args, add_info),
            None => Err(demands_arguments(method)),
        })
    }
}

/// `CommonInvoker`'s answer to a defined method called without an `args` object.
fn demands_arguments(method: &str) -> Failure {
    Failure::General(Some(format!("{method} demands arguments")))
}
