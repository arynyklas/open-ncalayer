//! The `kz.gov.pki.knca.basics` module, built into the core as a WebAssembly module:
//! `CommonInvoker` over the classes `PKIExtras` (`sign`: cms with NCA time-stamps, raw, and
//! enveloped XMLDSig) and `PKIEssentials` (`generateCsr`: new keys in PKCS#12 key files and
//! their requests; `importCertificate`: certificates installed next to those keys).
//!
//! The module reads the requests, in the original's order and with its error texts, and
//! writes the replies; the core shows the windows, checks the keys offered (against
//! `signerParams.chain` and their OCSP responders), signs, time-stamps and writes the key
//! files ([`Core`]). The private keys never reach the module.

mod args;
mod essentials;
mod failures;
mod sign;

#[cfg(target_arch = "wasm32")]
mod guest;

use oncl_pdk::abi::{
    CertInfo, CmsOutcome, CsrChoice, CsrDialogArgs, FlowArgs, HostResult, ImportChoice,
    ImportDialogArgs, InstallCertArgs, InstalledCert, NewKey, NewKeyArgs, SignCmsExArgs,
};
use oncl_pdk::invoker::{self, CallResult, Failure, NlClass};
use oncl_pdk::serde_json::{Map, Value};
use oncl_pdk::{AddInfo, Locale};

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.knca.basics";

/// What the module asks of the core. A failure the module has no answer for (the core
/// refusing what the module never sends) is the module's failure: the connection is
/// dropped.
pub trait Core {
    /// A key the user chose, usable until dropped.
    type Key;

    /// The windows of this call speak `locale`.
    fn set_locale(&self, locale: Locale);
    /// Writes `message` to the core's log (never a password, a path or the page's data).
    fn log(&self, message: &str);
    /// The details of the certificate `der`; `None` if it is no certificate.
    fn cert_info(&self, der: &[u8]) -> Option<CertInfo>;
    /// The core's time, Unix milliseconds.
    fn now(&self) -> i64;
    /// The line separator of the core's system.
    fn line_separator(&self) -> String;
    /// The storage and key windows of `flow`: the key picked, `None` if the user cancels.
    fn choose_key(&self, flow: &FlowArgs) -> Option<Self::Key>;
    /// The certificate of `key`, DER.
    fn certificate<'k>(&self, key: &'k Self::Key) -> &'k [u8];
    /// A CMS signature with `key` as `args` say.
    fn sign_cms(&self, key: &Self::Key, args: SignCmsExArgs) -> HostResult<CmsOutcome>;
    /// A signature of `data` with `key`'s algorithm.
    fn sign_raw(&self, key: &Self::Key, data: &[u8]) -> HostResult<Vec<u8>>;
    /// `xml` with an enveloped signature of the whole document.
    fn sign_xml(&self, key: &Self::Key, xml: &[u8]) -> HostResult<Vec<u8>>;
    /// The `generateCsr` window.
    fn dialog_csr(&self, args: &CsrDialogArgs) -> HostResult<Option<CsrChoice>>;
    /// The `importCertificate` window.
    fn dialog_import(&self, args: &ImportDialogArgs) -> Option<ImportChoice>;
    /// A new key in a key file, and its request.
    fn new_key(&self, args: &NewKeyArgs) -> HostResult<NewKey>;
    /// A certificate installed next to its key.
    fn install_cert(&self, args: &InstallCertArgs) -> HostResult<InstalledCert>;
}

/// The reply to `request` from the page of `add_info`.
pub fn handle(core: &(impl Core + Sync), request: &str, add_info: &AddInfo) -> String {
    invoker::invoke(request, add_info, &[&PkiExtras(core), &PkiEssentials(core)])
}

/// `PKIExtras`, the default class.
struct PkiExtras<'a, C>(&'a C);

impl<C: Core + Sync> NlClass for PkiExtras<'_, C> {
    fn class_name(&self) -> &'static str {
        "PKIExtras"
    }

    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        _: &AddInfo,
    ) -> Option<CallResult> {
        match method {
            "sign" => Some(match args {
                Some(args) => sign::sign(self.0, args),
                None => Err(demands_arguments(method)),
            }),
            _ => None,
        }
    }
}

/// `PKIEssentials`, reachable only by name.
struct PkiEssentials<'a, C>(&'a C);

impl<C: Core + Sync> NlClass for PkiEssentials<'_, C> {
    fn class_name(&self) -> &'static str {
        "PKIEssentials"
    }

    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        _: &AddInfo,
    ) -> Option<CallResult> {
        let call = match method {
            "generateCsr" => essentials::generate_csr::<C>,
            "importCertificate" => essentials::import_certificate::<C>,
            _ => return None,
        };
        Some(match args {
            Some(args) => call(self.0, args),
            None => Err(demands_arguments(method)),
        })
    }
}

/// `CommonInvoker`'s answer to a defined method called without an `args` object.
fn demands_arguments(method: &str) -> Failure {
    Failure::General(Some(format!("{method} demands arguments")))
}
