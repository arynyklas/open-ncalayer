//! The `kz.gov.pki.knca.commonUtils` module (the original's `NCALayerCommonBundle`), built
//! into the core as a WebAssembly module.
//!
//! A request is `{"method", "args"?: [positional], "uuid"?}`; the original finds the method
//! by reflection over its `CommonUtils` class, and so does this module's dispatcher. The
//! reply is `{"code":"200"|"500","message"?,"responseObject"?,"uuid"?}`.
//!
//! The module reads the requests and writes the replies, with the original's messages; the
//! core shows the windows, opens the keys, builds certificate paths, signs, time-stamps and
//! reads the files pages name ([`Core`]). The private keys never reach the module. The
//! dialog language is the process's (the core's shared state), Russian until
//! `changeLocale`.

mod dispatch;
mod methods;

#[cfg(target_arch = "wasm32")]
mod guest;

use oncl_pdk::abi::{
    CertDetails, CertInfo, CmsOutcome, FlowArgs, HostResult, KeyDescription, PageRead, PathOutcome,
    SignCmsExArgs, StampArgs, StampOutcome,
};
use oncl_pdk::{AddInfo, Locale};

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.knca.commonUtils";

/// What the module asks of the core. A failure the module has no answer for (the core
/// refusing what the module never sends) is the module's failure: the connection is
/// dropped.
pub trait Core {
    /// A key the user chose, usable until dropped.
    type Key;

    /// The dialog language of the process.
    fn locale(&self) -> Locale;
    /// Sets the dialog language of the process.
    fn set_locale(&self, locale: Locale);
    /// A debugging line in the core's log.
    fn debug(&self, line: &str);
    /// The language of this call's windows.
    fn call_locale(&self, locale: Locale);
    /// The storages of the tokens connected, in Kalkan's order.
    fn active_tokens(&self) -> Vec<String>;
    /// The readers holding a token of the storage `storage`.
    fn readers(&self, storage: &str) -> Vec<String>;
    /// The storage and key dialogs of `flow`: the key picked, `None` if cancelled.
    fn choose_key(&self, flow: &FlowArgs) -> Option<Self::Key>;
    /// The key's certificate, DER.
    fn certificate<'k>(&self, key: &'k Self::Key) -> &'k [u8];
    /// The key's alias, algorithm and certificate.
    fn describe(&self, key: &Self::Key) -> KeyDescription;
    /// The details of a certificate the core gave.
    fn cert_info(&self, der: &[u8]) -> CertInfo;
    /// Kalkan's view of a certificate the core gave.
    fn cert_details(&self, der: &[u8]) -> CertDetails;
    /// A certification path from `der` through the core's CAs, now or at its notAfter.
    fn path(&self, der: &[u8]) -> PathOutcome;
    /// A CMS signature.
    fn sign_cms(&self, key: &Self::Key, args: SignCmsExArgs) -> HostResult<CmsOutcome>;
    /// A time-stamp on a signer.
    fn stamp(&self, args: &StampArgs) -> HostResult<StampOutcome>;
    /// An XML signature: the whole document, or the `element` put into `parent`.
    fn sign_xml(
        &self,
        key: &Self::Key,
        xml: &[u8],
        element: Option<&str>,
        parent: Option<&str>,
    ) -> HostResult<Vec<u8>>;
    /// A file the page names.
    fn page_read(&self, path: &str) -> PageRead;
    /// The file chooser of the file type `kind`, starting in `directory`; `invalid` with
    /// the cause `file.unknown_kind` for an unknown type.
    fn choose_kind(&self, kind: &str, directory: &str) -> HostResult<Option<String>>;
}

/// The reply to `request` from the page of `add_info`.
pub fn handle(core: &impl Core, request: &str, add_info: &AddInfo) -> String {
    core.call_locale(core.locale());
    dispatch::process(core, request, add_info)
}
