//! The legacy `kz.gov.pki.knca.applet.Applet` module (the original's `knca_applet`
//! `Applet`), which also answers requests without a `module`, built into the core as a
//! WebAssembly module.
//!
//! A request is `{"class"?, "method", "args"?: [positional], "uuid"?}`; the original finds
//! the method by reflection over its single `Applet` instance, and so does this module's
//! dispatcher. The reply is the original's `ResultWrapper`:
//! `{"errorCode":"NONE"|<code>,"result"?,"secondResult"?,"uuid"?}`.
//!
//! The subset the original's pages use is implemented for the file storages `PKCS12` and
//! `JKS` (read-only): the file chooser, the password dialog, key files with their requests,
//! certificate installation, password change and XML signing. With token support off,
//! hardware tokens answer as if no device were connected (`EMPTY_SLOT`, or the original's
//! answer without a device). With it on, the readers holding tokens are listed and chosen,
//! an ID card's holder is read, and XML is signed on a token; the methods that would write
//! to a token refuse with the original's generic codes. A password or PIN the page passes
//! is therefore never sent to a token: the only PIN a token gets is the one typed in the
//! core's storage dialog. `genExt`, `getProvider`, `setProvider` and `showTokenChooser` are
//! not offered. Dialogs are Russian, as the original's.
//!
//! The module reads the requests and writes the replies, with the original's codes; the
//! core shows the windows, opens the keys and tokens, signs and writes the key files
//! ([`Core`]). The private keys and the passwords typed never reach the module. As in the
//! original, the last PIN try count is the process's (the core's shared state).

mod dispatch;
mod keygen;
mod methods;

#[cfg(target_arch = "wasm32")]
mod guest;

use oncl_pdk::Locale;
use oncl_pdk::abi::{
    ChangePasswordArgs, FlowArgs, FlowWrongPin, HostResult, IdCardHolder, InstallCertArgs,
    InstalledCert, NewKey, NewKeyArgs, TokenScan,
};

/// Name the module is registered under (also the core's default module).
pub const MODULE_NAME: &str = "kz.gov.pki.knca.applet.Applet";

/// The applet's dialogs are Russian: no request changes their language.
const LOCALE: Locale = Locale::Ru;

/// What the module asks of the core. A failure the module has no answer for (the core
/// refusing what the module never sends) is the module's failure: the connection is
/// dropped.
pub trait Core {
    /// A key choice whose store opened.
    type Flow;
    /// A key the user picked, usable until dropped.
    type Key;

    /// A debugging line in the core's log.
    fn debug(&self, line: &str);
    /// A line in the core's log.
    fn info(&self, line: &str);
    /// A warning in the core's log.
    fn warn(&self, line: &str);
    /// The language of this call's windows.
    fn call_locale(&self, locale: Locale);
    /// The PIN tries left after the last wrong password or PIN of the process; `-1` if none.
    fn try_count(&self) -> i32;
    /// Sets the PIN tries left of the process.
    fn set_try_count(&self, tries: i32);
    /// Whether token support is on, the tokens connected and whether a card is in a reader.
    fn tokens(&self) -> TokenScan;
    /// The readers holding a token of the storage `storage` (a token or the cloud storage);
    /// `Err` with the reason if the smart card service fails.
    fn readers(&self, storage: &str) -> Result<Vec<String>, String>;
    /// The reader dialog for a token of `storage`: the reader chosen, `None` if cancelled.
    fn choose_reader(&self, storage: &str) -> Option<String>;
    /// The file chooser of the file type `kind`, starting in `directory`: the path of an
    /// existing file or folder chosen; `invalid` with the cause `file.unknown_kind` for an
    /// unknown type.
    fn choose_kind(&self, kind: &str, directory: Option<&str>) -> HostResult<Option<String>>;
    /// The password dialog showing `message`: whether it was answered.
    fn password(&self, message: Option<&str>) -> bool;
    /// The holder of the ID card in `reader`.
    fn id_card(&self, reader: &str) -> HostResult<IdCardHolder>;
    /// Whether `der` is a certificate the core reads.
    fn is_certificate(&self, der: &[u8]) -> bool;
    /// A certificate installed next to its key.
    fn install_cert(&self, args: InstallCertArgs) -> HostResult<InstalledCert>;
    /// A new key in a key file, and its request.
    fn new_key(&self, args: NewKeyArgs) -> HostResult<NewKey>;
    /// A key file the page names, re-encrypted.
    fn change_password(&self, args: ChangePasswordArgs) -> HostResult<()>;
    /// The storage dialog of `flow` until a store opens: the flow, `None` if cancelled; and
    /// the last wrong PIN typed.
    fn flow_open(&self, flow: &FlowArgs) -> (Option<Self::Flow>, Option<FlowWrongPin>);
    /// The key dialog of `flow` with `error` as its error line: the key picked, `None` if
    /// cancelled.
    fn pick(&self, flow: &Self::Flow, error: Option<&str>) -> Option<Self::Key>;
    /// The key's alias.
    fn alias<'k>(&self, key: &'k Self::Key) -> &'k str;
    /// The enveloped signature of the whole document `xml` (the request's text, or the
    /// marker of the text the core keeps): the signed document, or its marker.
    fn sign_xml(&self, key: &Self::Key, xml: &str) -> HostResult<String>;
}

/// The reply to `request`. The core shows the page's origin in the windows itself.
pub fn handle(core: &impl Core, request: &str) -> String {
    core.call_locale(LOCALE);
    dispatch::process(core, request)
}
