//! The legacy `kz.gov.pki.knca.applet.Applet` module (the original's `knca_applet`
//! `Applet`), which also answers requests without a `module`.
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
//! to a token refuse with the original's generic codes. `genExt`, `getProvider`,
//! `setProvider` and `showTokenChooser` are not offered. Dialog flows take
//! [`oncl_basics::lock_dialog_flow`]; dialogs are Russian, as the original's.
//!
//! As in the original, the password of the password dialog and the last PIN try count are
//! the module's, shared by every connection.

mod dispatch;
mod keygen;
mod methods;

use oncl_basics::{Prompter, StorageKind};
use oncl_protocol::{AddInfo, Module};
use oncl_token::Tokens;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

/// Name the module is registered under (also `oncl_protocol::DEFAULT_MODULE`).
pub const MODULE_NAME: &str = "kz.gov.pki.knca.applet.Applet";

/// The `kz.gov.pki.knca.applet.Applet` module.
pub struct Applet {
    prompter: Arc<dyn Prompter>,
    /// The original's `password`: what the password dialog was last answered with, or the
    /// key file password of the last operation that sets it. Only the original's token
    /// writes read it, which OpenNCALayer does not do; it is never logged.
    password: Mutex<Option<Zeroizing<String>>>,
    /// The original's `tryCount`: the PIN tries left after the last wrong password or PIN,
    /// `-1` for a key file and for tokens that do not tell.
    try_count: AtomicI32,
    tokens: Arc<Tokens>,
}

impl Applet {
    /// The module, showing its dialogs with `prompter`, without tokens.
    pub fn new(prompter: Arc<dyn Prompter>) -> Self {
        Applet {
            prompter,
            password: Mutex::new(None),
            try_count: AtomicI32::new(-1),
            tokens: Tokens::disabled(),
        }
    }

    /// The same module with the hardware tokens of `tokens`, while their support is on.
    #[must_use]
    pub fn with_tokens(self, tokens: Arc<Tokens>) -> Self {
        Applet { tokens, ..self }
    }

    /// The readers holding a token of `storage`'s family: none with token support off, for
    /// a file or the cloud storage, or when the service fails.
    fn token_readers(&self, storage: StorageKind) -> Vec<String> {
        storage
            .token_kind()
            .and_then(|kind| self.tokens.readers(kind).ok())
            .unwrap_or_default()
    }

    /// A token of `storage`'s family is connected (with token support on).
    fn token_connected(&self, storage: StorageKind) -> bool {
        !self.token_readers(storage).is_empty()
    }

    fn set_password(&self, password: Option<Zeroizing<String>>) {
        *self.password.lock().unwrap_or_else(PoisonError::into_inner) = password;
    }

    fn try_count(&self) -> i32 {
        self.try_count.load(Ordering::Relaxed)
    }

    fn set_try_count(&self, n: i32) {
        self.try_count.store(n, Ordering::Relaxed);
    }
}

impl Module for Applet {
    fn process(&self, request: &str, add_info: &AddInfo) -> String {
        dispatch::process(self, request, add_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_basics::testing::{ScriptedPrompter, Step};

    fn kept(a: &Applet) -> Option<String> {
        a.password
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.as_str().to_owned())
    }

    #[test]
    fn password_is_kept_as_the_original_keeps_it() {
        let prompter =
            ScriptedPrompter::new(vec![Step::Password("one".to_owned()), Step::CancelPassword]);
        let a = Applet::new(Arc::new(prompter));
        let call = |request: &str| a.process(request, &AddInfo::default());
        assert_eq!(kept(&a), None);
        call(r#"{"method":"setPassword"}"#);
        assert_eq!(kept(&a).as_deref(), Some("one"));
        // Cancelled: unchanged.
        call(r#"{"method":"setPassword","args":["m"]}"#);
        assert_eq!(kept(&a).as_deref(), Some("one"));
        // Certificate installation keeps the key file password, even when it fails.
        assert_eq!(
            call(r#"{"method":"setX509CertToKeyStore","args":["PKCS12",null,"Def1","x"]}"#),
            r#"{"errorCode":"SETCERT_COMMON"}"#
        );
        assert_eq!(kept(&a).as_deref(), Some("Def1"));
        // Key generation forgets it afterwards, whatever its outcome…
        assert_eq!(
            call(r#"{"method":"genKeyPairAndGetPKCS10","args":["x","","G",[],[],[],"","",""]}"#),
            r#"{"errorCode":"UNKNOWN_STORAGE"}"#
        );
        assert_eq!(kept(&a), None);
        // …unless it throws: then the key file password stays.
        assert_eq!(
            call(
                r#"{"method":"genKeyPairAndGetPKCS10","args":["PKCS12","","G",[],[],[],null,"",""]}"#
            ),
            r#"{"errorCode":"java.lang.reflect.InvocationTargetException. Method: genKeyPairAndGetPKCS10"}"#
        );
        assert_eq!(kept(&a).as_deref(), Some("G"));
    }
}
