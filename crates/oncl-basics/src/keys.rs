//! The key choice every signing flow shares: the storage dialog until a key store opens, then
//! the key dialog, with the keys checked against the request's conditions and their OCSP
//! responders. `PKIExtras.sign` uses it, and so do plugins with the `keys` capability.

use crate::filter::{KeyFilter, availabilities};
use crate::ocsp_cache::OcspCache;
use crate::prompt::{
    Action, Busy, BusyPrompt, KeyPrompt, Locale, Prompt, Prompter, RecentPathStore, StorageKind,
    StoragePrompt,
};
use oncl_pki::cert::Certificate;
use oncl_pki::http::HttpTransport;
use oncl_pki::info::{CertInfo, cert_info};
use oncl_pki::pkcs12::KeyEntry;
use std::sync::Arc;
use time::OffsetDateTime;

/// Asks the user for a key: what the dialogs need and where the key checks go.
#[derive(Clone)]
pub struct KeyChooser {
    /// Shows the dialogs.
    pub prompter: Arc<dyn Prompter>,
    /// The last opened key store path, pre-filled and remembered.
    pub recent: Arc<dyn RecentPathStore>,
    /// The OCSP checks of the keys offered.
    pub http: Arc<dyn HttpTransport>,
    /// Responders that do not answer and verified answers.
    pub ocsp_cache: Arc<OcspCache>,
    /// The time of the checks (certificate validity, path validation, OCSP).
    pub clock: fn() -> OffsetDateTime,
}

/// What a key is chosen for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequest {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// Signing, authentication or certificate details.
    pub action: Action,
    /// Storages to offer, in order.
    pub storages: Vec<StorageKind>,
    /// The conditions a key must meet to be picked.
    pub filter: KeyFilter,
    /// A line both dialogs show besides the request.
    pub detail: Option<String>,
}

impl KeyChooser {
    /// Asks for a storage until one opens, then for one of its keys until an enabled one is
    /// picked: that key; `None` if the user cancels either dialog. The opened path is
    /// remembered.
    ///
    /// The caller holds the dialog-flow turn ([`crate::lock_dialog_flow`]) for its whole
    /// flow: this does not take it.
    pub fn choose(&self, request: &KeyRequest) -> Option<KeyEntry> {
        let (mut entries, busy) = self.open_storage(request)?;
        let index = self.choose_key(request, &entries, busy)?;
        Some(entries.swap_remove(index))
    }

    /// Asks for a storage until one opens; `None` if the user cancels. Saves the opened
    /// path. The busy indicator shows from each answer on; it is returned with the opened
    /// store.
    fn open_storage(&self, request: &KeyRequest) -> Option<(Vec<KeyEntry>, Busy)> {
        let mut prompt = StoragePrompt {
            origin: request.origin.clone(),
            locale: request.locale,
            action: request.action,
            storages: request.storages.clone(),
            recent_path: self.recent.load(),
            error: None,
            detail: request.detail.clone(),
        };
        loop {
            let answer = match self.prompter.storage(&prompt) {
                Prompt::Answer(answer) => answer,
                Prompt::Cancelled => return None,
            };
            let busy = self.prompter.busy(&BusyPrompt {
                origin: request.origin.clone(),
                locale: request.locale,
            });
            match answer.open(&prompt.storages) {
                Ok(entries) => {
                    self.recent.save(&answer.path);
                    return Some((entries, busy));
                }
                Err(e) => {
                    prompt.error = Some(e);
                    prompt.recent_path = Some(answer.path);
                }
            }
        }
    }

    /// Asks for a key until an enabled one is picked; `None` if the user cancels. The paths
    /// are built and the OCSP checks started, once, before the dialog opens, which ends
    /// `busy`; the dialog follows the checks.
    fn choose_key(&self, request: &KeyRequest, entries: &[KeyEntry], busy: Busy) -> Option<usize> {
        let keys: Vec<(Certificate, CertInfo)> = entries
            .iter()
            .map(|entry| (entry.cert.clone(), cert_info(&entry.cert)))
            .collect();
        let live = availabilities(
            &request.filter,
            &keys,
            &self.http,
            &self.ocsp_cache,
            (self.clock)(),
        );
        let mut prompt = KeyPrompt::new(
            request.origin.clone(),
            request.locale,
            request.action,
            entries
                .iter()
                .zip(keys)
                .map(|(entry, (_, info))| (entry.alias.clone(), info)),
            live,
        );
        prompt.detail = request.detail.clone();
        drop(busy);
        prompt.ask(self.prompter.as_ref())
    }
}
