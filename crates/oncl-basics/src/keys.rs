//! The key choice every signing flow shares: the storage dialog until a key store opens, then
//! the key dialog, with the keys checked against the request's conditions and their OCSP
//! responders. `PKIExtras.sign` uses it, and so do the other modules and plugins with the
//! `keys` capability. With token support on, the storage dialog offers the tokens plugged in
//! too.
//!
//! A [`KeyFlow`] names every way the flows differ: which readers the storage dialog offers,
//! the path it starts with, the password rules, how the file is read, which keys are listed
//! and in what order, and whether they are checked live. [`KeyChooser::open`] runs the
//! storage dialog; [`OpenedFlow::pick`] the key dialog, as often as the caller asks.

use crate::filter::{Availability, KeyFilter, availabilities};
use crate::live::LiveAvailability;
use crate::ocsp_cache::OcspCache;
use crate::page_file::PageFile;
use crate::prompt::{
    Action, Busy, BusyPrompt, KeyPrompt, Locale, OpenError, Prompt, Prompter, RecentPathStore,
    StorageAnswer, StorageKind, StoragePrompt,
};
use crate::tokens::{ReaderEntry, ReaderList};
use oncl_pki::cert::Certificate;
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::info::{CertInfo, KncaCertType, cert_info, kcert_types};
use oncl_pki::pkcs12::KeyEntry;
use oncl_token::Tokens;
use std::path::{Path, PathBuf};
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
    /// The hardware tokens the storage dialog offers while their support is on.
    pub tokens: Arc<Tokens>,
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
    /// The key store file the storage dialog starts with instead of the last opened one;
    /// the caller has checked it ([`crate::page_path`]).
    pub initial_path: Option<PathBuf>,
    /// The order of the keys in the key dialog.
    pub order: KeyOrder,
}

/// The order of the keys in the key dialog.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyOrder {
    /// As stored (the basics module).
    #[default]
    Store,
    /// The latest notBefore first (the original's key dialog).
    NewestFirst,
    /// The earliest notBefore first (some plugins' older key dialog).
    OldestFirst,
}

/// The readers the storage dialog offers for tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readers {
    /// Those holding a token, scanned when the dialog opens, while token support is on. A
    /// failed token answer is asked again with its storage and reader selected only if it
    /// was a token's.
    Live,
    /// These, chosen beforehand: the first one is the dialog's first. A failed answer is
    /// asked again with its storage and reader selected.
    Fixed(Vec<ReaderEntry>),
    /// None: the token storages are not selectable.
    None,
}

/// The key store file the storage dialog starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartPath {
    /// The last opened one ([`RecentPathStore`]).
    Recent,
    /// This one, which the caller has checked ([`crate::page_path`]).
    Given(PathBuf),
    /// None.
    Empty,
}

/// What the password of a storage answer must be before the store is opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PasswordRules {
    /// Not empty ([`OpenError::EmptyPassword`]).
    pub non_empty: bool,
    /// The policy for keys of internal systems ([`inner_password_ok`],
    /// [`OpenError::InnerPasswordPolicy`]).
    pub inner_policy: bool,
}

/// How the key store file of a storage answer is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRead {
    /// As [`StorageAnswer::open_with`]: any file the system opens.
    Open,
    /// As the user's choice of a page's file ([`PageFile::read_chosen`]): a regular disk
    /// file of at most [`crate::MAX_PAGE_FILE`] bytes, on a network share too, never a
    /// device.
    Chosen,
}

/// How the keys listed are checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyChecks {
    /// Not at all: every key may be picked.
    Settled,
    /// Against these conditions and the keys' OCSP responders, the key dialog following
    /// the checks ([`LiveAvailability`]).
    Live(Box<KeyFilter>),
}

/// One key choice: every rule its storage and key dialogs follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFlow {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// Signing, authentication or certificate details.
    pub action: Action,
    /// Storages to offer, in order.
    pub storages: Vec<StorageKind>,
    /// The readers offered for tokens.
    pub readers: Readers,
    /// The key store file the storage dialog starts with.
    pub start: StartPath,
    /// Whether the path of an opened file is saved as the last opened one.
    pub remember: bool,
    /// A line both dialogs show besides the request.
    pub detail: Option<String>,
    /// What the password must be before the store is opened.
    pub password: PasswordRules,
    /// An answer of a storage not offered is [`OpenError::UnsupportedStorage`] before the
    /// store is read.
    pub same_storage: bool,
    /// How the key store file is read.
    pub file: FileRead,
    /// The keys listed: those whose certificate is of one of these types; `None` for all.
    pub kinds: Option<Vec<KncaCertType>>,
    /// The storage dialog's error when no key is left to list.
    pub none: OpenError,
    /// An empty store ([`OpenError::NoKeys`] when opened) is a store without keys to list,
    /// which is [`KeyFlow::none`].
    pub empty_is_none: bool,
    /// The order of the keys in the key dialog.
    pub order: KeyOrder,
    /// How the keys listed are checked.
    pub checks: KeyChecks,
    /// A reader whose token refused the PIN as blocked is not tried again in this flow.
    pub skip_blocked_reader: bool,
}

impl KeyFlow {
    /// The flow of a [`KeyRequest`]: the readers holding tokens, the request's start path or
    /// else the last opened one, which an opened file replaces, the keys as stored checked
    /// live against the request's conditions.
    pub fn from_request(request: &KeyRequest) -> KeyFlow {
        KeyFlow {
            origin: request.origin.clone(),
            locale: request.locale,
            action: request.action,
            storages: request.storages.clone(),
            readers: Readers::Live,
            start: match &request.initial_path {
                Some(path) => StartPath::Given(path.clone()),
                None => StartPath::Recent,
            },
            remember: true,
            detail: request.detail.clone(),
            password: PasswordRules::default(),
            same_storage: false,
            file: FileRead::Open,
            kinds: None,
            none: OpenError::NoKeys,
            empty_is_none: false,
            order: request.order,
            checks: KeyChecks::Live(Box::new(request.filter.clone())),
            skip_blocked_reader: false,
        }
    }
}

/// The last wrong PIN of a flow's storage dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrongPin {
    /// The token's storage.
    pub storage: StorageKind,
    /// Tries left before the PIN is blocked, when the token tells them.
    pub tries_left: Option<u8>,
}

/// How a flow's storage dialog ended.
pub struct FlowOpen {
    /// The opened store; `None` if the dialog was cancelled.
    pub opened: Option<OpenedFlow>,
    /// The last wrong PIN typed, whether the store opened or not.
    pub wrong_pin: Option<WrongPin>,
}

/// The keys of an opened store, listed for a flow's key dialog.
pub struct OpenedFlow {
    entries: Vec<KeyEntry>,
    infos: Vec<CertInfo>,
    /// The busy indicator, up to the first key dialog.
    busy: Option<Busy>,
    /// The key dialog, built at the first pick.
    prompt: Option<KeyPrompt>,
}

impl OpenedFlow {
    /// The keys listed, in the key dialog's order.
    pub fn entries(&self) -> &[KeyEntry] {
        &self.entries
    }

    /// Asks for one of the keys until an enabled one is picked: its index in
    /// [`OpenedFlow::entries`]; `None` if the user cancels. `error` is the dialog's error
    /// line (why the previous pick failed). The live checks start, once, at the first pick,
    /// which ends the busy indicator; every pick shows the same list.
    pub fn pick(
        &mut self,
        chooser: &KeyChooser,
        flow: &KeyFlow,
        error: Option<String>,
    ) -> Option<usize> {
        let prompt = match &mut self.prompt {
            Some(prompt) => prompt,
            None => {
                let live = match &flow.checks {
                    KeyChecks::Settled => {
                        LiveAvailability::settled(vec![Availability::Enabled; self.entries.len()])
                    }
                    KeyChecks::Live(filter) => {
                        let keys: Vec<(Certificate, CertInfo)> = self
                            .entries
                            .iter()
                            .zip(&self.infos)
                            .map(|(entry, info)| (entry.cert.clone(), info.clone()))
                            .collect();
                        availabilities(
                            filter,
                            &keys,
                            &chooser.http,
                            &chooser.ocsp_cache,
                            (chooser.clock)(),
                        )
                    }
                };
                let mut prompt = KeyPrompt::new(
                    flow.origin.clone(),
                    flow.locale,
                    flow.action,
                    self.entries
                        .iter()
                        .zip(&self.infos)
                        .map(|(entry, info)| (entry.alias.clone(), info.clone())),
                    live,
                );
                prompt.detail = flow.detail.clone();
                self.prompt.insert(prompt)
            }
        };
        drop(self.busy.take());
        prompt.error = error;
        prompt.ask(chooser.prompter.as_ref())
    }

    /// The key at `i` of [`OpenedFlow::entries`].
    ///
    /// # Panics
    ///
    /// If `i` is out of range.
    pub fn take(mut self, i: usize) -> KeyEntry {
        self.entries.swap_remove(i)
    }
}

impl KeyChooser {
    /// A chooser for flows that neither check keys live nor use the last opened path: their
    /// checks are [`KeyChecks::Settled`], their start path is not [`StartPath::Recent`] and
    /// they do not remember. A live check through it reaches no responder, and it has no
    /// last opened path.
    pub fn local(prompter: Arc<dyn Prompter>, tokens: Arc<Tokens>) -> KeyChooser {
        KeyChooser {
            prompter,
            recent: Arc::new(NoRecentPath),
            http: Arc::new(NoNetwork),
            ocsp_cache: Arc::new(OcspCache::new()),
            clock: OffsetDateTime::now_utc,
            tokens,
        }
    }

    /// Asks for a storage until one opens, then for one of its keys until an enabled one is
    /// picked: that key; `None` if the user cancels either dialog. The opened file's path is
    /// remembered.
    ///
    /// The caller holds the dialog-flow turn ([`crate::lock_dialog_flow`]) for its whole
    /// flow: this does not take it.
    pub fn choose(&self, request: &KeyRequest) -> Option<KeyEntry> {
        let flow = KeyFlow::from_request(request);
        let mut opened = self.open(&flow).opened?;
        let index = opened.pick(self, &flow, None)?;
        Some(opened.take(index))
    }

    /// Asks for a storage until one opens with keys to list: the flow's storage dialog. The
    /// busy indicator shows from each answer on; it stays with the opened store up to its
    /// first key dialog. A token's reader is never remembered.
    ///
    /// The caller holds the dialog-flow turn ([`crate::lock_dialog_flow`]) for its whole
    /// flow: this does not take it.
    pub fn open(&self, flow: &KeyFlow) -> FlowOpen {
        let mut prompt = StoragePrompt {
            origin: flow.origin.clone(),
            locale: flow.locale,
            action: flow.action,
            storages: flow.storages.clone(),
            recent_path: match &flow.start {
                StartPath::Recent => self.recent.load(),
                StartPath::Given(path) => Some(path.clone()),
                StartPath::Empty => None,
            },
            error: None,
            detail: flow.detail.clone(),
            tokens: match &flow.readers {
                Readers::Live => self
                    .tokens
                    .is_enabled()
                    .then(|| ReaderList::new(Arc::clone(&self.tokens))),
                Readers::Fixed(entries) => Some(ReaderList::fixed(entries.clone(), None)),
                Readers::None => None,
            },
            chosen: None,
            reader: None,
        };
        let mut wrong_pin = None;
        // The reader whose token refused the PIN as blocked.
        let mut blocked: Option<String> = None;
        loop {
            let Prompt::Answer(answer) = self.prompter.storage(&prompt) else {
                return FlowOpen {
                    opened: None,
                    wrong_pin,
                };
            };
            let busy = self.prompter.busy(&BusyPrompt {
                origin: flow.origin.clone(),
                locale: flow.locale,
            });
            let opened = if blocked.is_some() && answer.reader == blocked {
                Err(OpenError::PinBlocked)
            } else {
                self.open_answer(flow, &answer)
            };
            match opened {
                Ok((entries, infos)) => {
                    if flow.remember && answer.storage.token_kind().is_none() {
                        self.recent.save(&answer.path);
                    }
                    return FlowOpen {
                        opened: Some(OpenedFlow {
                            entries,
                            infos,
                            busy: Some(busy),
                            prompt: None,
                        }),
                        wrong_pin,
                    };
                }
                Err(e) => {
                    if let OpenError::WrongPin { tries_left } = e {
                        wrong_pin = Some(WrongPin {
                            storage: answer.storage,
                            tries_left,
                        });
                    }
                    let token_retry = match flow.readers {
                        Readers::Fixed(_) => true,
                        Readers::Live => {
                            answer.storage.token_kind().is_some() && prompt.tokens.is_some()
                        }
                        Readers::None => false,
                    };
                    prompt.error = Some(e);
                    if token_retry {
                        if flow.skip_blocked_reader && e == OpenError::PinBlocked {
                            blocked.clone_from(&answer.reader);
                        }
                        prompt.chosen = Some(answer.storage);
                        prompt.reader = answer.reader;
                    } else {
                        prompt.chosen = None;
                        prompt.reader = None;
                        prompt.recent_path = Some(answer.path);
                    }
                }
            }
        }
    }

    /// The keys `answer` opens under `flow`'s rules, with their certificate details, in the
    /// flow's order.
    fn open_answer(
        &self,
        flow: &KeyFlow,
        answer: &StorageAnswer,
    ) -> Result<(Vec<KeyEntry>, Vec<CertInfo>), OpenError> {
        if flow.password.non_empty && answer.password.is_empty() {
            return Err(OpenError::EmptyPassword);
        }
        if flow.password.inner_policy && !inner_password_ok(&answer.password) {
            return Err(OpenError::InnerPasswordPolicy);
        }
        if flow.same_storage && !flow.storages.contains(&answer.storage) {
            return Err(OpenError::UnsupportedStorage);
        }
        let opened = match flow.file {
            FileRead::Chosen if answer.storage.token_kind().is_none() => {
                let file =
                    PageFile::read_chosen(&answer.path).map_err(|_| OpenError::FileNotFound)?;
                answer.open_data(&file.data)
            }
            FileRead::Open | FileRead::Chosen => answer.open_with(&flow.storages, &self.tokens),
        };
        let entries = match opened {
            Err(OpenError::NoKeys) if flow.empty_is_none => Vec::new(),
            opened => opened?,
        };
        let mut keys: Vec<(KeyEntry, CertInfo)> = entries
            .into_iter()
            .map(|entry| {
                let info = cert_info(&entry.cert);
                (entry, info)
            })
            .filter(|(_, info)| {
                flow.kinds.as_ref().is_none_or(|kinds| {
                    let types = kcert_types(info);
                    kinds.iter().any(|kind| types.contains(kind))
                })
            })
            .collect();
        if keys.is_empty() {
            return Err(flow.none);
        }
        match flow.order {
            KeyOrder::Store => {}
            // Stable: keys of the same notBefore keep their store order.
            KeyOrder::NewestFirst => {
                keys.sort_by_key(|(_, info)| std::cmp::Reverse(info.not_before))
            }
            KeyOrder::OldestFirst => keys.sort_by_key(|(_, info)| info.not_before),
        }
        Ok(keys.into_iter().unzip())
    }
}

/// The original dialog's password policy for keys of internal systems (`INAUTH`/`INSIGN`):
/// `^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#$^+=!*()@%&_-]).{8,32}$` — 8 to 32
/// characters (code points, as `java.util.regex` `.` takes a supplementary character
/// whole) without line terminators, with a Latin capital, a Latin small letter, a digit and
/// one of `#$^+=!*()@%&_-`.
pub fn inner_password_ok(password: &str) -> bool {
    (8..=32).contains(&password.chars().count())
        && !password.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
        && password.chars().any(|c| c.is_ascii_uppercase())
        && password.chars().any(|c| c.is_ascii_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| "#$^+=!*()@%&_-".contains(c))
}

/// No last opened path, and none kept.
struct NoRecentPath;

impl RecentPathStore for NoRecentPath {
    fn load(&self) -> Option<PathBuf> {
        None
    }

    fn save(&self, _: &Path) {}
}

/// No requests leave.
struct NoNetwork;

impl HttpTransport for NoNetwork {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("this key choice checks no key online"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_passwords() {
        assert!(inner_password_ok("Abcdef1#"));
        assert!(inner_password_ok(&format!("Ab1#{}", "x".repeat(28))));
        assert!(!inner_password_ok(&format!("Ab1#{}", "x".repeat(29))));
        assert!(!inner_password_ok("Abcde1#"));
        assert!(!inner_password_ok("abcdef1#"));
        assert!(!inner_password_ok("ABCDEF1#"));
        assert!(!inner_password_ok("Abcdefg#"));
        assert!(!inner_password_ok("Abcdefg1"));
        // `.` is not a special character of the policy; other characters are allowed.
        assert!(!inner_password_ok("Abcdef1."));
        assert!(inner_password_ok("Абвгд Ab1#"));
        // Code points, not UTF-16 units.
        assert!(!inner_password_ok("Ab1#😀😀"));
        assert!(inner_password_ok(&format!("Ab1#{}", "😀".repeat(28))));
        assert!(!inner_password_ok("Abcdef1#\n"));
    }
}
