//! The steps of one signing operation and what each of them may do, without Slint and without
//! the SDK: the state machine the signing page is driven by.
//!
//! `Source` (documents, key store) → `Unlock` (password, certificate) → `Confirm` (the one
//! place where the user agrees to this exact action) → `Running` → `Result`. Only
//! [`Event::Confirm`] in `Confirm`, with the frozen documents still the ones the user was
//! shown, produces an [`Approved`]; Enter in the password field and a double-click on a
//! certificate only move the page forward to the confirmation, they never produce it. Back
//! and errors keep the caller, the action and the documents; a finished or cancelled
//! operation forgets the password and the unlock, so the next request unlocks again.

use zeroize::Zeroizing;

/// Where the operation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Source,
    Unlock,
    Confirm,
    Running,
    Result,
}

/// What the key is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    Sign,
    Authenticate,
    KeyInfo,
}

/// A document as it was frozen: its name is the user's or the site's claim, its size and
/// SHA-256 are what the engine captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub name: String,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// Why a certificate cannot be chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsuitable {
    Expired,
    NotYetValid,
    NotForSigning,
    /// Its revocation check is still running (a site request's key dialog).
    Pending,
    /// Its certificate is revoked.
    Revoked,
    /// It fails the request's own conditions (a site request's key dialog).
    Disabled,
}

/// A certificate of the unlocked key store, as the page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub alias: String,
    /// SHA-256 of the certificate's DER; `None` where the host's dialog has no certificate
    /// bytes (a site request's key list): then nothing is bound to it.
    pub sha256: Option<[u8; 32]>,
    pub subject: String,
    pub unsuitable: Option<Unsuitable>,
}

/// What the user agrees to: who asks, what is done, with which certificate, to which frozen
/// documents. Not `Clone`: it exists once per confirmation and moves into [`Approved`].
#[derive(Debug, PartialEq, Eq)]
pub struct UserConsent {
    caller: String,
    action: ActionKind,
    certificate: Option<[u8; 32]>,
    alias: String,
    items: Vec<Item>,
}

impl UserConsent {
    pub fn caller(&self) -> &str {
        &self.caller
    }
    pub fn action(&self) -> ActionKind {
        self.action
    }
    /// The certificate's SHA-256, when the host had the certificate (the manual signing).
    pub fn certificate(&self) -> Option<&[u8; 32]> {
        self.certificate.as_ref()
    }
    pub fn alias(&self) -> &str {
        &self.alias
    }
    pub fn items(&self) -> &[Item] {
        &self.items
    }
    /// Whether the documents an engine captured are exactly the ones agreed to, in order.
    pub fn covers(&self, captured: &[Item]) -> bool {
        self.items.len() == captured.len()
            && self
                .items
                .iter()
                .zip(captured)
                .all(|(a, b)| a.bytes == b.bytes && a.sha256 == b.sha256)
    }
}

/// The permission to apply the key for [`UserConsent`]. Only the controller makes one, from an
/// explicit confirmation; the runner consumes it and nothing else grants the key's use.
pub struct Approved {
    pub consent: UserConsent,
}

/// What reaches the controller from the page.
pub enum Event<'a> {
    /// The documents the user picked, frozen.
    Documents(Vec<Item>),
    /// The key store to unlock.
    KeyStore(String),
    /// Enter in the password field, with the password: the page asks the host to open the
    /// key store. It confirms nothing.
    PasswordSubmitted(Zeroizing<String>),
    /// The host opened the key store: its certificates.
    Unlocked(Vec<Candidate>),
    /// The host could not open it (wrong password, unreadable file).
    UnlockFailed,
    /// Enter or a double-click on a certificate. It selects it and shows the confirmation;
    /// it confirms nothing.
    CertificateChosen(usize),
    /// The engine froze the documents for this operation: what it holds, to be compared with
    /// what the user was shown. Different documents void everything so far.
    Frozen(&'a [Item]),
    /// A short quiet time has passed since the confirmation was shown: only now can the
    /// button that agrees be pressed, so that a burst of clicks aimed at the list cannot land
    /// on it the moment it appears.
    Arm,
    /// The button that names the action. `frozen` is what the engine holds now.
    Confirm {
        frozen: &'a [Item],
    },
    Back,
    /// The user leaves the operation.
    Cancel,
    /// The runner ended, whichever way.
    Finished,
}

/// What the page must do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// Open the key store with the password (on a worker).
    OpenKeyStore,
    /// Why nothing happened, for the page to tell.
    Refused(Refusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The event does not belong to the step.
    WrongStep,
    NoDocuments,
    UnsuitableCertificate(Unsuitable),
    NoSuchCertificate,
    /// The documents are not the ones the user was shown: consent is void, the page shows
    /// them again.
    DocumentsChanged,
    /// The engine has not frozen the documents yet: there is nothing to agree to.
    NotFrozen,
    /// The confirmation was shown a moment ago: it cannot be pressed yet.
    NotArmed,
    /// The key store is being opened: a repeated Enter does not replace what is pending.
    Busy,
}

/// One operation's state. A new request is a new `Controller`.
pub struct Controller {
    caller: String,
    action: ActionKind,
    step: Step,
    items: Vec<Item>,
    key_store: Option<String>,
    secret: Option<Zeroizing<String>>,
    candidates: Vec<Candidate>,
    chosen: Option<usize>,
    unlock_failed: bool,
    frozen_ready: bool,
    armed: bool,
    /// A site request: the key store was opened by the host's own dialogs and the data to sign
    /// is the page's, handled by the module after the key is chosen. There are no documents
    /// to freeze, but the caller, the action and the certificate are bound all the same.
    request: bool,
    unlock_pending: bool,
    id: u64,
    approved: Option<Approved>,
}

static NEXT_OPERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Controller {
    /// A request from `caller` (shown as given, from the host, never from a document) to
    /// do `action`.
    pub fn new(caller: impl Into<String>, action: ActionKind) -> Controller {
        Controller {
            caller: caller.into(),
            action,
            step: Step::Source,
            items: Vec::new(),
            key_store: None,
            secret: None,
            candidates: Vec::new(),
            chosen: None,
            unlock_failed: false,
            frozen_ready: false,
            armed: false,
            request: false,
            unlock_pending: false,
            id: NEXT_OPERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            approved: None,
        }
    }

    /// A site's request: `caller` is the page's origin as the host verified it, `action` what
    /// the page asked for, `candidates` the keys of the store the host's dialogs opened. The
    /// operation starts at the certificate choice.
    pub fn for_request(
        caller: impl Into<String>,
        action: ActionKind,
        candidates: Vec<Candidate>,
    ) -> Controller {
        let mut c = Controller::new(caller, action);
        c.request = true;
        c.step = Step::Unlock;
        c.key_store = Some(String::new());
        c.candidates = candidates;
        c
    }

    pub fn step(&self) -> Step {
        self.step
    }
    pub fn caller(&self) -> &str {
        &self.caller
    }
    pub fn action(&self) -> ActionKind {
        self.action
    }
    pub fn items(&self) -> &[Item] {
        &self.items
    }
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
    pub fn chosen(&self) -> Option<&Candidate> {
        self.chosen.and_then(|i| self.candidates.get(i))
    }
    /// The engine's frozen copy is the one shown; the action can be confirmed.
    pub fn frozen_ready(&self) -> bool {
        self.frozen_ready
    }
    /// The confirmation may be pressed: frozen and quiet for a moment.
    pub fn armed(&self) -> bool {
        self.frozen_ready && self.armed
    }
    /// Unique per operation: a worker's late answer carries it, and an answer for another
    /// operation is dropped.
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn unlock_failed(&self) -> bool {
        self.unlock_failed
    }
    /// A copy of the password for the worker that opens the key store; the controller keeps
    /// its own until the confirmation, the back step or the end of the operation.
    pub fn unlock_secret(&self) -> Option<Zeroizing<String>> {
        self.secret.as_ref().map(|s| Zeroizing::new(s.to_string()))
    }
    /// The permission, once (after [`Event::Confirm`]); the step is `Running` meanwhile.
    pub fn take_approved(&mut self) -> Option<Approved> {
        self.approved.take()
    }

    pub fn dispatch(&mut self, event: Event<'_>) -> Effect {
        match event {
            Event::Documents(items) => self.in_step(Step::Source, |c| {
                if items.is_empty() {
                    return Effect::Refused(Refusal::NoDocuments);
                }
                c.items = items;
                Effect::None
            }),
            Event::KeyStore(path) => self.in_step(Step::Source, |c| {
                if c.items.is_empty() {
                    return Effect::Refused(Refusal::NoDocuments);
                }
                c.key_store = Some(path);
                c.step = Step::Unlock;
                Effect::None
            }),
            Event::PasswordSubmitted(secret) => self.in_step(Step::Unlock, |c| {
                if c.unlock_pending {
                    // A repeated Enter while the store opens: the first password stays.
                    return Effect::Refused(Refusal::Busy);
                }
                c.unlock_pending = true;
                c.unlock_failed = false;
                c.chosen = None;
                c.secret = Some(secret);
                Effect::OpenKeyStore
            }),
            Event::Unlocked(candidates) => self.in_step(Step::Unlock, |c| {
                c.unlock_pending = false;
                c.candidates = candidates;
                Effect::None
            }),
            Event::UnlockFailed => self.in_step(Step::Unlock, |c| {
                c.unlock_pending = false;
                c.secret = None;
                c.candidates.clear();
                c.unlock_failed = true;
                Effect::None
            }),
            Event::CertificateChosen(i) => self.in_step(Step::Unlock, |c| {
                if c.unlock_pending {
                    return Effect::Refused(Refusal::Busy);
                }
                let Some(candidate) = c.candidates.get(i) else {
                    return Effect::Refused(Refusal::NoSuchCertificate);
                };
                if let Some(why) = candidate.unsuitable {
                    return Effect::Refused(Refusal::UnsuitableCertificate(why));
                }
                c.chosen = Some(i);
                c.step = Step::Confirm;
                Effect::None
            }),
            Event::Frozen(frozen) => self.in_step(Step::Confirm, |c| {
                if c.same_documents(frozen) {
                    c.frozen_ready = true;
                    Effect::None
                } else {
                    c.void_consent(frozen)
                }
            }),
            Event::Arm => self.in_step(Step::Confirm, |c| {
                if c.frozen_ready {
                    c.armed = true;
                }
                Effect::None
            }),
            Event::Confirm { frozen } => self.in_step(Step::Confirm, |c| c.confirm(frozen)),
            Event::Back => match self.step {
                Step::Confirm => {
                    self.chosen = None;
                    self.frozen_ready = false;
                    self.armed = false;
                    self.step = Step::Unlock;
                    Effect::None
                }
                Step::Unlock => {
                    self.forget_unlock();
                    self.key_store = None;
                    self.step = Step::Source;
                    Effect::None
                }
                _ => Effect::Refused(Refusal::WrongStep),
            },
            Event::Cancel => {
                self.end();
                Effect::None
            }
            Event::Finished => {
                self.end();
                Effect::None
            }
        }
    }

    fn in_step(&mut self, step: Step, f: impl FnOnce(&mut Self) -> Effect) -> Effect {
        if self.step == step {
            f(self)
        } else {
            Effect::Refused(Refusal::WrongStep)
        }
    }

    fn confirm(&mut self, frozen: &[Item]) -> Effect {
        if !self.frozen_ready {
            return Effect::Refused(Refusal::NotFrozen);
        }
        if !self.armed {
            return Effect::Refused(Refusal::NotArmed);
        }
        if !self.same_documents(frozen) {
            return self.void_consent(frozen);
        }
        // The password stays with the worker that froze the documents; the controller only
        // checks that this operation was unlocked, and lets go of its copy. A site request has
        // no password here: the host's dialogs unlocked the store.
        let secret = self.secret.take();
        let (Some(chosen), true) = (self.chosen().cloned(), secret.is_some() || self.request)
        else {
            self.step = Step::Unlock;
            return Effect::Refused(Refusal::WrongStep);
        };
        self.approved = Some(Approved {
            consent: UserConsent {
                caller: self.caller.clone(),
                action: self.action,
                certificate: chosen.sha256,
                alias: chosen.alias,
                items: self.items.clone(),
            },
        });
        self.step = Step::Running;
        Effect::None
    }

    fn same_documents(&self, frozen: &[Item]) -> bool {
        self.items.len() == frozen.len()
            && self
                .items
                .iter()
                .zip(frozen)
                .all(|(a, b)| a.bytes == b.bytes && a.sha256 == b.sha256)
    }

    /// What the engine holds is not what the user saw: nothing agreed to stands, the unlock
    /// goes, and the documents shown from now on are the ones it holds.
    fn void_consent(&mut self, frozen: &[Item]) -> Effect {
        self.forget_unlock();
        self.items = frozen.to_vec();
        self.step = Step::Source;
        Effect::Refused(Refusal::DocumentsChanged)
    }

    fn forget_unlock(&mut self) {
        self.frozen_ready = false;
        self.armed = false;
        self.unlock_pending = false;
        self.secret = None;
        self.candidates.clear();
        self.chosen = None;
        self.unlock_failed = false;
    }

    /// The operation is over, ended or abandoned: nothing of the unlock stays.
    fn end(&mut self) {
        self.forget_unlock();
        self.approved = None;
        self.step = Step::Result;
    }
}
