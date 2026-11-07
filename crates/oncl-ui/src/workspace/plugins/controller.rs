//! The steps of one plugin operation in the manual window and what each may do, without Slint
//! and without the SDK: the state machine the Plugins page is driven by.
//!
//! `List` (the operations) → `Form` (the file and the other parameters, the key store) → `Key`
//! (the password, the certificate) → `Consent` (the one place where the user agrees to this
//! exact key use) → `Running` → `Result`. Only [`Event::Confirm`] in `Consent`, once the summary
//! was prepared and the button is armed, gives [`Effect::Confirmed`]; Enter in the password
//! field and a double-click on a certificate only move the page forward to the preparation, they
//! never confirm. A cancel or an error forgets the password; a finished operation forgets it
//! too, so the next one asks again. Nothing of a confirmation is kept: each key use is
//! confirmed on its own page.

use zeroize::Zeroizing;

use crate::signing::controller::{Candidate, Unsuitable};

/// Where the operation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    List,
    Form,
    Key,
    Consent,
    Running,
    Result,
}

/// What reaches the controller from the page.
pub(super) enum Event {
    /// The operation `index` of the offer (it uses a key: the page offers no other).
    Select(usize),
    /// The form was read: the key store to open.
    KeyStore(String),
    /// Enter in the password field, with the password: the page asks the host to open the key
    /// store. It confirms nothing.
    PasswordSubmitted(Zeroizing<String>),
    /// The host opened the key store: its certificates.
    Unlocked(Vec<Candidate>),
    /// It could not be opened (wrong password, unreadable file).
    UnlockFailed,
    /// Enter, a double-click or the button on a certificate: the key use is prepared for the
    /// user to read. It confirms nothing.
    CertificateChosen(usize),
    /// The engine prepared the confirmation: what is on the page is what it holds.
    Prepared,
    /// The confirmation could not be prepared: the page goes back to the key.
    PrepareFailed,
    /// A short quiet time has passed since the confirmation was shown: only now can the button
    /// that agrees be pressed, so that a burst of clicks aimed at something else cannot land
    /// on it the moment it appears.
    Arm,
    /// The button that names the action.
    Confirm,
    Back,
    /// The user leaves the operation.
    Cancel,
    /// The worker ended, whichever way.
    Finished,
    /// From the result: the same operation again (the password is asked again).
    Again,
    /// From the result: back to the list.
    Done,
}

/// What the page must do next.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Effect {
    None,
    /// Open the key store with the password (on a worker).
    OpenKeyStore,
    /// Prepare the confirmation (on the run's worker).
    Prepare,
    /// The user agreed to what the page showed: send the decision to the worker.
    Confirmed,
    /// A run is going: the worker was asked to stop; the page stays until it says how it ended.
    StopRunning,
    /// Why nothing happened, for the page to tell.
    Refused(Refusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The event does not belong to the step.
    WrongStep,
    NoKeyStore,
    UnsuitableCertificate(Unsuitable),
    NoSuchCertificate,
    /// The key store is being opened: a repeated Enter does not replace what is pending.
    Busy,
    /// The confirmation was shown a moment ago, or is not prepared yet.
    NotArmed,
}

static NEXT_OPERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One operation's state. A new operation is a new id; the page keeps one controller.
pub(super) struct PluginController {
    step: Step,
    id: u64,
    operation: Option<usize>,
    key_store: Option<String>,
    secret: Option<Zeroizing<String>>,
    candidates: Vec<Candidate>,
    chosen: Option<usize>,
    unlock_pending: bool,
    prepared: bool,
    armed: bool,
}

impl Default for PluginController {
    fn default() -> Self {
        PluginController {
            step: Step::List,
            id: NEXT_OPERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            operation: None,
            key_store: None,
            secret: None,
            candidates: Vec::new(),
            chosen: None,
            unlock_pending: false,
            prepared: false,
            armed: false,
        }
    }
}

impl PluginController {
    pub(super) fn step(&self) -> Step {
        self.step
    }
    /// Unique per operation: a worker's late answer carries it, and an answer for another
    /// operation is dropped.
    pub(super) fn id(&self) -> u64 {
        self.id
    }
    /// The operation of the offer the page is on.
    pub(super) fn operation(&self) -> Option<usize> {
        self.operation
    }
    pub(super) fn key_store(&self) -> Option<&str> {
        self.key_store.as_deref()
    }
    pub(super) fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
    pub(super) fn chosen(&self) -> Option<&Candidate> {
        self.chosen.and_then(|i| self.candidates.get(i))
    }
    /// The confirmation was prepared and shown.
    pub(super) fn prepared(&self) -> bool {
        self.prepared
    }
    /// The button that agrees may be pressed: prepared, and quiet for a moment.
    pub(super) fn armed(&self) -> bool {
        self.prepared && self.armed
    }
    /// Whether a password is held.
    #[cfg(test)]
    pub(super) fn holds_secret(&self) -> bool {
        self.secret.is_some()
    }
    /// A copy of the password for the worker that opens the key store; the controller keeps
    /// its own until the certificate is chosen, the page is left or the operation ends.
    pub(super) fn unlock_secret(&self) -> Option<Zeroizing<String>> {
        self.secret.as_ref().map(|s| Zeroizing::new(s.to_string()))
    }
    /// The password, moved out for the run's worker (after [`Effect::Prepare`]): the
    /// controller holds none from then on.
    pub(super) fn take_secret(&mut self) -> Option<Zeroizing<String>> {
        self.secret.take()
    }

    pub(super) fn dispatch(&mut self, event: Event) -> Effect {
        match event {
            Event::Select(index) => self.in_step(Step::List, |c| {
                // The caller checked that the operation exists; the controller only records it.
                c.id = NEXT_OPERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                c.operation = Some(index);
                c.step = Step::Form;
                Effect::None
            }),
            Event::KeyStore(path) => self.in_step(Step::Form, |c| {
                if path.trim().is_empty() {
                    return Effect::Refused(Refusal::NoKeyStore);
                }
                c.key_store = Some(path);
                c.step = Step::Key;
                Effect::None
            }),
            Event::PasswordSubmitted(secret) => self.in_step(Step::Key, |c| {
                if c.unlock_pending {
                    // A repeated Enter while the store opens: the first password stays.
                    return Effect::Refused(Refusal::Busy);
                }
                c.unlock_pending = true;
                c.chosen = None;
                c.candidates.clear();
                c.secret = Some(secret);
                Effect::OpenKeyStore
            }),
            Event::Unlocked(candidates) => self.in_step(Step::Key, |c| {
                c.unlock_pending = false;
                c.candidates = candidates;
                Effect::None
            }),
            Event::UnlockFailed => self.in_step(Step::Key, |c| {
                c.unlock_pending = false;
                c.secret = None;
                c.candidates.clear();
                Effect::None
            }),
            Event::CertificateChosen(i) => self.in_step(Step::Key, |c| {
                if c.unlock_pending {
                    return Effect::Refused(Refusal::Busy);
                }
                let Some(candidate) = c.candidates.get(i) else {
                    return Effect::Refused(Refusal::NoSuchCertificate);
                };
                if let Some(why) = candidate.unsuitable {
                    return Effect::Refused(Refusal::UnsuitableCertificate(why));
                }
                if c.secret.is_none() {
                    return Effect::Refused(Refusal::WrongStep);
                }
                c.chosen = Some(i);
                c.prepared = false;
                c.armed = false;
                c.step = Step::Consent;
                Effect::Prepare
            }),
            Event::Prepared => self.in_step(Step::Consent, |c| {
                c.prepared = true;
                Effect::None
            }),
            Event::PrepareFailed => self.in_step(Step::Consent, |c| {
                c.forget_unlock();
                c.step = Step::Key;
                Effect::None
            }),
            Event::Arm => self.in_step(Step::Consent, |c| {
                if c.prepared {
                    c.armed = true;
                }
                Effect::None
            }),
            Event::Confirm => self.in_step(Step::Consent, |c| {
                if !c.armed() {
                    return Effect::Refused(Refusal::NotArmed);
                }
                // The password went to the worker with the preparation; nothing is left here.
                c.step = Step::Running;
                Effect::Confirmed
            }),
            Event::Back => match self.step {
                Step::Form => {
                    self.reset();
                    Effect::None
                }
                Step::Key => {
                    self.forget_unlock();
                    self.key_store = None;
                    self.step = Step::Form;
                    Effect::None
                }
                _ => Effect::Refused(Refusal::WrongStep),
            },
            Event::Cancel => match self.step {
                // The key may be applied already: the worker is asked to stop and the page
                // stays until it says how far it got.
                Step::Running => Effect::StopRunning,
                _ => {
                    self.reset();
                    Effect::None
                }
            },
            Event::Finished => {
                self.forget_unlock();
                self.step = Step::Result;
                Effect::None
            }
            Event::Again => self.in_step(Step::Result, |c| {
                c.forget_unlock();
                c.key_store = None;
                c.step = Step::Form;
                Effect::None
            }),
            Event::Done => self.in_step(Step::Result, |c| {
                c.reset();
                Effect::None
            }),
        }
    }

    fn in_step(&mut self, step: Step, f: impl FnOnce(&mut Self) -> Effect) -> Effect {
        if self.step == step {
            f(self)
        } else {
            Effect::Refused(Refusal::WrongStep)
        }
    }

    fn forget_unlock(&mut self) {
        self.unlock_pending = false;
        self.secret = None;
        self.candidates.clear();
        self.chosen = None;
        self.prepared = false;
        self.armed = false;
    }

    /// Back to the list, with nothing of the operation left.
    fn reset(&mut self) {
        self.forget_unlock();
        self.operation = None;
        self.key_store = None;
        self.step = Step::List;
        self.id = NEXT_OPERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(unsuitable: Option<Unsuitable>) -> Candidate {
        Candidate {
            alias: "key".to_owned(),
            sha256: Some([1; 32]),
            subject: "Subject".to_owned(),
            unsuitable,
        }
    }

    fn secret() -> Zeroizing<String> {
        Zeroizing::new("password".to_owned())
    }

    /// A controller at the key step with an opened key store.
    fn at_key(candidates: Vec<Candidate>) -> PluginController {
        let mut c = PluginController::default();
        assert_eq!(c.dispatch(Event::Select(3)), Effect::None);
        assert_eq!(c.dispatch(Event::KeyStore("a.p12".into())), Effect::None);
        assert_eq!(
            c.dispatch(Event::PasswordSubmitted(secret())),
            Effect::OpenKeyStore
        );
        c.dispatch(Event::Unlocked(candidates));
        c
    }

    fn at_consent() -> PluginController {
        let mut c = at_key(vec![candidate(None)]);
        assert_eq!(c.dispatch(Event::CertificateChosen(0)), Effect::Prepare);
        assert_eq!(c.step(), Step::Consent);
        c
    }

    #[test]
    fn the_steps_go_in_order_and_nothing_confirms_before_the_consent_is_armed() {
        let mut c = PluginController::default();
        assert_eq!(c.step(), Step::List);
        // Nothing of the later steps works from the list.
        assert_eq!(
            c.dispatch(Event::Confirm),
            Effect::Refused(Refusal::WrongStep)
        );
        c.dispatch(Event::Select(3));
        assert_eq!((c.step(), c.operation()), (Step::Form, Some(3)));
        assert_eq!(
            c.dispatch(Event::KeyStore("  ".into())),
            Effect::Refused(Refusal::NoKeyStore)
        );
        c.dispatch(Event::KeyStore("a.p12".into()));
        assert_eq!((c.step(), c.key_store()), (Step::Key, Some("a.p12")));
        c.dispatch(Event::PasswordSubmitted(secret()));
        // A repeated Enter while the store opens changes nothing.
        assert_eq!(
            c.dispatch(Event::PasswordSubmitted(secret())),
            Effect::Refused(Refusal::Busy)
        );
        c.dispatch(Event::Unlocked(vec![candidate(None)]));
        assert_eq!(c.dispatch(Event::CertificateChosen(0)), Effect::Prepare);
        assert_eq!(c.step(), Step::Consent);
        // Choosing a certificate (Enter, double-click) is not a confirmation, and neither is a
        // press of the button before the summary is prepared or before it is armed.
        assert_eq!(
            c.dispatch(Event::Confirm),
            Effect::Refused(Refusal::NotArmed)
        );
        c.dispatch(Event::Arm);
        assert!(!c.armed(), "arming without a prepared summary does nothing");
        assert_eq!(
            c.dispatch(Event::Confirm),
            Effect::Refused(Refusal::NotArmed)
        );
        c.dispatch(Event::Prepared);
        assert_eq!(
            c.dispatch(Event::Confirm),
            Effect::Refused(Refusal::NotArmed)
        );
        c.dispatch(Event::Arm);
        assert!(c.armed());
        assert_eq!(c.dispatch(Event::Confirm), Effect::Confirmed);
        assert_eq!(c.step(), Step::Running);
        // Once: a second press finds the step gone.
        assert_eq!(
            c.dispatch(Event::Confirm),
            Effect::Refused(Refusal::WrongStep)
        );
        c.dispatch(Event::Finished);
        assert_eq!(c.step(), Step::Result);
        assert!(!c.holds_secret());
        c.dispatch(Event::Done);
        assert_eq!((c.step(), c.operation()), (Step::List, None));
    }

    #[test]
    fn an_unsuitable_certificate_is_not_chosen_and_nothing_is_prepared() {
        for why in [
            Unsuitable::Expired,
            Unsuitable::NotYetValid,
            Unsuitable::NotForSigning,
        ] {
            let mut c = at_key(vec![candidate(Some(why))]);
            assert_eq!(
                c.dispatch(Event::CertificateChosen(0)),
                Effect::Refused(Refusal::UnsuitableCertificate(why))
            );
            assert_eq!(c.step(), Step::Key);
        }
        let mut c = at_key(vec![candidate(None)]);
        assert_eq!(
            c.dispatch(Event::CertificateChosen(7)),
            Effect::Refused(Refusal::NoSuchCertificate)
        );
    }

    #[test]
    fn the_password_is_held_only_as_long_as_it_is_needed() {
        let mut c = at_key(vec![candidate(None)]);
        assert!(c.holds_secret());
        assert!(c.unlock_secret().is_some());
        c.dispatch(Event::CertificateChosen(0));
        // It goes to the worker with the preparation; the controller keeps none.
        let taken = c.take_secret();
        assert_eq!(taken.as_deref().map(String::as_str), Some("password"));
        assert!(!c.holds_secret());

        // Every way out forgets it.
        for leave in [Event::Cancel, Event::Back] {
            let mut c = at_key(vec![candidate(None)]);
            c.dispatch(leave);
            assert!(!c.holds_secret());
            assert!(c.candidates().is_empty());
        }
        let mut c = at_key(vec![candidate(None)]);
        c.dispatch(Event::CertificateChosen(0));
        c.dispatch(Event::PrepareFailed);
        assert_eq!(c.step(), Step::Key);
        assert!(!c.holds_secret() && c.candidates().is_empty());
        let mut c = PluginController::default();
        c.dispatch(Event::Select(0));
        c.dispatch(Event::KeyStore("a".into()));
        c.dispatch(Event::PasswordSubmitted(secret()));
        c.dispatch(Event::UnlockFailed);
        assert!(!c.holds_secret());
    }

    #[test]
    fn cancel_leaves_every_step_with_nothing_left_but_a_running_one_waits_for_the_worker() {
        type Make = Box<dyn Fn() -> PluginController>;
        let steps: Vec<(&str, Make)> = vec![
            (
                "form",
                Box::new(|| {
                    let mut c = PluginController::default();
                    c.dispatch(Event::Select(0));
                    c
                }),
            ),
            ("key", Box::new(|| at_key(vec![candidate(None)]))),
            ("consent", Box::new(at_consent)),
        ];
        for (name, make) in steps {
            let mut c = make();
            let before = c.id();
            assert_eq!(c.dispatch(Event::Cancel), Effect::None, "{name}");
            assert_eq!(c.step(), Step::List, "{name}");
            assert!(!c.holds_secret(), "{name}");
            assert_eq!(c.operation(), None, "{name}");
            assert_ne!(
                c.id(),
                before,
                "{name}: a late answer of the left operation is dropped"
            );
        }
        let mut c = at_consent();
        c.dispatch(Event::Prepared);
        c.dispatch(Event::Arm);
        c.dispatch(Event::Confirm);
        assert_eq!(c.dispatch(Event::Cancel), Effect::StopRunning);
        assert_eq!(
            c.step(),
            Step::Running,
            "the key may be applied: wait for the worker"
        );
    }

    #[test]
    fn the_result_goes_to_the_list_or_back_to_the_form_and_asks_the_password_again() {
        let finished = || {
            let mut c = at_consent();
            c.dispatch(Event::Prepared);
            c.dispatch(Event::Arm);
            c.dispatch(Event::Confirm);
            c.dispatch(Event::Finished);
            c
        };
        let mut c = finished();
        assert_eq!(c.dispatch(Event::Again), Effect::None);
        assert_eq!((c.step(), c.operation()), (Step::Form, Some(3)));
        assert!(c.key_store().is_none() && !c.holds_secret());
        let mut c = finished();
        // The result is not left by a Back.
        assert_eq!(c.dispatch(Event::Back), Effect::Refused(Refusal::WrongStep));
        c.dispatch(Event::Done);
        assert_eq!(c.step(), Step::List);
    }
}
