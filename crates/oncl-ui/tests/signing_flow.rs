//! The signing flow's contract: the key is applied only after an explicit confirmation of
//! exactly what the user was shown, and nothing of an unlock outlives its operation.

use oncl_ui::signing::{
    ActionKind, Candidate, Controller, Effect, Event, Item, Refusal, Step, Unsuitable,
};
use zeroize::Zeroizing;

fn doc(name: &str, fill: u8) -> Item {
    Item {
        name: name.to_owned(),
        bytes: 100,
        sha256: [fill; 32],
    }
}

fn candidate(alias: &str, fill: u8, unsuitable: Option<Unsuitable>) -> Candidate {
    Candidate {
        alias: alias.to_owned(),
        sha256: [fill; 32],
        subject: format!("Subject {alias}"),
        unsuitable,
    }
}

fn password(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

/// A controller at the unlock step with documents, a key store and two certificates.
fn unlocked() -> Controller {
    let mut c = Controller::new("https://site.example", ActionKind::Sign);
    c.dispatch(Event::Documents(vec![doc("a.pdf", 1), doc("b.pdf", 2)]));
    c.dispatch(Event::KeyStore("keys.p12".into()));
    assert_eq!(
        c.dispatch(Event::PasswordSubmitted(password("pw"))),
        Effect::OpenKeyStore
    );
    c.dispatch(Event::Unlocked(vec![
        candidate("expired", 7, Some(Unsuitable::Expired)),
        candidate("good", 8, None),
    ]));
    c
}

/// Enter in the password field and a double-click on a certificate move the page on; neither
/// ever yields the permission to apply the key. Only the button does.
#[test]
fn enter_and_doubleclick_do_not_sign() {
    let mut c = unlocked();
    // Enter in the password field again (a repeated Enter) opens the store again, nothing more.
    assert_eq!(
        c.dispatch(Event::PasswordSubmitted(password("pw"))),
        Effect::OpenKeyStore
    );
    assert!(c.take_approved().is_none());
    assert_eq!(c.step(), Step::Unlock);
    // A double-click on a certificate shows the confirmation.
    assert_eq!(c.dispatch(Event::CertificateChosen(1)), Effect::None);
    assert_eq!(c.step(), Step::Confirm);
    assert!(c.take_approved().is_none(), "choosing is not confirming");
    // Enter or a double-click arriving in the confirmation do nothing.
    assert_eq!(
        c.dispatch(Event::CertificateChosen(1)),
        Effect::Refused(Refusal::WrongStep)
    );
    assert_eq!(
        c.dispatch(Event::PasswordSubmitted(password("pw"))),
        Effect::Refused(Refusal::WrongStep)
    );
    assert_eq!(c.step(), Step::Confirm);
    assert!(c.take_approved().is_none());
    // The button does, once the engine froze the documents shown.
    let frozen = c.items().to_vec();
    assert_eq!(
        c.dispatch(Event::Confirm { frozen: &frozen }),
        Effect::Refused(Refusal::NotFrozen),
        "nothing to agree to before the engine froze them"
    );
    assert_eq!(c.dispatch(Event::Frozen(&frozen)), Effect::None);
    assert!(c.frozen_ready());
    assert_eq!(c.dispatch(Event::Confirm { frozen: &frozen }), Effect::None);
    let approved = c.take_approved().expect("explicit confirmation");
    assert_eq!(approved.consent.caller(), "https://site.example");
    assert_eq!(approved.consent.action(), ActionKind::Sign);
    assert_eq!(approved.consent.certificate(), &[8; 32]);
    assert_eq!(approved.consent.alias(), "good");
    assert!(approved.consent.covers(&frozen));
    assert_eq!(c.step(), Step::Running);
    assert!(c.take_approved().is_none(), "the permission exists once");
}

/// A certificate that cannot be used is refused where it is chosen and says why; the unlock
/// stays.
#[test]
fn an_unsuitable_certificate_cannot_be_chosen() {
    let mut c = unlocked();
    assert_eq!(
        c.dispatch(Event::CertificateChosen(0)),
        Effect::Refused(Refusal::UnsuitableCertificate(Unsuitable::Expired))
    );
    assert_eq!(
        c.dispatch(Event::CertificateChosen(9)),
        Effect::Refused(Refusal::NoSuchCertificate)
    );
    assert_eq!(c.step(), Step::Unlock);
    assert_eq!(c.candidates().len(), 2);
}

/// The caller, the action and the documents are the host's and survive going back, a failed
/// unlock and a retry; they are never taken from anything the user or a document typed.
#[test]
fn origin_survives_back_and_error() {
    let mut c = Controller::new("https://site.example", ActionKind::Authenticate);
    c.dispatch(Event::Documents(vec![doc("a", 1)]));
    c.dispatch(Event::KeyStore("k.p12".into()));
    c.dispatch(Event::PasswordSubmitted(password("wrong")));
    c.dispatch(Event::UnlockFailed);
    assert!(c.unlock_failed());
    assert_eq!(c.step(), Step::Unlock);
    assert!(c.unlock_secret().is_none(), "a wrong password is not kept");
    c.dispatch(Event::PasswordSubmitted(password("right")));
    c.dispatch(Event::Unlocked(vec![candidate("k", 3, None)]));
    c.dispatch(Event::CertificateChosen(0));
    assert_eq!(c.step(), Step::Confirm);
    assert_eq!(c.dispatch(Event::Back), Effect::None);
    assert_eq!(c.step(), Step::Unlock);
    assert!(c.chosen().is_none());
    assert_eq!(c.dispatch(Event::Back), Effect::None);
    assert_eq!(c.step(), Step::Source);
    for _ in 0..2 {
        assert_eq!(c.caller(), "https://site.example");
        assert_eq!(c.action(), ActionKind::Authenticate);
        assert_eq!(c.items().len(), 1);
    }
    assert!(
        c.unlock_secret().is_none(),
        "back to the source forgets the password"
    );
    assert!(c.candidates().is_empty());
}

/// Documents that are not the ones the user was shown void the consent: no permission, the
/// unlock is forgotten, the page starts again from the documents it now has.
#[test]
fn changed_file_invalidates_consent() {
    let mut c = unlocked();
    c.dispatch(Event::CertificateChosen(1));
    let mut changed = c.items().to_vec();
    changed[1].sha256 = [99; 32];
    assert_eq!(
        c.dispatch(Event::Frozen(&changed)),
        Effect::Refused(Refusal::DocumentsChanged)
    );
    assert!(c.take_approved().is_none());
    assert_eq!(c.step(), Step::Source);
    assert_eq!(
        c.items(),
        &changed[..],
        "the new bytes are shown, not hidden"
    );
    assert!(c.unlock_secret().is_none());
    assert!(c.candidates().is_empty());
    // Added or removed documents are changes too.
    let mut c = unlocked();
    c.dispatch(Event::CertificateChosen(1));
    let one = c.items()[..1].to_vec();
    assert_eq!(
        c.dispatch(Event::Frozen(&one)),
        Effect::Refused(Refusal::DocumentsChanged)
    );
    // And the same size with other bytes.
    let mut c = unlocked();
    c.dispatch(Event::CertificateChosen(1));
    let mut swapped = c.items().to_vec();
    swapped.swap(0, 1);
    assert_eq!(
        c.dispatch(Event::Frozen(&swapped)),
        Effect::Refused(Refusal::DocumentsChanged)
    );
    // And a confirmation that carries other documents than the ones the engine reported.
    let mut c = unlocked();
    c.dispatch(Event::CertificateChosen(1));
    let shown = c.items().to_vec();
    c.dispatch(Event::Frozen(&shown));
    let mut other = shown.clone();
    other[0].bytes += 1;
    assert_eq!(
        c.dispatch(Event::Confirm { frozen: &other }),
        Effect::Refused(Refusal::DocumentsChanged)
    );
    assert!(c.take_approved().is_none());
}

/// What an operation unlocked is gone when it ends, however it ends; a new request starts at
/// the documents and asks for the password again.
#[test]
fn no_unlock_between_operations() {
    for how in [Event::Finished, Event::Cancel] {
        let mut c = unlocked();
        c.dispatch(Event::CertificateChosen(1));
        let frozen = c.items().to_vec();
        c.dispatch(Event::Frozen(&frozen));
        c.dispatch(Event::Confirm { frozen: &frozen });
        let approved = c.take_approved().unwrap();
        drop(approved);
        c.dispatch(how);
        assert_eq!(c.step(), Step::Result);
        assert!(c.unlock_secret().is_none());
        assert!(c.candidates().is_empty() && c.chosen().is_none());
        assert_eq!(
            c.dispatch(Event::Confirm { frozen: &frozen }),
            Effect::Refused(Refusal::WrongStep),
            "a finished operation cannot be confirmed again"
        );
    }
    // A cancel before the confirmation also leaves nothing to apply.
    let mut c = unlocked();
    c.dispatch(Event::Cancel);
    assert!(c.take_approved().is_none() && c.unlock_secret().is_none());
    // The next request is a new controller: no key store, no password, no certificate.
    let next = Controller::new("https://site.example", ActionKind::Sign);
    assert_eq!(next.step(), Step::Source);
    assert!(next.unlock_secret().is_none() && next.candidates().is_empty());
}

/// Choosing needs the documents first, and a key store needs documents to be applied to.
#[test]
fn the_steps_come_in_order() {
    let mut c = Controller::new("tools", ActionKind::Sign);
    assert_eq!(
        c.dispatch(Event::KeyStore("k.p12".into())),
        Effect::Refused(Refusal::NoDocuments)
    );
    assert_eq!(
        c.dispatch(Event::Documents(Vec::new())),
        Effect::Refused(Refusal::NoDocuments)
    );
    assert_eq!(
        c.dispatch(Event::PasswordSubmitted(password("x"))),
        Effect::Refused(Refusal::WrongStep)
    );
    let frozen = [doc("a", 1)];
    assert_eq!(
        c.dispatch(Event::Confirm { frozen: &frozen }),
        Effect::Refused(Refusal::WrongStep)
    );
    assert_eq!(
        c.dispatch(Event::Frozen(&frozen)),
        Effect::Refused(Refusal::WrongStep)
    );
    assert!(c.take_approved().is_none());
}
