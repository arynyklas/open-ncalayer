//! A token PIN from a page reaches the card only with the user's consent, on emulated
//! cards: the APDU log shows what was sent.

use oncl_basics::{PagePins, PinFrom, PinRefusal, PinUse};
use oncl_testkit::synthetic;
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenError, TokenKind, Tokens};
use std::cell::RefCell;
use std::sync::Arc;

const READER: &str = "OpenNCALayer Emulated Reader 0";
const OTHER: &str = "OpenNCALayer Emulated Reader 1";
const SITE: &str = "https://site.kz";
const PIN: &str = "123456";
const WRONG: &str = "000000";

fn kaztoken(tries: u8) -> CardSpec {
    let k = synthetic("user-gost2015-sign");
    let mut spec = CardSpec::new(
        TokenKind::Kaztoken,
        PIN,
        vec![EmuKey::load(&k.path, &k.password).unwrap()],
    );
    spec.tries = tries;
    spec
}

fn emulator(readers: &[&str], tries: u8) -> Arc<EmulatorBackend> {
    let emu = Arc::new(EmulatorBackend::new());
    for reader in readers {
        emu.add_reader(reader);
        emu.insert(reader, card(kaztoken(tries)));
    }
    emu
}

/// The VERIFY commands that carried a PIN (one without data only asks for the tries).
fn pins_sent(emu: &EmulatorBackend, reader: &str) -> usize {
    emu.exchanges(reader)
        .iter()
        .filter(|e| e.command.get(1) == Some(&0x20) && e.command.len() > 5)
        .count()
}

/// Answers the questions with `answers` in order, recording the tries each one showed; a
/// question beyond them is declined.
struct User {
    answers: RefCell<Vec<bool>>,
    asked: RefCell<Vec<Option<u8>>>,
}

impl User {
    fn new(answers: &[bool]) -> User {
        User {
            answers: RefCell::new(answers.iter().rev().copied().collect()),
            asked: RefCell::new(Vec::new()),
        }
    }

    fn ask(&self) -> impl FnOnce(Option<u8>) -> bool + '_ {
        |tries| {
            self.asked.borrow_mut().push(tries);
            self.answers.borrow_mut().pop().unwrap_or(false)
        }
    }

    fn asked(&self) -> Vec<Option<u8>> {
        self.asked.borrow().clone()
    }
}

fn open(
    guard: &mut PagePins,
    tokens: &Tokens,
    origin: &str,
    reader: &str,
    pin: &str,
    from: PinFrom,
    user: &User,
) -> Result<usize, PinRefusal> {
    let pin_use = PinUse {
        origin,
        reader,
        kind: TokenKind::Kaztoken,
        pin,
        from,
    };
    guard
        .open(tokens, pin_use, user.ask())
        .map(|keys| keys.len())
}

fn wrong_pin(tries_left: u8) -> Result<usize, PinRefusal> {
    Err(PinRefusal::Token(TokenError::WrongPin {
        tries_left: Some(tries_left),
    }))
}

#[test]
fn declined_sends_no_pin() {
    let emu = emulator(&[READER], 10);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[false]);
    assert_eq!(
        open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
        Err(PinRefusal::Declined)
    );
    assert_eq!(user.asked(), [Some(10)], "the question shows the tries");
    assert_eq!(pins_sent(&emu, READER), 0);
}

#[test]
fn consent_once_per_origin_and_reader() {
    let emu = emulator(&[READER, OTHER], 10);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[true, true, true]);
    for _ in 0..3 {
        assert_eq!(
            open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
            Ok(1)
        );
    }
    assert_eq!(user.asked().len(), 1, "a right PIN keeps the consent");
    // Another site, another reader: asked again.
    open(
        &mut guard,
        &tokens,
        "https://b.kz",
        READER,
        PIN,
        PinFrom::Page,
        &user,
    )
    .unwrap();
    open(&mut guard, &tokens, SITE, OTHER, PIN, PinFrom::Page, &user).unwrap();
    assert_eq!(user.asked().len(), 3);
    assert_eq!(pins_sent(&emu, READER), 4);
}

#[test]
fn wrong_pin_is_one_verify_then_a_new_consent() {
    let emu = emulator(&[READER], 10);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[true]);
    assert_eq!(
        open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            WRONG,
            PinFrom::Page,
            &user
        ),
        wrong_pin(9)
    );
    assert_eq!(pins_sent(&emu, READER), 1, "exactly one VERIFY, no retry");
    // The next PIN asks again; declined, nothing is sent.
    assert_eq!(
        open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
        Err(PinRefusal::Declined)
    );
    assert_eq!(user.asked(), [Some(10), Some(9)]);
    assert_eq!(pins_sent(&emu, READER), 1);
    // A wrong PIN of another site withdraws every site's consent for that reader.
    let user = User::new(&[true, true, true]);
    let mut guard = PagePins::default();
    open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user).unwrap();
    let other = "https://b.kz";
    let _ = open(
        &mut guard,
        &tokens,
        other,
        READER,
        WRONG,
        PinFrom::Page,
        &user,
    );
    open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user).unwrap();
    assert_eq!(user.asked().len(), 3);
}

#[test]
fn few_tries_ask_before_every_pin() {
    // A card that never has more than two tries: every PIN is asked about, right or not.
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER);
    let mut spec = kaztoken(2);
    spec.max_tries = 2;
    emu.insert(READER, card(spec));
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[true; 3]);
    for _ in 0..3 {
        assert_eq!(
            open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
            Ok(1)
        );
    }
    assert_eq!(user.asked(), [Some(2); 3]);

    // Three tries: once; a wrong PIN leaves two, and the right one restores them.
    let emu = emulator(&[READER], 3);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[true; 3]);
    assert_eq!(
        open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            WRONG,
            PinFrom::Page,
            &user
        ),
        wrong_pin(2)
    );
    for _ in 0..2 {
        assert_eq!(
            open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
            Ok(1)
        );
    }
    assert_eq!(user.asked(), [Some(3), Some(2)]);
}

#[test]
fn a_site_cannot_go_below_two_tries_without_clicks() {
    let emu = emulator(&[READER], 10);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    // The user allows once; the site keeps trying wrong PINs.
    let user = User::new(&[true]);
    for _ in 0..20 {
        let _ = open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            WRONG,
            PinFrom::Page,
            &user,
        );
    }
    assert_eq!(pins_sent(&emu, READER), 1, "one click, one try");
    assert_eq!(tokens.pin_tries(READER, TokenKind::Kaztoken), Ok(Some(9)));
    // Even a user who allowed every question down to 3 tries is asked at 2 each time.
    let user = User::new(&[true; 7]);
    for _ in 0..7 {
        let _ = open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            WRONG,
            PinFrom::Page,
            &user,
        );
    }
    assert_eq!(tokens.pin_tries(READER, TokenKind::Kaztoken), Ok(Some(2)));
    let declining = User::new(&[]);
    for _ in 0..5 {
        assert_eq!(
            open(
                &mut guard,
                &tokens,
                SITE,
                READER,
                WRONG,
                PinFrom::Page,
                &declining
            ),
            Err(PinRefusal::Declined)
        );
    }
    assert_eq!(declining.asked(), [Some(2); 5]);
    assert_eq!(tokens.pin_tries(READER, TokenKind::Kaztoken), Ok(Some(2)));
}

#[test]
fn blocked_or_unfit_pin_sends_nothing_and_asks_nothing() {
    let emu = emulator(&[READER], 0);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[true]);
    assert_eq!(
        open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
        Err(PinRefusal::Token(TokenError::PinBlocked))
    );
    assert_eq!(
        open(&mut guard, &tokens, SITE, READER, "", PinFrom::Page, &user),
        Err(PinRefusal::Token(TokenError::InvalidPin))
    );
    assert!(user.asked().is_empty());
    assert_eq!(pins_sent(&emu, READER), 0);
    // Support off: nothing at all.
    let tokens = Tokens::new(emu.clone(), false);
    emu.clear_exchanges(READER);
    assert_eq!(
        open(&mut guard, &tokens, SITE, READER, PIN, PinFrom::Page, &user),
        Err(PinRefusal::Token(TokenError::Disabled))
    );
    assert!(emu.exchanges(READER).is_empty());
}

#[test]
fn typed_pin_goes_without_question_until_refused() {
    let emu = emulator(&[READER], 10);
    let tokens = Tokens::new(emu.clone(), true);
    let mut guard = PagePins::default();
    let user = User::new(&[]);
    assert_eq!(
        open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            PIN,
            PinFrom::Typed(1),
            &user
        ),
        Ok(1)
    );
    assert_eq!(
        open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            WRONG,
            PinFrom::Typed(2),
            &user
        ),
        wrong_pin(9)
    );
    assert!(user.asked().is_empty(), "typed in our dialog");
    // The refused one again is a retry: asked, declined, not sent.
    assert_eq!(
        open(
            &mut guard,
            &tokens,
            SITE,
            READER,
            WRONG,
            PinFrom::Typed(2),
            &user
        ),
        Err(PinRefusal::Declined)
    );
    assert_eq!(user.asked(), [Some(9)]);
    assert_eq!(pins_sent(&emu, READER), 2);
}
