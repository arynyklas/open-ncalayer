//! The token service on the emulator: support off, scanning, opening a token into key
//! entries, and keys that sign on the card — one transaction per signature, the card reset
//! after it, a refused PIN never sent again, another card or a removed card an error.

mod common;

use common::*;
use oncl_pki::cms::{self, SignOptions};
use oncl_pki::info::cert_info;
use oncl_pki::key::{KeyAlg, KeyError, SigAlg};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::xmldsig;
use oncl_token::backend::{Backend, BackendError, Connection, Protocol, ReaderState};
use oncl_token::emulator::{EmuKey, EmulatorBackend, SoftCard, card};
use oncl_token::{IdCardInfo, Present, ScanProblem, TokenError, TokenKind, Tokens};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::macros::datetime;

const PIN: &str = "123456";
const KEYS: [&str; 3] = ["user-gost2004-sign", "user-gost2015-sign", "user-rsa-sign"];

/// Counts what the service asks of the backend.
#[derive(Default)]
struct Counts {
    readers: AtomicUsize,
    connects: AtomicUsize,
    begins: AtomicUsize,
    ends: AtomicUsize,
    drops: AtomicUsize,
}

struct Counting {
    inner: Arc<EmulatorBackend>,
    counts: Arc<Counts>,
}

struct CountingConnection {
    inner: Box<dyn Connection>,
    counts: Arc<Counts>,
}

impl Backend for Counting {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        self.counts.readers.fetch_add(1, Ordering::SeqCst);
        self.inner.readers()
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        self.counts.connects.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CountingConnection {
            inner: self.inner.connect(reader)?,
            counts: self.counts.clone(),
        }))
    }
}

impl Connection for CountingConnection {
    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }

    fn atr(&self) -> &[u8] {
        self.inner.atr()
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        self.counts.begins.fetch_add(1, Ordering::SeqCst);
        self.inner.begin_transaction()
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.counts.ends.fetch_add(1, Ordering::SeqCst);
        self.inner.end_transaction()
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.inner.transmit(apdu)
    }

    fn reset_on_disconnect(&mut self) {
        self.inner.reset_on_disconnect();
    }
}

impl Drop for CountingConnection {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting(emu: Arc<EmulatorBackend>, enabled: bool) -> (Arc<Tokens>, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let backend = Counting {
        inner: emu,
        counts: counts.clone(),
    };
    (Tokens::new(Arc::new(backend), enabled), counts)
}

fn kaztoken() -> Arc<EmulatorBackend> {
    backend(spec(TokenKind::Kaztoken, PIN, &KEYS))
}

fn opts() -> SignOptions {
    SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: datetime!(2026-03-01 10:20:30 UTC),
    }
}

/// An unknown card.
struct Unknown;

impl SoftCard for Unknown {
    fn atr(&self) -> Vec<u8> {
        vec![0x3B, 0x00]
    }

    fn protocol(&self) -> Protocol {
        Protocol::T1
    }

    fn process(&mut self, _apdu: &[u8]) -> Vec<u8> {
        vec![0x6D, 0x00]
    }

    fn reset(&mut self) {}
}

#[test]
fn disabled_tokens_see_nothing() {
    let (tokens, counts) = counting(kaztoken(), false);
    assert!(!tokens.is_enabled());
    let scan = tokens.scan();
    assert!(scan.present.is_empty());
    assert_eq!(scan.problem, None);
    assert_eq!(tokens.readers(TokenKind::Kaztoken), Ok(vec![]));
    assert!(!tokens.any_card());
    assert_eq!(
        tokens.open(READER, TokenKind::Kaztoken, PIN).err(),
        Some(TokenError::Disabled)
    );
    assert_eq!(counts.readers.load(Ordering::SeqCst), 0);
    assert_eq!(counts.connects.load(Ordering::SeqCst), 0);

    let none = Tokens::disabled();
    assert!(!none.is_enabled());
    assert!(none.scan().present.is_empty());

    tokens.set_enabled(true);
    assert_eq!(tokens.scan().present.len(), 1);
}

#[test]
fn scan_finds_kaztoken_by_atr() {
    let emu = kaztoken();
    emu.add_reader("Empty reader");
    let tokens = Tokens::new(emu.clone(), true);
    let scan = tokens.scan();
    assert_eq!(
        scan.present,
        [Present {
            kind: TokenKind::Kaztoken,
            reader: READER.to_owned()
        }]
    );
    assert_eq!(scan.problem, None);
    assert_eq!(
        tokens.readers(TokenKind::Kaztoken),
        Ok(vec![READER.to_owned()])
    );
    assert_eq!(tokens.readers(TokenKind::JaCarta), Ok(vec![]));
    assert!(tokens.any_card());
}

#[test]
fn unknown_atr_is_ignored() {
    let emu = backend_with(Box::new(Unknown));
    let tokens = Tokens::new(emu, true);
    assert!(tokens.scan().present.is_empty());
    assert!(tokens.any_card(), "a card is there, of no known family");
    assert_eq!(
        tokens.open(READER, TokenKind::Kaztoken, PIN).err(),
        Some(TokenError::NoDevice)
    );
}

#[test]
fn no_service_is_a_problem_not_an_error() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    emu.set_service(false);
    let scan = tokens.scan();
    assert!(scan.present.is_empty());
    assert_eq!(scan.problem, Some(ScanProblem::NoService));
    assert_eq!(tokens.readers(TokenKind::Kaztoken), Ok(vec![]));
    assert!(!tokens.any_card());
    assert_eq!(
        tokens.open(READER, TokenKind::Kaztoken, PIN).err(),
        Some(TokenError::NoService)
    );

    let empty = Tokens::new(Arc::new(EmulatorBackend::new()), true);
    let scan = empty.scan();
    assert!(scan.present.is_empty());
    assert_eq!(scan.problem, None, "no reader is not a problem");
}

#[test]
fn open_pairs_keys_with_certificates() {
    let tokens = Tokens::new(kaztoken(), true);
    let entries = tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap();
    assert_eq!(entries.len(), 3);
    for (entry, name) in entries.iter().zip(KEYS) {
        let software = key(name).entry;
        assert_eq!(entry.alias, software.alias);
        assert_eq!(entry.cert, software.cert);
        assert_eq!(cert_info(&entry.cert), cert_info(&software.cert));
        assert_eq!(entry.key.alg(), software.key.alg());
        assert_eq!(entry.key.public_key(), software.key.public_key());
        assert_eq!(
            format!("{:?}", entry.key),
            format!("Token(AKKaztokenStore in {READER}, {})", software.alias)
        );
    }
}

#[test]
fn open_reports_pin_errors() {
    let tokens = Tokens::new(kaztoken(), true);
    assert_eq!(
        tokens.open(READER, TokenKind::Kaztoken, "000000").err(),
        Some(TokenError::WrongPin {
            tries_left: Some(9)
        })
    );
    assert_eq!(
        tokens.open(READER, TokenKind::Kaztoken, "").err(),
        Some(TokenError::InvalidPin)
    );
    assert_eq!(
        tokens
            .open("No such reader", TokenKind::Kaztoken, PIN)
            .err(),
        Some(TokenError::NoDevice)
    );
    assert_eq!(
        tokens.open(READER, TokenKind::JaCarta, "123456").err(),
        Some(TokenError::NoDevice),
        "the ATR is a Kaztoken's"
    );
}

#[test]
fn slot_with_foreign_certificate_is_skipped() {
    let mut s = spec(TokenKind::Kaztoken, PIN, &KEYS);
    // The second key's certificate file holds the first key's certificate.
    s.keys[1] = EmuKey {
        entry: KeyEntry {
            cert: key(KEYS[0]).entry.cert,
            ..key(KEYS[1]).entry
        },
    };
    let tokens = Tokens::new(backend(s), true);
    let entries = tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap();
    let aliases: Vec<&str> = entries.iter().map(|e| e.alias.as_str()).collect();
    assert_eq!(
        aliases,
        [key(KEYS[0]).entry.alias, key(KEYS[2]).entry.alias]
    );
}

#[test]
fn cms_from_token_entry_verifies() {
    let tokens = Tokens::new(kaztoken(), true);
    for entry in tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap() {
        let signed = cms::sign(&entry, b"data", &opts()).unwrap();
        let signers = cms::verify(&signed, None).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].cert, entry.cert);
    }
}

#[test]
fn xml_from_token_entry_verifies() {
    let tokens = Tokens::new(kaztoken(), true);
    for entry in tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap() {
        let signed = xmldsig::sign_enveloped(b"<a><b>1</b></a>", &entry.key, &entry.cert).unwrap();
        let signers = xmldsig::verify(&signed).unwrap();
        assert_eq!(signers[0].cert, entry.cert);
    }
}

#[test]
fn token_signature_equals_software() {
    let tokens = Tokens::new(kaztoken(), true);
    let entries = tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap();
    for ((entry, name), alg) in
        entries
            .iter()
            .zip(KEYS)
            .zip([SigAlg::Gost2004, SigAlg::Gost2015_512, SigAlg::RsaSha256])
    {
        assert_eq!(
            entry.key.sign(alg, b"message").unwrap(),
            software_signature(name, alg, b"message"),
            "{name}"
        );
    }
}

#[test]
fn swapped_halves_are_an_error() {
    let mut s = spec(TokenKind::Kaztoken, PIN, &KEYS[..2]);
    s.swap_signature_halves = true;
    let tokens = Tokens::new(backend(s), true);
    for entry in tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap() {
        let alg = match entry.key.alg() {
            KeyAlg::Gost2004 => SigAlg::Gost2004,
            _ => SigAlg::Gost2015_512,
        };
        assert!(matches!(
            entry.key.sign(alg, b"message"),
            Err(KeyError::Token(msg)) if msg.contains("does not verify")
        ));
    }
}

fn gost2015_entry(entries: Vec<KeyEntry>) -> KeyEntry {
    entries
        .into_iter()
        .find(|e| e.key.alg() == KeyAlg::Gost2015_512)
        .unwrap()
}

#[test]
fn card_swapped_between_open_and_sign() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    let mut other = spec(TokenKind::Kaztoken, PIN, &KEYS);
    other.serial = [9; 8];
    emu.insert(READER, card(other));
    match entry.key.sign(SigAlg::Gost2015_512, b"m") {
        Err(KeyError::Token(msg)) => assert!(msg.contains("another token"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert!(
        emu.exchanges(READER)
            .iter()
            .rev()
            .take_while(|e| e.command[..4] != [0x00, 0xCA, 0x01, 0x81])
            .all(|e| e.command[1] != 0x20),
        "no PIN for another token"
    );
}

#[test]
fn card_removed_mid_sign() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    emu.remove_after(READER, 3);
    match entry.key.sign(SigAlg::Gost2015_512, b"m") {
        Err(KeyError::Token(msg)) => assert!(msg.contains("removed"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert!(tokens.scan().present.is_empty());
    assert!(entry.key.sign(SigAlg::Gost2015_512, b"m").is_err());
}

#[test]
fn pin_rejected_once_never_retried() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    // The PIN was changed elsewhere: same token, another PIN.
    emu.insert(READER, card(spec(TokenKind::Kaztoken, "654321", &KEYS)));
    emu.clear_exchanges(READER);
    match entry.key.sign(SigAlg::Gost2015_512, b"m") {
        Err(KeyError::Token(msg)) => assert!(msg.contains("refused the PIN"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let verifies = emu
        .exchanges(READER)
        .iter()
        .filter(|e| e.command.starts_with(&[0x00, 0x20, 0x00, 0x02]) && e.command.len() > 4)
        .count();
    assert_eq!(verifies, 1, "one try spent");
    emu.clear_exchanges(READER);
    assert!(matches!(
        entry.key.sign(SigAlg::Gost2015_512, b"m"),
        Err(KeyError::Token(_))
    ));
    assert!(emu.exchanges(READER).is_empty(), "no command at all");
    // The token still has 9 tries: one was spent.
    let fresh = Tokens::new(emu, true);
    assert_eq!(
        fresh.open(READER, TokenKind::Kaztoken, "000000").err(),
        Some(TokenError::WrongPin {
            tries_left: Some(8)
        })
    );
}

#[test]
fn each_signature_is_one_transaction_and_resets_card() {
    let emu = kaztoken();
    let (tokens, counts) = counting(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    for _ in 0..2 {
        entry.key.sign(SigAlg::Gost2015_512, b"m").unwrap();
    }
    for n in [
        &counts.connects,
        &counts.begins,
        &counts.ends,
        &counts.drops,
    ] {
        assert_eq!(n.load(Ordering::SeqCst), 3);
    }
    // The reset ended the PIN verification: signing without VERIFY is refused.
    let mut conn = emu.connect(READER).unwrap();
    assert_eq!(
        conn.transmit(&hex_literal::hex!("002241B606910140840102"))
            .unwrap(),
        [0x90, 0x00]
    );
    let mut pso = hex_literal::hex!("002A9E9A40").to_vec();
    pso.extend([0; 64]);
    pso.push(0xFF);
    assert_eq!(conn.transmit(&pso).unwrap(), [0x69, 0x82]);
}

#[test]
fn transaction_ends_on_errors_too() {
    let emu = kaztoken();
    let (tokens, counts) = counting(emu, true);
    assert!(tokens.open(READER, TokenKind::Kaztoken, "000000").is_err());
    assert_eq!(counts.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counts.ends.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn waits_for_foreign_transaction() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    let guard = emu.foreign_transaction(READER);
    let done = Arc::new(AtomicBool::new(false));
    let thread = {
        let done = done.clone();
        std::thread::spawn(move || {
            let sig = entry.key.sign(SigAlg::Gost2015_512, b"m");
            done.store(true, Ordering::SeqCst);
            sig
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(!done.load(Ordering::SeqCst));
    drop(guard);
    thread.join().unwrap().unwrap();
}

#[test]
fn support_off_stops_keys_already_open() {
    let emu = kaztoken();
    let (tokens, counts) = counting(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    tokens.set_enabled(false);
    let connects = counts.connects.load(Ordering::SeqCst);
    match entry.key.sign(SigAlg::Gost2015_512, b"m") {
        Err(KeyError::Token(msg)) => assert_eq!(msg, "token support is off"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        counts.connects.load(Ordering::SeqCst),
        connects,
        "no connection with support off"
    );
    tokens.set_enabled(true);
    entry.key.sign(SigAlg::Gost2015_512, b"m").unwrap();
}

#[test]
fn pin_refused_once_for_all_keys_of_the_token() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    let entries = tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap();
    assert_eq!(entries.len(), 3);
    emu.insert(READER, card(spec(TokenKind::Kaztoken, "654321", &KEYS)));
    emu.clear_exchanges(READER);
    for (entry, alg) in
        entries
            .iter()
            .zip([SigAlg::Gost2004, SigAlg::Gost2015_512, SigAlg::RsaSha256])
    {
        match entry.key.sign(alg, b"m") {
            Err(KeyError::Token(msg)) => assert!(msg.contains("refused the PIN"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }
    let verifies = emu
        .exchanges(READER)
        .iter()
        .filter(|e| e.command.starts_with(&[0x00, 0x20, 0x00, 0x02]) && e.command.len() > 4)
        .count();
    assert_eq!(verifies, 1, "one try for the three keys");
}

#[test]
fn token_removed_between_open_and_sign_is_removed() {
    let emu = kaztoken();
    let tokens = Tokens::new(emu.clone(), true);
    let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
    emu.remove(READER);
    match entry.key.sign(SigAlg::Gost2015_512, b"m") {
        Err(KeyError::Token(msg)) => assert!(msg.contains("removed"), "{msg}"),
        other => panic!("{other:?}"),
    }
    // Another kind of card in the reader is another token.
    emu.insert(READER, Box::new(Unknown));
    match entry.key.sign(SigAlg::Gost2015_512, b"m") {
        Err(KeyError::Token(msg)) => assert!(msg.contains("another token"), "{msg}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn overlapping_operations_on_one_reader_succeed() {
    let emu = kaztoken();
    let (tokens, counts) = counting(emu.clone(), true);
    let entries = tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap();
    let begins = counts.begins.load(Ordering::SeqCst);
    // Both signatures connect while another process holds the card: the first to sign
    // resets the card under the other's connection.
    let guard = emu.foreign_transaction(READER);
    let threads: Vec<_> = entries
        .into_iter()
        .zip([SigAlg::Gost2004, SigAlg::Gost2015_512])
        .map(|(entry, alg)| std::thread::spawn(move || entry.key.sign(alg, b"m")))
        .collect();
    while counts.begins.load(Ordering::SeqCst) < begins + 2 {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(guard);
    for thread in threads {
        thread.join().unwrap().unwrap();
    }
}

#[test]
fn id_card_info_of_another_card_never_connects() {
    let emu = kaztoken();
    emu.add_reader("Empty reader");
    let (tokens, counts) = counting(emu, true);
    assert_eq!(tokens.id_card_info(READER), Err(TokenError::WrongCard));
    assert_eq!(
        tokens.id_card_info("Empty reader"),
        Err(TokenError::NoDevice)
    );
    assert_eq!(
        tokens.id_card_info("No such reader"),
        Err(TokenError::NoDevice)
    );
    assert_eq!(counts.connects.load(Ordering::SeqCst), 0);
}

#[test]
fn only_operations_with_a_pin_reset_the_card() {
    let mut s = spec(
        TokenKind::KzIdCard,
        "1234",
        &["user-gost2015-auth", "user-gost2015-sign"],
    );
    s.id_card = Some(IdCardInfo {
        iin: "123456789012".to_owned(),
        last_name: "ТЕСТОВ".to_owned(),
        first_name: "ТЕСТ".to_owned(),
        middle_name: None,
    });
    let emu = backend(s);
    let tokens = Tokens::new(emu.clone(), true);
    let mut other = emu.connect(READER).unwrap();
    tokens.id_card_info(READER).unwrap();
    other.begin_transaction().unwrap();
    other.end_transaction().unwrap();
    tokens.open(READER, TokenKind::KzIdCard, "1234").unwrap();
    assert_eq!(
        other.begin_transaction(),
        Err(BackendError::Reset),
        "the reset after the PIN ends its verification for everyone"
    );
}

#[test]
fn emulator_reset_reaches_other_connections() {
    let emu = kaztoken();
    let mut conn = emu.connect(READER).unwrap();
    emu.reset_card(READER);
    assert_eq!(conn.begin_transaction(), Err(BackendError::Reset));
    assert_eq!(
        conn.transmit(&[0x00, 0xA4, 0x04, 0x00]),
        Err(BackendError::Reset)
    );
    let mut fresh = emu.connect(READER).unwrap();
    fresh.begin_transaction().unwrap();
}

/// Connections that report a reset by another handle: at `begin` or at the first command,
/// on the first `connections` connections.
struct Resetting {
    inner: Arc<EmulatorBackend>,
    at_begin: bool,
    connections: AtomicUsize,
    connects: AtomicUsize,
}

struct ResettingConnection {
    inner: Box<dyn Connection>,
    reset: Option<bool>,
}

impl Backend for Resetting {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        self.inner.readers()
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let reset = self
            .connections
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
            .then_some(self.at_begin);
        Ok(Box::new(ResettingConnection {
            inner: self.inner.connect(reader)?,
            reset,
        }))
    }
}

impl Connection for ResettingConnection {
    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }

    fn atr(&self) -> &[u8] {
        self.inner.atr()
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        if self.reset == Some(true) {
            return Err(BackendError::Reset);
        }
        self.inner.begin_transaction()
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.inner.end_transaction()
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        if self.reset.is_some() {
            return Err(BackendError::Reset);
        }
        self.inner.transmit(apdu)
    }

    fn reset_on_disconnect(&mut self) {
        self.inner.reset_on_disconnect();
    }
}

fn resetting(at_begin: bool, connections: usize) -> Resetting {
    Resetting {
        inner: kaztoken(),
        at_begin,
        connections: AtomicUsize::new(connections),
        connects: AtomicUsize::new(0),
    }
}

#[test]
fn reset_by_another_handle_reconnects_once() {
    for at_begin in [true, false] {
        let backend = Arc::new(resetting(at_begin, 1));
        let tokens = Tokens::new(backend.clone(), true);
        assert_eq!(
            tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap().len(),
            3,
            "at begin: {at_begin}"
        );
        assert_eq!(backend.connects.load(Ordering::SeqCst), 2);

        let backend = Arc::new(resetting(at_begin, 2));
        let tokens = Tokens::new(backend.clone(), true);
        assert_eq!(
            tokens.open(READER, TokenKind::Kaztoken, PIN).err(),
            Some(TokenError::CardRemoved),
            "at begin: {at_begin}"
        );
        assert_eq!(backend.connects.load(Ordering::SeqCst), 2, "once");
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn trace_never_contains_pin() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let tokens = Tokens::new(kaztoken(), true);
        tokens.set_trace(true);
        let entry = gost2015_entry(tokens.open(READER, TokenKind::Kaztoken, PIN).unwrap());
        entry.key.sign(SigAlg::Gost2015_512, b"m").unwrap();
    });
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("<redacted 6 bytes>").count(), 2, "{text}");
    assert!(!text.contains("31 32 33 34 35 36"), "{text}");
    assert!(!text.contains("313233343536"), "{text}");
}

#[test]
fn id_card_shared_certificate_file_is_not_a_warning() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let entries = tracing::subscriber::with_default(subscriber, || {
        // The RSA key and a GOST key share a certificate file: one of them has none.
        let s = spec(
            TokenKind::KzIdCard,
            "1234",
            &["user-gost2015-auth", "user-gost2015-sign", "user-rsa-sign"],
        );
        Tokens::new(backend(s), true)
            .open(READER, TokenKind::KzIdCard, "1234")
            .unwrap()
    });
    assert_eq!(entries.len(), 2);
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(text.is_empty(), "{text}");
}

/// The PIN of a card of `kind` in these tests, and a wrong one that fits it.
fn pins(kind: TokenKind) -> (&'static str, &'static str) {
    match kind {
        TokenKind::KzIdCard => ("1234", "0000"),
        _ => (PIN, "000000"),
    }
}

#[test]
fn pin_tries_are_read_without_spending_one() {
    for kind in [TokenKind::Kaztoken, TokenKind::KzIdCard, TokenKind::AKey] {
        let (pin, wrong) = pins(kind);
        let emu = backend(spec(kind, pin, &["user-gost2015-sign"]));
        let tokens = Tokens::new(emu.clone(), true);
        assert_eq!(tokens.pin_tries(READER, kind), Ok(Some(10)), "{kind:?}");
        assert_eq!(tokens.pin_tries(READER, kind), Ok(Some(10)), "{kind:?}");
        assert_eq!(
            tokens.open(READER, kind, wrong).err(),
            Some(TokenError::WrongPin {
                tries_left: Some(9)
            }),
            "{kind:?}: reading the tries spent none"
        );
        assert_eq!(tokens.pin_tries(READER, kind), Ok(Some(9)), "{kind:?}");
        // A right PIN restores them.
        tokens.open(READER, kind, pin).unwrap();
        assert_eq!(tokens.pin_tries(READER, kind), Ok(Some(10)), "{kind:?}");
    }
}

#[test]
fn pin_tries_of_a_blocked_pin_are_zero() {
    for kind in [TokenKind::Kaztoken, TokenKind::KzIdCard, TokenKind::AKey] {
        let (pin, _) = pins(kind);
        let mut s = spec(kind, pin, &["user-gost2015-sign"]);
        s.tries = 0;
        let tokens = Tokens::new(backend(s), true);
        assert_eq!(tokens.pin_tries(READER, kind), Ok(Some(0)), "{kind:?}");
    }
}

#[test]
fn pin_tries_unknown_without_a_command_for_tokens_that_do_not_tell() {
    for kind in [
        TokenKind::EToken72K,
        TokenKind::EToken5110,
        TokenKind::JaCarta,
    ] {
        let emu = backend(spec(kind, PIN, &["user-rsa-sign"]));
        let tokens = Tokens::new(emu.clone(), true);
        assert_eq!(tokens.pin_tries(READER, kind), Ok(None), "{kind:?}");
        assert!(emu.exchanges(READER).is_empty(), "{kind:?}");
    }
}

#[test]
fn pin_tries_off_absent_or_another_card() {
    let (tokens, counts) = counting(kaztoken(), false);
    assert_eq!(
        tokens.pin_tries(READER, TokenKind::Kaztoken),
        Err(TokenError::Disabled)
    );
    assert_eq!(counts.readers.load(Ordering::SeqCst), 0);
    let tokens = Tokens::new(kaztoken(), true);
    assert_eq!(
        tokens.pin_tries("No such reader", TokenKind::Kaztoken),
        Err(TokenError::NoDevice)
    );
    assert_eq!(
        tokens.pin_tries(READER, TokenKind::AKey),
        Err(TokenError::NoDevice),
        "the ATR is a Kaztoken's"
    );
}
