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
use oncl_token::{Present, ScanProblem, TokenError, TokenKind, Tokens};
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
