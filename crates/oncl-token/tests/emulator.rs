//! The emulator's plumbing: readers and cards, a service that is off, removal mid-operation,
//! resets, transactions of other processes, the configuration file, the software card
//! operations, and the vpcd framing.

use hex_literal::hex;
use oncl_pki::key::{PrivateKey, SigAlg, digest_info};
use oncl_pki::pkcs12::KeyEntry;
use oncl_testkit::{synthetic, workspace_root};
use oncl_token::TokenKind;
use oncl_token::backend::{Backend, BackendError, Protocol};
use oncl_token::emulator::soft::{self, PinCheck, PinState};
use oncl_token::emulator::{EmuKey, EmulatorBackend, SoftCard, read_config, serve_vpcd};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const ATR: [u8; 4] = hex!("3B020102");

/// Answers every command with the command itself and `9000`; counts resets.
struct Echo {
    resets: Arc<AtomicUsize>,
}

impl SoftCard for Echo {
    fn atr(&self) -> Vec<u8> {
        ATR.to_vec()
    }

    fn protocol(&self) -> Protocol {
        Protocol::T1
    }

    fn process(&mut self, apdu: &[u8]) -> Vec<u8> {
        [apdu, &hex!("9000")].concat()
    }

    fn reset(&mut self) {
        self.resets.fetch_add(1, Ordering::SeqCst);
    }
}

fn echo() -> (Box<dyn SoftCard>, Arc<AtomicUsize>) {
    let resets = Arc::new(AtomicUsize::new(0));
    (
        Box::new(Echo {
            resets: resets.clone(),
        }),
        resets,
    )
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    EmuKey::load(&key.path, &key.password).unwrap().entry
}

#[test]
fn backend_lists_readers_and_atrs() {
    let emu = EmulatorBackend::new();
    assert_eq!(emu.readers(), Err(BackendError::NoReaders));
    emu.add_reader("Reader A");
    emu.add_reader("Reader B");
    emu.insert("Reader A", echo().0);
    let readers = emu.readers().unwrap();
    assert_eq!(readers.len(), 2);
    assert_eq!(readers[0].name, "Reader A");
    assert_eq!(readers[0].atr.as_deref(), Some(&ATR[..]));
    assert_eq!(readers[1].name, "Reader B");
    assert_eq!(readers[1].atr, None);
    assert_eq!(emu.connect("Reader B").err(), Some(BackendError::NoCard));
    assert_eq!(
        emu.connect("Reader C").err(),
        Some(BackendError::UnknownReader)
    );
    let mut conn = emu.connect("Reader A").unwrap();
    assert_eq!(conn.atr(), ATR);
    assert_eq!(conn.protocol(), Protocol::T1);
    assert_eq!(
        conn.transmit(&hex!("80400000")).unwrap(),
        hex!("804000009000")
    );
    let exchanges = emu.exchanges("Reader A");
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].command, hex!("80400000"));
    assert_eq!(exchanges[0].response, hex!("804000009000"));
    emu.clear_exchanges("Reader A");
    assert!(emu.exchanges("Reader A").is_empty());
    emu.remove("Reader A");
    assert_eq!(emu.readers().unwrap()[0].atr, None);
    assert_eq!(conn.transmit(&hex!("80400000")), Err(BackendError::Removed));
}

#[test]
fn service_off_is_no_service() {
    let emu = EmulatorBackend::new();
    emu.add_reader("Reader A");
    emu.insert("Reader A", echo().0);
    emu.set_service(false);
    assert_eq!(emu.readers(), Err(BackendError::NoService));
    assert_eq!(emu.connect("Reader A").err(), Some(BackendError::NoService));
    emu.set_service(true);
    assert!(emu.connect("Reader A").is_ok());
}

#[test]
fn removal_after_n_apdus() {
    let emu = EmulatorBackend::new();
    emu.add_reader("Reader A");
    emu.insert("Reader A", echo().0);
    let mut conn = emu.connect("Reader A").unwrap();
    emu.remove_after("Reader A", 2);
    assert!(conn.transmit(&hex!("80400000")).is_ok());
    assert!(conn.transmit(&hex!("80400000")).is_ok());
    assert_eq!(conn.transmit(&hex!("80400000")), Err(BackendError::Removed));
    assert_eq!(emu.readers().unwrap()[0].atr, None);
    assert_eq!(conn.begin_transaction(), Err(BackendError::Removed));
}

#[test]
fn connection_drop_resets_card_only_when_asked() {
    let emu = EmulatorBackend::new();
    emu.add_reader("Reader A");
    let (card, resets) = echo();
    emu.insert("Reader A", card);
    let mut conn = emu.connect("Reader A").unwrap();
    conn.begin_transaction().unwrap();
    drop(conn);
    assert_eq!(
        resets.load(Ordering::SeqCst),
        0,
        "the card is left as it is"
    );
    // A transaction left open by a dropped connection is over.
    let mut other = emu.connect("Reader A").unwrap();
    other.begin_transaction().unwrap();
    other.end_transaction().unwrap();
    let mut conn = emu.connect("Reader A").unwrap();
    conn.reset_on_disconnect();
    drop(conn);
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    assert_eq!(other.begin_transaction(), Err(BackendError::Reset));
}

#[test]
fn foreign_transaction_blocks_until_released() {
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader("Reader A");
    emu.insert("Reader A", echo().0);
    let guard = emu.foreign_transaction("Reader A");
    let started = Arc::new(AtomicBool::new(false));
    let thread = {
        let (emu, started) = (emu.clone(), started.clone());
        std::thread::spawn(move || {
            let mut conn = emu.connect("Reader A").unwrap();
            conn.begin_transaction().unwrap();
            started.store(true, Ordering::SeqCst);
            conn.end_transaction().unwrap();
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !started.load(Ordering::SeqCst),
        "waits for the other process"
    );
    drop(guard);
    thread.join().unwrap();
    assert!(started.load(Ordering::SeqCst));
}

#[test]
fn config_loads_synthetic_keys() {
    let text = r#"
[[reader]]
name = "OpenNCALayer Emulated Kaztoken 0"
kind = "AKKaztokenStore"
pin = "123456"
tries = 10
protocol = "T1"
keys = [{ p12 = "fixtures/synthetic/user-gost2015-sign.p12", password = "Qwerty12" }]

[[reader]]
name = "OpenNCALayer Emulated ID card"
kind = "AKKZIDCardStore"
pin = "1234"
tries = 3
protocol = "T0"
keys = [{ p12 = "fixtures/synthetic/user-rsa-sign.p12", password = "Qwerty12" }]
id_card = { iin = "123456789012", last_name = "ТЕСТОВ", first_name = "ТЕСТ", middle_name = "ТЕСТОВИЧ" }

[[reader]]
name = "Empty reader"
"#;
    let readers = read_config(text, &workspace_root()).unwrap();
    assert_eq!(readers.len(), 3);
    let kaztoken = readers[0].card.as_ref().unwrap();
    assert_eq!(readers[0].name, "OpenNCALayer Emulated Kaztoken 0");
    assert_eq!(kaztoken.kind, TokenKind::Kaztoken);
    assert_eq!(kaztoken.pin, "123456");
    assert_eq!((kaztoken.tries, kaztoken.max_tries), (10, 10));
    assert_eq!(kaztoken.protocol, Protocol::T1);
    assert_eq!(kaztoken.keys.len(), 1);
    assert_eq!(
        kaztoken.keys[0].entry.cert,
        entry("user-gost2015-sign").cert
    );
    let id = readers[1].card.as_ref().unwrap();
    assert_eq!(id.kind, TokenKind::KzIdCard);
    assert_eq!(id.protocol, Protocol::T0);
    assert!(id.t0_quirks);
    assert_eq!(id.keys[0].entry.cert, entry("user-rsa-sign").cert);
    let info = id.id_card.as_ref().unwrap();
    assert_eq!(info.full_name(), "ТЕСТОВ ТЕСТ ТЕСТОВИЧ");
    assert_eq!(info.iin, "123456789012");
    assert!(readers[2].card.is_none());

    let missing = text.replace("user-rsa-sign.p12", "nope.p12");
    assert!(read_config(&missing, &workspace_root()).is_err());
}

#[test]
fn config_rejects_unknown_kind() {
    let text = r#"
[[reader]]
name = "R"
kind = "AKKorganSStore"
pin = "1"
"#;
    let err = read_config(text, &workspace_root()).unwrap_err();
    assert!(err.contains("AKKorganSStore"), "{err}");
    let err = read_config("[[reader]]\nname = \"R\"\nbogus = 1\n", &workspace_root()).unwrap_err();
    assert!(err.contains("bogus"), "{err}");
}

#[test]
fn soft_rsa_block_check() {
    let e = entry("user-rsa-sign");
    let modulus = soft::rsa_modulus_be(&e);
    assert_eq!(modulus.len(), 256);
    let di = digest_info(SigAlg::RsaSha256, &SigAlg::RsaSha256.digest(b"m")).unwrap();
    let mut block = vec![0x00, 0x01];
    block.resize(modulus.len() - di.len() - 1, 0xFF);
    block.push(0x00);
    block.extend(&di);
    let sig = soft::rsa_sign_block(&e, &block).unwrap();
    e.key
        .public_key()
        .verify(SigAlg::RsaSha256, b"m", &sig)
        .unwrap();
    assert_eq!(sig, soft::rsa_sign_digest_info(&e, &di));
    assert_eq!(sig, e.key.sign(SigAlg::RsaSha256, b"m").unwrap());

    let mut type2 = block.clone();
    type2[1] = 0x02;
    assert_eq!(soft::rsa_sign_block(&e, &type2), Err(0x6A80));
    assert_eq!(soft::rsa_sign_block(&e, &block[1..]), Err(0x6A80));
    let mut short_padding = vec![0x00, 0x01, 0xFF, 0x00];
    short_padding.extend(&di);
    short_padding.resize(256, 0);
    assert_eq!(soft::rsa_sign_block(&e, &short_padding), Err(0x6A80));
}

#[test]
fn soft_gost_fixed_k_equals_software() {
    let k = hex!("0123456789ABCDEF0123456789ABCDEF");
    for (name, alg) in [
        ("user-gost2015-sign", SigAlg::Gost2015_512),
        ("user-gost2004-sign", SigAlg::Gost2004),
    ] {
        let e = entry(name);
        let PrivateKey::Gost(key) = &e.key else {
            panic!("{name} is a GOST key")
        };
        let digest = alg.digest(b"message");
        assert_eq!(
            soft::gost_sign(&e, &digest, Some(&k)),
            key.sign_digest_with_k(&digest, &k).unwrap(),
            "{name}"
        );
        let random = soft::gost_sign(&e, &digest, None);
        e.key.public_key().verify(alg, b"message", &random).unwrap();
        assert_eq!(
            soft::gost_point_le(&e),
            key.verifying_key().to_kz_bytes(),
            "{name}"
        );
    }
}

#[test]
fn soft_pin_state() {
    let mut pin = PinState::new("1234", 3, 3);
    assert_eq!(pin.verify(b"0000"), PinCheck::Wrong(2));
    assert_eq!(pin.verify(b"1234"), PinCheck::Ok);
    assert!(pin.is_verified());
    assert_eq!(pin.tries(), 3);
    pin.reset();
    assert!(!pin.is_verified());
    for left in [2, 1] {
        assert_eq!(pin.verify(b"0000"), PinCheck::Wrong(left));
    }
    assert_eq!(pin.verify(b"0000"), PinCheck::Blocked);
    assert_eq!(pin.verify(b"1234"), PinCheck::Blocked);
    assert!(!pin.is_verified());
}

fn frame(stream: &mut impl Write, payload: &[u8]) {
    let len = u16::try_from(payload.len()).unwrap().to_be_bytes();
    stream.write_all(&[&len[..], payload].concat()).unwrap();
}

fn read_frame(stream: &mut impl Read) -> Vec<u8> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).unwrap();
    let mut out = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut out).unwrap();
    out
}

#[test]
fn vpcd_framing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (card, resets) = echo();
    let server = std::thread::spawn(move || serve_vpcd(card, addr));
    let (mut vpcd, _) = listener.accept().unwrap();
    frame(&mut vpcd, &[0x01]);
    frame(&mut vpcd, &[0x04]);
    assert_eq!(read_frame(&mut vpcd), ATR);
    frame(&mut vpcd, &hex!("80400000"));
    assert_eq!(read_frame(&mut vpcd), hex!("804000009000"));
    frame(&mut vpcd, &[0x02]);
    frame(&mut vpcd, &[0x04]);
    assert_eq!(read_frame(&mut vpcd), ATR);
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    drop(vpcd);
    server.join().unwrap().unwrap();
}

#[test]
fn reset_on_disconnect_waits_for_another_transaction() {
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader("Reader A");
    let (card, resets) = echo();
    emu.insert("Reader A", card);
    let mut resetting = emu.connect("Reader A").unwrap();
    resetting.reset_on_disconnect();
    let mut other = emu.connect("Reader A").unwrap();
    other.begin_transaction().unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let thread = {
        let dropped = dropped.clone();
        std::thread::spawn(move || {
            drop(resetting);
            dropped.store(true, Ordering::SeqCst);
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the reset waits for the transaction"
    );
    assert!(
        other.transmit(&hex!("80400000")).is_ok(),
        "not reset mid-transaction"
    );
    other.end_transaction().unwrap();
    thread.join().unwrap();
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    assert_eq!(other.begin_transaction(), Err(BackendError::Reset));
}
