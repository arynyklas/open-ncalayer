//! The Kaztoken driver against the emulated Kaztoken: the exact commands, the key map,
//! signatures equal to the software ones, the PIN counter.

mod common;

use common::*;
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_token::backend::{Backend, Protocol};
use oncl_token::drivers::{check_pin, open_driver};
use oncl_token::emulator::SoftCard;
use oncl_token::{TokenError, TokenKind};

const PIN: &str = "123456";
const KEYS: [&str; 3] = ["user-gost2004-sign", "user-gost2015-sign", "user-rsa-sign"];

fn kaztoken() -> std::sync::Arc<oncl_token::emulator::EmulatorBackend> {
    backend(spec(TokenKind::Kaztoken, PIN, &KEYS))
}

fn alias(name: &str) -> String {
    key(name).entry.alias
}

#[test]
fn kaztoken_open_matches_golden() {
    let emu = kaztoken();
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::Kaztoken, PIN);
        for slot in &keys {
            driver.public_key(card, slot).unwrap();
            driver.certificate(card, slot).unwrap().unwrap();
        }
        driver.logout(card).unwrap();
    });
    golden("kaztoken-open", &transcript(&emu.exchanges(READER)));
}

#[test]
fn kaztoken_sign_transcripts_match_golden() {
    for (name, alg, file) in [
        (
            "user-gost2004-sign",
            SigAlg::Gost2004,
            "kaztoken-sign-gost2004",
        ),
        (
            "user-gost2015-sign",
            SigAlg::Gost2015_512,
            "kaztoken-sign-gost2015",
        ),
        ("user-rsa-sign", SigAlg::RsaSha256, "kaztoken-sign-rsa"),
    ] {
        let emu = kaztoken();
        let a = alias(name);
        sign_with(&emu, TokenKind::Kaztoken, PIN, |s| s.alias == a, alg, b"m");
        golden(file, &transcript(&emu.exchanges(READER)));
    }
}

#[test]
fn kaztoken_critical_commands_are_exact() {
    let emu = kaztoken();
    let a = alias("user-gost2004-sign");
    sign_with(
        &emu,
        TokenKind::Kaztoken,
        PIN,
        |s| s.alias == a,
        SigAlg::Gost2004,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(hex(&ex[0].command), "00CA0181FF");
    assert!(command_starting(&ex, "0020000206313233343536").is_some());
    assert_eq!(
        command_starting(&ex, "002241B6").as_deref(),
        Some("002241B606910140840101")
    );
    let pso = command_starting(&ex, "002A9E9A").unwrap();
    assert_eq!(pso.len(), (5 + 32 + 1) * 2, "hash as is, Le FF: {pso}");
    assert!(pso.ends_with("FF"));

    emu.clear_exchanges(READER);
    let a = alias("user-rsa-sign");
    sign_with(
        &emu,
        TokenKind::Kaztoken,
        PIN,
        |s| s.alias == a,
        SigAlg::RsaSha256,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(
        command_starting(&ex, "002241B6").as_deref(),
        Some("002241B606950140840103")
    );
    let chain: Vec<String> = ex
        .iter()
        .map(|e| hex(&e.command))
        .filter(|c| c[2..].starts_with("2A9E9A"))
        .collect();
    assert_eq!(chain.len(), 2, "{chain:?}");
    assert!(chain[0].starts_with("102A9E9A33"), "{}", chain[0]);
    assert!(chain[1].starts_with("002A9E9ACD"), "{}", chain[1]);
    assert!(
        chain[1].ends_with("010000"),
        "the reversed block ends 01 00, Le 256"
    );
}

#[test]
fn kaztoken_lists_three_keys_with_map_aliases() {
    let emu = kaztoken();
    let keys = with_card(&emu, |card| open(card, TokenKind::Kaztoken, PIN).1);
    let got: Vec<(String, u16, KeyAlg)> =
        keys.into_iter().map(|s| (s.alias, s.id, s.alg)).collect();
    assert_eq!(
        got,
        [
            (alias(KEYS[0]), 1, KeyAlg::Gost2004),
            (alias(KEYS[1]), 2, KeyAlg::Gost2015_512),
            (alias(KEYS[2]), 3, KeyAlg::Rsa),
        ]
    );
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::Kaztoken, PIN);
        assert_eq!(driver.token_id(), "0102030405060708");
        for (slot, name) in keys.iter().zip(KEYS) {
            let entry = key(name).entry;
            assert_eq!(
                driver.public_key(card, slot).unwrap(),
                entry.key.public_key()
            );
            assert_eq!(
                driver.certificate(card, slot).unwrap().unwrap(),
                der::Encode::to_der(&entry.cert).unwrap()
            );
        }
    });
}

fn equals_software(name: &str, alg: SigAlg) {
    let emu = kaztoken();
    let a = alias(name);
    let sig = sign_with(
        &emu,
        TokenKind::Kaztoken,
        PIN,
        |s| s.alias == a,
        alg,
        b"message",
    );
    assert_eq!(sig, software_signature(name, alg, b"message"));
    key(name)
        .entry
        .key
        .public_key()
        .verify(alg, b"message", &sig)
        .unwrap();
}

#[test]
fn kaztoken_gost2004_signature_equals_software() {
    equals_software("user-gost2004-sign", SigAlg::Gost2004);
}

#[test]
fn kaztoken_gost2015_signature_equals_software() {
    equals_software("user-gost2015-sign", SigAlg::Gost2015_512);
}

#[test]
fn kaztoken_rsa_signature_equals_software() {
    equals_software("user-rsa-sign", SigAlg::RsaSha256);
}

#[test]
fn kaztoken_wrong_pin_reports_tries() {
    let emu = kaztoken();
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::Kaztoken, card).unwrap();
        for left in [9, 8] {
            assert_eq!(
                driver.verify_pin(card, "000000"),
                Err(TokenError::WrongPin {
                    tries_left: Some(left)
                })
            );
        }
        driver.verify_pin(card, PIN).unwrap();
        assert_eq!(
            driver.verify_pin(card, "000000"),
            Err(TokenError::WrongPin {
                tries_left: Some(9)
            }),
            "a right PIN restores the tries"
        );
    });
}

#[test]
fn kaztoken_blocked_pin() {
    let emu = kaztoken();
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::Kaztoken, card).unwrap();
        for _ in 0..9 {
            assert!(matches!(
                driver.verify_pin(card, "000000"),
                Err(TokenError::WrongPin { .. })
            ));
        }
        assert_eq!(
            driver.verify_pin(card, "000000"),
            Err(TokenError::PinBlocked)
        );
        assert_eq!(driver.verify_pin(card, PIN), Err(TokenError::PinBlocked));
    });
}

#[test]
fn kaztoken_empty_pin_is_invalid() {
    let emu = kaztoken();
    assert_eq!(
        check_pin(TokenKind::Kaztoken, ""),
        Err(TokenError::InvalidPin)
    );
    assert_eq!(
        check_pin(TokenKind::Kaztoken, "пин"),
        Err(TokenError::InvalidPin)
    );
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::Kaztoken, card).unwrap();
        emu.clear_exchanges(READER);
        assert_eq!(driver.check_pin(""), Err(TokenError::InvalidPin));
        assert_eq!(driver.verify_pin(card, ""), Err(TokenError::InvalidPin));
    });
    assert!(
        emu.exchanges(READER).is_empty(),
        "no command for an invalid PIN"
    );
}

#[test]
fn kaztoken_missing_map_means_no_keys() {
    let emu = backend(spec(TokenKind::Kaztoken, PIN, &[]));
    let keys = with_card(&emu, |card| open(card, TokenKind::Kaztoken, PIN).1);
    assert!(keys.is_empty());
    let ex = emu.exchanges(READER);
    assert!(
        ex.iter()
            .all(|e| e.command[1] != 0xE0 && e.command[1] != 0xD6),
        "nothing is created or written"
    );
}

#[test]
fn kaztoken_raw_certificate_is_accepted() {
    let mut s = spec(TokenKind::Kaztoken, PIN, &["user-gost2015-sign"]);
    s.raw_certificates = true;
    let emu = backend(s);
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::Kaztoken, PIN);
        assert_eq!(
            driver.certificate(card, &keys[0]).unwrap().unwrap(),
            der::Encode::to_der(&key("user-gost2015-sign").entry.cert).unwrap()
        );
    });
}

/// A card with a Kaztoken ATR that refuses every command.
struct Foreign;

impl SoftCard for Foreign {
    fn atr(&self) -> Vec<u8> {
        oncl_token::ATRS
            .iter()
            .find(|(k, _)| *k == TokenKind::Kaztoken)
            .unwrap()
            .1
            .to_vec()
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
fn wrong_card_is_wrong_card() {
    let emu = backend_with(Box::new(Foreign));
    let mut conn = emu.connect(READER).unwrap();
    let mut card = oncl_token::card::Card::new(&mut *conn, false);
    assert_eq!(
        open_driver(TokenKind::Kaztoken, &mut card).err(),
        Some(TokenError::WrongCard)
    );
}
