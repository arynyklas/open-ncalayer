//! The AKey driver against the emulated AKey: the exact commands, the PIN counter from the
//! token information, `nca_` labels only, records spanning responses, signatures equal to
//! the software ones, certificates as DER.

mod common;

use common::*;
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_token::drivers::{check_pin, open_driver};
use oncl_token::emulator::EmulatorBackend;
use oncl_token::{TokenError, TokenKind, Tokens};
use std::sync::Arc;

const PIN: &str = "12345678";
const KEYS: [&str; 3] = ["user-gost2004-sign", "user-gost2015-sign", "user-rsa-sign"];

fn akey() -> Arc<EmulatorBackend> {
    backend(spec(TokenKind::AKey, PIN, &KEYS))
}

fn alias(name: &str) -> String {
    key(name).entry.alias
}

#[test]
fn akey_open_matches_golden() {
    let emu = akey();
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::AKey, PIN);
        for slot in &keys {
            driver.public_key(card, slot).unwrap();
            driver.certificate(card, slot).unwrap().unwrap();
        }
        driver.logout(card).unwrap();
    });
    golden("akey-open", &transcript(&emu.exchanges(READER)));
    for (name, alg, file) in [
        ("user-gost2004-sign", SigAlg::Gost2004, "akey-sign-gost2004"),
        (
            "user-gost2015-sign",
            SigAlg::Gost2015_512,
            "akey-sign-gost2015",
        ),
        ("user-rsa-sign", SigAlg::RsaSha256, "akey-sign-rsa"),
    ] {
        let emu = akey();
        let target = alias(name);
        sign_with(&emu, TokenKind::AKey, PIN, |s| s.alias == target, alg, b"m");
        golden(file, &transcript(&emu.exchanges(READER)));
    }
}

#[test]
fn akey_critical_commands_are_exact() {
    let emu = akey();
    let target = alias("user-gost2015-sign");
    sign_with(
        &emu,
        TokenKind::AKey,
        PIN,
        |s| s.alias == target,
        SigAlg::Gost2015_512,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(hex(&ex[0].command), "00A40400087711C13209000000");
    assert_eq!(hex(&ex[1].command), "8003000005");
    assert_eq!(hex(&ex[2].command), "800A0000B0");
    assert_eq!(
        command_starting(&ex, "80070000").unwrap(),
        format!("8007000008{}", hex(PIN.as_bytes()))
    );
    let sign = command_starting(&ex, "801202").unwrap();
    let mut hash = SigAlg::Gost2015_512.digest(b"m");
    hash.reverse();
    // The private key object of the second key is 0113: P2 = 13, the reversed hash, Le FF.
    assert_eq!(sign, format!("8012021340{}FF", hex(&hash)));
    assert_eq!(hex(&ex.last().unwrap().command), "80060000");

    let emu = akey();
    let target = alias("user-rsa-sign");
    sign_with(
        &emu,
        TokenKind::AKey,
        PIN,
        |s| s.alias == target,
        SigAlg::RsaSha256,
        b"m",
    );
    let pieces: Vec<String> = emu
        .exchanges(READER)
        .iter()
        .map(|e| hex(&e.command))
        .filter(|c| c.starts_with("801200"))
        .collect();
    assert_eq!(pieces.len(), 2);
    // The private key object of the third key is 0123.
    assert!(pieces[0].starts_with("80120023FF0001FF"), "{}", pieces[0]);
    assert!(pieces[0].ends_with("FF"));
    assert_eq!(pieces[0].len(), (5 + 255 + 1) * 2);
    assert_eq!(pieces[1].len(), (5 + 1 + 1) * 2);
}

#[test]
fn akey_pin_length_6_to_32() {
    for (pin, fits) in [
        ("12345", false),
        ("123456", true),
        (&"1".repeat(32)[..], true),
        (&"1".repeat(33)[..], false),
        ("12345Ж", false),
    ] {
        assert_eq!(check_pin(TokenKind::AKey, pin).is_ok(), fits, "{pin:?}");
    }
    let emu = akey();
    let tokens = Tokens::new(emu.clone(), true);
    assert_eq!(
        tokens.open(READER, TokenKind::AKey, "12345").err(),
        Some(TokenError::InvalidPin)
    );
    assert!(emu.exchanges(READER).is_empty());
}

#[test]
fn akey_wrong_pin_reads_tries_from_token_info() {
    let emu = akey();
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::AKey, card).unwrap();
        for left in [9, 8] {
            assert_eq!(
                driver.verify_pin(card, "00000000"),
                Err(TokenError::WrongPin {
                    tries_left: Some(left)
                })
            );
        }
    });
    let ex = emu.exchanges(READER);
    let after_login: Vec<String> = ex
        .windows(2)
        .filter(|w| w[0].command.starts_with(&[0x80, 0x07]))
        .map(|w| hex(&w[1].command))
        .collect();
    assert_eq!(after_login, ["800A0000B0", "800A0000B0"]);
    assert!(ex.iter().any(|e| e.response == [0x9C, 0x02]));
}

#[test]
fn akey_blocked_9c0c() {
    let mut s = spec(TokenKind::AKey, PIN, &KEYS);
    (s.tries, s.max_tries) = (2, 2);
    let tokens = Tokens::new(backend(s), true);
    assert_eq!(
        tokens.open(READER, TokenKind::AKey, "00000000").err(),
        Some(TokenError::WrongPin {
            tries_left: Some(1)
        })
    );
    for pin in ["00000000", PIN] {
        assert_eq!(
            tokens.open(READER, TokenKind::AKey, pin).err(),
            Some(TokenError::PinBlocked)
        );
    }
}

#[test]
fn akey_labels_without_nca_prefix_are_ignored() {
    let emu = akey();
    let keys = with_card(&emu, |card| open(card, TokenKind::AKey, PIN).1);
    let got: Vec<(String, KeyAlg)> = keys.into_iter().map(|s| (s.alias, s.alg)).collect();
    assert_eq!(
        got,
        [
            (alias(KEYS[0]), KeyAlg::Gost2004),
            (alias(KEYS[1]), KeyAlg::Gost2015_512),
            (alias(KEYS[2]), KeyAlg::Rsa),
        ]
    );
}

#[test]
fn akey_records_spanning_responses() {
    let emu = akey();
    with_card(&emu, |card| open(card, TokenKind::AKey, PIN));
    let lists: Vec<usize> = emu
        .exchanges(READER)
        .iter()
        .filter(|e| e.command.starts_with(&[0x80, 0x10]))
        .map(|e| e.response.len() - 2)
        .collect();
    assert!(lists.len() >= 3, "{lists:?}");
    assert!(
        lists[..lists.len() - 1].iter().all(|&n| n == 255),
        "{lists:?}"
    );
}

fn equals_software(name: &str, alg: SigAlg) {
    let emu = akey();
    let target = alias(name);
    let sig = sign_with(
        &emu,
        TokenKind::AKey,
        PIN,
        |s| s.alias == target,
        alg,
        b"message",
    );
    assert_eq!(sig, software_signature(name, alg, b"message"));
    let entry = Tokens::new(emu, true)
        .open(READER, TokenKind::AKey, PIN)
        .unwrap()
        .into_iter()
        .find(|e| e.alias == target)
        .unwrap();
    assert_eq!(
        entry.key.sign(alg, b"message").unwrap(),
        software_signature(name, alg, b"message")
    );
}

#[test]
fn akey_gost2004_equals_software() {
    equals_software("user-gost2004-sign", SigAlg::Gost2004);
}

#[test]
fn akey_gost2015_equals_software() {
    equals_software("user-gost2015-sign", SigAlg::Gost2015_512);
}

#[test]
fn akey_rsa_equals_software() {
    equals_software("user-rsa-sign", SigAlg::RsaSha256);
}

#[test]
fn akey_raw_der_certificate() {
    let emu = akey();
    let entries = Tokens::new(emu.clone(), true)
        .open(READER, TokenKind::AKey, PIN)
        .unwrap();
    assert_eq!(entries.len(), 3);
    for (entry, name) in entries.iter().zip(KEYS) {
        assert_eq!(entry.cert, key(name).entry.cert);
    }
    // The first answer of a certificate object is its length and DER (`30 82`).
    let first = emu
        .exchanges(READER)
        .into_iter()
        .find(|e| e.command.starts_with(&[0x80, 0x0F, 0x01, 0x01]))
        .unwrap();
    assert_eq!(first.response[2..4], [0x30, 0x82]);
}
