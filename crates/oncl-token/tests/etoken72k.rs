//! The eToken 72K driver against the emulated token: the exact commands, aliases as hex of
//! object names, signatures equal to the software ones, no count of PIN tries.

mod common;

use common::*;
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_token::drivers::open_driver;
use oncl_token::{TokenError, TokenKind, Tokens};

const PIN: &str = "1234567890";
const KEYS: [&str; 2] = ["user-gost2004-sign", "user-rsa-sign"];

fn etoken() -> std::sync::Arc<oncl_token::emulator::EmulatorBackend> {
    backend(spec(TokenKind::EToken72K, PIN, &KEYS))
}

fn alias(name: &str) -> String {
    hex(key(name).entry.alias.as_bytes()).to_lowercase()
}

#[test]
fn etoken72k_open_matches_golden() {
    let emu = etoken();
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::EToken72K, PIN);
        for slot in &keys {
            driver.public_key(card, slot).unwrap();
            driver.certificate(card, slot).unwrap().unwrap();
        }
        driver.logout(card).unwrap();
    });
    golden("etoken72k-open", &transcript(&emu.exchanges(READER)));
}

#[test]
fn etoken72k_sign_transcripts_match_golden() {
    for (name, alg, file) in [
        (
            "user-gost2004-sign",
            SigAlg::Gost2004,
            "etoken72k-sign-gost2004",
        ),
        ("user-rsa-sign", SigAlg::RsaSha256, "etoken72k-sign-rsa"),
    ] {
        let emu = etoken();
        let a = alias(name);
        sign_with(&emu, TokenKind::EToken72K, PIN, |s| s.alias == a, alg, b"m");
        golden(file, &transcript(&emu.exchanges(READER)));
    }
}

#[test]
fn etoken72k_critical_commands_are_exact() {
    let emu = etoken();
    let a = alias("user-rsa-sign");
    sign_with(
        &emu,
        TokenKind::EToken72K,
        PIN,
        |s| s.alias == a,
        SigAlg::RsaSha256,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(hex(&ex[0].command), "00A404000A00000000000001020300");
    assert_eq!(hex(&ex[1].command), "80152000");
    assert_eq!(hex(&ex[2].command), "8015100064");
    assert_eq!(
        command_starting(&ex, "80102000").unwrap(),
        format!("801020000A{}", hex(PIN.as_bytes()))
    );
    let upload = command_starting(&ex, "80124900").unwrap();
    // Lc 22: offset 00 00, then the first 32 bytes of the block 00 01 FF…
    assert!(upload.starts_with("801249002200000001FFFF"), "{upload}");
    let uploads = ex
        .iter()
        .filter(|e| e.command.starts_with(&[0x80, 0x12, 0x49]))
        .count();
    assert_eq!(uploads, 8);
    let reads = ex
        .iter()
        .filter(|e| e.command.starts_with(&[0x80, 0x12, 0x48]))
        .count();
    assert_eq!(reads, 8);
    let sign = command_starting(&ex, "80145277").unwrap();
    let name = key("user-rsa-sign").entry.alias;
    assert_eq!(
        sign,
        format!(
            "80145277{:02X}010000{:02X}{}",
            name.len() + 4,
            name.len(),
            hex(name.as_bytes())
        )
    );
}

#[test]
fn etoken72k_aliases_are_hex_names() {
    let emu = etoken();
    let keys = with_card(&emu, |card| open(card, TokenKind::EToken72K, PIN).1);
    let got: Vec<(String, u16, KeyAlg)> =
        keys.into_iter().map(|s| (s.alias, s.id, s.alg)).collect();
    assert_eq!(
        got,
        [
            (alias(KEYS[0]), 0, KeyAlg::Gost2004),
            (alias(KEYS[1]), 1, KeyAlg::Rsa),
        ]
    );
    let entries = Tokens::new(emu, true)
        .open(READER, TokenKind::EToken72K, PIN)
        .unwrap();
    for (entry, name) in entries.iter().zip(KEYS) {
        assert_eq!(entry.alias, alias(name));
        assert_eq!(entry.cert, key(name).entry.cert);
    }
}

fn equals_software(name: &str, alg: SigAlg) {
    let emu = etoken();
    let a = alias(name);
    let sig = sign_with(
        &emu,
        TokenKind::EToken72K,
        PIN,
        |s| s.alias == a,
        alg,
        b"message",
    );
    assert_eq!(sig, software_signature(name, alg, b"message"));
    let entry = Tokens::new(emu, true)
        .open(READER, TokenKind::EToken72K, PIN)
        .unwrap()
        .into_iter()
        .find(|e| e.alias == a)
        .unwrap();
    assert_eq!(
        entry.key.sign(alg, b"message").unwrap(),
        software_signature(name, alg, b"message")
    );
}

#[test]
fn etoken72k_gost2004_equals_software() {
    equals_software("user-gost2004-sign", SigAlg::Gost2004);
}

#[test]
fn etoken72k_rsa_equals_software() {
    equals_software("user-rsa-sign", SigAlg::RsaSha256);
}

#[test]
fn etoken72k_wrong_pin_has_no_count() {
    let emu = etoken();
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::EToken72K, card).unwrap();
        for _ in 0..3 {
            assert_eq!(
                driver.verify_pin(card, "0000000000"),
                Err(TokenError::WrongPin { tries_left: None })
            );
        }
        driver.verify_pin(card, PIN).unwrap();
    });
}

#[test]
fn etoken72k_gost512_slot_is_hidden() {
    let emu = backend(spec(
        TokenKind::EToken72K,
        PIN,
        &["user-gost2015-sign", "user-gost2004-sign"],
    ));
    let keys = with_card(&emu, |card| open(card, TokenKind::EToken72K, PIN).1);
    assert_eq!(
        keys.iter().map(|k| k.alias.clone()).collect::<Vec<_>>(),
        [alias("user-gost2004-sign")]
    );
}
