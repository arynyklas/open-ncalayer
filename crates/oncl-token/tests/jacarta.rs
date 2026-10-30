//! The JaCarta driver against the emulated token: the exact commands, RSA in an extended
//! APDU (and so not over T=0), signatures equal to the software ones.

mod common;

use common::*;
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_token::backend::Protocol;
use oncl_token::drivers::open_driver;
use oncl_token::emulator::EmulatorBackend;
use oncl_token::{TokenError, TokenKind, Tokens};
use std::sync::Arc;

const PIN: &str = "1234567890";
const KEYS: [&str; 2] = ["user-gost2004-sign", "user-rsa-sign"];

fn jacarta() -> Arc<EmulatorBackend> {
    backend(spec(TokenKind::JaCarta, PIN, &KEYS))
}

fn alias(name: &str) -> String {
    hex(key(name).entry.alias.as_bytes()).to_lowercase()
}

#[test]
fn jacarta_matches_golden() {
    let emu = jacarta();
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::JaCarta, PIN);
        for slot in &keys {
            driver.public_key(card, slot).unwrap();
            driver.certificate(card, slot).unwrap().unwrap();
        }
        driver.logout(card).unwrap();
    });
    golden("jacarta-open", &transcript(&emu.exchanges(READER)));
    for (name, alg, file) in [
        (
            "user-gost2004-sign",
            SigAlg::Gost2004,
            "jacarta-sign-gost2004",
        ),
        ("user-rsa-sign", SigAlg::RsaSha256, "jacarta-sign-rsa"),
    ] {
        let emu = jacarta();
        let target = alias(name);
        sign_with(
            &emu,
            TokenKind::JaCarta,
            PIN,
            |s| s.alias == target,
            alg,
            b"m",
        );
        golden(file, &transcript(&emu.exchanges(READER)));
    }
}

#[test]
fn jacarta_select_is_exact() {
    let emu = jacarta();
    let target = alias("user-rsa-sign");
    sign_with(
        &emu,
        TokenKind::JaCarta,
        PIN,
        |s| s.alias == target,
        SigAlg::RsaSha256,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(
        hex(&ex[0].command),
        format!("00A404000CA000{}00", hex(b"gammatech"))
    );
    assert_eq!(hex(&ex[0].command), "00A404000CA00067616D6D617465636800");
    assert_eq!(
        command_starting(&ex, "80122200").as_deref(),
        Some("80122200")
    );
    assert_eq!(
        command_starting(&ex, "80122100").as_deref(),
        Some("80122100020000")
    );
    let sign = ex
        .iter()
        .map(|e| &e.command)
        .find(|c| c.starts_with(&[0x80, 0x14, 0x23, 0x24]))
        .unwrap();
    assert_eq!(sign[4], 0x00, "extended");
    let lc = usize::from(u16::from_be_bytes([sign[5], sign[6]]));
    assert_eq!(sign.len(), 7 + lc, "no Le");
}

fn equals_software(name: &str, alg: SigAlg) {
    let emu = jacarta();
    let target = alias(name);
    let sig = sign_with(
        &emu,
        TokenKind::JaCarta,
        PIN,
        |s| s.alias == target,
        alg,
        b"message",
    );
    assert_eq!(sig, software_signature(name, alg, b"message"));
    let entry = Tokens::new(emu, true)
        .open(READER, TokenKind::JaCarta, PIN)
        .unwrap()
        .into_iter()
        .find(|e| e.alias == target)
        .unwrap();
    assert_eq!(entry.cert, key(name).entry.cert);
    assert_eq!(
        entry.key.sign(alg, b"message").unwrap(),
        software_signature(name, alg, b"message")
    );
}

#[test]
fn jacarta_gost2004_equals_software() {
    equals_software("user-gost2004-sign", SigAlg::Gost2004);
}

#[test]
fn jacarta_rsa_equals_software() {
    equals_software("user-rsa-sign", SigAlg::RsaSha256);
}

#[test]
fn jacarta_wrong_pin_has_no_count() {
    let emu = jacarta();
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::JaCarta, card).unwrap();
        assert_eq!(
            driver.verify_pin(card, "0000000000"),
            Err(TokenError::WrongPin { tries_left: None })
        );
    });
}

#[test]
fn jacarta_only_gost2004_and_rsa() {
    let emu = backend(spec(
        TokenKind::JaCarta,
        PIN,
        &["user-gost2015-sign", "user-rsa-sign"],
    ));
    let keys = with_card(&emu, |card| open(card, TokenKind::JaCarta, PIN).1);
    assert_eq!(
        keys.into_iter()
            .map(|k| (k.alias, k.alg))
            .collect::<Vec<_>>(),
        [(alias("user-rsa-sign"), KeyAlg::Rsa)]
    );
}

#[test]
fn jacarta_t0_hides_rsa() {
    let mut s = spec(TokenKind::JaCarta, PIN, &KEYS);
    s.protocol = Protocol::T0;
    s.t0_quirks = true;
    let emu = backend(s);
    let keys = with_card(&emu, |card| open(card, TokenKind::JaCarta, PIN).1);
    assert_eq!(
        keys.into_iter()
            .map(|k| (k.alias, k.alg))
            .collect::<Vec<_>>(),
        [(alias("user-gost2004-sign"), KeyAlg::Gost2004)]
    );
}
