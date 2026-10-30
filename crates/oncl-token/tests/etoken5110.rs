//! The eToken 5110 driver against the emulated token over T=0 and T=1: the exact commands,
//! RSA in one extended APDU or in pieces, signatures equal to the software ones, the
//! certificate with a status word after it.

mod common;

use common::*;
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_token::backend::Protocol;
use oncl_token::drivers::open_driver;
use oncl_token::emulator::{CardSpec, EmulatorBackend};
use oncl_token::{TokenError, TokenKind, Tokens};
use std::sync::Arc;

const PIN: &str = "1234567890";
const KEYS: [&str; 3] = ["user-gost2004-sign", "user-gost2015-sign", "user-rsa-sign"];
const PROTOCOLS: [Protocol; 2] = [Protocol::T0, Protocol::T1];

fn card_spec(protocol: Protocol) -> CardSpec {
    let mut s = spec(TokenKind::EToken5110, PIN, &KEYS);
    s.protocol = protocol;
    s.t0_quirks = protocol == Protocol::T0;
    s
}

fn etoken(protocol: Protocol) -> Arc<EmulatorBackend> {
    backend(card_spec(protocol))
}

fn alias(name: &str) -> String {
    hex(key(name).entry.alias.as_bytes()).to_lowercase()
}

fn name_hex(name: &str) -> String {
    let alias = key(name).entry.alias;
    format!("00{:02X}{}", alias.len(), hex(alias.as_bytes()))
}

fn open_golden(protocol: Protocol, file: &str) {
    let emu = etoken(protocol);
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::EToken5110, PIN);
        assert_eq!(keys.len(), 3);
        for slot in &keys {
            driver.public_key(card, slot).unwrap();
            driver.certificate(card, slot).unwrap().unwrap();
        }
        driver.logout(card).unwrap();
    });
    golden(file, &transcript(&emu.exchanges(READER)));
}

#[test]
fn etoken5110_t0_matches_golden() {
    open_golden(Protocol::T0, "etoken5110-t0-open");
}

#[test]
fn etoken5110_t1_matches_golden() {
    open_golden(Protocol::T1, "etoken5110-t1-open");
}

#[test]
fn etoken5110_sign_transcripts_match_golden() {
    for (protocol, p) in [(Protocol::T0, "t0"), (Protocol::T1, "t1")] {
        for (name, alg, a) in [
            ("user-gost2015-sign", SigAlg::Gost2015_512, "gost2015"),
            ("user-rsa-sign", SigAlg::RsaSha256, "rsa"),
        ] {
            let emu = etoken(protocol);
            let target = alias(name);
            sign_with(
                &emu,
                TokenKind::EToken5110,
                PIN,
                |s| s.alias == target,
                alg,
                b"m",
            );
            golden(
                &format!("etoken5110-{p}-sign-{a}"),
                &transcript(&emu.exchanges(READER)),
            );
        }
    }
}

#[test]
fn etoken5110_select_is_exact() {
    let emu = etoken(Protocol::T1);
    with_card(&emu, |card| open(card, TokenKind::EToken5110, PIN));
    let ex = emu.exchanges(READER);
    assert_eq!(
        hex(&ex[0].command),
        format!("00A404000DA000{}00", hex(b"gammatechg"))
    );
    assert_eq!(hex(&ex[1].command), "80152000");
    assert_eq!(hex(&ex[2].command), "8015210064");
    assert!(command_starting(&ex, "80102100").is_some());
    assert_eq!(
        command_starting(&ex, "80122200").as_deref(),
        Some("8012220000")
    );
    assert_eq!(
        command_starting(&ex, "80122100").as_deref(),
        Some("8012210002000032")
    );
}

#[test]
fn etoken5110_t1_rsa_is_one_extended_apdu() {
    let emu = etoken(Protocol::T1);
    let target = alias("user-rsa-sign");
    sign_with(
        &emu,
        TokenKind::EToken5110,
        PIN,
        |s| s.alias == target,
        SigAlg::RsaSha256,
        b"m",
    );
    let ex = emu.exchanges(READER);
    let signs: Vec<&Vec<u8>> = ex
        .iter()
        .map(|e| &e.command)
        .filter(|c| c.starts_with(&[0x80, 0x14]))
        .collect();
    assert_eq!(signs.len(), 1);
    let cmd = signs[0];
    let name = name_hex("user-rsa-sign");
    let lc = name.len() / 2 + 2 + 256;
    assert_eq!(cmd.len(), 4 + 3 + lc + 2);
    assert_eq!(cmd[4], 0x00);
    assert_eq!(hex(&cmd[..7]), format!("80142324{:06X}", lc));
    assert!(hex(cmd).starts_with(&format!("80142324{:06X}{name}01000001FF", lc)));
    assert_eq!(hex(&cmd[cmd.len() - 2..]), "0102", "Le 258");
}

#[test]
fn etoken5110_t0_rsa_is_chunked() {
    let emu = etoken(Protocol::T0);
    let target = alias("user-rsa-sign");
    sign_with(
        &emu,
        TokenKind::EToken5110,
        PIN,
        |s| s.alias == target,
        SigAlg::RsaSha256,
        b"m",
    );
    let ex = emu.exchanges(READER);
    let signs: Vec<String> = ex
        .iter()
        .map(|e| hex(&e.command))
        .filter(|c| c.starts_with("8014"))
        .collect();
    assert_eq!(signs.len(), 3, "{signs:?}");
    assert!(
        signs[0].starts_with("80142400E400E000000001FF"),
        "{}",
        signs[0]
    );
    assert_eq!(signs[0].len(), (5 + 0xE4) * 2);
    assert!(signs[1].starts_with("8014240024002000E0"), "{}", signs[1]);
    assert_eq!(signs[1].len(), (5 + 0x24) * 2);
    let name = name_hex("user-rsa-sign");
    assert_eq!(
        signs[2],
        format!("80142324{:02X}{name}0100", name.len() / 2 + 2)
    );
    assert!(
        ex.iter().all(|e| e.command.len() <= 5 + 255),
        "short APDUs only"
    );
    assert!(command_starting(&ex, "00C00000").is_some());
}

fn equals_software(name: &str, alg: SigAlg) {
    for protocol in PROTOCOLS {
        let emu = etoken(protocol);
        let target = alias(name);
        let sig = sign_with(
            &emu,
            TokenKind::EToken5110,
            PIN,
            |s| s.alias == target,
            alg,
            b"message",
        );
        assert_eq!(
            sig,
            software_signature(name, alg, b"message"),
            "{protocol:?}"
        );
        let entry = Tokens::new(emu, true)
            .open(READER, TokenKind::EToken5110, PIN)
            .unwrap()
            .into_iter()
            .find(|e| e.alias == target)
            .unwrap();
        assert_eq!(entry.cert, key(name).entry.cert);
        assert_eq!(
            entry.key.sign(alg, b"message").unwrap(),
            software_signature(name, alg, b"message"),
            "{protocol:?}"
        );
    }
}

#[test]
fn etoken5110_gost2004_equals_software() {
    equals_software("user-gost2004-sign", SigAlg::Gost2004);
}

#[test]
fn etoken5110_gost2015_equals_software() {
    equals_software("user-gost2015-sign", SigAlg::Gost2015_512);
}

#[test]
fn etoken5110_rsa_equals_software() {
    equals_software("user-rsa-sign", SigAlg::RsaSha256);
}

#[test]
fn etoken5110_key_types() {
    for protocol in PROTOCOLS {
        let emu = etoken(protocol);
        let keys = with_card(&emu, |card| open(card, TokenKind::EToken5110, PIN).1);
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
}

#[test]
fn etoken5110_cert_with_trailing_sw_decodes() {
    let emu = etoken(Protocol::T1);
    with_card(&emu, |card| {
        let (mut driver, keys) = open(card, TokenKind::EToken5110, PIN);
        emu.clear_exchanges(READER);
        let cert = driver.certificate(card, &keys[0]).unwrap().unwrap();
        assert_eq!(cert, der::Encode::to_der(&key(KEYS[0]).entry.cert).unwrap());
        let ex = emu.exchanges(READER);
        assert_eq!(ex.len(), 1);
        let (data, _) = ex[0].response.split_at(ex[0].response.len() - 2);
        assert_eq!(
            data[data.len() - 2..],
            [0x90, 0x00],
            "a status word after the member"
        );
        assert!(hex(&ex[0].command).ends_with("1000"), "Le 4096");
    });
}

#[test]
fn etoken5110_wrong_pin_has_no_count() {
    let emu = etoken(Protocol::T1);
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::EToken5110, card).unwrap();
        assert_eq!(
            driver.verify_pin(card, "0000000000"),
            Err(TokenError::WrongPin { tries_left: None })
        );
    });
}
