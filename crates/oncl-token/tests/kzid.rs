//! The ID card driver against the emulated ID card: the exact commands under T=0, the PIN
//! of 4 characters, key pairs sharing certificate files, the cards of 2020, the holder data
//! read without the PIN.

mod common;

use common::*;
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_token::backend::Protocol;
use oncl_token::drivers::{KeySlot, check_pin, open_driver};
use oncl_token::emulator::{CardSpec, SoftCard, card};
use oncl_token::{IdCardInfo, TokenError, TokenKind, Tokens};

const PIN: &str = "1234";
/// GOST1, GOST2, RSA1.
const KEYS: [&str; 3] = ["user-gost2015-auth", "user-gost2015-sign", "user-rsa-sign"];
const TOKEN_ID: &str = "010203040506070801";

fn holder() -> IdCardInfo {
    IdCardInfo {
        iin: "123456789012".to_owned(),
        last_name: "ТЕСТОВ".to_owned(),
        first_name: "ТЕСТ".to_owned(),
        middle_name: Some("ТЕСТОВИЧ".to_owned()),
    }
}

fn id_spec() -> CardSpec {
    let mut s = spec(TokenKind::KzIdCard, PIN, &KEYS);
    s.id_card = Some(holder());
    s
}

/// EF `0101` holds the RSA key's certificate.
fn rsa_spec() -> CardSpec {
    let mut s = id_spec();
    s.id_card_rsa_cert_first = true;
    s
}

fn aliases(tokens: &Tokens) -> Vec<String> {
    tokens
        .open(READER, TokenKind::KzIdCard, PIN)
        .unwrap()
        .into_iter()
        .map(|e| e.alias)
        .collect()
}

fn verifies(emu: &oncl_token::emulator::EmulatorBackend) -> usize {
    emu.exchanges(READER)
        .iter()
        .filter(|e| e.command.starts_with(&[0x00, 0x20]))
        .count()
}

#[test]
fn kzid_open_matches_golden() {
    let emu = backend(id_spec());
    with_card(&emu, |card| {
        assert_eq!(card.protocol(), Protocol::T0);
        let (mut driver, keys) = open(card, TokenKind::KzIdCard, PIN);
        for slot in &keys {
            driver.public_key(card, slot).unwrap();
            driver.certificate(card, slot).unwrap().unwrap();
        }
        driver.logout(card).unwrap();
    });
    golden("kzid-open", &transcript(&emu.exchanges(READER)));
}

#[test]
fn kzid_sign_transcripts_match_golden() {
    let emu = backend(id_spec());
    sign_with(
        &emu,
        TokenKind::KzIdCard,
        PIN,
        |s| s.alias.starts_with("GOST2"),
        SigAlg::Gost2015_512,
        b"m",
    );
    golden("kzid-sign-gost", &transcript(&emu.exchanges(READER)));
    let emu = backend(rsa_spec());
    sign_with(
        &emu,
        TokenKind::KzIdCard,
        PIN,
        |s| s.alias.starts_with("RSA1"),
        SigAlg::RsaSha256,
        b"m",
    );
    golden("kzid-sign-rsa", &transcript(&emu.exchanges(READER)));
}

#[test]
fn kzid_critical_commands_are_exact() {
    let emu = backend(id_spec());
    sign_with(
        &emu,
        TokenKind::KzIdCard,
        PIN,
        |s| s.alias.starts_with("GOST1"),
        SigAlg::Gost2015_512,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(hex(&ex[0].command), "00CADF0109");
    assert!(command_starting(&ex, "00200002083132333430303030").is_some());
    assert_eq!(
        command_starting(&ex, "002241B6").as_deref(),
        Some("002241B609950140840101800174")
    );
    let pso = command_starting(&ex, "002A9E9A").unwrap();
    assert_eq!(pso.len(), (5 + 64) * 2, "the reversed hash, no Le: {pso}");
    let mut hash = SigAlg::Gost2015_512.digest(b"m");
    hash.reverse();
    assert_eq!(pso[10..], hex(&hash));

    let emu = backend(rsa_spec());
    sign_with(
        &emu,
        TokenKind::KzIdCard,
        PIN,
        |s| s.alias.starts_with("RSA1"),
        SigAlg::RsaSha256,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert_eq!(
        command_starting(&ex, "002241A4").as_deref(),
        Some("002241A409950140840187800102")
    );
    let auth = command_starting(&ex, "00880200").unwrap();
    assert_eq!(
        auth,
        format!("0088020033{}", hex(&to_sign(SigAlg::RsaSha256, b"m")))
    );
}

#[test]
fn kzid_pin_must_be_four_chars() {
    let emu = backend(id_spec());
    let tokens = Tokens::new(emu.clone(), true);
    for pin in ["123", "12345", "12Ж4", "", "1234 "] {
        assert_eq!(
            tokens.open(READER, TokenKind::KzIdCard, pin).err(),
            Some(TokenError::InvalidPin),
            "{pin:?}"
        );
    }
    assert!(
        emu.exchanges(READER).is_empty(),
        "no command for an invalid PIN"
    );
    assert_eq!(check_pin(TokenKind::KzIdCard, "12a4"), Ok(()));
    assert_eq!(
        tokens.open(READER, TokenKind::KzIdCard, "12a4").err(),
        Some(TokenError::WrongPin {
            tries_left: Some(9)
        })
    );
}

#[test]
fn kzid_wrong_pin_tries() {
    let tokens = Tokens::new(backend(id_spec()), true);
    for left in [9, 8] {
        assert_eq!(
            tokens.open(READER, TokenKind::KzIdCard, "0000").err(),
            Some(TokenError::WrongPin {
                tries_left: Some(left)
            })
        );
    }
    assert_eq!(aliases(&tokens).len(), 2);
}

#[test]
fn kzid_blocked_6984() {
    let mut s = id_spec();
    (s.tries, s.max_tries) = (3, 3);
    let emu = backend(s);
    let tokens = Tokens::new(emu.clone(), true);
    for left in [2, 1] {
        assert_eq!(
            tokens.open(READER, TokenKind::KzIdCard, "0000").err(),
            Some(TokenError::WrongPin {
                tries_left: Some(left)
            })
        );
    }
    for pin in ["0000", PIN] {
        assert_eq!(
            tokens.open(READER, TokenKind::KzIdCard, pin).err(),
            Some(TokenError::PinBlocked)
        );
        let last_verify = emu
            .exchanges(READER)
            .into_iter()
            .rfind(|e| e.command.starts_with(&[0x00, 0x20]))
            .unwrap();
        assert_eq!(last_verify.response, [0x69, 0x84]);
    }
}

fn equals_software(spec: CardSpec, alias: &str, name: &str, alg: SigAlg) {
    let tokens = Tokens::new(backend(spec), true);
    let entry = tokens
        .open(READER, TokenKind::KzIdCard, PIN)
        .unwrap()
        .into_iter()
        .find(|e| e.alias == format!("{alias}{TOKEN_ID}"))
        .unwrap();
    assert_eq!(entry.cert, key(name).entry.cert);
    assert_eq!(
        entry.key.sign(alg, b"message").unwrap(),
        software_signature(name, alg, b"message")
    );
}

#[test]
fn kzid_gost512_equals_software() {
    equals_software(id_spec(), "GOST1", KEYS[0], SigAlg::Gost2015_512);
    equals_software(id_spec(), "GOST2", KEYS[1], SigAlg::Gost2015_512);
}

#[test]
fn kzid_rsa_equals_software() {
    equals_software(rsa_spec(), "RSA1", KEYS[2], SigAlg::RsaSha256);
}

#[test]
fn kzid_2020_card_retries_with_low_ref() {
    let mut s = rsa_spec();
    s.id_card_2020 = true;
    let emu = backend(s.clone());
    equals_software(s, "RSA1", KEYS[2], SigAlg::RsaSha256);
    sign_with(
        &emu,
        TokenKind::KzIdCard,
        PIN,
        |s| s.alias.starts_with("RSA1"),
        SigAlg::RsaSha256,
        b"m",
    );
    let mse: Vec<(String, Vec<u8>)> = emu
        .exchanges(READER)
        .into_iter()
        .filter(|e| e.command.starts_with(&[0x00, 0x22, 0x41, 0xA4]))
        .map(|e| (hex(&e.command), e.response))
        .collect();
    assert_eq!(
        mse,
        [
            ("002241A409950140840187800102".to_owned(), vec![0x6A, 0x80]),
            ("002241A409950140840107800102".to_owned(), vec![0x90, 0x00]),
        ]
    );
}

#[test]
fn kzid_t0_get_response_used() {
    let emu = backend(id_spec());
    sign_with(
        &emu,
        TokenKind::KzIdCard,
        PIN,
        |s| s.alias.starts_with("GOST1"),
        SigAlg::Gost2015_512,
        b"m",
    );
    let ex = emu.exchanges(READER);
    assert!(command_starting(&ex, "00C00000").is_some());
    assert!(
        ex.iter().all(|e| e.command.len() <= 5 + 255),
        "short APDUs only"
    );
}

#[test]
fn kzid_shared_ef_pairs_only_matching_key() {
    let tokens = Tokens::new(backend(id_spec()), true);
    assert_eq!(
        aliases(&tokens),
        [format!("GOST1{TOKEN_ID}"), format!("GOST2{TOKEN_ID}")]
    );
    let tokens = Tokens::new(backend(rsa_spec()), true);
    assert_eq!(
        aliases(&tokens),
        [format!("RSA1{TOKEN_ID}"), format!("GOST2{TOKEN_ID}")]
    );
    let emu = backend(id_spec());
    let keys = with_card(&emu, |card| open(card, TokenKind::KzIdCard, PIN).1);
    let listed: Vec<(String, u16, KeyAlg)> =
        keys.into_iter().map(|s| (s.alias, s.id, s.alg)).collect();
    assert_eq!(
        listed,
        [
            (format!("RSA1{TOKEN_ID}"), 0x87, KeyAlg::Rsa),
            (format!("RSA2{TOKEN_ID}"), 0x88, KeyAlg::Rsa),
            (format!("GOST1{TOKEN_ID}"), 0x01, KeyAlg::Gost2015_512),
            (format!("GOST2{TOKEN_ID}"), 0x02, KeyAlg::Gost2015_512),
        ]
    );
}

#[test]
fn kzid_public_info_without_pin() {
    let emu = backend(id_spec());
    let tokens = Tokens::new(emu.clone(), true);
    let info = tokens.id_card_info(READER).unwrap();
    assert_eq!(info, holder());
    assert_eq!(info.full_name(), "ТЕСТОВ ТЕСТ ТЕСТОВИЧ");
    assert_eq!(verifies(&emu), 0, "no PIN");

    let mut s = id_spec();
    s.id_card.as_mut().unwrap().middle_name = None;
    let tokens = Tokens::new(backend(s), true);
    assert_eq!(
        tokens.id_card_info(READER).unwrap().full_name(),
        "ТЕСТОВ ТЕСТ"
    );

    let kaztoken = Tokens::new(backend(spec(TokenKind::Kaztoken, "123456", &[])), true);
    assert_eq!(kaztoken.id_card_info(READER), Err(TokenError::WrongCard));
    let off = Tokens::new(emu, false);
    assert_eq!(off.id_card_info(READER), Err(TokenError::Disabled));
}

/// The emulated ID card over T=1, with RSA public keys of 1024 bits.
struct ShortModulus(Box<dyn SoftCard>);

impl SoftCard for ShortModulus {
    fn atr(&self) -> Vec<u8> {
        self.0.atr()
    }

    fn protocol(&self) -> Protocol {
        self.0.protocol()
    }

    fn process(&mut self, apdu: &[u8]) -> Vec<u8> {
        let mut resp = self.0.process(apdu);
        if apdu.starts_with(&[0x00, 0xCB, 0x3F, 0xFF, 0x0B, 0x4D, 0x09, 0xFF, 0xA0])
            && resp.len() > 2
        {
            resp.drain(15 + 128..resp.len() - 2);
        }
        resp
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

#[test]
fn kzid_rsa_modulus_must_be_2048() {
    let mut s = rsa_spec();
    s.protocol = Protocol::T1;
    s.t0_quirks = false;
    let emu = backend_with(Box::new(ShortModulus(card(s))));
    with_card(&emu, |card| {
        let mut driver = open_driver(TokenKind::KzIdCard, card).unwrap();
        let keys = driver.keys(card).unwrap();
        assert!(keys.iter().all(|k| k.alg != KeyAlg::Rsa), "{keys:?}");
        let rsa = KeySlot {
            alias: format!("RSA1{TOKEN_ID}"),
            id: 0x87,
            alg: KeyAlg::Rsa,
        };
        assert!(matches!(
            driver.public_key(card, &rsa),
            Err(TokenError::Malformed(_))
        ));
    });
    // Keys of the other algorithm still open.
    let tokens = Tokens::new(emu, true);
    assert_eq!(
        tokens
            .open(READER, TokenKind::KzIdCard, PIN)
            .unwrap()
            .into_iter()
            .map(|e| e.alias)
            .collect::<Vec<_>>(),
        [format!("GOST2{TOKEN_ID}")]
    );
}
