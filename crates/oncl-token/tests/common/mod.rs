//! Helpers of the driver and service tests: emulated cards with synthetic keys, APDU
//! transcripts against golden files, software signatures to compare with.

#![allow(dead_code, reason = "each test binary uses a part")]

use hex_literal::hex;
use oncl_pki::key::{PrivateKey, SigAlg, digest_info};
use oncl_testkit::synthetic;
use oncl_token::TokenKind;
use oncl_token::backend::{Backend, Connection};
use oncl_token::card::Card;
use oncl_token::drivers::{Driver, KeySlot, open_driver};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, Exchange, SoftCard, card};
use std::path::PathBuf;
use std::sync::Arc;

/// The emulator's fixed GOST nonce in the tests.
pub const K: [u8; 16] = hex!("0123456789ABCDEF0123456789ABCDEF");

pub const READER: &str = "OpenNCALayer Emulated Reader 0";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn key(name: &str) -> EmuKey {
    let k = synthetic(name);
    EmuKey::load(&k.path, &k.password).unwrap()
}

/// A card of `kind` with the synthetic keys `names` and the fixed nonce [`K`].
pub fn spec(kind: TokenKind, pin: &str, names: &[&str]) -> CardSpec {
    let mut spec = CardSpec::new(kind, pin, names.iter().map(|n| key(n)).collect());
    spec.fixed_k = Some(K.to_vec());
    spec
}

/// An emulator with `card` in [`READER`].
pub fn backend_with(card: Box<dyn SoftCard>) -> Arc<EmulatorBackend> {
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER);
    emu.insert(READER, card);
    emu
}

pub fn backend(spec: CardSpec) -> Arc<EmulatorBackend> {
    backend_with(card(spec))
}

/// Runs `f` on the card in [`READER`], in a transaction.
pub fn with_card<T>(emu: &EmulatorBackend, f: impl FnOnce(&mut Card<'_>) -> T) -> T {
    let mut conn: Box<dyn Connection> = emu.connect(READER).unwrap();
    conn.begin_transaction().unwrap();
    let out = {
        let mut card = Card::new(&mut *conn, false);
        f(&mut card)
    };
    conn.end_transaction().unwrap();
    out
}

/// Opens the token, verifies `pin` and lists the keys.
pub fn open(card: &mut Card<'_>, kind: TokenKind, pin: &str) -> (Box<dyn Driver>, Vec<KeySlot>) {
    let mut driver = open_driver(kind, card).unwrap();
    driver.check_pin(pin).unwrap();
    driver.verify_pin(card, pin).unwrap();
    let keys = driver.keys(card).unwrap();
    (driver, keys)
}

/// What the driver signs for `message`: the hash, or the `DigestInfo` for RSA.
pub fn to_sign(alg: SigAlg, message: &[u8]) -> Vec<u8> {
    let digest = alg.digest(message);
    match alg {
        SigAlg::RsaSha256 | SigAlg::RsaSha1 => digest_info(alg, &digest).unwrap(),
        SigAlg::Gost2004 | SigAlg::Gost2015_512 => digest,
    }
}

/// The software signature of `message` with the synthetic key `name`: GOST with [`K`].
pub fn software_signature(name: &str, alg: SigAlg, message: &[u8]) -> Vec<u8> {
    let entry = key(name).entry;
    match &entry.key {
        PrivateKey::Gost(k) => k.sign_digest_with_k(&alg.digest(message), &K).unwrap(),
        _ => entry.key.sign(alg, message).unwrap(),
    }
}

/// Signs `message` with the slot whose alias is the synthetic key `name`'s, on a fresh
/// connection.
pub fn sign_with(
    emu: &EmulatorBackend,
    kind: TokenKind,
    pin: &str,
    slot: impl Fn(&KeySlot) -> bool,
    alg: SigAlg,
    message: &[u8],
) -> Vec<u8> {
    with_card(emu, |card| {
        let (mut driver, keys) = open(card, kind, pin);
        let slot = keys
            .iter()
            .find(|s| slot(s))
            .expect("the slot is on the card");
        let sig = driver
            .sign(card, slot, alg, &to_sign(alg, message))
            .unwrap();
        driver.logout(card).unwrap();
        sig
    })
}

/// `> <command>` / `< <SW> +<N> bytes` lines of a transcript.
pub fn transcript(exchanges: &[Exchange]) -> String {
    let mut out = String::new();
    for e in exchanges {
        let (data, sw) = e.response.split_at(e.response.len() - 2);
        out.push_str(&format!(
            "> {}\n< {} +{} bytes\n",
            hex(&e.command),
            hex(sw),
            data.len()
        ));
    }
    out
}

/// The first command that starts with `prefix` (hex).
pub fn command_starting(exchanges: &[Exchange], prefix: &str) -> Option<String> {
    exchanges
        .iter()
        .map(|e| hex(&e.command))
        .find(|c| c.starts_with(prefix))
}

/// Compares `text` with `tests/golden/<name>.apdu`; `ONCL_BLESS=1` rewrites the file.
pub fn golden(name: &str, text: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.apdu"));
    if std::env::var_os("ONCL_BLESS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; run with ONCL_BLESS=1 and review the file",
            path.display()
        )
    });
    assert_eq!(
        text.replace("\r\n", "\n"),
        expected.replace("\r\n", "\n"),
        "transcript differs from {}",
        path.display()
    );
}
