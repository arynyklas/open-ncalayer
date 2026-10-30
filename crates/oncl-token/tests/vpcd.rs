//! The real PC/SC backend against an emulated Kaztoken behind vpcd (pcscd with
//! vsmartcard's virtual reader, the card served by `cargo xtask token-emu`). Runs only with
//! `ONCL_TOKEN_VPCD=1`; elsewhere every test is skipped.

use oncl_pki::cms::{self, SignOptions};
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_testkit::workspace_root;
use oncl_token::backend::{Backend, ReaderState};
use oncl_token::emulator::read_config;
use oncl_token::{PcscBackend, TokenKind, Tokens};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::macros::datetime;

/// Longest wait for the emulated card to appear in vpcd's reader.
const CARD_WAIT: Duration = Duration::from_secs(15);

fn enabled() -> bool {
    let on = std::env::var_os("ONCL_TOKEN_VPCD").is_some_and(|v| v == "1");
    if !on {
        eprintln!("skipped: ONCL_TOKEN_VPCD=1 runs the tests against vpcd");
    }
    on
}

fn config() -> (String, String, usize) {
    let text = std::fs::read_to_string(
        workspace_root().join("crates/oncl-token/tests/vpcd-kaztoken.toml"),
    )
    .unwrap();
    let reader = read_config(&text, &workspace_root())
        .unwrap()
        .into_iter()
        .find_map(|r| r.card)
        .unwrap();
    (text, reader.pin, reader.keys.len())
}

/// The vpcd reader once the emulated card is in it: the card connects to vpcd some time
/// after pcscd starts, so the readers are polled for up to [`CARD_WAIT`].
fn virtual_reader() -> ReaderState {
    let start = Instant::now();
    loop {
        let readers = PcscBackend::new().readers();
        if let Some(reader) = readers.as_ref().ok().and_then(|readers| {
            readers
                .iter()
                .find(|r| r.name.starts_with("Virtual PCD") && r.atr.is_some())
        }) {
            return reader.clone();
        }
        assert!(
            start.elapsed() < CARD_WAIT,
            "no vpcd reader with a card after {CARD_WAIT:?}: {readers:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn pcsc_backend_sees_virtual_reader() {
    if !enabled() {
        return;
    }
    let reader = virtual_reader();
    assert_eq!(
        TokenKind::from_atr(reader.atr.as_deref().unwrap()),
        Some(TokenKind::Kaztoken)
    );
    let tokens = Tokens::new(Arc::new(PcscBackend::new()), true);
    assert!(
        tokens
            .scan()
            .present
            .iter()
            .any(|p| p.kind == TokenKind::Kaztoken && p.reader == reader.name)
    );
}

#[test]
fn pcsc_backend_open_and_sign_kaztoken() {
    if !enabled() {
        return;
    }
    let (_, pin, keys) = config();
    let tokens = Tokens::new(Arc::new(PcscBackend::new()), true);
    let entries = tokens
        .open(&virtual_reader().name, TokenKind::Kaztoken, &pin)
        .unwrap();
    assert_eq!(entries.len(), keys);
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: datetime!(2026-03-01 10:20:30 UTC),
    };
    for entry in entries {
        let signed = cms::sign(&entry, b"data", &opts).unwrap();
        let signers = cms::verify(&signed, None).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].cert, entry.cert);
    }
}

#[test]
fn pcsc_backend_overlapping_signatures() {
    if !enabled() {
        return;
    }
    let (_, pin, _) = config();
    let tokens = Tokens::new(Arc::new(PcscBackend::new()), true);
    let entries = tokens
        .open(&virtual_reader().name, TokenKind::Kaztoken, &pin)
        .unwrap();
    assert!(entries.len() >= 2, "two keys to sign with");
    // The first signature to end resets the card under the other's connection.
    let threads: Vec<_> = entries
        .into_iter()
        .take(2)
        .map(|entry| {
            std::thread::spawn(move || {
                let alg = match entry.key.alg() {
                    KeyAlg::Gost2004 => SigAlg::Gost2004,
                    KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
                    KeyAlg::Rsa => SigAlg::RsaSha256,
                };
                entry.key.sign(alg, b"data")
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap().unwrap();
    }
}
