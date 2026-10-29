//! The real PC/SC backend against an emulated Kaztoken behind vpcd (pcscd with
//! vsmartcard's virtual reader, the card served by `cargo xtask token-emu`). Runs only with
//! `ONCL_TOKEN_VPCD=1`; elsewhere every test is skipped.

use oncl_pki::cms::{self, SignOptions};
use oncl_testkit::workspace_root;
use oncl_token::backend::Backend;
use oncl_token::emulator::read_config;
use oncl_token::{PcscBackend, TokenKind, Tokens};
use std::sync::Arc;
use time::macros::datetime;

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

fn virtual_reader() -> String {
    PcscBackend::new()
        .readers()
        .unwrap()
        .into_iter()
        .find(|r| r.name.starts_with("Virtual PCD") && r.atr.is_some())
        .expect("a vpcd reader with a card")
        .name
}

#[test]
fn pcsc_backend_sees_virtual_reader() {
    if !enabled() {
        return;
    }
    let readers = PcscBackend::new().readers().unwrap();
    let reader = readers
        .iter()
        .find(|r| r.name.starts_with("Virtual PCD") && r.atr.is_some())
        .unwrap_or_else(|| panic!("no vpcd reader with a card in {readers:?}"));
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
        .open(&virtual_reader(), TokenKind::Kaztoken, &pin)
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
