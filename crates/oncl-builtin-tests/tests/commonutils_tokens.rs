//! `kz.gov.pki.knca.commonUtils` with hardware tokens, on emulated cards: `getActiveTokens`,
//! signing in the first reader holding a token, PIN errors in the dialog.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{OpenError, ReaderEntry, StorageKind};
use oncl_builtin_tests::commonutils::{CommonUtils, MODULE_NAME};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::verify;
use oncl_pki::pkcs12::load;
use oncl_pki::pkix::{CaSet, build_path, validation_time};
use oncl_pki::tsp::{MockTsa, verify_token};
use oncl_pki::xmldsig;
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{read, synthetic, synthetic_cert};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};
use time::OffsetDateTime;

const R0: &str = "OpenNCALayer Emulated Reader 0";
const R1: &str = "OpenNCALayer Emulated Reader 1";
const KAZTOKEN: StorageKind = StorageKind::Token("AKKaztokenStore");
const PIN: &str = "123456";

fn key(name: &str) -> EmuKey {
    let k = synthetic(name);
    EmuKey::load(&k.path, &k.password).unwrap()
}

fn spec(kind: TokenKind) -> CardSpec {
    CardSpec::new(kind, PIN, vec![key("user-gost2015-sign")])
}

/// An emulator with `cards` in the readers R0, R1, … in order.
fn emulator(cards: Vec<CardSpec>) -> Arc<EmulatorBackend> {
    let emu = Arc::new(EmulatorBackend::new());
    for (i, spec) in cards.into_iter().enumerate() {
        let reader = format!("OpenNCALayer Emulated Reader {i}");
        emu.add_reader(&reader);
        emu.insert(&reader, card(spec));
    }
    emu
}

fn synthetic_cas() -> CaSet {
    CaSet::new(
        [
            "root-gost2015",
            "root-gost2004",
            "root-rsa",
            "inter-gost2015",
        ]
        .into_iter()
        .map(|name| -> Certificate { cert::parse(&synthetic_cert(name)).unwrap() })
        .collect(),
    )
}

struct Setup {
    cu: CommonUtils,
    prompter: Arc<ScriptedPrompter>,
    tsa: Arc<MockTsa>,
}

fn setup(emu: &Arc<EmulatorBackend>, enabled: bool, steps: Vec<Step>) -> Setup {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa_key = synthetic("tsa-gost2015");
    let tsa = Arc::new(MockTsa::new(
        load(&read(&tsa_key.path), &tsa_key.password)
            .unwrap()
            .swap_remove(0),
    ));
    let cu = CommonUtils::new(prompter.clone(), tsa.clone())
        .with_cas(synthetic_cas())
        .with_tokens(Tokens::new(emu.clone(), enabled));
    Setup { cu, prompter, tsa }
}

fn token(reader: &str, pin: &str) -> Step {
    Step::Token {
        storage: KAZTOKEN,
        reader: reader.to_owned(),
        pin: pin.to_owned(),
    }
}

fn call(cu: &CommonUtils, method: &str, args: Value) -> Value {
    let request = json!({"module": MODULE_NAME, "method": method, "args": args});
    let add_info = AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    };
    let reply = cu.process(&request.to_string(), &add_info);
    serde_json::from_str(reply.text().expect("a text reply")).unwrap()
}

fn ok(reply: &Value) -> &Value {
    assert_eq!(reply["code"], "200", "{reply}");
    &reply["responseObject"]
}

fn failed(reply: &Value) -> &str {
    assert_eq!(reply["code"], "500", "{reply}");
    reply["message"].as_str().unwrap()
}

fn unb64(reply: &Value) -> Vec<u8> {
    STANDARD.decode(ok(reply).as_str().unwrap()).unwrap()
}

#[test]
fn active_tokens_lists_present_kinds_in_kalkan_order() {
    let emu = emulator(vec![spec(TokenKind::AKey), spec(TokenKind::Kaztoken)]);
    let s = setup(&emu, true, vec![]);
    assert_eq!(
        ok(&call(&s.cu, "getActiveTokens", json!([]))),
        &json!(["AKKaztokenStore", "AKAKEYStore"])
    );
    // A reader without a card, or with an unknown card, adds nothing.
    emu.remove(R1);
    assert_eq!(
        ok(&call(&s.cu, "getActiveTokens", json!([]))),
        &json!(["AKAKEYStore"])
    );
    assert!(s.prompter.storage_prompts().is_empty());
}

#[test]
fn active_tokens_empty_when_disabled_or_no_service() {
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let s = setup(&emu, false, vec![]);
    assert_eq!(ok(&call(&s.cu, "getActiveTokens", json!([]))), &json!([]));
    let s = setup(&emu, true, vec![]);
    emu.set_service(false);
    assert_eq!(ok(&call(&s.cu, "getActiveTokens", json!([]))), &json!([]));
    assert!(emu.exchanges(R0).is_empty());
}

#[test]
fn token_storage_without_reader_is_storage_empty() {
    let emu = emulator(vec![spec(TokenKind::AKey)]);
    for enabled in [true, false] {
        let s = setup(&emu, enabled, vec![token(R0, PIN)]);
        let reply = call(&s.cu, "getKeyInfo", json!(["AKKaztokenStore"]));
        assert_eq!(failed(&reply), "storage.empty");
        assert!(s.prompter.storage_prompts().is_empty());
    }
    // With support off a connected token of the family is not seen either.
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let s = setup(&emu, false, vec![]);
    let reply = call(&s.cu, "getKeyInfo", json!(["AKKaztokenStore"]));
    assert_eq!(failed(&reply), "storage.empty");
}

#[test]
fn sign_xml_with_kaztoken_verifies() {
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let s = setup(&emu, true, vec![token(R0, PIN), Step::Key(0)]);
    let reply = call(
        &s.cu,
        "signXml",
        json!([
            "AKKaztokenStore",
            "SIGNATURE",
            "<root><a>x</a></root>",
            "",
            ""
        ]),
    );
    let signed = ok(&reply).as_str().unwrap();
    assert_eq!(xmldsig::verify(signed.as_bytes()).unwrap().len(), 1);
    let prompt = &s.prompter.storage_prompts()[0];
    assert_eq!(prompt.storages, [KAZTOKEN]);
    assert_eq!(
        prompt.tokens.as_ref().unwrap().current(),
        (
            vec![ReaderEntry {
                storage: KAZTOKEN,
                reader: R0.to_owned()
            }],
            None
        )
    );
}

#[test]
fn create_cades_with_kaztoken_verifies() {
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let s = setup(&emu, true, vec![token(R0, PIN), Step::Key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!([
            "AKKaztokenStore",
            "SIGNATURE",
            STANDARD.encode(b"doc"),
            true
        ]),
    );
    let signers = verify(&unb64(&reply), None).unwrap();
    assert_eq!(signers.len(), 1);

    // With a time-stamp from the TSA.
    let s = setup(&emu, true, vec![token(R0, PIN), Step::Key(0)]);
    let reply = call(
        &s.cu,
        "createCMSSignatureFromBase64",
        json!(["AKKaztokenStore", "", STANDARD.encode(b"doc"), false]),
    );
    let signers = verify(&unb64(&reply), Some(b"doc")).unwrap();
    verify_token(signers[0].timestamp_token.as_ref().unwrap()).unwrap();
    assert_eq!(s.tsa.calls().len(), 1);
}

#[test]
fn first_reader_is_used() {
    let mut second = spec(TokenKind::Kaztoken);
    second.serial = [9; 8];
    let emu = emulator(vec![spec(TokenKind::Kaztoken), second]);
    let s = setup(&emu, true, vec![token(R0, PIN), Step::Key(0)]);
    let reply = call(
        &s.cu,
        "signXml",
        json!(["AKKaztokenStore", "", "<a>1</a>", "", ""]),
    );
    ok(&reply);
    assert!(!emu.exchanges(R0).is_empty());
    assert!(
        emu.exchanges(R1).is_empty(),
        "the second token is not touched"
    );
    let (entries, _) = s.prompter.storage_prompts()[0]
        .tokens
        .as_ref()
        .unwrap()
        .current();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].reader, R0);
}

#[test]
fn wrong_pin_then_cancel_is_action_canceled() {
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let s = setup(&emu, true, vec![token(R0, "000000"), Step::CancelStorage]);
    let reply = call(
        &s.cu,
        "signXml",
        json!(["AKKaztokenStore", "", "<a>1</a>", "", ""]),
    );
    assert_eq!(failed(&reply), "action.canceled");
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(
        prompts[1].error,
        Some(OpenError::WrongPin {
            tries_left: Some(9)
        })
    );
    assert_eq!(prompts[1].chosen, Some(KAZTOKEN));
    assert_eq!(prompts[1].reader.as_deref(), Some(R0));
    assert_eq!(prompts[1].recent_path, None);
}

#[test]
fn card_removed_mid_sign_is_500() {
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let (opened, removed) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
    let s = setup(
        &emu,
        true,
        vec![
            token(R0, PIN),
            Step::Wait(opened.clone()),
            Step::Wait(removed.clone()),
            Step::Key(0),
        ],
    );
    let cu = Arc::new(s.cu);
    let running = std::thread::spawn({
        let cu = cu.clone();
        move || {
            call(
                &cu,
                "signXml",
                json!(["AKKaztokenStore", "", "<a>1</a>", "", ""]),
            )
        }
    });
    // The token is open and the key dialog is up: the card goes during the signature.
    opened.wait();
    emu.remove_after(R0, 2);
    removed.wait();
    let reply = running.join().unwrap();
    assert!(failed(&reply).contains("token"), "{reply}");
    assert_eq!(
        ok(&call(&cu, "getActiveTokens", json!([]))),
        &json!([]),
        "the card is gone"
    );
}

/// commonUtils from end to end on an emulated Kaztoken, trusting the synthetic roots as
/// these tests do (`with_cas`): the connected token, its certificate, a wrong PIN and the
/// right one in the dialog, a CAdES whose signer chains to the synthetic root, its
/// time-stamp, and an XML signature by the same key. The wrong PIN cost one try, which
/// the right one restored.
#[test]
fn token_signing_end_to_end_against_synthetic_root() {
    let emu = emulator(vec![spec(TokenKind::Kaztoken)]);
    let s = setup(
        &emu,
        true,
        vec![
            token(R0, PIN),
            Step::Key(0),
            token(R0, "000000"),
            token(R0, PIN),
            Step::Key(0),
            token(R0, PIN),
            Step::Key(0),
            token(R0, PIN),
            Step::Key(0),
        ],
    );
    let k = synthetic("user-gost2015-sign");
    let cert = load(&read(&k.path), &k.password)
        .unwrap()
        .swap_remove(0)
        .cert;

    assert_eq!(
        ok(&call(&s.cu, "getActiveTokens", json!([]))),
        &json!(["AKKaztokenStore"])
    );
    let info = call(&s.cu, "getKeyInfo", json!(["AKKaztokenStore"]));
    assert_eq!(ok(&info)["subjectCn"], "ТЕСТОВ ТЕСТ", "{info}");
    assert_eq!(
        ok(&info)["serialNumber"],
        oncl_pki::info::cert_info(&cert).serial_hex
    );

    let cades = unb64(&call(
        &s.cu,
        "createCAdESFromBase64",
        json!([
            "AKKaztokenStore",
            "SIGNATURE",
            STANDARD.encode(b"doc"),
            true
        ]),
    ));
    let prompts = s.prompter.storage_prompts();
    assert_eq!(
        prompts[2].error,
        Some(OpenError::WrongPin {
            tries_left: Some(9)
        })
    );
    let stamped = unb64(&call(
        &s.cu,
        "applyCAdEST",
        json!(["AKKaztokenStore", "SIGNATURE", STANDARD.encode(&cades)]),
    ));
    let signers = verify(&stamped, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].cert, cert);
    verify_token(signers[0].timestamp_token.as_ref().unwrap()).unwrap();
    assert_eq!(s.tsa.calls().len(), 1);
    let path = build_path(
        &signers[0].cert,
        &synthetic_cas(),
        validation_time(&signers[0].cert, OffsetDateTime::now_utc()),
    )
    .unwrap();
    let root = cert::parse(&synthetic_cert("root-gost2015")).unwrap();
    assert_eq!(path.last(), Some(&root));

    let signed = call(
        &s.cu,
        "signXml",
        json!([
            "AKKaztokenStore",
            "SIGNATURE",
            "<root><a>x</a></root>",
            "",
            ""
        ]),
    );
    let xml_signers = xmldsig::verify(ok(&signed).as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(xml_signers[0].cert, cert);

    assert_eq!(
        Tokens::new(emu.clone(), true).pin_tries(R0, TokenKind::Kaztoken),
        Ok(Some(10))
    );
}
