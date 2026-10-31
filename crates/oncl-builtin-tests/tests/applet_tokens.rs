//! `kz.gov.pki.knca.applet.Applet` with hardware tokens, on emulated cards: reader lists,
//! the reader dialog, ID card details, XML signing with the PIN and its try count, and the
//! writes it refuses without a command to the card.

use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{OpenError, ReaderEntry, StorageKind};
use oncl_builtin_tests::applet::Applet;
use oncl_pki::xmldsig;
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::synthetic;
use oncl_token::backend::Backend;
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{IdCardInfo, TokenKind, Tokens};
use serde_json::{Value, json};
use std::sync::Arc;

const R0: &str = "OpenNCALayer Emulated Reader 0";
const R1: &str = "OpenNCALayer Emulated Reader 1";
const KAZTOKEN: StorageKind = StorageKind::Token("AKKaztokenStore");
const PIN: &str = "123456";
const GOST2004: &str = "1.2.398.3.10.1.1.1.2";

fn key(name: &str) -> EmuKey {
    let k = synthetic(name);
    EmuKey::load(&k.path, &k.password).unwrap()
}

fn kaztoken() -> CardSpec {
    CardSpec::new(TokenKind::Kaztoken, PIN, vec![key("user-gost2015-sign")])
}

fn etoken72k() -> CardSpec {
    CardSpec::new(TokenKind::EToken72K, PIN, vec![key("user-gost2004-sign")])
}

fn id_card() -> CardSpec {
    let mut spec = CardSpec::new(
        TokenKind::KzIdCard,
        "1234",
        vec![key("user-gost2015-auth"), key("user-gost2015-sign")],
    );
    spec.id_card = Some(IdCardInfo {
        iin: "123456789012".to_owned(),
        last_name: "ТЕСТОВ".to_owned(),
        first_name: "ТЕСТ".to_owned(),
        middle_name: Some("ТЕСТОВИЧ".to_owned()),
    });
    spec
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

fn setup(
    emu: &Arc<EmulatorBackend>,
    enabled: bool,
    steps: Vec<Step>,
) -> (Applet, Arc<ScriptedPrompter>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let applet = Applet::new(prompter.clone()).with_tokens(Tokens::new(emu.clone(), enabled));
    (applet, prompter)
}

fn call(a: &Applet, method: &str, args: Value) -> Value {
    let request = json!({"method": method, "args": args});
    let add_info = AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    };
    let reply = a.process(&request.to_string(), &add_info);
    serde_json::from_str(reply.text().expect("a text reply")).unwrap()
}

/// The reply has only `errorCode`, equal to `expected`.
fn assert_code(reply: &Value, expected: &str) {
    assert_eq!(reply, &json!({"errorCode": expected}));
}

fn token(reader: &str, pin: &str) -> Step {
    Step::Token {
        storage: KAZTOKEN,
        reader: reader.to_owned(),
        pin: pin.to_owned(),
    }
}

fn all_exchanges(emu: &EmulatorBackend, readers: &[&str]) -> usize {
    readers.iter().map(|r| emu.exchanges(r).len()).sum()
}

#[test]
fn load_slot_list_lists_readers_joined() {
    let emu = emulator(vec![kaztoken(), kaztoken()]);
    let (a, _) = setup(&emu, true, vec![]);
    assert_eq!(
        call(&a, "loadSlotList", json!(["AKKaztokenStore"])),
        json!({"errorCode": "NONE", "result": format!("{R0}<:>{R1}")})
    );
    emu.remove(R0);
    assert_eq!(
        call(&a, "loadSlotList", json!(["AKKaztokenStore"])),
        json!({"errorCode": "NONE", "result": R1})
    );
}

#[test]
fn load_slot_list_empty_slot() {
    let emu = emulator(vec![kaztoken()]);
    let (a, _) = setup(&emu, true, vec![]);
    for storage in ["AKAKEYStore", "AKKZIDCardStore"] {
        assert_code(&call(&a, "loadSlotList", json!([storage])), "EMPTY_SLOT");
    }
    // No smart card service: no readers, no error.
    emu.set_service(false);
    for storage in [json!("AKKaztokenStore"), json!("PKCS12"), Value::Null] {
        assert_code(&call(&a, "loadSlotList", json!([storage])), "EMPTY_SLOT");
    }
}

#[test]
fn load_slot_list_unknown_smartcard_for_pkcs12_with_card() {
    let emu = emulator(vec![kaztoken()]);
    let (a, _) = setup(&emu, true, vec![]);
    for storage in [json!("PKCS12"), json!("JKS"), json!("nope"), Value::Null] {
        assert_code(
            &call(&a, "loadSlotList", json!([storage])),
            "UNKNOWN_SMARTCARD",
        );
    }
    emu.remove(R0);
    assert_code(&call(&a, "loadSlotList", json!(["PKCS12"])), "EMPTY_SLOT");
}

#[test]
fn load_slot_list_unchanged_when_disabled() {
    let emu = emulator(vec![kaztoken()]);
    let (a, _) = setup(&emu, false, vec![]);
    for storage in [json!("AKKaztokenStore"), json!("PKCS12"), Value::Null] {
        assert_code(&call(&a, "loadSlotList", json!([storage])), "EMPTY_SLOT");
    }
    assert!(emu.exchanges(R0).is_empty());
}

#[test]
fn browse_key_store_returns_chosen_reader() {
    let emu = emulator(vec![kaztoken(), kaztoken()]);
    let (a, prompter) = setup(&emu, true, vec![Step::Reader(R1.to_owned())]);
    assert_eq!(
        call(&a, "browseKeyStore", json!(["AKKaztokenStore", null, null])),
        json!({"errorCode": "NONE", "result": R1})
    );
    let prompts = prompter.reader_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].storage, KAZTOKEN);
    assert_eq!(prompts[0].origin, "https://x.kz");
    let entry = |reader: &str| ReaderEntry {
        storage: KAZTOKEN,
        reader: reader.to_owned(),
    };
    assert_eq!(
        prompts[0].readers.current(),
        (vec![entry(R0), entry(R1)], None)
    );
    assert!(prompter.file_prompts().is_empty());
}

#[test]
fn browse_key_store_cancel() {
    // Without a token of the family the dialog opens all the same.
    let emu = emulator(vec![kaztoken()]);
    let (a, prompter) = setup(&emu, true, vec![Step::CancelReader]);
    assert_code(
        &call(&a, "browseKeyStore", json!(["AKAKEYStore", null, null])),
        "TOKEN_CHOOSE_CANCEL",
    );
    assert_eq!(prompter.reader_prompts().len(), 1);
    assert!(
        prompter.reader_prompts()[0]
            .readers
            .readers_of(StorageKind::Token("AKAKEYStore"))
            .is_empty()
    );
    // The cloud storage has no reader.
    assert_code(
        &call(
            &a,
            "browseKeyStore",
            json!(["ABCloudServiceStore", null, null]),
        ),
        "TOKEN_CHOOSE_CANCEL",
    );
    assert_eq!(prompter.reader_prompts().len(), 1);
}

#[test]
fn public_part_info_from_id_card() {
    let emu = emulator(vec![id_card()]);
    let (a, _) = setup(&emu, true, vec![]);
    assert_eq!(
        call(&a, "getPublicPartInfo", json!([R0])),
        json!({"errorCode": "NONE", "result": "IIN123456789012 ТЕСТОВ ТЕСТ ТЕСТОВИЧ"})
    );
    assert!(
        !emu.exchanges(R0)
            .iter()
            .any(|e| e.command.starts_with(&[0x00, 0x20])),
        "no VERIFY"
    );
}

#[test]
fn public_part_info_for_kaztoken_is_exception() {
    let emu = emulator(vec![kaztoken()]);
    let (a, _) = setup(&emu, true, vec![]);
    // Another application's connection to the token.
    let mut other = emu.connect(R0).unwrap();
    for terminal in [json!(R0), json!("no such reader"), Value::Null] {
        assert_code(
            &call(&a, "getPublicPartInfo", json!([terminal])),
            "GETPUBLICPART_EXCEPTION",
        );
    }
    assert_eq!(
        other.begin_transaction(),
        Ok(()),
        "the token was neither connected to nor reset"
    );
}

#[test]
fn sign_xml_with_token_verifies() {
    let emu = emulator(vec![kaztoken(), kaztoken()]);
    let (a, prompter) = setup(&emu, true, vec![token(R1, PIN), Step::Key(0)]);
    let reply = call(
        &a,
        "signXml",
        json!(["AKKaztokenStore", R1, "SIGN", "<root><a>x</a></root>"]),
    );
    assert_eq!(reply["errorCode"], "NONE", "{reply}");
    let signed = reply["result"].as_str().unwrap();
    assert_eq!(xmldsig::verify(signed.as_bytes()).unwrap().len(), 1);
    assert_eq!(
        reply["secondResult"],
        json!(prompter.key_prompts()[0].candidates[0].alias)
    );
    let prompt = &prompter.storage_prompts()[0];
    assert_eq!(prompt.storages, [KAZTOKEN]);
    assert_eq!(prompt.recent_path, None, "a reader is no path");
    let (entries, _) = prompt.tokens.as_ref().unwrap().current();
    let readers: Vec<&str> = entries.iter().map(|e| e.reader.as_str()).collect();
    assert_eq!(readers, [R1, R0], "the container's reader first");
    assert!(emu.exchanges(R0).is_empty());
}

#[test]
fn sign_xml_pin_checks_come_first() {
    let emu = emulator(vec![kaztoken()]);
    let (a, prompter) = setup(
        &emu,
        true,
        vec![token(R0, ""), token(R0, PIN), Step::CancelStorage],
    );
    assert_code(
        &call(
            &a,
            "signXml",
            json!(["AKKaztokenStore", R0, "INSIGN", "<a/>"]),
        ),
        "SIGN_CANCEL",
    );
    let errors: Vec<_> = prompter.storage_prompts().iter().map(|p| p.error).collect();
    assert_eq!(
        errors,
        [
            None,
            Some(OpenError::EmptyPassword),
            Some(OpenError::InnerPasswordPolicy)
        ]
    );
    assert!(emu.exchanges(R0).is_empty(), "no command for a refused PIN");
}

#[test]
fn sign_xml_wrong_pin_sets_try_count() {
    let emu = emulator(vec![kaztoken(), etoken72k()]);
    let (a, prompter) = setup(
        &emu,
        true,
        vec![
            token(R0, "000000"),
            Step::CancelStorage,
            Step::Token {
                storage: StorageKind::Token("AKEToken72KStore"),
                reader: R1.to_owned(),
                pin: "000000".to_owned(),
            },
            Step::CancelStorage,
        ],
    );
    assert_code(
        &call(
            &a,
            "signXml",
            json!(["AKKaztokenStore", R0, "SIGN", "<a/>"]),
        ),
        "SIGN_CANCEL",
    );
    assert_eq!(
        call(&a, "getTryCount", json!([])),
        json!({"errorCode": "NONE", "result": 9})
    );
    let prompts = prompter.storage_prompts();
    assert_eq!(
        prompts[1].error,
        Some(OpenError::WrongPin {
            tries_left: Some(9)
        })
    );
    assert_eq!(prompts[1].reader.as_deref(), Some(R0));

    assert_code(
        &call(
            &a,
            "signXml",
            json!(["AKEToken72KStore", R1, "SIGN", "<a/>"]),
        ),
        "SIGN_CANCEL",
    );
    assert_eq!(
        call(&a, "getTryCount", json!([])),
        json!({"errorCode": "NONE", "result": -1})
    );
}

#[test]
fn sign_xml_blocked_pin_is_not_tried_again() {
    let commands = |answers: usize| {
        let mut spec = kaztoken();
        spec.tries = 0;
        let emu = emulator(vec![spec]);
        let mut steps = vec![token(R0, PIN); answers];
        steps.push(Step::CancelStorage);
        let (a, prompter) = setup(&emu, true, steps);
        assert_code(
            &call(
                &a,
                "signXml",
                json!(["AKKaztokenStore", R0, "SIGN", "<a/>"]),
            ),
            "SIGN_CANCEL",
        );
        let prompts = prompter.storage_prompts();
        assert!(
            prompts[1..]
                .iter()
                .all(|p| p.error == Some(OpenError::PinBlocked))
        );
        emu.exchanges(R0).len()
    };
    assert_eq!(commands(1), commands(3));
}

#[test]
fn sign_xml_without_reader_is_empty_slot() {
    let emu = emulator(vec![kaztoken()]);
    let (a, prompter) = setup(&emu, true, vec![]);
    assert_code(
        &call(&a, "signXml", json!(["AKAKEYStore", "c", "SIGN", "<a/>"])),
        "EMPTY_SLOT",
    );
    assert!(prompter.storage_prompts().is_empty());
}

/// The methods that take a password or PIN from the page answer without a command to a
/// connected token: a page's PIN never reaches the card through the Applet.
#[test]
fn write_methods_refuse_without_apdus() {
    let emu = emulator(vec![kaztoken(), etoken72k()]);
    let (a, prompter) = setup(&emu, true, vec![]);
    let kaz = "AKKaztokenStore";
    for (method, args, expected) in [
        (
            "genKeyPairAndGetPKCS10",
            json!([kaz, "c", "p", ["a"], [GOST2004], [256], "2.5.4.3", "CN", ""]),
            "GENKEY_COMMON",
        ),
        (
            "setX509CertToKeyStore",
            json!([kaz, "c", "p", "pem"]),
            "SETCERT_COMMON",
        ),
        (
            "setX509CertToKeyStoreAndChangePassword",
            json!([kaz, "c", "p", "n", "pem"]),
            "SETCERT_COMMON",
        ),
        ("deleteEntry", json!([kaz, "c", "alias"]), "COMMON"),
        ("resetStorage", json!(["AKEToken72KStore", "c"]), "COMMON"),
        (
            "changePassword",
            json!([kaz, "c", "old", "Pin12345"]),
            "CHANGEPASS_COMMON",
        ),
        (
            "changePassword",
            json!([kaz, "c", "old", "a b"]),
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
    ] {
        assert_code(&call(&a, method, args), expected);
        assert_eq!(all_exchanges(&emu, &[R0, R1]), 0, "{method}");
    }
    // A family without a connected token: the codes without a device.
    assert_code(
        &call(
            &a,
            "setX509CertToKeyStore",
            json!(["AKAKEYStore", "c", "p", "pem"]),
        ),
        "EMPTY_SLOT",
    );
    assert!(prompter.storage_prompts().is_empty());
}

#[test]
fn all_old_token_answers_unchanged_when_disabled() {
    let emu = emulator(vec![kaztoken(), id_card()]);
    let (a, prompter) = setup(&emu, false, vec![]);
    let token = "AKKaztokenStore";
    for (method, args, expected) in [
        ("loadSlotList", json!([token]), "EMPTY_SLOT"),
        ("loadSlotList", json!(["PKCS12"]), "EMPTY_SLOT"),
        ("getPublicPartInfo", json!([R1]), "GETPUBLICPART_EXCEPTION"),
        (
            "browseKeyStore",
            json!([token, null, null]),
            "TOKEN_CHOOSE_CANCEL",
        ),
        ("deleteEntry", json!([token, "c", "alias"]), "COMMON"),
        ("resetStorage", json!(["AKEToken72KStore", "c"]), "COMMON"),
        (
            "genKeyPairAndGetPKCS10",
            json!([
                token,
                "c",
                "p",
                ["a"],
                [GOST2004],
                [256],
                "2.5.4.3",
                "CN",
                ""
            ]),
            "EMPTY_SLOT",
        ),
        (
            "setX509CertToKeyStore",
            json!([token, "c", "p", "pem"]),
            "EMPTY_SLOT",
        ),
        (
            "setX509CertToKeyStoreAndChangePassword",
            json!([token, "c", "p", "n", "pem"]),
            "EMPTY_SLOT",
        ),
        ("signXml", json!([token, R0, "SIGN", "<a/>"]), "EMPTY_SLOT"),
        (
            "changePassword",
            json!([token, "c", "old", "Pin12345"]),
            "CHANGEPASS_COMMON",
        ),
    ] {
        assert_code(&call(&a, method, args), expected);
    }
    assert_eq!(
        call(&a, "getTryCount", json!([])),
        json!({"errorCode": "NONE", "result": -1})
    );
    assert_eq!(all_exchanges(&emu, &[R0, R1]), 0);
    assert!(prompter.storage_prompts().is_empty());
    assert!(prompter.reader_prompts().is_empty());
}
