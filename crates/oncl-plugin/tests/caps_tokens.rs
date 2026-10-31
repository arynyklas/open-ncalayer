//! The `keys` capability with hardware tokens, on emulated cards: a token chosen in the
//! storage dialog, the readers of `keys_terminals`, and `keys_open` with the PIN a port
//! passes (its tries, a blocked PIN, a PIN the card cannot take).

mod common;

use common::*;
use oncl_flows::StorageKind;
use oncl_flows::testing::{ScriptedPrompter, Step};
use oncl_pdk::abi::{
    self, Action, Bytes, ChooseArgs, Chosen, ErrorCode, Filter, Handle, HostResult, Import,
    KeySource, OpenArgs, OpenOutcome, Password, PasswordArgs, SignCmsArgs, TerminalsArgs,
};
use oncl_pki::pkcs12::load;
use oncl_plugin::{Engine, HostServices, Instance};
use oncl_testkit::{read, synthetic};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use serde::de::DeserializeOwned;
use std::sync::Arc;

const ORIGIN: &str = "https://idp.egov.kz";
const READER: &str = "OpenNCALayer Emulated Reader 0";
const KEY: &str = "user-gost2015-sign";
const PIN: &str = "123456";

fn key(name: &str) -> EmuKey {
    let k = synthetic(name);
    EmuKey::load(&k.path, &k.password).unwrap()
}

/// A reader holding the card of `spec`.
fn emulator(spec: CardSpec) -> Arc<EmulatorBackend> {
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER);
    emu.insert(READER, card(spec));
    emu
}

fn kaztoken() -> CardSpec {
    CardSpec::new(TokenKind::Kaztoken, PIN, vec![key(KEY)])
}

/// Services with the tokens of `emu`, support on or off, answering dialogs with `steps`.
fn services_on(
    emu: &Arc<EmulatorBackend>,
    enabled: bool,
    steps: Vec<Step>,
) -> (Arc<ScriptedPrompter>, HostServices) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let mut services = services_with(prompter.clone(), Arc::new(Offline));
    services.tokens = Tokens::new(emu.clone(), enabled);
    (prompter, services)
}

/// An instance of a guest calling `calls` in order, with the `keys` capability.
fn guest(services: &HostServices, calls: &[(Import, Vec<u8>)]) -> Instance {
    Engine::new()
        .compile(&manifest("keys = true"), &wasm(&probe(calls)))
        .unwrap()
        .instantiate(services, session(1))
        .unwrap()
}

/// The last call's result of one request to `instance`.
fn run<T: DeserializeOwned>(instance: &mut Instance) -> HostResult<T> {
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    probe_result(reply.text().unwrap())
}

fn terminals(services: &HostServices, storage: &str) -> HostResult<Vec<String>> {
    let call = (
        Import::KeysTerminals,
        abi::encode(&TerminalsArgs {
            storage: storage.to_owned(),
        }),
    );
    run(&mut guest(services, &[call]))
}

fn open_call(storage: &str, pin: &str) -> (Import, Vec<u8>) {
    (
        Import::KeysOpen,
        abi::encode(&OpenArgs {
            storage: storage.to_owned(),
            source: KeySource::Terminal(READER.to_owned()),
            password: Password::Text(pin.to_owned()),
        }),
    )
}

fn open(services: &HostServices, storage: &str, pin: &str) -> OpenOutcome {
    run(&mut guest(services, &[open_call(storage, pin)])).unwrap()
}

fn sign_call(handle: u32) -> (Import, Vec<u8>) {
    (
        Import::KeysSignCms,
        abi::encode(&SignCmsArgs {
            handle,
            data: Bytes::from(b"contract text".to_vec()),
            attached: true,
            timestamp: false,
        }),
    )
}

/// The VERIFY commands that carried a PIN (a VERIFY without data only asks for the tries).
fn pin_tries(emu: &EmulatorBackend) -> usize {
    emu.exchanges(READER)
        .iter()
        .filter(|e| e.command.get(1) == Some(&0x20) && e.command.len() > 5)
        .count()
}

fn cert_of(name: &str) -> oncl_pki::cert::Certificate {
    let k = synthetic(name);
    load(&read(&k.path), &k.password)
        .unwrap()
        .swap_remove(0)
        .cert
}

#[test]
fn choose_token_key_and_sign_cms_verifies() {
    let emu = emulator(kaztoken());
    let (prompter, services) = services_on(
        &emu,
        true,
        vec![
            Step::Token {
                storage: StorageKind::Token("AKKaztokenStore"),
                reader: READER.to_owned(),
                pin: PIN.to_owned(),
            },
            Step::Key(0),
        ],
    );
    let choose = (
        Import::KeysChoose,
        abi::encode(&ChooseArgs {
            action: Action::Sign,
            storages: vec!["AKKaztokenStore".to_owned()],
            filter: Filter {
                allow_expired: true,
                chain: Some(Vec::new()),
                ..Filter::default()
            },
            detail: None,
        }),
    );
    let mut chooser = guest(&services, std::slice::from_ref(&choose));
    let chosen: Option<Chosen> = run(&mut chooser).unwrap();
    assert_eq!(chosen.unwrap().handle, 1);
    assert!(
        prompter.storage_prompts()[0].tokens.is_some(),
        "the storage dialog offers the tokens"
    );

    let (_, services) = services_on(
        &emu,
        true,
        vec![
            Step::Token {
                storage: StorageKind::Token("AKKaztokenStore"),
                reader: READER.to_owned(),
                pin: PIN.to_owned(),
            },
            Step::Key(0),
        ],
    );
    let mut signer = guest(&services, &[choose, sign_call(1)]);
    let cms: Bytes = run(&mut signer).unwrap();
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].cert, cert_of(KEY));
}

#[test]
fn terminals_lists_kaztoken_reader() {
    let emu = emulator(kaztoken());
    let (_, services) = services_on(&emu, true, Vec::new());
    assert_eq!(terminals(&services, "AKKaztokenStore").unwrap(), [READER]);
    assert!(terminals(&services, "AKKZIDCardStore").unwrap().is_empty());
    assert!(
        terminals(&services, "ABCloudServiceStore")
            .unwrap()
            .is_empty()
    );
    for not_a_token in ["PKCS12", "NoSuchStore"] {
        assert_eq!(
            terminals(&services, not_a_token).unwrap_err().code,
            ErrorCode::Invalid,
            "{not_a_token}"
        );
    }
}

#[test]
fn terminals_empty_when_disabled() {
    let emu = emulator(kaztoken());
    let (_, services) = services_on(&emu, false, Vec::new());
    assert!(terminals(&services, "AKKaztokenStore").unwrap().is_empty());
    assert_eq!(
        open(&services, "AKKaztokenStore", PIN),
        OpenOutcome::NoDevice
    );
    assert!(
        emu.exchanges(READER).is_empty(),
        "no command with support off"
    );
}

#[test]
fn open_with_wrong_pin_reports_tries_and_spends_one() {
    let emu = emulator(kaztoken());
    let yes = Step::Confirm { yes: true };
    let (_, services) = services_on(&emu, true, vec![yes.clone(), yes.clone(), yes]);
    let mut plugin = guest(&services, &[open_call("AKKaztokenStore", "000000")]);
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::WrongPassword {
            tries_left: Some(9)
        }
    );
    assert_eq!(pin_tries(&emu), 1);
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::WrongPassword {
            tries_left: Some(8)
        }
    );
    assert_eq!(pin_tries(&emu), 2, "one try per call");

    let keys = match open(&services, "AKKaztokenStore", PIN) {
        OpenOutcome::Opened(keys) => keys,
        other => panic!("not opened: {other:?}"),
    };
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].certificate.to_vec(),
        der::Encode::to_der(&cert_of(KEY)).unwrap()
    );
}

#[test]
fn page_pin_declined_sends_nothing() {
    let emu = emulator(kaztoken());
    let (prompter, services) = services_on(&emu, true, vec![Step::Confirm { yes: false }]);
    assert_eq!(
        open(&services, "AKKaztokenStore", PIN),
        OpenOutcome::Declined
    );
    assert_eq!(pin_tries(&emu), 0, "no VERIFY with a PIN");
    let prompts = prompter.confirm_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].origin, ORIGIN);
    for part in [ORIGIN, READER, "Kaztoken", ": 10."] {
        assert!(
            prompts[0].text.contains(part),
            "{part}: {}",
            prompts[0].text
        );
    }
}

#[test]
fn page_pin_consent_once_per_instance() {
    let emu = emulator(kaztoken());
    let (prompter, services) = services_on(&emu, true, vec![Step::Confirm { yes: true }]);
    let mut plugin = guest(&services, &[open_call("AKKaztokenStore", PIN)]);
    for _ in 0..3 {
        assert!(matches!(
            run::<OpenOutcome>(&mut plugin).unwrap(),
            OpenOutcome::Opened(_)
        ));
    }
    assert_eq!(prompter.confirm_prompts().len(), 1);
    assert_eq!(pin_tries(&emu), 3);
}

#[test]
fn wrong_page_pin_is_one_verify_then_a_new_consent() {
    let emu = emulator(kaztoken());
    let (prompter, services) = services_on(
        &emu,
        true,
        vec![Step::Confirm { yes: true }, Step::Confirm { yes: false }],
    );
    let mut plugin = guest(&services, &[open_call("AKKaztokenStore", "000000")]);
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::WrongPassword {
            tries_left: Some(9)
        }
    );
    assert_eq!(pin_tries(&emu), 1, "exactly one VERIFY");
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::Declined
    );
    assert_eq!(pin_tries(&emu), 1);
    let prompts = prompter.confirm_prompts();
    assert_eq!(prompts.len(), 2);
    assert!(prompts[1].text.contains(": 9."), "{}", prompts[1].text);
}

#[test]
fn few_tries_ask_before_every_page_pin() {
    let mut spec = kaztoken();
    spec.tries = 2;
    spec.max_tries = 2;
    let emu = emulator(spec);
    let yes = Step::Confirm { yes: true };
    let (prompter, services) = services_on(
        &emu,
        true,
        vec![yes.clone(), yes, Step::Confirm { yes: false }],
    );
    let mut plugin = guest(&services, &[open_call("AKKaztokenStore", PIN)]);
    for _ in 0..2 {
        assert!(matches!(
            run::<OpenOutcome>(&mut plugin).unwrap(),
            OpenOutcome::Opened(_)
        ));
    }
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::Declined
    );
    assert_eq!(prompter.confirm_prompts().len(), 3, "asked every time");
    assert_eq!(pin_tries(&emu), 2);
}

#[test]
fn a_site_cannot_spend_tries_without_clicks() {
    let emu = emulator(kaztoken());
    let (_, services) = services_on(&emu, true, vec![Step::Confirm { yes: true }]);
    let mut plugin = guest(&services, &[open_call("AKKaztokenStore", "000000")]);
    for _ in 0..12 {
        let _ = run::<OpenOutcome>(&mut plugin);
    }
    assert_eq!(pin_tries(&emu), 1, "one click, one try");
    assert_eq!(
        services
            .tokens
            .pin_tries(READER, TokenKind::Kaztoken)
            .unwrap(),
        Some(9)
    );
}

#[test]
fn typed_pin_needs_no_question_until_the_card_refused_it() {
    let emu = emulator(kaztoken());
    let (prompter, services) = services_on(
        &emu,
        true,
        vec![
            Step::Password("000000".to_owned()),
            Step::Confirm { yes: false },
        ],
    );
    let ask = (
        Import::DialogPassword,
        abi::encode(&PasswordArgs {
            title: "Подписание".to_owned(),
            label: "PIN".to_owned(),
            ok: "OK".to_owned(),
            cancel: "Отмена".to_owned(),
            allow_empty: false,
        }),
    );
    let typed = (
        Import::KeysOpen,
        abi::encode(&OpenArgs {
            storage: "AKKaztokenStore".to_owned(),
            source: KeySource::Terminal(READER.to_owned()),
            password: Password::Secret(1),
        }),
    );
    // The typed PIN goes at once; sent again after the card refused it, it is a retry the
    // user is asked about.
    let mut plugin = Engine::new()
        .compile(
            &manifest("keys = true\ndialogs = true"),
            &wasm(&probe(&[ask, typed.clone(), typed])),
        )
        .unwrap()
        .instantiate(&services, session(1))
        .unwrap();
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::Declined
    );
    assert_eq!(pin_tries(&emu), 1);
    assert_eq!(prompter.confirm_prompts().len(), 1);
}

#[test]
fn open_blocked() {
    let mut spec = kaztoken();
    spec.tries = 0;
    let emu = emulator(spec);
    let (_, services) = services_on(&emu, true, Vec::new());
    assert_eq!(
        open(&services, "AKKaztokenStore", PIN),
        OpenOutcome::Blocked
    );
}

#[test]
fn open_without_token_is_no_device() {
    let emu = emulator(kaztoken());
    let (_, services) = services_on(&emu, true, Vec::new());
    assert_eq!(
        open(&services, "AKEToken72KStore", PIN),
        OpenOutcome::NoDevice
    );
    emu.remove(READER);
    assert_eq!(
        open(&services, "AKKaztokenStore", PIN),
        OpenOutcome::NoDevice
    );
}

#[test]
fn open_id_card_bad_pin_spends_nothing() {
    let emu = emulator(CardSpec::new(TokenKind::KzIdCard, "1234", vec![key(KEY)]));
    let (_, services) = services_on(&emu, true, Vec::new());
    for pin in ["12345", "123", "12а4"] {
        assert_eq!(
            open(&services, "AKKZIDCardStore", pin),
            OpenOutcome::WrongPassword { tries_left: None },
            "{pin}"
        );
    }
    assert!(emu.exchanges(READER).is_empty(), "no command to the card");
}

#[test]
fn released_token_handle_is_invalid() {
    let emu = emulator(kaztoken());
    let yes = Step::Confirm { yes: true };
    let (_, services) = services_on(&emu, true, vec![yes.clone(), yes]);
    let release = (Import::KeysRelease, abi::encode(&Handle { handle: 1 }));
    let mut plugin = guest(
        &services,
        &[open_call("AKKaztokenStore", PIN), release, sign_call(1)],
    );
    let err = run::<Bytes>(&mut plugin).unwrap_err();
    assert_eq!(err.code, ErrorCode::Invalid);

    // The same handle before its release signs on the card.
    let mut plugin = guest(
        &services,
        &[open_call("AKKaztokenStore", PIN), sign_call(1)],
    );
    let cms: Bytes = run(&mut plugin).unwrap();
    assert_eq!(oncl_pki::cms::verify(&cms, None).unwrap().len(), 1);
}

#[test]
fn support_off_stops_open_token_handles() {
    let emu = emulator(kaztoken());
    let (_, services) = services_on(&emu, true, vec![Step::Confirm { yes: true }]);
    let mut plugin = guest(
        &services,
        &[open_call("AKKaztokenStore", PIN), sign_call(1)],
    );
    let cms: Bytes = run(&mut plugin).unwrap();
    assert_eq!(oncl_pki::cms::verify(&cms, None).unwrap().len(), 1);

    // The handle survives into the next request; the switch applies to it at once.
    services.tokens.set_enabled(false);
    emu.clear_exchanges(READER);
    let err = run::<Bytes>(&mut plugin).unwrap_err();
    assert_eq!(err.code, ErrorCode::Failed);
    assert!(err.message.contains("token support is off"), "{err:?}");
    assert!(emu.exchanges(READER).is_empty(), "no command to the card");
}
