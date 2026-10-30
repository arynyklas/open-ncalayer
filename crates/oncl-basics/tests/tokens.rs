//! Hardware tokens in the storage dialog of `PKIExtras.sign`, on emulated cards: offered only
//! with token support on, PIN errors shown on a retry, the service's problems in the prompt.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{
    Basics, Locale, MODULE_NAME, OpenError, Prompt, Prompter, ReaderEntry, ReaderList,
    ReaderProblem, ReaderPrompt, StorageKind,
};
use oncl_pki::cms::verify;
use oncl_pki::pkcs12::load;
use oncl_pki::tsp::MockTsa;
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{read, synthetic};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

const READER: &str = "OpenNCALayer Emulated Reader 0";
const KAZTOKEN: StorageKind = StorageKind::Token("AKKaztokenStore");
const ID_CARD: StorageKind = StorageKind::Token("AKKZIDCardStore");

fn key(name: &str) -> EmuKey {
    let k = synthetic(name);
    EmuKey::load(&k.path, &k.password).unwrap()
}

fn kaztoken() -> CardSpec {
    CardSpec::new(
        TokenKind::Kaztoken,
        "123456",
        vec![key("user-gost2015-sign")],
    )
}

fn emulator(spec: CardSpec) -> Arc<EmulatorBackend> {
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER);
    emu.insert(READER, card(spec));
    emu
}

struct Setup {
    basics: Basics,
    prompter: Arc<ScriptedPrompter>,
    recent: Arc<MemoryRecentPath>,
}

fn setup(emu: &Arc<EmulatorBackend>, enabled: bool, steps: Vec<Step>) -> Setup {
    setup_recent(emu, enabled, steps, None)
}

fn setup_recent(
    emu: &Arc<EmulatorBackend>,
    enabled: bool,
    steps: Vec<Step>,
    recent: Option<PathBuf>,
) -> Setup {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let recent = Arc::new(MemoryRecentPath::new(recent));
    let tsa_key = synthetic("tsa-gost2015");
    let tsa = Arc::new(MockTsa::new(
        load(&read(&tsa_key.path), &tsa_key.password)
            .unwrap()
            .swap_remove(0),
    ));
    let basics = Basics::new(prompter.clone(), recent.clone(), tsa)
        .with_tokens(Tokens::new(emu.clone(), enabled));
    Setup {
        basics,
        prompter,
        recent,
    }
}

fn token(storage: StorageKind, pin: &str) -> Step {
    Step::Token {
        storage,
        reader: READER.to_owned(),
        pin: pin.to_owned(),
    }
}

fn sign(basics: &Basics, storages: &[&str]) -> Value {
    let request = json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "allowedStorages": storages,
            "format": "cms",
            "data": "aGVsbG8=",
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        },
    });
    let add_info = AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    };
    let reply = basics.process(&request.to_string(), &add_info);
    serde_json::from_str(reply.text().expect("a text reply")).unwrap()
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    STANDARD.decode(body).unwrap()
}

/// The signer certificate of a successful `sign` reply, verified.
fn signer_cert(r: &Value) -> Vec<u8> {
    assert_eq!(r["status"], true, "{r}");
    let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    let signers = verify(&der, None).unwrap();
    assert_eq!(signers.len(), 1);
    der::Encode::to_der(&signers[0].cert).unwrap()
}

fn cert_of(name: &str) -> Vec<u8> {
    let k = synthetic(name);
    let entry = load(&read(&k.path), &k.password).unwrap().swap_remove(0);
    der::Encode::to_der(&entry.cert).unwrap()
}

#[test]
fn token_storage_offered_when_enabled() {
    let emu = emulator(kaztoken());
    let s = setup(&emu, true, vec![token(KAZTOKEN, "123456"), Step::Key(0)]);
    signer_cert(&sign(&s.basics, &["PKCS12", "AKKaztokenStore"]));
    let prompt = &s.prompter.storage_prompts()[0];
    let list = prompt.tokens.as_ref().expect("tokens offered");
    assert_eq!(
        list.current(),
        (
            vec![ReaderEntry {
                storage: KAZTOKEN,
                reader: READER.to_owned()
            }],
            None
        )
    );
    assert_eq!(list.readers_of(KAZTOKEN), [READER]);
    assert!(list.readers_of(ID_CARD).is_empty());
}

#[test]
fn token_storage_absent_when_disabled() {
    let emu = emulator(kaztoken());
    let s = setup(&emu, false, vec![token(KAZTOKEN, "123456")]);
    let r = sign(&s.basics, &["AKKaztokenStore"]);
    // Cancelled on the retry: the same answer as before tokens existed.
    assert_eq!(r, json!({"status": true, "body": {}}), "{r}");
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[0].tokens, None);
    assert_eq!(prompts[1].error, Some(OpenError::UnsupportedStorage));
    assert_eq!(prompts[1].chosen, None);
    assert!(emu.exchanges(READER).is_empty());
}

#[test]
fn sign_cms_with_token_verifies() {
    let emu = emulator(kaztoken());
    let s = setup(&emu, true, vec![token(KAZTOKEN, "123456"), Step::Key(0)]);
    let cert = signer_cert(&sign(&s.basics, &["AKKaztokenStore"]));
    assert_eq!(cert, cert_of("user-gost2015-sign"));
    assert!(!s.prompter.key_prompts()[0].candidates[0].alias.is_empty());
}

#[test]
fn wrong_pin_shows_tries_and_asks_again() {
    let emu = emulator(kaztoken());
    let s = setup(
        &emu,
        true,
        vec![
            token(KAZTOKEN, "000000"),
            token(KAZTOKEN, "123456"),
            Step::Key(0),
        ],
    );
    signer_cert(&sign(&s.basics, &["AKKaztokenStore"]));
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(
        prompts[1].error,
        Some(OpenError::WrongPin {
            tries_left: Some(9)
        })
    );
    assert_eq!(prompts[1].chosen, Some(KAZTOKEN));
    assert_eq!(prompts[1].reader.as_deref(), Some(READER));
    assert_eq!(prompts[1].tokens, prompts[0].tokens, "the same reader list");
}

#[test]
fn blocked_pin_error() {
    let mut spec = kaztoken();
    spec.tries = 0;
    let emu = emulator(spec);
    let s = setup(&emu, true, vec![token(KAZTOKEN, "123456")]);
    assert_eq!(
        sign(&s.basics, &["AKKaztokenStore"]),
        json!({"status": true, "body": {}})
    );
    assert_eq!(
        s.prompter.storage_prompts()[1].error,
        Some(OpenError::PinBlocked)
    );
}

#[test]
fn token_removed_before_open_is_absent() {
    let emu = emulator(kaztoken());
    emu.remove(READER);
    let s = setup(&emu, true, vec![token(KAZTOKEN, "123456")]);
    sign(&s.basics, &["AKKaztokenStore"]);
    let prompts = s.prompter.storage_prompts();
    assert_eq!(
        prompts[0].tokens.as_ref().unwrap().current(),
        (vec![], None)
    );
    assert_eq!(prompts[1].error, Some(OpenError::TokenAbsent));
}

#[test]
fn no_service_problem_reaches_prompt() {
    let emu = emulator(kaztoken());
    emu.set_service(false);
    let s = setup(&emu, true, vec![token(KAZTOKEN, "123456")]);
    sign(&s.basics, &["AKKaztokenStore"]);
    let prompts = s.prompter.storage_prompts();
    assert_eq!(
        prompts[0].tokens.as_ref().unwrap().current(),
        (vec![], Some(ReaderProblem::NoService))
    );
    assert_eq!(prompts[1].error, Some(OpenError::TokenService));
}

#[test]
fn recent_path_not_saved_for_token() {
    let emu = emulator(kaztoken());
    let before = PathBuf::from("keys/previous.p12");
    let s = setup_recent(
        &emu,
        true,
        vec![token(KAZTOKEN, "123456"), Step::Key(0)],
        Some(before.clone()),
    );
    signer_cert(&sign(&s.basics, &["AKKaztokenStore"]));
    assert_eq!(s.recent.saved(), None);
    assert_eq!(s.prompter.storage_prompts()[0].recent_path, Some(before));
}

#[test]
fn id_card_pin_format_error() {
    let emu = emulator(CardSpec::new(
        TokenKind::KzIdCard,
        "1234",
        vec![key("user-gost2015-auth"), key("user-gost2015-sign")],
    ));
    let s = setup(&emu, true, vec![token(ID_CARD, "12345")]);
    sign(&s.basics, &["AKKZIDCardStore"]);
    assert_eq!(
        s.prompter.storage_prompts()[1].error,
        Some(OpenError::InvalidPin)
    );
    assert!(emu.exchanges(READER).is_empty(), "no APDU for a bad PIN");
}

#[test]
fn token_not_offered_is_unsupported() {
    let emu = emulator(kaztoken());
    let s = setup(&emu, true, vec![token(KAZTOKEN, "123456")]);
    sign(&s.basics, &["PKCS12"]);
    assert_eq!(
        s.prompter.storage_prompts()[1].error,
        Some(OpenError::UnsupportedStorage)
    );
    assert!(emu.exchanges(READER).is_empty());
}

#[test]
fn scripted_reader_step() {
    let prompter = ScriptedPrompter::new(vec![Step::Reader("R1".to_owned()), Step::CancelReader]);
    let list = ReaderList::fixed(
        vec![ReaderEntry {
            storage: KAZTOKEN,
            reader: "R1".to_owned(),
        }],
        None,
    );
    let prompt = ReaderPrompt {
        origin: "o".to_owned(),
        locale: Locale::Ru,
        storage: KAZTOKEN,
        readers: list.clone(),
    };
    assert_eq!(prompter.reader(&prompt), Prompt::Answer("R1".to_owned()));
    assert_eq!(prompter.reader(&prompt), Prompt::Cancelled);
    assert_eq!(prompter.reader(&prompt), Prompt::Cancelled, "empty script");
    assert_eq!(prompter.reader_prompts(), vec![prompt.clone(); 3]);
    assert_eq!(prompter.timeline(), ["reader"; 3]);
}

#[test]
fn reader_lists_scan_on_request() {
    let fixed = ReaderList::fixed(vec![], Some(ReaderProblem::Failed));
    assert_eq!(fixed.rescan(), (vec![], Some(ReaderProblem::Failed)));
    assert_eq!(fixed.rescans(), 1);
    assert_ne!(
        fixed,
        ReaderList::fixed(vec![], Some(ReaderProblem::Failed))
    );
    assert_eq!(fixed, fixed.clone());

    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER);
    let list = ReaderList::new(Tokens::new(emu.clone(), true));
    assert_eq!(list.current(), (vec![], None));
    emu.insert(READER, card(kaztoken()));
    assert_eq!(list.current(), (vec![], None), "no background scan");
    let entry = ReaderEntry {
        storage: KAZTOKEN,
        reader: READER.to_owned(),
    };
    assert_eq!(list.rescan(), (vec![entry.clone()], None));
    assert_eq!(list.current(), (vec![entry], None));
}
