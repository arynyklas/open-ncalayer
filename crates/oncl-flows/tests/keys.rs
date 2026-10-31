//! The shared key choice ([`KeyChooser`], [`KeyFlow`]) and the plugin dialogs of the scripted
//! prompter.

use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_flows::{
    Action, Availability, ChainPolicy, ConfirmPrompt, FileRead, KeyChecks, KeyChooser, KeyFilter,
    KeyFlow, KeyOrder, KeyRequest, Locale, MessageKind, MessagePrompt, OcspCache, OpenError,
    PasswordRules, Prompt, Prompter, ReaderEntry, Readers, SavePrompt, StartPath, StorageKind,
    WrongPin, lock_dialog_flow,
};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::info::KncaCertType;
use oncl_pki::pkcs12::{WriteOptions, write};
use oncl_testkit::{fixture, read, synthetic};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;

/// No network: the keys are not checked against responders here (an empty chain).
struct Offline;

impl HttpTransport for Offline {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        match request.method {
            HttpMethod::Get => {
                let (_, _) = (request.url, request.opts);
                Err(HttpError::other("offline"))
            }
            HttpMethod::Post => {
                let (_, _, _, _) = (
                    request.url,
                    request.content_type.unwrap_or_default(),
                    request.body,
                    request.opts,
                );
                Err(HttpError::other("offline"))
            }
        }
    }
}

const KEY: &str = "user-gost2015-sign";

fn setup(steps: Vec<Step>) -> (KeyChooser, Arc<ScriptedPrompter>, Arc<MemoryRecentPath>) {
    setup_with(steps, Tokens::disabled())
}

fn setup_with(
    steps: Vec<Step>,
    tokens: Arc<Tokens>,
) -> (KeyChooser, Arc<ScriptedPrompter>, Arc<MemoryRecentPath>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let recent = Arc::new(MemoryRecentPath::new(None));
    let chooser = KeyChooser {
        prompter: prompter.clone(),
        recent: recent.clone(),
        http: Arc::new(Offline),
        ocsp_cache: Arc::new(OcspCache::new()),
        clock: OffsetDateTime::now_utc,
        tokens,
    };
    (chooser, prompter, recent)
}

fn request() -> KeyRequest {
    KeyRequest {
        origin: "https://example.kz".to_owned(),
        locale: Locale::Ru,
        action: Action::Sign,
        storages: vec![StorageKind::Pkcs12],
        filter: KeyFilter {
            ext_key_usages: Default::default(),
            iin: String::new(),
            bin: String::new(),
            serial_number: String::new(),
            allow_expired: true,
            chain: ChainPolicy::Empty,
            allow_revoked: true,
            more: Default::default(),
        },
        detail: Some("Example: contract.pdf".to_owned()),
        initial_path: None,
        order: Default::default(),
    }
}

fn storage(password: &str) -> Step {
    Step::Storage {
        path: synthetic(KEY).path,
        password: password.to_owned(),
    }
}

#[test]
fn key_chooser_retries_storage_then_picks_key() {
    let key = synthetic(KEY);
    let (chooser, prompter, recent) = setup(vec![
        storage("wrong password"),
        storage(&key.password),
        Step::Key(0),
    ]);
    let entry = chooser.choose(&request()).expect("a key is chosen");
    assert_eq!(entry.alias, key.aliases[0]);

    let storages = prompter.storage_prompts();
    assert_eq!(storages.len(), 2);
    assert_eq!(storages[0].error, None);
    assert_eq!(storages[1].error, Some(OpenError::WrongPassword));
    assert_eq!(storages[1].recent_path.as_ref(), Some(&key.path));
    let keys = prompter.key_prompts();
    assert_eq!(keys.len(), 1);
    for detail in [&storages[0].detail, &storages[1].detail, &keys[0].detail] {
        assert_eq!(detail.as_deref(), Some("Example: contract.pdf"));
    }
    assert_eq!(keys[0].origin, "https://example.kz");
    assert_eq!(recent.saved(), Some(key.path));
    assert_eq!(
        prompter.timeline(),
        [
            "storage",
            "busy",
            "busy closed",
            "storage",
            "busy",
            "busy closed",
            "key"
        ]
    );
}

#[test]
fn key_chooser_cancel_returns_none() {
    let (chooser, prompter, recent) = setup(vec![Step::CancelStorage]);
    assert!(chooser.choose(&request()).is_none());
    assert_eq!(prompter.timeline(), ["storage"]);
    assert_eq!(recent.saved(), None);

    let password = synthetic(KEY).password;
    let (chooser, prompter, _) = setup(vec![storage(&password), Step::CancelKey]);
    assert!(chooser.choose(&request()).is_none());
    assert_eq!(prompter.key_prompts().len(), 1);
}

/// The caller holds the turn for its whole flow: the chooser does not take it again (on
/// the same thread that would never return).
#[test]
fn key_chooser_does_not_take_dialog_turn() {
    let password = synthetic(KEY).password;
    let (chooser, _, _) = setup(vec![storage(&password), Step::Key(0)]);
    let _turn = lock_dialog_flow();
    assert!(chooser.choose(&request()).is_some());
}

#[test]
fn scripted_prompter_answers_plugin_dialogs() {
    let path = PathBuf::from("out/report.pdf");
    let prompter = ScriptedPrompter::new(vec![
        Step::Message,
        Step::Confirm { yes: true },
        Step::Confirm { yes: false },
        Step::CancelConfirm,
        Step::Save { path: path.clone() },
        Step::CancelSave,
    ]);
    let message = MessagePrompt {
        origin: "o".to_owned(),
        locale: Locale::En,
        source: "Example".to_owned(),
        kind: MessageKind::Warning,
        text: "careful".to_owned(),
    };
    let question = ConfirmPrompt {
        origin: "o".to_owned(),
        locale: Locale::Kk,
        source: "Example".to_owned(),
        text: "sure?".to_owned(),
    };
    let save = SavePrompt {
        origin: "o".to_owned(),
        locale: Locale::Ru,
        source: "Example".to_owned(),
        suggested_name: "report.pdf".to_owned(),
        directory: None,
    };
    assert_eq!(prompter.message(&message), Prompt::Answer(()));
    assert_eq!(prompter.confirm(&question), Prompt::Answer(true));
    assert_eq!(prompter.confirm(&question), Prompt::Answer(false));
    assert_eq!(prompter.confirm(&question), Prompt::Cancelled);
    assert_eq!(prompter.save_file(&save), Prompt::Answer(path));
    assert_eq!(prompter.save_file(&save), Prompt::Cancelled);
    // An empty script cancels.
    assert_eq!(prompter.message(&message), Prompt::Cancelled);

    assert_eq!(prompter.message_prompts(), [message.clone(), message]);
    assert_eq!(prompter.confirm_prompts().len(), 3);
    assert_eq!(prompter.save_prompts(), [save.clone(), save]);
    assert_eq!(
        prompter.timeline(),
        [
            "message", "confirm", "confirm", "confirm", "save", "save", "message"
        ]
    );
}

const R0: &str = "OpenNCALayer Emulated Reader 0";
const R1: &str = "OpenNCALayer Emulated Reader 1";
const KAZTOKEN: StorageKind = StorageKind::Token("AKKaztokenStore");
const PIN: &str = "123456";

fn kaztoken() -> CardSpec {
    let k = synthetic(KEY);
    CardSpec::new(
        TokenKind::Kaztoken,
        PIN,
        vec![EmuKey::load(&k.path, &k.password).unwrap()],
    )
}

/// An emulator with `cards` in the readers R0, R1, … in order, its support on.
fn emulator(cards: Vec<CardSpec>) -> (Arc<EmulatorBackend>, Arc<Tokens>) {
    let emu = Arc::new(EmulatorBackend::new());
    for (i, spec) in cards.into_iter().enumerate() {
        let reader = format!("OpenNCALayer Emulated Reader {i}");
        emu.add_reader(&reader);
        emu.insert(&reader, card(spec));
    }
    let tokens = Tokens::new(emu.clone(), true);
    (emu, tokens)
}

fn token(reader: &str, pin: &str) -> Step {
    Step::Token {
        storage: KAZTOKEN,
        reader: reader.to_owned(),
        pin: pin.to_owned(),
    }
}

/// The synthetic store `name` with its password.
fn store(name: &str) -> Step {
    let k = synthetic(name);
    Step::Storage {
        path: k.path,
        password: k.password,
    }
}

/// A flow of the PKCS#12 storage without readers, start path, rules or checks.
fn flow() -> KeyFlow {
    KeyFlow {
        origin: "https://example.kz".to_owned(),
        locale: Locale::Ru,
        action: Action::Sign,
        storages: vec![StorageKind::Pkcs12],
        readers: Readers::None,
        start: StartPath::Empty,
        remember: false,
        detail: None,
        password: PasswordRules::default(),
        same_storage: false,
        file: FileRead::Open,
        kinds: None,
        none: OpenError::NoKeys,
        empty_is_none: false,
        order: KeyOrder::Store,
        checks: KeyChecks::Settled,
        skip_blocked_reader: false,
    }
}

/// The errors of the storage prompts shown, in order.
fn errors(prompter: &ScriptedPrompter) -> Vec<Option<OpenError>> {
    prompter.storage_prompts().iter().map(|p| p.error).collect()
}

#[test]
fn flow_hides_other_kinds_and_reports_none() {
    let flow = KeyFlow {
        kinds: Some(vec![KncaCertType::Signature]),
        none: OpenError::NoSigningKeys,
        ..flow()
    };
    // The TSA store has no signing key; of the two keys of the other, one signs.
    let (chooser, prompter, _) = setup(vec![
        store("tsa-gost2015"),
        store("multi-gost2015"),
        Step::Key(0),
    ]);
    let mut opened = chooser.open(&flow).opened.expect("the store opens");
    assert_eq!(errors(&prompter), [None, Some(OpenError::NoSigningKeys)]);
    assert_eq!(opened.entries().len(), 1);
    assert_eq!(opened.pick(&chooser, &flow, None), Some(0));
    assert_eq!(prompter.key_prompts()[0].candidates.len(), 1);

    // Without a type both keys are listed.
    let (chooser, _, _) = setup(vec![store("multi-gost2015")]);
    assert_eq!(
        chooser.open(&self::flow()).opened.unwrap().entries().len(),
        2
    );
}

#[test]
fn flow_empty_store_is_none_error() {
    // A store without any key (certificates only).
    let p12 = write(
        &[],
        &[read(fixture("synthetic/root-gost2015.cer"))],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(5),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.p12");
    std::fs::write(&empty, p12).unwrap();
    let answer = || Step::Storage {
        path: empty.clone(),
        password: "Qwerty12".to_owned(),
    };
    for (empty_is_none, error) in [(true, OpenError::NoAuthKeys), (false, OpenError::NoKeys)] {
        let flow = KeyFlow {
            none: OpenError::NoAuthKeys,
            empty_is_none,
            ..flow()
        };
        let (chooser, prompter, _) = setup(vec![answer(), Step::CancelStorage]);
        assert!(chooser.open(&flow).opened.is_none());
        assert_eq!(errors(&prompter), [None, Some(error)], "{empty_is_none}");
    }
}

#[test]
fn flow_fixed_readers_first_is_preselected() {
    let (_, tokens) = emulator(vec![kaztoken(), kaztoken()]);
    let fixed = vec![
        ReaderEntry {
            storage: KAZTOKEN,
            reader: R1.to_owned(),
        },
        ReaderEntry {
            storage: KAZTOKEN,
            reader: R0.to_owned(),
        },
    ];
    let flow = KeyFlow {
        storages: vec![KAZTOKEN],
        readers: Readers::Fixed(fixed.clone()),
        ..flow()
    };
    let (chooser, prompter, _) = setup_with(vec![token(R1, "000000"), Step::CancelStorage], tokens);
    assert!(chooser.open(&flow).opened.is_none());
    let prompts = prompter.storage_prompts();
    // The list is the one given, never scanned.
    let readers = prompts[0].tokens.as_ref().expect("readers are offered");
    assert_eq!(readers.current(), (fixed.clone(), None));
    assert_eq!(readers.rescans(), 0);
    // A failed token answer keeps its reader selected.
    assert!(matches!(prompts[1].error, Some(OpenError::WrongPin { .. })));
    assert_eq!(prompts[1].chosen, Some(KAZTOKEN));
    assert_eq!(prompts[1].reader.as_deref(), Some(R1));

    // A failed file answer of the same flow asks again with the file typed.
    let (_, tokens) = emulator(vec![kaztoken()]);
    let mixed = KeyFlow {
        storages: vec![StorageKind::Pkcs12, KAZTOKEN],
        readers: Readers::Fixed(fixed[..1].to_vec()),
        ..self::flow()
    };
    let (chooser, prompter, _) =
        setup_with(vec![storage("wrong password"), Step::CancelStorage], tokens);
    assert!(chooser.open(&mixed).opened.is_none());
    let prompts = prompter.storage_prompts();
    assert!(prompts[1].error.is_some());
    assert_eq!(prompts[1].chosen, None);
    assert_eq!(prompts[1].reader, None);
    assert_eq!(prompts[1].recent_path, Some(synthetic(KEY).path));
}

#[test]
fn flow_skip_blocked_reader() {
    let commands = |skip: bool, answers: usize| {
        let mut spec = kaztoken();
        spec.tries = 0;
        let (emu, tokens) = emulator(vec![spec]);
        let flow = KeyFlow {
            storages: vec![KAZTOKEN],
            readers: Readers::Fixed(vec![ReaderEntry {
                storage: KAZTOKEN,
                reader: R0.to_owned(),
            }]),
            skip_blocked_reader: skip,
            ..flow()
        };
        let mut steps = vec![token(R0, PIN); answers];
        steps.push(Step::CancelStorage);
        let (chooser, prompter, _) = setup_with(steps, tokens);
        assert!(chooser.open(&flow).opened.is_none());
        assert!(
            errors(&prompter)[1..]
                .iter()
                .all(|e| *e == Some(OpenError::PinBlocked))
        );
        emu.exchanges(R0).len()
    };
    assert_eq!(commands(true, 1), commands(true, 3));
    assert!(commands(false, 1) < commands(false, 3));
}

#[test]
fn flow_reports_last_wrong_pin_on_cancel() {
    let (_, tokens) = emulator(vec![kaztoken()]);
    let flow = KeyFlow {
        storages: vec![KAZTOKEN],
        readers: Readers::Live,
        ..flow()
    };
    let (chooser, prompter, _) = setup_with(
        vec![
            token(R0, "000000"),
            token(R0, "111111"),
            Step::CancelStorage,
        ],
        tokens.clone(),
    );
    let open = chooser.open(&flow);
    assert!(open.opened.is_none());
    let Some(OpenError::WrongPin { tries_left }) = errors(&prompter)[2] else {
        panic!("a wrong PIN is shown");
    };
    assert_eq!(
        open.wrong_pin,
        Some(WrongPin {
            storage: KAZTOKEN,
            tries_left
        })
    );

    // A store opened after a wrong PIN still reports it; none without one.
    let (chooser, _, _) = setup_with(vec![token(R0, "000000"), token(R0, PIN)], tokens.clone());
    let open = chooser.open(&flow);
    assert!(open.opened.is_some());
    assert!(open.wrong_pin.is_some());
    let (chooser, _, _) = setup_with(vec![token(R0, PIN)], tokens);
    assert_eq!(chooser.open(&flow).wrong_pin, None);
}

#[test]
fn flow_inner_password_policy() {
    let flow = KeyFlow {
        password: PasswordRules {
            non_empty: true,
            inner_policy: true,
        },
        ..flow()
    };
    let key = synthetic(KEY);
    let answer = |password: &str| Step::Storage {
        path: key.path.clone(),
        password: password.to_owned(),
    };
    // The synthetic password has no special character.
    let (chooser, prompter, _) =
        setup(vec![answer(""), answer(&key.password), Step::CancelStorage]);
    assert!(chooser.open(&flow).opened.is_none());
    assert_eq!(
        errors(&prompter),
        [
            None,
            Some(OpenError::EmptyPassword),
            Some(OpenError::InnerPasswordPolicy)
        ]
    );

    // Without the policy the same password opens the store.
    let flow = KeyFlow {
        password: PasswordRules {
            non_empty: true,
            inner_policy: false,
        },
        ..flow
    };
    let (chooser, _, _) = setup(vec![answer(&key.password)]);
    assert!(chooser.open(&flow).opened.is_some());
}

#[test]
fn flow_same_storage() {
    let missing = || Step::Jks {
        path: PathBuf::from("missing.jks"),
        password: "x".to_owned(),
    };
    for (same_storage, error) in [
        (true, OpenError::UnsupportedStorage),
        (false, OpenError::FileNotFound),
    ] {
        let flow = KeyFlow {
            same_storage,
            file: FileRead::Chosen,
            ..flow()
        };
        let (chooser, prompter, _) = setup(vec![missing(), Step::CancelStorage]);
        assert!(chooser.open(&flow).opened.is_none());
        assert_eq!(errors(&prompter)[1], Some(error), "{same_storage}");
    }
}

#[test]
fn flow_chosen_file_rules() {
    let key = synthetic(KEY);
    let flow = KeyFlow {
        file: FileRead::Chosen,
        ..flow()
    };
    // A file on a network share opens.
    if let Some(network) = oncl_testkit::network_form(&key.path) {
        let (chooser, _, _) = setup(vec![Step::Storage {
            path: PathBuf::from(network),
            password: key.password.clone(),
        }]);
        assert_eq!(chooser.open(&flow).opened.unwrap().entries().len(), 1);
    }
    // A device is not read.
    #[cfg(windows)]
    {
        let (chooser, prompter, _) = setup(vec![
            Step::Storage {
                path: PathBuf::from(r"\\.\pipe\oncl-flow-device"),
                password: key.password.clone(),
            },
            Step::CancelStorage,
        ]);
        assert!(chooser.open(&flow).opened.is_none());
        assert_eq!(errors(&prompter)[1], Some(OpenError::FileNotFound));
    }
    // A directory is not a key store file.
    let (chooser, prompter, _) = setup(vec![
        Step::Storage {
            path: fixture("synthetic"),
            password: key.password.clone(),
        },
        Step::CancelStorage,
    ]);
    assert!(chooser.open(&flow).opened.is_none());
    assert_eq!(errors(&prompter)[1], Some(OpenError::FileNotFound));
}

#[test]
fn flow_pick_again_with_error() {
    let flow = KeyFlow {
        detail: Some("contract.pdf".to_owned()),
        ..flow()
    };
    let (chooser, prompter, _) = setup(vec![store(KEY), Step::Key(0), Step::Key(0)]);
    let mut opened = chooser.open(&flow).opened.unwrap();
    assert_eq!(prompter.timeline(), ["storage", "busy"]);
    assert_eq!(opened.pick(&chooser, &flow, None), Some(0));
    assert_eq!(
        opened.pick(&chooser, &flow, Some("did not sign".to_owned())),
        Some(0)
    );
    let keys = prompter.key_prompts();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].error, None);
    assert_eq!(keys[1].error.as_deref(), Some("did not sign"));
    assert_eq!(keys[0].candidates, keys[1].candidates);
    assert_eq!(keys[1].detail.as_deref(), Some("contract.pdf"));
    assert_eq!(
        prompter.timeline(),
        ["storage", "busy", "busy closed", "key", "key"]
    );
    assert_eq!(opened.take(0).alias, synthetic(KEY).aliases[0]);
}

#[test]
fn flow_settled_vs_live() {
    let filter = KeyFilter {
        allow_expired: false,
        ..request().filter
    };
    let shown = |checks: KeyChecks| {
        let flow = KeyFlow { checks, ..flow() };
        let (chooser, prompter, _) = setup(vec![store("expired-gost2015-sign"), Step::CancelKey]);
        let mut opened = chooser.open(&flow).opened.unwrap();
        assert_eq!(opened.pick(&chooser, &flow, None), None);
        prompter.key_prompts()[0].candidates[0].availability.clone()
    };
    assert_eq!(shown(KeyChecks::Settled), Availability::Enabled);
    assert_ne!(
        shown(KeyChecks::Live(Box::new(filter))),
        Availability::Enabled
    );
}

#[test]
fn flow_remember_only_files() {
    let key = synthetic(KEY);
    let (_, tokens) = emulator(vec![kaztoken()]);
    let remembering = KeyFlow {
        storages: vec![StorageKind::Pkcs12, KAZTOKEN],
        readers: Readers::Live,
        start: StartPath::Recent,
        remember: true,
        ..flow()
    };
    // A file is remembered, and the next flow starts with it.
    let (chooser, prompter, recent) =
        setup_with(vec![store(KEY), Step::CancelStorage], tokens.clone());
    assert!(chooser.open(&remembering).opened.is_some());
    assert_eq!(recent.saved(), Some(key.path.clone()));
    assert!(chooser.open(&remembering).opened.is_none());
    assert_eq!(
        prompter.storage_prompts()[1].recent_path.as_ref(),
        Some(&key.path)
    );
    // A token's reader is not.
    let (chooser, _, recent) = setup_with(vec![token(R0, PIN)], tokens.clone());
    assert!(chooser.open(&remembering).opened.is_some());
    assert_eq!(recent.saved(), None);
    // Nor is anything without `remember`.
    let (chooser, _, recent) = setup_with(vec![store(KEY)], tokens);
    let flow = KeyFlow {
        remember: false,
        ..remembering
    };
    assert!(chooser.open(&flow).opened.is_some());
    assert_eq!(recent.saved(), None);
}
