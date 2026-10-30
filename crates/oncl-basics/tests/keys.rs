//! The shared key choice ([`KeyChooser`]) and the plugin dialogs of the scripted prompter.

use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{
    Action, ChainPolicy, ConfirmPrompt, KeyChooser, KeyFilter, KeyRequest, Locale, MessageKind,
    MessagePrompt, OcspCache, OpenError, Prompt, Prompter, SavePrompt, StorageKind,
    lock_dialog_flow,
};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_testkit::synthetic;
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
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let recent = Arc::new(MemoryRecentPath::new(None));
    let chooser = KeyChooser {
        prompter: prompter.clone(),
        recent: recent.clone(),
        http: Arc::new(Offline),
        ocsp_cache: Arc::new(OcspCache::new()),
        clock: OffsetDateTime::now_utc,
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
