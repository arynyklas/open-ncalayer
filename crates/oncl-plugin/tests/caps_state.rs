//! A plugin's choice dialog (`dialog_choice`), its settings kept on disk (`settings_get`,
//! `settings_put`) and the values its instances share in the process (`shared_get`,
//! `shared_put`).

mod common;

use common::*;
use oncl_flows::testing::{ScriptedPrompter, Step};
use oncl_pdk::abi::{
    self, Bytes, ChoiceArgs, ErrorCode, HostResult, Import, MAX_SETTINGS_KEYS, MAX_SHARED,
    MAX_SHARED_KEYS, MessageKind, SharedKey, SharedPut,
};
use oncl_plugin::{
    Engine, HostServices, Package, PluginModules, SessionContext, SharedState, Store,
};
use oncl_protocol::{AddInfo, DynamicModules};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const ORIGIN: &str = "https://bank.example.kz";

fn run_with<T: DeserializeOwned>(
    caps: &str,
    services: &HostServices,
    ctx: SessionContext,
    calls: &[(Import, Vec<u8>)],
) -> HostResult<T> {
    let mut instance = Engine::new()
        .compile(&manifest(caps), &wasm(&probe(calls)))
        .unwrap()
        .instantiate(services, ctx)
        .unwrap();
    probe_result(
        instance
            .process("{}", &from(ORIGIN))
            .unwrap()
            .text()
            .unwrap(),
    )
}

fn choice(buttons: &[&str], default: u8, options: &[&str]) -> (Import, Vec<u8>) {
    (
        Import::DialogChoice,
        abi::encode(&ChoiceArgs {
            kind: MessageKind::Warning,
            title: Some("Подпись".to_owned()),
            text: "Продолжить?".to_owned(),
            buttons: buttons.iter().map(|b| (*b).to_owned()).collect(),
            default,
            options: options.iter().map(|o| (*o).to_owned()).collect(),
        }),
    )
}

fn ask(
    steps: Vec<Step>,
    call: (Import, Vec<u8>),
) -> (HostResult<Option<u8>>, Arc<ScriptedPrompter>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let services = services_with(Arc::clone(&prompter), Arc::new(Offline));
    (
        run_with("dialogs = true", &services, session(1), &[call]),
        prompter,
    )
}

#[test]
fn choice_returns_button_index() {
    let (answer, prompter) = ask(
        vec![Step::Choice {
            button: 2,
            option: None,
        }],
        choice(&["Да", "Нет", "Отмена"], 1, &[]),
    );
    assert_eq!(answer.unwrap(), Some(2));
    let prompt = &prompter.choice_prompts()[0];
    assert_eq!(prompt.buttons, ["Да", "Нет", "Отмена"]);
    assert_eq!(prompt.default, 1);
    assert_eq!(prompt.title.as_deref(), Some("Подпись"));
    assert_eq!(prompt.text, "Продолжить?");
    assert_eq!(prompt.kind, oncl_flows::MessageKind::Warning);
    assert_eq!(prompt.origin, ORIGIN);
    assert_eq!(prompt.source, "Тестовый плагин");
}

#[test]
fn choice_list_option() {
    let list = choice(
        &["Выбрать", "Отмена"],
        0,
        &["Считыватель 1", "Считыватель 2"],
    );
    let (answer, prompter) = ask(
        vec![Step::Choice {
            button: 0,
            option: Some(1),
        }],
        list.clone(),
    );
    assert_eq!(answer.unwrap(), Some(1));
    assert_eq!(
        prompter.choice_prompts()[0].options,
        ["Считыватель 1", "Считыватель 2"]
    );
    // Another button, or nothing selected: no option.
    for (button, option) in [(1, Some(0)), (0, None)] {
        let (answer, _) = ask(vec![Step::Choice { button, option }], list.clone());
        assert_eq!(answer.unwrap(), None);
    }
}

#[test]
fn choice_closed_is_none() {
    let (answer, _) = ask(vec![Step::CancelChoice], choice(&["OK"], 0, &[]));
    assert_eq!(answer.unwrap(), None);
    let too_many: Vec<String> = (0..=abi::MAX_CHOICE_OPTIONS)
        .map(|i| i.to_string())
        .collect();
    let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
    let long = "x".repeat(2000);
    for bad in [
        choice(&[], 0, &[]),
        choice(&["1", "2", "3", "4"], 0, &[]),
        choice(&["1", "2"], 2, &[]),
        choice(&["OK"], 0, &too_many),
        choice(&[long.as_str()], 0, &[]),
    ] {
        let (answer, prompter) = ask(Vec::new(), bad);
        assert_eq!(answer.unwrap_err().code, ErrorCode::Invalid);
        assert!(prompter.choice_prompts().is_empty());
    }
}

fn settings_services(dir: &Path) -> HostServices {
    let mut services = services();
    services.settings_dir = Some(dir.join("plugins").join("settings"));
    services
}

fn put(map: &[(&str, &str)]) -> (Import, Vec<u8>) {
    let map: BTreeMap<String, String> = map
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    (Import::SettingsPut, abi::encode(&map))
}

fn get() -> (Import, Vec<u8>) {
    (Import::SettingsGet, abi::encode(&()))
}

fn settings_file(dir: &Path) -> std::path::PathBuf {
    dir.join("plugins")
        .join("settings")
        .join(format!("{PLUGIN_ID}.json"))
}

#[test]
fn settings_roundtrip_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let services = settings_services(dir.path());
    let empty: BTreeMap<String, String> =
        run_with("settings = true", &services, session(1), &[get()]).unwrap();
    assert!(empty.is_empty());
    let () = run_with(
        "settings = true",
        &services,
        session(1),
        &[put(&[("lang", "kk"), ("url", "https://a.kz")])],
    )
    .unwrap();
    // Another session (and instance) reads them; a put replaces them all.
    let read: BTreeMap<String, String> =
        run_with("settings = true", &services, session(2), &[get()]).unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!(read["lang"], "kk");
    let read: BTreeMap<String, String> = run_with(
        "settings = true",
        &services,
        session(3),
        &[put(&[("lang", "ru")]), get()],
    )
    .unwrap();
    assert_eq!(
        read.into_iter().collect::<Vec<_>>(),
        [("lang".to_owned(), "ru".to_owned())]
    );
    let on_disk: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(settings_file(dir.path())).unwrap()).unwrap();
    assert_eq!(on_disk["lang"], "ru");
    // Nothing else in the folder: no temporary files left.
    assert_eq!(
        std::fs::read_dir(settings_file(dir.path()).parent().unwrap())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn settings_limit() {
    let dir = tempfile::tempdir().unwrap();
    let with_dir = settings_services(dir.path());
    let keys: Vec<String> = (0..=MAX_SETTINGS_KEYS).map(|i| format!("k{i}")).collect();
    let many: Vec<(&str, &str)> = keys.iter().map(|k| (k.as_str(), "v")).collect();
    let big = "v".repeat(abi::MAX_SETTINGS);
    for args in [put(&many), put(&[("k", big.as_str())])] {
        let result: HostResult<()> = run_with("settings = true", &with_dir, session(1), &[args]);
        assert_eq!(result.unwrap_err().code, ErrorCode::Limit);
    }
    assert!(!settings_file(dir.path()).exists());
    // Without a place for settings: failed.
    let result: HostResult<BTreeMap<String, String>> =
        run_with("settings = true", &services(), session(1), &[get()]);
    assert_eq!(result.unwrap_err().code, ErrorCode::Failed);
}

#[test]
fn settings_survive_update_removed_with_plugin() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let bytes = oncl_testkit::plugin::example_package();
    let package = Package::read(&bytes).unwrap();
    let id = package.manifest.id.clone();
    store
        .install(&package, &bytes, oncl_plugin::Source::Catalog)
        .unwrap();
    let path = store.settings_path(&id);
    assert_eq!(
        path,
        dir.path()
            .join("plugins")
            .join("settings")
            .join(format!("{id}.json"))
    );
    assert_eq!(
        Some(path.parent().unwrap().to_path_buf()),
        Some(store.settings_dir())
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, br#"{"a":"1"}"#).unwrap();
    let newer = oncl_testkit::plugin::example_package_with(|m| {
        m.replacen("version = \"0.1.0\"", "version = \"0.2.0\"", 1)
    });
    store
        .install(
            &Package::read(&newer).unwrap(),
            &newer,
            oncl_plugin::Source::Catalog,
        )
        .unwrap();
    assert!(path.is_file(), "an update keeps the settings");
    store.remove(&id).unwrap();
    assert!(!path.exists(), "removing the plugin removes them");
}

#[test]
fn corrupt_settings_are_empty() {
    let dir = tempfile::tempdir().unwrap();
    let services = settings_services(dir.path());
    let path = settings_file(dir.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for garbage in [&b"{not json"[..], b"[1, 2]", br#"{"a": 1}"#] {
        std::fs::write(&path, garbage).unwrap();
        let read: BTreeMap<String, String> =
            run_with("settings = true", &services, session(1), &[get()]).unwrap();
        assert!(read.is_empty());
    }
}

fn shared_put(key: &str, value: Option<&[u8]>, ttl_ms: Option<u64>) -> (Import, Vec<u8>) {
    (
        Import::SharedPut,
        abi::encode(&SharedPut {
            key: key.to_owned(),
            value: value.map(|v| Bytes::from(v.to_vec())),
            ttl_ms,
        }),
    )
}

fn shared_get(key: &str) -> (Import, Vec<u8>) {
    (
        Import::SharedGet,
        abi::encode(&SharedKey {
            key: key.to_owned(),
        }),
    )
}

fn in_session(session: u64, shared: &Arc<SharedState>) -> SessionContext {
    SessionContext {
        shared: Arc::clone(shared),
        ..common::session(session)
    }
}

#[test]
fn shared_visible_across_sessions() {
    let services = services();
    let shared = Arc::new(SharedState::default());
    let () = run_with(
        "shared = true",
        &services,
        in_session(1, &shared),
        &[shared_put("state", Some(b"signing"), None)],
    )
    .unwrap();
    let seen: Option<Bytes> = run_with(
        "shared = true",
        &services,
        in_session(2, &shared),
        &[shared_get("state")],
    )
    .unwrap();
    assert_eq!(seen.as_deref().map(Vec::as_slice), Some(&b"signing"[..]));
    // Removed.
    let gone: Option<Bytes> = run_with(
        "shared = true",
        &services,
        in_session(3, &shared),
        &[shared_put("state", None, None), shared_get("state")],
    )
    .unwrap();
    assert_eq!(gone, None);
    // Another plugin's state is another.
    let other = Arc::new(SharedState::default());
    let none: Option<Bytes> = run_with(
        "shared = true",
        &services,
        in_session(4, &other),
        &[shared_get("state")],
    )
    .unwrap();
    assert_eq!(none, None);
}

#[test]
fn shared_ttl_expires() {
    let mut services = services();
    services.clock = time::OffsetDateTime::now_utc;
    let shared = Arc::new(SharedState::default());
    let () = run_with(
        "shared = true",
        &services,
        in_session(1, &shared),
        &[
            shared_put("short", Some(b"1"), Some(50)),
            shared_put("long", Some(b"2"), Some(60_000)),
        ],
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(120));
    let short: Option<Bytes> = run_with(
        "shared = true",
        &services,
        in_session(2, &shared),
        &[shared_get("short")],
    )
    .unwrap();
    assert_eq!(short, None);
    let long: Option<Bytes> = run_with(
        "shared = true",
        &services,
        in_session(2, &shared),
        &[shared_get("long")],
    )
    .unwrap();
    assert!(long.is_some());
}

#[test]
fn shared_reset_on_reload() {
    let caps = "shared = true";
    let package = |calls: &[(Import, Vec<u8>)]| Package {
        manifest: manifest(caps),
        wasm: wasm(&probe(calls)),
        sha256: [0; 32],
    };
    let modules = PluginModules::new(Arc::new(Engine::new()), services(), Vec::new());
    let module = || modules.module("kz.example.Test").unwrap();
    let call = |session: u64| -> HostResult<Option<Bytes>> {
        let add_info = AddInfo {
            origin: Some(ORIGIN.to_owned()),
            session,
        };
        probe_result(
            module()
                .process("{}", &add_info)
                .into_text()
                .unwrap()
                .as_str(),
        )
    };
    modules
        .load(package(&[
            shared_put("k", Some(b"v"), None),
            shared_get("k"),
        ]))
        .unwrap();
    assert!(call(1).unwrap().is_some());
    // The same generation: another session sees it.
    modules.load(package(&[shared_get("k")])).unwrap();
    assert_eq!(call(2).unwrap(), None, "a new generation starts empty");
    modules.unload(PLUGIN_ID);
}

#[test]
fn shared_limit() {
    let services = services();
    let shared = Arc::new(SharedState::default());
    let keys: Vec<String> = (0..MAX_SHARED_KEYS).map(|i| format!("k{i}")).collect();
    let fill: Vec<(Import, Vec<u8>)> = keys
        .iter()
        .map(|k| shared_put(k, Some(b"v"), None))
        .collect();
    let () = run_with("shared = true", &services, in_session(1, &shared), &fill).unwrap();
    let one_more: HostResult<()> = run_with(
        "shared = true",
        &services,
        in_session(1, &shared),
        &[shared_put("extra", Some(b"v"), None)],
    );
    assert_eq!(one_more.unwrap_err().code, ErrorCode::Limit);
    // Replacing a key is not one more.
    let () = run_with(
        "shared = true",
        &services,
        in_session(1, &shared),
        &[shared_put("k0", Some(b"w"), None)],
    )
    .unwrap();
    let big = vec![0u8; MAX_SHARED];
    let too_big: HostResult<()> = run_with(
        "shared = true",
        &services,
        in_session(2, &Arc::new(SharedState::default())),
        &[shared_put("big", Some(&big), None)],
    );
    assert_eq!(too_big.unwrap_err().code, ErrorCode::Limit);
}
