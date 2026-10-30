//! The key functions of the plugin ports (`keys_select`, `keys_open`, `keys_chain`,
//! `keys_terminals`, `dialog_password`) and the basic ones (`hash`, `cert_details`,
//! `local_time`, `platform`, `ca_list`, `ca_issuer`), through guests in WebAssembly text
//! that call them with fixed arguments.

mod common;

use common::*;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{Availability, DisabledReason};
use oncl_pdk::abi::{
    self, Action, Bytes, CertArgs, CertDetails, Chosen, ErrorCode, Filter, FilterMore, Handle,
    HashAlg, HashArgs, HostResult, Import, KeyOrder, KeySource, KeyUsageBit, LocalTime,
    LocalTimeArgs, OpenArgs, OpenOutcome, Os, Password, PasswordArgs, Platform, SecretRef,
    SelectArgs, TerminalsArgs,
};
use oncl_pki::cert;
use oncl_pki::pkcs12::{WriteEntry, WriteOptions, load, write};
use oncl_pki::pkix::CaSet;
use oncl_plugin::{Engine, HostServices, Instance, MAX_KEY_HANDLES, MAX_SECRETS, Manifest};
use oncl_testkit::{read, synthetic, synthetic_cert};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ORIGIN: &str = "https://idp.egov.kz";
const PASSWORD: &str = "Qwerty12";

/// An instance of a guest calling `calls` in order, under `capabilities`.
fn guest(services: &HostServices, capabilities: &str, calls: &[(Import, Vec<u8>)]) -> Instance {
    guest_in(services, &manifest(capabilities), calls, 1)
}

fn guest_in(
    services: &HostServices,
    manifest: &Manifest,
    calls: &[(Import, Vec<u8>)],
    session_id: u64,
) -> Instance {
    Engine::new()
        .compile(manifest, &wasm(&probe(calls)))
        .unwrap()
        .instantiate(services, session(session_id))
        .unwrap()
}

/// The last call's result of one request to `instance`.
fn run<T: DeserializeOwned>(instance: &mut Instance) -> HostResult<T> {
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    probe_result(reply.text().unwrap())
}

/// The raw CBOR of the last call's result.
fn run_raw(instance: &mut Instance) -> Vec<u8> {
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    let hex = reply.text().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn scripted(steps: Vec<Step>) -> (Arc<ScriptedPrompter>, HostServices) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let services = services_with(prompter.clone(), Arc::new(Offline));
    (prompter, services)
}

/// The synthetic CAs: the root and the intermediate of the GOST 2015 keys.
fn synthetic_cas() -> Arc<CaSet> {
    Arc::new(CaSet::new(
        ["root-gost2015", "inter-gost2015"]
            .map(|name| cert::parse(&synthetic_cert(name)).unwrap())
            .to_vec(),
    ))
}

fn der(certificate: &cert::Certificate) -> Vec<u8> {
    der::Encode::to_der(certificate).unwrap()
}

fn path_text(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

// keys_select

/// Selects a key of the synthetic store `name` (no path, no OCSP, expired allowed) with
/// `ekus` and `more`; the key dialog's first candidate and the result.
fn select(
    name: &str,
    ekus: &[&str],
    more: FilterMore,
) -> (Availability, HostResult<Option<Chosen>>) {
    let key = synthetic(name);
    let (prompter, services) = scripted(vec![
        Step::Storage {
            path: key.path,
            password: key.password,
        },
        Step::Key(0),
    ]);
    let args = SelectArgs {
        action: Action::Sign,
        storages: Vec::new(),
        filter: Filter {
            ext_key_usages: ekus.iter().map(|s| (*s).to_owned()).collect(),
            chain: Some(Vec::new()),
            allow_expired: true,
            ..Filter::default()
        },
        more,
        detail: None,
        initial_path: None,
        order: KeyOrder::NewestFirst,
    };
    let mut plugin = guest(
        &services,
        "keys = true",
        &[(Import::KeysSelect, abi::encode(&args))],
    );
    let result = run(&mut plugin);
    let shown = prompter.key_prompts()[0].candidates[0].availability.clone();
    (shown, result)
}

fn enabled(result: (Availability, HostResult<Option<Chosen>>)) {
    assert_eq!(result.0, Availability::Enabled);
    assert!(result.1.unwrap().is_some(), "picked");
}

fn disabled(result: (Availability, HostResult<Option<Chosen>>), reason: DisabledReason) {
    assert_eq!(result.0, Availability::Disabled(vec![reason]));
    assert_eq!(
        result.1.unwrap(),
        None,
        "not picked: the dialog was asked again"
    );
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn select_filters_any_eku() {
    let any = || FilterMore {
        any_ext_key_usages: strings(&["1.3.6.1.5.5.7.3.2", "1.2.398.3.3.4.1.2.1"]),
        ..FilterMore::default()
    };
    enabled(select("legal-gost2015-sign", &[], any()));
    enabled(select("user-gost2015-auth", &[], any()));
    disabled(
        select("user-gost2015-sign", &[], any()),
        DisabledReason::AnyExtKeyUsage,
    );
}

#[test]
fn select_excludes_eku() {
    let exclude = || FilterMore {
        exclude_ext_key_usages: strings(&["1.2.398.3.3.4.1.2.1"]),
        ..FilterMore::default()
    };
    disabled(
        select("legal-gost2015-sign", &[], exclude()),
        DisabledReason::ExcludedExtKeyUsage,
    );
    enabled(select("user-gost2015-sign", &[], exclude()));
}

#[test]
fn select_tin_prefers_bin_then_iin() {
    let tin = |tin: &str| FilterMore {
        tin: tin.to_owned(),
        ..FilterMore::default()
    };
    enabled(select("legal-gost2015-sign", &[], tin("123456789021")));
    disabled(
        select("legal-gost2015-sign", &[], tin("123456789022")),
        DisabledReason::Tin,
    );
    enabled(select("user-gost2015-sign", &[], tin("123456789011")));
    disabled(
        select("user-gost2015-sign", &[], tin("123456789021")),
        DisabledReason::Tin,
    );
}

#[test]
fn select_knca_type_signature() {
    let signature = || FilterMore {
        knca_types: strings(&["SIGNATURE"]),
        ..FilterMore::default()
    };
    enabled(select("user-gost2015-sign", &[], signature()));
    disabled(
        select("user-gost2015-auth", &[], signature()),
        DisabledReason::KncaType,
    );
    // An unknown type is an invalid argument, not an empty condition.
    let (_, services) = scripted(Vec::new());
    let args = SelectArgs {
        action: Action::Sign,
        storages: Vec::new(),
        filter: Filter::default(),
        more: FilterMore {
            knca_types: strings(&["SIGNING"]),
            ..FilterMore::default()
        },
        detail: None,
        initial_path: None,
        order: KeyOrder::NewestFirst,
    };
    let mut plugin = guest(
        &services,
        "keys = true",
        &[(Import::KeysSelect, abi::encode(&args))],
    );
    assert_eq!(
        run::<Option<Chosen>>(&mut plugin).unwrap_err().code,
        ErrorCode::Invalid
    );
}

#[test]
fn select_key_usage_all_of() {
    let bits = |bits: &[KeyUsageBit]| FilterMore {
        key_usage: bits.to_vec(),
        ..FilterMore::default()
    };
    let signing = [KeyUsageBit::DigitalSignature, KeyUsageBit::NonRepudiation];
    enabled(select("user-gost2015-sign", &[], bits(&signing)));
    disabled(
        select("user-gost2015-auth", &[], bits(&signing)),
        DisabledReason::KeyUsage,
    );
    enabled(select(
        "user-gost2015-auth",
        &[],
        bits(&[KeyUsageBit::KeyAgreement]),
    ));
}

#[test]
fn select_obsolete_auth() {
    const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
    disabled(
        select("user-gost2015-sign", &[CLIENT_AUTH], FilterMore::default()),
        DisabledReason::ExtKeyUsage,
    );
    let obsolete = || FilterMore {
        obsolete_auth: true,
        ..FilterMore::default()
    };
    enabled(select("user-gost2015-sign", &[CLIENT_AUTH], obsolete()));
    disabled(
        select("user-rsa-sign", &[CLIENT_AUTH], obsolete()),
        DisabledReason::ExtKeyUsage,
    );
}

/// A PKCS#12 file in `dir` with the keys of the synthetic stores `names`, in this order.
fn store_of(dir: &Path, names: &[&str]) -> PathBuf {
    let entries: Vec<WriteEntry> = names
        .iter()
        .flat_map(|name| {
            let key = synthetic(name);
            load(&read(&key.path), &key.password).unwrap()
        })
        .map(|entry| WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(der(&entry.cert)),
        })
        .collect();
    let p12 = write(
        &entries,
        &[],
        PASSWORD,
        &WriteOptions::default(),
        &mut |bytes: &mut [u8]| getrandom::fill(bytes).unwrap(),
    )
    .unwrap();
    let path = dir.join("two.p12");
    std::fs::write(&path, p12).unwrap();
    path
}

#[test]
fn select_oldest_first_order() {
    let dir = tempfile::tempdir().unwrap();
    // Valid from 2025 and from 2020.
    let path = store_of(dir.path(), &["user-gost2015-sign", "expired-gost2015-sign"]);
    let expired = load(&read(synthetic("expired-gost2015-sign").path), PASSWORD)
        .unwrap()
        .remove(0)
        .alias;
    for (order, first_is_expired) in [
        (KeyOrder::OldestFirst, true),
        (KeyOrder::NewestFirst, false),
    ] {
        let (prompter, services) = scripted(vec![
            Step::Storage {
                path: path.clone(),
                password: PASSWORD.to_owned(),
            },
            Step::CancelKey,
        ]);
        let args = SelectArgs {
            action: Action::Sign,
            storages: Vec::new(),
            filter: Filter {
                chain: Some(Vec::new()),
                allow_expired: true,
                ..Filter::default()
            },
            more: FilterMore::default(),
            detail: None,
            initial_path: None,
            order,
        };
        let mut plugin = guest(
            &services,
            "keys = true",
            &[(Import::KeysSelect, abi::encode(&args))],
        );
        assert_eq!(run::<Option<Chosen>>(&mut plugin).unwrap(), None);
        let candidates = &prompter.key_prompts()[0].candidates;
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].alias == expired,
            first_is_expired,
            "{order:?}"
        );
    }
}

#[test]
fn select_initial_path_prefills_storage_dialog() {
    let key = synthetic("user-gost2015-sign");
    let network = if cfg!(windows) {
        r"\\files.example.kz\keys\user.p12"
    } else {
        "//files.example.kz/keys/user.p12"
    };
    for (initial, prefilled) in [
        (path_text(&key.path), Some(key.path.clone())),
        // A network path the user did not choose is not offered.
        (network.to_owned(), None),
    ] {
        let (prompter, services) = scripted(vec![Step::CancelStorage]);
        let args = SelectArgs {
            action: Action::Sign,
            storages: Vec::new(),
            filter: Filter::default(),
            more: FilterMore::default(),
            detail: None,
            initial_path: Some(initial),
            order: KeyOrder::NewestFirst,
        };
        let mut plugin = guest(
            &services,
            "keys = true",
            &[(Import::KeysSelect, abi::encode(&args))],
        );
        assert_eq!(run::<Option<Chosen>>(&mut plugin).unwrap(), None);
        assert_eq!(prompter.storage_prompts()[0].recent_path, prefilled);
    }
}

// keys_open

fn open_args(storage: &str, source: KeySource, password: Password) -> Vec<u8> {
    abi::encode(&OpenArgs {
        storage: storage.to_owned(),
        source,
        password,
    })
}

fn page_path(name: &str) -> KeySource {
    KeySource::PagePath(path_text(&synthetic(name).path))
}

fn bytes_of(name: &str) -> KeySource {
    KeySource::Bytes(Bytes::from(read(synthetic(name).path)))
}

fn text(password: &str) -> Password {
    Password::Text(password.to_owned())
}

const KEY_FILES: &str = "keys = true\nkey_files = true";

fn opened(outcome: OpenOutcome) -> Vec<abi::OpenedKey> {
    match outcome {
        OpenOutcome::Opened(keys) => keys,
        other => panic!("not opened: {other:?}"),
    }
}

#[test]
fn open_page_path_asks_consent_once_per_session() {
    let (prompter, services) = scripted(vec![
        Step::Confirm { yes: true },
        Step::Confirm { yes: true },
    ]);
    let calls = [(
        Import::KeysOpen,
        open_args("PKCS12", page_path("user-gost2015-sign"), text(PASSWORD)),
    )];
    let mut first = guest(&services, KEY_FILES, &calls);
    let keys = opened(run(&mut first).unwrap());
    assert_eq!(keys.len(), 1);
    let entry = load(&read(synthetic("user-gost2015-sign").path), PASSWORD)
        .unwrap()
        .remove(0);
    assert_eq!(keys[0].certificate.as_slice(), der(&entry.cert));
    assert_eq!(keys[0].alias, entry.alias);
    // The same path again in the same session: no second question.
    opened(run(&mut first).unwrap());
    let asked = prompter.confirm_prompts();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].origin, ORIGIN);
    assert_eq!(asked[0].source, "Тестовый плагин");
    let shown = std::fs::canonicalize(synthetic("user-gost2015-sign").path).unwrap();
    let shown = path_text(&shown);
    let shown = shown.strip_prefix(r"\\?\").unwrap_or(&shown);
    assert!(asked[0].text.contains(shown), "{}", asked[0].text);
    assert!(asked[0].text.contains(ORIGIN), "{}", asked[0].text);
    // Another session asks again.
    let mut second = guest_in(&services, &manifest(KEY_FILES), &calls, 2);
    opened(run(&mut second).unwrap());
    assert_eq!(prompter.confirm_prompts().len(), 2);
}

#[test]
fn open_page_path_declined() {
    for step in [Step::Confirm { yes: false }, Step::CancelConfirm] {
        let (_, services) = scripted(vec![step]);
        let mut plugin = guest(
            &services,
            KEY_FILES,
            &[(
                Import::KeysOpen,
                open_args("PKCS12", page_path("user-gost2015-sign"), text(PASSWORD)),
            )],
        );
        assert_eq!(
            run::<OpenOutcome>(&mut plugin).unwrap(),
            OpenOutcome::Declined
        );
    }
}

/// `keys_open` of `path` by a page: the outcome, and whether the user was asked.
fn open_named(path: &str) -> (OpenOutcome, bool) {
    let (prompter, services) = scripted(vec![Step::Confirm { yes: true }]);
    let mut plugin = guest(
        &services,
        KEY_FILES,
        &[(
            Import::KeysOpen,
            open_args(
                "PKCS12",
                KeySource::PagePath(path.to_owned()),
                text(PASSWORD),
            ),
        )],
    );
    let outcome = run(&mut plugin).unwrap();
    (outcome, !prompter.confirm_prompts().is_empty())
}

#[test]
fn open_network_path_not_chosen_is_not_found() {
    let network = if cfg!(windows) {
        r"\\files.example.kz\keys\user.p12"
    } else {
        "//files.example.kz/keys/user.p12"
    };
    assert_eq!(open_named(network), (OpenOutcome::NotFound, false));
}

#[test]
fn open_device_path_is_not_found() {
    if cfg!(windows) {
        assert_eq!(
            open_named(r"\\.\pipe\oncl-test"),
            (OpenOutcome::NotFound, false)
        );
    }
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        open_named(&path_text(dir.path())),
        (OpenOutcome::NotFound, false),
        "a directory"
    );
    assert_eq!(
        open_named(&path_text(&dir.path().join("absent.p12"))),
        (OpenOutcome::NotFound, false)
    );
}

#[test]
fn open_wrong_password() {
    let mut plugin = guest(
        &services(),
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args("PKCS12", bytes_of("user-gost2015-sign"), text("wrong")),
        )],
    );
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::WrongPassword { tries_left: None }
    );
}

#[test]
fn open_corrupt_file() {
    for (storage, source) in [
        (
            "PKCS12",
            KeySource::Bytes(Bytes::from(b"not a key store".to_vec())),
        ),
        ("JKS", bytes_of("user-gost2015-sign")),
    ] {
        let mut plugin = guest(
            &services(),
            "keys = true",
            &[(Import::KeysOpen, open_args(storage, source, text(PASSWORD)))],
        );
        assert_eq!(
            run::<OpenOutcome>(&mut plugin).unwrap(),
            OpenOutcome::Corrupt,
            "{storage}"
        );
    }
}

#[test]
fn open_bytes_without_consent() {
    let (prompter, services) = scripted(Vec::new());
    let mut plugin = guest(
        &services,
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args("PKCS12", bytes_of("user-gost2015-sign"), text(PASSWORD)),
        )],
    );
    assert_eq!(opened(run(&mut plugin).unwrap()).len(), 1);
    assert!(prompter.timeline().is_empty(), "no dialog");
}

#[test]
fn open_returns_all_keys_in_file_order() {
    let key = synthetic("multi-gost2015");
    let stored = load(&read(&key.path), &key.password).unwrap();
    let mut plugin = guest(
        &services(),
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args("PKCS12", bytes_of("multi-gost2015"), text(PASSWORD)),
        )],
    );
    let keys = opened(run(&mut plugin).unwrap());
    let aliases: Vec<&str> = keys.iter().map(|k| k.alias.as_str()).collect();
    let expected: Vec<&str> = stored.iter().map(|e| e.alias.as_str()).collect();
    assert_eq!(aliases, expected);
    let handles: Vec<u32> = keys.iter().map(|k| k.handle).collect();
    assert_eq!(handles, [1, 2]);
    for (key, entry) in keys.iter().zip(&stored) {
        assert_eq!(key.certificate.as_slice(), der(&entry.cert));
    }
}

#[test]
fn open_page_path_without_key_files_is_denied() {
    let mut plugin = guest(
        &services(),
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args("PKCS12", page_path("user-gost2015-sign"), text(PASSWORD)),
        )],
    );
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap_err().code,
        ErrorCode::Denied
    );
}

#[test]
fn open_over_handle_limit_inserts_nothing() {
    let single = (
        Import::KeysOpen,
        open_args("PKCS12", page_path("user-gost2015-sign"), text(PASSWORD)),
    );
    let double = (
        Import::KeysOpen,
        open_args("PKCS12", page_path("multi-gost2015"), text(PASSWORD)),
    );
    let mut calls = vec![single.clone(); MAX_KEY_HANDLES - 1];
    calls.push(double);
    let consent = || vec![Step::Confirm { yes: true }, Step::Confirm { yes: true }];
    let (_, services) = scripted(consent());
    let mut full = guest(&services, KEY_FILES, &calls);
    assert_eq!(
        run::<OpenOutcome>(&mut full).unwrap_err().code,
        ErrorCode::Limit
    );
    // The two keys that did not fit took no handle: the last one still fits.
    calls.push(single);
    let (_, services) = scripted(consent());
    let mut fits = guest(&services, KEY_FILES, &calls);
    let keys = opened(run(&mut fits).unwrap());
    assert_eq!(keys[0].handle, MAX_KEY_HANDLES as u32);
}

#[test]
fn open_terminal_is_no_device_with_tokens_off() {
    let mut plugin = guest(
        &services(),
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args(
                "AKKaztokenStore",
                KeySource::Terminal("ACS ACR38U 0".to_owned()),
                text("123456"),
            ),
        )],
    );
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap(),
        OpenOutcome::NoDevice
    );
    let mut unknown = guest(
        &services(),
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args(
                "NoSuchStore",
                bytes_of("user-gost2015-sign"),
                text(PASSWORD),
            ),
        )],
    );
    assert_eq!(
        run::<OpenOutcome>(&mut unknown).unwrap_err().code,
        ErrorCode::Invalid
    );
}

#[test]
fn terminals_are_empty_with_tokens_off() {
    let terminals = |storage: &str| {
        let mut plugin = guest(
            &services(),
            "keys = true",
            &[(
                Import::KeysTerminals,
                abi::encode(&TerminalsArgs {
                    storage: storage.to_owned(),
                }),
            )],
        );
        run::<Vec<String>>(&mut plugin)
    };
    assert_eq!(terminals("AKKaztokenStore").unwrap(), Vec::<String>::new());
    assert_eq!(terminals("AKKZIDCardStore").unwrap(), Vec::<String>::new());
    for not_a_token in ["PKCS12", "NoSuchStore"] {
        assert_eq!(
            terminals(not_a_token).unwrap_err().code,
            ErrorCode::Invalid,
            "{not_a_token}"
        );
    }
}

// dialog_password

fn password_args() -> Vec<u8> {
    abi::encode(&PasswordArgs {
        title: "Подписание".to_owned(),
        label: "Пароль контейнера".to_owned(),
        ok: "Подписать".to_owned(),
        cancel: "Отменить".to_owned(),
        allow_empty: false,
    })
}

#[test]
fn password_secret_never_reaches_guest() {
    let (prompter, services) = scripted(vec![Step::Password(PASSWORD.to_owned())]);
    let mut plugin = guest(
        &services,
        "keys = true\ndialogs = true",
        &[(Import::DialogPassword, password_args())],
    );
    let raw = run_raw(&mut plugin);
    let expected: HostResult<Option<SecretRef>> = Ok(Some(SecretRef { id: 1 }));
    assert_eq!(raw, abi::encode(&expected), "only the id");
    assert!(
        !raw.windows(PASSWORD.len())
            .any(|w| w == PASSWORD.as_bytes())
    );
    let asked = prompter.password_prompts();
    assert_eq!(asked[0].origin, ORIGIN);
    assert_eq!(asked[0].source.as_deref(), Some("Тестовый плагин"));
    assert_eq!(asked[0].title.as_deref(), Some("Подписание"));
    assert_eq!(asked[0].message.as_deref(), Some("Пароль контейнера"));
    assert_eq!(asked[0].ok.as_deref(), Some("Подписать"));
    assert_eq!(asked[0].cancel.as_deref(), Some("Отменить"));
    assert!(!asked[0].allow_empty);
    // A cancelled dialog is `None`.
    let (_, services) = scripted(vec![Step::CancelPassword]);
    let mut plugin = guest(
        &services,
        "dialogs = true",
        &[(Import::DialogPassword, password_args())],
    );
    assert_eq!(run::<Option<SecretRef>>(&mut plugin).unwrap(), None);
}

#[test]
fn password_secret_opens_store() {
    let (_, services) = scripted(vec![Step::Password(PASSWORD.to_owned())]);
    let mut plugin = guest(
        &services,
        "keys = true\ndialogs = true",
        &[
            (Import::DialogPassword, password_args()),
            (
                Import::KeysOpen,
                open_args(
                    "PKCS12",
                    bytes_of("user-gost2015-sign"),
                    Password::Secret(1),
                ),
            ),
        ],
    );
    assert_eq!(opened(run(&mut plugin).unwrap()).len(), 1);
}

#[test]
fn unknown_secret_is_invalid() {
    let mut plugin = guest(
        &services(),
        "keys = true",
        &[(
            Import::KeysOpen,
            open_args(
                "PKCS12",
                bytes_of("user-gost2015-sign"),
                Password::Secret(7),
            ),
        )],
    );
    assert_eq!(
        run::<OpenOutcome>(&mut plugin).unwrap_err().code,
        ErrorCode::Invalid
    );
}

#[test]
fn password_asks_past_the_limit_evict_the_oldest() {
    let asks = MAX_SECRETS + 1;
    let answers = || vec![Step::Password(PASSWORD.to_owned()); asks];
    // Every ask of one session gets a new id, also past the limit.
    let (_, services) = scripted(answers());
    let mut plugin = guest(
        &services,
        "dialogs = true",
        &[(Import::DialogPassword, password_args())],
    );
    for id in 1..=asks as u32 {
        assert_eq!(
            run::<Option<SecretRef>>(&mut plugin).unwrap(),
            Some(SecretRef { id })
        );
    }
    // The oldest password is gone, the newer ones are kept.
    let open_with = |id: u32| {
        let (_, services) = scripted(answers());
        let mut calls = vec![(Import::DialogPassword, password_args()); asks];
        calls.push((
            Import::KeysOpen,
            open_args(
                "PKCS12",
                bytes_of("user-gost2015-sign"),
                Password::Secret(id),
            ),
        ));
        let mut plugin = guest(&services, "keys = true\ndialogs = true", &calls);
        run::<OpenOutcome>(&mut plugin)
    };
    assert_eq!(open_with(1).unwrap_err().code, ErrorCode::Invalid);
    assert_eq!(opened(open_with(2).unwrap()).len(), 1);
}

// keys_chain, ca_list, ca_issuer

#[test]
fn chain_of_inter_user_key() {
    let mut services = services();
    services.cas = synthetic_cas();
    let mut plugin = guest(
        &services,
        "keys = true",
        &[
            (
                Import::KeysOpen,
                open_args(
                    "PKCS12",
                    bytes_of("inter-user-gost2015-sign"),
                    text(PASSWORD),
                ),
            ),
            (Import::KeysChain, abi::encode(&Handle { handle: 1 })),
        ],
    );
    let chain: Vec<Bytes> = run(&mut plugin).unwrap();
    let leaf = load(&read(synthetic("inter-user-gost2015-sign").path), PASSWORD)
        .unwrap()
        .remove(0);
    let expected = vec![
        der(&leaf.cert),
        synthetic_cert("inter-gost2015"),
        synthetic_cert("root-gost2015"),
    ];
    let chain: Vec<Vec<u8>> = chain.into_iter().map(Bytes::into_vec).collect();
    assert_eq!(chain, expected);
    // An unknown handle.
    let mut plugin = guest(
        &services,
        "keys = true",
        &[(Import::KeysChain, abi::encode(&Handle { handle: 9 }))],
    );
    assert_eq!(
        run::<Vec<Bytes>>(&mut plugin).unwrap_err().code,
        ErrorCode::Invalid
    );
}

#[test]
fn ca_list_is_nca_production() {
    let mut plugin = guest(&services(), "", &[(Import::CaList, abi::encode(&()))]);
    let listed: Vec<Vec<u8>> = run::<Vec<Bytes>>(&mut plugin)
        .unwrap()
        .into_iter()
        .map(Bytes::into_vec)
        .collect();
    let expected: Vec<Vec<u8>> = oncl_pki::roots::nca_production().iter().map(der).collect();
    assert!(!expected.is_empty());
    assert_eq!(listed, expected);
}

#[test]
fn ca_issuer_by_aki() {
    let mut services = services();
    services.cas = synthetic_cas();
    let issuer_of = |der: Vec<u8>| {
        let mut plugin = guest(
            &services,
            "",
            &[(
                Import::CaIssuer,
                abi::encode(&CertArgs {
                    der: Bytes::from(der),
                }),
            )],
        );
        run::<Option<Bytes>>(&mut plugin)
    };
    let leaf = |name: &str| {
        der(&load(&read(synthetic(name).path), PASSWORD)
            .unwrap()
            .remove(0)
            .cert)
    };
    assert_eq!(
        issuer_of(leaf("inter-user-gost2015-sign"))
            .unwrap()
            .unwrap(),
        synthetic_cert("inter-gost2015")
    );
    assert_eq!(
        issuer_of(synthetic_cert("inter-gost2015"))
            .unwrap()
            .unwrap(),
        synthetic_cert("root-gost2015")
    );
    assert_eq!(issuer_of(leaf("user-rsa-sign")).unwrap(), None);
    assert_eq!(
        issuer_of(b"not a certificate".to_vec()).unwrap_err().code,
        ErrorCode::Invalid
    );
}

// hash, cert_details, local_time, platform

fn hash(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    let mut plugin = guest(
        &services(),
        "",
        &[(
            Import::Hash,
            abi::encode(&HashArgs {
                alg,
                data: Bytes::from(data.to_vec()),
            }),
        )],
    );
    run::<Bytes>(&mut plugin).unwrap().into_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn hash_vectors() {
    assert_eq!(
        hex(&hash(HashAlg::Sha1, b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(&hash(HashAlg::Sha256, b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&hash(HashAlg::Sha512, b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    // The GOST hashes as the signatures compute them.
    use oncl_pki::key::HashAlg as Pki;
    for (alg, pki) in [
        (HashAlg::Gost34311, Pki::Gost34311),
        (HashAlg::Streebog256, Pki::Streebog256),
        (HashAlg::Streebog512, Pki::Streebog512),
    ] {
        assert_eq!(hash(alg, b"contract"), pki.digest(b"contract"), "{alg:?}");
    }
    assert_eq!(
        Pki::Gost34311.digest(b"contract"),
        oncl_pki::key::SigAlg::Gost2004.digest(b"contract")
    );
    assert_eq!(hash(HashAlg::Streebog256, b"").len(), 32);
    // Streebog-256 of the empty message (GOST R 34.11-2012).
    assert_eq!(
        hex(&hash(HashAlg::Streebog256, b"")),
        "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"
    );
}

#[test]
fn cert_details_of_synthetic() {
    let entry = load(&read(synthetic("inter-user-gost2015-sign").path), PASSWORD)
        .unwrap()
        .remove(0);
    let mut plugin = guest(
        &services(),
        "",
        &[(
            Import::CertDetails,
            abi::encode(&CertArgs {
                der: Bytes::from(der(&entry.cert)),
            }),
        )],
    );
    let details: CertDetails = run(&mut plugin).unwrap();
    let tbs = entry.cert.tbs_certificate();
    let info = oncl_pki::info::cert_info(&entry.cert);
    assert_eq!(details.subject_dn, oncl_pki::info::kalkan_dn(tbs.subject()));
    assert!(details.subject_dn.contains("SERIALNUMBER=IIN123456789011"));
    assert_eq!(details.issuer_dn, oncl_pki::info::kalkan_dn(tbs.issuer()));
    let types: Vec<String> = oncl_pki::info::kcert_types(&info)
        .into_iter()
        .map(|t| t.name().to_owned())
        .collect();
    assert_eq!(details.knca_types, types);
    assert_eq!(details.knca_types, ["SIGNATURE", "AUTHENTICATION"]);
    let ski = oncl_pki::pkix::subject_key_id(&entry.cert).unwrap();
    assert_eq!(details.ski_hex.as_deref(), Some(hex(&ski).as_str()));
    assert_eq!(details.ski_hex.as_deref(), Some(entry.alias.as_str()));
    let inter = cert::parse(&synthetic_cert("inter-gost2015")).unwrap();
    let inter_ski = oncl_pki::pkix::subject_key_id(&inter).unwrap();
    assert_eq!(details.aki_hex.as_deref(), Some(hex(&inter_ski).as_str()));
    let serial = u128::from_str_radix(&info.serial_hex, 16).unwrap();
    assert_eq!(details.serial_dec, serial.to_string());
    assert_eq!(
        details.ocsp_urls,
        oncl_pki::ocsp::ocsp_url(&entry.cert)
            .into_iter()
            .collect::<Vec<_>>()
    );
    assert!(!details.ocsp_urls.is_empty());
    assert_eq!(details.crl_urls, oncl_pki::crl::crl_urls(&entry.cert));
    assert_eq!(details.signing_alg.as_deref(), Some("gost2015_512"));
}

/// The system's offset from UTC now, as another program reads it.
fn system_offset_seconds() -> i32 {
    if cfg!(windows) {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[int][System.TimeZoneInfo]::Local.GetUtcOffset([DateTime]::UtcNow).TotalSeconds",
            ])
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    } else {
        let out = std::process::Command::new("date")
            .arg("+%z")
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let text = text.trim();
        let sign = if text.starts_with('-') { -1 } else { 1 };
        let hours: i32 = text[1..3].parse().unwrap();
        let minutes: i32 = text[3..5].parse().unwrap();
        sign * (hours * 3600 + minutes * 60)
    }
}

#[test]
fn local_time_offset_is_systems() {
    let now = time::OffsetDateTime::now_utc();
    let unix_ms = (now.unix_timestamp_nanos() / 1_000_000) as i64;
    let mut plugin = guest(
        &services(),
        "",
        &[(Import::LocalTime, abi::encode(&LocalTimeArgs { unix_ms }))],
    );
    let local: LocalTime = run(&mut plugin).unwrap();
    assert_eq!(local.offset_seconds, system_offset_seconds());
}

#[test]
fn platform_line_separator() {
    let mut plugin = guest(&services(), "", &[(Import::Platform, abi::encode(&()))]);
    let platform: Platform = run(&mut plugin).unwrap();
    if cfg!(windows) {
        assert_eq!(platform.os, Os::Windows);
        assert_eq!(platform.line_separator, "\r\n");
    } else {
        assert_ne!(platform.os, Os::Windows);
        assert_eq!(platform.line_separator, "\n");
    }
}
