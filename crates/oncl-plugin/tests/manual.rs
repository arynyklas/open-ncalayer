//! The key choice of the manual window (`call_manual`, design `manual-plugins.md` 3.5):
//! the plugin's filter against the one key the user bound, never a dialog.

mod common;

use common::*;
use oncl_flows::OcspCache;
use oncl_pdk::abi::{
    self, Action, ChooseArgs, Chosen, ErrorCode, Filter, FilterMore, FlowArgs, FlowChecks,
    FlowFile, FlowNone, FlowOrder, FlowOutcome, FlowReaders, FlowStart, HostResult, Import,
    KeyOrder, PickArgs, SelectArgs, TerminalsArgs, TokenScan,
};
use oncl_pki::pkcs12::load;
use oncl_plugin::Engine;
use oncl_plugin::headless::{CallerContext, CapabilityBackend, HeadlessBindings, HeadlessError};
use oncl_plugin::manual::{BoundInteraction, BoundKey};
use oncl_testkit::{read, synthetic};
use serde::de::DeserializeOwned;
use std::sync::Arc;

const CAPS: &str = "keys = true\ndialogs = true\nfiles = true";

/// A backend that must never be reached for what the manual window answers itself.
#[derive(Default)]
struct Spy {
    invoked: Vec<Import>,
}
impl CapabilityBackend for Spy {
    fn checkpoint(&mut self) -> Result<(), HeadlessError> {
        Ok(())
    }
    fn invoke(&mut self, import: Import, _: &[u8]) -> Result<Vec<u8>, HeadlessError> {
        self.invoked.push(import);
        Err(HeadlessError::Backend)
    }
}

fn bound(name: &str) -> BoundInteraction {
    let key = synthetic(name);
    let entry = load(&read(&key.path), &key.password)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    BoundInteraction {
        key: BoundKey {
            handle: 41,
            alias: entry.alias.clone(),
            certificate: der::Encode::to_der(&entry.cert).unwrap(),
        },
        now: NOW,
        http: Arc::new(Offline),
        ocsp_cache: Arc::new(OcspCache::new()),
    }
}

fn caller() -> CallerContext {
    CallerContext::LocalOperator("manual".to_owned())
}

/// The result string of one `call_manual` of a guest making `calls`.
fn manual(
    interaction: &BoundInteraction,
    calls: &[(Import, Vec<u8>)],
) -> (Result<String, HeadlessError>, Spy) {
    let compiled = all_imports(calls);
    let imports: Vec<Import> = calls.iter().map(|(i, _)| *i).collect();
    let mut spy = Spy::default();
    let caller = caller();
    let result = compiled.call_manual(
        &mut spy,
        HeadlessBindings {
            caller: &caller,
            imports: &imports,
        },
        interaction,
        "{}",
    );
    (result, spy)
}

/// A built-in's manifest declares every import, `core_open_window` and `keystore_*` too.
fn all_imports(calls: &[(Import, Vec<u8>)]) -> oncl_plugin::Compiled {
    let manifest = oncl_plugin::Manifest::from_toml_builtin(&builtin_manifest(
        "builtin = true\nkeys = true\ndialogs = true\nfiles = true",
    ))
    .unwrap();
    Engine::new()
        .compile(&manifest, &wasm(&probe(calls)))
        .unwrap()
}

fn headless(calls: &[(Import, Vec<u8>)]) -> Result<String, HeadlessError> {
    let compiled = all_imports(calls);
    let imports: Vec<Import> = calls.iter().map(|(i, _)| *i).collect();
    let caller = caller();
    compiled.call_headless(
        &mut Spy::default(),
        HeadlessBindings {
            caller: &caller,
            imports: &imports,
        },
        "{}",
    )
}

fn result<T: DeserializeOwned>(reply: Result<String, HeadlessError>) -> HostResult<T> {
    probe_result(&reply.unwrap())
}

fn select_args(ekus: &[&str], more: FilterMore) -> Vec<u8> {
    abi::encode(&SelectArgs {
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
    })
}

fn signature_only() -> FilterMore {
    FilterMore {
        knca_types: vec!["SIGNATURE".to_owned()],
        ..FilterMore::default()
    }
}

#[test]
fn bound_key_matching_the_filter_is_chosen() {
    let me = bound("user-gost2015-sign");
    let (reply, spy) = manual(
        &me,
        &[(Import::KeysSelect, select_args(&[], signature_only()))],
    );
    let chosen = result::<Option<Chosen>>(reply).unwrap().unwrap();
    assert_eq!(chosen.handle, 41);
    assert_eq!(chosen.alias, me.key.alias);
    assert_eq!(chosen.certificate.as_ref(), me.key.certificate.as_slice());
    assert!(spy.invoked.is_empty(), "no backend, no dialog");
}

#[test]
fn filter_mismatch_is_no_suitable_key() {
    let me = bound("user-gost2015-auth");
    let (reply, _) = manual(
        &me,
        &[(Import::KeysSelect, select_args(&[], signature_only()))],
    );
    assert_eq!(result::<Option<Chosen>>(reply).unwrap(), None);
}

#[test]
fn choose_uses_the_basic_filter() {
    let me = bound("user-gost2015-sign");
    let args = |iin: &str| {
        abi::encode(&ChooseArgs {
            action: Action::Sign,
            storages: Vec::new(),
            filter: Filter {
                iin: iin.to_owned(),
                chain: Some(Vec::new()),
                allow_expired: true,
                ..Filter::default()
            },
            detail: None,
        })
    };
    let (reply, _) = manual(&me, &[(Import::KeysChoose, args("123456789011"))]);
    assert!(result::<Option<Chosen>>(reply).unwrap().is_some());
    let (reply, _) = manual(&me, &[(Import::KeysChoose, args("123456789012"))]);
    assert_eq!(result::<Option<Chosen>>(reply).unwrap(), None);
}

#[test]
fn every_select_answers_the_same_single_key() {
    let me = bound("user-gost2015-sign");
    let one = (Import::KeysSelect, select_args(&[], signature_only()));
    let first = manual(&me, std::slice::from_ref(&one)).0.unwrap();
    // Several selects in one call, and again in another call: the same answer.
    let many = manual(&me, &[one.clone(), one.clone(), one.clone()])
        .0
        .unwrap();
    let again = manual(&me, &[one]).0.unwrap();
    assert_eq!(first, many);
    assert_eq!(first, again);
}

fn flow_args(checks: FlowChecks) -> FlowArgs {
    FlowArgs {
        action: Action::Sign,
        storages: Vec::new(),
        readers: FlowReaders::None,
        start: FlowStart::Empty,
        remember: false,
        detail: None,
        non_empty_password: false,
        inner_password_policy: false,
        same_storage: false,
        file: FlowFile::Open,
        knca_types: None,
        none: FlowNone::NoKeys,
        empty_is_none: false,
        order: FlowOrder::Store,
        checks,
        skip_blocked_reader: false,
    }
}

fn live(more: FilterMore) -> FlowChecks {
    FlowChecks::Live {
        filter: Box::new(Filter {
            chain: Some(Vec::new()),
            allow_expired: true,
            ..Filter::default()
        }),
        more: Box::new(more),
    }
}

#[test]
fn flow_open_and_pick_answer_for_the_bound_key() {
    let me = bound("user-gost2015-sign");
    let open = abi::encode(&flow_args(live(signature_only())));
    let (reply, _) = manual(&me, &[(Import::KeysFlowOpen, open.clone())]);
    let outcome = result::<FlowOutcome>(reply).unwrap();
    let opened = outcome.opened.unwrap();
    assert_eq!(opened.keys.len(), 1);
    assert_eq!(
        opened.keys[0].certificate.as_ref(),
        me.key.certificate.as_slice()
    );
    // Open then pick in one call: the pick names the flow just opened.
    let pick = abi::encode(&PickArgs {
        flow: 0,
        error: None,
    });
    let (reply, _) = manual(
        &me,
        &[
            (Import::KeysFlowOpen, open),
            (Import::KeysFlowPick, pick.clone()),
        ],
    );
    assert_eq!(result::<Option<Chosen>>(reply).unwrap().unwrap().handle, 41);
    // A pick without an open flow is invalid, as in the dialogs.
    let (reply, _) = manual(&me, &[(Import::KeysFlowPick, pick)]);
    assert_eq!(
        result::<Option<Chosen>>(reply).unwrap_err().code,
        ErrorCode::Invalid
    );
    // A mismatching filter opens nothing.
    let nothing = bound("user-gost2015-auth");
    let open = abi::encode(&flow_args(live(signature_only())));
    let (reply, _) = manual(&nothing, &[(Import::KeysFlowOpen, open)]);
    assert_eq!(result::<FlowOutcome>(reply).unwrap().opened, None);
}

#[test]
fn terminals_are_empty_and_tokens_off() {
    let me = bound("user-gost2015-sign");
    let args = abi::encode(&TerminalsArgs {
        storage: "AKKaztokenStore".to_owned(),
    });
    let (reply, _) = manual(&me, &[(Import::KeysTerminals, args)]);
    assert_eq!(result::<Vec<String>>(reply).unwrap(), Vec::<String>::new());
    let (reply, _) = manual(&me, &[(Import::TokensScan, abi::encode(&()))]);
    assert_eq!(
        result::<TokenScan>(reply).unwrap(),
        TokenScan {
            enabled: false,
            present: Vec::new(),
            any_card: false
        }
    );
}

#[test]
fn keys_open_is_a_trap_never_a_hang() {
    let me = bound("user-gost2015-sign");
    let (reply, spy) = manual(&me, &[(Import::KeysOpen, vec![0xa0])]);
    assert!(matches!(reply, Err(HeadlessError::Denied)), "{reply:?}");
    assert!(spy.invoked.is_empty());
}

#[test]
fn interactive_imports_are_the_same_trap_in_both_windows() {
    let me = bound("user-gost2015-sign");
    let refused: Vec<Import> = Import::ALL
        .into_iter()
        .filter(|i| {
            let n = i.name();
            n.starts_with("dialog_")
                || n.starts_with("file_")
                || n.starts_with("keystore_")
                || *i == Import::CoreOpenWindow
        })
        .collect();
    assert!(refused.len() >= 12, "{refused:?}");
    for import in refused {
        let call = [(import, vec![0xa0])];
        let in_manual = manual(&me, &call).0;
        let in_plan = headless(&call);
        assert!(
            matches!(in_manual, Err(HeadlessError::InteractionRequired)),
            "{import:?}: {in_manual:?}"
        );
        // A plugin sees one trap either way: the outcome class is identical.
        assert_eq!(in_manual.unwrap_err(), in_plan.unwrap_err(), "{import:?}");
    }
}

#[test]
fn server_and_cli_path_is_unchanged() {
    // Without an interaction a key choice is still `InteractionRequired`.
    let call = [(Import::KeysSelect, select_args(&[], signature_only()))];
    assert_eq!(
        headless(&call).unwrap_err(),
        HeadlessError::InteractionRequired
    );
    // And an import that is not granted stays `Denied` in the manual window too.
    let me = bound("user-gost2015-sign");
    let compiled = Engine::new()
        .compile(&manifest(CAPS), &wasm(&probe(&call)))
        .unwrap();
    let caller = caller();
    let denied = compiled.call_manual(
        &mut Spy::default(),
        HeadlessBindings {
            caller: &caller,
            imports: &[],
        },
        &me,
        "{}",
    );
    assert_eq!(denied.unwrap_err(), HeadlessError::Denied);
}

#[test]
fn the_answer_carries_no_secret_or_path() {
    let me = bound("user-gost2015-sign");
    let key = synthetic("user-gost2015-sign");
    let (reply, _) = manual(
        &me,
        &[(Import::KeysSelect, select_args(&[], signature_only()))],
    );
    let hex = reply.unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    // Exactly the handle, alias and certificate, nothing else.
    let expected: HostResult<Option<Chosen>> = Ok(Some(Chosen {
        handle: 41,
        alias: me.key.alias.clone(),
        certificate: abi::Bytes::from(me.key.certificate.clone()),
    }));
    assert_eq!(bytes, abi::encode(&expected));
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(!has(key.password.as_bytes()));
    assert!(!has(key.path.to_str().unwrap().as_bytes()));
}

#[test]
fn reply_drop_is_allowed_and_harmless() {
    let me = bound("user-gost2015-sign");
    let (reply, spy) = manual(&me, &[(Import::ReplyDrop, abi::encode(&()))]);
    assert_eq!(result::<()>(reply).unwrap(), ());
    assert!(spy.invoked.is_empty());
}
