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
use oncl_pki::http::RouteTransport;
use oncl_pki::ocsp::{CertStatus, MockOcsp};
use oncl_pki::pkcs12::load;
use oncl_plugin::Engine;
use oncl_plugin::headless::{CallerContext, CapabilityBackend, HeadlessBindings, HeadlessError};
use oncl_plugin::manual::{BoundInteraction, BoundKey};
use oncl_testkit::{read, synthetic};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use time::macros::datetime;

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
    bound_with(name, Arc::new(Offline), NOW)
}

fn bound_with(
    name: &str,
    http: Arc<dyn oncl_pki::http::HttpTransport>,
    now: time::OffsetDateTime,
) -> BoundInteraction {
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
        now,
        http,
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

// The filter's own conditions, through the dialogs' functions.

fn filter_args(filter: Filter) -> Vec<u8> {
    abi::encode(&SelectArgs {
        action: Action::Sign,
        storages: Vec::new(),
        filter,
        more: FilterMore::default(),
        detail: None,
        initial_path: None,
        order: KeyOrder::NewestFirst,
    })
}

fn permissive() -> Filter {
    Filter {
        chain: Some(Vec::new()),
        allow_expired: true,
        ..Filter::default()
    }
}

fn selected(me: &BoundInteraction, filter: Filter) -> bool {
    let (reply, _) = manual(me, &[(Import::KeysSelect, filter_args(filter))]);
    result::<Option<Chosen>>(reply).unwrap().is_some()
}

#[test]
fn an_expired_key_matches_only_when_expired_keys_are_allowed() {
    let me = bound("expired-gost2015-sign");
    let strict = Filter {
        allow_expired: false,
        ..permissive()
    };
    assert!(!selected(&me, strict));
    assert!(selected(&me, permissive()));
}

#[test]
fn the_default_chain_is_not_permissive() {
    let me = bound("user-gost2015-sign");
    let default = Filter {
        allow_expired: true,
        ..Filter::default()
    };
    assert!(!selected(&me, default));
}

fn revoked_pki() -> (Arc<MockOcsp>, Arc<dyn oncl_pki::http::HttpTransport>) {
    let key = synthetic("inter-revoked-gost2015-sign");
    let leaf = load(&read(&key.path), &key.password)
        .unwrap()
        .remove(0)
        .cert;
    let serial: String = leaf
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let responder = {
        let k = synthetic("ocsp-gost2015");
        load(&read(&k.path), &k.password).unwrap().remove(0)
    };
    let ocsp = Arc::new(MockOcsp::new(responder).status(
        &serial,
        CertStatus::Revoked {
            time: datetime!(2026-01-15 08:00 UTC),
            reason: Some(1),
        },
    ));
    let http: Arc<dyn oncl_pki::http::HttpTransport> = Arc::new(RouteTransport::new(vec![(
        "http://".to_owned(),
        Arc::clone(&ocsp) as Arc<dyn oncl_pki::http::HttpTransport>,
    )]));
    (ocsp, http)
}

fn custom_chain() -> Option<Vec<abi::Bytes>> {
    Some(
        ["root-gost2015", "inter-gost2015"]
            .map(|n| abi::Bytes::from(oncl_testkit::synthetic_cert(n)))
            .to_vec(),
    )
}

#[test]
fn a_revoked_key_is_asked_once_and_does_not_match() {
    let (ocsp, http) = revoked_pki();
    let me = bound_with(
        "inter-revoked-gost2015-sign",
        http,
        time::OffsetDateTime::now_utc(),
    );
    let strict = Filter {
        chain: custom_chain(),
        ..Filter::default()
    };
    assert!(!selected(&me, strict.clone()));
    let calls = ocsp.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    // allow_revoked: matched, and the responder is not asked.
    let (ocsp, http) = revoked_pki();
    let me = bound_with(
        "inter-revoked-gost2015-sign",
        http,
        time::OffsetDateTime::now_utc(),
    );
    let lax = Filter {
        allow_revoked: true,
        ..strict
    };
    assert!(selected(&me, lax));
    assert!(ocsp.calls().is_empty());
    // chain []: neither path nor OCSP.
    assert!(selected(&me, permissive()));
    assert!(ocsp.calls().is_empty());
}

#[test]
fn many_selects_ask_the_responder_at_most_once() {
    let (ocsp, http) = revoked_pki();
    let me = bound_with(
        "inter-revoked-gost2015-sign",
        http,
        time::OffsetDateTime::now_utc(),
    );
    let call = (
        Import::KeysSelect,
        filter_args(Filter {
            chain: custom_chain(),
            ..Filter::default()
        }),
    );
    let calls = vec![call; 900];
    let (reply, _) = manual(&me, &calls);
    assert_eq!(result::<Option<Chosen>>(reply).unwrap(), None);
    assert_eq!(ocsp.calls().len(), 1);
}

#[test]
fn different_filters_per_call_are_capped() {
    let me = bound("user-gost2015-sign");
    let calls: Vec<_> = (0..=oncl_plugin::manual::MAX_EVALUATIONS)
        .map(|i| {
            let filter = Filter {
                serial_number: format!("{i:02x}"),
                ..permissive()
            };
            (Import::KeysSelect, filter_args(filter))
        })
        .collect();
    let (reply, _) = manual(&me, &calls);
    assert_eq!(
        result::<Option<Chosen>>(reply).unwrap_err().code,
        ErrorCode::Limit
    );
    let (reply, _) = manual(&me, &calls[..oncl_plugin::manual::MAX_EVALUATIONS]);
    assert_eq!(result::<Option<Chosen>>(reply).unwrap(), None);
}

#[test]
fn flows_respect_types_the_limit_and_unmatched_picks() {
    let me = bound("user-gost2015-auth");
    let with_types = |types: Option<Vec<&str>>| {
        let mut args = flow_args(FlowChecks::Settled);
        args.knca_types = types.map(|t| t.into_iter().map(str::to_owned).collect());
        abi::encode(&args)
    };
    // A type the key is not: nothing opens (Settled checks, so only the type decides).
    let (reply, _) = manual(
        &me,
        &[(Import::KeysFlowOpen, with_types(Some(vec!["SIGNATURE"])))],
    );
    assert_eq!(result::<FlowOutcome>(reply).unwrap().opened, None);
    let (reply, _) = manual(&me, &[(Import::KeysFlowOpen, with_types(None))]);
    assert!(result::<FlowOutcome>(reply).unwrap().opened.is_some());
    let (reply, _) = manual(
        &me,
        &[(Import::KeysFlowOpen, with_types(Some(vec!["NO_SUCH_TYPE"])))],
    );
    assert_eq!(
        result::<FlowOutcome>(reply).unwrap_err().code,
        ErrorCode::Invalid
    );
    // The fifth open in a call is over the limit.
    let open = (Import::KeysFlowOpen, with_types(None));
    let (reply, _) = manual(&me, &vec![open.clone(); 5]);
    assert_eq!(
        result::<FlowOutcome>(reply).unwrap_err().code,
        ErrorCode::Limit
    );
    let (reply, _) = manual(&me, &vec![open; 4]);
    assert!(result::<FlowOutcome>(reply).is_ok());
    // A pick of a flow that did not match is invalid.
    let pick = abi::encode(&PickArgs {
        flow: 0,
        error: None,
    });
    let (reply, _) = manual(
        &me,
        &[
            (Import::KeysFlowOpen, with_types(Some(vec!["SIGNATURE"]))),
            (Import::KeysFlowPick, pick),
        ],
    );
    assert_eq!(
        result::<Option<Chosen>>(reply).unwrap_err().code,
        ErrorCode::Invalid
    );
}

/// Counts the checkpoints and fails the one numbered `cancel_at`.
struct Counting {
    checks: usize,
    cancel_at: Option<usize>,
}
impl CapabilityBackend for Counting {
    fn checkpoint(&mut self) -> Result<(), HeadlessError> {
        self.checks += 1;
        if self.cancel_at == Some(self.checks) {
            return Err(HeadlessError::Backend);
        }
        Ok(())
    }
    fn invoke(&mut self, _: Import, _: &[u8]) -> Result<Vec<u8>, HeadlessError> {
        Err(HeadlessError::Backend)
    }
}

fn counted(
    me: &BoundInteraction,
    calls: &[(Import, Vec<u8>)],
    cancel_at: Option<usize>,
) -> (Result<String, HeadlessError>, usize) {
    let compiled = all_imports(calls);
    let imports: Vec<Import> = calls.iter().map(|(i, _)| *i).collect();
    let mut backend = Counting {
        checks: 0,
        cancel_at,
    };
    let caller = caller();
    let result = compiled.call_manual(
        &mut backend,
        HeadlessBindings {
            caller: &caller,
            imports: &imports,
        },
        me,
        "{}",
    );
    (result, backend.checks)
}

#[test]
fn every_filter_evaluation_is_bracketed_by_checkpoints() {
    // Each key choice evaluates one filter (an OCSP wait may follow): the call checks
    // for cancellation before it and after it, so a cancel or deadline is seen between two
    // evaluations, never only after all of them.
    let me = bound("user-gost2015-sign");
    let calls: Vec<_> = (0..4)
        .map(|i| {
            let filter = Filter {
                serial_number: format!("{i:02x}"),
                ..permissive()
            };
            (Import::KeysSelect, filter_args(filter))
        })
        .collect();
    let (reply, total) = counted(&me, &calls, None);
    assert!(reply.is_ok());
    let (_, one) = counted(&me, &calls[..1], None);
    assert!(
        total - one >= 3 * 2,
        "{total} checkpoints for 4, {one} for 1"
    );
    // Cancelled at the checkpoint before the second evaluation: the call ends there.
    let (reply, _) = counted(&me, &calls, Some(one + 1));
    assert!(matches!(reply, Err(HeadlessError::Backend)), "{reply:?}");
}
