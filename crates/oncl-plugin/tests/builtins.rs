//! The modules built into the core: their manifests, their trust, `call_locale`, the
//! errors' causes and the pool of their instances.

mod common;

use common::*;
use oncl_basics::Locale;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_pdk::abi::{self, ErrorCode, HostError, Import, PageRead};
use oncl_plugin::{
    BUILTIN_ID_PREFIX, BuiltinLimits, BuiltinSource, Builtins, Engine, HostServices,
    InstanceLimits, Manifest, Package, PackageError, SessionContext, Trust, archive,
};
use oncl_protocol::{AddInfo, Reply};
use oncl_testkit::synthetic;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};
use std::thread;

/// `value` as CBOR.
fn cbor(value: Value) -> Vec<u8> {
    abi::encode(&value)
}

/// The built-in module of `wat` with `capabilities`, served by `services`.
fn builtins(
    capabilities: &str,
    wat: &str,
    services: HostServices,
    limits: BuiltinLimits,
) -> Builtins {
    let manifest = builtin_manifest(capabilities);
    let wasm = wasm(wat);
    let source = BuiltinSource {
        manifest: &manifest,
        wasm: &wasm,
    };
    Builtins::load(&Engine::new(), services, &[source], limits).unwrap()
}

fn call(b: &Builtins, request: &str) -> Reply {
    b.module(BUILTIN_MODULE)
        .unwrap()
        .process(request, &from("https://x.kz"))
}

fn text(reply: Reply) -> String {
    reply.text().expect("a text reply").to_owned()
}

/// A guest answering `ok`, after `fail` for a request of over 100 bytes (its input).
fn failing_on_long(fail: &str) -> String {
    let output = abi::encode(&abi::Output {
        response: "ok".to_owned(),
    });
    format!(
        r#"(module
{}
  (data (i32.const 1024) "{}")
  (func (export "oncl_process") (param $p i32) (param $len i32) (result i64)
    (if (i32.gt_u (local.get $len) (i32.const 100)) (then {fail}))
    (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {})))
)"#,
        standard_exports(2),
        wat_bytes(&output),
        output.len()
    )
}

/// A guest that runs `before` and answers `response`.
fn answering_after(before: &str, response: &str) -> String {
    let output = abi::encode(&abi::Output {
        response: response.to_owned(),
    });
    format!(
        r#"(module
{}
  (data (i32.const 1024) "{}")
  (func (export "oncl_process") (param i32 i32) (result i64)
    (local $i i32)
    {before}
    (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {})))
)"#,
        standard_exports(2),
        wat_bytes(&output),
        output.len()
    )
}

/// A loop of `n` turns.
fn spin(n: u32) -> String {
    format!(
        "(loop $l (local.set $i (i32.add (local.get $i) (i32.const 1))) \
         (br_if $l (i32.lt_u (local.get $i) (i32.const {n}))))"
    )
}

fn scripted(steps: Vec<Step>) -> (Arc<ScriptedPrompter>, HostServices) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let services = services_with(prompter.clone(), Arc::new(Offline));
    (prompter, services)
}

fn context(trust: Trust) -> SessionContext {
    SessionContext {
        trust,
        ..session(1)
    }
}

// --- manifests ----------------------------------------------------------------------------

#[test]
fn external_package_cannot_claim_builtin() {
    let reserved = |r: Result<Manifest, PackageError>| {
        assert!(
            matches!(&r, Err(PackageError::Manifest(m)) if m.contains("reserved for built-in modules")),
            "{r:?}"
        )
    };
    reserved(Manifest::from_toml(&builtin_manifest("")));
    let plain_id = builtin_manifest("").replace(BUILTIN_ID, "kz.example.test");
    reserved(Manifest::from_toml(&plain_id));
    let package = archive(builtin_manifest("").as_bytes(), &wasm(&answering("{}"))).unwrap();
    assert!(matches!(
        Package::read(&package),
        Err(PackageError::Manifest(m)) if m.contains("reserved for built-in modules")
    ));
}

#[test]
fn builtin_id_prefix_is_reserved() {
    assert!(BUILTIN_ID.starts_with(BUILTIN_ID_PREFIX));
    let without_flag = builtin_manifest("").replace("builtin = true\n", "");
    assert!(Manifest::from_toml(&without_flag).is_err());
    // A built-in module's manifest needs both the flag and the prefix.
    assert!(Manifest::from_toml_builtin(&without_flag).is_err());
    let plain_id = builtin_manifest("").replace(BUILTIN_ID, "kz.example.test");
    assert!(Manifest::from_toml_builtin(&plain_id).is_err());
    let manifest = Manifest::from_toml_builtin(&builtin_manifest("")).unwrap();
    assert!(manifest.builtin);
    assert_eq!(manifest.id, BUILTIN_ID);
}

#[test]
fn builtin_imports_need_the_flag() {
    let plugin = r#"
id = "kz.example.test"
version = "1.0.0"
min_core = "0.1.0"
modules = ["kz.example.Test"]

[name]
ru = "a"
kk = "a"
en = "a"

[capabilities]
builtin = true
"#;
    assert!(Manifest::from_toml(plugin).is_err());
    let manifest = Manifest::from_toml_builtin(&builtin_manifest("builtin = true")).unwrap();
    assert!(manifest.capabilities.builtin);
    assert!(
        !Manifest::from_toml_builtin(&builtin_manifest(""))
            .unwrap()
            .capabilities
            .builtin
    );
}

// --- trust --------------------------------------------------------------------------------

fn password_args() -> Vec<u8> {
    cbor(json!({"title": "", "label": "", "ok": "", "cancel": "", "allow_empty": false}))
}

#[test]
fn builtin_trust_has_no_source_line() {
    for (trust, expected) in [
        (Trust::Builtin, None),
        (Trust::Installed, Some("Тестовый плагин".to_owned())),
    ] {
        let (prompter, services) = scripted(vec![Step::CancelPassword]);
        let compiled = Engine::new()
            .compile(
                &manifest("dialogs = true"),
                &wasm(&probe(&[(Import::DialogPassword, password_args())])),
            )
            .unwrap();
        let mut instance = compiled.instantiate(&services, context(trust)).unwrap();
        instance.process("{}", &from("https://x.kz")).unwrap();
        assert_eq!(prompter.password_prompts()[0].source, expected, "{trust:?}");
    }
}

#[test]
fn builtin_page_file_read_needs_no_consent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("doc.txt");
    std::fs::write(&path, b"doc").unwrap();
    let args = cbor(json!({"path": path.to_str().unwrap()}));
    for (trust, asked) in [(Trust::Builtin, 0), (Trust::Installed, 1)] {
        let (prompter, services) = scripted(vec![Step::Confirm { yes: true }]);
        let compiled = Engine::new()
            .compile(
                &manifest("page_files = true"),
                &wasm(&probe(&[(Import::PageFileRead, args.clone())])),
            )
            .unwrap();
        let mut instance = compiled.instantiate(&services, context(trust)).unwrap();
        let reply = instance.process("{}", &from("https://x.kz")).unwrap();
        let read = probe_result::<PageRead>(reply.text().unwrap()).unwrap();
        assert!(
            matches!(read, PageRead::Ok(f) if f.data.to_vec() == b"doc"),
            "{trust:?}"
        );
        assert_eq!(prompter.confirm_prompts().len(), asked, "{trust:?}");
    }
}

// --- call_locale --------------------------------------------------------------------------

fn locale(code: &str) -> Vec<u8> {
    cbor(json!({"locale": code}))
}

#[test]
fn call_locale_sets_dialog_language() {
    let (prompter, services) = scripted(vec![Step::CancelPassword]);
    let b = builtins(
        "dialogs = true",
        &probe(&[
            (Import::CallLocale, locale("kk")),
            (Import::DialogPassword, password_args()),
        ]),
        services,
        BuiltinLimits::default(),
    );
    text(call(&b, "{}"));
    assert_eq!(prompter.password_prompts()[0].locale, Locale::Kk);
}

#[test]
fn call_locale_rejects_unknown() {
    for code in ["de", "KK", ""] {
        let b = builtins(
            "",
            &probe(&[(Import::CallLocale, locale(code))]),
            services(),
            BuiltinLimits::default(),
        );
        let err = probe_result::<()>(&text(call(&b, "{}"))).unwrap_err();
        assert_eq!(err.code, ErrorCode::Invalid, "{code}");
    }
}

#[test]
fn call_locale_is_per_call() {
    let (prompter, services) = scripted(vec![Step::CancelPassword, Step::CancelPassword]);
    let b = builtins(
        "dialogs = true",
        &staged_probe(&[
            vec![
                (Import::CallLocale, locale("en")),
                (Import::DialogPassword, password_args()),
            ],
            vec![(Import::DialogPassword, password_args())],
        ]),
        services,
        BuiltinLimits::default(),
    );
    text(call(&b, "{}"));
    text(call(&b, "{}"));
    let locales: Vec<Locale> = prompter
        .password_prompts()
        .iter()
        .map(|p| p.locale)
        .collect();
    assert_eq!(locales, [Locale::En, Locale::Ru]);
}

// --- causes -------------------------------------------------------------------------------

#[test]
fn host_error_cause_roundtrips() {
    let error =
        HostError::new(ErrorCode::Failed, "m").with_cause(abi::cause::CMS_UNKNOWN_ALGORITHM);
    let back: HostError = abi::decode(&abi::encode(&error)).unwrap();
    assert_eq!(back, error);
    assert_eq!(back.cause(), Some("cms.unknown_algorithm"));
}

#[test]
fn host_error_without_cause_decodes() {
    // An older core's error, and what this one writes without a cause: the same bytes.
    let old = cbor(json!({"code": "failed", "message": "m"}));
    let error: HostError = abi::decode(&old).unwrap();
    assert_eq!(error, HostError::new(ErrorCode::Failed, "m"));
    assert_eq!(error.cause(), None);
    assert_eq!(abi::encode(&error), old);
}

// --- the pool -----------------------------------------------------------------------------

#[test]
fn pooled_instance_releases_keys_between_calls() {
    let key = synthetic("user-gost2015-sign");
    let (_, services) = scripted(vec![
        Step::Storage {
            path: key.path,
            password: key.password,
        },
        Step::Key(0),
    ]);
    // No CA path, no OCSP: the synthetic key is offered offline.
    let choose = cbor(json!({"action": "sign", "filter": {"chain": [], "allow_expired": true}}));
    let sign = abi::encode(&abi::SignRawArgs {
        handle: 1,
        data: abi::Bytes::from(b"doc".to_vec()),
    });
    let b = builtins(
        "keys = true",
        &staged_probe(&[
            vec![(Import::KeysChoose, choose)],
            vec![(Import::KeysSignRaw, sign)],
        ]),
        services,
        BuiltinLimits::default(),
    );
    // The call that chooses it holds the key behind handle 1.
    let chosen = probe_result::<Option<abi::Chosen>>(&text(call(&b, "{}"))).unwrap();
    assert_eq!(chosen.map(|c| c.handle), Some(1));
    // The next call, on the same instance, finds no key behind the handle.
    let err = probe_result::<abi::Bytes>(&text(call(&b, "{}"))).unwrap_err();
    assert_eq!(err.code, ErrorCode::Invalid, "{err}");
    assert_eq!(b.stats(BUILTIN_MODULE).unwrap().calls, 2);
}

#[test]
fn idle_pool_is_bounded() {
    let limits = BuiltinLimits {
        idle: 1,
        ..BuiltinLimits::default()
    };
    let b = builtins(
        "",
        &answering_after(&spin(2_000_000), "ok"),
        services(),
        limits,
    );
    assert_eq!(b.idle(BUILTIN_MODULE), Some(1), "the instance of the load");
    let start = Arc::new(Barrier::new(3));
    let calls: Vec<_> = (0..3)
        .map(|_| {
            let m = b.module(BUILTIN_MODULE).unwrap();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                m.process("{}", &AddInfo::default())
            })
        })
        .collect();
    for call in calls {
        assert_eq!(text(call.join().unwrap()), "ok");
    }
    assert_eq!(b.idle(BUILTIN_MODULE), Some(1));
}

#[test]
fn instance_over_high_water_is_dropped() {
    let limits = BuiltinLimits {
        high_water: 1 << 20,
        ..BuiltinLimits::default()
    };
    let b = builtins(
        "",
        &answering_after("(drop (memory.grow (i32.const 32)))", "ok"),
        services(),
        limits,
    );
    assert_eq!(text(call(&b, "{}")), "ok");
    assert_eq!(b.idle(BUILTIN_MODULE), Some(0));
    assert!(b.stats(BUILTIN_MODULE).unwrap().peak_memory > 1 << 20);
    // Another one answers the next call.
    assert_eq!(text(call(&b, "{}")), "ok");
}

#[test]
fn failed_builtin_call_is_dropped() {
    let long = format!("\"{}\"", "x".repeat(200));
    for fail in [
        "unreachable",
        "(loop $l (br $l))",
        "(drop (memory.grow (i32.const 60000)))",
    ] {
        let limits = BuiltinLimits {
            instance: InstanceLimits {
                fuel: 10_000_000,
                ..BuiltinLimits::default().instance
            },
            ..BuiltinLimits::default()
        };
        let b = builtins("", &failing_on_long(fail), services(), limits);
        assert!(matches!(call(&b, &long), Reply::Drop), "{fail}");
        assert_eq!(text(call(&b, "{}")), "ok", "{fail}");
        assert_eq!(b.stats(BUILTIN_MODULE).unwrap().calls, 2);
    }
}

#[test]
fn builtin_limits_apply() {
    let small = BuiltinLimits {
        instance: InstanceLimits {
            max_memory: 4 << 20,
            fuel: 100_000,
            max_transfer: 1000,
        },
        high_water: 4 << 20,
        idle: 2,
    };
    for (wat, what) in [
        (answering_after(&spin(1_000_000), "ok"), "fuel"),
        (
            answering_after("(drop (memory.grow (i32.const 100)))", "ok"),
            "memory",
        ),
        (answering(&"x".repeat(2000)), "transfer"),
    ] {
        let b = builtins("", &wat, services(), small);
        assert!(matches!(call(&b, "{}"), Reply::Drop), "{what}");
        let b = builtins("", &wat, services(), BuiltinLimits::default());
        assert!(matches!(call(&b, "{}"), Reply::Text(_)), "{what}");
    }
    let b = builtins(
        "",
        &answering_after(&spin(1_000), "ok"),
        services(),
        BuiltinLimits::default(),
    );
    text(call(&b, "{}"));
    assert!(b.stats(BUILTIN_MODULE).unwrap().max_fuel > 1_000);
}

#[test]
fn busy_pool_waits() {
    let limits = BuiltinLimits {
        idle: 1,
        ..BuiltinLimits::default()
    };
    let b = Arc::new(builtins(
        "",
        &answering_after(&spin(5_000_000), "ok"),
        services(),
        limits,
    ));
    let start = Arc::new(Barrier::new(2));
    let calls: Vec<_> = (0..2)
        .map(|_| {
            let (b, start) = (Arc::clone(&b), Arc::clone(&start));
            thread::spawn(move || {
                start.wait();
                text(call(&b, "{}"))
            })
        })
        .collect();
    for call in calls {
        assert_eq!(call.join().unwrap(), "ok");
    }
    assert_eq!(b.stats(BUILTIN_MODULE).unwrap().calls, 2);
}
