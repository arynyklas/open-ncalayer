//! The manual window's registry view: package identity, declared policy with the key on the
//! per-call grant side, declared operations, and the exact request built from a template.
//! Actual synthetic WASM and real source-bound crypto, like `plugin_access`.
#![allow(dead_code)]
#[path = "../examples/sdk_probe/plugin_fixture.rs"]
mod fixture;
#[path = "../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod plugin_crypto;
#[path = "support/i01.rs"]
mod real_pki;
use fixture::*;
use oncl_core::{Engine, EngineServices, ErrorCode, OperationContext, plugins::*};
use oncl_pdk::abi::{self, Import};
use oncl_pki::resource::ResourceLimits;
use oncl_plugin::{InstanceLimits, Manifest};
use std::sync::{Arc, atomic::Ordering};

const MODULE: &str = "test.l01.module";
const SHA: [u8; 32] = [9; 32];

fn manifest_text(name: &str, operations: &str) -> String {
    format!(
        r#"id = "{ID}"
name.ru = "{name}"
name.kk = "{name}"
name.en = "{name}"
version = "1.2.3"
min_core = "0.1.0-alpha.7"
modules = ["{MODULE}"]
[capabilities]
keys = true
{operations}"#
    )
}

const SIGN_RAW: &str = r#"
[[operations]]
name = "sign-raw"
module = "test.l01.module"
manual = true
request = '{"module":"test.l01.module","method":"signRaw","args":["{file:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 64
[operations.uses]
imports = ["keys_sign_raw"]
[[operations.uses.key]]
kind = "raw"
content = "param:file"
"#;

const REST: &str = r#"
[[operations]]
name = "note"
module = "test.l01.module"
manual = true
request = '{"module":"test.l01.module","method":"note","args":["{text}","{pick}","{on}","{lang}"]}'
label = { ru = "б", kk = "ә", en = "b" }
[[operations.params]]
name = "text"
kind = "text"
max_chars = 40
[[operations.params]]
name = "pick"
kind = "choice"
choices = ["one", "two"]
[[operations.params]]
name = "on"
kind = "flag"
[[operations.params]]
name = "lang"
kind = "locale"
[operations.uses]
imports = ["hash"]

[[operations]]
name = "derive-op"
module = "test.l01.module"
manual = true
request = '{"module":"test.l01.module","method":"derive","args":[]}'
label = { ru = "в", kk = "ә", en = "c" }
[operations.uses]
imports = ["keys_sign_cms_ex"]
[[operations.uses.key]]
kind = "cms_ex"
content = "derived"
[operations.uses.key.profile]
encapsulate = false
cosign = "never"
timestamp = "basics"
certificates = "signer"
output = "der"

[[operations]]
name = "server-only"
module = "test.l01.module"
manual = false
server = true
request = '{"module":"test.l01.module","method":"srv","args":[]}'
label = { ru = "г", kk = "ә", en = "d" }
[operations.uses]
imports = ["hash"]
"#;

/// The whole set, for tests that never run the module.
fn all_operations() -> String {
    format!("{SIGN_RAW}{REST}")
}

fn raw(handle: u32) -> (Import, Vec<u8>) {
    (
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle,
            data: MESSAGE.to_vec().into(),
        }),
    )
}

struct Rig {
    engine: Engine,
    guard: Arc<crypto::Guard>,
    provider: Arc<crypto::Provider>,
}

fn rig(
    name: &str,
    operations: &str,
    sha: [u8; 32],
    handle: u32,
    prepare: impl FnOnce(&mut PluginRegistry),
) -> Rig {
    let manifest = Manifest::from_toml(&manifest_text(name, operations)).unwrap();
    let mut plugins = PluginRegistry::new();
    prepare_install(
        &mut plugins,
        manifest,
        sha,
        handle,
        operations.contains("note"),
    );
    prepare(&mut plugins);
    let guard = Arc::new(crypto::Guard::default());
    let provider = Arc::new(crypto::Provider::default());
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(provider.clone(), guard.clone())
            .with_validation(crypto::validation())
            .with_plugins(plugins),
    )
    .unwrap();
    Rig {
        engine,
        guard,
        provider,
    }
}

fn prepare_install(
    plugins: &mut PluginRegistry,
    manifest: Manifest,
    sha: [u8; 32],
    handle: u32,
    extras: bool,
) {
    plugins
        .install(
            manifest,
            sha,
            &wasm_with_extra_imports(
                &[raw(handle)],
                "",
                if extras {
                    &[Import::Hash, Import::KeysSignCmsEx]
                } else {
                    &[]
                },
            ),
            InstanceLimits {
                max_memory: 1 << 20,
                max_transfer: 1 << 12,
                ..InstanceLimits::default()
            },
            Vec::new(),
        )
        .unwrap();
}

fn call_of<'a>(operation: &'a str) -> PluginCall<'a> {
    PluginCall {
        plugin_id: ID,
        operation,
        args: "{}",
    }
}

const PKI: [(oncl_pki::http::HttpMethod, &str); 3] = [
    (
        oncl_pki::http::HttpMethod::Get,
        "http://ocsp.synthetic.test",
    ),
    (
        oncl_pki::http::HttpMethod::Get,
        "http://crl.synthetic.test/root-gost2015.crl",
    ),
    (
        oncl_pki::http::HttpMethod::Get,
        "http://crl.synthetic.test/inter-gost2015.crl",
    ),
];

fn grant_ctx(
    engine: &Engine,
    keys: &[oncl_core::keys::KeySelector],
    op: &str,
    allowed: &[oncl_core::keys::KeySelector],
) -> OperationContext {
    let permission = PluginPermission::new(ID, op, caller(), [Import::KeysSignRaw])
        .with_keys(allowed.iter().map(|k| k.key_id()))
        .with_pki_endpoints(PKI)
        .unwrap();
    begin(engine, keys, Some(permission))
}

#[test]
fn install_records_package_hash_and_identity_ignores_name() {
    // Break caught: identity taken from the (author-chosen) manifest name, or no package hash.
    let a = rig("Plugin A", &all_operations(), SHA, 1, |_| {});
    let b = rig("Totally Different Name", &all_operations(), SHA, 1, |_| {});
    let expect = PluginIdentity {
        id: ID.to_owned(),
        package_sha256: SHA,
        version: "1.2.3".to_owned(),
    };
    assert_eq!(a.engine.plugin_identity(ID), Some(&expect));
    assert_eq!(b.engine.plugin_identity(ID), Some(&expect));
    let other = rig("Plugin A", &all_operations(), [1; 32], 1, |_| {});
    assert_ne!(other.engine.plugin_identity(ID), Some(&expect));
    assert_eq!(a.engine.plugin_identity("nobody"), None);
}

#[test]
fn declared_policy_with_per_call_key_scope() {
    // Break caught: the registry policy pins a key, or the declared side stands in for the
    // chosen key on the grant side.
    let key = crypto::selector("user-rsa-sign");
    let other = crypto::selector("user-gost2004-sign");
    let all = [key.clone(), other.clone()];
    let caller = caller();
    let declare = |p: &mut PluginRegistry| {
        p.allow_declared_with_pki(ID, "sign-raw", fixture::caller(), PKI)
            .unwrap();
    };
    // No declared policy yet: the call grant alone is not enough.
    let bare = rig("p", SIGN_RAW, SHA, 1, |_| {});
    let bindings = [binding(&key, 1)];
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = grant_ctx(&bare.engine, &all, "sign-raw", std::slice::from_ref(&key));
    assert_eq!(
        bare.engine
            .plugin_call(&call_of("sign-raw"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    drop(ctx);
    // The chosen key comes from the per-call grant only.
    let rig = rig("p", SIGN_RAW, SHA, 1, declare);
    let mut ctx = grant_ctx(&rig.engine, &all, "sign-raw", std::slice::from_ref(&key));
    let result = rig
        .engine
        .plugin_call(&call_of("sign-raw"), &bound, &mut ctx)
        .unwrap();
    assert!(!result.response().is_empty());
    assert_eq!(rig.guard.applied.load(Ordering::SeqCst), 1);
    drop((ctx, result));
    // Another key is refused by the grant side, before any use.
    let rig2 = self::rig("p", SIGN_RAW, SHA, 2, declare);
    let bindings = [binding(&key, 1), binding(&other, 2)];
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = grant_ctx(&rig2.engine, &all, "sign-raw", std::slice::from_ref(&key));
    assert_eq!(
        rig2.engine
            .plugin_call(&call_of("sign-raw"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(rig2.guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(rig2.provider.opens.load(Ordering::SeqCst), 0);
    drop(ctx);
    // A different caller has no registry policy.
    let stranger = CallerContext::ServiceClient("someone-else".into());
    let bound = PluginBindings::new(&stranger, &bindings);
    let mut ctx = begin(
        &rig2.engine,
        &all,
        Some(
            PluginPermission::new(ID, "sign-raw", stranger.clone(), [Import::KeysSignRaw])
                .with_keys([other.key_id()])
                .with_pki_endpoints(PKI)
                .unwrap(),
        ),
    );
    assert_eq!(
        rig2.engine
            .plugin_call(&call_of("sign-raw"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(rig2.guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn plugin_operations_lists_only_runnable_declared() {
    // Break caught: derived or non-manual operations are offered to the manual window.
    let r = rig("p", &all_operations(), SHA, 1, |_| {});
    let names: Vec<_> = r
        .engine
        .plugin_operations(ID)
        .unwrap()
        .iter()
        .map(|o| o.name().to_owned())
        .collect();
    assert_eq!(names, ["sign-raw", "note"]);
    assert_eq!(
        r.engine.plugin_operations("nobody").unwrap_err(),
        PluginRequestError::UnknownPlugin
    );
}

#[test]
fn undeclared_operation_refused_not_applied() {
    // Break caught: an operation name the manifest does not declare reaches a module.
    let r = rig("p", &all_operations(), SHA, 1, |_| {});
    for name in ["nope", "sign", "SIGN-RAW", ""] {
        let error = r.engine.plugin_request(ID, name, &[]).unwrap_err();
        assert_eq!(error, PluginRequestError::UndeclaredOperation);
        assert_eq!(
            error.applied_state(),
            oncl_pki::key::AppliedState::NotApplied
        );
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }
    assert_eq!(
        r.engine.plugin_request(ID, "server-only", &[]).unwrap_err(),
        PluginRequestError::NotManual
    );
    let mut plugins = PluginRegistry::new();
    prepare_install(
        &mut plugins,
        Manifest::from_toml(&manifest_text("p", &all_operations())).unwrap(),
        SHA,
        1,
        true,
    );
    assert_eq!(
        plugins.allow_declared(ID, "nope", caller()).unwrap_err(),
        PluginRequestError::UndeclaredOperation
    );
    assert_eq!(r.provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(r.guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn derived_operation_refused() {
    // Break caught: a derived operation runs before the plan-run stage exists.
    let r = rig("p", &all_operations(), SHA, 1, |_| {});
    let error = r.engine.plugin_request(ID, "derive-op", &[]).unwrap_err();
    assert_eq!(error, PluginRequestError::DerivedUnsupported);
    assert_eq!(
        error.applied_state(),
        oncl_pki::key::AppliedState::NotApplied
    );
    let mut plugins = PluginRegistry::new();
    prepare_install(
        &mut plugins,
        Manifest::from_toml(&manifest_text("p", &all_operations())).unwrap(),
        SHA,
        1,
        true,
    );
    assert_eq!(
        plugins
            .allow_declared(ID, "derive-op", caller())
            .unwrap_err(),
        PluginRequestError::DerivedUnsupported
    );
}

const NOTE: fn(&str) -> Vec<(&'static str, PluginParam<'_>)> = |text| {
    vec![
        ("text", PluginParam::Text(text)),
        ("pick", PluginParam::Choice("two")),
        ("on", PluginParam::Flag(true)),
        ("lang", PluginParam::Locale("kk")),
    ]
};

#[test]
fn request_built_from_template_and_params_exactly() {
    // Break caught: the request is not the template with typed values at the placeholders.
    let r = rig("p", &all_operations(), SHA, 1, |_| {});
    let doc = [0u8, 1, 2, 255];
    assert_eq!(
        r.engine
            .plugin_request(ID, "sign-raw", &[("file", PluginParam::Document(&doc))])
            .unwrap(),
        r#"{"args":["AAEC/w=="],"method":"signRaw","module":"test.l01.module"}"#
    );
    assert_eq!(
        r.engine.plugin_request(ID, "note", &NOTE("héllo")).unwrap(),
        r#"{"args":["héllo","two",true,"kk"],"method":"note","module":"test.l01.module"}"#
    );
}

#[test]
fn param_injection_cannot_change_module_method_or_key() {
    // Break caught: a value is pasted into the text, or rescanned for placeholders.
    let r = rig("p", &all_operations(), SHA, 1, |_| {});
    for hostile in [
        r#"{file:base64}"#,
        r#"","method":"x"#,
        r#"{"module":"y"}"#,
        "\"],\"module\":\"z",
        "{on}",
        "a\nb\u{0}",
    ] {
        let text = r.engine.plugin_request(ID, "note", &NOTE(hostile)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["module"], MODULE);
        assert_eq!(value["method"], "note");
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(
            value["args"],
            serde_json::json!([hostile, "two", true, "kk"])
        );
    }
    // Hostile document bytes are only ever base64.
    let doc = br#"{"module":"y"}"#;
    let text = r
        .engine
        .plugin_request(ID, "sign-raw", &[("file", PluginParam::Document(doc))])
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["method"], "signRaw");
    assert!(
        value["args"][0]
            .as_str()
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
    );
}

#[test]
fn unknown_missing_wrong_params_refused() {
    // Break caught: a malformed parameter set still builds a request.
    let r = rig("p", &all_operations(), SHA, 1, |_| {});
    let ask = |params: &[(&str, PluginParam<'_>)]| {
        r.engine.plugin_request(ID, "note", params).unwrap_err()
    };
    let full = NOTE("ok");
    let mut extra = full.clone();
    extra.push(("surprise", PluginParam::Flag(true)));
    assert_eq!(
        ask(&extra),
        PluginRequestError::UnknownParam("surprise".into())
    );
    assert_eq!(
        ask(&full[1..]),
        PluginRequestError::MissingParam("text".into())
    );
    let mut twice = full.clone();
    twice.push(("on", PluginParam::Flag(false)));
    assert_eq!(ask(&twice), PluginRequestError::DuplicateParam("on".into()));
    let mut wrong = full.clone();
    wrong[0] = ("text", PluginParam::Flag(true));
    assert_eq!(ask(&wrong), PluginRequestError::WrongKind("text".into()));
    let mut doc = full.clone();
    doc[1] = ("pick", PluginParam::Document(b"x"));
    assert_eq!(ask(&doc), PluginRequestError::WrongKind("pick".into()));
    assert_eq!(
        ask(&NOTE(&"1".repeat(41))),
        PluginRequestError::TooLarge("text".into())
    );
    let mut pick = full.clone();
    pick[1] = ("pick", PluginParam::Choice("three"));
    assert_eq!(ask(&pick), PluginRequestError::InvalidValue("pick".into()));
    let mut lang = full.clone();
    lang[3] = ("lang", PluginParam::Locale("fr"));
    assert_eq!(ask(&lang), PluginRequestError::InvalidValue("lang".into()));
    let big = [0u8; 65];
    assert_eq!(
        r.engine
            .plugin_request(ID, "sign-raw", &[("file", PluginParam::Document(&big))])
            .unwrap_err(),
        PluginRequestError::TooLarge("file".into())
    );
    assert_eq!(
        r.engine.plugin_request(ID, "sign-raw", &[]).unwrap_err(),
        PluginRequestError::MissingParam("file".into())
    );
    assert_eq!(ask(&extra).code(), ErrorCode::InvalidInput);
}

#[test]
fn legacy_plugin_without_operations_unchanged() {
    // Break caught: a plugin without [[operations]] gains manual operations, or its exact
    // key policy loosens.
    let key = crypto::selector("user-rsa-sign");
    let other = crypto::selector("user-gost2004-sign");
    let all = [key.clone(), other.clone()];
    let caller = caller();
    let legacy = |keys: &[oncl_core::keys::KeySelector]| {
        let permission = permission(&[Import::KeysSignRaw], keys);
        let r = rig("p", "", SHA, 2, |_| {});
        // Legacy host policy: installed through the unchanged `install(policy)`.
        let manifest = Manifest::from_toml(&manifest_text("p", "")).unwrap();
        let mut plugins = PluginRegistry::new();
        plugins
            .install(
                manifest,
                SHA,
                &wasm(&[raw(2)]),
                InstanceLimits {
                    max_memory: 1 << 20,
                    max_transfer: 1 << 12,
                    ..InstanceLimits::default()
                },
                vec![permission],
            )
            .unwrap();
        drop(r);
        let guard = Arc::new(crypto::Guard::default());
        let provider = Arc::new(crypto::Provider::default());
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_keys(provider.clone(), guard.clone())
                .with_validation(crypto::validation())
                .with_plugins(plugins),
        )
        .unwrap();
        (engine, guard, provider)
    };
    let (engine, guard, _) = legacy(&all);
    assert!(engine.plugin_operations(ID).unwrap().is_empty());
    assert_eq!(
        engine.plugin_request(ID, "sign", &[]).unwrap_err(),
        PluginRequestError::UndeclaredOperation
    );
    let bindings = [binding(&key, 1), binding(&other, 2)];
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = begin(
        &engine,
        &all,
        Some(permission(&[Import::KeysSignRaw], &all)),
    );
    engine
        .plugin_call(&call_of("sign"), &bound, &mut ctx)
        .unwrap();
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    drop(ctx);
    // Host policy that names only `key`: `other` stays refused, as before.
    let (engine, guard, provider) = legacy(std::slice::from_ref(&key));
    let mut ctx = begin(
        &engine,
        &all,
        Some(permission(&[Import::KeysSignRaw], &all)),
    );
    assert_eq!(
        engine
            .plugin_call(&call_of("sign"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
}
