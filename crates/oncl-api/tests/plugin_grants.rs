#![cfg(feature = "server")]
//! The grant matrix of a plugin operation over HTTP (docs/design/manual-plugins.md 4.7/4.8,
//! R14): a declared operation may use a key only under `plugin_bytes = true`, under the
//! declared options and once; an undeclared operation is skipped at start-up; a plugin
//! without declarations is unchanged. Every refusal is typed (`subcode`) and happens before
//! the audit journal and the key are touched.
mod private_support;
use oncl_pdk::abi::{self, Import};
use oncl_server::{
    audit::RecordKind,
    config::{Permission, PluginConfig, PluginGrant},
};
use private_support::*;

const MESSAGE: &[u8] = b"plugin raw signing over HTTP";

const HEADER: &str = r#"id = "test.declared"
name.ru = "synthetic"
name.kk = "synthetic"
name.en = "synthetic"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["test.declared.module"]
[capabilities]
keys = true
"#;
/// One declared server operation named `name` using one key of `kind` over a document.
fn operation(name: &str, imports: &str, kind: &str, profile: &str) -> String {
    format!(
        r#"[[operations]]
name = "{name}"
module = "test.declared.module"
server = true
request = '{{"module":"test.declared.module","method":"m","args":["{{file:base64}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[operations.uses]
imports = [{imports}]
network = "pki"
[[operations.uses.key]]
kind = "{kind}"
content = "param:file"
{profile}
"#
    )
}
fn grant(pki: &Pki, operation: &str, import: &str, plugin_bytes: bool) -> PluginGrant {
    PluginGrant {
        token: "test".into(),
        operation: operation.into(),
        imports: vec![import.into()],
        keys: vec!["ops-key".into()],
        plugin_bytes,
        pki_endpoints: vec![
            format!("{}/ocsp", pki.origin),
            format!("{}/root.crl", pki.origin),
            format!("{}/inter.crl", pki.origin),
        ],
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    plugin: PluginConfig,
}
fn fixture(
    id: &str,
    manifest: &str,
    calls: &[(Import, Vec<u8>)],
    grants: Vec<PluginGrant>,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (manifest_path, wasm) = (dir.path().join("p.toml"), dir.path().join("p.wasm"));
    std::fs::write(&manifest_path, manifest).unwrap();
    std::fs::write(&wasm, private_support::plugin::wasm(calls)).unwrap();
    Fixture {
        plugin: PluginConfig {
            id: id.into(),
            manifest: manifest_path,
            wasm,
            max_memory: 1 << 20,
            max_transfer: 1 << 18,
            permissions: grants,
        },
        _dir: dir,
    }
}
fn sign_raw() -> Vec<(Import, Vec<u8>)> {
    vec![(
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle: 1,
            data: MESSAGE.to_vec().into(),
        }),
    )]
}
async fn start(pki: &Pki, plugin: PluginConfig) -> Running {
    Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        named_key(config, dir, pki, "ops-key", "user-rsa-sign");
        config.tokens[0].actions = vec![Permission::Sign];
        config.tokens[0].keys = vec!["ops-key".into()];
        config.plugins = vec![plugin];
    })
    .await
}
fn begins(service: &Running) -> usize {
    service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .count()
}
async fn call(service: &Running, plugin: &str, operation: &str) -> (u16, serde_json::Value) {
    let body = format!(
        r#"{{"items":[{{"id":"p","operation":{{"kind":"plugin","plugin":"{plugin}","operation":"{operation}","args":"{{}}","keys":[{{"handle":1,"name":"ops-key"}}]}}}}],"parts":[]}}"#
    );
    let (status, _, response) = service.post(FORM, multipart(&body, &[])).await;
    let json = serde_json::from_slice(&response)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&response)));
    (status, json)
}
fn assert_refused(status: u16, error: &serde_json::Value, subcode: Option<&str>) {
    assert_eq!(status, 403, "{error}");
    assert_eq!(error["code"], "PermissionDenied", "{error}");
    assert_eq!(error["applied"], "NotApplied", "{error}");
    match subcode {
        Some(subcode) => assert_eq!(error["subcode"], subcode, "{error}"),
        None => assert!(error.get("subcode").is_none(), "{error}"),
    }
    assert_matches_schema("ApiError", error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_key_use_needs_plugin_bytes_and_is_refused_typed_before_the_journal() {
    let pki = Pki::start();
    let manifest = format!(
        "{HEADER}{}{}",
        operation("with-bytes", r#""keys_sign_raw""#, "raw", ""),
        operation("no-bytes", r#""keys_sign_raw""#, "raw", "")
    );
    let f = fixture(
        "test.declared",
        &manifest,
        &sign_raw(),
        vec![
            grant(&pki, "with-bytes", "keys_sign_raw", true),
            grant(&pki, "no-bytes", "keys_sign_raw", false),
            // Not declared by the plugin: skipped at start-up.
            grant(&pki, "legacy", "keys_sign_raw", true),
        ],
    );
    let service = start(&pki, f.plugin.clone()).await;
    // Under plugin_bytes the key signs through the original context and the durable audit.
    let (status, done) = call(&service, "test.declared", "with-bytes").await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["results"][0]["applied"], "Applied", "{done}");
    assert_eq!(begins(&service), 1);
    // The same declared operation without plugin_bytes: refused, NotApplied, no BEGIN.
    let (status, error) = call(&service, "test.declared", "no-bytes").await;
    assert_refused(status, &error, Some("not-granted"));
    assert_eq!(begins(&service), 1, "no journal record, no key use");
    // The grant of an undeclared operation was skipped: plain refusal, no subcode.
    let (status, error) = call(&service, "test.declared", "legacy").await;
    assert_refused(status, &error, None);
    assert_eq!(begins(&service), 1);
    // The refusal does not poison what follows: the granted operation still signs.
    let (status, done) = call(&service, "test.declared", "with-bytes").await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(begins(&service), 2);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn options_outside_the_declared_profile_are_refused_even_with_plugin_bytes() {
    let pki = Pki::start();
    // The declared CMS profile is detached without a time-stamp; the guest signs attached.
    let manifest = format!(
        "{HEADER}{}",
        operation(
            "run",
            r#""keys_sign_cms""#,
            "cms",
            "[operations.uses.key.profile]\nattached = false\ntimestamp = \"none\""
        )
    );
    let cms = |attached: bool| {
        vec![(
            Import::KeysSignCms,
            abi::encode(&abi::SignCmsArgs {
                handle: 1,
                data: MESSAGE.to_vec().into(),
                attached,
                timestamp: false,
            }),
        )]
    };
    let mismatching = fixture(
        "test.declared",
        &manifest,
        &cms(true),
        vec![grant(&pki, "run", "keys_sign_cms", true)],
    );
    let service = start(&pki, mismatching.plugin.clone()).await;
    let (status, error) = call(&service, "test.declared", "run").await;
    assert_refused(status, &error, Some("options-mismatch"));
    assert_eq!(begins(&service), 0, "the key was never applied");
    service.stop().await;
    // The very same operation with the declared options signs.
    let matching = fixture(
        "test.declared",
        &manifest,
        &cms(false),
        vec![grant(&pki, "run", "keys_sign_cms", true)],
    );
    let service = start(&pki, matching.plugin.clone()).await;
    let (status, done) = call(&service, "test.declared", "run").await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["results"][0]["applied"], "Applied", "{done}");
    assert_eq!(begins(&service), 1);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_request_cannot_use_the_key_twice() {
    let pki = Pki::start();
    let manifest = format!(
        "{HEADER}{}",
        operation("run", r#""keys_sign_raw""#, "raw", "")
    );
    let mut calls = sign_raw();
    calls.extend(sign_raw());
    let f = fixture(
        "test.declared",
        &manifest,
        &calls,
        vec![grant(&pki, "run", "keys_sign_raw", true)],
    );
    let service = start(&pki, f.plugin.clone()).await;
    let (status, error) = call(&service, "test.declared", "run").await;
    // The first signature may be applied; the second is refused (never silently signed) and
    // the honest state is stated: a key was applied, the failure follows it.
    assert_eq!(status, 403, "{error}");
    assert_eq!(error["code"], "PermissionDenied", "{error}");
    assert_eq!(error["subcode"], "key-use-spent", "{error}");
    assert_eq!(error["applied"], "Applied", "the first use is not hidden");
    assert_matches_schema("ApiError", &error);
    assert_eq!(begins(&service), 1, "exactly one key use was admitted");
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plugin_without_declarations_is_unchanged_with_or_without_plugin_bytes() {
    let pki = Pki::start();
    let plain = r#"id = "test.plain"
name.ru = "synthetic"
name.kk = "synthetic"
name.en = "synthetic"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["test.plain.module"]
[capabilities]
keys = true
"#;
    for plugin_bytes in [false, true] {
        let f = fixture(
            "test.plain",
            plain,
            &sign_raw(),
            vec![grant(&pki, "run", "keys_sign_raw", plugin_bytes)],
        );
        let service = start(&pki, f.plugin.clone()).await;
        let (status, done) = call(&service, "test.plain", "run").await;
        assert_eq!(status, 200, "plugin_bytes={plugin_bytes}: {done}");
        assert_eq!(done["results"][0]["applied"], "Applied", "{done}");
        assert_eq!(begins(&service), 1);
        service.stop().await;
    }
}
