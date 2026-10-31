//! The example plugin of `crates/oncl-pdk/example`, built with the guest SDK, in the
//! runtime: its CommonInvoker dialect, its state, and what happens when it misbehaves.

mod common;

use common::*;
use oncl_plugin::{Engine, Instance, Manifest, Package, PluginError};
use oncl_protocol::AddInfo;
use oncl_testkit::plugin::{example_package, example_wasm};
use serde_json::{Value, json};

fn example_manifest() -> Manifest {
    Manifest::from_toml(&oncl_testkit::plugin::example_manifest()).unwrap()
}

fn example_with(engine: &Engine) -> Instance {
    let wasm = oncl_testkit::read(example_wasm());
    engine
        .compile(&example_manifest(), &wasm)
        .unwrap()
        .instantiate(&services(), session(1))
        .unwrap()
}

fn example() -> Instance {
    example_with(&Engine::new())
}

/// A CommonInvoker request to the class `Example`.
fn call(method: &str, args: Value) -> String {
    json!({"module": "io.github.arynyklas.openncalayer.Example", "class": "Example", "method": method, "args": args})
        .to_string()
}

fn reply(instance: &mut Instance, method: &str, args: Value) -> Value {
    let reply = instance
        .process(&call(method, args), &from("https://a.kz"))
        .unwrap();
    serde_json::from_str(reply.text().unwrap()).unwrap()
}

#[test]
fn echo_roundtrip() {
    let mut instance = example();
    assert_eq!(
        instance.process(&call("echo", json!({"text": "hi"})), &from("https://a.kz")),
        Ok(r#"{"body":"hi","status":true}"#.into())
    );
}

#[test]
fn unknown_method_uses_invoker_dialect() {
    let mut instance = example();
    let request = call("nope", json!({}));
    let expected = oncl_protocol::invoker::invoke(&request, &AddInfo::default(), &[&NoMethods]);
    let reply = instance.process(&request, &from("o")).unwrap();
    assert_eq!(reply, expected);
    let reply: Value = serde_json::from_str(reply.text().unwrap()).unwrap();
    assert_eq!(reply["status"], false);
    assert_eq!(reply["code"], "GENERAL_ERROR");
    // Not JSON at all: the same dialect.
    let reply: Value =
        serde_json::from_str(instance.process("[", &from("o")).unwrap().text().unwrap()).unwrap();
    assert_eq!(reply["code"], "GENERAL_ERROR");
}

/// A class `Example` without methods: what the invoker answers for an unknown method.
struct NoMethods;

impl oncl_protocol::invoker::NlClass for NoMethods {
    fn class_name(&self) -> &'static str {
        "Example"
    }

    fn call(
        &self,
        _: &str,
        _: Option<&serde_json::Map<String, Value>>,
        _: &AddInfo,
    ) -> Option<oncl_protocol::invoker::CallResult> {
        None
    }
}

#[test]
fn state_lives_in_the_instance() {
    let mut instance = example();
    assert_eq!(reply(&mut instance, "count", json!({}))["body"], 1);
    assert_eq!(reply(&mut instance, "count", json!({}))["body"], 2);
    let mut fresh = example();
    assert_eq!(reply(&mut fresh, "count", json!({}))["body"], 1);
    assert_eq!(reply(&mut instance, "count", json!({}))["body"], 3);
}

#[test]
fn origin_reaches_the_guest() {
    let mut instance = example();
    let reply: Value = serde_json::from_str(
        &instance
            .process(&call("origin", json!({})), &from("https://idp.egov.kz"))
            .unwrap()
            .into_text()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["body"], "https://idp.egov.kz");
    let none: Value = serde_json::from_str(
        &instance
            .process(&call("origin", json!({})), &AddInfo::default())
            .unwrap()
            .into_text()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(none["body"], Value::Null);
}

#[test]
fn spin_is_stopped_by_fuel() {
    let mut instance = example_with(&Engine::new().with_process_fuel(50_000_000));
    assert_eq!(
        instance.process(&call("spin", json!({})), &from("o")),
        Err(PluginError::OutOfFuel)
    );
}

#[test]
fn grow_is_stopped_by_memory_limit() {
    let mut instance = example();
    assert_eq!(
        instance.process(&call("grow", json!({})), &from("o")),
        Err(PluginError::MemoryLimit)
    );
}

#[test]
fn panic_becomes_plugin_error() {
    let mut instance = example();
    assert!(matches!(
        instance.process(&call("panic", json!({})), &from("o")),
        Err(PluginError::Trap(_))
    ));
}

#[test]
fn failed_instance_is_not_reused() {
    let mut instance = example();
    assert_eq!(reply(&mut instance, "count", json!({}))["body"], 1);
    assert!(
        instance
            .process(&call("panic", json!({})), &from("o"))
            .is_err()
    );
    assert_eq!(
        instance.process(&call("count", json!({})), &from("o")),
        Err(PluginError::Poisoned)
    );
    assert_eq!(
        instance.process(&call("echo", json!({"text": "hi"})), &from("o")),
        Err(PluginError::Poisoned)
    );
}

#[test]
fn example_package_is_a_valid_package() {
    let package = Package::read(&example_package()).unwrap();
    assert_eq!(package.manifest, example_manifest());
    assert_eq!(
        package.manifest.id,
        "io.github.arynyklas.openncalayer.example"
    );
    let replaces = package.manifest.replaces.as_ref().unwrap();
    assert_eq!(
        (replaces.symname.as_str(), replaces.version.as_str()),
        ("kz.example.echo", "1.0.0")
    );
    Engine::new()
        .compile(&package.manifest, &package.wasm)
        .unwrap();
}
