//! The ports' workspace: it builds, every port packages and loads, every registry entry
//! matches its manifest.

use oncl_pdk::abi::Import;
use oncl_plugin::{Engine, Manifest, Package};
use oncl_port_tests::{CONFORMANCE, Registry, STATUSES, port_package};
use oncl_testkit::plugin::{port_dirs, ports_built};

/// The short name of a port directory.
fn short(dir: &std::path::Path) -> String {
    dir.file_name().unwrap().to_string_lossy().into_owned()
}

#[test]
fn ports_workspace_builds_for_wasm32() {
    let built = ports_built();
    assert!(built.is_dir(), "{} is not built", built.display());
    for dir in port_dirs() {
        let wasm = oncl_testkit::plugin::port_wasm(&short(&dir));
        assert!(wasm.is_file(), "{} is missing", wasm.display());
    }
}

#[test]
fn every_port_package_is_valid() {
    for dir in port_dirs() {
        let short = short(&dir);
        let package =
            Package::read(&port_package(&short)).unwrap_or_else(|e| panic!("{short}: {e}"));
        let compiled = Engine::new()
            .compile(&package.manifest, &package.wasm)
            .unwrap_or_else(|e| panic!("{short}: {e}"));
        let newest = compiled.imports().iter().map(Import::since).max();
        if let Some(newest) = newest {
            assert!(
                package.manifest.min_core >= newest,
                "{short}: min_core below {newest}"
            );
        }
        assert!(
            package.manifest.id == format!("io.github.arynyklas.openncalayer.port.{short}"),
            "{short}: id {}",
            package.manifest.id
        );
    }
}

#[test]
fn registry_files_parse() {
    for dir in port_dirs() {
        let short = short(&dir);
        let manifest = Manifest::from_toml(
            &String::from_utf8(oncl_testkit::read(dir.join("plugin.toml"))).unwrap(),
        )
        .unwrap_or_else(|e| panic!("{short}: {e}"));
        let text = String::from_utf8(oncl_testkit::read(dir.join("registry.toml"))).unwrap();
        let registry: Registry = toml::from_str(&text).unwrap_or_else(|e| panic!("{short}: {e}"));
        assert_eq!(registry.id, manifest.id, "{short}");
        assert_eq!(registry.modules, manifest.modules, "{short}");
        let replaces = manifest
            .replaces
            .as_ref()
            .expect("a port replaces a bundle");
        assert_eq!(registry.original.symname, replaces.symname, "{short}");
        assert_eq!(registry.original.version, replaces.version, "{short}");
        assert!(STATUSES.contains(&registry.port.status.as_str()), "{short}");
        assert!(
            CONFORMANCE.contains(&registry.port.conformance.as_str()),
            "{short}"
        );
    }
}

#[test]
fn registry_schema_reads_the_example_entry() {
    let registry: Registry = toml::from_str(
        r#"
id = "io.github.arynyklas.openncalayer.port.nursign"
modules = ["NURSign"]
[original]
symname = "kz.ecc.NurSignBundle"
version = "5.1.2"
vendor = "АО «Центр электронных финансов»"
[port]
status = "partial"
conformance = "computed"
[[differences]]
ru = "Окно выбора ключа — общее окно OpenNCALayer."
"#,
    )
    .unwrap();
    assert_eq!(registry.differences.len(), 1);
    assert!(toml::from_str::<Registry>("id = 1").is_err());
}

#[test]
fn harness_runs_a_package() {
    let harness = oncl_port_tests::Harness::new(vec![], vec![]);
    let mut session = harness.session_of(&oncl_testkit::plugin::example_package());
    let call = |method: &str| {
        serde_json::json!({"module": "io.github.arynyklas.openncalayer.Example", "class": "Example",
            "method": method, "args": {"text": "hi"}})
        .to_string()
    };
    assert_eq!(
        session.call(&call("echo"), Some("https://a.kz")),
        r#"{"status":true,"body":"hi"}"#
    );
    // The instance keeps its state between the calls of a session.
    session.call(&call("count"), None);
    let second = session.call(&call("count"), None);
    assert_eq!(second, r#"{"status":true,"body":2}"#);
    assert!(harness.http_log().is_empty());
}
