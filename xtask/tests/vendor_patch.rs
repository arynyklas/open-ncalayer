//! The patched copy of Slint's winit backend under `vendor/` is the one the lock file uses.
//!
//! A Slint upgrade leaves a `[patch.crates-io]` entry of the old version unused (cargo only
//! warns), and the backend from crates.io would bring back its static import of
//! `SystemParametersInfoForDpi`, which Windows 7 does not have.

use oncl_testkit::workspace_root;

/// `(version, source)` of the locked package `name`.
fn locked(lock: &toml::Table, name: &str) -> (String, Option<String>) {
    let packages = lock["package"]
        .as_array()
        .expect("[[package]] in Cargo.lock");
    let package = packages
        .iter()
        .find(|p| p["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{name} is not in Cargo.lock"));
    (
        package["version"].as_str().unwrap().to_owned(),
        package
            .get("source")
            .and_then(|s| s.as_str())
            .map(str::to_owned),
    )
}

#[test]
fn locked_slint_winit_backend_is_the_patched_copy() {
    let lock = std::fs::read_to_string(workspace_root().join("Cargo.lock")).unwrap();
    let lock: toml::Table = lock.parse().unwrap();
    let (backend, source) = locked(&lock, "i-slint-backend-winit");
    assert_eq!(
        source, None,
        "i-slint-backend-winit comes from {source:?}, not from vendor/: update the patched copy"
    );
    let (core, _) = locked(&lock, "i-slint-core");
    assert_eq!(backend, core, "the patched backend is not Slint's version");
}
