//! The patched copy of Velopack under `vendor/` is the one the lock file uses.
//!
//! A Velopack upgrade leaves a `[patch.crates-io]` entry of the old version unused (cargo
//! only warns), and the crate from crates.io would bring back an Update.exe taken from a
//! package rebuilt from a delta before anything checks it.

use oncl_testkit::workspace_root;

#[test]
fn locked_velopack_is_the_patched_copy() {
    let lock = std::fs::read_to_string(workspace_root().join("Cargo.lock")).unwrap();
    let lock: toml::Table = lock.parse().unwrap();
    let packages = lock["package"]
        .as_array()
        .expect("[[package]] in Cargo.lock");
    let velopack = packages
        .iter()
        .find(|p| p["name"].as_str() == Some("velopack"))
        .expect("velopack is not in Cargo.lock");
    assert_eq!(
        velopack.get("source").and_then(|s| s.as_str()),
        None,
        "velopack comes from a registry, not from vendor/: update the patched copy"
    );
    let manifest = std::fs::read_to_string(workspace_root().join("vendor/velopack/Cargo.toml"))
        .unwrap()
        .parse::<toml::Table>()
        .unwrap();
    assert_eq!(
        velopack["version"].as_str(),
        manifest["package"]["version"].as_str()
    );
}
