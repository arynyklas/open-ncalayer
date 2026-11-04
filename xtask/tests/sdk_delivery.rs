//! Guards of the SDK delivery evidence (docs/dev/sdk.md): no network, no builds, only
//! `cargo metadata` / `cargo tree` of the real workspace.
use std::collections::{BTreeSet, HashMap};

use xtask::licenses::Package;
use xtask::sdk_delivery::{
    CHAIN, chain_problems, closure_report, inventory_is_current, licenses, pick_packages,
};

#[test]
fn publishable_crates_are_exactly_the_chain_in_dependency_order() {
    let problems = chain_problems(&oncl_testkit::workspace_root()).unwrap();
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(CHAIN.last(), Some(&"oncl-core"));
}

#[test]
fn sdk_closures_contain_no_ui_desktop_updater_server_or_runtime_crate() {
    // `closure_report` fails naming the offending crates of any feature set.
    let report = closure_report(&oncl_testkit::workspace_root()).unwrap();
    assert!(report.contains("| minimal |"), "{report}");
    assert!(report.contains("| full |"), "{report}");
}

#[test]
fn committed_inventory_is_current_and_a_stale_copy_is_detected() {
    let root = oncl_testkit::workspace_root();
    let expected = licenses(&root).unwrap();
    let committed = root.join(xtask::sdk_delivery::LICENSES_OUTPUT);
    assert!(
        inventory_is_current(&committed, &expected),
        "{} is stale: run `cargo xtask sdk licenses`",
        xtask::sdk_delivery::LICENSES_OUTPUT
    );
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("THIRD-PARTY.txt");
    std::fs::write(&copy, &expected).unwrap();
    assert!(inventory_is_current(&copy, &expected));
    std::fs::write(&copy, expected.replacen("aes ", "aes-stale ", 1)).unwrap();
    assert!(!inventory_is_current(&copy, &expected));
    assert!(!inventory_is_current(
        &dir.path().join("absent.txt"),
        &expected
    ));
}

#[test]
fn a_closure_crate_missing_from_the_registry_is_an_error_naming_it() {
    let package = |name: &str| Package {
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        authors: vec![],
        license: Some("MIT".to_owned()),
        license_file: None,
        repository: None,
        dir: std::path::PathBuf::new(),
    };
    let key = |name: &str| (name.to_owned(), "1.0.0".to_owned());
    let wanted: BTreeSet<_> = [key("present"), key("gone"), key("oncl-core")].into();
    let packages: HashMap<_, _> = [(key("present"), package("present"))].into();
    let error = pick_packages(wanted.clone(), packages.clone()).unwrap_err();
    assert!(error.to_string().contains("gone 1.0.0"), "{error}");
    assert!(!error.to_string().contains("oncl-core"), "{error}");

    let mut complete = packages;
    complete.insert(key("gone"), package("gone"));
    assert_eq!(pick_packages(wanted, complete).unwrap().len(), 2);
}
