//! The committed third-party licences of the About window (`crates/oncl-ui/assets/
//! THIRD-PARTY.txt`) match `cargo xtask licenses`.

use oncl_testkit::workspace_root;

#[test]
fn committed_licenses_are_fresh() {
    assert!(
        xtask::licenses::check(&workspace_root()).unwrap(),
        "{} is stale: run `cargo xtask licenses`",
        xtask::licenses::OUTPUT
    );
}
