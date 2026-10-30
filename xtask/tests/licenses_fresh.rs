//! The committed third-party licences of the About window (`crates/oncl-ui/assets/
//! THIRD-PARTY.txt`) match `cargo xtask licenses`, those of the plugin ports
//! (`plugins/THIRD-PARTY.txt`) `cargo xtask licenses --plugins`.
//!
//! The generator works offline from the local cargo registry, which a normal build fills
//! only with the host's packages. Without the other platforms' packages the check is
//! skipped (with a note) on a developer's machine; in CI (`CI` set, after
//! `cargo fetch --locked`) it fails instead.

use oncl_testkit::workspace_root;
use xtask::licenses::{OUTPUT, PLUGINS_OUTPUT, PackagesMissing, check, check_plugins};

#[test]
fn committed_licenses_are_fresh() {
    match check(&workspace_root()) {
        Ok(fresh) => assert!(fresh, "{OUTPUT} is stale: run `cargo xtask licenses`"),
        Err(e) if e.is::<PackagesMissing>() && std::env::var_os("CI").is_none() => {
            eprintln!("{OUTPUT} not checked: {e}");
        }
        Err(e) => panic!("{e:#}"),
    }
}

#[test]
fn committed_plugin_licenses_are_fresh() {
    match check_plugins(&workspace_root()) {
        Ok(fresh) => assert!(
            fresh,
            "{PLUGINS_OUTPUT} is stale: run `cargo xtask licenses --plugins`"
        ),
        Err(e) if e.is::<PackagesMissing>() && std::env::var_os("CI").is_none() => {
            eprintln!("{PLUGINS_OUTPUT} not checked: {e}");
        }
        Err(e) => panic!("{e:#}"),
    }
}
