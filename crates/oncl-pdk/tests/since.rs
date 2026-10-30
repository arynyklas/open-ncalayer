//! The core version each host function appeared in: a plugin importing it needs a `min_core`
//! of at least that.

use oncl_pdk::abi::Import;
use semver::Version;

/// The first core with plugins.
const FIRST_PLUGIN_CORE: &str = "0.1.0-alpha.3";

#[test]
fn every_import_has_since() {
    let first = Version::parse(FIRST_PLUGIN_CORE).unwrap();
    for import in Import::ALL {
        assert!(import.since() >= first, "{}", import.name());
        assert_eq!(Import::from_name(import.name()), Some(import));
    }
    assert_eq!(Import::ReplyDrop.name(), "reply_drop");
    assert_eq!(Import::ReplyDrop.capability(), None);
}

#[test]
fn since_is_not_newer_than_the_workspace() {
    let workspace = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    for import in Import::ALL {
        assert!(
            import.since() <= workspace,
            "{} appeared in {}, after the workspace's {workspace}",
            import.name(),
            import.since()
        );
    }
}
