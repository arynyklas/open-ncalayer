//! A manifest's own version is bounded: it is written to audit records.
use oncl_plugin::Manifest;

fn manifest(version: &str) -> String {
    format!(
        r#"id = "test.version"
name.ru = "x"
name.kk = "x"
name.en = "x"
version = "{version}"
min_core = "0.1.0-alpha.7"
modules = ["test.version.module"]
"#
    )
}

#[test]
fn a_version_over_64_characters_is_refused_at_parse() {
    assert!(Manifest::from_toml(&manifest("1.2.3")).is_ok());
    let at_limit = format!("1.2.3-{}", "a".repeat(64 - 6));
    assert_eq!(at_limit.len(), 64);
    assert!(Manifest::from_toml(&manifest(&at_limit)).is_ok());
    let over = format!("1.2.3-{}", "a".repeat(300));
    assert!(Manifest::from_toml(&manifest(&over)).is_err());
    assert!(Manifest::from_toml(&manifest(&format!("{at_limit}a"))).is_err());
}
