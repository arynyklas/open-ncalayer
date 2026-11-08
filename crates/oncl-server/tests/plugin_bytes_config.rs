//! `plugin_bytes` of a plugin grant (docs/design/manual-plugins.md 4.7, R14): the operator's
//! explicit acceptance that a granted plugin operation may use a key to sign bytes the
//! plugin or its client chose. Off unless written.
use oncl_server::config::ServerConfig;

fn parse(grant: &str) -> Result<ServerConfig, toml::de::Error> {
    toml::from_str(&format!(
        r#"
[[tokens]]
id = "svc"
verifier = "{verifier}"
actions = ["sign"]
keys = ["ops"]

[[plugins]]
id = "vendor.sign"
manifest = "/etc/oncl-server/plugins/sign.toml"
wasm = "/etc/oncl-server/plugins/sign.wasm"

[[plugins.permissions]]
token = "svc"
operation = "sign-file"
imports = ["keys_sign_raw"]
{grant}
"#,
        verifier = "0".repeat(64)
    ))
}

#[test]
fn plugin_bytes_is_off_unless_written() {
    let config = parse(r#"keys = ["ops"]"#).unwrap();
    assert!(!config.plugins[0].permissions[0].plugin_bytes);
}

#[test]
fn plugin_bytes_true_is_read_and_validates_with_a_key() {
    let config = parse("keys = [\"ops\"]\nplugin_bytes = true").unwrap();
    assert!(config.plugins[0].permissions[0].plugin_bytes);
    config
        .validate()
        .expect("a key grant with plugin_bytes is valid");
}

#[test]
fn plugin_bytes_must_be_a_boolean() {
    for bad in ["\"yes\"", "1", "\"true\"", "[true]"] {
        assert!(
            parse(&format!("keys = [\"ops\"]\nplugin_bytes = {bad}")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn plugin_bytes_without_a_key_is_refused_by_validation() {
    let config = parse("plugin_bytes = true").unwrap();
    assert!(
        config.validate().is_err(),
        "bytes signed with a key need a key in the grant"
    );
    // The default (false) without keys is the old keyless grant and stays valid.
    parse("").unwrap().validate().unwrap();
}

#[test]
fn a_plugin_bytes_grant_needs_a_segment_that_holds_one_plugin_use() {
    let minimum = oncl_server::audit::PLUGIN_MIN_SEGMENT_BYTES;
    let mut config = parse("keys = [\"ops\"]\nplugin_bytes = true").unwrap();
    config.audit_segment_bytes = minimum - 1;
    assert!(
        config.validate().is_err(),
        "a segment below {minimum} bytes"
    );
    config.audit_segment_bytes = minimum;
    config.validate().expect("the minimum is enough");
    // Without a plugin_bytes grant the smaller (older) sizes stay valid.
    let mut plain = parse(r#"keys = ["ops"]"#).unwrap();
    plain.audit_segment_bytes = 1024;
    plain.validate().expect("no plugin key bytes granted");
}
