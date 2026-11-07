//! A key operation declared with `network = "none"`: the engine validates the signer online
//! (the signer's OCSP responder, GET) and a CMS time-stamp asks the TSA, both through the
//! operation's PKI endpoints; with none declared nothing reaches them.
use crate::ports::*;

/// Every kind of key use of rating1c (raw, CMS, XML): a key operation with `network = "none"`
/// can never sign in the manual window (the call would be refused before the key), so the
/// manifest parser refuses the combination (MP1b) and the operation cannot even be declared.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_key_operation_without_a_network_cannot_be_declared() {
    for operation in ["create-cms", "create-raw-sign", "sign-xml"] {
        let text = manifest_text("rating1c");
        let start = text.find(&format!("name = \"{operation}\"\n")).unwrap();
        let end = text[start..]
            .find("\n[[operations]]")
            .map_or(text.len(), |n| start + n);
        let at = start + text[start..end].find("network = \"pki\"").unwrap();
        let edited = format!(
            "{}network = \"none\"{}",
            &text[..at],
            &text[at + "network = \"pki\"".len()..]
        );
        let error = oncl_plugin::Manifest::from_toml(&edited)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("a key operation needs network = \"pki\""),
            "{operation}: {error}"
        );
    }
}
