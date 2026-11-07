//! Probe: replace it with the declaration when MP1b's template lands.
//! `com.osdkz.esf.signer.esfSigner` (`signPlainData`): NOT declared in the first release.
//!
//! The port reads `method`, `storageName` and `data` from the TOP LEVEL of the request
//! (plugins/esf-osdkz/src/lib.rs:36-60), and signs a TEXT with a raw signature; the template of
//! `[[operations]]` is `{"module","method","args":[..]}` and a text is content only for the XML
//! kinds. This probe declares the closest template there is, on a copy of the manifest, and
//! shows what the module does with it: it drops the request (`reply_drop`), nothing is signed.
use crate::ports::*;
use oncl_core::plugins::PluginParam;

const PROBE: &str = r#"
[[operations]]
name = "probe"
module = "com.osdkz.esf.signer.esfSigner"
manual = true
request = '{"module":"com.osdkz.esf.signer.esfSigner","method":"signPlainData","args":["PKCS12","{file:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }

[[operations.params]]
name = "file"
kind = "document"

[operations.uses]
imports = ["keys_select", "keys_release", "random", "cert_info", "cert_details", "reply_drop", "keys_sign_raw"]
network = "pki"

[[operations.uses.key]]
kind = "raw"
content = "param:file"
"#;

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_template_shape_does_not_reach_the_port_s_top_level_fields() {
    let options = RunOptions {
        tamper: Some(Box::new(|text| {
            format!(
                "{}\n{PROBE}",
                crate::ports::with_min_core(text, "0.1.0-alpha.7")
            )
        })),
        key: None,
        ..RunOptions::default()
    };
    let run = run_port_operation(
        "esf-osdkz",
        "probe",
        &[("file", PluginParam::Document(b"text"))],
        &options,
    );
    // The request is what the template builds: module, method, args and no `storageName`.
    let request: serde_json::Value = serde_json::from_str(&run.request).unwrap();
    assert!(
        request.get("storageName").is_none() && request.get("data").is_none(),
        "{request}"
    );
    // The port found no `storageName`/`data`: it dropped the request, the key was not used.
    assert_eq!(
        run.call.applied(),
        AppliedState::NotApplied,
        "{:?}",
        run.call
    );
    assert_eq!(run.applications, 0);
    assert!(
        run.reply().is_empty(),
        "a dropped request has no reply: {}",
        run.reply()
    );
}
