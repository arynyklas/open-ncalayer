//! Probe: replace it with the declaration when MP1b's template lands.
//! `kz.fhs.cabinet.FHSCabinetSigner` (V1 `signXml`, `signText`): NOT declared in the first
//! release. The module's dispatcher (`oncl_pdk::invoker::java::invoke_with`,
//! crates/oncl-protocol/src/invoker/java.rs:125-176) reads `args` with `optJSONObject`: the
//! method's one parameter is a JSON OBJECT (`"args":{"xml":..}`); the `[[operations]]` template
//! has an `args` ARRAY only. The probe shows the module's answer to the array.
use crate::ports::*;
use oncl_core::plugins::PluginParam;

const PROBE: &str = r#"
[[operations]]
name = "probe"
module = "kz.fhs.cabinet.FHSCabinetSigner"
manual = true
request = '{"module":"kz.fhs.cabinet.FHSCabinetSigner","method":"signXml","args":["{xml}"]}'
label = { ru = "а", kk = "ә", en = "a" }

[[operations.params]]
name = "xml"
kind = "text"
max_chars = 1000

[operations.uses]
imports = ["keys_select", "keys_release", "random", "cert_info", "cert_details", "keys_sign_xml"]
network = "pki"

[[operations.uses.key]]
kind = "xml"
content = "param:xml"
"#;

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn an_args_array_is_not_the_args_object_the_dispatcher_reads() {
    let options = RunOptions {
        tamper: Some(Box::new(|text| {
            format!(
                "{}\n{PROBE}",
                crate::ports::with_min_core(text, "0.1.0-alpha.7")
            )
        })),
        key: None,
    };
    let run = run_port_operation(
        "fhs",
        "probe",
        &[("xml", PluginParam::Text("<r/>"))],
        &options,
    );
    assert_eq!(
        run.call.applied(),
        AppliedState::NotApplied,
        "{:?}",
        run.call
    );
    assert_eq!(run.applications, 0);
    assert!(
        run.reply().contains("signXml demands arguments"),
        "{}",
        run.reply()
    );
}
