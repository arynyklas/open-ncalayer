//! `kz.energy.sign.SignEnergy`: `sign` with one document (the template's 1-element `data`
//! list, `alias` omitted, `isDigested = false`), four variants: attached or detached, with or
//! without Kalkan's time-stamp.
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::PluginParam;

const PORT: &str = "energy";
const DOC: &[u8] = b"Tezis (energy.kz): the document the user approved";

fn operation(suffix: &str) -> String {
    format!("sign-cms-{suffix}")
}

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    run_port_operation(PORT, operation, &[("file", PluginParam::Document(DOC))], options)
}

fn cms_run(suffix: &str, attached: bool, timestamped: bool) {
    let run = run_operation(&operation(suffix), &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({
            "module": "kz.energy.sign.SignEnergy",
            "method": "sign",
            "args": {
                "encapsulate": attached,
                "isDigested": false,
                "tsaProfile": timestamped,
                "data": [{"id": "1", "name": "document", "base64": base64_of(DOC)}]
            }
        }),
    );
    let reply = reply_json(&run);
    assert_eq!(reply["success"], true, "{reply} {:?}", run.http_log);
    let item = &reply["body"]["result"][0];
    assert_eq!(item["id"], "1");
    assert_eq!(item["name"], "document");
    let cms = from_base64(item["signedBase64"].as_str().unwrap());
    assert_cms(&run, &cms, DOC, attached, timestamped);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_attached_with_a_time_stamp() {
    cms_run("attached-timestamp", true, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_attached() {
    cms_run("attached", true, false);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_detached_with_a_time_stamp() {
    cms_run("detached-timestamp", false, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_detached() {
    cms_run("detached", false, false);
}

fn operations() -> Vec<String> {
    CMS_VARIANTS.iter().map(|(s, ..)| operation(s)).collect()
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_field_is_refused_before_the_key() {
    let tampers: Vec<_> = CMS_VARIANTS
        .iter()
        .map(|(s, a, t)| cms_tamper(&operation(s), "content = \"param:file\"", *a, *t))
        .collect();
    assert_tampers_refused(&tampers, &run_operation);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    assert_every_import_needed(PORT, &operations(), &run_operation);
}
