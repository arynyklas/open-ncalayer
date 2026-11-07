//! `kz.dogovor24.module`: `signCMS` (an attached CMS with Kalkan's time-stamp). `batchSignCMS`
//! and `signEsedo` are not declared (inventory MP0: `MULTI`, `OPTIONS`).
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::PluginParam;

const PORT: &str = "dogovor24";
const DOC: &[u8] = b"Dogovor24: the contract the user approved";

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    run_port_operation(PORT, operation, &[("file", PluginParam::Document(DOC))], options)
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_cms_is_an_attached_time_stamped_cms() {
    let run = run_operation("sign-cms", &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({
            "module": "kz.dogovor24.module",
            "method": "signCMS",
            "args": [base64_of(DOC)]
        }),
    );
    let reply = reply_json(&run);
    assert_eq!(reply["code"], "200", "{reply} {:?}", run.http_log);
    let cms = from_base64(reply["responseObject"].as_str().unwrap());
    assert_cms(&run, &cms, DOC, true, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_field_is_refused_before_the_key() {
    let tampers = vec![
        cms_tamper("sign-cms", "", true, true),
        (
            "sign-cms".to_owned(),
            "encapsulate = true".to_owned(),
            "encapsulate = false".to_owned(),
        ),
    ];
    assert_tampers_refused(&tampers, &run_operation);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    assert_every_import_needed(PORT, &["sign-cms".to_owned()], &run_operation);
}
