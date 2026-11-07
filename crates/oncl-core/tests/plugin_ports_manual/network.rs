//! A key operation declared with `network = "none"`: the engine validates the signer online
//! (the signer's OCSP responder, GET) and a CMS time-stamp asks the TSA, both through the
//! operation's PKI endpoints; with none declared nothing reaches them.
use crate::ports::*;
use oncl_core::plugins::PluginParam;

/// Every kind of key use of rating1c (raw, CMS, XML): with `network = "none"` the call is
/// refused with `PermissionDenied` BEFORE the key is applied, no HTTP request is made and no
/// typed refusal is recorded. So a key use with `network = "none"` can never sign in the
/// manual window; the parser may refuse the combination.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_key_operation_without_a_network_cannot_sign() {
    let doc = [("file", PluginParam::Document(b"the document"))];
    let xml = [("xml", PluginParam::Text("<r><a/></r>"))];
    for (operation, params) in [
        ("create-cms", &doc[..]),
        ("create-raw-sign", &doc[..]),
        ("sign-xml", &xml[..]),
    ] {
        let options = RunOptions::tampered(operation, "network = \"pki\"", "network = \"none\"");
        let run = run_port_operation("rating1c", operation, params, &options);
        assert_eq!(
            run.call.applied(),
            AppliedState::NotApplied,
            "{operation}: {:?}",
            run.call
        );
        assert_eq!(run.applications, 0, "{operation}");
        assert!(run.http_log.is_empty(), "{operation}: {:?}", run.http_log);
        assert!(
            run.call.refusals().is_empty(),
            "{operation}: {:?}",
            run.call.refusals()
        );
        assert!(
            matches!(run.call.error(), Some(e) if e.code() == oncl_core::ErrorCode::PermissionDenied),
            "{operation}: {:?}",
            run.call
        );
    }
}
