//! A key operation declared with `network = "none"` (MP1b): the engine validates the signer
//! online (the signer's OCSP responder, GET) and a CMS time-stamp asks the TSA, both through
//! the operation's PKI endpoints, so with none declared the key use could never sign. The
//! manifest parser refuses the combination, and no operation of such a manifest exists.
use crate::ports::*;
use oncl_plugin::PackageError;
use oncl_plugin::operations::OperationError;

/// Every kind of key use of rating1c (raw, CMS, XML): with `network = "none"` the manifest is
/// refused at parse with the typed `NetworkNeeded` error, so no operation can be
/// built from it and nothing can reach the key.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_key_operation_without_a_network_cannot_be_declared() {
    let original = manifest_text("rating1c");
    for operation in ["create-cms", "create-raw-sign", "sign-xml"] {
        let tamper = RunOptions::tampered(operation, "network = \"pki\"", "network = \"none\"");
        let text = (tamper.tamper.unwrap())(&original);
        assert_ne!(text, original, "{operation}");
        match oncl_plugin::Manifest::from_toml(&text) {
            Err(PackageError::Operation(OperationError::NetworkNeeded {
                operation: name,
                why,
            })) => {
                assert_eq!(name, operation);
                assert!(
                    why.contains("needs network = \"pki\""),
                    "{operation}: {why}"
                );
            }
            Err(other) => panic!("{operation}: another refusal: {other:?}"),
            Ok(manifest) => panic!(
                "{operation}: parsed, {} operations",
                manifest.operations().len()
            ),
        }
    }
}
