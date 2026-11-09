//! `kz.qiwi.osgi.SecurityUtils`: `signXml` as two declared operations, one per key algorithm
//! (`sign-xml-rsa`, `sign-xml-gost2004`). The module takes its signature and digest URIs from
//! the certificate of the key the user picks and passes `transforms = [Enveloped,
//! C14N-with-comments]` with the signature as the first child of the document; each operation
//! declares those and nothing else, so a key of the other algorithm makes the module call the
//! key import with a profile the declaration does not say: Core refuses it before the key.
//! A GOST 2015 key gets the GOST 2004 URIs from the module and is refused by the signer.
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::{PluginParam, PluginRefusalCode, TicketRefusal};
use oncl_plugin::operations::{KeyKind, Profile};

const PORT: &str = "qiwi";
const XML: &str = "<r xmlns=\"urn:q\"><a Id=\"a1\">1</a><b>два</b></r>";
const RSA_KEY: &str = "user-rsa-sign";
const GOST2004_KEY: &str = "user-gost2004-sign";
const GOST2015_KEY: &str = "user-gost2015-sign";
const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>";

/// The key fixture each operation is for.
fn key_of(operation: &str) -> Option<&'static str> {
    Some(match operation {
        "sign-xml-gost2004" => GOST2004_KEY,
        _ => RSA_KEY,
    })
}

/// `options` carry the key (the kit sets it by `key_of`) and the tamper, if any.
fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    run_port_operation(PORT, operation, &[("xml", PluginParam::Text(XML))], options)
}

fn run_with(operation: &str, key: &'static str) -> PortRun {
    run_operation(
        operation,
        &RunOptions {
            key: Some(key),
            ..RunOptions::default()
        },
    )
}

fn reply_of(run: &PortRun) -> serde_json::Value {
    let reply = reply_json(run);
    assert_eq!(reply["code"], "200", "{reply} {:?}", run.http_log);
    reply
}

/// The reply's `signedXml` and the checks both operations share.
fn signed_of(run: &PortRun) -> String {
    assert_applied(run);
    assert_request(
        run,
        serde_json::json!({
            "module": "kz.qiwi.osgi.SecurityUtils",
            "method": "signXml",
            "args": ["1", XML]
        }),
    );
    assert_eq!(run.summary.kind, KeyKind::XmlEx);
    assert!(matches!(run.summary.profile, Profile::XmlEx(_)));
    let reply = reply_of(run);
    let result = &reply["responseObject"];
    assert_eq!(result["callID"], "1");
    assert_eq!(result["verificationResult"], true, "{reply}");
    assert_eq!(result["logOutResult"], false);
    let signed = result["signedXml"].as_str().expect("signedXml").to_owned();
    assert!(signed.starts_with(DECLARATION), "{signed}");
    // The signature is the last child of the first node (the document element), after `b`.
    assert!(signed.contains("</b><ds:Signature"), "{signed}");
    assert!(
        signed.trim_end().ends_with("</ds:Signature></r>"),
        "{signed}"
    );
    signed
}

const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_rsa_signs_with_an_rsa_key_and_the_signature_verifies_independently() {
    let run = run_with("sign-xml-rsa", RSA_KEY);
    let signed = signed_of(&run);
    // lxml + cryptography, not OpenNCALayer's verifier (it runs as well).
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    let signature = &facts.json["signatures"][0];
    assert_eq!(facts.referenced_nodes(), ["r"], "{:?}", facts.json);
    assert_eq!(
        signature["signature_method"],
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    );
    assert_eq!(signature["c14n"], C14N);
    let reference = &signature["references"][0];
    assert_eq!(reference["uri"], "");
    assert_eq!(
        reference["transforms"],
        serde_json::json!([ENVELOPED, C14N_COMMENTS])
    );
    assert_eq!(
        reference["digest_method"],
        "http://www.w3.org/2001/04/xmlenc#sha256"
    );
    assert_eq!(
        without_signature(&signed).trim_start_matches(DECLARATION),
        XML
    );
    oracle::assert_xml_rejected(signed.replace("два", "три").as_bytes(), &run.cert);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_gost2004_signs_with_a_gost_2004_key() {
    let run = run_with("sign-xml-gost2004", GOST2004_KEY);
    let signed = signed_of(&run);
    // The XML oracle checks RSA only: the repository's verifier says it is a GOST 2004
    // signature of this key, over the document, and refuses the changed one.
    let infos = oncl_xml::verify(signed.as_bytes()).expect("the signature verifies");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].sig_alg, oncl_pki::key::SigAlg::Gost2004);
    assert_eq!(infos[0].cert, run.cert);
    assert!(
        signed.contains("xmldsig-more#gost34310-gost34311"),
        "{signed}"
    );
    assert!(signed.contains("xmldsig-more#gost34311"), "{signed}");
    assert!(oncl_xml::verify(signed.replace("два", "три").as_bytes()).is_err());
}

/// A key of the other algorithm: the module chooses its URIs from the key's certificate, so
/// the call differs from the declaration and Core refuses it before the key is used.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_key_of_the_other_algorithm_is_refused_before_the_key() {
    for (operation, key) in [
        ("sign-xml-rsa", GOST2004_KEY),
        ("sign-xml-gost2004", RSA_KEY),
    ] {
        let run = run_with(operation, key);
        assert_refused_before_the_key(&run);
        assert_eq!(
            run.call.refusals(),
            [TicketRefusal::Options],
            "{operation} {key}"
        );
        assert_eq!(
            run.call.subcode(),
            Some(PluginRefusalCode::OptionsMismatch),
            "{operation} {key}"
        );
        assert!(run.call.response().is_none(), "{operation} {key}");
    }
}

/// A GOST 2015 key is not supported by either operation: the module sends it the GOST 2004
/// URIs (declared by `sign-xml-gost2004`), the signing engine does not take a 2004 method for a
/// 2015 key and the call ends with an error before the key is used: no signature, no reply.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_gost_2015_key_is_refused_before_the_key() {
    for operation in ["sign-xml-gost2004", "sign-xml-rsa"] {
        let run = run_with(operation, GOST2015_KEY);
        assert_eq!(
            run.call.applied(),
            AppliedState::NotApplied,
            "{operation}: {:?}",
            run.call
        );
        assert_eq!(run.applications, 0, "{operation}: no key use");
        assert!(run.call.response().is_none(), "{operation}: {:?}", run.call);
        assert!(
            matches!(run.call.error(), Some(e) if e.code() == oncl_core::ErrorCode::InvalidInput),
            "{operation}: {:?}",
            run.call
        );
    }
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_field_is_refused_before_the_key() {
    let mut tampers = Vec::new();
    for operation in ["sign-xml-rsa", "sign-xml-gost2004"] {
        for (from, to) in [
            (
                "transforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
                "transforms = [\"enveloped\", { c14n = \"inclusive\" }]",
            ),
            (
                "transforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
                "transforms = [\"enveloped\"]",
            ),
            (
                "transforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]\n",
                "",
            ),
            ("c14n = \"inclusive\"", "c14n = \"exclusive\""),
            (
                "placement = \"first_child_of_document\"",
                "placement = \"document_element\"",
            ),
            ("trim = false", "trim = true"),
            ("standalone_no = true", "standalone_no = false"),
            ("declaration = true", "declaration = false"),
            (
                "\nc14n = \"inclusive\"",
                "\nc14n = \"inclusive\"\nstrip_whitespace = true",
            ),
        ] {
            tampers.push((operation.to_owned(), from.to_owned(), to.to_owned()));
        }
    }
    assert_tampers_refused_with_keys(&tampers, &key_of, &run_operation);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    let operations = ["sign-xml-rsa".to_owned(), "sign-xml-gost2004".to_owned()];
    assert_every_import_needed_with_keys(
        PORT,
        &operations,
        &["keys_release"],
        &key_of,
        &run_operation,
    );
}

/// RSA-SHA1 keys are not declared and cannot be: `SIGNATURE_METHODS` lacks the SHA-1 URIs, so
/// no operation can name them (the module sends them for a sha1RSA certificate; the call is
/// refused as a mismatch and the manifest cannot be edited into accepting it).
#[test]
fn an_rsa_sha1_operation_cannot_be_declared() {
    let text = manifest_text(PORT);
    let tampered = text
        .replace("xmldsig-more#rsa-sha256", "xmldsig-more#rsa-sha1")
        .replace("xmlenc#sha256", "xmldsig-more#sha1");
    assert_ne!(tampered, text);
    let error = oncl_plugin::Manifest::from_toml(&tampered)
        .unwrap_err()
        .to_string();
    assert!(error.contains("known method"), "{error}");
}

/// The declaration cannot drop `enveloped` for a whole document: the manifest is refused (the
/// signature of a whole document is inside what it signs), so no tampered text gets as far as a
/// call.
#[test]
fn a_whole_document_declaration_without_enveloped_is_refused() {
    let text = manifest_text(PORT);
    let tampered = text.replace(
        "transforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
        "transforms = [{ c14n = \"inclusive_with_comments\" }]",
    );
    assert_ne!(tampered, text);
    let error = oncl_plugin::Manifest::from_toml(&tampered)
        .unwrap_err()
        .to_string();
    assert!(error.contains("need `enveloped`"), "{error}");
}
