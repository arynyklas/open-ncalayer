//! The limits of the desktop's manual window (`ManualLimits::desktop()`, MP7b) under the real
//! wasm of `rating1c`: the largest document it admits through every CMS and raw operation, and
//! a budget that is too small refused before the key, through the real module.
//!
//! `ONCL_PORT_MAX_DOC_MIB` re-runs the tests for limits and documents of that size
//! (`ManualLimits::for_max_document`): how the trade-off table of the docs was measured.
use crate::ports::*;
use oncl_core::plugins::{ManualLimits, PluginParam, PluginPrepareError, PluginRefusalCode};
use oncl_pki::resource::ResourceLimits;
use oncl_plugin::operations::KeyKind;

const PORT: &str = "rating1c";
const XML: &str = "<r><data Id=\"d1\">actual XML text</data><s></s></r>";

fn limits() -> ManualLimits {
    match std::env::var("ONCL_PORT_MAX_DOC_MIB") {
        Ok(mib) => ManualLimits::for_max_document(mib.parse::<u64>().unwrap() << 20, 1 << 30),
        Err(_) => ManualLimits::desktop(),
    }
}

/// A document of `len` bytes that no encoding makes small.
fn document(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn options(limits: &ManualLimits) -> RunOptions {
    RunOptions {
        limits: Some(limits.clone()),
        ..RunOptions::default()
    }
}

fn response_object(run: &PortRun) -> serde_json::Value {
    let json = reply_json(run);
    assert_eq!(json["code"], "200", "{:?}", run.http_log);
    json["responseObject"].clone()
}

/// The attached CMS of a document of the largest size: the worst operation (the document goes
/// in, and comes back inside the CMS, as base64 both ways). Alone, so that the peak memory of
/// the process is its own (`tools`: run it by name and sample the process).
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_attached_cms_of_the_largest_document_signs() {
    let limits = limits();
    let doc = document(limits.max_document as usize);
    let need = oncl_core::plugins::manual_call_budget(
        &limits.instance,
        KeyKind::CmsEx,
        doc.len() as u64,
        0,
    )
    .unwrap();
    // For the trade-off table of docs/dev/plugins-manual-tests.md.
    println!("LIMITS {limits:?}\nMODEL {need:?}");
    let params = [("file", PluginParam::Document(&doc))];
    let run = run_port_operation(PORT, "create-cms-attached", &params, &options(&limits));
    assert_applied(&run);
    let cms = from_base64(response_object(&run).as_str().unwrap());
    let facts = oracle::verify_cms(&cms, &doc, &run.cert, true);
    assert_eq!(facts.sig_alg, oncl_pki::key::SigAlg::RsaSha256);
}

/// Every CMS and raw operation signs a document of the largest size under the desktop's
/// limits, and what comes out verifies by the oracles. This is the evidence for the sizing.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_cms_and_raw_operation_signs_a_document_at_the_limit() {
    let limits = limits();
    let doc = document(limits.max_document as usize);
    let params = [("file", PluginParam::Document(&doc))];
    for (operation, attached, timestamped) in [
        ("create-cms", false, false),
        ("create-cms-attached", true, false),
        ("create-cms-timestamp", false, true),
        ("create-cms-attached-timestamp", true, true),
    ] {
        let run = run_port_operation(PORT, operation, &params, &options(&limits));
        assert_applied(&run);
        assert_eq!(run.summary.content.len, doc.len() as u64);
        let cms = from_base64(response_object(&run).as_str().unwrap());
        let facts = oracle::verify_cms(&cms, &doc, &run.cert, attached);
        assert_eq!(facts.time_stamped, timestamped, "{operation}: {facts:?}");
    }
    let run = run_port_operation(PORT, "create-raw-sign", &params, &options(&limits));
    assert_applied(&run);
    let object = response_object(&run);
    let signature = from_base64(object["signResult"].as_str().unwrap());
    oracle::verify_raw_rsa(&run.cert, &doc, &signature);
}

/// The XML operations at the largest text the manifest allows (64 Ki characters).
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_xml_operations_sign_the_largest_text_under_the_desktop_limits() {
    let limits = limits();
    let short = {
        let mut s = String::from("<r><data Id=\"d1\">");
        s.push_str(&"x".repeat(65_000));
        s.push_str("</data><s></s></r>");
        s
    };
    let params = [("xml", PluginParam::Text(&short))];
    let run = run_port_operation(PORT, "sign-xml", &params, &options(&limits));
    assert_applied(&run);
    let signed = response_object(&run);
    oracle::verify_xml(signed.as_str().unwrap().as_bytes(), &run.cert, 1);
}

/// The operations of `rating1c` as (name, key kind, params) with a document of `len` bytes.
fn kinds() -> Vec<(&'static str, KeyKind)> {
    vec![
        ("sign-xml", KeyKind::XmlEx),
        ("sign-xml-element", KeyKind::XmlEx),
        ("create-cms", KeyKind::CmsEx),
        ("create-cms-attached", KeyKind::CmsEx),
        ("create-cms-timestamp", KeyKind::CmsEx),
        ("create-cms-attached-timestamp", KeyKind::CmsEx),
        ("create-raw-sign", KeyKind::Raw),
    ]
}

/// At exactly `manual_call_budget` every operation signs (the model is enough); with one byte
/// less of the metadata budget, or of the memory budget, Core refuses it before the user is
/// asked and before the key is used (`resource-budget`), and no key is applied. The estimate
/// is the engine's own: the text parameters count as key import arguments on top of the
/// bound content (`Engine::plugin_prepare` sums every text parameter, the bound XML text
/// included, since a `param:` option may name any of them).
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_estimate_signs_and_one_byte_less_is_refused_before_the_key() {
    let desktop = limits();
    let doc = document(64 * 1024);
    for (operation, kind) in kinds() {
        let xml = operation.starts_with("sign-xml");
        let params: Vec<(&str, PluginParam<'_>)> = if operation == "sign-xml" {
            vec![("xml", PluginParam::Text(XML))]
        } else if xml {
            vec![
                ("xml", PluginParam::Text(XML)),
                ("tbs", PluginParam::Text("/r/data")),
                ("parent", PluginParam::Text("/r/s")),
            ]
        } else {
            vec![("file", PluginParam::Document(&doc))]
        };
        let len = if xml { XML.len() } else { doc.len() };
        let text_len: usize = params
            .iter()
            .map(|(_, p)| match p {
                PluginParam::Text(text) => text.len(),
                _ => 0,
            })
            .sum();
        let need = oncl_core::plugins::manual_call_budget(
            &desktop.instance,
            kind,
            len as u64,
            text_len as u64,
        )
        .unwrap();
        let with = |metadata_bytes: u64, memory_bytes: u64| RunOptions {
            limits: Some(ManualLimits {
                resources: ResourceLimits {
                    metadata_bytes,
                    memory_bytes,
                    ..desktop.resources.clone()
                },
                ..desktop.clone()
            }),
            ..RunOptions::default()
        };
        let run = run_port_operation(PORT, operation, &params, &with(need.metadata, need.memory));
        assert_applied(&run);
        for (metadata, memory) in [
            (need.metadata - 1, need.memory),
            (need.metadata, need.memory - 1),
        ] {
            let error = try_run_port_operation(PORT, operation, &params, &with(metadata, memory))
                .err()
                .unwrap_or_else(|| panic!("{operation}: not refused"));
            assert!(
                matches!(
                    error,
                    PluginPrepareError::ResourceBudget | PluginPrepareError::DocumentTooLarge
                ),
                "{operation}"
            );
            assert_eq!(error.subcode(), PluginRefusalCode::ResourceBudget);
        }
    }
}

/// The SDK's own budgets (64 MiB of metadata) cannot hold a Kalkan XML signature: before this
/// check the call failed AFTER the key was applied (`AfterKeyUse(MetadataLimit)`); now it is
/// refused before the key.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_default_metadata_budget_refuses_an_xml_signature_before_the_key() {
    let options = RunOptions {
        limits: Some(ManualLimits {
            resources: ResourceLimits::default(),
            ..ManualLimits::desktop()
        }),
        ..RunOptions::default()
    };
    let params = [("xml", PluginParam::Text(XML))];
    let error = try_run_port_operation(PORT, "sign-xml", &params, &options)
        .err()
        .expect("refused");
    assert_eq!(error, PluginPrepareError::ResourceBudget);
}

/// A document over what the limits are sized for does not reach the key: its request does not
/// fit the transfer buffer.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_document_over_the_limit_is_refused_before_the_key() {
    let limits = limits();
    let doc = document(limits.max_document as usize * 2);
    let params = [("file", PluginParam::Document(&doc))];
    let error = try_run_port_operation(PORT, "create-cms-attached", &params, &options(&limits))
        .err()
        .expect("refused");
    assert!(
        matches!(
            error,
            PluginPrepareError::ResourceBudget
                | PluginPrepareError::DocumentTooLarge
                | PluginPrepareError::Request(_)
        ),
        "{error:?}"
    );
}

/// An engine without a temporary store refuses the XML operations before the key, through the
/// real module; the CMS needs none.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn an_engine_without_a_temporary_store_refuses_xml_before_the_key() {
    let options = RunOptions {
        no_temporary_store: true,
        ..RunOptions::default()
    };
    let xml = [("xml", PluginParam::Text(XML))];
    let error = try_run_port_operation(PORT, "sign-xml", &xml, &options)
        .err()
        .expect("refused");
    assert_eq!(error, PluginPrepareError::NoTemporaryStore);
    let doc = [("file", PluginParam::Document(b"a document"))];
    let run = run_port_operation(PORT, "create-cms", &doc, &options);
    assert_applied(&run);
}
