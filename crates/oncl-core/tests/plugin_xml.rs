//! Final L01 actual-WASM XML/XAdES capability acceptance, not a wrapper-only test.
#![cfg(all(feature = "plugins", feature = "tokens", feature = "xml"))]
#[path = "../examples/sdk_probe/plugin_fixture.rs"]
mod fixture;
#[path = "../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod plugin_crypto;
#[path = "../examples/sdk_probe/plugin_xml_fixture.rs"]
mod xades_fixture;
use fixture::*;
use oncl_core::{ErrorCode, keys::AppliedState, plugins::*};
use oncl_pdk::abi::{self, Import};
use oncl_pki::io::TemporaryStore;
use std::sync::atomic::Ordering;
const XML:&[u8]=b"<r xmlns:p='urn:p' xml:lang='kk'><p:data Id='payload'>actual WASM protected text</p:data><s/></r>";
const RSA: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
fn call() -> PluginCall<'static> {
    PluginCall {
        plugin_id: ID,
        operation: "sign",
        args: "{}",
    }
}
fn decoded<T: serde::de::DeserializeOwned>(response: &str) -> T {
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    abi::decode::<abi::HostResult<T>>(&bytes).unwrap().unwrap()
}
fn extended() -> abi::SignXmlExArgs {
    abi::SignXmlExArgs {
        handle: 1,
        xml: XML.to_vec().into(),
        element: Some("//p:data".into()),
        parent: Some("/r/s".into()),
        namespaces: vec![abi::NsBinding {
            prefix: "p".into(),
            uri: "urn:p".into(),
        }],
        other_prefix_uri: None,
        placement: abi::Placement::Parent,
        signature_method: Some(RSA.into()),
        digest_method: None,
        signed_info_c14n: None,
        transforms: None,
        signature_id: Some("legacy-signature".into()),
        signing_time_object: None,
        strip_whitespace: true,
        base64_line_breaks: Some(false),
        output: abi::XmlOutput::Serialize {
            declaration: false,
            standalone_no: false,
            trim: true,
        },
    }
}
#[test]
fn actual_wasm_basic_xml_signs_with_rsa_and_both_gost_leaf_keys() {
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let (key, validation) = xades_fixture::matching_issuer(name);
        let methods = [Import::KeysSignXml];
        let args = abi::SignXmlArgs {
            handle: 1,
            xml: XML.to_vec().into(),
            element: None,
            parent: None,
        };
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, guard, provider) = engine_configured(
            &[(Import::KeysSignXml, abi::encode(&args))],
            permission(&methods, std::slice::from_ref(&key)),
            |s| s.with_temporary_store(store).with_validation(validation),
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(
            &engine,
            std::slice::from_ref(&key),
            Some(permission(&methods, std::slice::from_ref(&key))),
        );
        let result = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let signed = signature(result.response());
        assert_eq!(oncl_xml::verify(&signed).unwrap().len(), 1);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
        assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
        assert_eq!(guard.events.lock().unwrap()[0].operation_id, ctx.id());
        assert_eq!(
            guard.events.lock().unwrap()[0].action,
            oncl_core::Action::Sign
        );
        assert_eq!(guard.events.lock().unwrap()[0].batch_item(), None);
        assert!(!ctx.policy().allow_prehashed);
    }
}
#[test]
fn actual_wasm_extended_xml_preserves_namespace_xpath_placement_and_layout() {
    let (key, certificate) = crypto::selector_with_certificate("user-rsa-sign");
    let args = extended();
    let methods = [Import::KeysSignXmlEx];
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    let result = engine
        .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
        .unwrap();
    let signed = signature(result.response());
    let mut entry = crypto::raw("user-rsa-sign");
    entry.cert = certificate;
    let mut expected = oncl_xml::XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
    expected.namespaces.push(("p", "urn:p"));
    expected.signature_method = Some(RSA);
    expected.signature_id = Some("legacy-signature");
    expected.base64_line_breaks = Some(false);
    assert_eq!(
        signed.as_slice(),
        oncl_xml::sign_spec(XML, &expected, &entry.key, &entry.cert).unwrap()
    );
    assert_eq!(oncl_xml::verify(&signed).unwrap().len(), 1);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
}
#[test]
fn actual_wasm_xades_b_has_real_baseline_properties_and_guarded_signature() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXades];
    let args = abi::XadesArgs {
        handle: 1,
        xml: XML.to_vec().into(),
        level: abi::XadesLevel::B,
        tsa: abi::TsaChoice::Basics,
        chain: vec![],
        signature_method: Some(RSA.into()),
        digest_method: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXades, abi::encode(&args))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    let result = engine
        .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
        .unwrap();
    let abi::XadesOutcome::Signed(signed) = decoded(result.response()) else {
        panic!("no actual XAdES signature")
    };
    assert_eq!(oncl_xml::verify(&signed).unwrap().len(), 1);
    assert!(
        std::str::from_utf8(&signed)
            .unwrap()
            .contains("SignedProperties")
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert_eq!(result.applied_state(), AppliedState::Applied);
}
#[test]
fn actual_wasm_xml_denied_handle_and_nested_method_never_open_a_key() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let mut args = extended();
    args.handle = 2;
    let (engine, guard, provider) = engine(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        std::slice::from_ref(&key),
        &methods,
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    assert_eq!(
        engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    drop(ctx);
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(
            &[Import::KeysSignRaw],
            std::slice::from_ref(&key),
        )),
    );
    assert_eq!(
        engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_wasm_xades_b_t_lt_reports_real_baseline_evidence() {
    for (level, expected) in [
        (abi::XadesLevel::B, oncl_pki::evidence::AdesLevel::B),
        (abi::XadesLevel::T, oncl_pki::evidence::AdesLevel::T),
        (abi::XadesLevel::Lt, oncl_pki::evidence::AdesLevel::Lt),
    ] {
        let key = crypto::selector("user-rsa-sign");
        let methods = [Import::KeysSignXades];
        let args = xades_fixture::args(level, XML);
        let p = xades_fixture::permission(&methods, std::slice::from_ref(&key));
        let (validation, configuration, transport) = xades_fixture::services();
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, guard, _) = engine_configured(
            &[(Import::KeysSignXades, abi::encode(&args))],
            p.clone(),
            |s| {
                s.with_validation(validation)
                    .with_cades(configuration)
                    .with_temporary_store(store)
            },
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
        let result = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap();
        let abi::XadesOutcome::Signed(signed) = decoded(result.response()) else {
            panic!("no XAdES result for {level:?}")
        };
        assert_eq!(oncl_xml::verify(&signed).unwrap().len(), 1);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
        assert_eq!(
            transport.tsa_requests.load(Ordering::SeqCst),
            if level == abi::XadesLevel::B { 0 } else { 1 }
        );
        drop(result);
        drop(ctx);
        let mut ctx = engine
            .begin(
                oncl_core::ExecutionGrant::new([oncl_core::Action::Verify]),
                oncl_core::OperationPolicy::strict_online(),
                std::sync::Arc::new(Control),
            )
            .unwrap();
        let report = engine
            .verify(
                &oncl_core::VerifyRequest::xml(),
                oncl_pki::io::Source::sequential(
                    &mut std::io::Cursor::new(signed.as_ref()),
                    Some(signed.len() as u64),
                ),
                None,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(report.verdict, oncl_pki::validation::Verdict::Valid);
        assert_eq!(
            report.xml.as_ref().unwrap().signatures()[0].level,
            Some(expected)
        );
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn known_xml_selector_and_algorithm_errors_precede_provider_and_private_use() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let mut missing = extended();
    missing.element = Some("//p:missing".into());
    let mut signature = extended();
    signature.signature_method = Some("urn:unknown-signature-algorithm".into());
    let mut digest = extended();
    digest.digest_method = Some("urn:unknown-digest-algorithm".into());
    let mut transforms = extended();
    transforms.transforms = Some(vec![
        abi::Transform::C14n(abi::C14n::Exclusive),
        abi::Transform::Enveloped,
    ]);
    for args in [missing, signature, digest, transforms] {
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, guard, provider) = engine_configured(
            &[(Import::KeysSignXmlEx, abi::encode(&args))],
            permission(&methods, std::slice::from_ref(&key)),
            |s| s.with_temporary_store(store),
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(
            &engine,
            std::slice::from_ref(&key),
            Some(permission(&methods, std::slice::from_ref(&key))),
        );
        let error = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn xml_original_input_temp_memory_and_output_limits_remain_typed() {
    use oncl_pki::resource::ResourceLimits;
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let args = extended();
    for (limits, expected) in [
        (
            ResourceLimits {
                input_bytes: XML.len() as u64 - 1,
                ..ResourceLimits::default()
            },
            ErrorCode::InputLimit,
        ),
        (
            ResourceLimits {
                temp_bytes: XML.len() as u64 - 1,
                ..ResourceLimits::default()
            },
            ErrorCode::TempLimit,
        ),
        (
            ResourceLimits {
                memory_bytes: 3_600_000,
                ..ResourceLimits::default()
            },
            ErrorCode::MemoryLimit,
        ),
        (
            ResourceLimits {
                output_bytes: 1,
                ..ResourceLimits::default()
            },
            ErrorCode::OutputLimit,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let p = permission(&methods, std::slice::from_ref(&key));
        let (engine, guard, _) = engine_limited(
            &[(Import::KeysSignXmlEx, abi::encode(&args))],
            p.clone(),
            limits,
            |s| s.with_temporary_store(store),
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
        let error = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err();
        assert_eq!(error.code(), expected);
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn xades_missing_configuration_host_tsa_mismatch_and_chain_caps_do_not_open_keys() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXades];
    for mode in 0..3 {
        let (validation, mut configuration, transport) = xades_fixture::services();
        let mut args = xades_fixture::args(
            if mode == 2 {
                abi::XadesLevel::Lt
            } else {
                abi::XadesLevel::T
            },
            XML,
        );
        if mode == 1 {
            args.tsa = abi::TsaChoice::Kalkan;
        }
        if mode == 2 {
            configuration.evidence_limits.max_chain_len = 1;
            args.chain.push(args.chain[0].clone());
        }
        let p = xades_fixture::permission(&methods, std::slice::from_ref(&key));
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, guard, provider) = engine_configured(
            &[(Import::KeysSignXades, abi::encode(&args))],
            p.clone(),
            |s| {
                let s = s.with_validation(validation).with_temporary_store(store);
                if mode == 0 {
                    s
                } else {
                    s.with_cades(configuration)
                }
            },
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
        let error = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(
            error.code(),
            match mode {
                0 => ErrorCode::MissingCadesConfiguration,
                1 => ErrorCode::PermissionDenied,
                _ => ErrorCode::MetadataLimit,
            }
        );
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
        assert_eq!(transport.tsa_requests.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn xml_original_guard_finish_failure_latches_and_late_guest_trap_keeps_applied() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let args = extended();
    let p = permission(&methods, std::slice::from_ref(&key));
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, provider) = engine_configured(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        p.clone(),
        |s| s.with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound);
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p.clone()));
    guard.audit_fail.store(true, Ordering::SeqCst);
    let error = engine
        .plugin_call(&call(), &bindings, &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuditFailed);
    assert_eq!(error.applied_state(), AppliedState::Applied);
    guard.audit_fail.store(false, Ordering::SeqCst);
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    drop(ctx);
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let module = wasm_with_tail(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        "unreachable",
    );
    let (engine, guard, _) = engine_wasm(
        &module,
        p.clone(),
        oncl_pki::resource::ResourceLimits::default(),
        |s| s.with_temporary_store(store),
    );
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
    let error = engine
        .plugin_call(&call(), &bindings, &mut ctx)
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Applied);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
}

#[test]
fn xades_post_key_tsa_failure_is_applied_and_no_successful_artifact_escapes() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXades];
    let (validation, configuration, transport) = xades_fixture::services();
    transport.fail_tsa.store(true, Ordering::SeqCst);
    let args = xades_fixture::args(abi::XadesLevel::T, XML);
    let p = xades_fixture::permission(&methods, std::slice::from_ref(&key));
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXades, abi::encode(&args))],
        p.clone(),
        |s| {
            s.with_validation(validation)
                .with_cades(configuration)
                .with_temporary_store(store)
        },
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
    let error = engine
        .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Applied);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert!(transport.tsa_requests.load(Ordering::SeqCst) > 0);
}

#[test]
fn all_extended_xml_layout_and_reference_selectors_share_the_legacy_wire_kernel() {
    let (key, certificate) = crypto::selector_with_certificate("user-rsa-sign");
    let mut entry = crypto::raw("user-rsa-sign");
    entry.cert = certificate;
    let mut cases = Vec::new();
    for (wire, actual) in [
        (abi::C14n::Inclusive, oncl_xml::C14n::Inclusive),
        (
            abi::C14n::InclusiveWithComments,
            oncl_xml::C14n::InclusiveWithComments,
        ),
        (abi::C14n::Exclusive, oncl_xml::C14n::Exclusive),
        (
            abi::C14n::ExclusiveWithComments,
            oncl_xml::C14n::ExclusiveWithComments,
        ),
    ] {
        let mut args = extended();
        args.element = None;
        args.parent = None;
        args.namespaces.clear();
        args.placement = abi::Placement::DocumentElement;
        args.signed_info_c14n = Some(wire);
        args.transforms = Some(vec![abi::Transform::Enveloped, abi::Transform::C14n(wire)]);
        let mut expected = oncl_xml::XmlSignSpec::kalkan(None, None);
        expected.signature_method = Some(RSA);
        expected.signature_id = Some("legacy-signature");
        expected.base64_line_breaks = Some(false);
        expected.signed_info_c14n = Some(actual);
        expected.transforms = Some(vec![
            oncl_xml::Transform::Enveloped,
            oncl_xml::Transform::C14n(actual),
        ]);
        cases.push((args, expected));
    }
    for output in [
        abi::XmlOutput::AsIs,
        abi::XmlOutput::Serialize {
            declaration: true,
            standalone_no: false,
            trim: true,
        },
        abi::XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim: false,
        },
    ] {
        let mut args = extended();
        args.output = output;
        args.strip_whitespace = false;
        args.base64_line_breaks = Some(true);
        let mut expected = oncl_xml::XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
        expected.namespaces.push(("p", "urn:p"));
        expected.signature_method = Some(RSA);
        expected.signature_id = Some("legacy-signature");
        expected.strip_whitespace = false;
        expected.base64_line_breaks = Some(true);
        expected.output = match output {
            abi::XmlOutput::AsIs => oncl_xml::XmlOutput::AsIs,
            abi::XmlOutput::Serialize {
                declaration,
                standalone_no,
                trim,
            } => oncl_xml::XmlOutput::Serialize {
                declaration,
                standalone_no,
                trim,
            },
        };
        cases.push((args, expected));
    }
    for target_ref in [false, true] {
        let mut args = extended();
        args.signing_time_object = Some(abi::SigningTimeObject {
            property_id: "time-property".into(),
            target_ref,
            text: "2026-11-02T12:00:00Z".into(),
        });
        let mut expected = oncl_xml::XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
        expected.namespaces.push(("p", "urn:p"));
        expected.signature_method = Some(RSA);
        expected.signature_id = Some("legacy-signature");
        expected.base64_line_breaks = Some(false);
        expected.signing_time_object = Some(oncl_xml::SigningTimeObject {
            property_id: "time-property",
            target_ref,
            text: "2026-11-02T12:00:00Z",
        });
        cases.push((args, expected));
    }
    let mut args = extended();
    args.namespaces.clear();
    args.other_prefix_uri = Some("urn:p".into());
    args.element = Some("//alias:data".into());
    let mut expected = oncl_xml::XmlSignSpec::kalkan(Some("//alias:data"), Some("/r/s"));
    expected.other_prefix_uri = Some("urn:p");
    expected.signature_method = Some(RSA);
    expected.signature_id = Some("legacy-signature");
    expected.base64_line_breaks = Some(false);
    cases.push((args, expected));
    let mut args = extended();
    args.element = None;
    args.parent = None;
    args.namespaces.clear();
    args.placement = abi::Placement::FirstChildOfDocument;
    let mut expected = oncl_xml::XmlSignSpec::kalkan(None, None);
    expected.placement = oncl_xml::Placement::FirstChildOfDocument;
    expected.signature_method = Some(RSA);
    expected.signature_id = Some("legacy-signature");
    expected.base64_line_breaks = Some(false);
    cases.push((args, expected));
    for trim in [false, true] {
        let mut args = extended();
        let mut data = b"\xef\xbb\xbf<?xml version='1.0' encoding='UTF-8'?> \r\n".to_vec();
        data.extend_from_slice(XML);
        data.extend_from_slice(b" \t\r\n");
        args.xml = data.into();
        args.output = abi::XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim,
        };
        args.base64_line_breaks = Some(true);
        args.strip_whitespace = false;
        let mut expected = oncl_xml::XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
        expected.namespaces.push(("p", "urn:p"));
        expected.signature_method = Some(RSA);
        expected.signature_id = Some("legacy-signature");
        expected.base64_line_breaks = Some(true);
        expected.strip_whitespace = false;
        expected.output = oncl_xml::XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim,
        };
        cases.push((args, expected));
    }
    for (index, (args, expected)) in cases.into_iter().enumerate() {
        let methods = [Import::KeysSignXmlEx];
        let p = permission(&methods, std::slice::from_ref(&key));
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, guard, _) = engine_configured(
            &[(Import::KeysSignXmlEx, abi::encode(&args))],
            p.clone(),
            |s| s.with_temporary_store(store),
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
        let result = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_or_else(|error| panic!("selector {index}: {error:?}"));
        let signed = signature(result.response());
        assert_eq!(
            signed,
            oncl_xml::sign_spec(&args.xml, &expected, &entry.key, &entry.cert).unwrap(),
            "selector {index}"
        );
        assert_eq!(oncl_xml::verify(&signed).unwrap().len(), 1);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let p = permission(&methods, std::slice::from_ref(&key));
        let (limited, guard, _) = engine_limited(
            &[(Import::KeysSignXmlEx, abi::encode(&args))],
            p.clone(),
            oncl_pki::resource::ResourceLimits {
                output_bytes: signed.len() as u64 - 1,
                ..Default::default()
            },
            |s| s.with_temporary_store(store),
        );
        let mut limited_ctx = begin(&limited, std::slice::from_ref(&key), Some(p));
        let error = limited
            .plugin_call(
                &call(),
                &PluginBindings::new(&caller, &bound),
                &mut limited_ctx,
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::OutputLimit, "projection {index}");
        assert_eq!(
            guard.applied.load(Ordering::SeqCst),
            0,
            "projection {index}"
        );
        assert_eq!(limited_ctx.resources().progress().bytes_out, 0);
    }
}

#[test]
fn exact_xml_output_preflight_and_abi_target_precede_private_use_and_restore() {
    let (key, certificate) = crypto::selector_with_certificate("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let args = extended();
    let p = permission(&methods, std::slice::from_ref(&key));
    let calls = [(Import::KeysSignXmlEx, abi::encode(&args))];
    let mut entry = crypto::raw("user-rsa-sign");
    entry.cert = certificate;
    let mut spec = oncl_xml::XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
    spec.namespaces.push(("p", "urn:p"));
    spec.signature_method = Some(RSA);
    spec.signature_id = Some("legacy-signature");
    spec.base64_line_breaks = Some(false);
    let size = oncl_xml::sign_spec(XML, &spec, &entry.key, &entry.cert)
        .unwrap()
        .len();
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let limits = oncl_pki::resource::ResourceLimits {
        output_bytes: size as u64 - 1,
        ..oncl_pki::resource::ResourceLimits::default()
    };
    let (engine, guard, _) =
        engine_limited(&calls, p.clone(), limits, |s| s.with_temporary_store(store));
    let caller = caller();
    let bound = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound);
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p.clone()));
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::OutputLimit
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(ctx.resources().progress().bytes_out, 0);
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let transfer = calls[0].1.len() + 32;
    assert!(transfer < size);
    let (engine, guard, _) = engine_profile(
        &wasm(&calls),
        p.clone(),
        oncl_pki::resource::ResourceLimits::default(),
        oncl_plugin::InstanceLimits {
            max_memory: 1 << 20,
            max_transfer: transfer,
            ..oncl_plugin::InstanceLimits::default()
        },
        |s| s.with_temporary_store(store),
    );
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::ContainerLimit
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    // The actual target cap is temporary, not a mutation of the original budget.
    let mut output = Vec::new();
    engine
        .sign(
            oncl_core::SignRequest::xml_legacy(
                oncl_core::keys::KeyRequest::new(&key, Some(crypto::PASSWORD)),
                spec,
            ),
            oncl_pki::io::Source::sequential(
                &mut std::io::Cursor::new(XML),
                Some(XML.len() as u64),
            ),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(oncl_xml::verify(&output).unwrap().len(), 1);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
}

#[test]
fn opaque_xml_key_cannot_upgrade_issuer_algorithm_or_enable_prehash() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXml];
    let args = abi::SignXmlArgs {
        handle: 1,
        xml: XML.to_vec().into(),
        element: None,
        parent: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXml, abi::encode(&args))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    // This certificate is signed by GOST2015 but its actual private key is RSA:
    // legacy's omitted algorithm cannot silently become a prehash/issuer bypass.
    assert_eq!(
        engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert!(!ctx.policy().allow_prehashed);
}

#[test]
fn xml_cancellation_before_and_after_private_use_preserves_original_control_and_applied() {
    use oncl_core::keys::{KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt};
    use oncl_pki::resource::{OperationControl, ProcessingError, Progress};
    use std::sync::{Arc, atomic::AtomicBool};
    struct Cancel(Arc<AtomicBool>);
    impl OperationControl for Cancel {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    struct Guard {
        inner: Arc<crypto::Guard>,
        flag: Arc<AtomicBool>,
        after: bool,
    }
    impl KeyUseGuard for Guard {
        fn before_use(
            &self,
            event: &KeyUseEvent,
        ) -> Result<KeyUseReceipt, oncl_core::OperationError> {
            self.inner.before_use(event)
        }
        fn finish(
            &self,
            receipt: KeyUseReceipt,
            outcome: KeyUseOutcome,
        ) -> Result<(), oncl_core::OperationError> {
            let result = self.inner.finish(receipt, outcome);
            if self.after {
                self.flag.store(true, Ordering::SeqCst);
            }
            result
        }
    }
    for after in [false, true] {
        let key = crypto::selector("user-rsa-sign");
        let methods = [Import::KeysSignXmlEx];
        let p = permission(&methods, std::slice::from_ref(&key));
        let flag = Arc::new(AtomicBool::new(false));
        let inner = std::sync::Arc::new(crypto::Guard::default());
        if !after {
            let flag = flag.clone();
            *inner.hook.lock().unwrap() =
                Some(Box::new(move || flag.store(true, Ordering::SeqCst)));
        }
        let guard = Arc::new(Guard {
            inner: inner.clone(),
            flag: flag.clone(),
            after,
        });
        let provider = Arc::new(crypto::Provider::default());
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, _, _) = engine_configured(
            &[(Import::KeysSignXmlEx, abi::encode(&extended()))],
            p.clone(),
            |s| s.with_keys(provider, guard).with_temporary_store(store),
        );
        let mut ctx = engine
            .begin(
                oncl_core::ExecutionGrant::new([oncl_core::Action::Sign])
                    .with_keys([key.key_id()])
                    .with_plugins([p]),
                oncl_core::OperationPolicy::strict_online(),
                Arc::new(Cancel(flag)),
            )
            .unwrap();
        let caller = caller();
        let bound = [binding(&key, 1)];
        let error = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(
            error.applied_state(),
            if after {
                AppliedState::Applied
            } else {
                AppliedState::NotApplied
            }
        );
        assert_eq!(inner.applied.load(Ordering::SeqCst), usize::from(after));
    }
}

#[test]
fn xml_document_and_host_secret_do_not_enter_tracing() {
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let key = crypto::selector("user-gost2015-sign");
    let methods = [Import::KeysSignXml];
    let xml = format!(
        "<r><payload>{}</payload></r>",
        std::str::from_utf8(MESSAGE).unwrap()
    );
    let args = abi::SignXmlArgs {
        handle: 1,
        xml: xml.as_bytes().to_vec().into(),
        element: None,
        parent: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXml, abi::encode(&args))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    let captured = Capture(Arc::default());
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, || {
        engine.plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
    })
    .unwrap();
    assert_eq!(
        oncl_xml::verify(&signature(result.response()))
            .unwrap()
            .len(),
        1
    );
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains(std::str::from_utf8(MESSAGE).unwrap()));
    assert!(!text.contains(crypto::PASSWORD));
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
}

#[test]
fn foreign_context_and_mandatory_prompt_cannot_enter_xml_private_use() {
    use std::sync::Arc;
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let foreign = crypto::engine(
        store.clone(),
        Arc::new(crypto::Guard::default()),
        Arc::new(crypto::Provider::default()),
        oncl_pki::resource::ResourceLimits::default(),
    );
    let mut foreign_ctx = foreign
        .begin(
            oncl_core::ExecutionGrant::new([oncl_core::Action::Hash]),
            oncl_core::OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let (engine, guard, provider) = engine_configured(
        &[(Import::KeysSignXmlEx, abi::encode(&extended()))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound);
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut foreign_ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    let methods = [Import::DialogConfirm, Import::KeysSignXmlEx];
    let (engine, guard, provider) = fixture::engine(
        &[
            (
                Import::DialogConfirm,
                abi::encode(&abi::ConfirmArgs {
                    text: "mandatory".into(),
                }),
            ),
            (Import::KeysSignXmlEx, abi::encode(&extended())),
        ],
        std::slice::from_ref(&key),
        &methods,
    );
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InteractionRequired
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn xades_guest_tsa_cannot_replace_host_profile_even_with_an_endpoint_grant() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXades];
    let (validation, configuration, transport) = xades_fixture::services();
    let mut args = xades_fixture::args(abi::XadesLevel::T, XML);
    args.tsa = abi::TsaChoice::Kalkan;
    let p = xades_fixture::permission(&methods, std::slice::from_ref(&key))
        .with_pki_endpoints([(oncl_pki::http::HttpMethod::Get, "http://tsp.pki.gov.kz")])
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, provider) = engine_configured(
        &[(Import::KeysSignXades, abi::encode(&args))],
        p.clone(),
        |s| {
            s.with_validation(validation)
                .with_cades(configuration)
                .with_temporary_store(store)
        },
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
    let error = engine
        .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(transport.tsa_requests.load(Ordering::SeqCst), 0);
    assert_eq!(ctx.resources().progress().bytes_in, 0);
}

#[test]
fn xades_b_and_t_preserve_unused_valid_chain_selector_semantics() {
    for level in [abi::XadesLevel::B, abi::XadesLevel::T] {
        let key = crypto::selector("user-rsa-sign");
        let methods = [Import::KeysSignXades];
        let (validation, configuration, _) = xades_fixture::services();
        let mut args = xades_fixture::args(level, XML);
        args.chain = vec![args.chain[0].clone(); configuration.evidence_limits.max_chain_len + 1];
        let p = xades_fixture::permission(&methods, std::slice::from_ref(&key));
        let directory = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(directory.path()).unwrap();
        let (engine, guard, _) = engine_configured(
            &[(Import::KeysSignXades, abi::encode(&args))],
            p.clone(),
            |s| {
                s.with_validation(validation)
                    .with_cades(configuration)
                    .with_temporary_store(store)
            },
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
        let result = engine
            .plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap();
        let abi::XadesOutcome::Signed(signed) = decoded(result.response()) else {
            panic!("actual signed baseline absent")
        };
        assert_eq!(oncl_xml::verify(&signed).unwrap().len(), 1);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn xml_route_arguments_cannot_forge_caller_origin_or_change_nested_method() {
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let (engine, guard, provider) = engine_configured(
        &[(Import::KeysSignXmlEx, abi::encode(&extended()))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_temporary_store(store),
    );
    let bound = [binding(&key, 1)];
    let impostor = CallerContext::Browser {
        origin: "l01-authorized-service".into(),
    };
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    let request = PluginCall {
        args: r#"{"origin":"https://trusted.example","method":"keys_sign_raw","handle":1,"allow_prehashed":true}"#,
        ..call()
    };
    assert_eq!(
        engine
            .plugin_call(&request, &PluginBindings::new(&impostor, &bound), &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert!(!ctx.policy().allow_prehashed);
}
