//! Actual bounded WASM XML/XAdES smoke, independently checked outside the SDK.
use super::fixture::*;
#[path = "plugin_xml_fixture.rs"]
mod xades_fixture;
use oncl_core::{ErrorCode, keys::AppliedState, plugins::*};
use oncl_pdk::abi::{self, Import};
use oncl_pki::io::TemporaryStore;
use std::{path::Path, sync::atomic::Ordering};
const XML:&[u8]=b"<r xmlns:p='urn:p' xml:lang='kk'><p:data Id='payload'>actual WASM protected text</p:data><s/></r>";
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
        signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".into()),
        digest_method: None,
        signed_info_c14n: None,
        transforms: None,
        signature_id: Some("legacy-signature".into()),
        signing_time_object: Some(abi::SigningTimeObject {
            property_id: "time-property".into(),
            target_ref: true,
            text: "2026-11-02T12:00:00Z".into(),
        }),
        strip_whitespace: false,
        base64_line_breaks: Some(true),
        output: abi::XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim: false,
        },
    }
}
pub(super) fn run(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (key, validation) = xades_fixture::matching_issuer("user-rsa-sign");
    let methods = [Import::KeysSignXml];
    let args = abi::SignXmlArgs {
        handle: 1,
        xml: XML.to_vec().into(),
        element: None,
        parent: None,
    };
    let directory = tempfile::tempdir()?;
    let store = TemporaryStore::new(directory.path())?;
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXml, abi::encode(&args))],
        permission(&methods, std::slice::from_ref(&key)),
        |s| s.with_validation(validation).with_temporary_store(store),
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    let result = engine.plugin_call(&call(), &PluginBindings::new(&caller, &bound), &mut ctx)?;
    let signed = signature(result.response());
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    std::fs::write(out.join("plugin-xml-basic.xml"), &signed)?;
    let key = crypto::selector("user-rsa-sign");
    let methods = [Import::KeysSignXmlEx];
    let args = extended();
    let p = permission(&methods, std::slice::from_ref(&key));
    let directory = tempfile::tempdir()?;
    let store = TemporaryStore::new(directory.path())?;
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        p.clone(),
        |s| s.with_temporary_store(store),
    );
    let bound = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound);
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p.clone()));
    let result = engine.plugin_call(&call(), &bindings, &mut ctx)?;
    let signed = signature(result.response());
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    std::fs::write(out.join("plugin-xml-ex.xml"), &signed)?;
    let directory = tempfile::tempdir()?;
    let store = TemporaryStore::new(directory.path())?;
    let (engine, guard, provider) = engine_limited(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        p.clone(),
        oncl_pki::resource::ResourceLimits {
            output_bytes: 1,
            ..Default::default()
        },
        |s| s.with_temporary_store(store),
    );
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p.clone()));
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::OutputLimit
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    let directory = tempfile::tempdir()?;
    let store = TemporaryStore::new(directory.path())?;
    let module = wasm_with_tail(
        &[(Import::KeysSignXmlEx, abi::encode(&args))],
        "unreachable",
    );
    let (engine, guard, _) = engine_wasm(
        &module,
        p,
        oncl_pki::resource::ResourceLimits::default(),
        |s| s.with_temporary_store(store),
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
            .applied_state(),
        AppliedState::Applied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    for (level, name, expected) in [
        (
            abi::XadesLevel::B,
            "plugin-xades-b.xml",
            oncl_pki::evidence::AdesLevel::B,
        ),
        (
            abi::XadesLevel::T,
            "plugin-xades-t.xml",
            oncl_pki::evidence::AdesLevel::T,
        ),
        (
            abi::XadesLevel::Lt,
            "plugin-xades-lt.xml",
            oncl_pki::evidence::AdesLevel::Lt,
        ),
    ] {
        let args = xades_fixture::args(level, XML);
        let methods = [Import::KeysSignXades];
        let p = xades_fixture::permission(&methods, std::slice::from_ref(&key));
        let (validation, configuration, transport) = xades_fixture::services();
        let directory = tempfile::tempdir()?;
        let store = TemporaryStore::new(directory.path())?;
        let (engine, guard, _) = engine_configured(
            &[(Import::KeysSignXades, abi::encode(&args))],
            p.clone(),
            |s| {
                s.with_validation(validation)
                    .with_cades(configuration)
                    .with_temporary_store(store)
            },
        );
        let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
        let result = engine.plugin_call(&call(), &bindings, &mut ctx)?;
        let abi::XadesOutcome::Signed(signed) = decoded(result.response()) else {
            return Err("actual XAdES signature missing".into());
        };
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
        assert_eq!(
            transport.tsa_requests.load(Ordering::SeqCst),
            usize::from(level != abi::XadesLevel::B)
        );
        std::fs::write(out.join(name), signed.as_ref())?;
        drop(result);
        drop(ctx);
        let mut ctx = engine.begin(
            oncl_core::ExecutionGrant::new([oncl_core::Action::Verify]),
            oncl_core::OperationPolicy::strict_online(),
            std::sync::Arc::new(Control),
        )?;
        let report = engine.verify(
            &oncl_core::VerifyRequest::xml(),
            oncl_pki::io::Source::sequential(
                &mut std::io::Cursor::new(signed.as_ref()),
                Some(signed.len() as u64),
            ),
            None,
            &mut ctx,
        )?;
        assert_eq!(report.verdict, oncl_pki::validation::Verdict::Valid);
        assert_eq!(
            report.xml.as_ref().unwrap().signatures()[0].level,
            Some(expected)
        );
    }
    let methods = [Import::KeysSignXades];
    let p = xades_fixture::permission(&methods, std::slice::from_ref(&key));
    let (validation, configuration, transport) = xades_fixture::services();
    transport.fail_tsa.store(true, Ordering::SeqCst);
    let directory = tempfile::tempdir()?;
    let store = TemporaryStore::new(directory.path())?;
    let (engine, guard, _) = engine_configured(
        &[(
            Import::KeysSignXades,
            abi::encode(&xades_fixture::args(abi::XadesLevel::T, XML)),
        )],
        p.clone(),
        |s| {
            s.with_validation(validation)
                .with_cades(configuration)
                .with_temporary_store(store)
        },
    );
    let mut ctx = begin(&engine, std::slice::from_ref(&key), Some(p));
    assert_eq!(
        engine
            .plugin_call(&call(), &bindings, &mut ctx)
            .unwrap_err()
            .applied_state(),
        AppliedState::Applied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    std::fs::write(
        out.join("plugin-xml-manifest.json"),
        r#"{"rsa_files":["plugin-xml-basic.xml","plugin-xml-ex.xml","plugin-xades-b.xml","plugin-xades-t.xml","plugin-xades-lt.xml"]}"#,
    )?;
    let oracle = std::process::Command::new("python")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/sdk_probe/plugin_xml_oracle.py"))
        .arg("--out")
        .arg(out)
        .output()?;
    std::fs::write(out.join("plugin-xml-oracle.stdout.log"), &oracle.stdout)?;
    std::fs::write(out.join("plugin-xml-oracle.stderr.log"), &oracle.stderr)?;
    std::fs::write(
        out.join("plugin-xml-oracle.exit.txt"),
        oracle.status.to_string(),
    )?;
    if !oracle.status.success() {
        return Err(format!("independent bounded XML oracle: {}", oracle.status).into());
    }
    std::fs::write(
        out.join("plugin-xml-report.json"),
        r#"{"actual_wasm":true,"xml_basic":true,"xml_ex_namespace_xpath_layout":true,"xades_levels":["B","T","LT"],"baseline_facts":"verified_by_host_Core","independent_Rsa_references":true,"low_output_private_uses":0,"late_trap_applied":true,"late_tsa_applied":true,"platform_acceptance":false}"#,
    )?;
    println!(
        "case=L01 xml=actual-wasm baseline=B,T,LT independent-bounded-rsa-oracle=verified low-output-private=0 late-trap-and-tsa=Applied"
    );
    Ok(())
}
