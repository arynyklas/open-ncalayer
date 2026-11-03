//! Actual WASM, synthetic-only private use and an independent OpenSSL RSA oracle.
#[path = "plugin_fixture.rs"]
mod fixture;
use fixture::*;
use oncl_core::{ErrorCode, plugins::*};
use oncl_pdk::abi::{self, Import};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
fn call(args: &str) -> PluginCall<'_> {
    PluginCall {
        plugin_id: ID,
        operation: "sign",
        args,
    }
}
pub(super) fn run(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use der::Encode;
    std::fs::create_dir_all(out)?;
    let out = out.canonicalize()?;
    let key = crypto::selector("user-rsa-sign");
    let other = crypto::selector("user-gost2004-sign");
    let methods = [Import::KeysSignRaw];
    let signing = |handle| {
        (
            Import::KeysSignRaw,
            abi::encode(&abi::SignRawArgs {
                handle,
                data: MESSAGE.to_vec().into(),
            }),
        )
    };
    let (engine, guard, provider) =
        fixture::engine(&[signing(1)], std::slice::from_ref(&key), &methods);
    let caller = caller();
    let bound_keys = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound_keys);
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    let result = engine.plugin_call(&call("{}"), &bindings, &mut ctx)?;
    let signature = signature(result.response());
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    assert!(!ctx.policy().allow_prehashed);
    std::fs::write(out.join("message.bin"), MESSAGE)?;
    std::fs::write(out.join("signature.bin"), &signature)?;
    std::fs::write(
        out.join("certificate.der"),
        crypto::issued("user-rsa-sign").cert.to_der()?,
    )?;
    std::fs::write(out.join("altered.bin"), b"L01 altered document")?;
    let oracle =
        |name: &str, args: &[&str], success: bool| -> Result<(), Box<dyn std::error::Error>> {
            let output = std::process::Command::new("openssl")
                .current_dir(&out)
                .args(args)
                .output()?;
            std::fs::write(out.join(format!("{name}.stdout.log")), &output.stdout)?;
            std::fs::write(out.join(format!("{name}.stderr.log")), &output.stderr)?;
            if output.status.success() != success {
                return Err(format!("OpenSSL {name} returned {}", output.status).into());
            }
            Ok(())
        };
    oracle(
        "public-key",
        &[
            "x509",
            "-inform",
            "DER",
            "-in",
            "certificate.der",
            "-pubkey",
            "-noout",
            "-out",
            "public.pem",
        ],
        true,
    )?;
    oracle(
        "positive",
        &[
            "dgst",
            "-sha256",
            "-verify",
            "public.pem",
            "-signature",
            "signature.bin",
            "message.bin",
        ],
        true,
    )?;
    oracle(
        "altered-negative",
        &[
            "dgst",
            "-sha256",
            "-verify",
            "public.pem",
            "-signature",
            "signature.bin",
            "altered.bin",
        ],
        false,
    )?;
    drop(result);
    drop(ctx);
    let all = [key.clone(), other.clone()];
    let (engine, guard, provider) = fixture::engine(&[signing(2)], &all, &methods);
    let bound_keys = [binding(&key, 1), binding(&other, 2)];
    let bindings = PluginBindings::new(&caller, &bound_keys);
    let mut ctx = begin(
        &engine,
        &all,
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    let methods = [Import::DialogConfirm, Import::KeysSignRaw];
    let (engine, guard, provider) = fixture::engine(
        &[
            (
                Import::DialogConfirm,
                abi::encode(&abi::ConfirmArgs {
                    text: "mandatory".into(),
                }),
            ),
            signing(1),
        ],
        std::slice::from_ref(&key),
        &methods,
    );
    let bound_keys = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound_keys);
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, std::slice::from_ref(&key))),
    );
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InteractionRequired
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    struct NeverNetwork(AtomicUsize);
    impl oncl_pki::http::HttpTransport for NeverNetwork {
        fn send(
            &self,
            _: &oncl_pki::http::HttpRequest<'_>,
        ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(oncl_pki::http::HttpError::other(
                "forged origin reached transport",
            ))
        }
    }
    let methods = [Import::HttpRequestEx];
    let p = permission(&methods, &[]).with_http_endpoints(["https://trusted.example/private"])?;
    let request = abi::HttpExArgs {
        method: abi::Method::Get,
        url: "/private".into(),
        relative_to_origin: true,
        headers: vec![],
        content_type: None,
        body: vec![].into(),
        timeout_ms: None,
    };
    let (engine, _, _) = engine_configured(
        &[(Import::HttpRequestEx, abi::encode(&request))],
        p.clone(),
        |s| s,
    );
    let network = NeverNetwork(AtomicUsize::new(0));
    let policy = oncl_pki::validation::NetworkPolicy::only_endpoints(["https://trusted.example"])?;
    let bindings = PluginBindings::new(&caller, &[]).with_network(&network, &policy);
    let mut ctx = begin(&engine, &[], Some(p));
    assert_eq!(
        engine
            .plugin_call(
                &call(r#"{"origin":"https://trusted.example"}"#),
                &bindings,
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(network.0.load(Ordering::SeqCst), 0);
    std::fs::write(
        out.join("report.json"),
        r#"{"case":"L01","actual_wasm":true,"private_uses":1,"openssl_signature":"verified","altered":"rejected","forbidden_key":"permission_denied_before_open","prompt":"interaction_required_before_private_use","forged_origin":"permission_denied_without_network","fixture_limits":{"wasm_memory":1048576,"abi_transfer":262144},"platform_acceptance":false}"#,
    )?;
    println!(
        "case=L01 actual-wasm=executed private-uses=1 signature=openssl-verified altered=rejected forbidden-key=denied prompt=interaction-required forged-origin=denied out={}",
        out.display()
    );
    Ok(())
}
