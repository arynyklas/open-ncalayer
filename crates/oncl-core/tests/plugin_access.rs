//! Actual synthetic WASM, real source-bound crypto, and negative private-use controls.
#[path = "../examples/sdk_probe/plugin_fixture.rs"]
mod fixture;
#[path = "../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod plugin_crypto;
#[path = "support/i01.rs"]
mod real_pki;
use fixture::*;
use oncl_core::{ErrorCode, plugins::*};

thread_local! { static REVIEW_ALLOCATED:std::cell::Cell<Option<usize>>=const {std::cell::Cell::new(None)}; }
struct ReviewAllocator;
#[global_allocator]
static REVIEW_ALLOCATOR: ReviewAllocator = ReviewAllocator;
unsafe impl std::alloc::GlobalAlloc for ReviewAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        // SAFETY: forwards the allocator contract unchanged; TLS bookkeeping allocates nothing.
        let pointer = unsafe { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) };
        if !pointer.is_null() {
            let _ = REVIEW_ALLOCATED.try_with(|counter| {
                if let Some(n) = counter.get() {
                    counter.set(Some(n.saturating_add(layout.size())))
                }
            });
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: the allocation and its original layout are forwarded unchanged.
        unsafe { std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        // SAFETY: preserves System's ownership/layout/reallocation requirements.
        let result =
            unsafe { std::alloc::GlobalAlloc::realloc(&std::alloc::System, pointer, layout, size) };
        if !result.is_null() {
            let _ = REVIEW_ALLOCATED.try_with(|counter| {
                if let Some(n) = counter.get() {
                    counter.set(Some(n.saturating_add(size)))
                }
            });
        }
        result
    }
}
use oncl_pdk::abi::{self, Import};
use std::sync::atomic::Ordering;
fn raw(handle: u32) -> (Import, Vec<u8>) {
    (
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle,
            data: MESSAGE.to_vec().into(),
        }),
    )
}
fn call<'a>(args: &'a str) -> PluginCall<'a> {
    PluginCall {
        plugin_id: ID,
        operation: "sign",
        args,
    }
}
#[test]
fn installed_is_not_authorized() {
    // Break caught: installed registry entry is treated as caller/key authority.
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw];
    let (engine, guard, provider) = engine(&[raw(1)], &keys, &methods);
    let bindings = [binding(&key, 1)];
    let caller = caller();
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = begin(&engine, &keys, None);
    let error = engine
        .plugin_call(&call("{}"), &bound, &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    drop(ctx);
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let result = engine.plugin_call(&call("{}"), &bound, &mut ctx).unwrap();
    let signature = signature(result.response());
    crypto::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(oncl_pki::key::SigAlg::RsaSha256, MESSAGE, &signature)
        .unwrap();
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert!(!ctx.policy().allow_prehashed);
    assert_eq!(guard.events.lock().unwrap()[0].operation_id, ctx.id());
    assert_eq!(
        guard.events.lock().unwrap()[0].action,
        oncl_core::Action::Sign
    );
    assert_eq!(guard.events.lock().unwrap()[0].batch_item(), None);
}
#[test]
fn allowed_method_cannot_smuggle_sign() {
    // Break caught: route authorization replaces checking every actual nested import/key/caller.
    let key = crypto::selector("user-rsa-sign");
    let other = crypto::selector("user-gost2004-sign");
    let all = [key.clone(), other.clone()];
    let allowed = [key.clone()];
    let methods = [Import::Hash, Import::KeysSignRaw];
    let (engine, guard, provider) = engine(&[raw(2)], &all, &methods);
    let bindings = [binding(&key, 1), binding(&other, 2)];
    let caller = caller();
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = begin(&engine, &all, Some(permission(&methods, &allowed)));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    drop(ctx);
    let mut ctx = begin(&engine, &all, Some(permission(&[Import::Hash], &all)));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    drop(ctx);
    let mut ctx = begin(&engine, &all, Some(permission(&methods, &all)));
    let impostor = CallerContext::ServiceClient("https://trusted.example".into());
    let fake = PluginBindings::new(&impostor, &bindings);
    assert_eq!(
        engine
            .plugin_call(
                &call(r#"{"origin":"https://trusted.example","method":"sign","handle":1}"#),
                &fake,
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}
#[test]
fn dialog_is_interaction_required() {
    // Break caught: mandatory interaction becomes cancellation/auto-consent or reaches GUI lock.
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::DialogConfirm, Import::KeysSignRaw];
    let calls = [
        (
            Import::DialogConfirm,
            abi::encode(&abi::ConfirmArgs {
                text: "Mandatory consent".into(),
            }),
        ),
        raw(1),
    ];
    let (engine, guard, provider) = engine(&calls, &keys, &methods);
    let bindings = [binding(&key, 1)];
    let caller = caller();
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InteractionRequired
    );
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn private_use_before_later_guest_refusal_is_not_rolled_back() {
    // Break caught: a later capability refusal claims NotApplied after real signature creation.
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw, Import::DialogConfirm];
    let calls = [
        raw(1),
        (
            Import::DialogConfirm,
            abi::encode(&abi::ConfirmArgs {
                text: "too late".into(),
            }),
        ),
    ];
    let (engine, guard, _) = engine(&calls, &keys, &methods);
    let bindings = [binding(&key, 1)];
    let caller = caller();
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let error = engine
        .plugin_call(
            &call("{}"),
            &PluginBindings::new(&caller, &bindings),
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InteractionRequired);
    assert_eq!(
        error.applied_state(),
        oncl_core::keys::AppliedState::Applied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
}

#[test]
fn original_guard_finish_failure_keeps_first_cause_and_stops_same_context() {
    // Break caught: adapter replaces the original ctx/guard, or retries after guard failure.
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw];
    let (engine, guard, provider) = engine(&[raw(1), raw(1)], &keys, &methods);
    let bindings = [binding(&key, 1)];
    let caller = caller();
    let bound = PluginBindings::new(&caller, &bindings);
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    guard.audit_fail.store(true, Ordering::SeqCst);
    let error = engine
        .plugin_call(&call("{}"), &bound, &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuditFailed);
    assert_eq!(
        error.applied_state(),
        oncl_core::keys::AppliedState::Applied
    );
    guard.audit_fail.store(false, Ordering::SeqCst);
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bound, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    drop(ctx);
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    engine.plugin_call(&call("{}"), &bound, &mut ctx).unwrap();
    assert_eq!(guard.applied.load(Ordering::SeqCst), 3);
}

fn decoded<T: serde::de::DeserializeOwned>(response: &str) -> T {
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    abi::decode::<abi::HostResult<T>>(&bytes).unwrap().unwrap()
}

#[test]
fn bound_settings_survive_real_wasm_without_distribution() {
    let directory = tempfile::tempdir().unwrap();
    let settings =
        oncl_plugin::headless::BoundSettings::new(directory.path().to_owned(), ID).unwrap();
    let values = std::collections::BTreeMap::from([("language".to_owned(), "kk".to_owned())]);
    let methods = [Import::SettingsPut, Import::SettingsGet];
    let calls = [
        (Import::SettingsPut, abi::encode(&values)),
        (Import::SettingsGet, abi::encode(&())),
    ];
    let (engine, _, _) = engine(&calls, &[], &methods);
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &[]).with_settings(&settings);
    let mut ctx = begin(&engine, &[], Some(permission(&methods, &[])));
    let result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    assert_eq!(
        decoded::<std::collections::BTreeMap<String, String>>(result.response()),
        values
    );
}

#[test]
fn files_are_frozen_bound_sources_and_unpublished_outputs() {
    use oncl_pki::io::{FrozenInput, Source, TemporaryStore};
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let methods = [Import::PageFileRead, Import::PageFileWrite];
    let p = permission(&methods, &[]).with_files(["document", "result/output.bin"]);
    let calls = [
        (
            Import::PageFileRead,
            abi::encode(&abi::PagePathArgs {
                path: "document".into(),
            }),
        ),
        (
            Import::PageFileWrite,
            abi::encode(&abi::PageWriteArgs {
                dir: "result".into(),
                name: "output.bin".into(),
                data: b"bounded public output".to_vec().into(),
            }),
        ),
    ];
    let (engine, _, _) =
        engine_configured(&calls, p.clone(), |s| s.with_temporary_store(store.clone()));
    let mut ctx = begin(&engine, &[], Some(p));
    let mut source = FrozenInput::capture(
        Source::sequential(&mut std::io::Cursor::new(b"immutable document"), None),
        &store,
        ctx.resources(),
    )
    .unwrap();
    let inputs = [PluginInputBinding::new("document", &mut source)];
    let outputs = [PluginOutputBinding {
        directory: "result",
        name: "output.bin",
    }];
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &[]).with_files(&inputs, &outputs);
    let mut result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    assert_eq!(
        decoded::<abi::PageWrite>(result.response()),
        abi::PageWrite::Written("result/output.bin".into())
    );
    let output = result.take_output("result/output.bin").unwrap();
    let mut bytes = Vec::new();
    output.copy_to(&mut bytes).unwrap();
    assert_eq!(bytes, b"bounded public output");
    assert!(!dir.path().join("result/output.bin").exists());
}

#[test]
fn forged_origin_and_unbound_paths_never_reach_transports() {
    use oncl_pki::{http::*, validation::NetworkPolicy};
    struct Transport(std::sync::atomic::AtomicUsize);
    impl HttpTransport for Transport {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.url, "https://network.synthetic.test/document");
            assert!(!request.opts.redirects);
            Ok(HttpReply {
                status: 200,
                content_type: None,
                location: None,
                body: b"bound server data".to_vec(),
            })
        }
    }
    let transport = Transport(std::sync::atomic::AtomicUsize::new(0));
    let network = NetworkPolicy::only_endpoints(["https://network.synthetic.test"]).unwrap();
    let methods = [Import::HttpRequestEx];
    let p = permission(&methods, &[])
        .with_http_endpoints(["https://network.synthetic.test/document"])
        .unwrap();
    let args = abi::HttpExArgs {
        method: abi::Method::Get,
        url: "https://network.synthetic.test/document".into(),
        relative_to_origin: false,
        headers: vec![],
        content_type: None,
        body: Vec::new().into(),
        timeout_ms: None,
    };
    let (engine, _, _) = engine_configured(
        &[(Import::HttpRequestEx, abi::encode(&args))],
        p.clone(),
        |s| s,
    );
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &[]).with_network(&transport, &network);
    let mut ctx = begin(&engine, &[], Some(p.clone()));
    let response = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    assert_eq!(
        decoded::<abi::HttpResponse>(response.response())
            .body
            .as_ref(),
        b"bound server data"
    );
    drop(response);
    drop(ctx);
    let args = abi::HttpExArgs {
        url: "/document".into(),
        relative_to_origin: true,
        ..args
    };
    let (engine, _, _) = engine_configured(
        &[(Import::HttpRequestEx, abi::encode(&args))],
        p.clone(),
        |s| s,
    );
    let mut ctx = begin(&engine, &[], Some(p));
    let error = engine
        .plugin_call(
            &call(r#"{"origin":"https://trusted.example"}"#),
            &bindings,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(transport.0.load(Ordering::SeqCst), 1);
}

#[test]
fn public_key_metadata_never_opens_or_exports_private_material() {
    use der::Encode;
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let entry = crypto::issued("user-rsa-sign");
    let methods = [Import::KeysDescribe, Import::KeysChain];
    let calls = [
        (
            Import::KeysDescribe,
            abi::encode(&abi::Handle { handle: 7 }),
        ),
        (Import::KeysChain, abi::encode(&abi::Handle { handle: 7 })),
    ];
    let (engine, guard, provider) = engine(&calls, &keys, &methods);
    let chain = [crypto::raw("inter-gost2015.key").cert];
    let bindings = [
        PluginKeyBinding::new(7, oncl_core::keys::KeyRequest::new(&key, None))
            .with_public_metadata(&entry.alias, &entry.cert, &chain),
    ];
    let caller = caller();
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let result = engine
        .plugin_call(
            &call("{}"),
            &PluginBindings::new(&caller, &bindings),
            &mut ctx,
        )
        .unwrap();
    let actual: Vec<abi::Bytes> = decoded(result.response());
    assert_eq!(actual[0].as_ref(), entry.cert.to_der().unwrap());
    assert_eq!(actual[1].as_ref(), chain[0].to_der().unwrap());
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn guest_http_and_private_pki_share_one_actual_request_cap() {
    use oncl_pki::{http::*, validation::NetworkPolicy};
    struct Transport(std::sync::atomic::AtomicUsize);
    impl HttpTransport for Transport {
        fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HttpReply {
                status: 200,
                content_type: None,
                location: None,
                body: vec![],
            })
        }
    }
    let transport = Transport(std::sync::atomic::AtomicUsize::new(0));
    let network = NetworkPolicy::only_endpoints(["https://network.synthetic.test"]).unwrap();
    let request = (
        Import::HttpRequest,
        abi::encode(&abi::HttpArgs {
            method: abi::Method::Get,
            url: "https://network.synthetic.test/".into(),
            content_type: None,
            body: vec![].into(),
        }),
    );
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::HttpRequest, Import::KeysSignRaw];
    let p = permission(&methods, &keys)
        .with_http_endpoints(["https://network.synthetic.test/"])
        .unwrap();
    let mut calls = vec![request; oncl_plugin::MAX_HTTP_REQUESTS as usize];
    calls.push(raw(1));
    let (engine, guard, _) = engine_configured(&calls, p.clone(), |s| s);
    let caller = caller();
    let keys_bound = [binding(&key, 1)];
    let bound = PluginBindings::new(&caller, &keys_bound).with_network(&transport, &network);
    let mut ctx = begin(&engine, &keys, Some(p));
    let error = engine
        .plugin_call(&call("{}"), &bound, &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CapacityExceeded);
    assert_eq!(transport.0.load(Ordering::SeqCst), 64);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_redirect_metadata_is_returned_without_following() {
    use oncl_pki::{http::*, validation::NetworkPolicy};
    struct Redirect(std::sync::atomic::AtomicUsize);
    impl HttpTransport for Redirect {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            assert!(!request.opts.redirects);
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HttpReply {
                status: 302,
                content_type: Some("text/plain".into()),
                location: Some("http://127.0.0.1/private".into()),
                body: b"not followed".to_vec(),
            })
        }
    }
    let transport = Redirect(std::sync::atomic::AtomicUsize::new(0));
    let policy = NetworkPolicy::only_endpoints(["https://network.synthetic.test"]).unwrap();
    let methods = [Import::HttpRequest];
    let p = permission(&methods, &[])
        .with_http_endpoints(["https://network.synthetic.test/"])
        .unwrap();
    let (engine, _, _) = engine_configured(
        &[(
            Import::HttpRequest,
            abi::encode(&abi::HttpArgs {
                method: abi::Method::Get,
                url: "https://network.synthetic.test/".into(),
                content_type: None,
                body: vec![].into(),
            }),
        )],
        p.clone(),
        |s| s,
    );
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &[]).with_network(&transport, &policy);
    let mut ctx = begin(&engine, &[], Some(p));
    let result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    let response: abi::HttpResponse = decoded(result.response());
    assert_eq!(response.status, 302);
    assert_eq!(
        response.location.as_deref(),
        Some("http://127.0.0.1/private")
    );
    assert_eq!(response.body.as_ref(), b"not followed");
    assert_eq!(transport.0.load(Ordering::SeqCst), 1);
}

fn cms_ex(content: abi::CmsContent) -> abi::SignCmsExArgs {
    abi::SignCmsExArgs {
        handle: 1,
        content,
        encapsulate: true,
        cosign: abi::CoSign::Never,
        econtent_type: None,
        digest: Some(abi::HashAlg::Sha256),
        attrs: abi::SignedAttrs {
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: Some(abi::SigningTime {
                at: abi::TimeSource::UnixMs(1_793_620_800_000),
                form: abi::TimeForm::Generalized,
            }),
            extra: vec![abi::RawAttribute {
                oid: "1.2.3.4".into(),
                values: vec![vec![4, 3, b'a', b'b', b'c'].into()],
            }],
        },
        certificates: abi::CmsCerts::Chain,
        timestamp: None,
        output: abi::CmsOutput::Der,
    }
}
#[test]
fn actual_wasm_cms_profiles_use_guarded_leaf_signer_and_deny_prehash_upgrade() {
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignCmsEx];
    let args = cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into()));
    let (engine, guard, _) = engine(
        &[(Import::KeysSignCmsEx, abi::encode(&args))],
        &keys,
        &methods,
    );
    let entry = crypto::issued("user-rsa-sign");
    let chain = [crypto::raw("inter-gost2015.key").cert];
    let bound_keys = [binding(&key, 1).with_public_metadata(&entry.alias, &entry.cert, &chain)];
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &bound_keys);
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    let abi::CmsOutcome::Signed(cms) = decoded(result.response()) else {
        panic!("real CMS was not returned")
    };
    let verified = oncl_pki::cms::verify(&cms, None).unwrap();
    assert_eq!(verified[0].sig_alg, oncl_pki::key::SigAlg::RsaSha256);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert!(!ctx.policy().allow_prehashed);
    drop(result);
    drop(ctx);
    let digest = oncl_pki::key::SigAlg::RsaSha256.digest(MESSAGE);
    let args = abi::SignCmsExArgs {
        content: abi::CmsContent::Digest(digest.into()),
        encapsulate: false,
        ..args
    };
    let (engine, guard, provider) = fixture::engine(
        &[(Import::KeysSignCmsEx, abi::encode(&args))],
        &keys,
        &methods,
    );
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let error = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
}

#[test]
fn wasm_verification_never_promotes_guest_chain_to_trusted_roots() {
    let entry = crypto::raw("user-rsa-sign");
    let cms = oncl_pki::cms::sign_spec(
        &entry,
        &[],
        &oncl_pki::cms::SignSpec {
            content: oncl_pki::cms::Content::Data(MESSAGE),
            encapsulate: true,
            cosign: oncl_pki::cms::CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: oncl_pki::cms::AttrSpec::cades(crypto::NOW),
            certificates: oncl_pki::cms::CertSpec::Signer,
        },
    )
    .unwrap();
    let methods = [Import::CmsVerify];
    let args = abi::VerifyArgs {
        cms: cms.into(),
        data: None,
        at: abi::VerifyAt::SigningTime,
        chain: Some(vec![oncl_testkit::synthetic_cert("root-rsa").into()]),
        revocation: abi::Revocation::None,
        first_signer_only: false,
        require_key_usage: vec![],
    };
    let (engine, guard, provider) =
        engine(&[(Import::CmsVerify, abi::encode(&args))], &[], &methods);
    let mut ctx = engine
        .begin(
            oncl_core::ExecutionGrant::new([oncl_core::Action::Validate])
                .with_plugins([permission(&methods, &[])]),
            oncl_core::OperationPolicy::strict_online(),
            std::sync::Arc::new(Control),
        )
        .unwrap();
    let caller = caller();
    let result = engine
        .plugin_call(&call("{}"), &PluginBindings::new(&caller, &[]), &mut ctx)
        .unwrap();
    let report: abi::VerifyReport = decoded(result.response());
    assert_eq!(report.signers[0].signature, abi::Check::Ok);
    assert!(matches!(report.signers[0].path, abi::Check::Fail(_)));
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
}

#[test]
fn forbidden_bound_token_sends_no_apdu() {
    use oncl_core::keys::{KeyRequest, KeySelector, KeySources};
    use oncl_token::{
        TokenKind, Tokens,
        emulator::{CardSpec, EmuKey, EmulatorBackend, card},
        execution::{TokenDeviceId, TokenGateRegistry},
    };
    use std::sync::Arc;
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader("L01 reader");
    let entry = crypto::issued("user-rsa-sign");
    let alias = entry.alias.clone();
    emu.insert(
        "L01 reader",
        card(CardSpec::new(
            TokenKind::Kaztoken,
            "123456",
            vec![EmuKey { entry }],
        )),
    );
    let key = KeySelector::token(
        TokenDeviceId::new("L01 reader").unwrap(),
        TokenKind::Kaztoken,
        alias,
    );
    let provider = KeySources::new().with_tokens(
        Tokens::new(emu.clone(), true),
        Arc::new(TokenGateRegistry::new(1, 1).unwrap()),
    );
    let guard = Arc::new(crypto::Guard::default());
    let methods = [Import::KeysSignRaw];
    let host = permission(&methods, std::slice::from_ref(&key));
    let (engine, _, _) = engine_configured(&[raw(1)], host, |s| {
        s.with_keys(Arc::new(provider), guard.clone())
    });
    let caller = caller();
    let bindings = [PluginKeyBinding::new(
        1,
        KeyRequest::new(&key, Some("123456")),
    )];
    let mut ctx = begin(
        &engine,
        std::slice::from_ref(&key),
        Some(permission(&methods, &[])),
    );
    assert_eq!(
        engine
            .plugin_call(
                &call("{}"),
                &PluginBindings::new(&caller, &bindings),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert!(emu.exchanges("L01 reader").is_empty());
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn explicit_pki_endpoint_grants_are_not_guest_http_authority() {
    use oncl_pki::{http::*, pkix::CaSet, tsp::MockTsa, validation::NetworkPolicy};
    use std::sync::Arc;
    struct Counted {
        tsa: MockTsa,
        calls: AtomicUsize,
    }
    use std::sync::atomic::AtomicUsize;
    impl HttpTransport for Counted {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.tsa.send(request)
        }
    }
    let transport = Arc::new(Counted {
        tsa: MockTsa::new(crypto::raw("tsa-gost2015")).with_gen_time(crypto::NOW),
        calls: AtomicUsize::new(0),
    });
    let methods = [Import::TspRequest];
    let guest = permission(&methods, &[])
        .with_http_endpoints(["http://tsp.pki.gov.kz"])
        .unwrap();
    let host = guest
        .clone()
        .with_pki_endpoints([(HttpMethod::Get, "http://tsp.pki.gov.kz")])
        .unwrap();
    let args = abi::TspRequestArgs {
        tsa: abi::TsaSpec {
            url: abi::PkiUrl::Default,
            method: abi::PkiMethod::Get,
            hash: abi::HashAlg::Sha256,
            policy: None,
            nonce: abi::Nonce::Random(8),
            cert_req: true,
            retries: 0,
            timeout_ms: 5000,
            check_skew_ms: None,
            require_tsa_eku: true,
        },
        imprint: vec![7; 32].into(),
    };
    let (engine, _, _) = engine_configured(
        &[(Import::TspRequest, abi::encode(&args))],
        host.clone(),
        |s| {
            s.with_validation(oncl_core::ValidationServices::new(
                CaSet::new(vec![crypto::raw("root-gost2015.key").cert]),
                vec![],
                transport.clone(),
                NetworkPolicy::only_endpoints(["http://tsp.pki.gov.kz"]).unwrap(),
                Arc::new(|| crypto::NOW),
            ))
        },
    );
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &[]);
    let mut ctx = begin(&engine, &[], Some(guest));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    drop(ctx);
    let mut ctx = begin(&engine, &[], Some(host));
    let result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    let abi::TspOutcome::Ok {
        token, gen_time_ms, ..
    } = decoded(result.response())
    else {
        panic!("TSA did not grant")
    };
    assert_eq!(gen_time_ms, crypto::NOW.unix_timestamp() * 1000);
    assert_eq!(oncl_pki::cms::verify(&token, None).unwrap().len(), 1);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn plugin_reply_retains_the_original_operation_admission() {
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw];
    let (engine, _, _) = engine(&[raw(1)], &keys, &methods);
    let caller = caller();
    let keys_bound = [binding(&key, 1)];
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let result = engine
        .plugin_call(
            &call("{}"),
            &PluginBindings::new(&caller, &keys_bound),
            &mut ctx,
        )
        .unwrap();
    drop(ctx);
    assert!(
        engine
            .begin(
                oncl_core::ExecutionGrant::new([oncl_core::Action::Hash]),
                oncl_core::OperationPolicy::strict_online(),
                std::sync::Arc::new(Control)
            )
            .is_err()
    );
    drop(result);
    engine
        .begin(
            oncl_core::ExecutionGrant::new([oncl_core::Action::Hash]),
            oncl_core::OperationPolicy::strict_online(),
            std::sync::Arc::new(Control),
        )
        .unwrap();
}

#[test]
fn frozen_file_from_another_operation_cannot_enter_this_invocation() {
    use oncl_pki::{
        io::{FrozenInput, Source, TemporaryStore},
        resource::ResourceLimits,
    };
    use std::sync::Arc;
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let owner = crypto::engine(
        store.clone(),
        Arc::new(crypto::Guard::default()),
        Arc::new(crypto::Provider::default()),
        ResourceLimits::default(),
    );
    let mut original = owner
        .begin(
            oncl_core::ExecutionGrant::new([oncl_core::Action::Hash]),
            oncl_core::OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut std::io::Cursor::new(b"foreign snapshot"), None),
        &store,
        original.resources(),
    )
    .unwrap();
    let methods = [Import::PageFileRead];
    let p = permission(&methods, &[]).with_files(["document"]);
    let (engine, guard, _) = engine_configured(
        &[(
            Import::PageFileRead,
            abi::encode(&abi::PagePathArgs {
                path: "document".into(),
            }),
        )],
        p.clone(),
        |s| s,
    );
    let inputs = [PluginInputBinding::new("document", &mut frozen)];
    let caller = caller();
    let bindings = PluginBindings::new(&caller, &[]).with_files(&inputs, &[]);
    let mut ctx = begin(&engine, &[], Some(p));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn repeated_plugin_calls_cannot_reset_the_original_context_request_budget() {
    use oncl_pki::{http::*, validation::NetworkPolicy};
    use std::sync::atomic::AtomicUsize;
    struct Transport(AtomicUsize);
    impl HttpTransport for Transport {
        fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HttpReply {
                status: 200,
                content_type: None,
                location: None,
                body: vec![],
            })
        }
    }
    let transport = Transport(AtomicUsize::new(0));
    let methods = [Import::HttpRequest];
    let p = permission(&methods, &[])
        .with_http_endpoints(["https://network.synthetic.test/"])
        .unwrap();
    let request = (
        Import::HttpRequest,
        abi::encode(&abi::HttpArgs {
            method: abi::Method::Get,
            url: "https://network.synthetic.test/".into(),
            content_type: None,
            body: vec![].into(),
        }),
    );
    let (engine, _, _) = engine_configured(&vec![request; 64], p.clone(), |s| s);
    let caller = caller();
    let network = NetworkPolicy::only_endpoints(["https://network.synthetic.test"]).unwrap();
    let bindings = PluginBindings::new(&caller, &[]).with_network(&transport, &network);
    let mut ctx = begin(&engine, &[], Some(p));
    drop(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap(),
    );
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    assert_eq!(transport.0.load(Ordering::SeqCst), 64);
}

#[test]
fn guest_log_acknowledges_without_emitting_payload_at_any_level() {
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
    const SENTINEL: &str = "L01_PRIVATE_DOCUMENT_SENTINEL_NO_TRACE";
    let methods = [Import::Log];
    let calls = [(
        Import::Log,
        abi::encode(&abi::LogArgs {
            level: abi::Level::Error,
            message: SENTINEL.into(),
        }),
    )];
    let (engine, _, _) = engine(&calls, &[], &methods);
    let caller = caller();
    let mut ctx = begin(&engine, &[], Some(permission(&methods, &[])));
    let capture = Capture(Arc::default());
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, || {
        engine.plugin_call(&call("{}"), &PluginBindings::new(&caller, &[]), &mut ctx)
    })
    .unwrap();
    decoded::<()>(result.response());
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        !output.contains(SENTINEL),
        "guest document payload entered tracing"
    );
}

#[test]
fn mandatory_private_status_checks_require_invocation_pki_grants() {
    use oncl_pki::http::*;
    use std::sync::{Arc, Mutex};
    struct Counted {
        inner: Arc<dyn HttpTransport>,
        urls: Arc<Mutex<Vec<String>>>,
    }
    impl HttpTransport for Counted {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.urls.lock().unwrap().push(request.url.into());
            self.inner.send(request)
        }
    }
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw];
    let allowed = permission(&methods, &keys);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let observed = sent.clone();
    let (engine, guard, _) = engine_configured(&[raw(1)], allowed.clone(), |services| {
        services.with_validation(crypto::validation_using(|inner| {
            Arc::new(Counted {
                inner,
                urls: observed,
            })
        }))
    });
    let denied = PluginPermission::new(ID, "sign", caller(), methods).with_keys([key.key_id()]);
    let mut ctx = begin(&engine, &keys, Some(denied));
    let caller = caller();
    let keys_bound = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &keys_bound);
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert!(sent.lock().unwrap().is_empty());
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
}

#[test]
fn root_pki_get_grant_is_not_a_fixed_path_or_post_wildcard() {
    use oncl_pki::{http::*, pkix::CaSet, tsp::MockTsa, validation::NetworkPolicy};
    use std::sync::{Arc, atomic::AtomicUsize};
    struct Counted {
        inner: MockTsa,
        sends: AtomicUsize,
    }
    impl HttpTransport for Counted {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            self.inner.send(request)
        }
    }
    for (url, method) in [
        ("http://tsp.pki.gov.kz/other/path", abi::PkiMethod::Get),
        (
            "http://tsp.pki.gov.kz",
            abi::PkiMethod::Post { content_type: None },
        ),
        (
            "http://tsp.pki.gov.kz/other/path",
            abi::PkiMethod::Post { content_type: None },
        ),
        ("http://tsp.pki.gov.kz/%2fother", abi::PkiMethod::Get),
        ("http://tsp.pki.gov.kz/a/../", abi::PkiMethod::Get),
        ("http://tsp.pki.gov.kz:80", abi::PkiMethod::Get),
        ("http://tsp.pki.gov.kz:81", abi::PkiMethod::Get),
        ("http://user@tsp.pki.gov.kz", abi::PkiMethod::Get),
    ] {
        let transport = Arc::new(Counted {
            inner: MockTsa::new(crypto::raw("tsa-gost2015")).with_gen_time(crypto::NOW),
            sends: AtomicUsize::new(0),
        });
        let methods = [Import::TspRequest];
        let p = permission(&methods, &[])
            .with_pki_endpoints([(HttpMethod::Get, "http://tsp.pki.gov.kz")])
            .unwrap();
        let args = abi::TspRequestArgs {
            tsa: abi::TsaSpec {
                url: abi::PkiUrl::Fixed(url.into()),
                method,
                hash: abi::HashAlg::Sha256,
                policy: None,
                nonce: abi::Nonce::Random(8),
                cert_req: true,
                retries: 0,
                timeout_ms: 5000,
                check_skew_ms: None,
                require_tsa_eku: true,
            },
            imprint: vec![7; 32].into(),
        };
        let (engine, _, _) = engine_configured(
            &[(Import::TspRequest, abi::encode(&args))],
            p.clone(),
            |s| {
                s.with_validation(oncl_core::ValidationServices::new(
                    CaSet::new(vec![crypto::raw("root-gost2015.key").cert]),
                    vec![],
                    transport.clone(),
                    NetworkPolicy::only_endpoints([
                        "http://tsp.pki.gov.kz",
                        "http://tsp.pki.gov.kz:81",
                    ])
                    .unwrap(),
                    Arc::new(|| crypto::NOW),
                ))
            },
        );
        let caller = caller();
        let mut ctx = begin(&engine, &[], Some(p));
        let error = engine
            .plugin_call(&call("{}"), &PluginBindings::new(&caller, &[]), &mut ctx)
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied, "{url}");
        assert_eq!(transport.sends.load(Ordering::SeqCst), 0, "{url}");
    }
}

#[test]
fn tiny_guest_cannot_copy_a_large_bound_chain_or_apply_a_key_before_admission() {
    assert_bound_chain_admission(Import::KeysChain);
}
#[test]
fn tiny_cms_request_admits_actual_bound_chain_before_private_use() {
    assert_bound_chain_admission(Import::KeysSignCmsEx);
}
fn assert_bound_chain_admission(import: Import) {
    use oncl_pki::resource::{ResourceLimits, SharedBudget};
    use std::sync::Arc;
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let leaf = crypto::issued("user-rsa-sign");
    let issuer = crypto::raw("root-gost2015.key");
    let mut chain = vec![issuer.cert.clone(); 8192];
    for ordinal in 1u16..=32 {
        let mut certificate = oncl_pki::testing::TestCertSpec::from_cert(&issuer.cert);
        certificate.serial = ordinal.to_be_bytes().to_vec();
        chain.push(oncl_pki::testing::issue_cert(&issuer, certificate));
    }
    let methods = [import];
    let p = permission(&methods, &keys);
    let args = if import == Import::KeysChain {
        abi::encode(&abi::Handle { handle: 1 })
    } else {
        abi::encode(&cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into())))
    };
    let limits = ResourceLimits {
        metadata_bytes: 4 << 20,
        memory_bytes: 128 << 20,
        ..ResourceLimits::default()
    };
    let (engine, guard, provider) = engine_configured(&[(import, args)], p.clone(), |services| {
        services.with_shared_budget(Arc::new(SharedBudget::new(limits).unwrap()))
    });
    let bound_keys = [binding(&key, 1).with_public_metadata(&leaf.alias, &leaf.cert, &chain)];
    let caller = caller();
    let mut ctx = begin(&engine, &keys, Some(p));
    REVIEW_ALLOCATED.with(|counter| counter.set(Some(0)));
    let result = engine.plugin_call(
        &call("{}"),
        &PluginBindings::new(&caller, &bound_keys),
        &mut ctx,
    );
    let allocated = REVIEW_ALLOCATED.with(|counter| counter.replace(None).unwrap());
    let error = result.unwrap_err();
    assert!(
        matches!(
            error.code(),
            ErrorCode::MetadataLimit | ErrorCode::MemoryLimit
        ),
        "{import:?}: {error:?}"
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0, "{import:?}");
    assert_eq!(provider.opens.load(Ordering::SeqCst), 0, "{import:?}");
    assert!(
        allocated < 2 << 20,
        "{import:?} copied host metadata before admission: {allocated} bytes"
    );
}

#[test]
fn known_cms_output_limit_is_refused_before_private_use_without_debit() {
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignCmsEx];
    let mut args = cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into()));
    args.certificates = abi::CmsCerts::Signer;
    let limits = oncl_pki::resource::ResourceLimits {
        output_bytes: 32,
        ..oncl_pki::resource::ResourceLimits::default()
    };
    let p = permission(&methods, &keys);
    let (engine, guard, _) = engine_limited(
        &[(Import::KeysSignCmsEx, abi::encode(&args))],
        p.clone(),
        limits,
        |s| s,
    );
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(&engine, &keys, Some(p));
    let error = engine
        .plugin_call(&call("{}"), &PluginBindings::new(&caller, &bound), &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::OutputLimit);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(ctx.resources().progress().bytes_out, 0);
}

#[test]
fn cms_format_projection_matches_real_der_base64_and_pem_without_double_debit() {
    use base64::Engine as _;
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignCmsEx];
    for output in [
        abi::CmsOutput::Der,
        abi::CmsOutput::Base64,
        abi::CmsOutput::Pem,
    ] {
        let mut args = cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into()));
        args.certificates = abi::CmsCerts::Signer;
        args.output = output;
        let (engine, guard, _) = engine(
            &[(Import::KeysSignCmsEx, abi::encode(&args))],
            &keys,
            &methods,
        );
        let caller = caller();
        let bound = [binding(&key, 1)];
        let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
        let result = engine
            .plugin_call(&call("{}"), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap();
        let abi::CmsOutcome::Signed(bytes) = decoded(result.response()) else {
            panic!("CMS missing")
        };
        assert_eq!(
            ctx.resources().progress().bytes_out,
            bytes.len() as u64 + result.response().len() as u64
        );
        let der = match output {
            abi::CmsOutput::Der => bytes.to_vec(),
            abi::CmsOutput::Base64 => base64::engine::general_purpose::STANDARD
                .decode(&bytes)
                .unwrap(),
            abi::CmsOutput::Pem => {
                let pem = std::str::from_utf8(&bytes).unwrap();
                let data = pem
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>();
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .unwrap()
            }
        };
        assert_eq!(oncl_pki::cms::verify(&der, None).unwrap().len(), 1);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn cms_preflight_does_not_fabricate_output_when_original_guard_refuses() {
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignCmsEx];
    let mut args = cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into()));
    args.certificates = abi::CmsCerts::Signer;
    let (engine, guard, _) = engine(
        &[(Import::KeysSignCmsEx, abi::encode(&args))],
        &keys,
        &methods,
    );
    guard.deny.store(true, Ordering::SeqCst);
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &PluginBindings::new(&caller, &bound), &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    assert_eq!(ctx.resources().progress().bytes_out, 0);
}

#[test]
fn authoritative_verify_and_cosign_cannot_bypass_pki_invocation_grants() {
    use oncl_pki::{cms, http::*};
    use std::sync::{Arc, Mutex};
    struct Counted {
        inner: Arc<dyn HttpTransport>,
        sent: Arc<Mutex<Vec<String>>>,
    }
    impl HttpTransport for Counted {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.sent.lock().unwrap().push(request.url.into());
            self.inner.send(request)
        }
    }
    let existing = crypto::raw("inter-user-gost2015-sign");
    let original = cms::sign_spec(
        &existing,
        &[],
        &cms::SignSpec {
            content: cms::Content::Data(MESSAGE),
            encapsulate: true,
            cosign: cms::CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: cms::AttrSpec::cades(crypto::NOW),
            certificates: cms::CertSpec::Signer,
        },
    )
    .unwrap();
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    for import in [Import::CmsVerify, Import::KeysSignCmsEx] {
        let args = if import == Import::CmsVerify {
            abi::encode(&abi::VerifyArgs {
                cms: original.clone().into(),
                data: None,
                at: abi::VerifyAt::Now,
                chain: None,
                revocation: abi::Revocation::LiveOcspThenCrl,
                first_signer_only: false,
                require_key_usage: vec![],
            })
        } else {
            let mut args = cms_ex(abi::CmsContent::Data(original.clone().into()));
            args.cosign = abi::CoSign::Auto;
            args.certificates = abi::CmsCerts::Signer;
            abi::encode(&args)
        };
        let p = permission(&[import], &keys);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let observed = sent.clone();
        let (engine, guard, provider) = engine_configured(&[(import, args)], p, |services| {
            services.with_validation(crypto::validation_using(|inner| {
                Arc::new(Counted {
                    inner,
                    sent: observed,
                })
            }))
        });
        let denied =
            PluginPermission::new(ID, "sign", caller(), [import]).with_keys([key.key_id()]);
        let mut ctx = engine
            .begin(
                oncl_core::ExecutionGrant::new([
                    oncl_core::Action::Sign,
                    oncl_core::Action::Validate,
                ])
                .with_keys([key.key_id()])
                .with_plugins([denied]),
                oncl_core::OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let caller = caller();
        let bound = [binding(&key, 1)];
        assert_eq!(
            engine
                .plugin_call(&call("{}"), &PluginBindings::new(&caller, &bound), &mut ctx)
                .unwrap_err()
                .code(),
            ErrorCode::PermissionDenied
        );
        assert!(sent.lock().unwrap().is_empty(), "{import:?}");
        assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn mandatory_status_redirects_are_not_followed_even_when_host_network_is_wider() {
    use oncl_pki::http::*;
    use std::sync::{Arc, Mutex};
    struct Redirect {
        inner: Arc<dyn HttpTransport>,
        sent: Arc<Mutex<Vec<String>>>,
    }
    impl HttpTransport for Redirect {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            assert!(!request.opts.redirects);
            self.sent.lock().unwrap().push(request.url.into());
            if request.url.starts_with("http://ocsp.synthetic.test/") {
                Ok(HttpReply {
                    status: 302,
                    content_type: None,
                    location: Some("http://crl.synthetic.test/redirected".into()),
                    body: vec![],
                })
            } else {
                self.inner.send(request)
            }
        }
    }
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw];
    let sent = Arc::new(Mutex::new(Vec::new()));
    let observed = sent.clone();
    let (engine, guard, _) =
        engine_configured(&[raw(1)], permission(&methods, &keys), |services| {
            services.with_validation(crypto::validation_using(|inner| {
                Arc::new(Redirect {
                    inner,
                    sent: observed,
                })
            }))
        });
    let caller = caller();
    let bound = [binding(&key, 1)];
    let mut ctx = begin(&engine, &keys, Some(permission(&methods, &keys)));
    let result = engine
        .plugin_call(&call("{}"), &PluginBindings::new(&caller, &bound), &mut ctx)
        .unwrap();
    crypto::raw("user-rsa-sign")
        .key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            MESSAGE,
            &signature(result.response()),
        )
        .unwrap();
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert!(
        sent.lock()
            .unwrap()
            .iter()
            .all(|url| !url.contains("/redirected"))
    );
}

#[test]
fn actual_wasm_nonroot_ocsp_binding_uses_real_pinned_http_only_after_exact_grant() {
    use der::Encode;
    use oncl_pki::{
        http::{HttpMethod, ProxySetting, UreqTransport},
        key::PrivateKey,
        pkcs12,
        testing::{TestCertSpec, issue_cert},
    };
    use std::sync::Arc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let fixtures = real_pki::SignedFixtures::new(&origin, crypto::NOW, real_pki::Status::Good);
    let server = real_pki::Server::start(listener, fixtures.clone());
    let mut root = crypto::raw("root-gost2015.key");
    root.key = PrivateKey::from_pkcs8_der(
        include_bytes!("../../../fixtures/openssl/rsa.pk8.der"),
        None,
    )
    .unwrap();
    root.cert = fixtures.root.clone();
    let mut leaf = crypto::raw("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&leaf.cert);
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions.extend(
        TestCertSpec::from_cert(&fixtures.tsa_cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    spec.serial = vec![0x22, 0x43];
    leaf.cert = issue_cert(&root, spec);
    let container = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: leaf.alias.clone(),
            pkcs8_der: leaf.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(leaf.cert.to_der().unwrap()),
        }],
        &[],
        crypto::PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x31),
    )
    .unwrap();
    let key = oncl_core::keys::KeySelector::inline(container, None);
    let keys = [key.clone()];
    let methods = [Import::KeysSignRaw];
    let allowed = PluginPermission::new(ID, "sign", caller(), methods)
        .with_keys([key.key_id()])
        .with_pki_endpoints([
            (HttpMethod::Get, format!("{origin}/ocsp")),
            (HttpMethod::Get, format!("{origin}/crl")),
        ])
        .unwrap();
    let transport = Arc::new(UreqTransport::with_proxy(ProxySetting::None));
    let (engine, guard, _) = engine_configured(&[raw(1)], allowed.clone(), |services| {
        services.with_validation(fixtures.services_with(true, transport))
    });
    let caller = caller();
    let bound = [binding(&key, 1)];
    let bindings = PluginBindings::new(&caller, &bound);
    let denied =
        PluginPermission::new(ID, "sign", caller.clone(), methods).with_keys([key.key_id()]);
    let mut ctx = begin(&engine, &keys, Some(denied));
    assert_eq!(
        engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(fixtures.requests.load(Ordering::SeqCst), 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 0);
    drop(ctx);
    let mut ctx = begin(&engine, &keys, Some(allowed));
    let result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    leaf.key
        .public_key()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            MESSAGE,
            &signature(result.response()),
        )
        .unwrap();
    assert!(fixtures.requests.load(Ordering::SeqCst) > 0);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    let before_tsa = fixtures.requests.load(Ordering::SeqCst);
    let methods = [Import::KeysSignCmsEx];
    let allowed = PluginPermission::new(ID, "sign", caller.clone(), methods)
        .with_keys([key.key_id()])
        .with_pki_endpoints([
            (HttpMethod::Get, format!("{origin}/ocsp")),
            (HttpMethod::Get, format!("{origin}/crl")),
            (HttpMethod::Post, format!("{origin}/tsa")),
        ])
        .unwrap();
    let mut args = cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into()));
    args.certificates = abi::CmsCerts::Signer;
    args.timestamp = Some(abi::TsaChoice::Custom(abi::TsaSpec {
        url: abi::PkiUrl::Fixed(format!("{origin}/tsa")),
        method: abi::PkiMethod::Post { content_type: None },
        hash: abi::HashAlg::Sha256,
        policy: None,
        nonce: abi::Nonce::Random(8),
        cert_req: true,
        retries: 0,
        timeout_ms: 5000,
        check_skew_ms: None,
        require_tsa_eku: true,
    }));
    let transport = Arc::new(UreqTransport::with_proxy(ProxySetting::None));
    let (engine, guard, _) = engine_configured(
        &[(Import::KeysSignCmsEx, abi::encode(&args))],
        allowed.clone(),
        |services| services.with_validation(fixtures.services_with(true, transport)),
    );
    let mut ctx = begin(&engine, &keys, Some(allowed));
    let result = engine
        .plugin_call(&call("{}"), &bindings, &mut ctx)
        .unwrap();
    let abi::CmsOutcome::Signed(cms) = decoded(result.response()) else {
        panic!("timestamped CMS missing")
    };
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    let token = signers[0]
        .timestamp_token
        .as_ref()
        .expect("TSA token absent");
    assert_eq!(oncl_pki::cms::verify(token, None).unwrap().len(), 1);
    assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
    assert!(fixtures.requests.load(Ordering::SeqCst) > before_tsa);
    server.finish().unwrap();
}

#[test]
fn nonplugin_context_keeps_legacy_host_authorized_redirects() {
    use oncl_pki::{http::*, pkix::CaSet, resource::ResourceLimits, validation::NetworkPolicy};
    use std::sync::{Arc, atomic::AtomicUsize};
    struct Redirect(AtomicUsize);
    impl HttpTransport for Redirect {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(if request.url.ends_with("/start") {
                HttpReply {
                    status: 302,
                    content_type: None,
                    location: Some("/after".into()),
                    body: vec![],
                }
            } else {
                HttpReply {
                    status: 200,
                    content_type: None,
                    location: None,
                    body: b"legacy".to_vec(),
                }
            })
        }
    }
    let transport = Arc::new(Redirect(AtomicUsize::new(0)));
    let services = oncl_core::ValidationServices::new(
        CaSet::new(vec![]),
        vec![],
        transport.clone(),
        NetworkPolicy::only_endpoints(["http://legacy.synthetic.test"]).unwrap(),
        Arc::new(|| crypto::NOW),
    );
    let engine = oncl_core::Engine::new(
        oncl_core::EngineServices::hash_only(ResourceLimits::default()).with_validation(services),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            oncl_core::ExecutionGrant::new([oncl_core::Action::Validate]),
            oncl_core::OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let request = HttpRequest::get(
        "http://legacy.synthetic.test/start",
        GetOptions {
            redirects: true,
            ..GetOptions::default()
        },
    );
    let result = engine.validation_http(&request, &mut ctx).unwrap();
    assert_eq!(result.status, 200);
    assert_eq!(transport.0.load(Ordering::SeqCst), 2);
}

#[test]
fn exact_fitting_cms_output_budget_is_debited_only_by_actual_outputs() {
    let key = crypto::selector("user-rsa-sign");
    let keys = [key.clone()];
    let methods = [Import::KeysSignCmsEx];
    for output in [
        abi::CmsOutput::Der,
        abi::CmsOutput::Base64,
        abi::CmsOutput::Pem,
    ] {
        let mut args = cms_ex(abi::CmsContent::Data(MESSAGE.to_vec().into()));
        args.certificates = abi::CmsCerts::Signer;
        args.output = output;
        let calls = [(Import::KeysSignCmsEx, abi::encode(&args))];
        let p = permission(&methods, &keys);
        let (first, _, _) = engine_configured(&calls, p.clone(), |s| s);
        let caller = caller();
        let bound = [binding(&key, 1)];
        let bindings = PluginBindings::new(&caller, &bound);
        let mut ctx = begin(&first, &keys, Some(p.clone()));
        let result = first.plugin_call(&call("{}"), &bindings, &mut ctx).unwrap();
        let exact = ctx.resources().progress().bytes_out;
        drop(result);
        drop(ctx);
        let limits = oncl_pki::resource::ResourceLimits {
            output_bytes: exact,
            ..oncl_pki::resource::ResourceLimits::default()
        };
        let (engine, guard, _) = engine_limited(&calls, p.clone(), limits, |s| s);
        let mut ctx = begin(&engine, &keys, Some(p));
        let result = engine
            .plugin_call(&call("{}"), &bindings, &mut ctx)
            .unwrap();
        let abi::CmsOutcome::Signed(bytes) = decoded(result.response()) else {
            panic!("CMS absent")
        };
        assert_eq!(ctx.resources().progress().bytes_out, exact);
        assert_eq!(exact, bytes.len() as u64 + result.response().len() as u64);
        assert_eq!(guard.applied.load(Ordering::SeqCst), 1);
        assert!(matches!(
            ctx.resources().check_output_capacity(1),
            Err(oncl_pki::resource::ProcessingError::OutputLimit)
        ));
    }
}
