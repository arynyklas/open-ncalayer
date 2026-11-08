//! The manual window's call path (docs/design/manual-plugins.md 4.2, 4.3, 4.8; MP3a-2): Core
//! prepares the consent from the declared operation and the frozen bytes, issues the approval
//! only for a confirmed summary, and runs the module under it with the one guard. Actual
//! synthetic WASM and real source-bound crypto, like `plugin_ticket`; every key use is a real
//! signature, checked by `oncl_pki` where it is cheap.
#![allow(dead_code)]
#![allow(clippy::disallowed_methods)] // Core's own tests make confirmations to test the guard
#[path = "../examples/sdk_probe/plugin_fixture.rs"]
mod fixture;
#[path = "../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod plugin_crypto;
#[path = "../examples/sdk_probe/plugin_xml_fixture.rs"]
mod xades_fixture;
use fixture::*;
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy,
    keys::{KeyLease, KeyProvider, KeyRequest, KeySelector, KeySources},
    plugins::*,
};
use oncl_pdk::abi::{self, Import};
use oncl_pki::{
    cert::Certificate,
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::TemporaryStore,
    key::{AppliedState, SigAlg},
    resource::ResourceLimits,
    validation::NetworkPolicy,
};
use oncl_plugin::{
    InstanceLimits, Manifest,
    manual::OcspCache,
    operations::{KeyKind, Profile, Source},
};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{Receiver, Sender, channel},
};
use std::time::{Duration, Instant};

const MODULE: &str = "test.l01.module";
const SHA: PackageHash = PackageHash::File([9; 32]);
const DOC: &[u8] = b"the document the user approved";
const OTHER: &[u8] = b"a document the user did not approve";
const XML: &[u8] = b"<r xmlns:p='urn:p' xml:lang='kk'><p:data Id='payload'>actual WASM protected text</p:data><p:more Id='second'>another</p:more></r>";
const PKI: [(oncl_pki::http::HttpMethod, &str); 3] = [
    (
        oncl_pki::http::HttpMethod::Get,
        "http://ocsp.synthetic.test",
    ),
    (
        oncl_pki::http::HttpMethod::Get,
        "http://crl.synthetic.test/root-gost2015.crl",
    ),
    (
        oncl_pki::http::HttpMethod::Get,
        "http://crl.synthetic.test/inter-gost2015.crl",
    ),
];

fn manual() -> CallerContext {
    CallerContext::LocalOperator("manual".to_owned())
}

const KEY_IMPORTS: &str = r#""keys_describe", "keys_chain", "keys_release""#;

fn operations() -> String {
    format!(
        r#"
[[operations]]
name = "sign-raw"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"m","args":["{{file:base64}}"]}}'
label = {{ ru = "EVIL-LABEL", kk = "EVIL-LABEL", en = "EVIL-LABEL" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[operations.uses]
imports = ["keys_sign_raw", {KEY_IMPORTS}, "keys_select"]
interactive = ["keys_select"]
network = "pki"
[[operations.uses.key]]
kind = "raw"
content = "param:file"

[[operations]]
name = "sign-cms-ex"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"m","args":["{{file:base64}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[operations.uses]
imports = ["keys_sign_cms_ex"]
network = "pki"
[[operations.uses.key]]
kind = "cms_ex"
content = "param:file"
[operations.uses.key.profile]
cosign = "never"

[[operations]]
name = "sign-cms-digest"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"m","args":["{{file:base64}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[operations.uses]
imports = ["keys_sign_cms_ex"]
network = "pki"
[[operations.uses.key]]
kind = "cms_ex"
content = "param:file"
[operations.uses.key.profile]
content_form = "digest"

[[operations]]
name = "sign-xml"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"m","args":["{{file:base64}}","{{path}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[[operations.params]]
name = "path"
kind = "text"
max_chars = 64
[operations.uses]
imports = ["keys_sign_xml"]
network = "pki"
[[operations.uses.key]]
kind = "xml"
content = "param:file"
[operations.uses.key.profile]
element = "param:path"

[[operations]]
name = "sign-raw-text"
module = "{MODULE}"
manual = true
request = '{{"method":"signPlainData","storageName":"PKCS12","data":"{{text}}"}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "text"
kind = "text"
max_chars = 64
[operations.uses]
imports = ["keys_sign_raw"]
network = "pki"
[[operations.uses.key]]
kind = "raw"
content = "param:text"

[[operations]]
name = "sign-cms-text"
module = "{MODULE}"
manual = true
request = '{{"type":"text","data":"{{text}}"}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "text"
kind = "text"
max_chars = 64
[operations.uses]
imports = ["keys_sign_cms_ex"]
network = "pki"
[[operations.uses.key]]
kind = "cms_ex"
content = "param:text"
[operations.uses.key.profile]
cosign = "never"

[[operations]]
name = "no-key"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"m","args":[]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[operations.uses]
imports = ["hash"]

[[operations]]
name = "derive-op"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"derive","args":[]}}'
label = {{ ru = "в", kk = "ә", en = "c" }}
[operations.uses]
imports = ["keys_sign_cms_ex"]
network = "pki"
[[operations.uses.key]]
kind = "cms_ex"
content = "derived"
[operations.uses.key.profile]
cosign = "never"

[[operations]]
name = "server-only"
module = "{MODULE}"
manual = false
server = true
request = '{{"module":"{MODULE}","method":"srv","args":[]}}'
label = {{ ru = "г", kk = "ә", en = "d" }}
[operations.uses]
imports = ["hash"]
"#
    )
}

/// Every import some operation declares, once.
fn declared_imports(manifest: &Manifest) -> Vec<Import> {
    let mut all: Vec<Import> = Vec::new();
    for import in manifest
        .operations()
        .iter()
        .flat_map(|o| o.uses().imports().iter().copied())
    {
        if !all.contains(&import) {
            all.push(import);
        }
    }
    all
}

fn manifest() -> Manifest {
    Manifest::from_toml(&format!(
        r#"id = "{ID}"
name.ru = "EVIL-NAME"
name.kk = "EVIL-NAME"
name.en = "EVIL-NAME"
description.ru = "EVIL-DESCRIPTION"
description.kk = "EVIL-DESCRIPTION"
description.en = "EVIL-DESCRIPTION"
version = "1.2.3"
min_core = "0.1.0-alpha.7"
modules = ["{MODULE}"]
[capabilities]
keys = true
{}"#,
        operations()
    ))
    .unwrap()
}

/// Opens the key like the host's key sources do, counting opens; it can be made to panic
/// once, or to wait for a signal, at the open.
#[derive(Default)]
struct Counting {
    opens: AtomicUsize,
    panic_once: AtomicBool,
    /// Told when the next open is reached, if set; the open then waits for `release`.
    entered: Mutex<Option<Sender<()>>>,
    release: Mutex<Option<Receiver<()>>>,
}
impl KeyProvider for Counting {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        if self.panic_once.swap(false, Ordering::SeqCst) {
            panic!("the key provider panicked");
        }
        // Taken first: the locks must not be held while this open waits.
        let entered = self.entered.lock().unwrap().take();
        if let Some(tx) = entered {
            let release = self.release.lock().unwrap().take();
            tx.send(()).unwrap();
            if let Some(rx) = release {
                rx.recv().unwrap();
            }
        }
        KeySources::new().open(request, ctx)
    }
}

/// No network: the manual host's transport, never reached by these modules.
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline"))
    }
}

struct Rig {
    engine: Engine,
    guard: Arc<PluginConsentGuard>,
    provider: Arc<Counting>,
    key: KeySelector,
    cert: Certificate,
    alias: String,
    transport: Arc<dyn HttpTransport>,
    network: NetworkPolicy,
    cache: Arc<OcspCache>,
    _dir: tempfile::TempDir,
}

/// The module makes `calls` in order, then runs `tail`; the registry has every operation of
/// the manifest declared for the manual caller.
fn rigged(calls: &[(Import, Vec<u8>)], tail: &str) -> Rig {
    rig_with(calls, tail, true, "user-rsa-sign")
}
fn rig_with(calls: &[(Import, Vec<u8>)], tail: &str, plugin_guard: bool, key: &str) -> Rig {
    // The budgets of a desktop's manual window: the default ones cannot hold an XML signature.
    rig_budgeted(
        calls,
        tail,
        plugin_guard,
        key,
        ManualLimits::desktop().resources,
        true,
    )
}
/// [`rig_with`] on an engine with `resources` and, or not, a temporary store.
fn rig_budgeted(
    calls: &[(Import, Vec<u8>)],
    tail: &str,
    plugin_guard: bool,
    key: &str,
    resources: ResourceLimits,
    temporary_store: bool,
) -> Rig {
    let (selector, validation, cert) = xades_fixture::matching_issuer_with_certificate(key);
    let manifest = manifest();
    let extras = declared_imports(&manifest);
    let names: Vec<String> = manifest
        .operations()
        .iter()
        .map(|o| o.name().to_owned())
        .collect();
    let mut plugins = PluginRegistry::new();
    plugins
        .install(
            manifest,
            SHA,
            &wasm_with_extra_imports(calls, tail, &extras),
            InstanceLimits {
                max_memory: 1 << 20,
                max_transfer: 1 << 16,
                ..InstanceLimits::default()
            },
            Vec::new(),
        )
        .unwrap();
    for name in &names {
        // `derive-op` and `server-only` are refused by the registry; the others are declared.
        let _ = plugins.allow_declared_with_pki(ID, name, manual(), PKI, &["synthetic.test"]);
    }
    let dir = tempfile::tempdir().unwrap();
    let guard = Arc::new(PluginConsentGuard::new());
    let provider = Arc::new(Counting::default());
    let services = EngineServices::hash_only(ResourceLimits {
        // A test holds several invocations at once (a refused one, the one that follows).
        max_in_flight: 4,
        ..resources
    })
    .with_validation(validation)
    .with_plugins(plugins);
    let services = if temporary_store {
        services.with_temporary_store(TemporaryStore::new(dir.path()).unwrap())
    } else {
        services
    };
    let services = if plugin_guard {
        services.with_plugin_keys(provider.clone(), guard.clone())
    } else {
        services.with_keys(provider.clone(), guard.clone())
    };
    Rig {
        engine: Engine::new(services).unwrap(),
        guard,
        provider,
        key: selector,
        cert,
        alias: crypto::raw(key).alias,
        transport: Arc::new(Offline),
        network: NetworkPolicy::default(),
        cache: Arc::new(OcspCache::new()),
        _dir: dir,
    }
}

fn permission(rig: &Rig, op: &str, caller: CallerContext) -> PluginPermission {
    let imports: Vec<Import> = rig
        .engine
        .plugin_operations(ID)
        .unwrap()
        .iter()
        .find(|o| o.name() == op)
        .map(|o| o.uses().imports().to_vec())
        .unwrap_or_else(|| vec![Import::Hash]);
    PluginPermission::new(ID, op, caller, imports)
        .with_keys([rig.key.key_id()])
        .with_pki_endpoints(PKI)
        .unwrap()
}
fn ctx_for(rig: &Rig, op: &str, digest: bool) -> OperationContext {
    let actions: &[Action] = if digest {
        &[Action::Sign, Action::SignDigest, Action::Hash]
    } else {
        &[Action::Sign, Action::Hash]
    };
    let grant = ExecutionGrant::new(actions.iter().copied())
        .with_keys([rig.key.key_id()])
        .with_plugins([permission(rig, op, manual())]);
    let policy = OperationPolicy {
        allow_prehashed: digest,
        ..OperationPolicy::strict_online()
    };
    rig.engine.begin(grant, policy, Arc::new(Control)).unwrap()
}
fn ctx(rig: &Rig, op: &str) -> OperationContext {
    ctx_for(rig, op, op == "sign-cms-digest")
}
fn bound(rig: &Rig) -> PluginKeyBinding<'_> {
    binding(&rig.key, 1).with_public_metadata(&rig.alias, &rig.cert, &[])
}
fn host(rig: &Rig) -> ManualHost<'_> {
    ManualHost {
        transport: &rig.transport,
        network: &rig.network,
        ocsp_cache: &rig.cache,
    }
}
fn doc(bytes: &[u8]) -> Vec<(&'static str, PluginParam<'_>)> {
    vec![("file", PluginParam::Document(bytes))]
}
/// `plugin_prepare` for any operation, params, key binding and caller.
fn try_prepare(
    rig: &Rig,
    op: &str,
    params: &[(&str, PluginParam<'_>)],
    key: &PluginKeyBinding<'_>,
    caller: &CallerContext,
    ctx: &mut OperationContext,
) -> Result<PluginPrepared, PluginPrepareError> {
    rig.engine.plugin_prepare(
        &ManualCall {
            plugin_id: ID,
            operation: op,
            params,
            key,
            caller,
        },
        ctx,
    )
}
fn prepare(
    rig: &Rig,
    op: &str,
    params: &[(&str, PluginParam<'_>)],
    ctx: &mut OperationContext,
) -> PluginPrepared {
    let prepared = try_prepare(rig, op, params, &bound(rig), &manual(), ctx)
        .unwrap_or_else(|e| panic!("{op}: {e:?}"));
    // Preparing opened the key once to compare certificates; the tests count what follows.
    rig.provider.opens.store(0, Ordering::SeqCst);
    prepared
}
fn confirm(prepared: PluginPrepared) -> PluginApproval {
    let confirmation = UserConfirmation::after_user_confirmed(prepared.summary());
    prepared.approve(confirmation, None).unwrap()
}
/// `plugin_call_approved` for any key binding.
fn call_with(
    rig: &Rig,
    op: &str,
    params: &[(&str, PluginParam<'_>)],
    key: &PluginKeyBinding<'_>,
    approval: PluginApproval,
    ctx: &mut OperationContext,
) -> ApprovedCall {
    let caller = manual();
    rig.engine.plugin_call_approved(
        &ManualCall {
            plugin_id: ID,
            operation: op,
            params,
            key,
            caller: &caller,
        },
        approval,
        &host(rig),
        ctx,
    )
}
fn call(
    rig: &Rig,
    op: &str,
    params: &[(&str, PluginParam<'_>)],
    approval: PluginApproval,
    ctx: &mut OperationContext,
) -> ApprovedCall {
    call_with(rig, op, params, &bound(rig), approval, ctx)
}
/// Prepare, confirm, call, with the params of the approval and of the call the same.
fn flow(
    rig: &Rig,
    op: &str,
    params: &[(&str, PluginParam<'_>)],
) -> (OperationContext, ApprovedCall) {
    let mut c = ctx(rig, op);
    let approval = confirm(prepare(rig, op, params, &mut c));
    let result = call(rig, op, params, approval, &mut c);
    (c, result)
}

fn raw_call(data: &[u8]) -> (Import, Vec<u8>) {
    (
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle: 1,
            data: data.to_vec().into(),
        }),
    )
}
fn cms_ex_args(content: abi::CmsContent) -> abi::SignCmsExArgs {
    abi::SignCmsExArgs {
        handle: 1,
        content,
        encapsulate: false,
        cosign: abi::CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs: abi::SignedAttrs {
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: Some(abi::SigningTime {
                at: abi::TimeSource::Now,
                form: abi::TimeForm::Auto,
            }),
            extra: Vec::new(),
        },
        certificates: abi::CmsCerts::Signer,
        timestamp: None,
        output: abi::CmsOutput::Der,
    }
}
fn cms_call(args: abi::SignCmsExArgs) -> (Import, Vec<u8>) {
    (Import::KeysSignCmsEx, abi::encode(&args))
}
fn data(bytes: &[u8]) -> abi::CmsContent {
    abi::CmsContent::Data(bytes.to_vec().into())
}
fn xml_call(element: Option<&str>) -> (Import, Vec<u8>) {
    (
        Import::KeysSignXml,
        abi::encode(&abi::SignXmlArgs {
            handle: 1,
            xml: XML.to_vec().into(),
            element: element.map(str::to_owned),
            parent: None,
        }),
    )
}
fn handle_call(import: Import, handle: u32) -> (Import, Vec<u8>) {
    (import, abi::encode(&abi::Handle { handle }))
}
fn decoded<T: serde::de::DeserializeOwned>(response: &str) -> T {
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    abi::decode::<abi::HostResult<T>>(&bytes).unwrap().unwrap()
}
fn denied(call: &ApprovedCall) -> bool {
    call.error()
        .is_some_and(|e| e.code() == ErrorCode::PermissionDenied)
        && call.applied() == AppliedState::NotApplied
}

#[test]
fn confirmed_cms_ex_run_applies_the_key_once_and_the_signature_verifies() {
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    let params = doc(DOC);
    let (_c, result) = flow(&rig, "sign-cms-ex", &params);
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    assert!(result.refusals().is_empty());
    assert_eq!(rig.guard.applications(), 1);
    let abi::CmsOutcome::Signed(cms) = decoded(result.response().unwrap()) else {
        panic!("not a CMS")
    };
    // Independent oracle: the CMS verifies over the approved document and over nothing else.
    let signers = oncl_pki::cms::verify(&cms, Some(DOC)).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].sig_alg, SigAlg::RsaSha256);
    assert!(oncl_pki::cms::verify(&cms, Some(OTHER)).is_err());
}

#[test]
fn confirmed_raw_run_applies_the_key_and_the_signature_verifies() {
    let rig = rigged(&[raw_call(DOC)], "");
    let (_c, result) = flow(&rig, "sign-raw", &doc(DOC));
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    let signature = signature(result.response().unwrap());
    let key = oncl_pki::pkcs12::load(
        &oncl_testkit::read(oncl_testkit::synthetic("user-rsa-sign").path),
        &oncl_testkit::synthetic("user-rsa-sign").password,
    )
    .unwrap()
    .remove(0);
    key.key
        .public_key()
        .verify(SigAlg::RsaSha256, DOC, &signature)
        .expect("the raw signature verifies over the approved document");
}

#[test]
fn consent_summary_is_trusted_data_from_core() {
    let rig = rigged(&[], "");
    let mut c = ctx(&rig, "sign-cms-ex");
    let prepared = prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c);
    let s = prepared.summary();
    assert_eq!(&s.plugin, rig.engine.plugin_identity(ID).unwrap());
    assert_eq!(s.operation, "sign-cms-ex");
    assert_eq!(s.kind, KeyKind::CmsEx);
    assert_eq!(s.uses, 1);
    assert_eq!(s.content.param, "file");
    assert_eq!(s.content.len, DOC.len() as u64);
    assert_eq!(s.content.sha256, <[u8; 32]>::from(Sha256::digest(DOC)));
    assert!(s.content.prehashed.is_none());
    assert_eq!(s.key.alias, rig.alias);
    let info = oncl_pki::info::cert_info(&rig.cert);
    assert_eq!(s.key.serial_hex, info.serial_hex);
    assert_eq!(s.key.subject_cn, info.subject_cn);
    assert_eq!(s.key.not_after, info.not_after);
    assert_eq!(
        s.key.fingerprint_sha256,
        <[u8; 32]>::from(Sha256::digest(der::Encode::to_der(&rig.cert).unwrap()))
    );
    let mut expected: Vec<String> = PKI
        .iter()
        .map(|(_, u)| oncl_plugin::Url::parse(u).unwrap().to_string())
        .collect();
    expected.sort();
    expected.dedup();
    assert_eq!(
        s.network,
        ConsentNetwork::Pki {
            endpoints: expected
        }
    );
    assert!(matches!(s.profile, Profile::CmsEx(_)));
    // None of the plugin author's text is in what the user is asked to approve.
    let shown = format!("{s:?}");
    for author in ["EVIL-NAME", "EVIL-LABEL", "EVIL-DESCRIPTION"] {
        assert!(!shown.contains(author), "{author} leaked into the summary");
    }
    // Another document, another summary; the same input, the same one.
    let again = prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c);
    assert_eq!(s.digest(), again.summary().digest());
    let other = prepare(&rig, "sign-cms-ex", &doc(OTHER), &mut c);
    assert_ne!(s.digest(), other.summary().digest());
}

#[test]
fn confirmation_of_another_summary_issues_nothing() {
    let rig = rigged(&[], "");
    let mut c = ctx(&rig, "sign-cms-ex");
    let a = prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c);
    let b = prepare(&rig, "sign-cms-ex", &doc(OTHER), &mut c);
    let shown_b = UserConfirmation::after_user_confirmed(b.summary());
    assert_eq!(
        a.approve(shown_b, None).unwrap_err(),
        ApprovalIssueError::ConfirmationMismatch
    );
    let c2 = prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c);
    let conf = UserConfirmation::after_user_confirmed(c2.summary());
    assert_eq!(
        c2.approve(conf, Some(Duration::ZERO)).unwrap_err(),
        ApprovalIssueError::Ttl
    );
}

#[test]
fn ttl_is_at_most_the_constant_and_configurable_only_downward() {
    let rig = rigged(&[], "");
    let mut c = ctx(&rig, "sign-cms-ex");
    let mut take = |ttl: Option<Duration>| {
        let p = prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c);
        let conf = UserConfirmation::after_user_confirmed(p.summary());
        let before = Instant::now();
        let a = p.approve(conf, ttl).unwrap();
        (before, a.expires_at())
    };
    assert_eq!(APPROVAL_TTL, Duration::from_secs(120));
    let (before, at) = take(None);
    assert!(at >= before + APPROVAL_TTL && at <= Instant::now() + APPROVAL_TTL);
    let (before, at) = take(Some(Duration::from_secs(3600)));
    assert!(
        at <= Instant::now() + APPROVAL_TTL,
        "never above the constant"
    );
    assert!(at >= before + APPROVAL_TTL);
    let (before, at) = take(Some(Duration::from_secs(5)));
    assert!(at >= before + Duration::from_secs(5) && at <= Instant::now() + Duration::from_secs(5));
}

#[test]
fn every_approval_has_its_own_nonce_so_flows_follow_each_other_on_one_guard() {
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    for round in 0..3 {
        let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
        assert_eq!(
            result.applied(),
            AppliedState::Applied,
            "round {round}: {result:?}"
        );
    }
    assert_eq!(rig.guard.applications(), 3);
}

#[test]
fn approval_with_an_expired_ttl_is_refused_before_the_module_runs() {
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    let params = doc(DOC);
    let mut c = ctx(&rig, "sign-cms-ex");
    let p = prepare(&rig, "sign-cms-ex", &params, &mut c);
    let conf = UserConfirmation::after_user_confirmed(p.summary());
    let approval = p.approve(conf, Some(Duration::from_millis(1))).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let result = call(&rig, "sign-cms-ex", &params, approval, &mut c);
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Expired]);
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(rig.guard.applications(), 0);
}

#[test]
fn guard_refuses_an_approval_that_expires_during_the_call() {
    // The approval passes the call's own fast check and runs out before the key use: the
    // guard decides at `before_use`. The module burns time by waiting on the key provider.
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    let params = doc(DOC);
    let mut c = ctx(&rig, "sign-cms-ex");
    let p = prepare(&rig, "sign-cms-ex", &params, &mut c);
    let conf = UserConfirmation::after_user_confirmed(p.summary());
    let approval = p.approve(conf, Some(Duration::from_millis(300))).unwrap();
    let (tx, rx) = channel();
    *rig.provider.entered.lock().unwrap() = Some(tx);
    let (release_tx, release_rx) = channel();
    *rig.provider.release.lock().unwrap() = Some(release_rx);
    let result = std::thread::scope(|s| {
        let waiter = s.spawn(move || {
            rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(400));
            release_tx.send(()).unwrap();
        });
        let result = call(&rig, "sign-cms-ex", &params, approval, &mut c);
        waiter.join().unwrap();
        result
    });
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Expired]);
    assert_eq!(rig.guard.applications(), 0);
}

#[test]
fn another_document_than_the_approved_one_never_reaches_the_plugin() {
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    let mut c = ctx(&rig, "sign-cms-ex");
    let approved = confirm(prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c));
    // A -> B at the call: refused before the module ran, with nothing opened or applied.
    let result = call(&rig, "sign-cms-ex", &doc(OTHER), approved, &mut c);
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Content]);
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
    assert_eq!(rig.guard.applications(), 0);
    // B -> A: a fresh confirmation for A runs.
    let (_c, back) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert_eq!(back.applied(), AppliedState::Applied, "{back:?}");
    // The same bytes as a one-byte-different document: another content.
    let mut longer = DOC.to_vec();
    longer.push(b'!');
    let mut c = ctx(&rig, "sign-cms-ex");
    let approved = confirm(prepare(&rig, "sign-cms-ex", &doc(DOC), &mut c));
    let result = call(&rig, "sign-cms-ex", &doc(&longer), approved, &mut c);
    assert!(denied(&result));
}

#[test]
fn approval_of_another_invocation_or_key_or_caller_is_refused() {
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    let params = doc(DOC);
    // Another invocation than the approved one.
    let mut c1 = ctx(&rig, "sign-cms-ex");
    let approval = confirm(prepare(&rig, "sign-cms-ex", &params, &mut c1));
    let mut c2 = ctx(&rig, "sign-cms-ex");
    let result = call(&rig, "sign-cms-ex", &params, approval, &mut c2);
    assert!(denied(&result));
    assert_eq!(result.refusals(), [TicketRefusal::OperationId]);
    // Another operation.
    let mut c = ctx(&rig, "sign-cms-ex");
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
    let result = call(&rig, "sign-cms-ex", &params, approval, &mut c);
    assert!(denied(&result));
    assert_eq!(result.refusals(), [TicketRefusal::Operation]);
    // Another handle for the same key.
    let mut c = ctx(&rig, "sign-cms-ex");
    let approval = confirm(prepare(&rig, "sign-cms-ex", &params, &mut c));
    let rebound = binding(&rig.key, 2).with_public_metadata(&rig.alias, &rig.cert, &[]);
    let result = call_with(&rig, "sign-cms-ex", &params, &rebound, approval, &mut c);
    assert!(denied(&result));
    assert_eq!(result.refusals(), [TicketRefusal::Key]);
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
}

#[test]
fn a_plugin_that_signs_other_bytes_than_the_document_is_refused_by_the_guard() {
    // The call's own check passes (the document is the approved one); the module signs bytes
    // it chose: the ticket does not match, the key is never applied.
    let rig = rigged(&[cms_call(cms_ex_args(data(OTHER)))], "");
    let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Content]);
    assert_eq!(rig.guard.applications(), 0);
    let rig = rig_raw(OTHER);
    let (_c, result) = flow(&rig, "sign-raw", &doc(DOC));
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Content]);
}
fn rig_raw(signs: &[u8]) -> Rig {
    rigged(&[raw_call(signs)], "")
}

#[test]
fn options_outside_the_profile_are_refused() {
    // Attached CMS where the profile says detached: the options hash differs, the guard says so.
    let mut args = cms_ex_args(data(DOC));
    args.encapsulate = true;
    let rig = rigged(&[cms_call(args)], "");
    let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Options]);
    assert_eq!(rig.guard.applications(), 0);
    // Options no profile can say (an extra attribute) are refused when the ticket is built.
    let mut args = cms_ex_args(data(DOC));
    args.attrs.extra.push(abi::RawAttribute {
        oid: "1.2.3.4".into(),
        values: vec![vec![5, 0].into()],
    });
    let rig2 = rig_with(&[cms_call(args)], "", true, "user-rsa-sign");
    let (_c, result) = flow(&rig2, "sign-cms-ex", &doc(DOC));
    assert!(denied(&result), "{result:?}");
    assert_eq!(rig2.guard.applications(), 0);
}

#[test]
fn a_text_parameter_of_the_profile_is_part_of_the_approved_options() {
    let params = |path: &'static str| {
        vec![
            ("file", PluginParam::Document(XML)),
            ("path", PluginParam::Text(path)),
        ]
    };
    // The module signs the element the user was shown.
    let rig = rigged(&[xml_call(Some("//p:data"))], "");
    let mut c = ctx(&rig, "sign-xml");
    let prepared = prepare(&rig, "sign-xml", &params("//p:data"), &mut c);
    let Profile::Xml(profile) = &prepared.summary().profile else {
        panic!("not an XML profile")
    };
    assert_eq!(profile.element, Some(Source::Fixed("//p:data".to_owned())));
    drop(prepared);
    let (_c, result) = flow(&rig, "sign-xml", &params("//p:data"));
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    // The module signs another element than the one shown: refused on the options.
    let rig = rig_xml(Some("//p:more"));
    let (_c, result) = flow(&rig, "sign-xml", &params("//p:data"));
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Options]);
    // An XPath no XPath rule allows is no operation to approve.
    let mut c = ctx(&rig, "sign-xml");
    let key = bound(&rig);
    for bad in ["not-absolute", "/r\u{202e}"] {
        let error =
            try_prepare(&rig, "sign-xml", &params(bad), &key, &manual(), &mut c).unwrap_err();
        assert_eq!(error, PluginPrepareError::Options, "{bad}");
    }
}
fn rig_xml(element: Option<&str>) -> Rig {
    rigged(&[xml_call(element)], "")
}

#[test]
fn prehashed_digest_is_computed_by_core_with_the_key_algorithm() {
    // RSA: SHA-256, the same the signer uses; the module that passes it signs.
    let digest = SigAlg::RsaSha256.digest(DOC);
    let rig = rigged(
        &[cms_call(cms_ex_args(abi::CmsContent::Digest(
            digest.clone().into(),
        )))],
        "",
    );
    let mut c = ctx(&rig, "sign-cms-digest");
    let prepared = prepare(&rig, "sign-cms-digest", &doc(DOC), &mut c);
    let p = prepared.summary().content.prehashed.clone().unwrap();
    assert_eq!(p.alg, oncl_pki::key::HashAlg::Sha256);
    assert_eq!(p.digest, digest);
    drop(prepared);
    let (_c, result) = flow(&rig, "sign-cms-digest", &doc(DOC));
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    let abi::CmsOutcome::Signed(cms) = decoded(result.response().unwrap()) else {
        panic!("not a CMS")
    };
    assert_eq!(oncl_pki::cms::verify(&cms, Some(DOC)).unwrap().len(), 1);
    // A module that passes the digest of other bytes (or any digest of its own) is refused.
    let forged = SigAlg::RsaSha256.digest(OTHER);
    let rig = rig_digest(forged);
    let (_c, result) = flow(&rig, "sign-cms-digest", &doc(DOC));
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::Content]);
    assert_eq!(rig.guard.applications(), 0);
    // A document, not its digest, where the profile says digest: a different binding.
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
    let (_c, result) = flow(&rig, "sign-cms-digest", &doc(DOC));
    assert!(denied(&result), "{result:?}");
}
fn rig_digest(digest: Vec<u8>) -> Rig {
    rigged(
        &[cms_call(cms_ex_args(abi::CmsContent::Digest(
            digest.into(),
        )))],
        "",
    )
}

#[test]
fn prehashed_digest_of_a_gost_key_uses_streebog() {
    let rig = rig_with(&[], "", true, "user-gost2015-sign");
    let mut c = ctx(&rig, "sign-cms-digest");
    let prepared = prepare(&rig, "sign-cms-digest", &doc(DOC), &mut c);
    let p = prepared.summary().content.prehashed.clone().unwrap();
    assert_eq!(p.alg, oncl_pki::key::HashAlg::Streebog512);
    assert_eq!(p.digest, SigAlg::Gost2015_512.digest(DOC));
}

#[test]
fn second_use_in_the_same_call_is_refused_and_the_first_is_reported_applied() {
    let call_one = cms_call(cms_ex_args(data(DOC)));
    let rig = rigged(&[call_one.clone(), call_one], "");
    let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert!(result.response().is_none(), "{result:?}");
    assert_eq!(result.applied(), AppliedState::Applied);
    assert_eq!(result.refusals(), [TicketRefusal::AlreadyUsed]);
    assert_eq!(rig.guard.applications(), 1);
}

#[test]
fn a_trap_after_the_key_use_is_reported_applied_not_hidden() {
    let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "(unreachable)");
    let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert!(result.response().is_none(), "{result:?}");
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    assert_eq!(rig.guard.applications(), 1);
    // And a trap BEFORE any key use reports not applied.
    let rig = rigged(&[], "(unreachable)");
    let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert!(result.response().is_none());
    assert_eq!(result.applied(), AppliedState::NotApplied);
    assert_eq!(rig.guard.applications(), 0);
}

#[test]
fn the_approval_is_revoked_when_the_call_ends() {
    // After a call the guard holds no approval: a key use in the same invocation, outside
    // `plugin_call_approved`, is refused for want of one, not for being spent.
    let signs = cms_call(cms_ex_args(data(DOC)));
    let rig = rigged(&[signs], "");
    let (mut c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert_eq!(result.applied(), AppliedState::Applied);
    let caller = manual();
    let key = [bound(&rig)];
    let error = rig
        .engine
        .plugin_call(
            &PluginCall {
                plugin_id: ID,
                operation: "sign-cms-ex",
                args: "{}",
            },
            &PluginBindings::new(&caller, &key),
            &mut c,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        rig.guard.refusal_log().last().map(|(_, r)| *r),
        Some(TicketRefusal::NoApproval)
    );
    // The same after a call that failed without using the key.
    let rig = rig_raw(DOC);
    let mut c = ctx(&rig, "sign-raw");
    let approval = confirm(prepare(&rig, "sign-raw", &doc(DOC), &mut c));
    let refused = call(&rig, "sign-raw", &doc(OTHER), approval, &mut c);
    assert!(denied(&refused));
    let key = [bound(&rig)];
    let error = rig
        .engine
        .plugin_call(
            &PluginCall {
                plugin_id: ID,
                operation: "sign-raw",
                args: "{}",
            },
            &PluginBindings::new(&caller, &key),
            &mut c,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        rig.guard.refusal_log().last().map(|(_, r)| *r),
        Some(TicketRefusal::NoApproval)
    );
}

/// Panics at the first checkpoint after being armed: a panic in the call itself, outside any
/// host function (a panic in a host function is turned into a trap by the plugin runtime).
struct PanicControl(AtomicBool);
impl oncl_pki::resource::OperationControl for PanicControl {
    fn checkpoint(
        &self,
        _: oncl_pki::resource::Progress,
    ) -> Result<(), oncl_pki::resource::ProcessingError> {
        if self.0.swap(false, Ordering::SeqCst) {
            panic!("the host's control panicked");
        }
        Ok(())
    }
}

#[test]
fn the_approval_is_revoked_when_the_call_panics() {
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let caller = manual();
    let refused_for_want_of_approval = |c: &mut OperationContext| {
        let key = [bound(&rig)];
        let error = rig
            .engine
            .plugin_call(
                &PluginCall {
                    plugin_id: ID,
                    operation: "sign-raw",
                    args: "{}",
                },
                &PluginBindings::new(&caller, &key),
                c,
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            rig.guard.refusal_log().last().map(|(_, r)| *r),
            Some(TicketRefusal::NoApproval)
        );
    };
    // A panic in a host function (the key provider) is a trap of the module: the call
    // ends with the key not applied, and the approval is gone.
    let mut c = ctx(&rig, "sign-raw");
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
    rig.provider.panic_once.store(true, Ordering::SeqCst);
    let trapped = call(&rig, "sign-raw", &params, approval, &mut c);
    assert!(trapped.response().is_none());
    assert_eq!(trapped.applied(), AppliedState::NotApplied);
    refused_for_want_of_approval(&mut c);
    drop(c);
    // A panic that unwinds out of the call itself.
    let control = Arc::new(PanicControl(AtomicBool::new(false)));
    let grant = ExecutionGrant::new([Action::Sign, Action::Hash])
        .with_keys([rig.key.key_id()])
        .with_plugins([permission(&rig, "sign-raw", manual())]);
    let mut c = rig
        .engine
        .begin(grant, OperationPolicy::strict_online(), control.clone())
        .unwrap();
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
    control.0.store(true, Ordering::SeqCst);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call(&rig, "sign-raw", &params, approval, &mut c)
    }));
    assert!(unwound.is_err(), "the panic left the call");
    refused_for_want_of_approval(&mut c);
    drop(c);
    // The engine is usable after the panic (the in-flight lock is not stuck).
    let (_c, result) = flow(&rig, "sign-raw", &params);
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
}

#[test]
fn an_approved_call_of_another_engine_configuration_or_concurrent_call_is_refused() {
    // An engine whose guard was configured as a document guard cannot run an approved call.
    let rig = rig_with(&[raw_call(DOC)], "", false, "user-rsa-sign");
    let (_c, result) = flow(&rig, "sign-raw", &doc(DOC));
    assert!(denied(&result));
    assert_eq!(result.refusals(), [TicketRefusal::NoGuard]);
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
    // A second approved call while one is in flight is refused as busy.
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let mut c = ctx(&rig, "sign-raw");
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
    let (tx, rx) = channel();
    *rig.provider.entered.lock().unwrap() = Some(tx);
    let (release_tx, release_rx) = channel();
    *rig.provider.release.lock().unwrap() = Some(release_rx);
    let (first, second) = std::thread::scope(|s| {
        let (rig, params) = (&rig, &params);
        let busy = s.spawn(move || {
            rx.recv().unwrap();
            let mut c2 = ctx(rig, "sign-raw");
            let approval2 = confirm(prepare(rig, "sign-raw", params, &mut c2));
            let second = call(rig, "sign-raw", params, approval2, &mut c2);
            release_tx.send(()).unwrap();
            second
        });
        let first = call(rig, "sign-raw", params, approval, &mut c);
        (first, busy.join().unwrap())
    });
    assert_eq!(first.applied(), AppliedState::Applied, "{first:?}");
    assert!(denied(&second));
    assert_eq!(second.refusals(), [TicketRefusal::Busy]);
}

#[test]
fn replayed_nonce_is_refused_by_the_call() {
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let nonce = [7u8; 16];
    let forge = |c: &mut OperationContext| {
        let p = prepare(&rig, "sign-raw", &params, c);
        let s = p.summary();
        PluginApproval::for_tests(
            s.plugin.clone(),
            "sign-raw",
            manual(),
            c.id(),
            rig.key.key_id(),
            1,
            vec![ApprovedUse::for_tests(
                s.kind,
                ContentBinding::bytes(DOC),
                s.options_sha256,
                s.key.fingerprint_sha256,
            )],
            Instant::now() + APPROVAL_TTL,
            nonce,
        )
    };
    let mut c = ctx(&rig, "sign-raw");
    let first = call(&rig, "sign-raw", &params, forge(&mut c), &mut c);
    assert_eq!(first.applied(), AppliedState::Applied, "{first:?}");
    let mut c = ctx(&rig, "sign-raw");
    let second = call(&rig, "sign-raw", &params, forge(&mut c), &mut c);
    assert!(denied(&second));
    assert_eq!(second.refusals(), [TicketRefusal::Replayed]);
    assert_eq!(rig.guard.applications(), 1);
}

#[test]
fn undeclared_derived_server_and_keyless_operations_have_no_approved_run() {
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let mut c = ctx(&rig, "sign-raw");
    let key = bound(&rig);
    let mut prepare_error =
        |op: &str| try_prepare(&rig, op, &params, &key, &manual(), &mut c).unwrap_err();
    assert_eq!(
        prepare_error("nope"),
        PluginPrepareError::Request(PluginRequestError::UndeclaredOperation)
    );
    assert_eq!(
        prepare_error("derive-op"),
        PluginPrepareError::Request(PluginRequestError::DerivedUnsupported)
    );
    assert_eq!(
        prepare_error("server-only"),
        PluginPrepareError::Request(PluginRequestError::NotManual)
    );
    assert_eq!(
        try_prepare(&rig, "no-key", &[], &key, &manual(), &mut c).unwrap_err(),
        PluginPrepareError::NoKeyUse
    );
    // The call refuses the same, with the typed reason where there is one.
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
    let mut c = ctx(&rig, "sign-raw");
    let undeclared = call(&rig, "nope", &params, approval, &mut c);
    assert!(denied(&undeclared));
    assert_eq!(undeclared.refusals(), [TicketRefusal::UndeclaredOperation]);
    let mut c0 = ctx(&rig, "sign-raw");
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c0));
    let mut c = ctx(&rig, "sign-raw");
    let derived = call(&rig, "derive-op", &params, approval, &mut c);
    assert!(denied(&derived));
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
    // A caller that is not a local operator has no manual window.
    let service = CallerContext::ServiceClient("svc".to_owned());
    assert_eq!(
        try_prepare(&rig, "sign-raw", &params, &key, &service, &mut c).unwrap_err(),
        PluginPrepareError::CallerNotManual
    );
    // A key binding without its public metadata cannot be shown to the user.
    let bare = binding(&rig.key, 1);
    assert_eq!(
        try_prepare(&rig, "sign-raw", &params, &bare, &manual(), &mut c).unwrap_err(),
        PluginPrepareError::KeyMetadataMissing
    );
    // A parameter the operation does not declare, a missing one, a wrong kind.
    for (name, params) in [
        (
            "unknown",
            vec![
                ("file", PluginParam::Document(DOC)),
                ("x", PluginParam::Flag(true)),
            ],
        ),
        ("missing", vec![]),
        ("kind", vec![("file", PluginParam::Text("text"))]),
    ] {
        assert!(
            matches!(
                try_prepare(&rig, "sign-raw", &params, &key, &manual(), &mut c).unwrap_err(),
                PluginPrepareError::Request(_)
            ),
            "{name}"
        );
    }
}

#[test]
fn key_description_and_chain_come_from_the_single_binding_and_other_handles_are_denied() {
    let params = doc(DOC);
    // keys_describe: the bound key's alias, algorithm and certificate.
    let rig = rigged(&[handle_call(Import::KeysDescribe, 1)], "");
    let (_c, result) = flow(&rig, "sign-raw", &params);
    assert_eq!(result.applied(), AppliedState::NotApplied, "{result:?}");
    let description: abi::KeyDescription = decoded(result.response().unwrap());
    assert_eq!(description.alias, rig.alias);
    assert_eq!(description.alg, "rsa");
    assert_eq!(
        description.certificate.as_ref(),
        der::Encode::to_der(&rig.cert).unwrap()
    );
    // keys_chain: the same certificate first.
    let rig = rig_chain();
    let (_c, result) = flow(&rig, "sign-raw", &params);
    let chain: Vec<abi::Bytes> = decoded(result.response().unwrap());
    assert_eq!(chain[0].as_ref(), der::Encode::to_der(&rig.cert).unwrap());
    // Any other handle, and a handle that was never bound, are denied alike.
    for handle in [0, 2, 99] {
        for import in [Import::KeysDescribe, Import::KeysChain, Import::KeysRelease] {
            let rig = rig_with(&[handle_call(import, handle)], "", true, "user-rsa-sign");
            let (_c, result) = flow(&rig, "sign-raw", &params);
            assert!(result.response().is_none(), "{import:?} {handle}");
            assert_eq!(
                result.error().map(OperationError::code),
                Some(ErrorCode::PermissionDenied),
                "{import:?} {handle}"
            );
            assert_eq!(result.applied(), AppliedState::NotApplied);
        }
    }
    // keys_release of the bound handle is idempotent; a released handle then signs nothing.
    let rig = rigged(
        &[
            handle_call(Import::KeysRelease, 1),
            handle_call(Import::KeysRelease, 1),
        ],
        "",
    );
    let (_c, result) = flow(&rig, "sign-raw", &params);
    assert!(result.response().is_some(), "{result:?}");
    let rig = rigged(&[handle_call(Import::KeysRelease, 1), raw_call(DOC)], "");
    let (_c, result) = flow(&rig, "sign-raw", &params);
    assert!(denied(&result), "{result:?}");
    assert_eq!(rig.guard.applications(), 0);
}
fn rig_chain() -> Rig {
    rigged(&[handle_call(Import::KeysChain, 1)], "")
}

#[test]
fn key_choice_is_answered_for_the_one_bound_key_in_the_manual_window() {
    let select = abi::SelectArgs {
        action: abi::Action::Sign,
        storages: Vec::new(),
        filter: abi::Filter {
            chain: Some(Vec::new()),
            allow_expired: true,
            ..abi::Filter::default()
        },
        more: abi::FilterMore::default(),
        detail: None,
        initial_path: None,
        order: abi::KeyOrder::NewestFirst,
    };
    let rig = rigged(&[(Import::KeysSelect, abi::encode(&select))], "");
    let (_c, result) = flow(&rig, "sign-raw", &doc(DOC));
    let chosen: Option<abi::Chosen> =
        decoded(result.response().unwrap_or_else(|| panic!("{result:?}")));
    let chosen = chosen.expect("the bound key suits the filter");
    assert_eq!(chosen.handle, 1);
    assert_eq!(chosen.alias, rig.alias);
    assert_eq!(
        chosen.certificate.as_ref(),
        der::Encode::to_der(&rig.cert).unwrap()
    );
    assert_eq!(rig.guard.applications(), 0, "choosing a key applies none");
}

#[test]
fn the_manual_window_has_no_origin() {
    // A module that answers `N` when its request has no origin and `S` when it has one.
    let scan = r#"
        (local.set $i (i32.const 0))
        (i32.store8 (i32.const 900) (i32.const 0x53))
        (block $done (loop $next
          (br_if $done (i32.ge_u (i32.add (local.get $i) (i32.const 7)) (local.get 1)))
          (if (i32.and
                (i32.eq (i32.load align=1 (i32.add (local.get 0) (local.get $i))) (i32.const 0x6769726f))
                (i32.eq (i32.load16_u align=1 (i32.add (local.get 0) (i32.add (local.get $i) (i32.const 4)))) (i32.const 0x6e69)))
            (then
              (if (i32.eq (i32.load8_u (i32.add (local.get 0) (i32.add (local.get $i) (i32.const 6)))) (i32.const 0xf6))
                (then (i32.store8 (i32.const 900) (i32.const 0x4e))))
              (br $done)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $next)))
        (local.set $i (i32.const 0))
        (local.set $r (i64.or (i64.shl (i64.const 900) (i64.const 32)) (i64.const 1)))
    "#;
    let rig = rigged(&[], scan);
    let (_c, result) = flow(&rig, "sign-raw", &doc(DOC));
    assert_eq!(
        result.response(),
        Some("4e"),
        "no origin in the manual window: {result:?}"
    );
    // The same module with a browser caller sees one (the scan is not vacuous).
    let browser = CallerContext::Browser {
        origin: "https://site.kz".to_owned(),
    };
    let rig2 = rig_browser(scan, &browser);
    let c = rig2.engine.begin(
        ExecutionGrant::new([Action::Hash]).with_plugins([PluginPermission::new(
            ID,
            "no-key",
            browser.clone(),
            [Import::Hash],
        )]),
        OperationPolicy::strict_online(),
        Arc::new(Control),
    );
    let mut c = c.unwrap();
    let result = rig2
        .engine
        .plugin_call(
            &PluginCall {
                plugin_id: ID,
                operation: "no-key",
                args: "{}",
            },
            &PluginBindings::new(&browser, &[]),
            &mut c,
        )
        .unwrap();
    assert_eq!(result.response(), "53");
}
fn rig_browser(scan: &str, browser: &CallerContext) -> Rig {
    // The keyless operation registered for the browser caller (an exact policy).
    let (selector, validation, cert) =
        xades_fixture::matching_issuer_with_certificate("user-rsa-sign");
    let manifest = manifest();
    let extras = declared_imports(&manifest);
    let mut plugins = PluginRegistry::new();
    plugins
        .install(
            manifest,
            SHA,
            &wasm_with_extra_imports(&[], scan, &extras),
            InstanceLimits {
                max_memory: 1 << 20,
                max_transfer: 1 << 16,
                ..InstanceLimits::default()
            },
            vec![PluginPermission::new(
                ID,
                "no-key",
                browser.clone(),
                [Import::Hash],
            )],
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let guard = Arc::new(PluginConsentGuard::new());
    let provider = Arc::new(Counting::default());
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits {
            max_in_flight: 4,
            ..ResourceLimits::default()
        })
        .with_temporary_store(TemporaryStore::new(dir.path()).unwrap())
        .with_validation(validation)
        .with_plugins(plugins)
        .with_plugin_keys(provider.clone(), guard.clone()),
    )
    .unwrap();
    Rig {
        engine,
        guard,
        provider,
        key: selector,
        cert,
        alias: String::new(),
        transport: Arc::new(Offline),
        network: NetworkPolicy::default(),
        cache: Arc::new(OcspCache::new()),
        _dir: dir,
    }
}

#[test]
fn the_certificate_that_signs_is_the_one_the_user_approved() {
    let params = doc(DOC);
    let other = crypto::issued("user-gost2015-sign").cert;
    // Positive control: the binding's certificate is the key's.
    let rig = rigged(&[raw_call(DOC)], "");
    let (_c, ok) = flow(&rig, "sign-raw", &params);
    assert_eq!(ok.applied(), AppliedState::Applied, "{ok:?}");
    // Prepare refuses metadata that is not what the key store holds for the key.
    let mut c = ctx(&rig, "sign-raw");
    let lying = binding(&rig.key, 1).with_public_metadata(&rig.alias, &other, &[]);
    assert_eq!(
        try_prepare(&rig, "sign-raw", &params, &lying, &manual(), &mut c).unwrap_err(),
        PluginPrepareError::CertificateMismatch
    );
    // Approved with certificate A, called with the same selector and handle but certificate
    // B in the metadata: refused before the module runs, key not applied.
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
    let result = call_with(&rig, "sign-raw", &params, &lying, approval, &mut c);
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::CertificateChanged]);
    assert_eq!(
        rig.guard.applications(),
        1,
        "only the control applied the key"
    );
    drop(c);
    // The guard decides on the certificate of the key that actually signs: an approval for
    // certificate B with the honest binding (metadata says A) is refused by the fast check
    // before the module runs; the guard-only case is the next test.
    let mut c = ctx(&rig, "sign-raw");
    let p = prepare(&rig, "sign-raw", &params, &mut c);
    assert_eq!(rig.guard.applications(), 1, "preparing applies no key");
    let s = p.summary();
    let fingerprint: [u8; 32] = {
        use sha2::Digest;
        Sha256::digest(der::Encode::to_der(&other).unwrap()).into()
    };
    let forged = PluginApproval::for_tests(
        s.plugin.clone(),
        "sign-raw",
        manual(),
        c.id(),
        rig.key.key_id(),
        1,
        vec![ApprovedUse::for_tests(
            s.kind,
            ContentBinding::bytes(DOC),
            s.options_sha256,
            fingerprint,
        )],
        Instant::now() + APPROVAL_TTL,
        [9; 16],
    );
    // The metadata is not compared by the guard; the fast check compares the plan's
    // fingerprint (A) with the approval's (B) and refuses first, so assert that too.
    let result = call(&rig, "sign-raw", &params, forged, &mut c);
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::CertificateChanged]);
    assert_eq!(rig.guard.applications(), 1);
}

#[test]
fn guard_refuses_a_key_whose_certificate_changed_after_the_fast_check() {
    // Lease certificate A, approval and metadata B: reaches the guard only if the fast check
    // is bypassed, which `plugin_call` (no fast check) does.
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let mut c = ctx(&rig, "sign-raw");
    let p = prepare(&rig, "sign-raw", &params, &mut c);
    let s = p.summary();
    let forged = PluginApproval::for_tests(
        s.plugin.clone(),
        "sign-raw",
        manual(),
        c.id(),
        rig.key.key_id(),
        1,
        vec![ApprovedUse::for_tests(
            s.kind,
            ContentBinding::bytes(DOC),
            s.options_sha256,
            [7; 32],
        )],
        Instant::now() + APPROVAL_TTL,
        [8; 16],
    );
    rig.guard.grant(forged).unwrap();
    let caller = manual();
    let key = [bound(&rig)];
    let error = rig
        .engine
        .plugin_call(
            &PluginCall {
                plugin_id: ID,
                operation: "sign-raw",
                args: "{}",
            },
            &PluginBindings::new(&caller, &key),
            &mut c,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        rig.guard.refusal_log().last().map(|(_, r)| *r),
        Some(TicketRefusal::CertificateChanged)
    );
    assert_eq!(rig.guard.applications(), 0);
}

#[test]
fn prehash_algorithm_agrees_with_the_signer_under_ncalayer_compatibility() {
    // A certificate whose issuer signed with another algorithm than the leaf key's: the
    // non-strict selection would take the issuer's, the signer (strict) the key's.
    let (selector, cert) = crypto::selector_with_certificate("user-rsa-sign");
    assert_ne!(
        oncl_pki::info::cert_info(&cert).signing_alg().ok(),
        Some(SigAlg::RsaSha256),
        "the fixture's issuer signs with another algorithm"
    );
    let mut rig = rigged(&[], "");
    rig.key = selector;
    rig.cert = cert;
    rig.alias = crypto::raw("user-rsa-sign").alias;
    let grant = ExecutionGrant::new([Action::Sign, Action::SignDigest, Action::Hash])
        .with_keys([rig.key.key_id()])
        .with_plugins([permission(&rig, "sign-cms-digest", manual())]);
    let policy = OperationPolicy {
        allow_prehashed: true,
        ..OperationPolicy::ncalayer_compatibility()
    };
    let mut c = rig.engine.begin(grant, policy, Arc::new(Control)).unwrap();
    let prepared = prepare(&rig, "sign-cms-digest", &doc(DOC), &mut c);
    let p = prepared.summary().content.prehashed.clone().unwrap();
    assert_eq!(p.alg, oncl_pki::key::HashAlg::Sha256);
    assert_eq!(p.digest, SigAlg::RsaSha256.digest(DOC));
}

#[test]
fn guard_decides_on_lease_certificate_not_on_metadata() {
    let params = doc(DOC);
    let other = crypto::issued("user-gost2015-sign").cert;
    let rig = rigged(&[raw_call(DOC)], "");
    let mut c = ctx(&rig, "sign-raw");
    let lying = binding(&rig.key, 1).with_public_metadata(&rig.alias, &other, &[]);
    let p = prepare(&rig, "sign-raw", &params, &mut c);
    assert_eq!(rig.guard.applications(), 0, "preparing applies no key");
    let s = p.summary();
    let fingerprint: [u8; 32] = {
        use sha2::Digest;
        Sha256::digest(der::Encode::to_der(&other).unwrap()).into()
    };
    // Lease A, metadata B, approval B: the fast check passes; only the guard can stop it.
    let forged = PluginApproval::for_tests(
        s.plugin.clone(),
        "sign-raw",
        manual(),
        c.id(),
        rig.key.key_id(),
        1,
        vec![ApprovedUse::for_tests(
            s.kind,
            ContentBinding::bytes(DOC),
            s.options_sha256,
            fingerprint,
        )],
        Instant::now() + APPROVAL_TTL,
        [9; 16],
    );
    let result = call_with(&rig, "sign-raw", &params, &lying, forged, &mut c);
    assert!(denied(&result), "{result:?}");
    assert_eq!(result.refusals(), [TicketRefusal::CertificateChanged]);
    assert_eq!(rig.guard.applications(), 0);
    assert_eq!(result.applied(), AppliedState::NotApplied);
}

// ---- MP3a-3: stable subcodes and the audit facts ---------------------------------------

/// The call was refused with exactly this subcode, the plugin saw plain `PermissionDenied`
/// (never the subcode: the error is the bare variant), and the key was not applied.
fn refused_with(result: &ApprovedCall, id: &str, label: &str) {
    assert_eq!(
        result.subcode().map(PluginRefusalCode::id),
        Some(id),
        "{label}: {result:?}"
    );
    assert!(
        matches!(result.error(), Some(OperationError::PermissionDenied)),
        "{label}: {:?}",
        result.error()
    );
    assert_eq!(
        result.error().unwrap().code(),
        result.subcode().unwrap().error_code(),
        "{label}: the subcode's ErrorCode is the one the caller gets"
    );
    assert_eq!(result.applied(), AppliedState::NotApplied, "{label}");
    // The text of the error carries nothing of the subcode.
    let shown = format!("{:?}", result.error().unwrap());
    assert!(!shown.contains(id) || id == "busy", "{label}");
}

/// Every refusal path that can run end to end with real synthetic WASM, in one table:
/// (case, expected subcode id).
#[test]
fn every_reachable_refusal_path_yields_its_stable_subcode() {
    let params = doc(DOC);
    // content-mismatch: another document at the call.
    {
        let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
        let mut c = ctx(&rig, "sign-cms-ex");
        let approved = confirm(prepare(&rig, "sign-cms-ex", &params, &mut c));
        let result = call(&rig, "sign-cms-ex", &doc(OTHER), approved, &mut c);
        refused_with(&result, "content-mismatch", "other document");
    }
    // content-mismatch at the guard: the plugin signs bytes it chose.
    {
        let rig = rigged(&[cms_call(cms_ex_args(data(OTHER)))], "");
        let (_c, result) = flow(&rig, "sign-cms-ex", &params);
        refused_with(&result, "content-mismatch", "plugin-chosen bytes");
    }
    // options-mismatch.
    {
        let mut args = cms_ex_args(data(DOC));
        args.encapsulate = true;
        let rig = rigged(&[cms_call(args)], "");
        let (_c, result) = flow(&rig, "sign-cms-ex", &params);
        refused_with(&result, "options-mismatch", "attached cms");
    }
    // operation-id-mismatch, operation-mismatch, key-mismatch.
    {
        let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
        let mut c1 = ctx(&rig, "sign-cms-ex");
        let approval = confirm(prepare(&rig, "sign-cms-ex", &params, &mut c1));
        let mut c2 = ctx(&rig, "sign-cms-ex");
        let result = call(&rig, "sign-cms-ex", &params, approval, &mut c2);
        refused_with(&result, "operation-id-mismatch", "another invocation");
        let mut c = ctx(&rig, "sign-cms-ex");
        let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
        let result = call(&rig, "sign-cms-ex", &params, approval, &mut c);
        refused_with(&result, "operation-mismatch", "another operation");
        let mut c = ctx(&rig, "sign-cms-ex");
        let approval = confirm(prepare(&rig, "sign-cms-ex", &params, &mut c));
        let rebound = binding(&rig.key, 2).with_public_metadata(&rig.alias, &rig.cert, &[]);
        let result = call_with(&rig, "sign-cms-ex", &params, &rebound, approval, &mut c);
        refused_with(&result, "key-mismatch", "another handle");
    }
    // approval-expired before the module runs.
    {
        let rig = rigged(&[cms_call(cms_ex_args(data(DOC)))], "");
        let mut c = ctx(&rig, "sign-cms-ex");
        let p = prepare(&rig, "sign-cms-ex", &params, &mut c);
        let conf = UserConfirmation::after_user_confirmed(p.summary());
        let approval = p.approve(conf, Some(Duration::from_millis(1))).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let result = call(&rig, "sign-cms-ex", &params, approval, &mut c);
        refused_with(&result, "approval-expired", "expired");
    }
    // key-use-spent: the first use is applied, the second refused; the subcode names the
    // refusal while the applied state stays honest.
    {
        let one = cms_call(cms_ex_args(data(DOC)));
        let rig = rigged(&[one.clone(), one], "");
        let (_c, result) = flow(&rig, "sign-cms-ex", &params);
        assert_eq!(
            result.subcode().map(PluginRefusalCode::id),
            Some("key-use-spent")
        );
        assert_eq!(result.applied(), AppliedState::Applied);
    }
    // no-consent-guard.
    {
        let rig = rig_with(&[raw_call(DOC)], "", false, "user-rsa-sign");
        let (_c, result) = flow(&rig, "sign-raw", &params);
        refused_with(&result, "no-consent-guard", "document guard engine");
    }
    // approval-replayed.
    {
        let rig = rigged(&[raw_call(DOC)], "");
        let forge = |c: &mut OperationContext| {
            let p = prepare(&rig, "sign-raw", &params, c);
            let s = p.summary();
            PluginApproval::for_tests(
                s.plugin.clone(),
                "sign-raw",
                manual(),
                c.id(),
                rig.key.key_id(),
                1,
                vec![ApprovedUse::for_tests(
                    s.kind,
                    ContentBinding::bytes(DOC),
                    s.options_sha256,
                    s.key.fingerprint_sha256,
                )],
                Instant::now() + APPROVAL_TTL,
                [5; 16],
            )
        };
        let mut c = ctx(&rig, "sign-raw");
        let first = call(&rig, "sign-raw", &params, forge(&mut c), &mut c);
        assert_eq!(first.applied(), AppliedState::Applied);
        assert_eq!(
            first.subcode(),
            None,
            "a use that was applied is no refusal"
        );
        let mut c = ctx(&rig, "sign-raw");
        let second = call(&rig, "sign-raw", &params, forge(&mut c), &mut c);
        refused_with(&second, "approval-replayed", "replayed nonce");
    }
    // busy: a second approved call while one is in flight.
    {
        let rig = rigged(&[raw_call(DOC)], "");
        let mut c = ctx(&rig, "sign-raw");
        let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c));
        let (tx, rx) = channel();
        *rig.provider.entered.lock().unwrap() = Some(tx);
        let (release_tx, release_rx) = channel();
        *rig.provider.release.lock().unwrap() = Some(release_rx);
        let (first, second) = std::thread::scope(|s| {
            let (rig, params) = (&rig, &params);
            let busy = s.spawn(move || {
                rx.recv().unwrap();
                let mut c2 = ctx(rig, "sign-raw");
                let approval2 = confirm(prepare(rig, "sign-raw", params, &mut c2));
                let second = call(rig, "sign-raw", params, approval2, &mut c2);
                release_tx.send(()).unwrap();
                second
            });
            let first = call(rig, "sign-raw", params, approval, &mut c);
            (first, busy.join().unwrap())
        });
        assert_eq!(first.applied(), AppliedState::Applied);
        refused_with(&second, "busy", "concurrent approved call");
    }
    // not-declared at the call (the undeclared label): the approved call's own subcode and
    // the context's.
    {
        let rig = rigged(&[raw_call(DOC)], "");
        let mut c0 = ctx(&rig, "sign-raw");
        let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c0));
        let mut c = ctx(&rig, "sign-raw");
        let undeclared = call(&rig, "nope", &params, approval, &mut c);
        refused_with(&undeclared, "not-declared", "undeclared label");
    }
}

/// Every way `plugin_prepare` can fail (reachable here) names its subcode, and it is the
/// one whose ErrorCode is the `OperationError`'s.
#[test]
fn every_reachable_prepare_failure_yields_its_stable_subcode() {
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let key = bound(&rig);
    let mut c = ctx(&rig, "sign-raw");
    let service = CallerContext::ServiceClient("svc".to_owned());
    let bare = binding(&rig.key, 1);
    let table: Vec<(&str, PluginPrepareError, &str)> = vec![
        (
            "undeclared",
            try_prepare(&rig, "nope", &params, &key, &manual(), &mut c).unwrap_err(),
            "not-declared",
        ),
        (
            "derived",
            try_prepare(&rig, "derive-op", &params, &key, &manual(), &mut c).unwrap_err(),
            "derived-unsupported",
        ),
        (
            "server-only",
            try_prepare(&rig, "server-only", &params, &key, &manual(), &mut c).unwrap_err(),
            "not-manual",
        ),
        (
            "keyless",
            try_prepare(&rig, "no-key", &[], &key, &manual(), &mut c).unwrap_err(),
            "no-key-use",
        ),
        (
            "service caller",
            try_prepare(&rig, "sign-raw", &params, &key, &service, &mut c).unwrap_err(),
            "caller-not-manual",
        ),
        (
            "no metadata",
            try_prepare(&rig, "sign-raw", &params, &bare, &manual(), &mut c).unwrap_err(),
            "key-metadata-missing",
        ),
        (
            "unknown param",
            try_prepare(
                &rig,
                "sign-raw",
                &[
                    ("file", PluginParam::Document(DOC)),
                    ("x", PluginParam::Flag(true)),
                ],
                &key,
                &manual(),
                &mut c,
            )
            .unwrap_err(),
            "unknown-param",
        ),
        (
            "missing param",
            try_prepare(&rig, "sign-raw", &[], &key, &manual(), &mut c).unwrap_err(),
            "missing-param",
        ),
        (
            "wrong kind",
            try_prepare(
                &rig,
                "sign-raw",
                &[("file", PluginParam::Text("text"))],
                &key,
                &manual(),
                &mut c,
            )
            .unwrap_err(),
            "param-wrong-kind",
        ),
    ];
    for (case, error, id) in table {
        assert_eq!(error.subcode().id(), id, "{case}: {error:?}");
        assert_eq!(
            error.subcode().error_code(),
            OperationError::from(error.clone()).code(),
            "{case}"
        );
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
    }
    // And through the approved call, which reports the same subcode as the prepare error.
    let mut c0 = ctx(&rig, "sign-raw");
    let approval = confirm(prepare(&rig, "sign-raw", &params, &mut c0));
    let mut c = ctx(&rig, "sign-raw");
    let derived = call(&rig, "derive-op", &params, approval, &mut c);
    assert_eq!(
        derived.subcode().map(PluginRefusalCode::id),
        Some("derived-unsupported")
    );
    assert!(
        derived.refusals().is_empty(),
        "no guard refusal: before the module"
    );
}

/// The audit facts of an approved use name the approval by a hash of its nonce, never the
/// nonce, and nothing of the document.
#[test]
fn audit_facts_carry_the_nonce_hash_not_the_nonce_or_the_document() {
    let rig = rigged(&[raw_call(DOC)], "");
    let params = doc(DOC);
    let mut c = ctx(&rig, "sign-raw");
    let p = prepare(&rig, "sign-raw", &params, &mut c);
    let s = p.summary();
    let nonce = [0xA5u8; 16];
    let approval = PluginApproval::for_tests(
        s.plugin.clone(),
        "sign-raw",
        manual(),
        c.id(),
        rig.key.key_id(),
        1,
        vec![ApprovedUse::for_tests(
            s.kind,
            ContentBinding::bytes(DOC),
            s.options_sha256,
            s.key.fingerprint_sha256,
        )],
        Instant::now() + APPROVAL_TTL,
        nonce,
    );
    let ticket = PluginUse::for_tests(
        s.plugin.clone(),
        "sign-raw",
        manual(),
        s.kind,
        1,
        rig.key.key_id(),
        ContentBinding::bytes(DOC),
        s.options_sha256,
        s.key.fingerprint_sha256,
    );
    let facts = approval.audit_record(&ticket);
    let hash = facts.approval_nonce_sha256.expect("a user approved it");
    assert_ne!(hash.as_slice(), &nonce[..]);
    // Pinned: the domain-separated hash of the nonce, so a change of the prefix is deliberate.
    let mut expected = Sha256::new();
    expected.update(b"ONCLNONCE1\0");
    expected.update(nonce);
    assert_eq!(hash.as_slice(), expected.finalize().as_slice());
    assert!(!hash.windows(16).any(|w| w == nonce));
    assert_eq!(facts.plugin_id, ID);
    assert_eq!(facts.package_kind, 1);
    assert_eq!(facts.package_sha256, [9; 32]);
    assert_eq!(facts.operation, "sign-raw");
    assert_eq!(facts.ticket_digest, ticket.digest());
    assert_eq!(facts.content_sha256, Sha256::digest(DOC).as_slice());
    assert_eq!(facts.content_len, DOC.len() as u64);
    assert_eq!(facts.caller, PluginCallerKind::LocalOperator);
    assert!(facts.declared);
    assert_eq!(facts.grant_id, None);
    // Another nonce, another hash; the same nonce the same.
    let other = PluginAuditRecord::from_ticket(&ticket, Some(&[0xA6; 16]), None);
    assert_ne!(other.approval_nonce_sha256, facts.approval_nonce_sha256);
    let none = PluginAuditRecord::from_ticket(&ticket, None, Some("g".into()));
    assert_eq!(none.approval_nonce_sha256, None);
    assert_eq!(none.grant_id.as_deref(), Some("g"));
}

fn text(value: &str) -> Vec<(&'static str, PluginParam<'_>)> {
    vec![("text", PluginParam::Text(value))]
}

#[test]
fn raw_over_a_text_parameter_signs_the_utf8_bytes_and_the_summary_says_so() {
    // Break caught: a text is not content, or its bytes are not what is bound and signed.
    let typed = "héllo \u{4e16}";
    let rig = rigged(&[raw_call(typed.as_bytes())], "");
    let mut c = ctx(&rig, "sign-raw-text");
    let prepared = prepare(&rig, "sign-raw-text", &text(typed), &mut c);
    let s = prepared.summary();
    assert_eq!(s.kind, KeyKind::Raw);
    assert_eq!(s.content.param, "text");
    assert_eq!(s.content.len, typed.len() as u64, "bytes, not characters");
    assert_eq!(
        s.content.sha256,
        <[u8; 32]>::from(Sha256::digest(typed.as_bytes()))
    );
    assert!(s.content.prehashed.is_none());
    // Another text, another summary.
    let other = prepare(&rig, "sign-raw-text", &text("other"), &mut c);
    assert_ne!(s.digest(), other.summary().digest());
    // The run signs exactly those bytes, and the signature verifies over them.
    let (_c, result) = flow(&rig, "sign-raw-text", &text(typed));
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    let signature = signature(result.response().unwrap());
    let key = oncl_pki::pkcs12::load(
        &oncl_testkit::read(oncl_testkit::synthetic("user-rsa-sign").path),
        &oncl_testkit::synthetic("user-rsa-sign").password,
    )
    .unwrap()
    .remove(0);
    key.key
        .public_key()
        .verify(SigAlg::RsaSha256, typed.as_bytes(), &signature)
        .unwrap();
}

#[test]
fn a_plugin_that_signs_other_bytes_than_the_text_is_refused() {
    let rig = rigged(&[raw_call(b"something else")], "");
    let (_c, result) = flow(&rig, "sign-raw-text", &text("what the user typed"));
    assert_eq!(rig.guard.applications(), 0, "{result:?}");
    assert!(denied(&result), "{result:?}");
}

#[test]
fn cms_ex_over_a_text_parameter_signs_the_utf8_bytes() {
    let typed = "договор №1";
    let rig = rigged(&[cms_call(cms_ex_args(data(typed.as_bytes())))], "");
    let (_c, result) = flow(&rig, "sign-cms-text", &text(typed));
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    let abi::CmsOutcome::Signed(cms) = decoded(result.response().unwrap()) else {
        panic!("not a CMS")
    };
    assert_eq!(
        oncl_pki::cms::verify(&cms, Some(typed.as_bytes()))
            .unwrap()
            .len(),
        1
    );
    assert!(oncl_pki::cms::verify(&cms, Some(b"x")).is_err());
}

#[test]
fn an_empty_text_is_not_content() {
    let rig = rigged(&[], "");
    let mut c = ctx(&rig, "sign-raw-text");
    assert_eq!(
        try_prepare(
            &rig,
            "sign-raw-text",
            &text(""),
            &bound(&rig),
            &manual(),
            &mut c
        )
        .unwrap_err(),
        PluginPrepareError::Request(PluginRequestError::InvalidValue("text".into()))
    );
    // And a flag or a document is not a text.
    let wrong = [("text", PluginParam::Flag(true))];
    assert!(
        try_prepare(
            &rig,
            "sign-raw-text",
            &wrong,
            &bound(&rig),
            &manual(),
            &mut c
        )
        .is_err()
    );
}

#[test]
fn a_signed_text_holds_nothing_a_window_could_hide() {
    // Break caught: a text bound as content carries characters the consent could strip,
    // reorder or not show; the user would approve other characters than the key signs.
    let rig = rigged(&[], "");
    let mut c = ctx(&rig, "sign-raw-text");
    for bad in [
        "pay \u{202e}100\u{202c}",
        "a\u{0}b",
        "a\r\nb",
        "x\u{200b}y",
        "\u{feff}x",
        "a\u{2028}b",
        "a\u{85}b",
        "a\u{7f}",
        "\u{1b}[2J",
    ] {
        assert_eq!(
            try_prepare(
                &rig,
                "sign-raw-text",
                &text(bad),
                &bound(&rig),
                &manual(),
                &mut c
            )
            .unwrap_err(),
            PluginPrepareError::Request(PluginRequestError::InvalidValue("text".into())),
            "{bad:?}"
        );
    }
    for good in ["a\tb\nc", "договор №1 \u{4e16}", " x ", "emoji \u{1f600}"] {
        try_prepare(
            &rig,
            "sign-raw-text",
            &text(good),
            &bound(&rig),
            &manual(),
            &mut c,
        )
        .unwrap_or_else(|e| panic!("{good:?}: {e:?}"));
    }
}

// ---- the engine's budgets (MP7b) --------------------------------------------------------------

/// The instance limits `rig_budgeted` registers the module with.
fn rig_instance() -> InstanceLimits {
    InstanceLimits {
        max_memory: 1 << 20,
        max_transfer: 1 << 16,
        ..InstanceLimits::default()
    }
}
fn sign_xml_params() -> Vec<(&'static str, PluginParam<'static>)> {
    vec![
        ("file", PluginParam::Document(XML)),
        ("path", PluginParam::Text("//p:data")),
    ]
}
fn budgets(metadata_bytes: u64, memory_bytes: u64) -> ResourceLimits {
    ResourceLimits {
        metadata_bytes,
        memory_bytes,
        ..ResourceLimits::default()
    }
}
fn xml_rig(resources: ResourceLimits, temporary_store: bool) -> Rig {
    rig_budgeted(
        &[xml_call(Some("//p:data"))],
        "",
        true,
        "user-rsa-sign",
        resources,
        temporary_store,
    )
}

/// The worst failure mode, gone: with the SDK's default metadata budget (64 MiB) the check of a
/// signed document takes what the budget has, and the legacy XML signature used to fail AFTER
/// the key was applied. Now the call is refused before the user is asked, before the key is
/// opened, with a typed subcode.
#[test]
fn an_xml_signature_the_budgets_cannot_hold_is_refused_before_the_key_is_opened() {
    let rig = xml_rig(ResourceLimits::default(), true);
    let mut c = ctx(&rig, "sign-xml");
    let error = try_prepare(
        &rig,
        "sign-xml",
        &sign_xml_params(),
        &bound(&rig),
        &manual(),
        &mut c,
    )
    .unwrap_err();
    // The budgets cannot hold even an XML signature of an empty document: the engine is wrong.
    assert_eq!(error, PluginPrepareError::ResourceBudget);
    assert_eq!(error.subcode(), PluginRefusalCode::ResourceBudget);
    assert_eq!(error.subcode().id(), "resource-budget");
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(OperationError::from(error).code(), ErrorCode::MemoryLimit);
    assert_eq!(
        rig.provider.opens.load(Ordering::SeqCst),
        0,
        "the key is not even opened"
    );
    assert_eq!(rig.guard.applications(), 0);
}

/// The estimate is a sufficient budget: at exactly the estimate every kind of operation signs;
/// one byte less of the metadata or of the memory budget is refused before the key.
#[test]
fn the_estimate_is_enough_and_one_byte_less_is_refused_before_the_key() {
    for (op, kind, calls) in [
        ("sign-xml", KeyKind::Xml, vec![xml_call(Some("//p:data"))]),
        (
            "sign-cms-ex",
            KeyKind::CmsEx,
            vec![cms_call(cms_ex_args(data(DOC)))],
        ),
        ("sign-raw", KeyKind::Raw, vec![raw_call(DOC)]),
    ] {
        let params = if op == "sign-xml" {
            sign_xml_params()
        } else {
            doc(DOC)
        };
        let len = if op == "sign-xml" {
            XML.len()
        } else {
            DOC.len()
        };
        let text = if op == "sign-xml" {
            "//p:data".len()
        } else {
            0
        };
        let need = manual_call_budget(&rig_instance(), kind, len as u64, text as u64).unwrap();
        let rig = rig_budgeted(
            &calls,
            "",
            true,
            "user-rsa-sign",
            budgets(need.metadata, need.memory),
            true,
        );
        let (_c, result) = flow(&rig, op, &params);
        assert_eq!(result.applied(), AppliedState::Applied, "{op}: {result:?}");
        assert_eq!(rig.guard.applications(), 1);
        for (metadata, memory) in [
            (need.metadata - 1, need.memory),
            (need.metadata, need.memory - 1),
        ] {
            let rig = rig_budgeted(
                &calls,
                "",
                true,
                "user-rsa-sign",
                budgets(metadata, memory),
                true,
            );
            let mut c = ctx(&rig, op);
            let error =
                try_prepare(&rig, op, &params, &bound(&rig), &manual(), &mut c).unwrap_err();
            assert_eq!(error.subcode(), PluginRefusalCode::ResourceBudget, "{op}");
            assert!(
                matches!(
                    error,
                    PluginPrepareError::ResourceBudget | PluginPrepareError::DocumentTooLarge
                ),
                "{op}"
            );
            assert_eq!(rig.guard.applications(), 0, "{op}");
        }
    }
}

/// The budget estimate counts the text parameters the options are filled from: a long XPath
/// that the estimate for the same document without it would not hold is refused at
/// `plugin_prepare`, before the user is asked, not by the call after consent.
#[test]
fn a_long_xpath_parameter_is_part_of_the_budget_and_refused_before_consent() {
    let short = sign_xml_params();
    let need = manual_call_budget(
        &rig_instance(),
        KeyKind::Xml,
        XML.len() as u64,
        "//p:data".len() as u64,
    )
    .unwrap();
    let rig = rig_budgeted(
        &[xml_call(Some("//p:data"))],
        "",
        true,
        "user-rsa-sign",
        budgets(need.metadata, need.memory),
        true,
    );
    let (_c, result) = flow(&rig, "sign-xml", &short);
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
    // The same budgets, a 2 KiB XPath (within the parameter's own limit): short by its size.
    let long = format!("//p:data{}", "[1]".repeat(700));
    let long_params = vec![
        ("file", PluginParam::Document(XML)),
        ("path", PluginParam::Text(&long)),
    ];
    let rig = rig_budgeted(
        &[xml_call(Some("//p:data"))],
        "",
        true,
        "user-rsa-sign",
        budgets(need.metadata, need.memory),
        true,
    );
    let mut c = ctx(&rig, "sign-xml");
    let error = try_prepare(
        &rig,
        "sign-xml",
        &long_params,
        &bound(&rig),
        &manual(),
        &mut c,
    )
    .unwrap_err();
    assert_eq!(error.subcode(), PluginRefusalCode::ResourceBudget);
    assert_eq!(rig.guard.applications(), 0);
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
}

/// The preflight is the call's too: a budget that has shrunk since the preparation (another
/// holder of the operation's budget) is refused by `plugin_call_approved` before the module
/// runs, not after the key was used.
#[test]
fn a_budget_that_shrank_since_the_preparation_is_refused_by_the_call_before_the_key() {
    let rig = xml_rig(ManualLimits::desktop().resources, true);
    let params = sign_xml_params();
    let mut c = ctx(&rig, "sign-xml");
    let approval = confirm(prepare(&rig, "sign-xml", &params, &mut c));
    let hog = c
        .resources()
        .reserve_metadata(ManualLimits::desktop().resources.metadata_bytes - (1 << 20))
        .unwrap();
    let result = call(&rig, "sign-xml", &params, approval, &mut c);
    drop(hog);
    assert_eq!(result.applied(), AppliedState::NotApplied, "{result:?}");
    assert_eq!(result.subcode(), Some(PluginRefusalCode::ResourceBudget));
    assert!(result.response().is_none());
    assert_eq!(rig.guard.applications(), 0);
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
}

/// An XML signature spools through the engine's temporary store: without one it is refused
/// before the user is asked. A CMS needs none.
#[test]
fn an_engine_without_a_temporary_store_refuses_xml_but_not_a_cms_before_the_key() {
    let rig = xml_rig(ManualLimits::desktop().resources, false);
    let mut c = ctx(&rig, "sign-xml");
    let error = try_prepare(
        &rig,
        "sign-xml",
        &sign_xml_params(),
        &bound(&rig),
        &manual(),
        &mut c,
    )
    .unwrap_err();
    assert_eq!(error, PluginPrepareError::NoTemporaryStore);
    assert_eq!(error.subcode().id(), "no-temporary-store");
    assert_eq!(
        OperationError::from(error).code(),
        ErrorCode::MissingTemporaryStore
    );
    assert_eq!(rig.provider.opens.load(Ordering::SeqCst), 0);
    let rig = rig_budgeted(
        &[cms_call(cms_ex_args(data(DOC)))],
        "",
        true,
        "user-rsa-sign",
        ManualLimits::desktop().resources,
        false,
    );
    let (_c, result) = flow(&rig, "sign-cms-ex", &doc(DOC));
    assert_eq!(result.applied(), AppliedState::Applied, "{result:?}");
}

/// A budget that holds the module but not this document is a too large DOCUMENT (`InputLimit`,
/// design 4.8), with the same subcode; a host whose `max_transfer` is large and whose document
/// is small is held by the reply term of the sum, not slipped past it.
#[test]
fn a_document_over_the_budgets_is_input_limit_and_a_wrong_engine_is_memory_limit() {
    let need_empty = manual_call_budget(&rig_instance(), KeyKind::Raw, 0, 0).unwrap();
    let limits = budgets(
        need_empty.metadata + (1 << 10),
        need_empty.memory + (1 << 10),
    );
    let rig = rig_budgeted(&[raw_call(DOC)], "", true, "user-rsa-sign", limits, true);
    let mut c = ctx(&rig, "sign-raw");
    let error =
        try_prepare(&rig, "sign-raw", &doc(DOC), &bound(&rig), &manual(), &mut c).unwrap_err();
    assert_eq!(error, PluginPrepareError::DocumentTooLarge);
    assert_eq!(error.subcode(), PluginRefusalCode::ResourceBudget);
    assert_eq!(OperationError::from(error).code(), ErrorCode::InputLimit);
    assert_eq!(rig.guard.applications(), 0);
}
