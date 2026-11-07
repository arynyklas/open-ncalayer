//! The key-use ticket of a declared plugin operation and its guard (docs/design/
//! manual-plugins.md 4.2): Core builds the ticket from the decoded arguments it runs, the
//! guard decides before the key is touched. Actual synthetic WASM and real source-bound
//! crypto, like `plugin_manual`.
#![allow(dead_code)]
#[path = "../examples/sdk_probe/plugin_fixture.rs"]
mod fixture;
#[path = "../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod plugin_crypto;
#[path = "../examples/sdk_probe/plugin_xml_fixture.rs"]
mod xades_fixture;
use fixture::*;
use oncl_core::{
    Engine, EngineServices, ErrorCode, OperationContext, OperationError, OperationId,
    keys::{KeyId, KeySelector, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt},
    plugins::*,
};
use oncl_pdk::abi::{self, Import};
use oncl_pki::{io::TemporaryStore, key::AppliedState, resource::ResourceLimits};
use oncl_plugin::{InstanceLimits, Manifest, operations::KeyKind};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const MODULE: &str = "test.l01.module";
const SHA: PackageHash = PackageHash::File([9; 32]);
const XML: &[u8] = b"<r xmlns:p='urn:p' xml:lang='kk'><p:data Id='payload'>actual WASM protected text</p:data><s/></r>";
const RSA: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
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

fn op(name: &str, imports: &str, kind: &str, profile: &str) -> String {
    format!(
        r#"
[[operations]]
name = "{name}"
module = "{MODULE}"
manual = true
request = '{{"module":"{MODULE}","method":"m","args":["{{file:base64}}"]}}'
label = {{ ru = "а", kk = "ә", en = "a" }}
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[operations.uses]
imports = [{imports}]
network = "pki"
[[operations.uses.key]]
kind = "{kind}"
content = "param:file"
[operations.uses.key.profile]
{profile}
"#
    )
}

const KEY_IMPORTS: &str = r#""keys_describe", "keys_chain", "keys_release""#;

fn operations() -> String {
    [
        op(
            "sign-raw",
            &format!(r#""keys_sign_raw", {KEY_IMPORTS}"#),
            "raw",
            "",
        ),
        op("sign-cms", r#""keys_sign_cms""#, "cms", ""),
        op(
            "sign-cms-ex",
            r#""keys_sign_cms_ex""#,
            "cms_ex",
            r#"cosign = "never""#,
        ),
        op("sign-xml", r#""keys_sign_xml""#, "xml", ""),
        op("sign-xml-ex", r#""keys_sign_xml_ex""#, "xml_ex", ""),
        op("sign-xades", r#""keys_sign_xades""#, "xades", ""),
    ]
    .concat()
}

fn manifest(with_operations: bool) -> Manifest {
    Manifest::from_toml(&format!(
        r#"id = "{ID}"
name.ru = "p"
name.kk = "p"
name.en = "p"
version = "1.2.3"
min_core = "0.1.0-alpha.7"
modules = ["{MODULE}"]
[capabilities]
keys = true
{}"#,
        if with_operations {
            operations()
        } else {
            String::new()
        }
    ))
    .unwrap()
}

/// A guard that can be the allow-everything guard of the other tests (`consent` off) or the
/// plugin consent guard, and counts what reaches it.
struct Watch {
    consent: Option<PluginConsentGuard>,
    before: AtomicUsize,
    finished: AtomicUsize,
    events: Mutex<Vec<KeyUseEvent>>,
}
impl Watch {
    fn new(consent: bool) -> Arc<Self> {
        Arc::new(Self {
            consent: consent.then(PluginConsentGuard::new),
            before: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            events: Mutex::new(Vec::new()),
        })
    }
    fn consent(&self) -> &PluginConsentGuard {
        self.consent.as_ref().unwrap()
    }
}
impl KeyUseGuard for Watch {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        self.before.fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push(event.clone());
        match &self.consent {
            Some(guard) => guard.before_use(event),
            None => Ok(KeyUseReceipt::new(event.clone())),
        }
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        self.finished.fetch_add(1, Ordering::SeqCst);
        match &self.consent {
            Some(guard) => guard.finish(receipt, outcome),
            None => Ok(()),
        }
    }
}

struct Rig {
    engine: Engine,
    guard: Arc<Watch>,
    provider: Arc<crypto::Provider>,
    key: KeySelector,
    _dir: tempfile::TempDir,
}

/// Declared operations take the registry's declared policy; with `exact` a plain exact
/// permission is registered instead (the legacy and server shape).
fn rig(
    calls: &[(Import, Vec<u8>)],
    declare: &[&str],
    exact: &[(&str, &[Import])],
    consent: bool,
    with_operations: bool,
) -> Rig {
    let (key, validation) = xades_fixture::matching_issuer("user-rsa-sign");
    let exact: Vec<PluginPermission> = exact
        .iter()
        .map(|(op, imports)| {
            PluginPermission::new(ID, *op, caller(), imports.iter().copied())
                .with_keys([key.key_id()])
                .with_pki_endpoints(PKI)
                .unwrap()
        })
        .collect();
    let manifest = manifest(with_operations);
    let extras: Vec<Import> = manifest
        .operations()
        .iter()
        .flat_map(|o| o.uses().imports().iter().copied())
        .collect();
    let mut plugins = PluginRegistry::new();
    plugins
        .install(
            manifest,
            SHA,
            &wasm_with_extra_imports(calls, "", &extras),
            InstanceLimits {
                max_memory: 1 << 20,
                max_transfer: 1 << 16,
                ..InstanceLimits::default()
            },
            exact,
        )
        .unwrap();
    for name in declare {
        plugins
            .allow_declared_with_pki(ID, name, caller(), PKI, &["synthetic.test"])
            .unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let guard = Watch::new(consent);
    let provider = Arc::new(crypto::Provider::default());
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(TemporaryStore::new(dir.path()).unwrap())
            .with_keys(provider.clone(), guard.clone())
            .with_validation(validation)
            .with_plugins(plugins),
    )
    .unwrap();
    Rig {
        engine,
        guard,
        provider,
        key,
        _dir: dir,
    }
}

fn permission(rig: &Rig, op: &str, imports: &[Import]) -> PluginPermission {
    PluginPermission::new(ID, op, caller(), imports.iter().copied())
        .with_keys([rig.key.key_id()])
        .with_pki_endpoints(PKI)
        .unwrap()
}
fn ctx(rig: &Rig, op: &str, imports: &[Import]) -> OperationContext {
    begin(
        &rig.engine,
        std::slice::from_ref(&rig.key),
        Some(permission(rig, op, imports)),
    )
}
fn call_of(operation: &str) -> PluginCall<'_> {
    PluginCall {
        plugin_id: ID,
        operation,
        args: "{}",
    }
}
fn run(
    rig: &Rig,
    op: &str,
    imports: &[Import],
    ctx: &mut OperationContext,
) -> Result<PluginResult, OperationError> {
    let caller = caller();
    let bound = [binding(&rig.key, 1)];
    rig.engine
        .plugin_call(&call_of(op), &PluginBindings::new(&caller, &bound), ctx)
        .inspect(|_| {
            let _ = imports;
        })
}

static NONCE: AtomicUsize = AtomicUsize::new(1);
fn nonce() -> [u8; 16] {
    let mut n = [0; 16];
    n[..8].copy_from_slice(&(NONCE.fetch_add(1, Ordering::SeqCst) as u64).to_be_bytes());
    n
}
/// The approval of the (single) use the declared operation describes.
fn approval(rig: &Rig, id: OperationId, op: &str, uses: Vec<ApprovedUse>) -> PluginApproval {
    PluginApproval::new(
        rig.engine.plugin_identity(ID).unwrap().clone(),
        op,
        caller(),
        id,
        rig.key.key_id(),
        1,
        uses,
        Instant::now() + Duration::from_secs(120),
        nonce(),
    )
}
/// SHA-256 of the options the manifest declares for `op`, a `param:` filled in with `text`.
fn declared_options(rig: &Rig, op: &str, text: &str) -> [u8; 32] {
    let ops = rig.engine.plugin_operations(ID).unwrap();
    let op = ops.iter().find(|o| o.name() == op).unwrap();
    op.uses().keys()[0]
        .options_sha256(&|_| Some(text.to_owned()))
        .unwrap()
}
fn used(rig: &Rig, op: &str, kind: KeyKind, content: ContentBinding) -> ApprovedUse {
    ApprovedUse {
        kind,
        content,
        options_sha256: declared_options(rig, op, "/r"),
    }
}
fn raw_call(handle: u32, data: &[u8]) -> (Import, Vec<u8>) {
    (
        Import::KeysSignRaw,
        abi::encode(&abi::SignRawArgs {
            handle,
            data: data.to_vec().into(),
        }),
    )
}
fn handle_call(import: Import, handle: u32) -> (Import, Vec<u8>) {
    (import, abi::encode(&abi::Handle { handle }))
}
const RAW_IMPORTS: [Import; 4] = [
    Import::KeysSignRaw,
    Import::KeysDescribe,
    Import::KeysChain,
    Import::KeysRelease,
];
fn denied(error: OperationError) -> bool {
    error.code() == ErrorCode::PermissionDenied && error.applied_state() == AppliedState::NotApplied
}

fn cms_ex_args(content: &[u8]) -> abi::SignCmsExArgs {
    abi::SignCmsExArgs {
        handle: 1,
        content: abi::CmsContent::Data(content.to_vec().into()),
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
fn xml_ex_args() -> abi::SignXmlExArgs {
    abi::SignXmlExArgs {
        handle: 1,
        xml: XML.to_vec().into(),
        element: None,
        parent: None,
        namespaces: Vec::new(),
        other_prefix_uri: None,
        placement: abi::Placement::DocumentElement,
        signature_method: None,
        digest_method: None,
        signed_info_c14n: None,
        transforms: None,
        signature_id: None,
        signing_time_object: None,
        strip_whitespace: false,
        base64_line_breaks: None,
        output: abi::XmlOutput::AsIs,
    }
}
fn custom_tsa() -> abi::TsaSpec {
    abi::TsaSpec {
        url: abi::PkiUrl::Fixed("http://tsa.example/".into()),
        method: abi::PkiMethod::Post { content_type: None },
        hash: abi::HashAlg::Sha256,
        policy: None,
        nonce: abi::Nonce::None,
        cert_req: true,
        retries: 0,
        timeout_ms: 1000,
        check_skew_ms: None,
        require_tsa_eku: false,
    }
}
fn xades_args() -> abi::XadesArgs {
    abi::XadesArgs {
        handle: 1,
        xml: XML.to_vec().into(),
        level: abi::XadesLevel::B,
        tsa: abi::TsaChoice::Basics,
        chain: Vec::new(),
        signature_method: None,
        digest_method: None,
    }
}

/// One declared operation, one call, an approval of exactly what the call does.
struct Case {
    op: &'static str,
    import: Import,
    args: Vec<u8>,
    kind: KeyKind,
    content: ContentBinding,
}
fn cases() -> Vec<Case> {
    vec![
        Case {
            op: "sign-raw",
            import: Import::KeysSignRaw,
            args: abi::encode(&abi::SignRawArgs {
                handle: 1,
                data: MESSAGE.to_vec().into(),
            }),
            kind: KeyKind::Raw,
            content: ContentBinding::bytes(MESSAGE),
        },
        Case {
            op: "sign-cms",
            import: Import::KeysSignCms,
            args: abi::encode(&abi::SignCmsArgs {
                handle: 1,
                data: MESSAGE.to_vec().into(),
                attached: false,
                timestamp: false,
            }),
            kind: KeyKind::Cms,
            content: ContentBinding::bytes(MESSAGE),
        },
        Case {
            op: "sign-cms-ex",
            import: Import::KeysSignCmsEx,
            args: abi::encode(&cms_ex_args(MESSAGE)),
            kind: KeyKind::CmsEx,
            content: ContentBinding::bytes(MESSAGE),
        },
        Case {
            op: "sign-xml",
            import: Import::KeysSignXml,
            args: abi::encode(&abi::SignXmlArgs {
                handle: 1,
                xml: XML.to_vec().into(),
                element: None,
                parent: None,
            }),
            kind: KeyKind::Xml,
            content: ContentBinding::bytes(XML),
        },
        Case {
            op: "sign-xml-ex",
            import: Import::KeysSignXmlEx,
            args: abi::encode(&xml_ex_args()),
            kind: KeyKind::XmlEx,
            content: ContentBinding::bytes(XML),
        },
        Case {
            op: "sign-xades",
            import: Import::KeysSignXades,
            args: abi::encode(&xades_args()),
            kind: KeyKind::Xades,
            content: ContentBinding::bytes(XML),
        },
    ]
}
fn declared_rig(case: &Case, consent: bool) -> Rig {
    rig(
        &[(case.import, case.args.clone())],
        &[case.op],
        &[],
        consent,
        true,
    )
}
fn go(rig: &Rig, case: &Case, uses: Vec<ApprovedUse>) -> Result<PluginResult, OperationError> {
    let mut c = ctx(rig, case.op, &[case.import]);
    rig.guard
        .consent()
        .grant(approval(rig, c.id(), case.op, uses))
        .unwrap();
    run(rig, case.op, &[case.import], &mut c)
}

#[test]
fn approved_ticket_is_accepted_for_every_kind() {
    // The actual call's options hash equals the declared profile's through the one encoder,
    // for each of the six signing imports; the approval names exactly what the call does.
    for case in cases() {
        let r = declared_rig(&case, true);
        let result = go(&r, &case, vec![used(&r, case.op, case.kind, case.content)]);
        let result = result.unwrap_or_else(|e| panic!("{}: {e:?}", case.op));
        assert_eq!(result.applied_state(), AppliedState::Applied, "{}", case.op);
        assert_eq!(r.guard.consent().applications(), 1, "{}", case.op);
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 1, "{}", case.op);
    }
}

#[test]
fn event_names_the_plugin_and_the_ticket() {
    // A plugin key use is distinguishable from a document key use, with identity, operation,
    // kind, bound key, content and options; the digest is stable and covers the content.
    let case = &cases()[0];
    let r = declared_rig(case, false);
    let mut c = ctx(&r, case.op, &[case.import]);
    run(&r, case.op, &[case.import], &mut c).unwrap();
    let events = r.guard.events.lock().unwrap();
    let ticket = events[0].plugin().expect("plugin ticket").clone();
    assert_eq!(ticket.identity(), r.engine.plugin_identity(ID).unwrap());
    assert_eq!(ticket.operation(), "sign-raw");
    assert_eq!(ticket.kind(), KeyKind::Raw);
    assert_eq!(ticket.handle(), 1);
    assert_eq!(ticket.key(), &r.key.key_id());
    assert_eq!(ticket.caller(), &caller());
    assert_eq!(*ticket.content(), ContentBinding::bytes(MESSAGE));
    assert_eq!(
        *ticket.options_sha256(),
        declared_options(&r, "sign-raw", "")
    );
    assert_eq!(ticket.max_uses(), 1);
    drop(events);
    let other = Case {
        content: ContentBinding::bytes(b"other"),
        ..cases().remove(0)
    };
    let r2 = rig(&[raw_call(1, b"other")], &["sign-raw"], &[], false, true);
    let mut c2 = ctx(&r2, other.op, &[other.import]);
    run(&r2, other.op, &[other.import], &mut c2).unwrap();
    let t2 = r2.guard.events.lock().unwrap()[0].plugin().unwrap().clone();
    assert_ne!(ticket.digest(), t2.digest());
    assert_eq!(ticket.digest(), ticket.clone().digest());
}

#[test]
fn ticket_missing_refuses_before_key() {
    // A key use without a ticket (a document use, or a plugin operation without
    // declarations) is refused by the plugin guard, and the key is never applied.
    let r = rig(
        &[raw_call(1, MESSAGE)],
        &[],
        &[("sign-raw", &[Import::KeysSignRaw])],
        true,
        false,
    );
    let mut c = ctx(&r, "sign-raw", &[Import::KeysSignRaw]);
    let error = run(&r, "sign-raw", &[], &mut c).unwrap_err();
    assert!(denied(error), "no declaration means no ticket");
    assert_eq!(r.guard.before.load(Ordering::SeqCst), 1);
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::NoTicket)
    );
    assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0);
    assert_eq!(r.guard.consent().applications(), 0);
    drop(c);
    // A document key use through the same guard.
    let mut c = begin(&r.engine, std::slice::from_ref(&r.key), None);
    let request = oncl_core::SignRequest::raw_message(oncl_core::keys::KeyRequest::new(
        &r.key,
        Some(crypto::PASSWORD),
    ));
    let mut out = Vec::new();
    let error = r
        .engine
        .sign(
            request,
            oncl_pki::io::Source::sequential(
                &mut std::io::Cursor::new(MESSAGE),
                Some(MESSAGE.len() as u64),
            ),
            &mut out,
            &mut c,
        )
        .unwrap_err();
    assert!(denied(error));
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::NoTicket)
    );
    assert!(out.is_empty());
    assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0);
    // Without an approval even a ticketed use is refused.
    let case = &cases()[0];
    let r = declared_rig(case, true);
    let mut c = ctx(&r, case.op, &[case.import]);
    let error = run(&r, case.op, &[case.import], &mut c).unwrap_err();
    assert!(denied(error));
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::NoApproval)
    );
    assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0);
}

#[test]
fn content_hash_mismatch_refused() {
    // Every kind: approval of other bytes (or a one-byte longer/shorter same-hash claim) is
    // refused by the guard, with the key unused.
    for case in cases() {
        let r = declared_rig(&case, true);
        let error = go(
            &r,
            &case,
            vec![used(
                &r,
                case.op,
                case.kind,
                ContentBinding::bytes(b"different bytes"),
            )],
        )
        .unwrap_err();
        assert!(denied(error), "{}", case.op);
        assert_eq!(
            r.guard.consent().last_refusal(),
            Some(TicketRefusal::Content),
            "{}",
            case.op
        );
        assert_eq!(r.guard.before.load(Ordering::SeqCst), 1, "{}", case.op);
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0, "{}", case.op);
        // The same digest with another length is another content.
        let mut lying = case.content;
        lying.len += 1;
        let r = declared_rig(&case, true);
        assert!(denied(
            go(&r, &case, vec![used(&r, case.op, case.kind, lying)]).unwrap_err()
        ));
        assert_eq!(
            r.guard.consent().last_refusal(),
            Some(TicketRefusal::Content)
        );
        // A digest input is not the same content as the bytes.
        let mut prehashed = case.content;
        prehashed.prehashed = true;
        let r = declared_rig(&case, true);
        assert!(denied(
            go(&r, &case, vec![used(&r, case.op, case.kind, prehashed)]).unwrap_err()
        ));
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn key_use_with_other_bytes_is_not_applied() {
    // The plugin signs bytes other than the approved ones: nothing is applied and no
    // signature is produced.
    for (call, name) in [
        (raw_call(1, b"other bytes"), "sign-raw"),
        (
            (
                Import::KeysSignCmsEx,
                abi::encode(&cms_ex_args(b"other bytes")),
            ),
            "sign-cms-ex",
        ),
    ] {
        let case = cases().into_iter().find(|c| c.op == name).unwrap();
        let r = rig(&[call], &[name], &[], true, true);
        let result = go(&r, &case, vec![used(&r, name, case.kind, case.content)]);
        let error = result.expect_err("other bytes are refused");
        assert!(denied(error), "{name}");
        assert_eq!(r.guard.consent().applications(), 0, "{name}");
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0, "{name}");
    }
}

#[test]
fn options_mismatch_refused() {
    // (modifier, name, representable): a representable deviation from the declared options
    // reaches the guard and fails on the options hash; one no profile can say is refused by
    // Core before the guard (and before the provider is asked for the key).
    type Edit = Box<dyn Fn(&mut abi::SignCmsExArgs)>;
    let edits: Vec<(&str, bool, Edit)> = vec![
        ("encapsulate", true, Box::new(|a| a.encapsulate = true)),
        (
            "content_type",
            true,
            Box::new(|a| a.attrs.content_type = false),
        ),
        (
            "message_digest",
            true,
            Box::new(|a| a.attrs.message_digest = false),
        ),
        (
            "signing_certificate_v2",
            true,
            Box::new(|a| a.attrs.signing_certificate_v2 = false),
        ),
        (
            "signing_time none",
            true,
            Box::new(|a| a.attrs.signing_time = None),
        ),
        (
            "output",
            true,
            Box::new(|a| a.output = abi::CmsOutput::Base64),
        ),
        (
            "attrs.extra",
            false,
            Box::new(|a| {
                a.attrs.extra.push(abi::RawAttribute {
                    oid: "1.2.3.4".into(),
                    values: vec![vec![4, 1, 1].into()],
                })
            }),
        ),
        (
            "econtent_type",
            false,
            Box::new(|a| a.econtent_type = Some("1.2.840.113549.1.7.1".into())),
        ),
        (
            "digest",
            false,
            Box::new(|a| a.digest = Some(abi::HashAlg::Sha256)),
        ),
        (
            "certificates extra",
            false,
            Box::new(|a| a.certificates = abi::CmsCerts::Extra(vec![vec![1].into()])),
        ),
        (
            "custom tsa",
            false,
            Box::new(|a| a.timestamp = Some(abi::TsaChoice::Custom(custom_tsa()))),
        ),
        (
            "cosign into",
            false,
            Box::new(|a| a.cosign = abi::CoSign::Into(vec![1].into())),
        ),
        (
            "signing time fixed",
            false,
            Box::new(|a| {
                a.attrs.signing_time = Some(abi::SigningTime {
                    at: abi::TimeSource::UnixMs(1),
                    form: abi::TimeForm::Auto,
                })
            }),
        ),
        (
            "signing time form",
            false,
            Box::new(|a| {
                a.attrs.signing_time = Some(abi::SigningTime {
                    at: abi::TimeSource::Now,
                    form: abi::TimeForm::Utc,
                })
            }),
        ),
    ];
    for (name, representable, edit) in edits {
        let mut args = cms_ex_args(MESSAGE);
        edit(&mut args);
        let case = Case {
            args: abi::encode(&args),
            ..cases().remove(2)
        };
        let r = declared_rig(&case, true);
        let error = go(&r, &case, vec![used(&r, case.op, case.kind, case.content)])
            .err()
            .unwrap_or_else(|| panic!("{name} was signed"));
        assert!(denied(error), "{name}");
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0, "{name}");
        assert_eq!(r.guard.consent().applications(), 0, "{name}");
        if representable {
            assert_eq!(
                r.guard.consent().last_refusal(),
                Some(TicketRefusal::Options),
                "{name}"
            );
        } else {
            assert_eq!(r.guard.before.load(Ordering::SeqCst), 0, "{name}");
            assert_eq!(r.provider.opens.load(Ordering::SeqCst), 0, "{name}");
        }
    }
    // XML and XAdES.
    type Xml = Box<dyn Fn(&mut abi::SignXmlExArgs)>;
    let xml: Vec<(&str, bool, Xml)> = vec![
        (
            "placement",
            true,
            Box::new(|a| a.placement = abi::Placement::FirstChildOfDocument),
        ),
        (
            "signature_method",
            true,
            Box::new(|a| a.signature_method = Some(RSA.into())),
        ),
        (
            "strip_whitespace",
            true,
            Box::new(|a| a.strip_whitespace = true),
        ),
        (
            "c14n",
            true,
            Box::new(|a| a.signed_info_c14n = Some(abi::C14n::Exclusive)),
        ),
        (
            "element",
            true,
            Box::new(|a| a.element = Some("//p:data".into())),
        ),
        (
            "output",
            true,
            Box::new(|a| {
                a.output = abi::XmlOutput::Serialize {
                    declaration: true,
                    standalone_no: false,
                    trim: false,
                }
            }),
        ),
        (
            "transforms",
            false,
            Box::new(|a| a.transforms = Some(Vec::new())),
        ),
        (
            "signature_id",
            false,
            Box::new(|a| a.signature_id = Some("sig".into())),
        ),
    ];
    for (name, representable, edit) in xml {
        let mut args = xml_ex_args();
        edit(&mut args);
        let case = Case {
            args: abi::encode(&args),
            ..cases().remove(4)
        };
        let r = declared_rig(&case, true);
        let error = go(&r, &case, vec![used(&r, case.op, case.kind, case.content)])
            .err()
            .unwrap_or_else(|| panic!("xml {name} was signed"));
        assert!(denied(error), "xml {name}");
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0, "xml {name}");
        if representable {
            assert_eq!(
                r.guard.consent().last_refusal(),
                Some(TicketRefusal::Options),
                "xml {name}"
            );
        } else {
            assert_eq!(r.guard.before.load(Ordering::SeqCst), 0, "xml {name}");
        }
    }
    type Ades = Box<dyn Fn(&mut abi::XadesArgs)>;
    let ades: Vec<(&str, bool, Ades)> = vec![
        (
            "signature_method",
            true,
            Box::new(|a| a.signature_method = Some(RSA.into())),
        ),
        ("chain", false, Box::new(|a| a.chain = vec![vec![1].into()])),
        (
            "custom tsa",
            false,
            Box::new(|a| a.tsa = abi::TsaChoice::Custom(custom_tsa())),
        ),
    ];
    for (name, representable, edit) in ades {
        let mut args = xades_args();
        edit(&mut args);
        let case = Case {
            args: abi::encode(&args),
            ..cases().remove(5)
        };
        let r = declared_rig(&case, true);
        let error = go(&r, &case, vec![used(&r, case.op, case.kind, case.content)])
            .err()
            .unwrap_or_else(|| panic!("xades {name} was signed"));
        assert!(denied(error), "xades {name}");
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0, "xades {name}");
        if representable {
            assert_eq!(
                r.guard.consent().last_refusal(),
                Some(TicketRefusal::Options),
                "xades {name}"
            );
        } else {
            assert_eq!(r.guard.before.load(Ordering::SeqCst), 0, "xades {name}");
        }
    }
    // The approval of other options than the declared ones does not cover the declared call.
    let case = cases().remove(2);
    let r = declared_rig(&case, true);
    let mut wrong = used(&r, case.op, case.kind, case.content);
    wrong.options_sha256[0] ^= 1;
    assert!(denied(go(&r, &case, vec![wrong]).unwrap_err()));
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::Options)
    );
}

#[test]
fn handle_other_than_bound_denied_identically() {
    // Describe, chain, release and every signing import answer a handle that is not THE
    // bound one (never bound, released, one of two) with the one PermissionDenied, before
    // any key is asked for or the guard consulted.
    let entry = crypto::issued("user-rsa-sign");
    let chain = [crypto::raw("inter-gost2015.key").cert];
    let mut seen = Vec::new();
    for (import, call) in [
        (Import::KeysDescribe, handle_call(Import::KeysDescribe, 2)),
        (Import::KeysChain, handle_call(Import::KeysChain, 2)),
        (Import::KeysRelease, handle_call(Import::KeysRelease, 2)),
        (Import::KeysSignRaw, raw_call(2, MESSAGE)),
        (Import::KeysDescribe, handle_call(Import::KeysDescribe, 99)),
        (Import::KeysSignRaw, raw_call(0, MESSAGE)),
    ] {
        let r = rig(&[call], &["sign-raw"], &[], true, true);
        let mut c = ctx(&r, "sign-raw", &RAW_IMPORTS);
        let caller = caller();
        let bound = [binding(&r.key, 1).with_public_metadata(&entry.alias, &entry.cert, &chain)];
        r.guard
            .consent()
            .grant(approval(
                &r,
                c.id(),
                "sign-raw",
                vec![used(
                    &r,
                    "sign-raw",
                    KeyKind::Raw,
                    ContentBinding::bytes(MESSAGE),
                )],
            ))
            .unwrap();
        let error = r
            .engine
            .plugin_call(
                &call_of("sign-raw"),
                &PluginBindings::new(&caller, &bound),
                &mut c,
            )
            .err()
            .unwrap_or_else(|| panic!("{import:?} with another handle succeeded"));
        assert!(denied(error), "{import:?}");
        seen.push(format!("{:?}", {
            let r2 = rig(
                &[handle_call(Import::KeysDescribe, 2)],
                &["sign-raw"],
                &[],
                true,
                true,
            );
            let mut c2 = ctx(&r2, "sign-raw", &RAW_IMPORTS);
            let bound =
                [binding(&r2.key, 1).with_public_metadata(&entry.alias, &entry.cert, &chain)];
            r2.engine
                .plugin_call(
                    &call_of("sign-raw"),
                    &PluginBindings::new(&caller, &bound),
                    &mut c2,
                )
                .err()
                .unwrap()
        }));
        assert_eq!(r.guard.before.load(Ordering::SeqCst), 0, "{import:?}");
        assert_eq!(r.provider.opens.load(Ordering::SeqCst), 0, "{import:?}");
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]));
    // The bound handle itself is described.
    let r = rig(
        &[handle_call(Import::KeysDescribe, 1)],
        &["sign-raw"],
        &[],
        true,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &RAW_IMPORTS);
    let caller = caller();
    let bound = [binding(&r.key, 1).with_public_metadata(&entry.alias, &entry.cert, &chain)];
    r.engine
        .plugin_call(
            &call_of("sign-raw"),
            &PluginBindings::new(&caller, &bound),
            &mut c,
        )
        .unwrap();
    // A declared operation binds at most one key: two bindings are refused before the
    // module runs.
    let other = crypto::selector("user-gost2015-sign");
    let r = rig(&[raw_call(1, MESSAGE)], &["sign-raw"], &[], true, true);
    let both = [other.clone(), r.key.clone()];
    let mut c = begin(
        &r.engine,
        &both,
        Some(
            PluginPermission::new(ID, "sign-raw", caller.clone(), RAW_IMPORTS)
                .with_keys(both.iter().map(KeySelector::key_id))
                .with_pki_endpoints(PKI)
                .unwrap(),
        ),
    );
    let bound = [binding(&r.key, 1), binding(&other, 2)];
    let error = r
        .engine
        .plugin_call(
            &call_of("sign-raw"),
            &PluginBindings::new(&caller, &bound),
            &mut c,
        )
        .unwrap_err();
    assert!(denied(error));
    assert_eq!(r.guard.before.load(Ordering::SeqCst), 0);
    assert_eq!(r.provider.opens.load(Ordering::SeqCst), 0);
}

#[test]
fn second_use_refused() {
    // max_uses = 1: the second signing of the very same bytes in one call, and a second
    // call on the same context, are refused; the first was applied.
    let case = &cases()[0];
    let r = rig(
        &[raw_call(1, MESSAGE), raw_call(1, MESSAGE)],
        &["sign-raw"],
        &[],
        true,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &RAW_IMPORTS);
    r.guard
        .consent()
        .grant(approval(
            &r,
            c.id(),
            "sign-raw",
            vec![used(
                &r,
                "sign-raw",
                KeyKind::Raw,
                ContentBinding::bytes(MESSAGE),
            )],
        ))
        .unwrap();
    let error = run(&r, "sign-raw", &[], &mut c).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        r.guard.consent().applications(),
        1,
        "only the first use passed"
    );
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::AlreadyUsed)
    );
    drop(c);
    // The same approval does not cover another call of the same context.
    let r = declared_rig(case, true);
    let mut c = ctx(&r, case.op, &[case.import]);
    r.guard
        .consent()
        .grant(approval(
            &r,
            c.id(),
            case.op,
            vec![used(&r, case.op, case.kind, case.content)],
        ))
        .unwrap();
    run(&r, case.op, &[], &mut c).unwrap();
    let error = run(&r, case.op, &[], &mut c).unwrap_err();
    assert!(denied(error));
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::AlreadyUsed)
    );
    assert_eq!(r.guard.consent().applications(), 1);
}

#[test]
fn kind_mismatch_refused() {
    // A call whose import is not a kind the operation declares is refused by Core (the
    // exact-grant shape lets the import through; the declaration does not).
    let imports = [Import::KeysSignRaw, Import::KeysSignCmsEx];
    let r = rig(
        &[(Import::KeysSignCmsEx, abi::encode(&cms_ex_args(MESSAGE)))],
        &[],
        &[("sign-raw", &imports)],
        true,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &imports);
    r.guard
        .consent()
        .grant(approval(
            &r,
            c.id(),
            "sign-raw",
            vec![used(
                &r,
                "sign-raw",
                KeyKind::CmsEx,
                ContentBinding::bytes(MESSAGE),
            )],
        ))
        .unwrap();
    let error = run(&r, "sign-raw", &[], &mut c).unwrap_err();
    assert!(denied(error));
    assert_eq!(r.guard.before.load(Ordering::SeqCst), 0);
    assert_eq!(r.provider.opens.load(Ordering::SeqCst), 0);
    // An approval of another kind than the ticket's is refused by the guard.
    let case = &cases()[0];
    let r = declared_rig(case, true);
    let error = go(
        &r,
        case,
        vec![used(&r, case.op, KeyKind::Xml, case.content)],
    )
    .unwrap_err();
    assert!(denied(error));
    assert_eq!(r.guard.consent().last_refusal(), Some(TicketRefusal::Kind));
    assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0);
}

#[test]
fn approval_binds_operation_plugin_key_and_time() {
    // One field at a time: another invocation, plugin version, operation, caller or key,
    // an expired deadline, and a replayed nonce.
    let case = &cases()[0];
    let fresh = |f: &dyn Fn(&mut Parts)| {
        let r = declared_rig(case, true);
        let c = ctx(&r, case.op, &[case.import]);
        let mut p = Parts {
            identity: r.engine.plugin_identity(ID).unwrap().clone(),
            op: case.op.to_owned(),
            caller: caller(),
            id: c.id(),
            key: r.key.key_id(),
            handle: 1,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        f(&mut p);
        r.guard
            .consent()
            .grant(PluginApproval::new(
                p.identity,
                p.op,
                p.caller,
                p.id,
                p.key,
                p.handle,
                vec![used(&r, case.op, case.kind, case.content)],
                p.deadline,
                nonce(),
            ))
            .unwrap();
        let mut c = c;
        let error = run(&r, case.op, &[], &mut c);
        (error, r)
    };
    struct Parts {
        identity: PluginIdentity,
        op: String,
        caller: CallerContext,
        id: OperationId,
        key: KeyId,
        handle: u32,
        deadline: Instant,
    }
    let (ok, _) = fresh(&|_| {});
    ok.unwrap();
    for (name, reason, edit) in [
        (
            "version",
            TicketRefusal::Identity,
            Box::new(|p: &mut Parts| p.identity.version = "9".into()) as Box<dyn Fn(&mut Parts)>,
        ),
        (
            "package",
            TicketRefusal::Identity,
            Box::new(|p: &mut Parts| p.identity.package = PackageHash::File([1; 32])),
        ),
        (
            "operation",
            TicketRefusal::Operation,
            Box::new(|p: &mut Parts| p.op = "sign-cms".into()),
        ),
        (
            "caller",
            TicketRefusal::Caller,
            Box::new(|p: &mut Parts| p.caller = CallerContext::ServiceClient("x".into())),
        ),
        (
            "key",
            TicketRefusal::Key,
            Box::new(|p: &mut Parts| p.key = KeyId::new("other").unwrap()),
        ),
        (
            "handle",
            TicketRefusal::Key,
            Box::new(|p: &mut Parts| p.handle = 2),
        ),
        (
            "expired",
            TicketRefusal::Expired,
            Box::new(|p: &mut Parts| p.deadline = Instant::now()),
        ),
    ] {
        let (error, r) = fresh(&*edit);
        assert!(
            denied(error.err().unwrap_or_else(|| panic!("{name}"))),
            "{name}"
        );
        assert_eq!(r.guard.consent().last_refusal(), Some(reason), "{name}");
        assert_eq!(r.guard.finished.load(Ordering::SeqCst), 0, "{name}");
    }
    // Another invocation id.
    let r = declared_rig(case, true);
    let c1 = ctx(&r, case.op, &[case.import]);
    let first = c1.id();
    drop(c1);
    let mut c2 = ctx(&r, case.op, &[case.import]);
    r.guard
        .consent()
        .grant(approval(
            &r,
            first,
            case.op,
            vec![used(&r, case.op, case.kind, case.content)],
        ))
        .unwrap();
    assert!(denied(run(&r, case.op, &[], &mut c2).unwrap_err()));
    assert_eq!(
        r.guard.consent().last_refusal(),
        Some(TicketRefusal::OperationId)
    );
    // A nonce is granted once; an approval needs exactly one use.
    let guard = PluginConsentGuard::new();
    let mk = |n: [u8; 16], uses: usize| {
        PluginApproval::new(
            r.engine.plugin_identity(ID).unwrap().clone(),
            case.op,
            caller(),
            first,
            r.key.key_id(),
            1,
            vec![used(&r, case.op, case.kind, case.content); uses],
            Instant::now() + Duration::from_secs(60),
            n,
        )
    };
    guard.grant(mk([7; 16], 1)).unwrap();
    assert_eq!(guard.grant(mk([7; 16], 1)), Err(ApprovalRejected::Replayed));
    assert_eq!(guard.grant(mk([8; 16], 2)), Err(ApprovalRejected::Uses));
    assert_eq!(guard.grant(mk([9; 16], 0)), Err(ApprovalRejected::Uses));
    guard.revoke();
}

#[test]
fn legacy_document_key_use_unchanged() {
    // A document key use carries no plugin ticket and passes a plain guard as before.
    let r = rig(&[], &[], &[], false, false);
    let mut c = begin(&r.engine, std::slice::from_ref(&r.key), None);
    let request = oncl_core::SignRequest::raw_message(oncl_core::keys::KeyRequest::new(
        &r.key,
        Some(crypto::PASSWORD),
    ));
    let mut out = Vec::new();
    r.engine
        .sign(
            request,
            oncl_pki::io::Source::sequential(
                &mut std::io::Cursor::new(MESSAGE),
                Some(MESSAGE.len() as u64),
            ),
            &mut out,
            &mut c,
        )
        .unwrap();
    assert!(!out.is_empty());
    let events = r.guard.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].plugin().is_none());
    assert_eq!(events[0].action, oncl_core::Action::Sign);
    assert_eq!(r.guard.finished.load(Ordering::SeqCst), 1);
}

#[test]
fn plugin_without_declaration_unchanged_on_server_path() {
    // A plugin whose manifest declares no operation signs through an exact grant exactly as
    // before: no ticket, a plain guard sees the use, the key is applied.
    let r = rig(
        &[raw_call(1, MESSAGE)],
        &[],
        &[("sign-raw", &[Import::KeysSignRaw])],
        false,
        false,
    );
    let mut c = ctx(&r, "sign-raw", &[Import::KeysSignRaw]);
    let result = run(&r, "sign-raw", &[], &mut c).unwrap();
    assert_eq!(result.applied_state(), AppliedState::Applied);
    let events = r.guard.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].plugin().is_none());
    drop(events);
    // Releasing twice is still refused for such a plugin (the idempotent release is the
    // declared operation's).
    let r = rig(
        &[
            handle_call(Import::KeysRelease, 1),
            handle_call(Import::KeysRelease, 1),
        ],
        &[],
        &[("sign-raw", &[Import::KeysRelease])],
        false,
        false,
    );
    let mut c = ctx(&r, "sign-raw", &[Import::KeysRelease]);
    assert!(denied(run(&r, "sign-raw", &[], &mut c).unwrap_err()));
    // A declared operation of the same plugin through an exact grant is ticketed: the
    // server's key use of it carries the ticket (and its guard refuses it until MP8).
    let r = rig(
        &[raw_call(1, MESSAGE)],
        &[],
        &[("sign-raw", &[Import::KeysSignRaw])],
        false,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &[Import::KeysSignRaw]);
    run(&r, "sign-raw", &[], &mut c).unwrap();
    assert!(r.guard.events.lock().unwrap()[0].plugin().is_some());
}

#[test]
fn cosign_auto_is_coerced_to_never() {
    // cosign Auto over content that is itself a CMS signs those bytes as a new, only
    // signer; the ticket's content is the effective content (the whole CMS).
    let entry = crypto::raw("user-rsa-sign");
    let inner = oncl_pki::cms::sign_spec(
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
    let mut args = cms_ex_args(&inner);
    args.cosign = abi::CoSign::Auto;
    let case = Case {
        args: abi::encode(&args),
        content: ContentBinding::bytes(&inner),
        ..cases().remove(2)
    };
    let r = declared_rig(&case, true);
    let result = go(&r, &case, vec![used(&r, case.op, case.kind, case.content)])
        .unwrap_or_else(|e| panic!("{e:?}"));
    let response = result.response();
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    let abi::CmsOutcome::Signed(signed) = abi::decode::<abi::HostResult<abi::CmsOutcome>>(&bytes)
        .unwrap()
        .unwrap()
    else {
        panic!("no CMS")
    };
    let verified = oncl_pki::cms::verify(&signed, Some(&inner)).unwrap();
    assert_eq!(
        verified.len(),
        1,
        "one new signer over the CMS bytes, not a co-signature"
    );
    assert_eq!(
        *r.guard.events.lock().unwrap()[0]
            .plugin()
            .unwrap()
            .content(),
        ContentBinding::bytes(&inner)
    );
    // The simple keys_sign_cms (which hard-codes Auto) is coerced the same way.
    let simple = Case {
        args: abi::encode(&abi::SignCmsArgs {
            handle: 1,
            data: inner.clone().into(),
            attached: false,
            timestamp: false,
        }),
        content: ContentBinding::bytes(&inner),
        ..cases().remove(1)
    };
    let r = declared_rig(&simple, true);
    go(
        &r,
        &simple,
        vec![used(&r, simple.op, simple.kind, simple.content)],
    )
    .unwrap();
}

#[test]
fn release_idempotent() {
    // The bound handle of a declared operation can be released twice; afterwards nothing
    // uses it.
    let r = rig(
        &[
            handle_call(Import::KeysRelease, 1),
            handle_call(Import::KeysRelease, 1),
        ],
        &["sign-raw"],
        &[],
        true,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &RAW_IMPORTS);
    run(&r, "sign-raw", &[], &mut c).unwrap();
    let r = rig(
        &[handle_call(Import::KeysRelease, 1), raw_call(1, MESSAGE)],
        &["sign-raw"],
        &[],
        true,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &RAW_IMPORTS);
    r.guard
        .consent()
        .grant(approval(
            &r,
            c.id(),
            "sign-raw",
            vec![used(
                &r,
                "sign-raw",
                KeyKind::Raw,
                ContentBinding::bytes(MESSAGE),
            )],
        ))
        .unwrap();
    assert!(denied(run(&r, "sign-raw", &[], &mut c).unwrap_err()));
    assert_eq!(r.guard.before.load(Ordering::SeqCst), 0);
    // Releasing a handle that is not the bound one is not idempotent success but the same
    // denial as any other handle.
    let r = rig(
        &[handle_call(Import::KeysRelease, 2)],
        &["sign-raw"],
        &[],
        true,
        true,
    );
    let mut c = ctx(&r, "sign-raw", &RAW_IMPORTS);
    assert!(denied(run(&r, "sign-raw", &[], &mut c).unwrap_err()));
}
