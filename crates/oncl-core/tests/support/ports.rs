//! The harness of the plugin ports' manual-window tests (`plugin_ports_manual.rs`, one module
//! per wave of ports): the REAL wasm of a port under the REAL manual call path.
//!
//! [`run_port_operation`] loads `plugins/<port>/plugin.toml` and the port's built module,
//! registers them as the desktop does (`PackageHash::Loose`, the declared policy of every
//! manual operation with the production PKI endpoints), then runs one declared operation:
//! `plugin_prepare` -> [`ConsentSummary`] -> [`UserConfirmation::after_user_confirmed`] ->
//! `approve` -> `plugin_call_approved`, with a REAL synthetic key (a fixture PKCS#12 reissued
//! under a throwaway root, so that Core's own strict online validation of the signer runs for
//! real against mock OCSP and TSA responders). Nothing is stubbed on the plugin's side: the
//! module calls `keys_select`, `keys_sign_*`, `cert_info` ... exactly as in a session.
//!
//! The oracles ([`oracle`]) check what comes back by tools that are not OpenNCALayer's
//! signer: `openssl cms -verify` and `openssl pkeyutl -verify` for CMS and raw RSA
//! signatures, and `oracle/xmldsig_verify.py` (lxml + cryptography) for XML-DSig; the
//! repository's own verifiers (`oncl_pki::cms::verify`, `oncl_xml::verify`) run as well.
//!
//! Environment: `ONCL_PLUGIN_WASM_DIR` (the directory of the built `oncl_port_*.wasm`; unset,
//! the tests build `plugins/` themselves into `<target>/plugin-ports`), `ONCL_OPENSSL`,
//! `ONCL_PYHANKO_PYTHON` (a Python with `lxml` and `cryptography`; else `python3`/`python`).
//!
//! A test file includes it with `#[path = "support/ports.rs"] mod ports;`.
#![allow(dead_code)]

#[path = "../../examples/sdk_probe/batch_fixture.rs"]
pub(crate) mod crypto;

use der::{Decode, Encode};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationPolicy,
    keys::{KeyRequest, KeySelector, KeySources},
    plugins::*,
};
use oncl_pdk::abi::Import;
use oncl_pki::{
    cert::Certificate,
    http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport, RouteTransport},
    ocsp::MockOcsp,
    pkcs12,
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    testing::{TestCertSpec, issue_cert},
    tsp::MockTsa,
    validation::NetworkPolicy,
};
use oncl_plugin::{DEFAULT_OCSP, DEFAULT_TSA, InstanceLimits, Manifest, NCA_PKI_HOSTS};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub use oncl_pki::key::AppliedState;

/// The synthetic key fixtures the ports are run with.
pub const RSA: &str = "user-rsa-sign";
pub const GOST2015: &str = "user-gost2015-sign";

/// The fixed time of every run (the fixtures' `NOW`).
pub const NOW: time::OffsetDateTime = crypto::NOW;

/// The PKI endpoints this harness grants a `network = "pki"` operation: the default OCSP
/// responder and the default (Kalkan) TSA, GET and POST each. This is what the runs showed is
/// needed (signer OCSP and Kalkan TSA are GETs); it is NOT a claim about the desktop wiring
/// (`crates/openncalayer/src/plugins/manual.rs` on the integration tip grants POST only and
/// uses `InstanceLimits::default()`): when feat/mp7b-limits exposes one shared definition of
/// limits and endpoints, switch `PKI_ENDPOINTS`/`instance_limits()`/`resource_limits()` below
/// to it (the single place to change). The synthetic leaf names the same OCSP responder.
pub const PKI_ENDPOINTS: [(HttpMethod, &str); 4] = [
    (HttpMethod::Get, DEFAULT_OCSP),
    (HttpMethod::Post, DEFAULT_OCSP),
    (HttpMethod::Get, DEFAULT_TSA),
    (HttpMethod::Post, DEFAULT_TSA),
];

/// The instance limits a manual window can run the ports with under `ResourceLimits::default()`:
/// a call reserves `8 * max_transfer + max_memory` of the operation's memory budget (1 GiB by
/// default), so `InstanceLimits::default()` (1 GiB of linear memory, 256 MiB transfers) can
/// never run there (`Processing(MemoryLimit)`, observed). The transfer size holds a 16 MiB
/// document as base64 plus the request around it.
pub fn instance_limits() -> InstanceLimits {
    InstanceLimits {
        max_memory: 128 << 20,
        max_transfer: 16 << 20,
        ..InstanceLimits::default()
    }
}

/// The resource limits of a manual window that can sign XML: a Kalkan XML signature reserves
/// about 61 MiB of the operation's METADATA budget (observed), plus `max_transfer` for the
/// call itself, and the default budget is 64 MiB, so with `ResourceLimits::default()` an XML
/// signature fails after the key use (`AfterKeyUse(MetadataLimit)`, key applied) for any
/// transfer size above about 1 MiB.
pub fn resource_limits() -> ResourceLimits {
    ResourceLimits {
        metadata_bytes: 256 << 20,
        ..ResourceLimits::default()
    }
}

/// The local operator of the manual window.
pub fn manual() -> CallerContext {
    CallerContext::LocalOperator("manual".to_owned())
}

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}

/// The workspace root.
pub fn root() -> PathBuf {
    oncl_testkit::workspace_root()
}

/// The directory of the built port modules: `ONCL_PLUGIN_WASM_DIR` (what `cargo xtask
/// plugin-ports-manual` sets), else the workspace of `plugins/` built here once per process
/// like `oncl-port-tests` do (`oncl_testkit::plugin::ports_built`: offline, `--locked`).
pub fn wasm_dir() -> PathBuf {
    match std::env::var_os("ONCL_PLUGIN_WASM_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => oncl_testkit::plugin::ports_built().to_path_buf(),
    }
}

/// The built module of the port `short` (`plugins/<short>`).
///
/// # Panics
///
/// If it is not built: the message says how.
pub fn wasm_of(short: &str) -> Vec<u8> {
    let path = wasm_dir().join(format!("oncl_port_{}.wasm", short.replace('-', "_")));
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}): see docs/dev/plugins-manual-tests.md (ONCL_PLUGIN_WASM_DIR must name the directory of the built oncl_port_*.wasm)",
            path.display()
        )
    })
}

/// The text of `plugins/<short>/plugin.toml`.
pub fn manifest_text(short: &str) -> String {
    let path = root().join("plugins").join(short).join("plugin.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A transport that logs `METHOD url` of every request, then routes it.
pub struct Logged {
    routes: RouteTransport,
    log: Mutex<Vec<String>>,
}
impl HttpTransport for Logged {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let method = match request.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        let reply = self.routes.send(request);
        let status = match &reply {
            Ok(reply) if reply.status == 200 => "200".to_owned(),
            Ok(reply) => format!("{} {}", reply.status, String::from_utf8_lossy(&reply.body)),
            Err(e) => format!("{e:?}"),
        };
        self.log
            .lock()
            .unwrap()
            .push(format!("{method} {} -> {status}", request.url));
        reply
    }
}

/// A synthetic user key under a throwaway root, with the mock PKI around it.
pub struct World {
    pub selector: KeySelector,
    pub alias: String,
    pub cert: Certificate,
    pub validation: oncl_core::ValidationServices,
    pub transport: Arc<Logged>,
    /// Where the signer's validation and the plugin's PKI requests are allowed to go.
    pub network: NetworkPolicy,
}

fn without(spec: &mut TestCertSpec, oids: &[&str]) {
    spec.extensions
        .retain(|e| !oids.contains(&e.extn_id.to_string().as_str()));
}

/// The AIA extension naming the OCSP responder `url`.
fn aia(url: &str) -> x509_cert::ext::Extension {
    use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax, name::GeneralName};
    let syntax = AuthorityInfoAccessSyntax(vec![AccessDescription {
        access_method: "1.3.6.1.5.5.7.48.1".parse().unwrap(),
        access_location: GeneralName::UniformResourceIdentifier(url.to_owned().try_into().unwrap()),
    }]);
    x509_cert::ext::Extension {
        extn_id: "1.3.6.1.5.5.7.1.1".parse().unwrap(),
        critical: false,
        extn_value: der::asn1::OctetString::new(syntax.to_der().unwrap()).unwrap(),
    }
}

/// The fixture key `name`, its certificate reissued by a throwaway root that shares the key
/// algorithm, with `AIA = OCSP at DEFAULT_OCSP` and no CDP; mock OCSP and TSA responders
/// signed under the same root answer at the NCA's default addresses.
pub fn world(name: &str) -> World {
    let leaf = crypto::raw(name);
    let mut root = crypto::raw("root-gost2015.key");
    root.key = leaf.key.clone();
    let mut root_spec = TestCertSpec::from_cert(&root.cert);
    without(&mut root_spec, &["2.5.29.14", "2.5.29.35"]);
    root_spec.public_key = root.key.public_key().to_spki();
    root.cert = issue_cert(&root, root_spec);
    // The user's certificate.
    let mut spec = TestCertSpec::from_cert(&leaf.cert);
    without(
        &mut spec,
        &["2.5.29.14", "2.5.29.35", "1.3.6.1.5.5.7.1.1", "2.5.29.31"],
    );
    spec.extensions.push(aia(DEFAULT_OCSP));
    let cert = issue_cert(&root, spec);
    let container = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: leaf.alias.clone(),
            pkcs8_der: leaf.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(cert.to_der().unwrap()),
        }],
        &[],
        crypto::PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x71),
    )
    .unwrap();
    // The responders: their fixture keys under the same root.
    let under_root = |fixture: &str| {
        let mut entry = crypto::raw(fixture);
        let mut spec = TestCertSpec::from_cert(&entry.cert);
        without(&mut spec, &["2.5.29.35"]);
        entry.cert = issue_cert(&root, spec);
        entry
    };
    // The TSA signs with the user's algorithm (Kalkan's default profile asks for the policy
    // of its key type): the fixture's certificate with the root's key.
    let mut tsa_entry = under_root("tsa-gost2015");
    tsa_entry.key = root.key.clone();
    let mut tsa_spec = TestCertSpec::from_cert(&tsa_entry.cert);
    tsa_spec.public_key = root.key.public_key().to_spki();
    tsa_entry.cert = issue_cert(&root, tsa_spec);
    let ocsp: Arc<dyn HttpTransport> =
        Arc::new(MockOcsp::new(under_root("ocsp-gost2015")).with_now(NOW));
    let tsa: Arc<dyn HttpTransport> = Arc::new(MockTsa::new(tsa_entry).with_gen_time(NOW));
    let transport = Arc::new(Logged {
        routes: RouteTransport::new(vec![
            (DEFAULT_OCSP.to_owned(), ocsp),
            (DEFAULT_TSA.to_owned(), tsa),
        ]),
        log: Mutex::new(Vec::new()),
    });
    let network = NetworkPolicy::only_endpoints([DEFAULT_OCSP, DEFAULT_TSA]).unwrap();
    let validation = oncl_core::ValidationServices::new(
        CaSet::new(vec![root.cert]),
        vec![],
        transport.clone(),
        network.clone(),
        Arc::new(|| NOW),
    );
    World {
        selector: KeySelector::inline(container, None),
        alias: leaf.alias,
        cert,
        validation,
        transport,
        network,
    }
}

/// An edit of the manifest text.
pub type Tamper = Box<dyn Fn(&str) -> String>;

/// What to vary in a run.
#[derive(Default)]
pub struct RunOptions {
    /// Edits the manifest text before it is parsed: a TAMPERED declaration.
    pub tamper: Option<Tamper>,
    /// The key fixture; `RSA` by default.
    pub key: Option<&'static str>,
}

impl RunOptions {
    /// A TAMPERED declaration: `from` -> `to` once, inside the section of the operation
    /// `operation` (from its `name = "..."` to the next `[[operations]]`).
    pub fn tampered(operation: &'static str, from: &'static str, to: &'static str) -> Self {
        RunOptions {
            tamper: Some(Box::new(move |text| {
                let start = text
                    .find(&format!("name = \"{operation}\"\n"))
                    .unwrap_or_else(|| panic!("no operation {operation}"));
                let end = text[start..]
                    .find("\n[[operations]]")
                    .map_or(text.len(), |n| start + n);
                let at = start
                    + text[start..end]
                        .find(from)
                        .unwrap_or_else(|| panic!("{operation} has no {from:?}"));
                format!("{}{}{}", &text[..at], to, &text[at + from.len()..])
            })),
            key: None,
        }
    }
}

/// Everything a run produced.
pub struct PortRun {
    pub call: ApprovedCall,
    pub summary: ConsentSummary,
    /// The exact request the host built from the template.
    pub request: String,
    pub cert: Certificate,
    /// Key applications the guard counted.
    pub applications: usize,
    /// `GET url` / `POST url` of the PKI requests made, in order.
    pub http_log: Vec<String>,
}

impl PortRun {
    /// The plugin's reply text.
    pub fn reply(&self) -> &str {
        self.call.response().unwrap_or_else(|| {
            panic!("the call has no reply: {:?}", self.call);
        })
    }
}

/// [`run_port_operation`] that returns the refusal of `plugin_prepare` instead of panicking.
pub fn try_run_port_operation(
    port: &str,
    operation: &str,
    params: &[(&str, PluginParam<'_>)],
    options: &RunOptions,
) -> Result<PortRun, PluginPrepareError> {
    let key_name = options.key.unwrap_or(RSA);
    let world = world(key_name);
    let mut text = manifest_text(port);
    if let Some(tamper) = &options.tamper {
        let edited = tamper(&text);
        assert_ne!(edited, text, "the tamper changed nothing");
        text = edited;
    }
    let manifest = Manifest::from_toml(&text).unwrap_or_else(|e| panic!("{port}: {e}"));
    let id = manifest.id.clone();
    let wasm = wasm_of(port);
    let hash = loose_package_hash(text.as_bytes(), &wasm);
    let pki = manifest
        .operations()
        .iter()
        .find(|o| o.name() == operation)
        .is_some_and(|o| matches!(o.uses().network(), oncl_plugin::operations::Network::Pki));
    let endpoints: &[(HttpMethod, &str)] = if pki { &PKI_ENDPOINTS } else { &[] };
    let mut plugins = PluginRegistry::new();
    plugins
        .install(manifest, hash, &wasm, instance_limits(), Vec::new())
        .unwrap_or_else(|e| panic!("{port}: installing: {e:?}"));
    plugins
        .allow_declared_with_pki(
            &id,
            operation,
            manual(),
            endpoints.iter().copied(),
            &NCA_PKI_HOSTS,
        )
        .unwrap_or_else(|e| panic!("{port}.{operation}: not offered: {e:?}"));
    let guard = Arc::new(PluginConsentGuard::new());
    // XML signing spools through the temporary store: the host must provide one.
    let spool = tempfile::tempdir().unwrap();
    let services = EngineServices::hash_only(resource_limits())
        .with_temporary_store(oncl_pki::io::TemporaryStore::new(spool.path()).unwrap())
        .with_validation(world.validation.clone())
        .with_plugins(plugins)
        .with_plugin_keys(Arc::new(KeySources::new()), guard.clone());
    let engine = Engine::new(services).unwrap();
    let operations = engine
        .plugin_operations(&id)
        .unwrap_or_else(|e| panic!("{port}: {e:?}"));
    let declared = operations
        .iter()
        .find(|o| o.name() == operation)
        .unwrap_or_else(|| panic!("{port}.{operation}: not declared"));
    let digest = declared.uses().keys().iter().any(|k| {
        matches!(
            k.profile(),
            oncl_plugin::operations::Profile::CmsEx(p)
                if p.content_form == oncl_plugin::operations::ContentForm::Digest
        )
    });
    let imports: Vec<Import> = declared.uses().imports().to_vec();
    let permission = PluginPermission::new(&id, operation, manual(), imports)
        .with_keys([world.selector.key_id()])
        .with_pki_endpoints(endpoints.iter().copied())
        .unwrap();
    let actions: &[Action] = if digest {
        &[Action::Sign, Action::SignDigest, Action::Hash]
    } else {
        &[Action::Sign, Action::Hash]
    };
    let grant = ExecutionGrant::new(actions.iter().copied())
        .with_keys([world.selector.key_id()])
        .with_plugins([permission]);
    let policy = OperationPolicy {
        allow_prehashed: digest,
        ..OperationPolicy::strict_online()
    };
    let mut ctx: OperationContext = engine.begin(grant, policy, Arc::new(Control)).unwrap();
    let binding =
        PluginKeyBinding::new(1, KeyRequest::new(&world.selector, Some(crypto::PASSWORD)))
            .with_public_metadata(&world.alias, &world.cert, &[]);
    let caller = manual();
    let call = ManualCall {
        plugin_id: &id,
        operation,
        params,
        key: &binding,
        caller: &caller,
    };
    let prepared = engine.plugin_prepare(&call, &mut ctx)?;
    let summary = prepared.summary().clone();
    // The user read the summary and confirmed it.
    let confirmation = UserConfirmation::after_user_confirmed(prepared.summary());
    let approval = prepared.approve(confirmation, None).unwrap();
    let request = engine
        .plugin_request(&id, operation, params)
        .unwrap_or_else(|e| panic!("{port}.{operation}: {e:?}"));
    let cache = Arc::new(oncl_plugin::manual::OcspCache::new());
    let transport: Arc<dyn HttpTransport> = world.transport.clone();
    let host = ManualHost {
        transport: &transport,
        network: &world.network,
        ocsp_cache: &cache,
    };
    let result = engine.plugin_call_approved(&call, approval, &host, &mut ctx);
    Ok(PortRun {
        call: result,
        summary,
        request,
        cert: world.cert.clone(),
        applications: guard.applications(),
        http_log: world.transport.log.lock().unwrap().clone(),
    })
}

/// Runs the declared operation `operation` of the port `port` as the manual window does.
///
/// # Panics
///
/// If the plugin cannot be installed or the operation is not offered or cannot be prepared.
pub fn run_port_operation(
    port: &str,
    operation: &str,
    params: &[(&str, PluginParam<'_>)],
    options: &RunOptions,
) -> PortRun {
    try_run_port_operation(port, operation, params, options)
        .unwrap_or_else(|e| panic!("{port}.{operation}: prepare refused: {e:?}"))
}

/// `Applied`, no refusal, and the reply: what every positive test asserts first.
pub fn assert_applied(run: &PortRun) {
    assert_eq!(run.call.applied(), AppliedState::Applied, "{:?}", run.call);
    assert!(run.call.refusals().is_empty(), "{:?}", run.call.refusals());
    assert_eq!(run.applications, 1, "the key is applied once");
}

/// The refusal a TAMPERED declaration must meet: `NotApplied`, before the key was used.
pub fn assert_refused_before_the_key(run: &PortRun) {
    assert_eq!(
        run.call.applied(),
        AppliedState::NotApplied,
        "{:?}",
        run.call
    );
    assert_eq!(run.applications, 0, "no key use");
    assert!(
        !run.call.refusals().is_empty() || run.call.error().is_some(),
        "{:?}",
        run.call
    );
}

/// The JSON of a port's reply.
pub fn reply_json(run: &PortRun) -> serde_json::Value {
    serde_json::from_str(run.reply())
        .unwrap_or_else(|e| panic!("the reply is not JSON ({e}): {}", run.reply()))
}

pub fn from_base64(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .unwrap_or_else(|e| panic!("not base64 ({e}): {text}"))
}

/// Independent oracles.
pub mod oracle {
    use super::*;
    use std::process::Command;

    /// OpenSSL: `ONCL_OPENSSL`, `openssl` on the path, Git for Windows' copy.
    pub fn openssl() -> String {
        let mut candidates: Vec<String> = Vec::new();
        if let Ok(explicit) = std::env::var("ONCL_OPENSSL") {
            candidates.push(explicit);
        }
        candidates.push("openssl".to_owned());
        if cfg!(windows) {
            for var in ["ProgramFiles", "ProgramW6432"] {
                if let Some(base) = std::env::var_os(var) {
                    candidates.push(
                        Path::new(&base)
                            .join("Git/usr/bin/openssl.exe")
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        candidates
            .into_iter()
            .find(|c| {
                Command::new(c)
                    .arg("version")
                    .output()
                    .is_ok_and(|o| o.status.success())
            })
            .expect("OpenSSL oracle unavailable: install OpenSSL or set ONCL_OPENSSL")
    }

    /// A Python with `lxml` and `cryptography`.
    pub fn python() -> String {
        let mut candidates: Vec<String> = Vec::new();
        if let Ok(explicit) = std::env::var("ONCL_PYHANKO_PYTHON") {
            candidates.push(explicit);
        }
        candidates.extend(["python3".to_owned(), "python".to_owned()]);
        candidates
            .into_iter()
            .find(|c| {
                Command::new(c)
                    .args(["-c", "import lxml.etree, cryptography"])
                    .output()
                    .is_ok_and(|o| o.status.success())
            })
            .expect("XML oracle unavailable: a Python with lxml and cryptography (set ONCL_PYHANKO_PYTHON)")
    }

    fn run(mut command: Command) -> std::process::Output {
        let name = format!("{command:?}");
        command
            .output()
            .unwrap_or_else(|e| panic!("cannot run {name}: {e}"))
    }

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// What a CMS check established.
    #[derive(Debug)]
    pub struct CmsFacts {
        pub signers: usize,
        pub sig_alg: oncl_pki::key::SigAlg,
        /// Whether the CMS carries a signature time-stamp token (an unsigned attribute).
        pub time_stamped: bool,
        /// Whether the content is in the CMS.
        pub attached: bool,
    }

    /// `cms` is a valid CMS signature by `cert` over `content`: by the repository's
    /// `oncl_pki::cms::verify` (and not over anything else) AND by `openssl cms -verify`
    /// (RSA keys; the chain is not checked by it: the signer's own certificate is). An
    /// attached CMS must carry exactly `content`.
    pub fn verify_cms(cms: &[u8], content: &[u8], cert: &Certificate, attached: bool) -> CmsFacts {
        let own = if attached {
            oncl_pki::cms::verify(cms, None)
        } else {
            oncl_pki::cms::verify(cms, Some(content))
        }
        .unwrap_or_else(|e| panic!("oncl_pki::cms::verify: {e:?}"));
        assert_eq!(own.len(), 1, "one signer");
        if !attached {
            assert!(
                oncl_pki::cms::verify(cms, Some(b"another content")).is_err(),
                "the signature must not verify over another content"
            );
        }
        let dir = scratch();
        let cms_path = dir.path().join("sig.cms");
        let content_path = dir.path().join("content.bin");
        let out_path = dir.path().join("out.bin");
        let cert_path = dir.path().join("signer.der");
        std::fs::write(&cms_path, cms).unwrap();
        std::fs::write(&content_path, content).unwrap();
        std::fs::write(&cert_path, cert.to_der().unwrap()).unwrap();
        let mut command = Command::new(openssl());
        command
            .args(["cms", "-verify", "-inform", "DER", "-binary", "-noverify"])
            .arg("-in")
            .arg(&cms_path)
            .arg("-out")
            .arg(&out_path);
        if !attached {
            command.arg("-content").arg(&content_path);
        }
        let output = run(command);
        assert!(
            output.status.success(),
            "openssl cms -verify: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if attached {
            assert_eq!(
                std::fs::read(&out_path).unwrap(),
                content,
                "attached content"
            );
        }
        // openssl must also refuse another content.
        if !attached {
            std::fs::write(&content_path, b"another content").unwrap();
            let mut command = Command::new(openssl());
            command
                .args(["cms", "-verify", "-inform", "DER", "-binary", "-noverify"])
                .arg("-in")
                .arg(&cms_path)
                .arg("-content")
                .arg(&content_path)
                .arg("-out")
                .arg(&out_path);
            assert!(
                !run(command).status.success(),
                "openssl accepted another content"
            );
        }
        // The signer certificate in the CMS is the key's.
        let der = cert.to_der().unwrap();
        assert!(
            cms.windows(der.len()).any(|w| w == der.as_slice()),
            "the CMS carries the signer's certificate"
        );
        let report = oncl_pki::cms::report(
            cms,
            if attached { None } else { Some(content) },
            &Default::default(),
        )
        .unwrap_or_else(|e| panic!("cms report: {e:?}"));
        CmsFacts {
            signers: own.len(),
            sig_alg: own[0].sig_alg,
            time_stamped: report.signers.iter().any(|s| s.tsp.is_some()),
            attached,
        }
    }

    /// `signature` is an RSA PKCS#1 v1.5 SHA-256 signature by the key of `cert` over `data`:
    /// by the certificate's public key in the repository AND by `openssl pkeyutl -verify`.
    pub fn verify_raw_rsa(cert: &Certificate, data: &[u8], signature: &[u8]) {
        let key =
            oncl_pki::key::PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
                .expect("the certificate's key");
        key.verify(oncl_pki::key::SigAlg::RsaSha256, data, signature)
            .expect("the repository verifies the raw signature");
        assert!(
            key.verify(oncl_pki::key::SigAlg::RsaSha256, b"another data", signature)
                .is_err()
        );
        let dir = scratch();
        let cert_path = dir.path().join("cert.der");
        let pub_path = dir.path().join("pub.pem");
        let data_path = dir.path().join("data.bin");
        let sig_path = dir.path().join("sig.bin");
        std::fs::write(&cert_path, cert.to_der().unwrap()).unwrap();
        std::fs::write(&data_path, data).unwrap();
        std::fs::write(&sig_path, signature).unwrap();
        let mut command = Command::new(openssl());
        command
            .args(["x509", "-inform", "DER", "-pubkey", "-noout"])
            .arg("-in")
            .arg(&cert_path);
        let output = run(command);
        assert!(output.status.success(), "openssl x509");
        std::fs::write(&pub_path, output.stdout).unwrap();
        let mut command = Command::new(openssl());
        command
            .args([
                "pkeyutl", "-verify", "-pubin", "-rawin", "-digest", "sha256",
            ])
            .arg("-inkey")
            .arg(&pub_path)
            .arg("-in")
            .arg(&data_path)
            .arg("-sigfile")
            .arg(&sig_path);
        let output = run(command);
        assert!(
            output.status.success(),
            "openssl pkeyutl -verify: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// What the XML oracle established, as `xmldsig_verify.py` prints it.
    #[derive(Debug)]
    pub struct XmlFacts {
        pub json: serde_json::Value,
    }
    impl XmlFacts {
        /// The `local name` of every referenced element, in signature order.
        pub fn referenced_nodes(&self) -> Vec<String> {
            self.json["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|s| s["references"].as_array().unwrap().iter())
                .map(|r| r["node"].as_str().unwrap_or("").to_owned())
                .collect()
        }
    }

    fn run_xml_oracle(signed: &[u8], cert: &Certificate) -> (bool, String) {
        let dir = scratch();
        let xml_path = dir.path().join("signed.xml");
        let cert_path = dir.path().join("signer.der");
        std::fs::write(&xml_path, signed).unwrap();
        std::fs::write(&cert_path, cert.to_der().unwrap()).unwrap();
        let script = root().join("crates/oncl-core/tests/support/oracle/xmldsig_verify.py");
        let mut command = Command::new(python());
        command.arg(script).arg(&xml_path).arg(&cert_path);
        let output = run(command);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.success(), text)
    }

    /// `signed` has exactly `signatures` XML signatures, all valid for the key of `cert`:
    /// by `oncl_xml::verify` AND by `xmldsig_verify.py` (RSA keys).
    pub fn verify_xml(signed: &[u8], cert: &Certificate, signatures: usize) -> XmlFacts {
        let own = oncl_xml::verify(signed).unwrap_or_else(|e| panic!("oncl_xml::verify: {e:?}"));
        assert_eq!(own.len(), signatures, "oncl_xml::verify");
        let (ok, text) = run_xml_oracle(signed, cert);
        assert!(ok, "xmldsig_verify.py failed: {text}");
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["signatures"].as_array().unwrap().len(), signatures);
        XmlFacts { json }
    }

    /// The oracle REFUSES `document` (a signed document that was changed after signing): the
    /// check that the oracle can say no.
    pub fn assert_xml_rejected(document: &[u8], cert: &Certificate) {
        let (ok, text) = run_xml_oracle(document, cert);
        assert!(!ok, "the oracle accepted a changed document: {text}");
    }
}

/// `Certificate` from DER (for a test that has only bytes).
pub fn certificate(der: &[u8]) -> Certificate {
    Certificate::from_der(der).unwrap()
}
