//! Invocation-scoped host: no browser session, prompter, key material, UI or dialog turn.
//! The backend is borrowed for the entire real WASM execution, never stored in an Arc.
use crate::host::{AbiState, Phase, trap};
use crate::runtime::{Compiled, Guest, LoadError, PluginError};
use oncl_pdk::abi::{self, Import};
use wasmi::{Memory, StoreLimits, TypedFunc};

/// Trusted caller identity supplied by the embedding host, never deserialized from guest input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallerContext {
    Browser { origin: String },
    LocalOperator(String),
    ServiceClient(String),
}
impl CallerContext {
    pub fn browser_origin(&self) -> Option<&str> {
        match self {
            Self::Browser { origin } => Some(origin),
            _ => None,
        }
    }
}
/// Already intersected invocation permissions. Compilation additionally enforces the manifest.
pub struct HeadlessBindings<'a> {
    pub caller: &'a CallerContext,
    pub imports: &'a [Import],
}
/// Backend failures retain their original typed host error in the embedding adapter.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeadlessError {
    #[error("the capability is not authorized for this invocation")]
    Denied,
    #[error("the capability requires interactive host input")]
    InteractionRequired,
    #[error("the scoped capability backend failed")]
    Backend,
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error(transparent)]
    Plugin(#[from] PluginError),
}
/// Encoded ABI arguments/results, with a concrete normalized Import at every invocation.
/// Implementations must retain typed errors and original operation control/resources.
pub trait CapabilityBackend {
    fn checkpoint(&mut self) -> Result<(), HeadlessError>;
    fn invoke(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, HeadlessError>;
}
struct HeadlessState<'a, 'b> {
    limits: StoreLimits,
    max_transfer: usize,
    phase: Phase,
    guest: Option<(Memory, TypedFunc<i32, i32>)>,
    bindings: HeadlessBindings<'b>,
    backend: &'a mut dyn CapabilityBackend,
    failure: Option<HeadlessError>,
    fuel: crate::host::FuelBank,
}
impl AbiState for HeadlessState<'_, '_> {
    fn limits(&mut self) -> &mut StoreLimits {
        &mut self.limits
    }
    fn phase(&self) -> Phase {
        self.phase
    }
    fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }
    fn guest(&self) -> Option<(Memory, TypedFunc<i32, i32>)> {
        self.guest
    }
    fn attach(&mut self, memory: Memory, alloc: TypedFunc<i32, i32>) {
        self.guest = Some((memory, alloc));
    }
    fn max_transfer(&self) -> usize {
        self.max_transfer
    }
    fn fuel_bank(&mut self) -> Option<&mut crate::host::FuelBank> {
        Some(&mut self.fuel)
    }
    fn checkpoint(&mut self) -> Result<(), wasmi::Error> {
        self.backend.checkpoint().map_err(|error| {
            self.failure = Some(error);
            trap("headless operation interrupted")
        })
    }
    fn dispatch(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, wasmi::Error> {
        let result = if !self.bindings.imports.contains(&import) {
            Err(HeadlessError::Denied)
        } else if requires_interaction(import) {
            // Before any interactive dispatch, DialogTurn or global UI lock.
            Err(HeadlessError::InteractionRequired)
        } else {
            self.backend
                .checkpoint()
                .and_then(|()| self.backend.invoke(import, args))
        };
        result.map_err(|error| {
            self.failure = Some(error);
            trap("headless capability refused")
        })
    }
}
/// Mandatory UI capabilities cannot be converted to auto-consent, cancellation or empty answers.
fn requires_interaction(import: Import) -> bool {
    matches!(
        import,
        Import::DialogMessage
            | Import::DialogConfirm
            | Import::DialogPassword
            | Import::DialogChoice
            | Import::DialogReader
            | Import::DialogCsr
            | Import::DialogImport
            | Import::KeysChoose
            | Import::KeysSelect
            | Import::KeysFlowOpen
            | Import::KeysFlowPick
            | Import::FileOpen
            | Import::FileSave
            | Import::FileChoose
            | Import::FileChooseKind
            | Import::FileOpenEx
            | Import::CoreOpenWindow
            | Import::KeystoreNewKey
            | Import::KeystoreInstallCert
            | Import::KeystoreChangePassword
    )
}
impl Compiled {
    /// Executes the same metered ABI runner as interactive instances, with only borrowed
    /// invocation authority. Nothing unlocked or guest-owned survives this call.
    pub fn call_headless(
        &self,
        backend: &mut dyn CapabilityBackend,
        bindings: HeadlessBindings<'_>,
        request: &str,
    ) -> Result<String, HeadlessError> {
        if request.len() > self.limits().max_transfer {
            return Err(PluginError::TooLarge.into());
        }
        backend.checkpoint()?;
        let input =
            crate::runtime::encode_input(request, bindings.caller.browser_origin(), "ru", None);
        let state = HeadlessState {
            limits: self.store_limits(),
            max_transfer: self.limits().max_transfer,
            phase: Phase::Idle,
            guest: None,
            bindings,
            backend,
            failure: None,
            fuel: Default::default(),
        };
        let mut guest = Guest::new(self, state)?;
        let result = guest.invoke(&input);
        if let Some(error) = guest.store.data_mut().failure.take() {
            return Err(error);
        }
        let response = result?.response;
        guest.store.data_mut().backend.checkpoint()?;
        Ok(response)
    }
}

/// A fixed host-owned plugin namespace; no guest path is ever used as its filename.
#[derive(Debug)]
pub struct BoundSettings {
    path: std::path::PathBuf,
}
impl BoundSettings {
    pub fn new(directory: std::path::PathBuf, plugin_id: &str) -> abi::HostResult<Self> {
        if !crate::is_symbolic_name(plugin_id) {
            return Err(abi::HostError::new(
                abi::ErrorCode::Invalid,
                "invalid settings namespace",
            ));
        }
        Ok(Self {
            path: directory.join(format!("{plugin_id}.json")),
        })
    }
    pub fn get(&self) -> abi::HostResult<std::collections::BTreeMap<String, String>> {
        crate::caps::settings_read(&self.path)
    }
    pub fn put(&self, settings: std::collections::BTreeMap<String, String>) -> abi::HostResult<()> {
        crate::caps::settings_write(&self.path, settings)
    }
}

/// Pure existing ABI implementations; authority and resource admission are the
/// invoking host's responsibility, exactly as for a borrowed CapabilityBackend.
pub fn public_capability(import: Import, args: &[u8]) -> Option<Vec<u8>> {
    use crate::{caps, host};
    Some(match import {
        Import::Random => host::run(args, host::random),
        Import::CertInfo => host::run(args, host::cert_info),
        Import::CertDetails => host::run(args, caps::cert_details),
        Import::XmlVerify => host::run(args, caps::xml_verify),
        Import::Platform => host::run(args, |()| Ok(host::platform())),
        Import::LocalTime => host::run(args, |a: abi::LocalTimeArgs| {
            Ok(abi::LocalTime {
                offset_seconds: host::local_offset_seconds(a.unix_ms),
            })
        }),
        _ => return None,
    })
}

/// Uses the same URI/origin/header rules as the interactive capabilities, without
/// granting transport authority or looking up any browser session.
pub struct PreparedHttp<'a> {
    url: url::Url,
    args: &'a abi::HttpExArgs,
    headers: Vec<(&'a str, &'a str)>,
    timeout: std::time::Duration,
}
impl PreparedHttp<'_> {
    pub fn url(&self) -> &str {
        self.url.as_str()
    }
    pub fn request(&self, max_len: u64) -> oncl_pki::http::HttpRequest<'_> {
        use oncl_pki::http::{CONNECT_TIMEOUT, GetOptions, HttpMethod, HttpRequest};
        HttpRequest {
            method: match self.args.method {
                abi::Method::Get => HttpMethod::Get,
                abi::Method::Post => HttpMethod::Post,
            },
            url: self.url.as_str(),
            headers: &self.headers,
            content_type: self.args.content_type.as_deref(),
            body: &self.args.body,
            opts: GetOptions {
                timeout: self.timeout,
                connect_timeout: CONNECT_TIMEOUT.min(self.timeout),
                max_len,
                https_only: self.url.scheme() == "https",
                redirects: false,
            },
        }
    }
}
pub fn prepare_http<'a>(
    import: Import,
    capabilities: &crate::Capabilities,
    caller: &CallerContext,
    args: &'a abi::HttpExArgs,
) -> abi::HostResult<PreparedHttp<'a>> {
    use crate::caps;
    let invalid = |text| abi::HostError::new(abi::ErrorCode::Invalid, text);
    let headers = caps::checked_headers(args)?;
    if args
        .content_type
        .as_deref()
        .is_some_and(caps::has_line_break)
        || (args.method == abi::Method::Get
            && (!args.body.is_empty() || args.content_type.is_some()))
    {
        return Err(invalid("invalid HTTP body or content type"));
    }
    if args.body.len() as u64 > crate::MAX_HTTP_BODY {
        return Err(abi::HostError::new(
            abi::ErrorCode::Limit,
            "HTTP body exceeds limit",
        ));
    }
    let timeout = args.timeout_ms.map_or(crate::HTTP_TIMEOUT, |ms| {
        std::time::Duration::from_millis(ms.into())
    });
    if timeout.is_zero() || timeout > crate::HTTP_TIMEOUT {
        return Err(invalid("invalid HTTP timeout"));
    }
    let url = if import == Import::HttpRequest {
        caps::allowed_url(&capabilities.http, &args.url)?
    } else {
        caps::allowed_ex_url(
            capabilities,
            caller.browser_origin(),
            &args.url,
            args.relative_to_origin,
        )?
    };
    Ok(PreparedHttp {
        url,
        args,
        headers,
        timeout,
    })
}

/// The existing request cap, shared by guest transport and invocation-bound PKI.
#[derive(Clone, Default)]
pub struct RequestBudget(crate::caps::RequestBudget);
impl RequestBudget {
    pub fn take(&self) -> abi::HostResult<()> {
        self.0.take()
    }
}

/// Borrowed explicit PKI services. URL authority is separate from guest HTTP,
/// and its transport retains the embedding host's pins, scope and request cap.
pub struct PkiServices<'a> {
    pub cas: &'a oncl_pki::pkix::CaSet,
    pub clock: &'a (dyn Fn() -> time::OffsetDateTime + Send + Sync),
    pub tsa: &'a oncl_pki::tsp::TsaSpec,
    pub http: &'a dyn oncl_pki::http::HttpTransport,
    pub authorize: &'a (dyn Fn(&str) -> abi::HostResult<()> + Send + Sync),
}
impl crate::caps::CryptoHost for PkiServices<'_> {
    fn cas(&self) -> &oncl_pki::pkix::CaSet {
        self.cas
    }
    fn now(&self) -> time::OffsetDateTime {
        (self.clock)()
    }
    fn basics_tsa(&self) -> oncl_pki::tsp::TsaSpec {
        self.tsa.clone()
    }
    fn check_url(&self, url: &str) -> abi::HostResult<()> {
        (self.authorize)(url)
    }
    fn pki_http(&self) -> crate::caps::PkiHttp<'_> {
        crate::caps::PkiHttp::bound(self.http, self.authorize)
    }
}
impl PkiServices<'_> {
    pub fn capability(&self, import: Import, args: &[u8]) -> Option<Vec<u8>> {
        use crate::{caps, host};
        Some(match import {
            Import::CaList => host::run(args, |()| Ok(caps::ca_list(self))),
            Import::CaIssuer => host::run(args, |a| caps::ca_issuer(self, a)),
            Import::PkixPath => host::run(args, |a| caps::pkix_path(self, a)),
            Import::OcspFetch => host::run(args, |a| caps::ocsp_fetch(self, a)),
            Import::CrlFetch => host::run(args, |a| caps::crl_fetch(self, a)),
            Import::TspRequest => host::run(args, |a| caps::tsp_request(self, a)),
            Import::TspStamp => host::run(args, |a| caps::tsp_stamp(self, a)),
            _ => return None,
        })
    }
    pub fn resolve_tsa(
        &self,
        choice: &abi::TsaChoice,
    ) -> abi::HostResult<Result<oncl_pki::tsp::TsaSpec, abi::NetFailure>> {
        crate::caps::tsa_spec(self, choice)
    }
    pub fn timestamp(
        &self,
        cms: &[u8],
        spec: &oncl_pki::tsp::TsaSpec,
    ) -> Result<Vec<u8>, abi::NetFailure> {
        oncl_pki::tsp::stamp(
            cms,
            oncl_pki::tsp::SignerSel::Last,
            spec,
            oncl_pki::tsp::StampMode::Replace,
            oncl_pki::tsp::TokenForm::Token,
            &crate::caps::PkiHttp::of(self),
        )
        .map_err(|error| crate::caps::tsp_failure(spec, &error))
    }
}
pub fn cms_spec<'a>(
    args: &'a abi::SignCmsExArgs,
    now: time::OffsetDateTime,
) -> abi::HostResult<oncl_pki::cms::SignSpec<'a>> {
    let content = match &args.content {
        abi::CmsContent::Data(data) => oncl_pki::cms::Content::Data(data),
        abi::CmsContent::Digest(data) => oncl_pki::cms::Content::Digest(data),
    };
    crate::caps::cms_spec(args, content, None, || now)
}
pub fn format_cms(der: Vec<u8>, output: abi::CmsOutput) -> abi::Bytes {
    crate::caps::cms_output(der, output)
}

impl PkiServices<'_> {
    /// Public metadata only: authoritative checks are supplied by Core's scoped
    /// report, not promoted from this legacy-format projection.
    pub fn cms_metadata(
        &self,
        cms: &[u8],
        detached: Option<&[u8]>,
    ) -> abi::HostResult<abi::VerifyReport> {
        let report = oncl_pki::cms::report(
            cms,
            detached,
            &oncl_pki::cms::ReportSpec {
                at: oncl_pki::cms::VerifyAt::Now,
                chain: oncl_pki::cms::ChainPolicy::Skip,
                trust: self.cas,
                revocation: oncl_pki::cms::Revocation::None,
                first_signer_only: false,
                require_key_usage: oncl_pki::info::KeyUsageBits::default(),
            },
            self.http,
            (self.clock)(),
        )
        .map_err(|error| abi::HostError::new(abi::ErrorCode::Invalid, error.to_string()))?;
        Ok(crate::caps::project_report(report))
    }
}

pub fn shared_capability(
    shared: &crate::SharedState,
    now_ms: i128,
    import: Import,
    args: &[u8],
) -> Option<Vec<u8>> {
    Some(match import {
        Import::SharedGet => {
            crate::host::run(args, |a| crate::caps::shared_get_from(shared, a, now_ms))
        }
        Import::SharedPut => {
            crate::host::run(args, |a| crate::caps::shared_put_into(shared, a, now_ms))
        }
        _ => return None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn compiled(body: &str, imports: &str, data: &str) -> Compiled {
        let manifest = crate::Manifest::from_toml(
            r#"id="test.headless"
version="1.0.0"
min_core="0.1.0"
modules=["test.headless"]
name.ru="test"
name.kk="test"
name.en="test"
[capabilities]
dialogs=true
"#,
        )
        .unwrap();
        let wasm = wat::parse_str(format!(
            r#"(module {imports}
            (memory (export "memory") 1)
            (func (export "oncl_abi_version") (result i32) i32.const 1)
            (func (export "oncl_alloc") (param i32) (result i32) i32.const 4096)
            (func (export "oncl_free") (param i32 i32))
            {data}
            (func (export "oncl_process") (param i32 i32) (result i64) {body}))"#
        ))
        .unwrap();
        crate::Engine::new()
            .compile(&manifest, &wasm)
            .unwrap()
            .with_limits(crate::InstanceLimits {
                max_memory: 65536,
                fuel: 500_000,
                max_transfer: 4096,
                ..crate::InstanceLimits::default()
            })
    }
    struct Cancel {
        checks: usize,
    }
    impl CapabilityBackend for Cancel {
        fn checkpoint(&mut self) -> Result<(), HeadlessError> {
            self.checks += 1;
            if self.checks >= 2 {
                Err(HeadlessError::Backend)
            } else {
                Ok(())
            }
        }
        fn invoke(&mut self, _: Import, _: &[u8]) -> Result<Vec<u8>, HeadlessError> {
            panic!("no capability was imported")
        }
    }
    #[test]
    fn guest_loop_observes_scoped_control_before_exhausting_total_fuel() {
        let compiled = compiled("(loop $spin br $spin) unreachable", "", "");
        let mut backend = Cancel { checks: 0 };
        let caller = CallerContext::LocalOperator("test".into());
        assert_eq!(
            compiled.call_headless(
                &mut backend,
                HeadlessBindings {
                    caller: &caller,
                    imports: &[]
                },
                "{}"
            ),
            Err(HeadlessError::Backend)
        );
        assert_eq!(backend.checks, 2);
    }
    #[test]
    fn mandatory_prompt_never_waits_for_the_global_dialog_turn() {
        let args = abi::encode(&abi::ConfirmArgs {
            text: "mandatory".into(),
        });
        let data = format!(
            "(data (i32.const 128) \"{}\")",
            args.iter()
                .map(|b| format!("\\{b:02x}"))
                .collect::<String>()
        );
        let compiled = compiled(
            &format!(
                "i32.const 128 i32.const {} call $prompt drop unreachable",
                args.len()
            ),
            "(import \"oncl\" \"dialog_confirm\" (func $prompt (param i32 i32) (result i64)))",
            &data,
        );
        let turn = oncl_flows::lock_dialog_flow();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut backend = Cancel { checks: 0 };
            let caller = CallerContext::LocalOperator("test".into());
            tx.send(compiled.call_headless(
                &mut backend,
                HeadlessBindings {
                    caller: &caller,
                    imports: &[Import::DialogConfirm],
                },
                "{}",
            ))
            .unwrap();
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(2));
        drop(turn);
        thread.join().unwrap();
        assert_eq!(result.unwrap(), Err(HeadlessError::InteractionRequired));
    }
}
