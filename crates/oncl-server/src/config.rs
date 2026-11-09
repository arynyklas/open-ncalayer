use crate::{
    auth::{TokenRecord, TokenVerifier},
    executor::ExecutorConfig,
    telemetry::TelemetryConfig,
};
use oncl_core::Action;
use oncl_pki::{private_fs::PrivateDirectory, resource::ResourceLimits};
use serde::Deserialize;
use std::{
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

/// Only the IPv4-mapped representation aliases IPv4. Compatible/native IPv6
/// addresses remain distinct; headers never participate in peer normalization.
pub(crate) fn normalized_peer(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Exposure {
    #[default]
    Loopback,
    Tls {
        certificate: PathBuf,
        private_key: SecretMount,
    },
    TrustedProxy {
        peers: Vec<IpAddr>,
    },
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMount {
    pub directory: PathBuf,
    pub name: String,
}
impl SecretMount {
    pub fn read(&self, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        let directory = PrivateDirectory::open(&self.directory)?;
        let mut file = directory.open_file(&self.name)?;
        if file.metadata()?.len() > limit as u64 {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub fn text(&self) -> io::Result<Zeroizing<String>> {
        let bytes = self.read(4096)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        Ok(Zeroizing::new(
            text.trim_end_matches(['\r', '\n']).to_owned(),
        ))
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Hash,
    Sign,
    SignDigest,
    Verify,
    Extract,
    Extend,
    Inspect,
    Stamp,
    VerifyStamp,
    /// Right to submit `POST /v1/batch`; not an SDK action. Each item still needs its
    /// own action/key permission.
    Batch,
}
impl Permission {
    fn action(self) -> Option<Action> {
        Some(match self {
            Self::Hash => Action::Hash,
            Self::Sign => Action::Sign,
            Self::SignDigest => Action::SignDigest,
            Self::Verify => Action::Verify,
            Self::Extract => Action::Extract,
            Self::Extend => Action::Extend,
            Self::Inspect => Action::Inspect,
            Self::Stamp => Action::Stamp,
            Self::VerifyStamp => Action::VerifyStamp,
            Self::Batch => return None,
        })
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    pub id: String,
    pub verifier: String,
    pub actions: Vec<Permission>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub inline_pkcs12: bool,
    /// Exact container aliases this token may inspect (public metadata only).
    #[serde(default)]
    pub metadata_aliases: Vec<String>,
}
impl TokenConfig {
    pub fn record(&self) -> io::Result<TokenRecord> {
        Ok(TokenRecord::new(
            &self.id,
            TokenVerifier::parse(&self.verifier)?,
            self.actions.iter().filter_map(|p| p.action()).collect(),
            self.keys.clone(),
        )?
        .with_batch(self.actions.iter().any(|p| matches!(p, Permission::Batch)))
        .with_inline_pkcs12(self.inline_pkcs12)
        .with_metadata_aliases(self.metadata_aliases.clone()))
    }
}
#[derive(Clone, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyConfig {
    File {
        name: String,
        path: PathBuf,
        alias: Option<String>,
        secret: SecretMount,
    },
    Token {
        name: String,
        reader: String,
        kind: String,
        alias: String,
        secret: SecretMount,
    },
}
/// An operator-installed plugin: code availability only. Authority is the
/// separate per-token `permissions` below, never the installation itself.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub id: String,
    /// `plugin.toml` text file (at most 64 KiB).
    pub manifest: PathBuf,
    /// The module bytes (at most 16 MiB).
    pub wasm: PathBuf,
    #[serde(default = "default_plugin_memory")]
    pub max_memory: usize,
    #[serde(default = "default_plugin_transfer")]
    pub max_transfer: usize,
    #[serde(default)]
    pub permissions: Vec<PluginGrant>,
}
fn default_plugin_memory() -> usize {
    1 << 20
}
fn default_plugin_transfer() -> usize {
    1 << 18
}
/// One exact (token, operation) grant: the allowed host imports and operator
/// key names. The caller identity is the token, never a request field/Origin.
///
/// For a plugin operation that declares its key use (`[[operations]]`), the server cannot
/// bind the signed content to a document (the arguments are free JSON of the client), so a
/// key may be used only if the operator accepted that explicitly with `plugin_bytes = true`
/// (docs/design/manual-plugins.md 4.7). Plugins without declarations are unchanged.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginGrant {
    pub token: String,
    pub operation: String,
    pub imports: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    /// The operator accepts that the plugin (or its client) chooses the bytes the granted
    /// key signs. Required for any key use of a declared operation; off unless written.
    #[serde(default)]
    pub plugin_bytes: bool,
    /// Exact GET PKI status URLs the plugin's nested validation may reach.
    #[serde(default)]
    pub pki_endpoints: Vec<String>,
}
/// Immutable operator trust/network configuration, never request metadata.
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PkiConfig {
    pub anchors: Vec<PathBuf>,
    pub intermediates: Vec<PathBuf>,
    pub endpoints: Vec<PkiEndpoint>,
    /// Operator-selected TSA for CAdES/PAdES T/LT/LTA and standalone stamps.
    pub tsa: Option<TsaConfig>,
    /// Host JWT claims policy; never read from a token or request.
    pub jwt: JwtConfig,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JwtConfig {
    pub expected_issuer: Option<String>,
    pub expected_audience: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsaConfig {
    pub url: String,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default = "default_tsa_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_tsa_skew")]
    pub skew_ms: u64,
}
fn default_tsa_timeout() -> u64 {
    10_000
}
fn default_tsa_skew() -> u64 {
    300_000
}
impl TsaConfig {
    pub(crate) fn spec(&self) -> io::Result<oncl_pki::tsp::TsaSpec> {
        if self.url.is_empty()
            || self.url.len() > 2048
            || self.timeout_ms == 0
            || self.timeout_ms > 120_000
        {
            return Err(invalid());
        }
        let policy = self
            .policy
            .as_deref()
            .map(|p| p.parse::<der::asn1::ObjectIdentifier>())
            .transpose()
            .map_err(|_| invalid())?;
        Ok(oncl_pki::tsp::TsaSpec {
            url: self.url.clone(),
            method: oncl_pki::http::PkiMethod::Post { content_type: None },
            hash: oncl_pki::key::HashAlg::Sha256,
            policy,
            nonce: oncl_pki::http::NonceSpec::Random(8),
            cert_req: true,
            retries: 0,
            timeout: Duration::from_millis(self.timeout_ms),
            check_skew: Some(Duration::from_millis(self.skew_ms)),
            require_tsa_eku: true,
        })
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PkiEndpoint {
    pub origin: String,
    pub addresses: Vec<SocketAddr>,
}
impl PkiConfig {
    /// DER-sized bytes of the operator trust set (file lengths; PEM overestimates).
    pub(crate) fn trust_bytes(&self) -> io::Result<u64> {
        let mut total = 0u64;
        for path in self.anchors.iter().chain(&self.intermediates) {
            total = total
                .checked_add(std::fs::metadata(path)?.len())
                .ok_or_else(invalid)?;
        }
        Ok(total)
    }
    fn validate_limits(&self) -> io::Result<()> {
        if self.anchors.len() > 256
            || self.intermediates.len() > 256
            || self.endpoints.len() > 128
            || self.endpoints.iter().any(|endpoint| {
                endpoint.origin.len() > 2048
                    || endpoint.addresses.is_empty()
                    || endpoint.addresses.len() > 16
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn services(&self) -> io::Result<oncl_core::ValidationServices> {
        let mut network = oncl_pki::validation::NetworkPolicy::deny_all();
        for endpoint in &self.endpoints {
            network = network
                .with_resolved_endpoint(&endpoint.origin, endpoint.addresses.clone())
                .map_err(|_| invalid())?;
        }
        let mut total = 0;
        let anchors = read_public_certificates(&self.anchors, &mut total)?;
        let intermediates = read_public_certificates(&self.intermediates, &mut total)?;
        Ok(oncl_core::ValidationServices::new(
            oncl_pki::pkix::CaSet::new(anchors),
            intermediates,
            std::sync::Arc::new(oncl_pki::http::UreqTransport::with_proxy(
                oncl_pki::http::ProxySetting::None,
            )),
            network,
            std::sync::Arc::new(time::OffsetDateTime::now_utc),
        ))
    }
}
fn read_public_certificates(
    paths: &[PathBuf],
    total: &mut u64,
) -> io::Result<Vec<oncl_pki::cert::Certificate>> {
    let mut certificates = Vec::with_capacity(paths.len());
    for path in paths {
        let mut file = std::fs::File::open(path)?;
        let length = file.metadata()?.len();
        if length > 1_048_576 {
            return Err(invalid());
        }
        let next = total
            .checked_add(length)
            .filter(|n| *n <= 16_777_216)
            .ok_or_else(invalid)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length as usize)
            .map_err(|_| invalid())?;
        bytes.resize(length as usize, 0);
        file.read_exact(&mut bytes)?;
        if file.read(&mut [0])? != 0 {
            return Err(invalid());
        }
        certificates.push(oncl_pki::cert::parse(&bytes).map_err(|_| invalid())?);
        *total = next;
    }
    Ok(certificates)
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    pub exposure: Exposure,
    /// Exact HTTP authorities, including port, when explicitly provided.
    pub hosts: Vec<String>,
    pub max_connections: usize,
    pub header_timeout_ms: u64,
    pub max_in_flight: u64,
    /// Requests that may be receiving their body at once (the upload phase: waiting for the
    /// client and spooling the documents), a limit of its own. An upload takes no
    /// `max_in_flight` slot and no native worker while it waits for the client; it holds one
    /// of these until its operation is admitted to run. 1 ..= 256, and at most
    /// `total_temp / (input_bytes + container_bytes)`, so that every upload can reserve the
    /// largest spool in the shared temp budget at once.
    pub max_uploads: usize,
    pub total_memory: u64,
    pub total_temp: u64,
    pub memory_per_operation: u64,
    pub temp_per_operation: u64,
    /// Document allowance of one operation: a document one byte past it is refused with
    /// `InputLimit`.
    pub input_bytes: u64,
    /// Signature, revision or envelope bytes a signed result of this service may add to
    /// a document that is at `input_bytes`. Only the `input` of a `verify`, `extend`,
    /// `extract` or `sign` item (a document that may already carry signatures) may exceed
    /// `input_bytes`, by container bytes only: the engine classifies the signed bytes and
    /// refuses a document part past `input_bytes`, or a surcharge past this value or past
    /// the format's own bound, with `InputLimit`. The upload of such an input is spooled up
    /// to `input_bytes + container_bytes` before that classification.
    pub container_bytes: u64,
    pub framing_bytes: u64,
    pub metadata_bytes: u64,
    pub blocking_workers: usize,
    pub queue_capacity: usize,
    /// How long a request that arrives while `max_in_flight` operations run waits for a
    /// slot, and how long an admitted operation waits for a native worker, before the
    /// typed `CapacityExceeded` refusal.
    pub admission_wait_ms: u64,
    pub operation_timeout_ms: u64,
    /// An upload body that delivers no byte for this long is ended with
    /// `DeadlineExceeded`/`NotApplied`, releasing its slot and spool. Also the length of
    /// the window in which `upload_min_bytes_per_second` is judged.
    pub upload_idle_timeout_ms: u64,
    /// Minimum average upload throughput over each idle-timeout window of waiting for the
    /// client; 0 disables the rule (idle timeout only).
    pub upload_min_bytes_per_second: u64,
    pub audit_directory: PathBuf,
    /// Explicit operator-owned namespace for transient public documents only.
    pub scratch_directory: PathBuf,
    pub audit_segment_bytes: u64,
    pub audit_quota_bytes: u64,
    pub recover_audit: bool,
    pub inline_pkcs12: bool,
    pub tokens: Vec<TokenConfig>,
    pub keys: Vec<KeyConfig>,
    pub pki: PkiConfig,
    pub plugins: Vec<PluginConfig>,
    /// Opt-in OTLP metrics/traces. Disabled by default: no thread, no connection.
    pub telemetry: TelemetryConfig,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:13579".parse().expect("literal address"),
            exposure: Exposure::Loopback,
            hosts: Vec::new(),
            max_connections: 32,
            header_timeout_ms: 5000,
            max_in_flight: 2,
            max_uploads: 8,
            total_memory: 536_870_912,
            total_temp: 17_179_869_184,
            memory_per_operation: 268_435_456,
            temp_per_operation: 8_589_934_592,
            input_bytes: 1_073_741_824,
            container_bytes: 1_073_741_824,
            framing_bytes: 67_108_864,
            metadata_bytes: 67_108_864,
            blocking_workers: 2,
            queue_capacity: 2,
            admission_wait_ms: 1000,
            upload_idle_timeout_ms: 30_000,
            upload_min_bytes_per_second: 1024,
            operation_timeout_ms: 300_000,
            audit_directory: PathBuf::new(),
            scratch_directory: PathBuf::new(),
            audit_segment_bytes: 1_048_576,
            audit_quota_bytes: 67_108_864,
            recover_audit: false,
            inline_pkcs12: false,
            tokens: Vec::new(),
            keys: Vec::new(),
            pki: PkiConfig::default(),
            plugins: Vec::new(),
            telemetry: TelemetryConfig::default(),
        }
    }
}
pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid service configuration")
}
impl ServerConfig {
    pub fn read(path: &Path) -> io::Result<Self> {
        let mount = SecretMount {
            directory: path.parent().ok_or_else(invalid)?.to_path_buf(),
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(invalid)?
                .into(),
        };
        let bytes = mount.read(65_536)?;
        let config: Self = toml::from_str(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> io::Result<()> {
        self.pki.validate_limits()?;
        self.telemetry.validate()?;
        if self.max_in_flight == 0
            || self.max_in_flight > 256
            || self.blocking_workers == 0
            || self.blocking_workers > 64
            || self.queue_capacity > 256
            || self.max_connections == 0
            || self.max_connections > 1024
            || self.operation_timeout_ms == 0
            || self.operation_timeout_ms > 86_400_000
            || self.admission_wait_ms == 0
            || self.admission_wait_ms > self.operation_timeout_ms
            || self.header_timeout_ms == 0
            || self.header_timeout_ms > self.operation_timeout_ms
            || self.upload_idle_timeout_ms < 1000
            || self.upload_idle_timeout_ms > 86_400_000
            || self.upload_min_bytes_per_second > 1_073_741_824
            || self.container_bytes == 0
            || self
                .input_bytes
                .checked_add(self.container_bytes)
                .and_then(|n| n.checked_add(self.framing_bytes))
                .and_then(|n| n.checked_add(65_536))
                .is_none()
            || self.metadata_bytes < 32_768
            || self.max_uploads == 0
            || self.max_uploads > 256
            || self.max_uploads as u64
                > self.total_temp / self.input_bytes.saturating_add(self.container_bytes)
            || self.memory_per_operation < 65_536
            || self.total_memory < self.memory_per_operation
            || self.total_temp < self.temp_per_operation
            || self.tokens.len() > 256
            || self.keys.len() > 64
            || self.plugins.len() > 16
            || self.plugins.iter().any(|p| {
                p.id.is_empty()
                    || p.id.len() > 64
                    || p.max_memory == 0
                    || p.max_memory > oncl_plugin::MAX_MEMORY
                    || p.max_transfer == 0
                    || p.max_transfer > oncl_plugin::MAX_TRANSFER
                    || p.permissions.len() > 256
                    || p.permissions.iter().any(|g| {
                        g.token.len() > 64
                            || g.operation.is_empty()
                            || g.operation.len() > 64
                            || g.imports.len() > 72
                            || g.keys.len() > 8
                            || (g.plugin_bytes && g.keys.is_empty())
                            || g.pki_endpoints.len() > 16
                            || g.pki_endpoints.iter().any(|u| u.len() > 2048)
                    })
                    || p.permissions.iter().enumerate().any(|(i, g)| {
                        p.permissions[..i]
                            .iter()
                            .any(|o| o.token == g.token && o.operation == g.operation)
                    })
            })
            || (self.audit_segment_bytes < crate::audit::PLUGIN_MIN_SEGMENT_BYTES
                && self
                    .plugins
                    .iter()
                    .any(|p| p.permissions.iter().any(|g| g.plugin_bytes)))
            || self.hosts.len() > 32
            || self
                .hosts
                .iter()
                .any(|s| s.len() > 255 || s.parse::<axum::http::uri::Authority>().is_err())
        {
            return Err(invalid());
        }
        match &self.exposure {
            Exposure::Loopback if !self.bind.ip().is_loopback() => return Err(invalid()),
            Exposure::TrustedProxy { peers }
                if peers.is_empty()
                    || peers.len() > 64
                    || peers.iter().any(|ip| normalized_peer(*ip).is_unspecified()) =>
            {
                return Err(invalid());
            }
            Exposure::Tls {
                certificate,
                private_key,
            } if certificate.as_os_str().is_empty()
                || private_key.directory.as_os_str().is_empty() =>
            {
                return Err(invalid());
            }
            _ => {}
        }
        if !self.bind.ip().is_loopback() && self.hosts.is_empty() {
            return Err(invalid());
        }
        self.executor().validate().map_err(|_| invalid())?;
        Ok(())
    }
    pub fn limits(&self) -> ResourceLimits {
        ResourceLimits {
            max_in_flight: self.max_in_flight,
            input_bytes: self.input_bytes,
            container_bytes: self.container_bytes,
            framing_bytes: self.framing_bytes,
            memory_bytes: self.memory_per_operation,
            temp_bytes: self.temp_per_operation,
            metadata_bytes: self.metadata_bytes,
            operation_timeout: Duration::from_millis(self.operation_timeout_ms),
            ..ResourceLimits::default()
        }
    }
    pub fn aggregate_limits(&self) -> ResourceLimits {
        ResourceLimits {
            memory_bytes: self.total_memory,
            temp_bytes: self.total_temp,
            ..self.limits()
        }
    }
    pub fn executor(&self) -> ExecutorConfig {
        ExecutorConfig {
            blocking_workers: self.blocking_workers,
            queue_capacity: self.queue_capacity,
            admission_wait: Duration::from_millis(self.admission_wait_ms),
        }
    }
    pub(crate) fn upload_pace(&self) -> crate::pace::PaceConfig {
        crate::pace::PaceConfig {
            idle: Duration::from_millis(self.upload_idle_timeout_ms),
            min_rate: self.upload_min_bytes_per_second,
        }
    }
}
