use crate::{
    auth::{TokenRecord, TokenVerifier},
    executor::ExecutorConfig,
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
}
impl Permission {
    fn action(self) -> Action {
        match self {
            Self::Hash => Action::Hash,
            Self::Sign => Action::Sign,
            Self::SignDigest => Action::SignDigest,
        }
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
}
impl TokenConfig {
    pub fn record(&self) -> io::Result<TokenRecord> {
        Ok(TokenRecord::new(
            &self.id,
            TokenVerifier::parse(&self.verifier)?,
            self.actions.iter().map(|p| p.action()).collect(),
            self.keys.clone(),
        )?
        .with_inline_pkcs12(self.inline_pkcs12))
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
    pub total_memory: u64,
    pub total_temp: u64,
    pub memory_per_operation: u64,
    pub temp_per_operation: u64,
    pub input_bytes: u64,
    pub framing_bytes: u64,
    pub metadata_bytes: u64,
    pub blocking_workers: usize,
    pub queue_capacity: usize,
    pub admission_wait_ms: u64,
    pub operation_timeout_ms: u64,
    pub audit_directory: PathBuf,
    /// Explicit operator-owned namespace for transient public documents only.
    pub scratch_directory: PathBuf,
    pub audit_segment_bytes: u64,
    pub audit_quota_bytes: u64,
    pub recover_audit: bool,
    pub inline_pkcs12: bool,
    pub tokens: Vec<TokenConfig>,
    pub keys: Vec<KeyConfig>,
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
            total_memory: 536_870_912,
            total_temp: 68_719_476_736,
            memory_per_operation: 268_435_456,
            temp_per_operation: 34_359_738_368,
            input_bytes: 10_737_418_240,
            framing_bytes: 67_108_864,
            metadata_bytes: 1_048_576,
            blocking_workers: 2,
            queue_capacity: 2,
            admission_wait_ms: 1000,
            operation_timeout_ms: 300_000,
            audit_directory: PathBuf::new(),
            scratch_directory: PathBuf::new(),
            audit_segment_bytes: 1_048_576,
            audit_quota_bytes: 67_108_864,
            recover_audit: false,
            inline_pkcs12: false,
            tokens: Vec::new(),
            keys: Vec::new(),
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
            || self.metadata_bytes < 32_768
            || self.memory_per_operation < 65_536
            || self.total_memory < self.memory_per_operation
            || self.total_temp < self.temp_per_operation
            || self.tokens.len() > 256
            || self.keys.len() > 64
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
}
