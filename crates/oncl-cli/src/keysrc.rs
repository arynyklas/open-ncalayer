//! Operator-configured named key sources.
//!
//! `--key-config` is a bounded JSON file written by the operator; `--key-name`
//! only selects an entry in it. The config holds source locations (file or
//! token reader), never passwords or PINs, and unknown fields are denied. The
//! command line therefore never names a container path for a named key, and the
//! Core `KeySources` provider resolves the name; the guard and grant bind the
//! exact `named:NAME` key id, not the underlying path.
use crate::args::{PrivateKeyArgs, TokenFamily};
use clap::ValueEnum;
use oncl_core::{
    OperationError,
    keys::{KeyId, KeySelector},
};
use oncl_pki::resource::ProcessingError;
use serde::Deserialize;
use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};

const CONFIG_BYTES: u64 = 64 * 1024;
const MAX_KEYS: usize = 64;

/// The resolved key choice of one invocation.
pub struct Plan {
    /// What requests and the grant carry: `named:NAME` or the direct selector.
    pub selector: KeySelector,
    /// The operator binding the provider must be configured with.
    pub binding: Option<(KeyId, KeySelector)>,
    pub token: bool,
}
impl Plan {
    pub fn direct(selector: KeySelector, token: bool) -> Self {
        Self {
            selector,
            binding: None,
            token,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    keys: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
enum Entry {
    File {
        name: String,
        path: PathBuf,
        alias: Option<String>,
    },
    Token {
        name: String,
        reader: String,
        kind: String,
        alias: String,
    },
}
impl Entry {
    fn name(&self) -> &str {
        match self {
            Self::File { name, .. } | Self::Token { name, .. } => name,
        }
    }
}
fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn invalid() -> OperationError {
    OperationError::InvalidKeySource
}
/// Parses the whole config (so a duplicate or malformed entry anywhere is
/// refused) and resolves `name`. Only the selected source is opened later.
pub fn resolve(
    config: &Path,
    name: &str,
    control: &crate::control::Control,
    reservation: &mut oncl_pki::resource::ConfigurationReservation,
) -> Result<Plan, OperationError> {
    if !name_ok(name) {
        return Err(invalid());
    }
    // Trust model: the file decides which container or reader a granted
    // `named:NAME` reaches, so it is read exactly like a secret file, from an
    // owner-only directory through the SDK's ownership/ACL/link checks, which also
    // refuse anything that is not a regular file (no FIFO/device read can block).
    // Its bytes are charged to the one configuration budget before being read.
    control.check()?;
    let parent = config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = config
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(OperationError::InvalidKeySource)?;
    let mut file = oncl_pki::private_fs::PrivateDirectory::open(parent)
        .and_then(|directory| directory.open_file(file_name))
        .map_err(ProcessingError::from)?;
    let metadata = file.metadata().map_err(ProcessingError::from)?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    let length = metadata.len();
    if length > CONFIG_BYTES {
        return Err(ProcessingError::MetadataLimit.into());
    }
    reservation.grow(length, length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    let mut chunk = [0u8; 8192];
    loop {
        control.check()?;
        let read = file.read(&mut chunk).map_err(ProcessingError::from)?;
        if read == 0 {
            break;
        }
        if bytes.len() + read > length as usize {
            return Err(
                ProcessingError::InvalidInput("key configuration changed during intake").into(),
            );
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    control.check()?;
    if bytes.len() as u64 != length {
        return Err(
            ProcessingError::InvalidInput("key configuration changed during intake").into(),
        );
    }
    let parsed: Config = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if parsed.keys.len() > MAX_KEYS {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut seen = HashSet::new();
    for entry in &parsed.keys {
        if !name_ok(entry.name()) || !seen.insert(entry.name()) {
            return Err(invalid());
        }
    }
    let base = config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let entry = parsed
        .keys
        .iter()
        .find(|entry| entry.name() == name)
        .ok_or(OperationError::KeyNotFound)?;
    let (selector, token) = match entry {
        Entry::File { path, alias, .. } => {
            (KeySelector::file(base.join(path), alias.clone())?, false)
        }
        Entry::Token {
            reader,
            kind,
            alias,
            ..
        } => {
            let family = TokenFamily::from_str(kind, true).map_err(|_| invalid())?;
            (crate::args::token_selector(reader, family, alias)?, true)
        }
    };
    let id = KeyId::new(name)?;
    Ok(Plan {
        selector: KeySelector::named(id.clone()),
        binding: Some((id, selector)),
        token,
    })
}
/// The operator-configured provider for this invocation: the named binding and,
/// only for a token source, the hardware (or, with the test-only
/// `token-emulator` feature, emulated) token service.
pub fn sources(plan: &Plan) -> Result<oncl_core::keys::KeySources, OperationError> {
    let mut sources = oncl_core::keys::KeySources::new();
    if let Some((id, selector)) = &plan.binding {
        sources = sources.with_named(id.clone(), selector.clone())?;
    }
    if plan.token {
        let gates = oncl_token::execution::TokenGateRegistry::new(1, 4)
            .map_err(|_| ProcessingError::InvalidInput("token gate"))?;
        sources = sources.with_tokens(token_service()?, std::sync::Arc::new(gates));
    }
    Ok(sources)
}
/// With feature `token-emulator` (tests and demonstrations only, never a
/// release build) and `ONCL_TOKEN_EMULATOR=<config.toml>` set, software cards
/// of that file replace the system smart-card service; an unreadable file is a
/// refusal, never a fallback to the real service.
fn token_service() -> Result<std::sync::Arc<oncl_token::Tokens>, OperationError> {
    #[cfg(feature = "token-emulator")]
    if let Some(path) = std::env::var_os("ONCL_TOKEN_EMULATOR") {
        let path = PathBuf::from(path);
        let base = path.parent().unwrap_or(Path::new(""));
        let backend = std::fs::read_to_string(&path)
            .map_err(|_| ())
            .and_then(|text| {
                oncl_token::emulator::EmulatorBackend::from_config(&text, base).map_err(|_| ())
            })
            .map_err(|()| ProcessingError::InvalidInput("token emulator configuration"))?;
        return Ok(oncl_token::Tokens::new(std::sync::Arc::new(backend), true));
    }
    Ok(oncl_token::Tokens::new(
        std::sync::Arc::new(oncl_token::PcscBackend::new()),
        true,
    ))
}
impl PrivateKeyArgs {
    pub fn plan(
        &self,
        control: &crate::control::Control,
        reservation: &mut oncl_pki::resource::ConfigurationReservation,
    ) -> Result<Plan, OperationError> {
        if let (Some(config), Some(name)) = (&self.key_config, &self.key_name) {
            return resolve(config, name, control, reservation);
        }
        Ok(Plan::direct(self.selector()?, self.uses_token()))
    }
}
