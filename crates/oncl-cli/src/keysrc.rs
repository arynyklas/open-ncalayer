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
pub fn resolve(config: &Path, name: &str) -> Result<Plan, OperationError> {
    if !name_ok(name) {
        return Err(invalid());
    }
    let mut file = std::fs::File::open(config).map_err(ProcessingError::from)?;
    let length = file.metadata().map_err(ProcessingError::from)?.len();
    if length > CONFIG_BYTES {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(ProcessingError::from)?;
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
impl PrivateKeyArgs {
    pub fn plan(&self) -> Result<Plan, OperationError> {
        if let (Some(config), Some(name)) = (&self.key_config, &self.key_name) {
            return resolve(config, name);
        }
        Ok(Plan::direct(self.selector()?, self.uses_token()))
    }
}
