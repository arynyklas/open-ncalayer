//! `settings`: a plugin's settings, kept on disk across sessions and updates; `shared`: the
//! values a plugin's instances share in the process, until the plugin is reloaded.

use super::{failed, limit};
use crate::host::HostState;
use oncl_pdk::abi::{
    Bytes, HostResult, MAX_SETTINGS, MAX_SETTINGS_KEYS, MAX_SHARED, MAX_SHARED_KEYS, SharedKey,
    SharedPut,
};
use oncl_pki::fsutil::{Access, write_atomically};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

/// The settings file of the instance's plugin, if the core keeps settings.
fn settings_file(state: &HostState) -> HostResult<PathBuf> {
    let dir = state
        .services
        .settings_dir
        .as_ref()
        .ok_or_else(|| failed("the core keeps no plugin settings"))?;
    Ok(dir.join(format!("{}.json", state.session.plugin_id)))
}

/// `settings_get`: the plugin's settings; none if there are none yet, and none (logged) if
/// the file is not a JSON object of strings.
pub(crate) fn settings_get(state: &mut HostState) -> HostResult<BTreeMap<String, String>> {
    let path = settings_file(state)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(failed(format!("{}: {e}", path.display()))),
    };
    Ok(serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), error = %e, "plugin settings are corrupt; read as empty");
        BTreeMap::new()
    }))
}

/// `settings_put`: replaces the plugin's settings, through a temporary file; at most
/// [`MAX_SETTINGS_KEYS`] keys and [`MAX_SETTINGS`] bytes of JSON.
pub(crate) fn settings_put(
    state: &mut HostState,
    settings: BTreeMap<String, String>,
) -> HostResult<()> {
    if settings.len() > MAX_SETTINGS_KEYS {
        return Err(limit(format!("more than {MAX_SETTINGS_KEYS} settings")));
    }
    let json = serde_json::to_vec(&settings).map_err(failed)?;
    if json.len() > MAX_SETTINGS {
        return Err(limit(format!("the settings are over {MAX_SETTINGS} bytes")));
    }
    let path = settings_file(state)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| failed(format!("{}: {e}", dir.display())))?;
    }
    write_atomically(&path, &json, Access::Private)
        .map_err(|e| failed(format!("{}: {e}", path.display())))
}

/// The values a plugin's instances share: one per loaded generation of the plugin, so a
/// reload or an update starts empty. At most [`MAX_SHARED_KEYS`] keys and [`MAX_SHARED`]
/// bytes of keys and values together.
#[derive(Debug, Default)]
pub struct SharedState {
    values: Mutex<HashMap<String, Shared>>,
}

/// A shared value and when it goes (Unix milliseconds), if it does.
#[derive(Debug)]
struct Shared {
    value: Vec<u8>,
    expires_ms: Option<i128>,
}

impl SharedState {
    /// The values, without those expired at `now_ms`.
    fn live(&self, now_ms: i128) -> std::sync::MutexGuard<'_, HashMap<String, Shared>> {
        let mut values = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        values.retain(|_, v| v.expires_ms.is_none_or(|at| at > now_ms));
        values
    }
}

/// The services' clock in Unix milliseconds.
fn now_ms(state: &HostState) -> i128 {
    (state.services.clock)().unix_timestamp_nanos() / 1_000_000
}

/// `shared_get`: the value of `key`, if set and not expired.
pub(crate) fn shared_get(state: &mut HostState, args: SharedKey) -> HostResult<Option<Bytes>> {
    let now = now_ms(state);
    let values = state.session.shared.live(now);
    Ok(values.get(&args.key).map(|v| Bytes::from(v.value.clone())))
}

/// `shared_put`: sets `key` (for `ttl_ms` if given), or removes it.
pub(crate) fn shared_put(state: &mut HostState, args: SharedPut) -> HostResult<()> {
    let now = now_ms(state);
    let mut values = state.session.shared.live(now);
    let Some(value) = args.value else {
        values.remove(&args.key);
        return Ok(());
    };
    if !values.contains_key(&args.key) && values.len() >= MAX_SHARED_KEYS {
        return Err(limit(format!("more than {MAX_SHARED_KEYS} shared values")));
    }
    let others: usize = values
        .iter()
        .filter(|(k, _)| **k != args.key)
        .map(|(k, v)| k.len() + v.value.len())
        .sum();
    if others + args.key.len() + value.len() > MAX_SHARED {
        return Err(limit(format!(
            "the shared values are over {MAX_SHARED} bytes"
        )));
    }
    let expires_ms = args.ttl_ms.map(|ttl| now + i128::from(ttl));
    values.insert(
        args.key,
        Shared {
            value: value.into_vec(),
            expires_ms,
        },
    );
    Ok(())
}
