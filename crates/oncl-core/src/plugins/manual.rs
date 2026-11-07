//! The manual window's view of a registered plugin: the declared operations of its manifest
//! and the module request built from one of them. No ticket, approval or key use lives here.
use super::{Installed, PluginPermission, PluginRegistry};
use crate::{Engine, OperationError, plugins::CallerContext};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oncl_pki::{key::AppliedState, resource::ProcessingError};
use oncl_plugin::operations::{Operation, Param, ParamKind};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// What a registered plugin is, for audit and tickets: never its manifest name or label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginIdentity {
    pub id: String,
    /// Sum of the package file (or [`loose_package_sha256`]).
    pub package_sha256: [u8; 32],
    pub version: String,
}

/// A value for one declared parameter, typed like [`ParamKind`].
#[derive(Clone, Copy, Debug)]
pub enum PluginParam<'a> {
    /// The frozen bytes of the chosen file.
    Document(&'a [u8]),
    Text(&'a str),
    Choice(&'a str),
    Flag(bool),
    Locale(&'a str),
}

/// Why a declared operation cannot be offered or its request cannot be built. Every one is
/// raised before any key is opened.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginRequestError {
    UnknownPlugin,
    /// The manifest declares no such operation (a plugin without `[[operations]]` has none).
    UndeclaredOperation,
    /// Declared, but not for the manual window.
    NotManual,
    /// `derived` content needs the plan-run of a later stage; not run here.
    DerivedUnsupported,
    UnknownParam(String),
    DuplicateParam(String),
    MissingParam(String),
    WrongKind(String),
    TooLarge(String),
    InvalidValue(String),
    /// A PKI endpoint given to the declared policy is not an exact http(s) URL.
    InvalidEndpoint,
    /// The built request exceeds the plugin's `max_transfer`.
    RequestTooLarge,
}

impl PluginRequestError {
    /// Always `NotApplied`: nothing here touches a key.
    pub fn applied_state(&self) -> AppliedState {
        AppliedState::NotApplied
    }
    pub fn code(&self) -> crate::ErrorCode {
        OperationError::from(self.clone()).code()
    }
}
impl std::fmt::Display for PluginRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPlugin => f.write_str("unknown plugin"),
            Self::UndeclaredOperation => f.write_str("operation is not declared"),
            Self::NotManual => f.write_str("operation is not offered in the manual window"),
            Self::DerivedUnsupported => f.write_str("derived content is not supported"),
            Self::UnknownParam(p) => write!(f, "unknown parameter {p:?}"),
            Self::DuplicateParam(p) => write!(f, "parameter {p:?} given twice"),
            Self::MissingParam(p) => write!(f, "missing parameter {p:?}"),
            Self::WrongKind(p) => write!(f, "parameter {p:?} has the wrong kind"),
            Self::TooLarge(p) => write!(f, "parameter {p:?} is too large"),
            Self::InvalidValue(p) => write!(f, "parameter {p:?} has an invalid value"),
            Self::InvalidEndpoint => f.write_str("invalid PKI endpoint"),
            Self::RequestTooLarge => f.write_str("request exceeds the plugin transfer limit"),
        }
    }
}
impl std::error::Error for PluginRequestError {}
impl From<PluginRequestError> for OperationError {
    fn from(error: PluginRequestError) -> Self {
        match error {
            PluginRequestError::UnknownPlugin
            | PluginRequestError::UndeclaredOperation
            | PluginRequestError::NotManual
            | PluginRequestError::DerivedUnsupported => OperationError::PermissionDenied,
            PluginRequestError::TooLarge(_) | PluginRequestError::RequestTooLarge => {
                ProcessingError::InvalidInput("plugin request too large").into()
            }
            _ => ProcessingError::InvalidInput("invalid plugin operation parameters").into(),
        }
    }
}

/// SHA-256 over a length-prefixed manifest text and module, for hosts that load them
/// separately instead of from a package file.
pub fn loose_package_sha256(manifest_toml: &[u8], wasm: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ONCLPKG-LOOSE1\0");
    h.update((manifest_toml.len() as u64).to_be_bytes());
    h.update(manifest_toml);
    h.update((wasm.len() as u64).to_be_bytes());
    h.update(wasm);
    h.finalize().into()
}

impl Installed {
    fn declared(&self, name: &str) -> Result<&Operation, PluginRequestError> {
        self.operations
            .iter()
            .find(|o| o.name() == name)
            .ok_or(PluginRequestError::UndeclaredOperation)
    }
    fn manual_operation(&self, name: &str) -> Result<&Operation, PluginRequestError> {
        let op = self.declared(name)?;
        if !op.runnable() {
            return Err(PluginRequestError::DerivedUnsupported);
        }
        if !op.manual() {
            return Err(PluginRequestError::NotManual);
        }
        Ok(op)
    }
}

impl PluginRegistry {
    /// Adds the registry policy for a declared operation and caller: the operation's
    /// declared imports, any key (the chosen key is checked on the per-call grant side,
    /// which never accepts this permission for a key). Built from the manifest only.
    pub fn allow_declared(
        &mut self,
        plugin_id: &str,
        operation: &str,
        caller: CallerContext,
    ) -> Result<(), PluginRequestError> {
        self.allow_declared_with_pki(
            plugin_id,
            operation,
            caller,
            std::iter::empty::<(oncl_pki::http::HttpMethod, &str)>(),
        )
    }

    /// [`allow_declared`](Self::allow_declared) with the host's exact PKI endpoints (the
    /// per-call grant must name them too).
    pub fn allow_declared_with_pki(
        &mut self,
        plugin_id: &str,
        operation: &str,
        caller: CallerContext,
        pki_endpoints: impl IntoIterator<Item = (oncl_pki::http::HttpMethod, impl AsRef<str>)>,
    ) -> Result<(), PluginRequestError> {
        let installed = self
            .installed
            .get_mut(plugin_id)
            .ok_or(PluginRequestError::UnknownPlugin)?;
        let permission =
            PluginPermission::declared(plugin_id, installed.manual_operation(operation)?, caller)
                .with_pki_endpoints(pki_endpoints)
                .map_err(|_| PluginRequestError::InvalidEndpoint)?;
        let mut policy = installed.policy.to_vec();
        policy.push(permission);
        installed.policy = policy.into();
        Ok(())
    }
}

impl Engine {
    /// The identity of a registered plugin, if any.
    pub fn plugin_identity(&self, plugin_id: &str) -> Option<&PluginIdentity> {
        Some(&self.plugins.as_ref()?.installed.get(plugin_id)?.identity)
    }

    /// The declared operations the manual window may offer: manual and runnable (not
    /// derived), in manifest order. Empty for a plugin without `[[operations]]`.
    pub fn plugin_operations(
        &self,
        plugin_id: &str,
    ) -> Result<Vec<&Operation>, PluginRequestError> {
        let installed = self
            .plugins
            .as_ref()
            .and_then(|r| r.installed.get(plugin_id))
            .ok_or(PluginRequestError::UnknownPlugin)?;
        Ok(installed
            .operations
            .iter()
            .filter(|o| o.manual() && o.runnable())
            .collect())
    }

    /// The exact request text the module receives for a declared operation: the template
    /// parsed as JSON, each whole-string placeholder in `args` replaced by the typed value
    /// (documents as standard base64), serialized compactly with keys sorted. `module` and
    /// `method` come from the manifest alone.
    pub fn plugin_request(
        &self,
        plugin_id: &str,
        operation: &str,
        params: &[(&str, PluginParam<'_>)],
    ) -> Result<String, PluginRequestError> {
        let installed = self
            .plugins
            .as_ref()
            .and_then(|r| r.installed.get(plugin_id))
            .ok_or(PluginRequestError::UnknownPlugin)?;
        let op = installed.manual_operation(operation)?;
        for (i, (name, _)) in params.iter().enumerate() {
            if !op.params().iter().any(|p| p.name == *name) {
                return Err(PluginRequestError::UnknownParam((*name).to_owned()));
            }
            if params[..i].iter().any(|(n, _)| n == name) {
                return Err(PluginRequestError::DuplicateParam((*name).to_owned()));
            }
        }
        let mut values = Vec::with_capacity(op.params().len());
        for param in op.params() {
            let (_, value) = params
                .iter()
                .find(|(n, _)| *n == param.name)
                .ok_or_else(|| PluginRequestError::MissingParam(param.name.clone()))?;
            values.push((param.name.as_str(), typed(param, value)?));
        }
        let mut request: Value = serde_json::from_str(op.request_template())
            .map_err(|_| PluginRequestError::UndeclaredOperation)?;
        if let Some(args) = request.get_mut("args") {
            substitute(args, &values);
        }
        let text =
            serde_json::to_string(&request).map_err(|_| PluginRequestError::UndeclaredOperation)?;
        if text.len() > installed.compiled.limits().max_transfer {
            return Err(PluginRequestError::RequestTooLarge);
        }
        Ok(text)
    }
}

fn typed(param: &Param, value: &PluginParam<'_>) -> Result<Value, PluginRequestError> {
    let name = || param.name.clone();
    match (&param.kind, value) {
        (ParamKind::Document { max_bytes }, PluginParam::Document(bytes)) => {
            if bytes.len() as u64 > *max_bytes {
                return Err(PluginRequestError::TooLarge(name()));
            }
            Ok(Value::String(STANDARD.encode(bytes)))
        }
        (ParamKind::Text { max_chars }, PluginParam::Text(text)) => {
            if text.chars().count() as u64 > u64::from(*max_chars) {
                return Err(PluginRequestError::TooLarge(name()));
            }
            Ok(Value::String((*text).to_owned()))
        }
        (ParamKind::Choice { choices }, PluginParam::Choice(choice)) => {
            if !choices.iter().any(|c| c == choice) {
                return Err(PluginRequestError::InvalidValue(name()));
            }
            Ok(Value::String((*choice).to_owned()))
        }
        (ParamKind::Flag, PluginParam::Flag(flag)) => Ok(Value::Bool(*flag)),
        (ParamKind::Locale, PluginParam::Locale(locale)) => {
            if !matches!(*locale, "ru" | "kk" | "en") {
                return Err(PluginRequestError::InvalidValue(name()));
            }
            Ok(Value::String((*locale).to_owned()))
        }
        _ => Err(PluginRequestError::WrongKind(name())),
    }
}

/// Replaces whole-string placeholders; substituted values are never rescanned.
fn substitute(value: &mut Value, values: &[(&str, Value)]) {
    match value {
        Value::String(s) => {
            let name = s
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .map(|i| i.strip_suffix(":base64").unwrap_or(i));
            if let Some(name) = name
                && let Some((_, v)) = values.iter().find(|(n, _)| *n == name)
            {
                *value = v.clone();
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| substitute(v, values)),
        Value::Object(map) => map.values_mut().for_each(|v| substitute(v, values)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyId;
    use oncl_pdk::abi::Import;

    #[test]
    fn declared_permission_never_stands_in_for_the_chosen_key_on_the_grant_side() {
        let manifest = oncl_plugin::Manifest::from_toml(
            r#"id = "t.p"
name.ru = "p"
name.kk = "p"
name.en = "p"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["m"]
[capabilities]
keys = true
[[operations]]
name = "s"
module = "m"
manual = true
request = '{"module":"m","method":"s","args":["{f:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "f"
kind = "document"
[operations.uses]
imports = ["keys_sign_raw"]
[[operations.uses.key]]
kind = "raw"
content = "param:f"
"#,
        )
        .unwrap();
        let p = PluginPermission::declared(
            "t.p",
            &manifest.operations()[0],
            CallerContext::LocalOperator("u".into()),
        );
        let key = KeyId::new("k").unwrap();
        assert!(p.permits(Import::KeysSignRaw, Some(&key)));
        assert!(!p.permits_grant(Import::KeysSignRaw, Some(&key)));
        assert!(!p.permits(Import::Hash, None));
    }
}
