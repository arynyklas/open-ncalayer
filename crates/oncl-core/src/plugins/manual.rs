//! The manual window's view of a registered plugin: the declared operations of its manifest
//! and the module request built from one of them. No ticket, approval or key use lives here.
use super::{Installed, PluginPermission, PluginRegistry};
use crate::{Engine, OperationError, plugins::CallerContext};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oncl_pki::{http::HttpMethod, key::AppliedState, resource::ProcessingError};
use oncl_plugin::operations::{Network, Operation, Param, ParamKind, Profile, Source};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The SHA-256 a registered plugin is known by, tagged with what was hashed. The two kinds
/// never compare equal and never share a canonical encoding.
///
/// The registry cannot check a hash against the manifest and module it is given: whoever
/// installs must take all three from one source (see [`PluginRegistry::install_package`]).
/// `oncl_plugin::BuiltinInfo::sha256` (the module alone) is neither kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PackageHash {
    /// The whole package file as read by `oncl_plugin::Package::read`.
    File([u8; 32]),
    /// [`loose_package_hash`]: a manifest text and a module that were not loaded from a
    /// package file.
    Loose([u8; 32]),
}

impl PackageHash {
    /// The tagged encoding (tag `1` file, `2` loose, then the digest) to be used wherever
    /// the hash is bound into another hash or compared as bytes.
    pub fn canonical(&self) -> [u8; 33] {
        let (tag, digest) = match self {
            Self::File(d) => (1, d),
            Self::Loose(d) => (2, d),
        };
        let mut out = [0; 33];
        out[0] = tag;
        out[1..].copy_from_slice(digest);
        out
    }
    /// The digest, without its kind.
    pub fn digest(&self) -> &[u8; 32] {
        match self {
            Self::File(d) | Self::Loose(d) => d,
        }
    }
}

/// What a registered plugin is, for audit and tickets: never its manifest name or label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginIdentity {
    pub id: String,
    pub package: PackageHash,
    pub version: String,
}

/// A value for one declared parameter, typed like [`ParamKind`].
#[derive(Clone, Copy, Debug)]
pub enum PluginParam<'a> {
    /// The frozen bytes of the chosen file; never empty.
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
    /// `network = [urls]` is not runnable in the manual window in this release.
    NetworkUnsupported,
    /// Endpoints were given to an operation whose declared `network` is `none`.
    NetworkNotDeclared,
    UnknownParam(String),
    DuplicateParam(String),
    MissingParam(String),
    WrongKind(String),
    TooLarge(String),
    InvalidValue(String),
    /// A PKI endpoint is not an exact http(s) URL, or its host is not a PKI host.
    InvalidEndpoint,
    /// The request exceeds the plugin's `max_transfer`.
    RequestTooLarge,
    /// The manifest's template is not one this host can build a request from (a number
    /// that JSON re-printing would change, or text that does not parse).
    InvalidTemplate,
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
            Self::NetworkUnsupported => f.write_str("URL network access is not supported here"),
            Self::NetworkNotDeclared => f.write_str("the operation declares no such network"),
            Self::UnknownParam(p) => write!(f, "unknown parameter {p:?}"),
            Self::DuplicateParam(p) => write!(f, "parameter {p:?} given twice"),
            Self::MissingParam(p) => write!(f, "missing parameter {p:?}"),
            Self::WrongKind(p) => write!(f, "parameter {p:?} has the wrong kind"),
            Self::TooLarge(p) => write!(f, "parameter {p:?} is too large"),
            Self::InvalidValue(p) => write!(f, "parameter {p:?} has an invalid value"),
            Self::InvalidEndpoint => f.write_str("invalid PKI endpoint"),
            Self::RequestTooLarge => f.write_str("request exceeds the plugin transfer limit"),
            Self::InvalidTemplate => f.write_str("the request template cannot be built"),
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
            | PluginRequestError::DerivedUnsupported
            | PluginRequestError::NetworkUnsupported
            | PluginRequestError::NetworkNotDeclared => OperationError::PermissionDenied,
            PluginRequestError::TooLarge(_) | PluginRequestError::RequestTooLarge => {
                ProcessingError::InputLimit.into()
            }
            _ => ProcessingError::InvalidInput("invalid plugin operation parameters").into(),
        }
    }
}

/// A [`PackageHash::Loose`]: SHA-256 over a length-prefixed manifest text and module, for
/// hosts that load them separately instead of from a package file. It can never equal a
/// file hash and is not verified against anything.
pub fn loose_package_hash(manifest_toml: &[u8], wasm: &[u8]) -> PackageHash {
    let mut h = Sha256::new();
    h.update(b"ONCLPKG-LOOSE1\0");
    h.update((manifest_toml.len() as u64).to_be_bytes());
    h.update(manifest_toml);
    h.update((wasm.len() as u64).to_be_bytes());
    h.update(wasm);
    PackageHash::Loose(h.finalize().into())
}

impl Installed {
    /// The operation, if the manual window may offer it: declared, runnable (not derived),
    /// manual, and not `network = [urls]`.
    pub(super) fn manual_operation(&self, name: &str) -> Result<&Operation, PluginRequestError> {
        let op = self
            .manifest
            .operations()
            .iter()
            .find(|o| o.name() == name)
            .ok_or(PluginRequestError::UndeclaredOperation)?;
        if !op.runnable() {
            return Err(PluginRequestError::DerivedUnsupported);
        }
        if !op.manual() {
            return Err(PluginRequestError::NotManual);
        }
        if matches!(op.uses().network(), Network::Urls(_)) {
            return Err(PluginRequestError::NetworkUnsupported);
        }
        Ok(op)
    }
}

/// Whether `host` is one of `hosts` or a subdomain of one.
fn in_hosts(host: &str, hosts: &[&str]) -> bool {
    hosts.iter().any(|h| {
        host.eq_ignore_ascii_case(h)
            || host.len().checked_sub(h.len() + 1).is_some_and(|at| {
                host.as_bytes()[at] == b'.' && host[at + 1..].eq_ignore_ascii_case(h)
            })
    })
}

impl PluginRegistry {
    /// Adds the registry policy for a declared operation and caller: the operation's
    /// declared imports, any key (the chosen key is checked on the per-call grant side,
    /// which never accepts this permission for a key), and no network. Built from the
    /// manifest only. Whether `caller` may use the operation's `manual`/`server` flavour
    /// is the wiring host's check (MP8 for servers).
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
            std::iter::empty::<(HttpMethod, &str)>(),
            &[],
        )
    }

    /// [`allow_declared`](Self::allow_declared) with the host's exact PKI endpoints (the
    /// per-call grant must name them too). Enforces the declared `network`: `none` takes
    /// no endpoint; `pki` takes only endpoints whose host is one of `pki_hosts` (or a
    /// subdomain; the host passes [`oncl_plugin::NCA_PKI_HOSTS`] unless it configures
    /// others); `[urls]` is refused ([`PluginRequestError::NetworkUnsupported`]).
    pub fn allow_declared_with_pki(
        &mut self,
        plugin_id: &str,
        operation: &str,
        caller: CallerContext,
        pki_endpoints: impl IntoIterator<Item = (HttpMethod, impl AsRef<str>)>,
        pki_hosts: &[&str],
    ) -> Result<(), PluginRequestError> {
        let installed = self
            .installed
            .get_mut(plugin_id)
            .ok_or(PluginRequestError::UnknownPlugin)?;
        let op = installed.manual_operation(operation)?;
        let endpoints: Vec<(HttpMethod, String)> = pki_endpoints
            .into_iter()
            .map(|(m, u)| (m, u.as_ref().to_owned()))
            .collect();
        if !endpoints.is_empty() {
            if !matches!(op.uses().network(), Network::Pki) {
                return Err(PluginRequestError::NetworkNotDeclared);
            }
            for (_, url) in &endpoints {
                let url = oncl_plugin::Url::parse(url)
                    .map_err(|_| PluginRequestError::InvalidEndpoint)?;
                if !url.host_str().is_some_and(|h| in_hosts(h, pki_hosts)) {
                    return Err(PluginRequestError::InvalidEndpoint);
                }
            }
        }
        let permission = PluginPermission::declared(plugin_id, op, caller)
            .with_pki_endpoints(endpoints)
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

    /// The declared operations the manual window may offer (`Manifest::manual_operations`
    /// without `network = [urls]`), in manifest order. Empty for a plugin without
    /// `[[operations]]`.
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
            .manifest
            .manual_operations()
            .filter(|o| !matches!(o.uses().network(), Network::Urls(_)))
            .collect())
    }

    /// The exact request text the module receives for a declared operation: the template
    /// parsed as JSON, each whole-string placeholder in `args` replaced by the typed value
    /// (documents as standard base64), serialized compactly with object keys sorted and
    /// integers as written. `module` and `method` come from the manifest alone. The final
    /// length is computed before anything is substituted and refused above `max_transfer`;
    /// the text is then built once in a buffer of exactly that size.
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
        let xpath_params = xpath_params(op);
        let mut values = Vec::with_capacity(op.params().len());
        for param in op.params() {
            let (_, value) = params
                .iter()
                .find(|(n, _)| *n == param.name)
                .ok_or_else(|| PluginRequestError::MissingParam(param.name.clone()))?;
            check(param, value, xpath_params.contains(&param.name.as_str()))?;
            values.push((param.name.as_str(), *value));
        }
        let template: Value = serde_json::from_str(op.request_template())
            .map_err(|_| PluginRequestError::InvalidTemplate)?;
        let max = installed.compiled.limits().max_transfer;
        let mut count = Out::counting(max);
        emit(&template, &values, &mut count)?;
        let mut out = Out::writing(count.len, max);
        emit(&template, &values, &mut out)?;
        let text = out.buf.unwrap_or_default();
        debug_assert_eq!(text.len(), count.len);
        Ok(text)
    }
}

/// The text parameters a key profile reads as an XPath.
fn xpath_params(op: &Operation) -> Vec<&str> {
    let mut names = Vec::new();
    for key in op.uses().keys() {
        let sources: [&Option<Source>; 2] = match key.profile() {
            Profile::Xml(p) => [&p.element, &p.parent],
            Profile::XmlEx(p) => [&p.element, &p.parent],
            _ => continue,
        };
        for source in sources.into_iter().flatten() {
            if let Source::Param(name) = source {
                names.push(name.as_str());
            }
        }
    }
    names
}

fn check(param: &Param, value: &PluginParam<'_>, xpath: bool) -> Result<(), PluginRequestError> {
    let name = || param.name.clone();
    match (&param.kind, value) {
        (ParamKind::Document { max_bytes }, PluginParam::Document(bytes)) => {
            if bytes.is_empty() {
                return Err(PluginRequestError::InvalidValue(name()));
            }
            if bytes.len() as u64 > *max_bytes {
                return Err(PluginRequestError::TooLarge(name()));
            }
        }
        (ParamKind::Text { max_chars }, PluginParam::Text(text)) => {
            // Counted in characters, like the declared limit; a text longer in bytes than
            // `4 * max_chars` cannot fit, which bounds the count itself.
            if text.len() as u64 > 4 * u64::from(*max_chars)
                || text.chars().count() as u64 > u64::from(*max_chars)
            {
                return Err(PluginRequestError::TooLarge(name()));
            }
            if xpath && Source::check_value(text).is_err() {
                return Err(PluginRequestError::InvalidValue(name()));
            }
        }
        (ParamKind::Choice { choices }, PluginParam::Choice(choice)) => {
            if !choices.iter().any(|c| c == choice) {
                return Err(PluginRequestError::InvalidValue(name()));
            }
        }
        (ParamKind::Flag, PluginParam::Flag(_)) => {}
        (ParamKind::Locale, PluginParam::Locale(locale)) => {
            if !matches!(*locale, "ru" | "kk" | "en") {
                return Err(PluginRequestError::InvalidValue(name()));
            }
        }
        _ => return Err(PluginRequestError::WrongKind(name())),
    }
    Ok(())
}

/// A request buffer that either only counts (refusing early above `max`) or writes into a
/// buffer of the counted size.
struct Out {
    buf: Option<String>,
    len: usize,
    max: usize,
}

impl Out {
    fn counting(max: usize) -> Self {
        Self {
            buf: None,
            len: 0,
            max,
        }
    }
    fn writing(exact: usize, max: usize) -> Self {
        Self {
            buf: Some(String::with_capacity(exact)),
            len: 0,
            max,
        }
    }
    fn add(&mut self, n: usize) -> Result<(), PluginRequestError> {
        self.len = self
            .len
            .checked_add(n)
            .filter(|l| *l <= self.max)
            .ok_or(PluginRequestError::RequestTooLarge)?;
        Ok(())
    }
    fn lit(&mut self, s: &str) -> Result<(), PluginRequestError> {
        self.add(s.len())?;
        if let Some(b) = &mut self.buf {
            b.push_str(s);
        }
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<(), PluginRequestError> {
        self.add(json_len(s))?;
        if let Some(b) = &mut self.buf {
            push_json(b, s);
        }
        Ok(())
    }
    fn document(&mut self, bytes: &[u8]) -> Result<(), PluginRequestError> {
        let encoded = bytes
            .len()
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(PluginRequestError::RequestTooLarge)?;
        self.add(encoded + 2)?;
        if let Some(b) = &mut self.buf {
            b.push('"');
            STANDARD.encode_string(bytes, b);
            b.push('"');
        }
        Ok(())
    }
}

/// The length of `s` as a JSON string, quotes included, escaped as `serde_json` does.
fn json_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
}

fn push_json(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Writes `value` (the template; `args` placeholders replaced) as compact JSON with sorted
/// keys. Substituted values are written straight into the output and never rescanned.
fn emit(
    value: &Value,
    values: &[(&str, PluginParam<'_>)],
    out: &mut Out,
) -> Result<(), PluginRequestError> {
    match value {
        Value::Null => out.lit("null"),
        Value::Bool(b) => out.lit(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if !(n.is_u64() || n.is_i64()) {
                return Err(PluginRequestError::InvalidTemplate);
            }
            out.lit(&n.to_string())
        }
        Value::String(s) => {
            let name = s
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .map(|i| i.strip_suffix(":base64").unwrap_or(i));
            match name.and_then(|n| values.iter().find(|(v, _)| *v == n)) {
                Some((_, PluginParam::Document(bytes))) => out.document(bytes),
                Some((_, PluginParam::Flag(b))) => out.lit(if *b { "true" } else { "false" }),
                Some((
                    _,
                    PluginParam::Text(t) | PluginParam::Choice(t) | PluginParam::Locale(t),
                )) => out.string(t),
                None => out.string(s),
            }
        }
        Value::Array(items) => {
            out.lit("[")?;
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.lit(",")?;
                }
                emit(item, values, out)?;
            }
            out.lit("]")
        }
        Value::Object(map) => {
            out.lit("{")?;
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.lit(",")?;
                }
                out.string(key)?;
                out.lit(":")?;
                emit(item, values, out)?;
            }
            out.lit("}")
        }
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
