//! `[[operations]]` of `plugin.toml`: what the manual-tools window may offer of a plugin.
//!
//! An operation is not a name. It is a request template the *host* fills in (the plugin
//! never chooses the operation), the host functions the plugin may import for it, the
//! network it may reach and, for every use of a key, a **profile**: the kind of signature,
//! where the signed content comes from and the signature options the core will force. The
//! schema is described in `docs/design/plugins.md` (section "Operations") and
//! `docs/design/manual-plugins.md` (section 4.1).
//!
//! A plugin without `[[operations]]` has none ([`Manifest::operations`] is empty): the
//! manual window offers nothing of it. A manifest carrying operations needs
//! `min_core >=` [`operations_min_core`]; older cores refuse the table anyway
//! (`deny_unknown_fields` on the manifest).
//!
//! [`Manifest::operations`]: crate::Manifest::operations

use crate::manifest::{HttpPrefix, Localized};
use crate::{Capabilities, runtime};
use oncl_flows::capabilities::{
    AddedLine, CapabilityLine, KeyUseKind, NetworkLine, OperationConsent, ProfileFact, TsaFamily,
    XadesLevelKind,
};
use oncl_pdk::abi::{C14n, CmsOutput, Import, Placement, XadesLevel};
use semver::{BuildMetadata, Prerelease, Version};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

/// Most operations of one plugin.
pub const MAX_OPERATIONS: usize = 32;
/// Most `[[operations.params]]` of one operation.
pub const MAX_PARAMS: usize = 16;
/// Most `[[operations.uses.key]]` of one operation: one use of a key per operation (R9).
pub const MAX_KEY_USES: usize = 1;
/// Most URL prefixes of `uses.network`.
pub const MAX_NETWORK_URLS: usize = 8;
/// Most imports of `uses.imports`.
pub const MAX_IMPORTS: usize = 64;
/// The only valid `max_uses`: one use of the key per call of the manual window.
pub const MAX_USES: u8 = 1;
/// Longest `label`, in characters: it is shown framed as the plugin's own words.
pub const MAX_LABEL: usize = 80;
/// Longest request template, in bytes.
pub const MAX_REQUEST: usize = 16 * 1024;
/// Longest `max_bytes` of a `document` parameter, in bytes: the most whose base64 form and
/// a request template still fit [`runtime::MAX_TRANSFER`]; a larger document could never run.
pub const MAX_DOCUMENT_BYTES: u64 = (runtime::MAX_TRANSFER as u64 - MAX_REQUEST as u64) / 4 * 3;
/// Default `max_bytes` of a `document` parameter: 16 MiB.
pub const DEFAULT_DOCUMENT_BYTES: u64 = 16 << 20;
/// Longest `max_chars` of a `text` parameter.
pub const MAX_TEXT_CHARS: u32 = 65_536;
/// Default `max_chars` of a `text` parameter.
pub const DEFAULT_TEXT_CHARS: u32 = 256;
/// Most choices of a `choice` parameter.
pub const MAX_CHOICES: usize = 32;
/// Longest choice, in characters.
pub const MAX_CHOICE_CHARS: usize = 64;
/// Longest fixed XPath of a profile, in bytes.
pub const MAX_XPATH: usize = 1024;
/// Longest `max_chars` of a `text` parameter that is the source of an XPath (4 bytes a
/// character at most keep it within [`MAX_XPATH`]).
pub const MAX_XPATH_PARAM_CHARS: u32 = (MAX_XPATH / 4) as u32;
/// Most namespace bindings of an XML profile.
pub const MAX_NAMESPACES: usize = 16;

/// The `SignatureMethod` URIs a profile may fix (the ones the core signs with).
pub const SIGNATURE_METHODS: [&str; 3] = [
    "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
    "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
];
/// The `DigestMethod` URIs a profile may fix.
pub const DIGEST_METHODS: [&str; 3] = [
    "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
    "http://www.w3.org/2001/04/xmldsig-more#gost34311",
    "http://www.w3.org/2001/04/xmlenc#sha256",
];

/// The text a user gave for a `param:<name>` of a profile; `None` for a name without one.
pub type ParamValues<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The oldest core a package with `[[operations]]` may name in `min_core`.
pub fn operations_min_core() -> Version {
    Version {
        major: 0,
        minor: 1,
        patch: 0,
        pre: Prerelease::new("alpha.7").expect("a valid pre-release"),
        build: BuildMetadata::EMPTY,
    }
}

/// Why `[[operations]]` are refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
    /// More than [`MAX_OPERATIONS`].
    #[error("operations: more than {MAX_OPERATIONS}")]
    TooMany,
    /// `min_core` is older than [`operations_min_core`]: an older core cannot read them.
    #[error("operations need min_core {needed} or later, not {found}")]
    MinCore { needed: Version, found: Version },
    /// More than [`MAX_IMPORTS`] imports.
    #[error("operation {0:?}: more than {MAX_IMPORTS} imports")]
    TooManyImports(String),
    /// More than [`MAX_KEY_USES`] `[[operations.uses.key]]`.
    #[error("operation {0:?}: more than {MAX_KEY_USES} uses.key: an operation uses a key once")]
    TooManyKeyUses(String),
    /// `network = "none"` with an import or a profile that reaches the network.
    #[error("operation {operation:?}: network is `none` but {why}")]
    NetworkNeeded { operation: String, why: String },
    /// A name is not `^[a-z][a-z0-9-]{0,31}$`.
    #[error("operation name {0:?} is not 1 to 32 of a-z, 0-9 and `-`, starting with a letter")]
    Name(String),
    /// Two operations share a name.
    #[error("operation {0:?} is declared twice")]
    DuplicateName(String),
    /// `module` is not one of the plugin's `modules`.
    #[error("operation {operation:?}: module {module:?} is not one of the plugin's modules")]
    Module { operation: String, module: String },
    /// Neither `manual` nor `server`: nothing offers the operation.
    #[error("operation {0:?} is offered nowhere: set `manual` or `server`")]
    NotOffered(String),
    /// A label is blank, longer than [`MAX_LABEL`] or has control or bidirectional
    /// formatting characters.
    #[error("operation {operation:?}: label.{lang} {why}")]
    Label {
        operation: String,
        lang: &'static str,
        why: &'static str,
    },
    /// The request template is wrong.
    #[error("operation {operation:?}: request: {why}")]
    Request { operation: String, why: String },
    /// A parameter is wrong.
    #[error("operation {operation:?}: param {param:?}: {why}")]
    Param {
        operation: String,
        param: String,
        why: String,
    },
    /// More than [`MAX_PARAMS`] parameters.
    #[error("operation {0:?}: more than {MAX_PARAMS} params")]
    TooManyParams(String),
    /// An import name is not a host function of the ABI.
    #[error("operation {operation:?}: imports: {name:?} is not a host function")]
    UnknownImport { operation: String, name: String },
    /// An import is listed twice.
    #[error("operation {operation:?}: imports: {name} is listed twice")]
    DuplicateImport {
        operation: String,
        name: &'static str,
    },
    /// An import the manual window never allows (dialogs, files, key stores, windows).
    #[error("operation {operation:?}: imports: {name} is not allowed in the manual window")]
    ForbiddenImport {
        operation: String,
        name: &'static str,
    },
    /// An import whose capability the manifest does not declare.
    #[error("operation {operation:?}: imports: {name} needs a capability the manifest lacks")]
    UndeclaredImport {
        operation: String,
        name: &'static str,
    },
    /// An `interactive` import is not a key choice, or is not among the imports.
    #[error("operation {operation:?}: interactive: {name} is not a key-choice import in imports")]
    Interactive { operation: String, name: String },
    /// A `network` prefix is wrong or not under `capabilities.http`.
    #[error("operation {operation:?}: network: {why}")]
    Network { operation: String, why: String },
    /// A key-signing import without a `[[operations.uses.key]]` of its kind, or the other
    /// way round.
    #[error("operation {operation:?}: {why}")]
    KeyUse { operation: String, why: String },
    /// A key use is wrong: `max_uses`, `content`, a kind rule.
    #[error("operation {operation:?}: uses.key[{index}]: {why}")]
    KeyContent {
        operation: String,
        index: usize,
        why: String,
    },
    /// A profile is wrong: an unknown or forbidden field, a value out of range.
    #[error("operation {operation:?}: uses.key[{index}].profile: {why}")]
    Profile {
        operation: String,
        index: usize,
        why: String,
    },
}

/// A checked `[[operations]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    name: String,
    module: String,
    manual: bool,
    server: bool,
    request: String,
    label: Localized,
    params: Vec<Param>,
    uses: Uses,
}

impl Operation {
    /// `^[a-z][a-z0-9-]{0,31}$`, unique in the manifest.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The module (of the plugin's `modules`) the request goes to.
    pub fn module(&self) -> &str {
        &self.module
    }
    /// Whether the manual window offers it.
    pub fn manual(&self) -> bool {
        self.manual
    }
    /// Whether a server or CLI grant may name it.
    pub fn server(&self) -> bool {
        self.server
    }
    /// The request template as written: JSON with `"{param}"` / `"{param:base64}"` string
    /// values inside `args` (see [`Param`]); the host builds the request from the parsed
    /// JSON, never by pasting text.
    pub fn request_template(&self) -> &str {
        &self.request
    }
    /// The plugin author's words for the operation: untrusted display text, to be shown
    /// framed as the plugin's own.
    pub fn label(&self) -> &Localized {
        &self.label
    }
    /// The typed parameters, in the manifest's order.
    pub fn params(&self) -> &[Param] {
        &self.params
    }
    /// What the operation may use.
    pub fn uses(&self) -> &Uses {
        &self.uses
    }
    /// Whether any use of a key takes `content = "derived"`.
    pub fn is_derived(&self) -> bool {
        self.uses
            .key
            .iter()
            .any(|k| matches!(k.content, Content::Derived))
    }
    /// Whether this host can run the operation. `derived` content needs the plan-run of
    /// stage MP3b, which does not exist yet: such an operation parses but is refused
    /// here. Hosts MUST NOT run an operation for which this is `false`.
    pub fn runnable(&self) -> bool {
        !self.is_derived()
    }

    /// What the install consent says of the operation: its name, and lines built only from
    /// checked fields (the kind of key use and the profile the core forces, the network,
    /// the `server` flag, and, for an update, why it is `added`: new or wider than the
    /// installed one). The label is the plugin's own text: it goes into
    /// [`OperationConsent::label`] and never into a line.
    pub fn consent(&self, added: Option<&AddedOperation>) -> OperationConsent {
        let mut lines = Vec::new();
        if let Some(added) = added {
            for reason in &added.reasons {
                lines.push(CapabilityLine::Added(match reason {
                    AddedReason::New => AddedLine::New,
                    AddedReason::Changed => AddedLine::Changed,
                    AddedReason::KeyUse => AddedLine::KeyUse,
                    AddedReason::Imports(names) => {
                        AddedLine::Imports(names.iter().map(|n| (*n).to_owned()).collect())
                    }
                    AddedReason::Network => AddedLine::Network,
                    AddedReason::Server => AddedLine::Server,
                }));
            }
        }
        if self.uses.key.is_empty() {
            lines.push(CapabilityLine::NoKey);
        }
        for key in &self.uses.key {
            lines.push(CapabilityLine::KeyUse(match key.kind {
                KeyKind::Raw => KeyUseKind::Raw,
                KeyKind::Cms => KeyUseKind::Cms,
                KeyKind::CmsEx => KeyUseKind::CmsEx,
                KeyKind::Xml => KeyUseKind::Xml,
                KeyKind::XmlEx => KeyUseKind::XmlEx,
                KeyKind::Xades => KeyUseKind::Xades,
            }));
            let facts = key.profile.facts();
            if !facts.is_empty() {
                lines.push(CapabilityLine::KeyProfile(facts));
            }
        }
        lines.push(CapabilityLine::OperationNetwork(match &self.uses.network {
            Network::None => NetworkLine::None,
            Network::Pki => NetworkLine::Pki,
            Network::Urls(urls) => {
                NetworkLine::Urls(urls.iter().map(ToString::to_string).collect())
            }
        }));
        lines.push(CapabilityLine::OperationServer(self.server));
        OperationConsent {
            name: self.name.clone(),
            lines,
            label: [
                self.label.ru.clone(),
                self.label.kk.clone(),
                self.label.en.clone(),
            ],
        }
    }

    /// The canonical encoding of the whole declaration but the label: what a later change
    /// is detected by ([`Manifest::added_over`](crate::Manifest::added_over)). Imports and
    /// network prefixes are encoded as sorted sets, the rest in the manifest's order. The
    /// request is the template as written, byte for byte.
    pub fn canonical(&self) -> Vec<u8> {
        let mut w = Writer::new(b"ONCLOP1\0");
        w.str(&self.name);
        w.str(&self.module);
        w.bool(self.manual);
        w.bool(self.server);
        w.str(&self.request);
        w.u32(self.params.len() as u32);
        for p in &self.params {
            p.encode(&mut w);
        }
        self.uses.encode_widening(&mut w);
        w.out
    }

    /// Whether `new` differs from `self` in more than being narrower: another module or
    /// request (JSON compared as JSON, so spacing does not count), a parameter added,
    /// changed in kind or widened (a larger limit, more choices), or `manual` newly set.
    fn changed_beyond_narrowing(&self, new: &Operation) -> bool {
        let template = |o: &Operation| serde_json::from_str::<serde_json::Value>(&o.request).ok();
        self.module != new.module
            || template(self) != template(new)
            || (new.manual && !self.manual)
            || new.params.len() != self.params.len()
            || !new
                .params
                .iter()
                .all(|n| self.params.iter().any(|o| n.within(o)))
    }

    /// SHA-256 of [`canonical`](Self::canonical).
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }
}

/// A typed parameter of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// `^[a-z][a-z0-9_]{0,31}$`, unique in the operation.
    pub name: String,
    /// Its type.
    pub kind: ParamKind,
}

impl Param {
    /// Whether `self` asks for no more than `old`: the same name and kind, and limits and
    /// choices not larger.
    fn within(&self, old: &Param) -> bool {
        self.name == old.name
            && match (&self.kind, &old.kind) {
                (ParamKind::Document { max_bytes: n }, ParamKind::Document { max_bytes: o }) => {
                    n <= o
                }
                (ParamKind::Text { max_chars: n }, ParamKind::Text { max_chars: o }) => n <= o,
                (ParamKind::Choice { choices: n }, ParamKind::Choice { choices: o }) => {
                    n.iter().all(|c| o.contains(c))
                }
                (ParamKind::Flag, ParamKind::Flag) | (ParamKind::Locale, ParamKind::Locale) => true,
                _ => false,
            }
    }

    fn encode(&self, w: &mut Writer) {
        w.str(&self.name);
        match &self.kind {
            ParamKind::Document { max_bytes } => {
                w.u8(1);
                w.u64(*max_bytes);
            }
            ParamKind::Text { max_chars } => {
                w.u8(2);
                w.u32(*max_chars);
            }
            ParamKind::Choice { choices } => {
                w.u8(3);
                w.u32(choices.len() as u32);
                for c in choices {
                    w.str(c);
                }
            }
            ParamKind::Flag => w.u8(4),
            ParamKind::Locale => w.u8(5),
        }
    }
}

/// The type of a [`Param`], and with it the placeholder in the request template:
/// `document` is `"{name:base64}"` (a JSON string, the bytes in standard base64); `text`,
/// `choice` and `locale` are `"{name}"` (a JSON string); `flag` is `"{name}"` (a JSON
/// boolean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamKind {
    /// A file the user picks, frozen by the host; at most `max_bytes` bytes.
    Document { max_bytes: u64 },
    /// Text the user types; at most `max_chars` characters.
    Text { max_chars: u32 },
    /// One of `choices`.
    Choice { choices: Vec<String> },
    /// A yes/no.
    Flag,
    /// The interface language (`ru`, `kk` or `en`).
    Locale,
}

/// What an operation may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uses {
    imports: Vec<Import>,
    network: Network,
    interactive: Vec<Import>,
    key: Vec<KeyUse>,
}

impl Uses {
    /// The host functions the operation may import (a subset of the plugin's own imports,
    /// checked again when the package is compiled).
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }
    /// The network the operation may reach.
    pub fn network(&self) -> &Network {
        &self.network
    }
    /// The key-choice imports the host answers for the key the user bound.
    pub fn interactive(&self) -> &[Import] {
        &self.interactive
    }
    /// Every use of a key: at most [`MAX_KEY_USES`], each exactly once.
    pub fn keys(&self) -> &[KeyUse] {
        &self.key
    }

    fn encode_widening(&self, w: &mut Writer) {
        let mut names: Vec<&str> = self.imports.iter().map(Import::name).collect();
        names.sort_unstable();
        w.u32(names.len() as u32);
        for n in names {
            w.str(n);
        }
        let mut names: Vec<&str> = self.interactive.iter().map(Import::name).collect();
        names.sort_unstable();
        w.u32(names.len() as u32);
        for n in names {
            w.str(n);
        }
        self.network.encode(w);
        w.u32(self.key.len() as u32);
        for k in &self.key {
            w.bytes(&k.declared_canonical());
        }
    }
}

/// `uses.network`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// No request leaves the machine.
    None,
    /// The PKI hosts of the core only ([`crate::NCA_PKI_HOSTS`]).
    Pki,
    /// These URL prefixes, each under `capabilities.http`.
    Urls(Vec<HttpPrefix>),
}

impl Network {
    fn encode(&self, w: &mut Writer) {
        match self {
            Network::None => w.u8(0),
            Network::Pki => w.u8(1),
            Network::Urls(urls) => {
                w.u8(2);
                let mut texts: Vec<String> = urls.iter().map(ToString::to_string).collect();
                texts.sort_unstable();
                w.u32(texts.len() as u32);
                for t in &texts {
                    w.str(t);
                }
            }
        }
    }

    /// Whether `self` reaches nothing `old` does not.
    fn within(&self, old: &Network) -> bool {
        match (self, old) {
            (Network::None, _) => true,
            (Network::Pki, Network::Pki) => true,
            (Network::Urls(new), Network::Urls(old)) => {
                new.iter().all(|n| old.iter().any(|o| o.covers(n)))
            }
            _ => false,
        }
    }
}

/// The signature kind of a key use, and with it the host function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// `keys_sign_raw`.
    Raw,
    /// `keys_sign_cms`.
    Cms,
    /// `keys_sign_cms_ex`.
    CmsEx,
    /// `keys_sign_xml`.
    Xml,
    /// `keys_sign_xml_ex`.
    XmlEx,
    /// `keys_sign_xades`.
    Xades,
}

impl KeyKind {
    /// The name in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::Raw => "raw",
            KeyKind::Cms => "cms",
            KeyKind::CmsEx => "cms_ex",
            KeyKind::Xml => "xml",
            KeyKind::XmlEx => "xml_ex",
            KeyKind::Xades => "xades",
        }
    }
    /// The host function that signs.
    pub fn import(self) -> Import {
        match self {
            KeyKind::Raw => Import::KeysSignRaw,
            KeyKind::Cms => Import::KeysSignCms,
            KeyKind::CmsEx => Import::KeysSignCmsEx,
            KeyKind::Xml => Import::KeysSignXml,
            KeyKind::XmlEx => Import::KeysSignXmlEx,
            KeyKind::Xades => Import::KeysSignXades,
        }
    }
    fn tag(self) -> u8 {
        match self {
            KeyKind::Raw => 1,
            KeyKind::Cms => 2,
            KeyKind::CmsEx => 3,
            KeyKind::Xml => 4,
            KeyKind::XmlEx => 5,
            KeyKind::Xades => 6,
        }
    }
    fn of_import(import: Import) -> Option<KeyKind> {
        [
            KeyKind::Raw,
            KeyKind::Cms,
            KeyKind::CmsEx,
            KeyKind::Xml,
            KeyKind::XmlEx,
            KeyKind::Xades,
        ]
        .into_iter()
        .find(|k| k.import() == import)
    }
    fn is_xml(self) -> bool {
        matches!(self, KeyKind::Xml | KeyKind::XmlEx | KeyKind::Xades)
    }
}

/// Where the signed content comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// `param:<name>`: the bytes of a parameter the user supplied, frozen by the host
    /// before the request is built. The only content the host runs today.
    Bound(String),
    /// `derived`: bytes the plugin computes. Parsed, but **not runnable** until stage MP3b
    /// ([`Operation::runnable`] is `false`); never with `raw` or a digest input.
    Derived,
}

/// One use of a key: [`MAX_USES`] time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUse {
    kind: KeyKind,
    content: Content,
    profile: Profile,
}

impl KeyUse {
    /// The kind.
    pub fn kind(&self) -> KeyKind {
        self.kind
    }
    /// Where the content comes from.
    pub fn content(&self) -> &Content {
        &self.content
    }
    /// The options the core forces on the plugin's call.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    /// Always [`MAX_USES`].
    pub fn max_uses(&self) -> u8 {
        MAX_USES
    }

    fn declared_canonical(&self) -> Vec<u8> {
        let mut w = Writer::new(b"ONCLKU1\0");
        w.u8(self.kind.tag());
        match &self.content {
            Content::Bound(p) => {
                w.u8(1);
                w.str(p);
            }
            Content::Derived => w.u8(2),
        }
        w.bytes(
            &self
                .profile
                .encode(self.kind, None)
                .expect("no params resolved"),
        );
        w.out
    }

    /// The canonical encoding of the options of this use: the input of `options_sha256` of
    /// the `PluginUse` ticket. Every field of the kind's profile is written, defaults
    /// included, so an unset field and its explicit default encode alike. A field that
    /// names a parameter (`param:<name>`) is written as the value `values` gives for it,
    /// as if fixed; `None` if `values` has none.
    ///
    /// The encoding (all integers big-endian): the magic `ONCLOPT1\0`, the kind (1 raw, 2
    /// cms, 3 cms_ex, 4 xml, 5 xml_ex, 6 xades), then the kind's fields in the order of the
    /// profile struct, each as `field-id u8` and a self-delimiting value: `bool` one byte
    /// 0/1; an enum one byte (its position in the struct's documentation); a string `u32`
    /// length and its UTF-8 bytes; an optional `0` or `1` and the value; a list `u32`
    /// count and its items; a source `0` none, `1` fixed text. The set and order of fields
    /// are fixed per kind, so no two different profiles encode alike.
    pub fn options_canonical(&self, values: ParamValues<'_>) -> Option<Vec<u8>> {
        self.profile.encode(self.kind, Some(values))
    }

    /// SHA-256 of [`options_canonical`](Self::options_canonical).
    pub fn options_sha256(&self, values: ParamValues<'_>) -> Option<[u8; 32]> {
        self.options_canonical(values)
            .map(|bytes| Sha256::digest(bytes).into())
    }
}

/// A string of a profile: a fixed text or a parameter the user fills in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A constant XPath (it starts with `/`).
    Fixed(String),
    /// `param:<name>`: the text of a `text` parameter, shown to the user in the consent.
    Param(String),
}

impl TryFrom<String> for Source {
    type Error = String;
    fn try_from(text: String) -> Result<Self, String> {
        if let Some(name) = text.strip_prefix("param:") {
            return Ok(Source::Param(name.to_owned()));
        }
        match Source::check_value(&text) {
            Ok(()) => Ok(Source::Fixed(text)),
            Err(why) => Err(format!(
                "{text:?} is neither `param:<name>` nor an XPath: {why}"
            )),
        }
    }
}

impl Source {
    /// Whether `text` may be an XPath of a profile, fixed or typed by the user: absolute (it
    /// starts with `/`), at most [`MAX_XPATH`] bytes, without control, bidirectional or other
    /// invisible format characters (it is drawn in the trusted part of the consent).
    /// Whoever resolves a `param:` source MUST check the user's text with this before
    /// [`KeyUse::options_canonical`], which refuses a text that fails it.
    ///
    /// # Errors
    ///
    /// What is wrong.
    pub fn check_value(text: &str) -> Result<(), &'static str> {
        if !text.starts_with('/') {
            Err("it is not absolute (it must start with `/`)")
        } else if text.len() > MAX_XPATH {
            Err("it is too long")
        } else if text.chars().any(|c| c.is_control() || is_invisible(c)) {
            Err("it has control, bidirectional or invisible characters")
        } else {
            Ok(())
        }
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Source::try_from(text).map_err(serde::de::Error::custom)
    }
}

/// A time-stamp of a profile (`Custom` is never allowed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Timestamp {
    /// None. Tag 0.
    #[default]
    None,
    /// The basics TSA. Tag 1.
    Basics,
    /// Kalkan's default TSA. Tag 2.
    Kalkan,
}

/// `cosign`: only `never` exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoSign {
    /// The content is signed as it is, even if it is a CMS. Tag 0.
    #[default]
    Never,
}

/// What a `cms_ex` signature signs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentForm {
    /// The document's bytes. Tag 0.
    #[default]
    Data,
    /// The document's digest, computed by the core: only for bound content. Tag 1.
    Digest,
}

/// The certificates of a `cms_ex` signature (`Extra` is never allowed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Certificates {
    /// The signer's. Tag 0.
    #[default]
    Signer,
    /// The key's chain. Tag 1.
    Chain,
}

/// The signingTime of a `cms_ex` signature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningTime {
    /// The core's clock, encoded as the core does by default. Tag 0.
    #[default]
    Now,
    /// No signingTime attribute. Tag 1.
    None,
}

impl Timestamp {
    fn tag(self) -> u8 {
        match self {
            Timestamp::None => 0,
            Timestamp::Basics => 1,
            Timestamp::Kalkan => 2,
        }
    }
}

impl ContentForm {
    fn tag(self) -> u8 {
        match self {
            ContentForm::Data => 0,
            ContentForm::Digest => 1,
        }
    }
}

impl Certificates {
    fn tag(self) -> u8 {
        match self {
            Certificates::Signer => 0,
            Certificates::Chain => 1,
        }
    }
}

impl SigningTime {
    fn tag(self) -> u8 {
        match self {
            SigningTime::Now => 0,
            SigningTime::None => 1,
        }
    }
}

impl XadesTsa {
    fn tag(self) -> u8 {
        match self {
            XadesTsa::Basics => 0,
            XadesTsa::Kalkan => 1,
        }
    }
}

fn yes() -> bool {
    true
}

/// `keys_sign_cms`. No field outside this list exists: the plugin cannot reach anything
/// else.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CmsProfile {
    /// Put the content into the CMS. Field 1; default `false`.
    pub attached: bool,
    /// Field 2; default none; `basics` only (the call's time-stamp is the basics TSA).
    pub timestamp: Timestamp,
}

impl Default for CmsProfile {
    fn default() -> Self {
        CmsProfile {
            attached: false,
            timestamp: Timestamp::None,
        }
    }
}

/// `keys_sign_cms_ex`. Never allowed (absent from the profile, so the call must leave
/// them as the core's default): `cosign` other than `never`, `attrs.extra`,
/// `econtent_type`, `digest`, `timestamp = Custom`, `certificates = Extra`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CmsExProfile {
    /// Field 1; default `false`; not with `content_form = "digest"`.
    pub encapsulate: bool,
    /// Field 2; default `never`, the only value.
    pub cosign: CoSign,
    /// Field 3; default `data`.
    pub content_form: ContentForm,
    /// Field 4; default none.
    pub timestamp: Timestamp,
    /// Field 5; default `signer`.
    pub certificates: Certificates,
    /// Field 6; default `der`.
    pub output: CmsOutput,
    /// Field 7: the contentType attribute; default `true`.
    #[serde(default = "yes")]
    pub content_type: bool,
    /// Field 8: the messageDigest attribute; default `true`.
    #[serde(default = "yes")]
    pub message_digest: bool,
    /// Field 9: signingCertificateV2; default `true`.
    #[serde(default = "yes")]
    pub signing_certificate_v2: bool,
    /// Field 10; default `now`.
    pub signing_time: SigningTime,
}

impl Default for CmsExProfile {
    fn default() -> Self {
        CmsExProfile {
            encapsulate: false,
            cosign: CoSign::Never,
            content_form: ContentForm::Data,
            timestamp: Timestamp::None,
            certificates: Certificates::Signer,
            output: CmsOutput::Der,
            content_type: true,
            message_digest: true,
            signing_certificate_v2: true,
            signing_time: SigningTime::Now,
        }
    }
}

/// `keys_sign_xml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XmlProfile {
    /// Field 1: the element to sign; absent: the whole document.
    pub element: Option<Source>,
    /// Field 2: where the signature goes; only with `element`.
    pub parent: Option<Source>,
}

/// A namespace binding of an XPath.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    /// The prefix.
    pub prefix: String,
    /// The URI.
    pub uri: String,
}

/// The output form of an XML signature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum XmlOutputProfile {
    /// The input with the signature spliced in. Tag 0.
    #[default]
    AsIs,
    /// As a JDK `Transformer` writes it. Tag 1.
    Serialize {
        /// Write the declaration.
        declaration: bool,
        /// With `standalone="no"`.
        standalone_no: bool,
        /// No whitespace at either end.
        trim: bool,
    },
}

/// `keys_sign_xml_ex`. Never allowed (absent): `transforms`, `signature_id`,
/// `signing_time_object`, a `signature_method` or `digest_method` outside
/// [`SIGNATURE_METHODS`] / [`DIGEST_METHODS`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XmlExProfile {
    /// Field 1.
    pub element: Option<Source>,
    /// Field 2; only with `element` and `placement = "parent"`.
    pub parent: Option<Source>,
    /// Field 3; default `document_element`; `parent` needs `parent`.
    pub placement: Placement,
    /// Field 4: prefix → URI bindings of the XPaths.
    pub namespaces: Vec<Namespace>,
    /// Field 5.
    pub other_prefix_uri: Option<String>,
    /// Field 6; absent: Kalkan's for the certificate.
    pub signature_method: Option<String>,
    /// Field 7; absent: the one paired with the signature method.
    pub digest_method: Option<String>,
    /// Field 8; absent: Kalkan's. The abi's names (`inclusive`, `exclusive`, …).
    pub c14n: Option<C14n>,
    /// Field 9; default `false`.
    pub strip_whitespace: bool,
    /// Field 10; absent: as the core's default.
    pub base64_line_breaks: Option<bool>,
    /// Field 11; default `as_is`.
    pub output: XmlOutputProfile,
}

/// The TSA of a XAdES profile (`Custom` is never allowed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XadesTsa {
    /// The basics TSA. Tag 0.
    #[default]
    Basics,
    /// Kalkan's. Tag 1.
    Kalkan,
}

/// `keys_sign_xades`. Never allowed (absent): `chain` (the call must send none),
/// a custom TSA, a method URI outside the known lists.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XadesProfile {
    /// Field 1; default `b`.
    pub level: XadesLevel,
    /// Field 2; default `basics`.
    pub tsa: XadesTsa,
    /// Field 3.
    pub signature_method: Option<String>,
    /// Field 4.
    pub digest_method: Option<String>,
}

impl Default for XadesProfile {
    fn default() -> Self {
        XadesProfile {
            level: XadesLevel::B,
            tsa: XadesTsa::Basics,
            signature_method: None,
            digest_method: None,
        }
    }
}

/// The options profile of a key use, by kind. `raw` has none: nothing but the content is
/// signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// `raw`.
    Raw,
    /// `cms`.
    Cms(CmsProfile),
    /// `cms_ex`.
    CmsEx(CmsExProfile),
    /// `xml`.
    Xml(XmlProfile),
    /// `xml_ex`.
    XmlEx(XmlExProfile),
    /// `xades`.
    Xades(XadesProfile),
}

impl Profile {
    /// The profile in words: what the core forces on the call, as [`ProfileFact`]s.
    fn facts(&self) -> Vec<ProfileFact> {
        let timestamp = |t: Timestamp| match t {
            Timestamp::None => ProfileFact::NoTimestamp,
            Timestamp::Basics => ProfileFact::Timestamp(TsaFamily::Basics),
            Timestamp::Kalkan => ProfileFact::Timestamp(TsaFamily::Kalkan),
        };
        let attached = |a: bool| {
            if a {
                ProfileFact::Attached
            } else {
                ProfileFact::Detached
            }
        };
        let element = |e: &Option<Source>| match e {
            None => ProfileFact::XmlWholeDocument,
            Some(Source::Fixed(xpath)) => ProfileFact::XmlElement(xpath.clone()),
            Some(Source::Param(_)) => ProfileFact::XmlElementParam,
        };
        match self {
            Profile::Raw => Vec::new(),
            Profile::Cms(p) => vec![attached(p.attached), timestamp(p.timestamp)],
            Profile::CmsEx(p) => {
                let mut facts = vec![attached(p.encapsulate)];
                if p.content_form == ContentForm::Digest {
                    facts.push(ProfileFact::DigestOnly);
                }
                facts.push(timestamp(p.timestamp));
                if p.certificates == Certificates::Chain {
                    facts.push(ProfileFact::ChainCertificates);
                }
                if p.signing_time == SigningTime::None {
                    facts.push(ProfileFact::NoSigningTime);
                }
                facts
            }
            Profile::Xml(p) => vec![element(&p.element)],
            Profile::XmlEx(p) => vec![element(&p.element)],
            Profile::Xades(p) => {
                let tsa = match p.tsa {
                    XadesTsa::Basics => TsaFamily::Basics,
                    XadesTsa::Kalkan => TsaFamily::Kalkan,
                };
                match p.level {
                    XadesLevel::B => vec![
                        ProfileFact::Xades(XadesLevelKind::B),
                        ProfileFact::NoTimestamp,
                    ],
                    XadesLevel::T => vec![
                        ProfileFact::Xades(XadesLevelKind::T),
                        ProfileFact::Timestamp(tsa),
                    ],
                    XadesLevel::Lt => vec![
                        ProfileFact::Xades(XadesLevelKind::Lt),
                        ProfileFact::Timestamp(tsa),
                    ],
                }
            }
        }
    }

    fn encode(&self, kind: KeyKind, values: Option<ParamValues<'_>>) -> Option<Vec<u8>> {
        let mut w = Writer::new(b"ONCLOPT1\0");
        w.u8(kind.tag());
        let src = |w: &mut Writer, id: u8, s: &Option<Source>| -> Option<()> {
            w.u8(id);
            match s {
                None => w.u8(0),
                Some(Source::Fixed(text)) => {
                    w.u8(1);
                    w.str(text);
                }
                Some(Source::Param(name)) => match values {
                    // Resolved: as if fixed, so a ticket's options hash is the declared
                    // profile's with the user's text filled in.
                    Some(values) => {
                        let text = values(name)?;
                        Source::check_value(&text).ok()?;
                        w.u8(1);
                        w.str(&text);
                    }
                    None => {
                        w.u8(2);
                        w.str(name);
                    }
                },
            }
            Some(())
        };
        match self {
            Profile::Raw => {}
            Profile::Cms(p) => {
                w.u8(1);
                w.bool(p.attached);
                w.u8(2);
                w.u8(p.timestamp.tag());
            }
            Profile::CmsEx(p) => {
                w.u8(1);
                w.bool(p.encapsulate);
                w.u8(2);
                w.u8(0);
                w.u8(3);
                w.u8(p.content_form.tag());
                w.u8(4);
                w.u8(p.timestamp.tag());
                w.u8(5);
                w.u8(p.certificates.tag());
                w.u8(6);
                w.u8(match p.output {
                    CmsOutput::Der => 0,
                    CmsOutput::Base64 => 1,
                    CmsOutput::Pem => 2,
                });
                w.u8(7);
                w.bool(p.content_type);
                w.u8(8);
                w.bool(p.message_digest);
                w.u8(9);
                w.bool(p.signing_certificate_v2);
                w.u8(10);
                w.u8(p.signing_time.tag());
            }
            Profile::Xml(p) => {
                src(&mut w, 1, &p.element)?;
                src(&mut w, 2, &p.parent)?;
            }
            Profile::XmlEx(p) => {
                src(&mut w, 1, &p.element)?;
                src(&mut w, 2, &p.parent)?;
                w.u8(3);
                w.u8(match p.placement {
                    Placement::DocumentElement => 0,
                    Placement::FirstChildOfDocument => 1,
                    Placement::Parent => 2,
                });
                w.u8(4);
                w.u32(p.namespaces.len() as u32);
                for ns in &p.namespaces {
                    w.str(&ns.prefix);
                    w.str(&ns.uri);
                }
                w.u8(5);
                w.opt_str(p.other_prefix_uri.as_deref());
                w.u8(6);
                w.opt_str(p.signature_method.as_deref());
                w.u8(7);
                w.opt_str(p.digest_method.as_deref());
                w.u8(8);
                match p.c14n {
                    None => w.u8(0),
                    Some(c) => w.u8(1 + match c {
                        C14n::Inclusive => 0,
                        C14n::InclusiveWithComments => 1,
                        C14n::Exclusive => 2,
                        C14n::ExclusiveWithComments => 3,
                    }),
                }
                w.u8(9);
                w.bool(p.strip_whitespace);
                w.u8(10);
                match p.base64_line_breaks {
                    None => w.u8(0),
                    Some(b) => w.u8(1 + u8::from(b)),
                }
                w.u8(11);
                match p.output {
                    XmlOutputProfile::AsIs => w.u8(0),
                    XmlOutputProfile::Serialize {
                        declaration,
                        standalone_no,
                        trim,
                    } => {
                        w.u8(1);
                        w.bool(declaration);
                        w.bool(standalone_no);
                        w.bool(trim);
                    }
                }
            }
            Profile::Xades(p) => {
                w.u8(1);
                w.u8(match p.level {
                    XadesLevel::B => 0,
                    XadesLevel::T => 1,
                    XadesLevel::Lt => 2,
                });
                w.u8(2);
                w.u8(p.tsa.tag());
                w.u8(3);
                w.opt_str(p.signature_method.as_deref());
                w.u8(4);
                w.opt_str(p.digest_method.as_deref());
            }
        }
        Some(w.out)
    }

    /// Whether the signature asks a time-stamp authority.
    fn needs_network(&self) -> bool {
        match self {
            Profile::Cms(p) => p.timestamp != Timestamp::None,
            Profile::CmsEx(p) => p.timestamp != Timestamp::None,
            Profile::Xades(p) => p.level != XadesLevel::B,
            _ => false,
        }
    }

    /// The names of the parameters the profile reads.
    fn params(&self) -> Vec<&str> {
        fn sources<'a>(a: &'a Option<Source>, b: &'a Option<Source>) -> Vec<&'a str> {
            [a, b]
                .into_iter()
                .filter_map(|s| match s {
                    Some(Source::Param(name)) => Some(name.as_str()),
                    _ => None,
                })
                .collect()
        }
        match self {
            Profile::Xml(p) => sources(&p.element, &p.parent),
            Profile::XmlEx(p) => sources(&p.element, &p.parent),
            _ => Vec::new(),
        }
    }
}

/// The writer of the canonical encodings.
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new(magic: &[u8]) -> Writer {
        Writer {
            out: magic.to_vec(),
        }
    }
    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    fn bool(&mut self, v: bool) {
        self.out.push(u8::from(v));
    }
    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.out.extend_from_slice(v);
    }
    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
    fn opt_str(&mut self, v: Option<&str>) {
        match v {
            None => self.u8(0),
            Some(v) => {
                self.u8(1);
                self.str(v);
            }
        }
    }
}

// ---- the TOML as written ----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawOperation {
    name: String,
    module: String,
    #[serde(default)]
    manual: bool,
    #[serde(default)]
    server: bool,
    request: String,
    label: Localized,
    #[serde(default)]
    params: Vec<RawParam>,
    #[serde(default)]
    uses: RawUses,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParam {
    name: String,
    kind: RawParamKind,
    max_bytes: Option<u64>,
    max_chars: Option<u32>,
    choices: Option<Vec<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawParamKind {
    Document,
    Text,
    Choice,
    Flag,
    Locale,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawUses {
    imports: Vec<String>,
    network: RawNetwork,
    interactive: Vec<String>,
    key: Vec<RawKeyUse>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNetwork {
    Word(String),
    Urls(Vec<String>),
}

impl Default for RawNetwork {
    fn default() -> Self {
        RawNetwork::Word("none".to_owned())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyUse {
    kind: KeyKind,
    content: String,
    #[serde(default = "one")]
    max_uses: u64,
    #[serde(default)]
    profile: toml::Table,
}

fn one() -> u64 {
    1
}

/// `^[a-z][a-z0-9<extra>]{0,max-1}$`.
fn is_ident(text: &str, max: usize, extra: u8) -> bool {
    let b = text.as_bytes();
    (1..=max).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == extra)
}

/// Characters that can make a text read other than it is written or show nothing:
/// bidirectional formatting, the line and paragraph separators and the other format
/// characters (Unicode category Cf: zero-width, joiners, word joiner, BOM, soft hyphen,
/// interlinear annotation, language tags, musical formatting).
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn plain_text_problem(text: &str, max: usize) -> Option<&'static str> {
    if text.trim().is_empty() {
        Some("is empty")
    } else if text.chars().count() > max {
        Some("is too long")
    } else if text.trim() != text {
        Some("has leading or trailing whitespace")
    } else if text.chars().any(|c| c.is_control() || is_invisible(c)) {
        Some("has control, bidirectional or invisible characters")
    } else {
        None
    }
}

/// What the manual window makes of a host function named by an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportPolicy {
    /// May be listed in `uses.imports` (its capability declared).
    Allowed,
    /// Never: the manual window has no dialogs, files, key stores, page paths, state kept
    /// between calls, window or bundle control (design 3.5, 4.6, R6).
    Forbidden,
    /// A signing function: listed only with a `[[operations.uses.key]]` of its kind, whose
    /// profile the core enforces.
    NeedsProfile,
}

impl ImportPolicy {
    /// The policy for `import`. The match is exhaustive on purpose: a new host function does
    /// not compile until it is classified here.
    pub fn of(import: Import) -> ImportPolicy {
        use ImportPolicy::{Allowed, Forbidden, NeedsProfile};
        match import {
            Import::Log
            | Import::Now
            | Import::Random
            | Import::CertInfo
            | Import::KeysChoose
            | Import::KeysRelease
            | Import::HttpRequest
            | Import::ReplyDrop
            | Import::Hash
            | Import::CertDetails
            | Import::LocalTime
            | Import::Platform
            | Import::CaList
            | Import::CaIssuer
            | Import::KeysSelect
            | Import::KeysChain
            | Import::KeysTerminals
            | Import::TspStamp
            | Import::TspRequest
            | Import::OcspFetch
            | Import::CrlFetch
            | Import::CmsVerify
            | Import::XmlVerify
            | Import::HttpRequestEx
            | Import::CallLocale
            | Import::KeysFlowOpen
            | Import::KeysFlowPick
            | Import::KeysDescribe
            | Import::TokensScan
            | Import::PkixPath => Allowed,
            Import::KeysSignCms
            | Import::KeysSignRaw
            | Import::KeysSignXml
            | Import::KeysSignCmsEx
            | Import::KeysSignXmlEx
            | Import::KeysSignXades => NeedsProfile,
            Import::DialogMessage
            | Import::DialogConfirm
            | Import::DialogPassword
            | Import::DialogChoice
            | Import::DialogReader
            | Import::DialogCsr
            | Import::DialogImport
            | Import::FileOpen
            | Import::FileSave
            | Import::FileChoose
            | Import::FileOpenEx
            | Import::FileChooseKind
            | Import::PageFileRead
            | Import::PageFileWrite
            | Import::KeysOpen
            | Import::SettingsGet
            | Import::SettingsPut
            | Import::SharedGet
            | Import::SharedPut
            | Import::CoreModules
            | Import::CoreBundles
            | Import::CoreInstallBundle
            | Import::CoreOpenWindow
            | Import::KeystoreNewKey
            | Import::KeystoreInstallCert
            | Import::KeystoreChangePassword
            | Import::TokensIdCard
            | Import::DataRead
            | Import::DataDecode
            | Import::DataEncode
            | Import::DataSignCms
            | Import::DataSignXml
            | Import::DataSignRaw
            | Import::DataStamp
            | Import::DataPageRead => Forbidden,
        }
    }
}

/// Host functions that send a request over the network (or need the clock and revocation
/// data a request fetches): they need `network` other than `none`.
fn reaches_network(import: Import) -> bool {
    matches!(
        import,
        Import::HttpRequest
            | Import::HttpRequestEx
            | Import::TspStamp
            | Import::TspRequest
            | Import::OcspFetch
            | Import::CrlFetch
            | Import::CmsVerify
            | Import::CaIssuer
            | Import::PkixPath
    )
}

fn is_key_choice(import: Import) -> bool {
    matches!(
        import,
        Import::KeysSelect | Import::KeysChoose | Import::KeysFlowOpen | Import::KeysFlowPick
    )
}

/// JSON that refuses an object with a repeated key: which of two readings a parser takes
/// (the first, the last) is not for a manifest to leave open.
struct StrictJson(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        use serde_json::{Map, Number, Value};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
                Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("a number JSON cannot hold"))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }
            fn visit_unit<E: Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictJson(v)) = seq.next_element()? {
                    items.push(v);
                }
                Ok(Value::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut out = Map::new();
                while let Some((k, StrictJson(v))) = map.next_entry::<String, StrictJson>()? {
                    if out.insert(k.clone(), v).is_some() {
                        return Err(A::Error::custom(format!("the key {k:?} is repeated")));
                    }
                }
                Ok(Value::Object(out))
            }
        }
        d.deserialize_any(V).map(StrictJson)
    }
}

impl RawOperation {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn check(
        self,
        modules: &[String],
        capabilities: &Capabilities,
    ) -> Result<Operation, OperationError> {
        let op = self.name.clone();
        if !is_ident(&self.name, 32, b'-') {
            return Err(OperationError::Name(self.name));
        }
        if !modules.contains(&self.module) {
            return Err(OperationError::Module {
                operation: op,
                module: self.module,
            });
        }
        if !self.manual && !self.server {
            return Err(OperationError::NotOffered(op));
        }
        for (lang, text) in [
            ("ru", &self.label.ru),
            ("kk", &self.label.kk),
            ("en", &self.label.en),
        ] {
            if let Some(why) = plain_text_problem(text, MAX_LABEL) {
                return Err(OperationError::Label {
                    operation: op,
                    lang,
                    why,
                });
            }
        }
        let params = self.check_params(&op)?;
        self.check_request(&op, &params)?;
        let uses = self.uses.check(&op, &params, capabilities)?;
        Ok(Operation {
            name: self.name,
            module: self.module,
            manual: self.manual,
            server: self.server,
            request: self.request,
            label: self.label,
            params,
            uses,
        })
    }

    fn check_params(&self, op: &str) -> Result<Vec<Param>, OperationError> {
        if self.params.len() > MAX_PARAMS {
            return Err(OperationError::TooManyParams(op.to_owned()));
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for raw in &self.params {
            let bad = |why: String| OperationError::Param {
                operation: op.to_owned(),
                param: raw.name.clone(),
                why,
            };
            if !is_ident(&raw.name, 32, b'_') {
                return Err(bad("the name is not `^[a-z][a-z0-9_]{0,31}$`".to_owned()));
            }
            if !seen.insert(raw.name.as_str()) {
                return Err(bad("is declared twice".to_owned()));
            }
            let stray = |field: &str, present: bool, kind: &str| {
                present
                    .then(|| bad(format!("`{field}` belongs to {kind} parameters only")))
                    .map_or(Ok(()), Err)
            };
            let kind = match raw.kind {
                RawParamKind::Document => {
                    stray("max_chars", raw.max_chars.is_some(), "text")?;
                    stray("choices", raw.choices.is_some(), "choice")?;
                    let max_bytes = raw.max_bytes.unwrap_or(DEFAULT_DOCUMENT_BYTES);
                    if !(1..=MAX_DOCUMENT_BYTES).contains(&max_bytes) {
                        return Err(bad(format!("max_bytes must be 1 to {MAX_DOCUMENT_BYTES}")));
                    }
                    ParamKind::Document { max_bytes }
                }
                RawParamKind::Text => {
                    stray("max_bytes", raw.max_bytes.is_some(), "document")?;
                    stray("choices", raw.choices.is_some(), "choice")?;
                    let max_chars = raw.max_chars.unwrap_or(DEFAULT_TEXT_CHARS);
                    if !(1..=MAX_TEXT_CHARS).contains(&max_chars) {
                        return Err(bad(format!("max_chars must be 1 to {MAX_TEXT_CHARS}")));
                    }
                    ParamKind::Text { max_chars }
                }
                RawParamKind::Choice => {
                    stray("max_bytes", raw.max_bytes.is_some(), "document")?;
                    stray("max_chars", raw.max_chars.is_some(), "text")?;
                    let choices = raw.choices.clone().unwrap_or_default();
                    if choices.is_empty() || choices.len() > MAX_CHOICES {
                        return Err(bad(format!("choices must list 1 to {MAX_CHOICES}")));
                    }
                    let mut distinct = HashSet::new();
                    for c in &choices {
                        if plain_text_problem(c, MAX_CHOICE_CHARS).is_some() {
                            return Err(bad(format!("choice {c:?} is not plain text")));
                        }
                        if !distinct.insert(c.as_str()) {
                            return Err(bad(format!("choice {c:?} is listed twice")));
                        }
                    }
                    ParamKind::Choice { choices }
                }
                RawParamKind::Flag | RawParamKind::Locale => {
                    stray("max_bytes", raw.max_bytes.is_some(), "document")?;
                    stray("max_chars", raw.max_chars.is_some(), "text")?;
                    stray("choices", raw.choices.is_some(), "choice")?;
                    if raw.kind == RawParamKind::Flag {
                        ParamKind::Flag
                    } else {
                        ParamKind::Locale
                    }
                }
            };
            out.push(Param {
                name: raw.name.clone(),
                kind,
            });
        }
        Ok(out)
    }

    /// The template is JSON `{"module": <module>, "method": <name>, "args": [...]}` where
    /// a string of `args` that has a `{` or `}` is exactly one placeholder of a declared
    /// parameter, and every parameter is used.
    fn check_request(&self, op: &str, params: &[Param]) -> Result<(), OperationError> {
        let bad = |why: String| OperationError::Request {
            operation: op.to_owned(),
            why,
        };
        if self.request.len() > MAX_REQUEST {
            return Err(bad(format!("longer than {MAX_REQUEST} bytes")));
        }
        let StrictJson(value) =
            serde_json::from_str(&self.request).map_err(|e| bad(format!("not JSON: {e}")))?;
        let serde_json::Value::Object(map) = &value else {
            return Err(bad("not a JSON object".to_owned()));
        };
        if map.len() != 3 {
            return Err(bad(
                "must have exactly `module`, `method` and `args`".to_owned()
            ));
        }
        match map.get("module") {
            Some(serde_json::Value::String(m)) if *m == self.module => {}
            _ => return Err(bad("`module` must be the operation's module".to_owned())),
        }
        match map.get("method") {
            Some(serde_json::Value::String(m))
                if plain_text_problem(m, 128).is_none() && !m.contains(['{', '}']) => {}
            _ => {
                return Err(bad("`method` must be plain text without braces".to_owned()));
            }
        }
        let Some(serde_json::Value::Array(args)) = map.get("args") else {
            return Err(bad("`args` must be an array".to_owned()));
        };
        let mut used = HashSet::new();
        let mut stack: Vec<&serde_json::Value> = args.iter().collect();
        while let Some(v) = stack.pop() {
            match v {
                serde_json::Value::String(s) if s.contains(['{', '}']) => {
                    let inner = s
                        .strip_prefix('{')
                        .and_then(|s| s.strip_suffix('}'))
                        .filter(|i| !i.contains(['{', '}']))
                        .ok_or_else(|| bad(format!("{s:?} is not exactly one placeholder")))?;
                    let (name, base64) = match inner.strip_suffix(":base64") {
                        Some(name) => (name, true),
                        None => (inner, false),
                    };
                    let param = params
                        .iter()
                        .find(|p| p.name == name)
                        .ok_or_else(|| bad(format!("placeholder {s:?} names no declared param")))?;
                    let is_doc = matches!(param.kind, ParamKind::Document { .. });
                    if is_doc != base64 {
                        return Err(bad(format!(
                            "placeholder {s:?}: only a document takes (and needs) `:base64`"
                        )));
                    }
                    used.insert(name);
                }
                serde_json::Value::Array(items) => stack.extend(items),
                serde_json::Value::Object(map) => {
                    if let Some(k) = map.keys().find(|k| k.contains(['{', '}'])) {
                        return Err(bad(format!("key {k:?} has braces")));
                    }
                    stack.extend(map.values());
                }
                _ => {}
            }
        }
        if let Some(p) = params.iter().find(|p| !used.contains(p.name.as_str())) {
            return Err(OperationError::Param {
                operation: op.to_owned(),
                param: p.name.clone(),
                why: "is not used in the request".to_owned(),
            });
        }
        Ok(())
    }
}

impl RawUses {
    fn check(
        self,
        op: &str,
        params: &[Param],
        caps: &Capabilities,
    ) -> Result<Uses, OperationError> {
        if self.imports.len() > MAX_IMPORTS {
            return Err(OperationError::TooManyImports(op.to_owned()));
        }
        let mut imports = Vec::new();
        for name in &self.imports {
            let import = Import::from_name(name).ok_or_else(|| OperationError::UnknownImport {
                operation: op.to_owned(),
                name: name.clone(),
            })?;
            let name = import.name();
            if imports.contains(&import) {
                return Err(OperationError::DuplicateImport {
                    operation: op.to_owned(),
                    name,
                });
            }
            if ImportPolicy::of(import) == ImportPolicy::Forbidden {
                return Err(OperationError::ForbiddenImport {
                    operation: op.to_owned(),
                    name,
                });
            }
            if !runtime::declares(caps, import) {
                return Err(OperationError::UndeclaredImport {
                    operation: op.to_owned(),
                    name,
                });
            }
            imports.push(import);
        }
        let mut interactive = Vec::new();
        for name in &self.interactive {
            let import = Import::from_name(name)
                .filter(|i| is_key_choice(*i) && imports.contains(i))
                .ok_or_else(|| OperationError::Interactive {
                    operation: op.to_owned(),
                    name: name.clone(),
                })?;
            if !interactive.contains(&import) {
                interactive.push(import);
            }
        }
        let network_error = |why: String| OperationError::Network {
            operation: op.to_owned(),
            why,
        };
        let network = match self.network {
            RawNetwork::Word(w) if w == "none" => Network::None,
            RawNetwork::Word(w) if w == "pki" => Network::Pki,
            RawNetwork::Word(w) => {
                return Err(network_error(format!(
                    "{w:?} is not `none`, `pki` or a list of URL prefixes"
                )));
            }
            RawNetwork::Urls(urls) => {
                if urls.is_empty() || urls.len() > MAX_NETWORK_URLS {
                    return Err(network_error(format!(
                        "a list of 1 to {MAX_NETWORK_URLS} URL prefixes"
                    )));
                }
                let mut parsed: Vec<HttpPrefix> = Vec::new();
                for url in &urls {
                    let prefix: HttpPrefix = url
                        .parse()
                        .map_err(|e: crate::PackageError| network_error(e.to_string()))?;
                    if !caps.http.iter().any(|c| c.covers(&prefix)) {
                        return Err(network_error(format!(
                            "{url} is not under capabilities.http"
                        )));
                    }
                    if !parsed.contains(&prefix) {
                        parsed.push(prefix);
                    }
                }
                Network::Urls(parsed)
            }
        };

        if self.key.len() > MAX_KEY_USES {
            return Err(OperationError::TooManyKeyUses(op.to_owned()));
        }
        let mut key = Vec::new();
        for (index, raw) in self.key.into_iter().enumerate() {
            key.push(raw.check(op, index, params)?);
        }
        if !key.is_empty() && !caps.keys {
            return Err(OperationError::KeyUse {
                operation: op.to_owned(),
                why: "uses.key needs capabilities.keys".to_owned(),
            });
        }
        for k in &key {
            if !imports.contains(&k.kind.import()) {
                return Err(OperationError::KeyUse {
                    operation: op.to_owned(),
                    why: format!(
                        "uses.key {} needs the import {}",
                        k.kind.as_str(),
                        k.kind.import().name()
                    ),
                });
            }
        }
        for import in &imports {
            if let Some(kind) = KeyKind::of_import(*import)
                && !key.iter().any(|k| k.kind == kind)
            {
                return Err(OperationError::KeyUse {
                    operation: op.to_owned(),
                    why: format!(
                        "import {} needs a uses.key of kind {}",
                        import.name(),
                        kind.as_str()
                    ),
                });
            }
        }
        if network == Network::None {
            if let Some(import) = imports.iter().find(|i| reaches_network(**i)) {
                return Err(OperationError::NetworkNeeded {
                    operation: op.to_owned(),
                    why: format!("{} sends requests", import.name()),
                });
            }
            if key.iter().any(|k| k.profile.needs_network()) {
                return Err(OperationError::NetworkNeeded {
                    operation: op.to_owned(),
                    why: "the profile time-stamps".to_owned(),
                });
            }
        }
        Ok(Uses {
            imports,
            network,
            interactive,
            key,
        })
    }
}

impl RawKeyUse {
    fn check(self, op: &str, index: usize, params: &[Param]) -> Result<KeyUse, OperationError> {
        let content_error = |why: String| OperationError::KeyContent {
            operation: op.to_owned(),
            index,
            why,
        };
        if self.max_uses != u64::from(MAX_USES) {
            return Err(content_error(format!(
                "max_uses must be {MAX_USES}, not {}",
                self.max_uses
            )));
        }
        let kind = self.kind;
        let content = if self.content == "derived" {
            Content::Derived
        } else if let Some(name) = self.content.strip_prefix("param:") {
            let param = params.iter().find(|p| p.name == name).ok_or_else(|| {
                content_error(format!("content names the undeclared param {name:?}"))
            })?;
            let ok = match param.kind {
                ParamKind::Document { .. } => true,
                ParamKind::Text { .. } => kind.is_xml(),
                _ => false,
            };
            if !ok {
                return Err(content_error(format!(
                    "param {name:?} cannot be the content of {}: a document (a text for xml, xml_ex, xades)",
                    kind.as_str()
                )));
            }
            Content::Bound(name.to_owned())
        } else {
            return Err(content_error(
                "content is `param:<name>` or `derived`".to_owned(),
            ));
        };
        if matches!(content, Content::Derived) && kind == KeyKind::Raw {
            return Err(content_error(
                "raw signs bound content only: derived is refused".to_owned(),
            ));
        }
        let profile_error = |why: String| OperationError::Profile {
            operation: op.to_owned(),
            index,
            why,
        };
        let table = toml::Value::Table(self.profile);
        let from = |e: toml::de::Error| profile_error(e.to_string().trim_end().to_owned());
        let profile = match kind {
            KeyKind::Raw => {
                let toml::Value::Table(t) = &table else {
                    unreachable!()
                };
                if let Some(field) = t.keys().next() {
                    return Err(profile_error(format!(
                        "raw has no options: unknown field `{field}`"
                    )));
                }
                Profile::Raw
            }
            KeyKind::Cms => {
                let p: CmsProfile = table.try_into().map_err(from)?;
                if p.timestamp == Timestamp::Kalkan {
                    return Err(profile_error(
                        "timestamp `kalkan` is for cms_ex: cms stamps with the basics TSA"
                            .to_owned(),
                    ));
                }
                Profile::Cms(p)
            }
            KeyKind::CmsEx => {
                let p: CmsExProfile = table.try_into().map_err(from)?;
                if p.content_form == ContentForm::Digest {
                    if matches!(content, Content::Derived) {
                        return Err(content_error(
                            "content_form `digest` needs bound content".to_owned(),
                        ));
                    }
                    if p.encapsulate {
                        return Err(profile_error("a digest is never encapsulated".to_owned()));
                    }
                }
                Profile::CmsEx(p)
            }
            KeyKind::Xml => {
                let p: XmlProfile = table.try_into().map_err(from)?;
                if p.parent.is_some() && p.element.is_none() {
                    return Err(profile_error("parent needs element".to_owned()));
                }
                Profile::Xml(p)
            }
            KeyKind::XmlEx => {
                let p: XmlExProfile = table.try_into().map_err(from)?;
                if p.parent.is_some() && p.element.is_none() {
                    return Err(profile_error("parent needs element".to_owned()));
                }
                if (p.placement == Placement::Parent) != p.parent.is_some() {
                    return Err(profile_error(
                        "placement `parent` and `parent` go together".to_owned(),
                    ));
                }
                if p.namespaces.len() > MAX_NAMESPACES {
                    return Err(profile_error(format!(
                        "more than {MAX_NAMESPACES} namespaces"
                    )));
                }
                let mut prefixes = HashSet::new();
                for ns in &p.namespaces {
                    if !prefixes.insert(ns.prefix.as_str()) {
                        return Err(profile_error(format!(
                            "namespace prefix {:?} is bound twice",
                            ns.prefix
                        )));
                    }
                    if plain_text_problem(&ns.prefix, 64).is_some()
                        || plain_text_problem(&ns.uri, 512).is_some()
                    {
                        return Err(profile_error("a namespace is not plain text".to_owned()));
                    }
                }
                if let Some(uri) = &p.other_prefix_uri
                    && plain_text_problem(uri, 512).is_some()
                {
                    return Err(profile_error(
                        "other_prefix_uri is not plain text".to_owned(),
                    ));
                }
                methods(&p.signature_method, &p.digest_method).map_err(profile_error)?;
                Profile::XmlEx(p)
            }
            KeyKind::Xades => {
                let p: XadesProfile = table.try_into().map_err(from)?;
                if p.level == XadesLevel::Lt {
                    return Err(profile_error(
                        "level `lt` is not offered yet: the core needs the chain for its evidence"
                            .to_owned(),
                    ));
                }
                methods(&p.signature_method, &p.digest_method).map_err(profile_error)?;
                Profile::Xades(p)
            }
        };
        for name in profile.params() {
            let param = params.iter().find(|p| p.name == name).ok_or_else(|| {
                profile_error(format!("`param:{name}` names an undeclared param"))
            })?;
            match param.kind {
                ParamKind::Text { max_chars } if max_chars <= MAX_XPATH_PARAM_CHARS => {}
                ParamKind::Text { .. } => {
                    return Err(profile_error(format!(
                        "param {name:?} is an XPath: max_chars must be at most {MAX_XPATH_PARAM_CHARS}"
                    )));
                }
                _ => return Err(profile_error(format!("param {name:?} must be a text"))),
            }
        }
        Ok(KeyUse {
            kind,
            content,
            profile,
        })
    }
}

fn methods(signature: &Option<String>, digest: &Option<String>) -> Result<(), String> {
    if let Some(s) = signature
        && !SIGNATURE_METHODS.contains(&s.as_str())
    {
        return Err(format!("signature_method {s:?} is not a known method"));
    }
    if let Some(d) = digest
        && !DIGEST_METHODS.contains(&d.as_str())
    {
        return Err(format!("digest_method {d:?} is not a known method"));
    }
    Ok(())
}

// ---- what an update adds ----------------------------------------------------------------

/// What an update's `[[operations]]` ask for over the installed ones: each is a capability
/// the user has not agreed to yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedOperation {
    /// The operation.
    pub name: String,
    /// Why it counts.
    pub reasons: Vec<AddedReason>,
}

/// Why an operation counts as added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddedReason {
    /// No operation of this name was installed, and it uses a key, imports a function that
    /// needs a capability or reaches the network.
    New,
    /// Its module, request, parameters or `manual` changed, and it uses a key.
    Changed,
    /// A use of a key (kind, content or profile) the installed operation lacks.
    KeyUse,
    /// Imports of a capability the installed operation lacks.
    Imports(Vec<&'static str>),
    /// A wider network.
    Network,
    /// `server` newly set.
    Server,
}

impl fmt::Display for AddedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddedReason::New => f.write_str("a new operation"),
            AddedReason::Changed => f.write_str("a changed operation"),
            AddedReason::KeyUse => f.write_str("a new use of a key"),
            AddedReason::Imports(names) => write!(f, "more imports: {}", names.join(", ")),
            AddedReason::Network => f.write_str("a wider network"),
            AddedReason::Server => f.write_str("open to servers"),
        }
    }
}

/// What `new` asks for over `old`.
///
/// An operation counts when it has a use of a key, an import of a capability or network
/// that is new over the installed operation of the same name (an operation that is not
/// installed has none); or, with a use of a key, its module, request, parameters or
/// `manual` differ in a way that is not only narrower. Changing a label counts for nothing
/// (it is the plugin's own words, trusted nowhere), and neither does narrowing.
pub(crate) fn added(new: &[Operation], old: &[Operation]) -> Vec<AddedOperation> {
    let mut out = Vec::new();
    for op in new {
        let installed = old.iter().find(|o| o.name == op.name);
        let mut reasons = Vec::new();
        let none = Network::None;
        let old_network = installed.map_or(&none, |o| &o.uses.network);
        let old_imports: &[Import] = installed.map_or(&[], |o| &o.uses.imports);
        let old_keys: &[KeyUse] = installed.map_or(&[], |o| &o.uses.key);
        let widened: Vec<&'static str> = op
            .uses
            .imports
            .iter()
            .filter(|i| i.capability().is_some() && !old_imports.contains(i))
            .map(Import::name)
            .collect();
        if !widened.is_empty() {
            reasons.push(AddedReason::Imports(widened));
        }
        if !op.uses.network.within(old_network) {
            reasons.push(AddedReason::Network);
        }
        if op.uses.key.iter().any(|k| !old_keys.contains(k)) {
            reasons.push(AddedReason::KeyUse);
        }
        if op.server && !installed.is_some_and(|o| o.server) {
            reasons.push(AddedReason::Server);
        }
        if !op.uses.key.is_empty() {
            match installed {
                None => reasons.push(AddedReason::New),
                Some(o) if o.changed_beyond_narrowing(op) => reasons.push(AddedReason::Changed),
                Some(_) => {}
            }
        } else if installed.is_none() && !reasons.is_empty() {
            reasons.push(AddedReason::New);
        }
        if !reasons.is_empty() {
            out.push(AddedOperation {
                name: op.name.clone(),
                reasons,
            });
        }
    }
    out
}
