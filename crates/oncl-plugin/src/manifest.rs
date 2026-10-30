//! `plugin.toml`, a plugin's manifest: its id and version, the modules it serves, the
//! original bundle it ports and what it may do. Unknown keys are refused, so a manifest
//! written for a later format is not read as a weaker one.

use crate::PackageError;
use oncl_basics::Locale;
use oncl_basics::capabilities::CapabilityLine;
use semver::Version;
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use url::Url;

/// Longest plugin id, in bytes.
const MAX_ID: usize = 64;
/// Most module names one plugin serves.
const MAX_MODULES: usize = 32;
/// Longest module name and `replaces.symname`, in bytes.
const MAX_SYMBOLIC_NAME: usize = 128;
/// Longest translation of `name`, in characters.
const MAX_NAME: usize = 128;
/// Longest translation of `description`, in characters.
const MAX_DESCRIPTION: usize = 2048;
/// Longest `replaces.version`, in characters.
const MAX_REPLACES_VERSION: usize = 64;
/// Most URL prefixes of `capabilities.http`.
const MAX_HTTP_PREFIXES: usize = 32;
/// Most origin patterns of `capabilities.origins`.
const MAX_ORIGINS: usize = 32;
/// Most URL prefixes of `capabilities.http_insecure`.
const MAX_INSECURE_PREFIXES: usize = 8;
/// Most extensions of `capabilities.page_files_ext`.
const MAX_PAGE_FILES_EXT: usize = 16;
/// Longest extension of `capabilities.page_files_ext`, in bytes.
const MAX_EXT: usize = 16;

/// A checked `plugin.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Reverse domain name, `^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$` with at least one dot; the
    /// key of the plugin in the update index and on disk.
    pub id: String,
    /// The plugin's own version.
    pub version: Version,
    /// What the plugin is called in the plugin manager.
    pub name: Localized,
    /// What the plugin does, if it says.
    pub description: Option<Localized>,
    /// The oldest core version the plugin runs on.
    pub min_core: Version,
    /// The `module` names of requests the plugin serves: 1 to 32, distinct, each
    /// `^[A-Za-z0-9._-]{1,128}$`.
    pub modules: Vec<String>,
    /// The bundle of the original NCALayer the plugin is a port of, if it is one.
    pub replaces: Option<Replaces>,
    /// What the plugin may do beyond answering requests.
    pub capabilities: Capabilities,
}

/// A text in the three languages of the dialogs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Localized {
    /// Russian.
    pub ru: String,
    /// Kazakh.
    pub kk: String,
    /// English.
    pub en: String,
}

impl Localized {
    /// The text in `locale`.
    pub fn get(&self, locale: Locale) -> &str {
        match locale {
            Locale::Ru => &self.ru,
            Locale::Kk => &self.kk,
            Locale::En => &self.en,
        }
    }

    /// Each translation at most `max` characters, and not blank if `required`.
    fn check(&self, field: &str, max: usize, required: bool) -> Result<(), String> {
        for (lang, text) in [("ru", &self.ru), ("kk", &self.kk), ("en", &self.en)] {
            if required && text.trim().is_empty() {
                return Err(format!("{field}.{lang} is empty"));
            }
            if text.chars().count() > max {
                return Err(format!("{field}.{lang} is longer than {max} characters"));
            }
        }
        Ok(())
    }
}

/// The bundle of the original NCALayer a plugin ports: what `getBundles` reports while the
/// plugin is installed and enabled, and what `installBundle` matches.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replaces {
    /// The bundle's symbolic name, `^[A-Za-z0-9._-]{1,128}$`.
    pub symname: String,
    /// The bundle's version as the original reports it: an OSGi version string, not semver;
    /// 1 to 64 characters.
    pub version: String,
}

/// What a plugin may do beyond answering requests; everything is off unless asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Use the user's keys (open a key store, sign).
    pub keys: bool,
    /// Show dialogs.
    pub dialogs: bool,
    /// Read and write files the user chooses in a dialog.
    pub files: bool,
    /// The HTTPS URL prefixes the plugin may send requests to; empty: none.
    pub http: Vec<HttpPrefix>,
    /// The origins of pages whose own origin the plugin may send requests to
    /// (`http_request_ex`, relative URLs included); empty: none.
    pub origins: Vec<OriginPattern>,
    /// The plain-HTTP URL prefixes the plugin may send requests to: an exact host and port
    /// each; empty: none.
    pub http_insecure: Vec<HttpPrefix>,
    /// Open key stores whose path the page names (`keys_open` with a page path), each file
    /// once the user allows it; needs `keys`.
    pub key_files: bool,
    /// Read files and write into folders the page names, each once the user allows it.
    pub page_files: bool,
    /// The extensions, lowercase, of the files `page_file_write` may write; needs
    /// `page_files`.
    pub page_files_ext: Vec<String>,
    /// Keep settings on disk.
    pub settings: bool,
    /// Share values between the plugin's instances (and so between sites) in the process.
    pub shared: bool,
}

impl Capabilities {
    /// Whether nothing is asked for.
    pub fn is_empty(&self) -> bool {
        *self == Capabilities::default()
    }

    /// What these capabilities allow, a line each, in the manifest's order.
    pub fn lines(&self) -> Vec<CapabilityLine> {
        let texts = |items: &[HttpPrefix]| -> Vec<String> {
            items.iter().map(ToString::to_string).collect()
        };
        let mut lines = Vec::new();
        if self.keys {
            lines.push(CapabilityLine::Keys);
        }
        if self.dialogs {
            lines.push(CapabilityLine::Dialogs);
        }
        if self.files {
            lines.push(CapabilityLine::Files);
        }
        if !self.http.is_empty() {
            lines.push(CapabilityLine::Http(texts(&self.http)));
        }
        if !self.origins.is_empty() {
            lines.push(CapabilityLine::Origins(
                self.origins.iter().map(ToString::to_string).collect(),
            ));
        }
        if !self.http_insecure.is_empty() {
            lines.push(CapabilityLine::HttpInsecure(texts(&self.http_insecure)));
        }
        if self.key_files {
            lines.push(CapabilityLine::KeyFiles);
        }
        if self.page_files || !self.page_files_ext.is_empty() {
            lines.push(CapabilityLine::PageFiles(self.page_files_ext.clone()));
        }
        if self.settings {
            lines.push(CapabilityLine::Settings);
        }
        if self.shared {
            lines.push(CapabilityLine::Shared);
        }
        lines
    }

    /// What these capabilities allow that `old` does not: the flags `old` lacks, the
    /// prefixes no prefix of `old` [covers](HttpPrefix::covers), the origin patterns no
    /// pattern of `old` [covers](OriginPattern::covers) and the extensions `old` lacks.
    /// Empty: nothing new.
    pub fn added_over(&self, old: &Capabilities) -> Capabilities {
        let prefixes = |new: &[HttpPrefix], old: &[HttpPrefix]| -> Vec<HttpPrefix> {
            new.iter()
                .filter(|new| !old.iter().any(|o| o.covers(new)))
                .cloned()
                .collect()
        };
        Capabilities {
            keys: self.keys && !old.keys,
            dialogs: self.dialogs && !old.dialogs,
            files: self.files && !old.files,
            http: prefixes(&self.http, &old.http),
            origins: self
                .origins
                .iter()
                .filter(|new| !old.origins.iter().any(|o| o.covers(new)))
                .cloned()
                .collect(),
            http_insecure: prefixes(&self.http_insecure, &old.http_insecure),
            key_files: self.key_files && !old.key_files,
            page_files: self.page_files && !old.page_files,
            page_files_ext: self
                .page_files_ext
                .iter()
                .filter(|new| !old.page_files_ext.contains(new))
                .cloned()
                .collect(),
            settings: self.settings && !old.settings,
            shared: self.shared && !old.shared,
        }
    }
}

/// A URL prefix of `capabilities.http` (`https://`) or `capabilities.http_insecure`
/// (`http://`): the scheme, a host, an optional port and a path ending with `/`, without
/// user info, query or fragment. An `https` prefix's host may be `*.` and a domain of at
/// least two labels (`https://*.gov.kz/`): any host under that domain, on a label boundary,
/// not the domain itself.
///
/// URLs are parsed as browsers parse them ([WHATWG URL], the `url` crate): the host is
/// compared lowercased (and IDNA-mapped), the port with the scheme's default for none, the
/// path after dot segments are resolved. Text other parsers could read differently is
/// refused outright: backslashes, spaces and control characters, and user info (`@` before
/// the path).
///
/// [WHATWG URL]: https://url.spec.whatwg.org/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPrefix {
    secure: bool,
    host: Host,
    port: u16,
    path: String,
}

/// The host of a prefix or an origin pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    /// This host, lowercased.
    Exact(String),
    /// Any host under this domain (`*.` and the domain), not the domain itself.
    Under(String),
}

impl Host {
    /// Whether `host` (of a parsed URL) is this one.
    fn matches(&self, host: Option<url::Host<&str>>) -> bool {
        match (self, host) {
            (Host::Exact(exact), Some(host)) => host.to_string() == *exact,
            (Host::Under(domain), Some(url::Host::Domain(host))) => host
                .strip_suffix(domain.as_str())
                .is_some_and(|label| label.len() > 1 && label.ends_with('.')),
            _ => false,
        }
    }

    /// Whether every host this one matches, `other` matches too.
    fn covers(&self, other: &Host) -> bool {
        match (self, other) {
            (Host::Exact(a), Host::Exact(b)) => a == b,
            (Host::Under(domain), Host::Exact(host)) => {
                Host::Under(domain.clone()).matches(Some(url::Host::Domain(host)))
            }
            (Host::Under(a), Host::Under(b)) => {
                a == b || Host::Under(a.clone()).matches(Some(url::Host::Domain(b)))
            }
            (Host::Exact(_), Host::Under(_)) => false,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Exact(host) => f.write_str(host),
            Host::Under(domain) => write!(f, "*.{domain}"),
        }
    }
}

impl HttpPrefix {
    /// Whether the prefix is `https://`.
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// The host, lowercased; `*.` and the domain for any host under it.
    pub fn host(&self) -> String {
        self.host.to_string()
    }

    /// The port, the scheme's default if the prefix names none.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path, ending with `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether every URL under `other` is under this prefix too: the same scheme and port, a
    /// host covering `other`'s, and `other`'s path starts with this one's.
    pub fn covers(&self, other: &HttpPrefix) -> bool {
        self.secure == other.secure
            && self.host.covers(&other.host)
            && self.port == other.port
            && other.path.starts_with(&self.path)
    }

    /// Whether `url` is under this prefix: [`check`](Self::check) accepts it.
    pub fn allows(&self, url: &str) -> bool {
        self.check(url).is_some()
    }

    /// `url`, parsed and normalized, if it is under this prefix: the same scheme, no user
    /// info, a matching host, the same port, a path starting with the prefix's. The query
    /// and fragment of `url` do not matter.
    ///
    /// Under a prefix path other than `/`, a path with `;` or an encoded `/` or `\` (`%2f`,
    /// `%5c`, any case) is refused: the parser leaves `..%2f` and `..;` in the path as they
    /// are, while servers that decode before resolving `..` or strip `;` parameters resolve
    /// them outside the prefix.
    ///
    /// The request must be sent to [`Url::as_str`] of the result, not to `url`: what was
    /// checked is then what is sent. Every redirect is checked again, hop by hop.
    pub fn check(&self, url: &str) -> Option<Url> {
        let url = parse_url(url, self.scheme()).ok()?;
        let path = url.path();
        let under = self.host.matches(url.host())
            && url.port_or_known_default() == Some(self.port)
            && path.starts_with(&self.path)
            && (self.path == "/" || !has_hidden_separator(path));
        under.then_some(url)
    }

    fn scheme(&self) -> &'static str {
        if self.secure { HTTPS } else { HTTP }
    }

    /// `text` as a prefix of `scheme`; `*.` hosts only if `wildcard`.
    fn parse(text: &str, scheme: &'static str, wildcard: bool) -> Result<Self, PackageError> {
        let bad = |why: &str| PackageError::Manifest(format!("HTTP prefix {text:?}: {why}"));
        if text.contains(['?', '#']) {
            return Err(bad("has a query or a fragment"));
        }
        let (url, host) = parse_pattern(text, scheme, wildcard).map_err(bad)?;
        let rest = &text[scheme.len()..];
        if !rest.contains('/') {
            return Err(bad("has no path; a prefix ends with `/`"));
        }
        if !text.ends_with('/') || !url.path().ends_with('/') {
            return Err(bad("the path does not end with `/`"));
        }
        if has_hidden_separator(url.path()) {
            return Err(bad("the path has `;`, `%2f` or `%5c`"));
        }
        let Some(port) = url.port_or_known_default() else {
            return Err(bad("has no port"));
        };
        Ok(HttpPrefix {
            secure: scheme == HTTPS,
            host,
            port,
            path: url.path().to_owned(),
        })
    }

    /// `text` as a prefix of `capabilities.http_insecure`: `http://`, an exact host.
    ///
    /// # Errors
    ///
    /// [`PackageError::Manifest`] for anything else.
    pub fn parse_insecure(text: &str) -> Result<Self, PackageError> {
        HttpPrefix::parse(text, HTTP, false)
    }
}

/// Whether `path` has `;` or an encoded `/` or `\`, which servers may turn into a segment
/// boundary the URL parser did not see.
fn has_hidden_separator(path: &str) -> bool {
    path.contains(';')
        || path
            .as_bytes()
            .windows(3)
            .any(|w| w.eq_ignore_ascii_case(b"%2f") || w.eq_ignore_ascii_case(b"%5c"))
}

impl FromStr for HttpPrefix {
    type Err = PackageError;

    /// An `https://` prefix of `capabilities.http`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        HttpPrefix::parse(text, HTTPS, true)
    }
}

impl fmt::Display for HttpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.scheme(), self.host)?;
        if self.port != if self.secure { 443 } else { 80 } {
            write!(f, ":{}", self.port)?;
        }
        f.write_str(&self.path)
    }
}

/// An origin pattern of `capabilities.origins`: `https://` or `http://`, a host (or `*.`
/// and a domain of at least two labels) and an optional port, without a path. A page whose
/// origin matches may have the plugin send requests to that same origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPattern {
    secure: bool,
    host: Host,
    port: u16,
}

impl OriginPattern {
    /// Whether the pattern is `https://`.
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// Whether `origin` (a URL's scheme, host and port) matches.
    pub fn matches(&self, origin: &Url) -> bool {
        origin.scheme() == if self.secure { "https" } else { "http" }
            && self.host.matches(origin.host())
            && origin.port_or_known_default() == Some(self.port)
    }

    /// Whether every origin `other` matches, this one matches too.
    pub fn covers(&self, other: &OriginPattern) -> bool {
        self.secure == other.secure && self.port == other.port && self.host.covers(&other.host)
    }
}

impl FromStr for OriginPattern {
    type Err = PackageError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = |why: &str| PackageError::Manifest(format!("origin {text:?}: {why}"));
        let scheme = if text.starts_with(HTTP) { HTTP } else { HTTPS };
        let rest = text
            .strip_prefix(scheme)
            .ok_or_else(|| bad("is not https:// nor http://"))?;
        if rest.contains(['/', '?', '#']) {
            return Err(bad("has a path, a query or a fragment"));
        }
        let (url, host) = parse_pattern(text, scheme, true).map_err(bad)?;
        let Some(port) = url.port_or_known_default() else {
            return Err(bad("has no port"));
        };
        Ok(OriginPattern {
            secure: scheme == HTTPS,
            host,
            port,
        })
    }
}

impl fmt::Display for OriginPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (scheme, default) = if self.secure {
            (HTTPS, 443)
        } else {
            (HTTP, 80)
        };
        write!(f, "{scheme}{}", self.host)?;
        if self.port != default {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

const HTTPS: &str = "https://";
const HTTP: &str = "http://";

/// `text` as an `https://` or `http://` URL, parsed as [`HttpPrefix::check`] parses: `None`
/// for another scheme spelling, user info, backslashes, spaces or control characters.
pub(crate) fn parse_web_url(text: &str) -> Option<Url> {
    let scheme = if text.starts_with(HTTP) { HTTP } else { HTTPS };
    parse_url(text, scheme).ok()
}

/// `text`, of `scheme`, as a URL and its host pattern: with `wildcard`, a host `*.` and a
/// domain of at least two labels (not an IP address) is any host under that domain.
fn parse_pattern(
    text: &str,
    scheme: &'static str,
    wildcard: bool,
) -> Result<(Url, Host), &'static str> {
    let rest = text.strip_prefix(scheme).ok_or("has another scheme")?;
    let (text, under) = match rest.strip_prefix("*.") {
        Some(domain) if wildcard => (format!("{scheme}{domain}"), true),
        Some(_) => return Err("has a `*` host"),
        None => (text.to_owned(), false),
    };
    let authority_end = text[scheme.len()..]
        .find(['/', '?', '#'])
        .map_or(text.len(), |i| i + scheme.len());
    if text[..authority_end].contains('*') {
        return Err("has `*` other than a leading `*.`");
    }
    let url = parse_url(&text, scheme)?;
    let host = match url.host() {
        Some(url::Host::Domain(domain)) if under => {
            if domain.split('.').filter(|l| !l.is_empty()).count() < 2 {
                return Err("a `*.` domain needs at least two labels");
            }
            Host::Under(domain.to_owned())
        }
        Some(_) if under => return Err("a `*.` host is a domain, not an address"),
        Some(host) => Host::Exact(host.to_string()),
        None => return Err("has no host"),
    };
    Ok((url, host))
}

/// `text` as a URL of `scheme` (`https://` or `http://`) without user info. Refused before
/// parsing: another scheme spelling, backslashes (a path separator to browsers, not to
/// every HTTP client), spaces and control characters (which the WHATWG parser drops), and
/// `@` in the authority.
fn parse_url(text: &str, scheme: &'static str) -> Result<Url, &'static str> {
    let Some(rest) = text.strip_prefix(scheme) else {
        return Err(if scheme == HTTPS {
            "is not an https:// URL"
        } else {
            "is not an http:// URL"
        });
    };
    if text
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
    {
        return Err("has spaces, control characters or backslashes");
    }
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@') {
        return Err("has user info");
    }
    if authority.is_empty() {
        return Err("has no host");
    }
    let url = Url::parse(text).map_err(|_| "is not a valid URL")?;
    if url.scheme() != &scheme[..scheme.len() - 3]
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("is not a URL of its scheme without user info");
    }
    Ok(url)
}

impl Manifest {
    /// Parses and checks `plugin.toml`.
    pub fn from_toml(text: &str) -> Result<Manifest, PackageError> {
        let raw: RawManifest = toml::from_str(text)
            .map_err(|e| PackageError::Manifest(e.to_string().trim_end().to_owned()))?;
        raw.check()
    }
}

/// `plugin.toml` as written, before the checks.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    id: String,
    version: Version,
    min_core: Version,
    modules: Vec<String>,
    name: Localized,
    description: Option<Localized>,
    replaces: Option<Replaces>,
    #[serde(default)]
    capabilities: RawCapabilities,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawCapabilities {
    keys: bool,
    dialogs: bool,
    files: bool,
    http: Vec<String>,
    origins: Vec<String>,
    http_insecure: Vec<String>,
    key_files: bool,
    page_files: bool,
    page_files_ext: Vec<String>,
    settings: bool,
    shared: bool,
}

impl RawManifest {
    fn check(self) -> Result<Manifest, PackageError> {
        let bad = PackageError::Manifest;
        if !is_plugin_id(&self.id) {
            return Err(bad(format!(
                "id {:?} is not a lowercase reverse domain name of 3 to {MAX_ID} characters",
                self.id
            )));
        }
        if self.modules.is_empty() || self.modules.len() > MAX_MODULES {
            return Err(bad(format!(
                "modules must name 1 to {MAX_MODULES} modules, not {}",
                self.modules.len()
            )));
        }
        let mut seen = HashSet::new();
        for module in &self.modules {
            if !is_symbolic_name(module) {
                return Err(bad(format!("module name {module:?} is not valid")));
            }
            if !seen.insert(module.as_str()) {
                return Err(bad(format!("module {module:?} is listed twice")));
            }
        }
        self.name.check("name", MAX_NAME, true).map_err(bad)?;
        if let Some(description) = &self.description {
            description
                .check("description", MAX_DESCRIPTION, false)
                .map_err(bad)?;
        }
        if let Some(replaces) = &self.replaces {
            if !is_symbolic_name(&replaces.symname) {
                return Err(bad(format!(
                    "replaces.symname {:?} is not valid",
                    replaces.symname
                )));
            }
            if replaces.version.trim().is_empty() {
                return Err(bad("replaces.version is empty".to_owned()));
            }
            if replaces.version.chars().count() > MAX_REPLACES_VERSION {
                return Err(bad(format!(
                    "replaces.version is longer than {MAX_REPLACES_VERSION} characters"
                )));
            }
        }
        let caps = self.capabilities;
        if caps.key_files && !caps.keys {
            return Err(bad(
                "capabilities.key_files needs capabilities.keys".to_owned()
            ));
        }
        if caps.http.len() > MAX_HTTP_PREFIXES {
            return Err(bad(format!(
                "capabilities.http has more than {MAX_HTTP_PREFIXES} prefixes"
            )));
        }
        let http = caps
            .http
            .iter()
            .map(|p| p.parse())
            .collect::<Result<_, _>>()?;
        if caps.origins.len() > MAX_ORIGINS {
            return Err(bad(format!(
                "capabilities.origins has more than {MAX_ORIGINS} patterns"
            )));
        }
        let origins = caps
            .origins
            .iter()
            .map(|p| p.parse())
            .collect::<Result<_, _>>()?;
        if caps.http_insecure.len() > MAX_INSECURE_PREFIXES {
            return Err(bad(format!(
                "capabilities.http_insecure has more than {MAX_INSECURE_PREFIXES} prefixes"
            )));
        }
        let http_insecure = caps
            .http_insecure
            .iter()
            .map(|p| HttpPrefix::parse_insecure(p))
            .collect::<Result<_, _>>()?;
        if !caps.page_files_ext.is_empty() && !caps.page_files {
            return Err(bad(
                "capabilities.page_files_ext needs capabilities.page_files".to_owned(),
            ));
        }
        if caps.page_files_ext.len() > MAX_PAGE_FILES_EXT {
            return Err(bad(format!(
                "capabilities.page_files_ext has more than {MAX_PAGE_FILES_EXT} extensions"
            )));
        }
        let mut page_files_ext: Vec<String> = Vec::with_capacity(caps.page_files_ext.len());
        for ext in &caps.page_files_ext {
            if ext.is_empty()
                || ext.len() > MAX_EXT
                || !ext.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(bad(format!(
                    "capabilities.page_files_ext: {ext:?} is not 1 to {MAX_EXT} letters and digits"
                )));
            }
            let ext = ext.to_ascii_lowercase();
            if !page_files_ext.contains(&ext) {
                page_files_ext.push(ext);
            }
        }
        Ok(Manifest {
            id: self.id,
            version: self.version,
            name: self.name,
            description: self.description,
            min_core: self.min_core,
            modules: self.modules,
            replaces: self.replaces,
            capabilities: Capabilities {
                keys: caps.keys,
                dialogs: caps.dialogs,
                files: caps.files,
                http,
                origins,
                http_insecure,
                key_files: caps.key_files,
                page_files: caps.page_files,
                page_files_ext,
                settings: caps.settings,
                shared: caps.shared,
            },
        })
    }
}

/// `^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$` with at least one dot.
fn is_plugin_id(id: &str) -> bool {
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = id.as_bytes();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    (3..=MAX_ID).contains(&bytes.len())
        && edge(first)
        && edge(last)
        && bytes.iter().all(|&b| edge(b) || b == b'.' || b == b'-')
        && bytes.contains(&b'.')
}

/// `^[A-Za-z0-9._-]{1,128}$`: a module name or an OSGi symbolic name.
pub fn is_symbolic_name(name: &str) -> bool {
    (1..=MAX_SYMBOLIC_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
