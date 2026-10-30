//! `plugin.toml`, a plugin's manifest: its id and version, the modules it serves, the
//! original bundle it ports and what it may do. Unknown keys are refused, so a manifest
//! written for a later format is not read as a weaker one.

use crate::PackageError;
use oncl_basics::Locale;
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
}

impl Capabilities {
    /// Whether nothing is asked for.
    pub fn is_empty(&self) -> bool {
        *self == Capabilities::default()
    }

    /// What these capabilities allow that `old` does not: the flags `old` lacks, and the
    /// prefixes no prefix of `old` [covers](HttpPrefix::covers). Empty: nothing new.
    pub fn added_over(&self, old: &Capabilities) -> Capabilities {
        Capabilities {
            keys: self.keys && !old.keys,
            dialogs: self.dialogs && !old.dialogs,
            files: self.files && !old.files,
            http: self
                .http
                .iter()
                .filter(|new| !old.http.iter().any(|o| o.covers(new)))
                .cloned()
                .collect(),
        }
    }
}

/// A URL prefix of `capabilities.http`: `https://`, a host, an optional port and a path
/// ending with `/`, without user info, query or fragment.
///
/// URLs are parsed as browsers parse them ([WHATWG URL], the `url` crate): the host is
/// compared lowercased (and IDNA-mapped), the port with `443` for none, the path after dot
/// segments are resolved. Text other parsers could read differently is refused outright:
/// backslashes, spaces and control characters, and user info (`@` before the path).
///
/// [WHATWG URL]: https://url.spec.whatwg.org/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPrefix {
    host: String,
    port: u16,
    path: String,
}

impl HttpPrefix {
    /// The host, lowercased.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, `443` if the prefix names none.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path, ending with `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether every URL under `other` is under this prefix too: the same host and port, and
    /// `other`'s path starts with this one's.
    pub fn covers(&self, other: &HttpPrefix) -> bool {
        self.host == other.host && self.port == other.port && other.path.starts_with(&self.path)
    }

    /// Whether `url` is under this prefix: [`check`](Self::check) accepts it.
    pub fn allows(&self, url: &str) -> bool {
        self.check(url).is_some()
    }

    /// `url`, parsed and normalized, if it is under this prefix: `https`, no user info, the
    /// same host and port, a path starting with the prefix's. The query and fragment of `url`
    /// do not matter.
    ///
    /// Under a prefix path other than `/`, a path with `;` or an encoded `/` or `\` (`%2f`,
    /// `%5c`, any case) is refused: the parser leaves `..%2f` and `..;` in the path as they
    /// are, while servers that decode before resolving `..` or strip `;` parameters resolve
    /// them outside the prefix.
    ///
    /// The request must be sent to [`Url::as_str`] of the result, not to `url`: what was
    /// checked is then what is sent. Every redirect is checked again, hop by hop.
    pub fn check(&self, url: &str) -> Option<Url> {
        let url = parse_https(url).ok()?;
        let path = url.path();
        let under = url.host_str() == Some(self.host.as_str())
            && url.port_or_known_default() == Some(self.port)
            && path.starts_with(&self.path)
            && (self.path == "/" || !has_hidden_separator(path));
        under.then_some(url)
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

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = |why: &str| PackageError::Manifest(format!("HTTP prefix {text:?}: {why}"));
        if text.contains(['?', '#']) {
            return Err(bad("has a query or a fragment"));
        }
        let url = parse_https(text).map_err(bad)?;
        let rest = &text[HTTPS.len()..];
        if !rest.contains('/') {
            return Err(bad("has no path; a prefix ends with `/`"));
        }
        if !text.ends_with('/') || !url.path().ends_with('/') {
            return Err(bad("the path does not end with `/`"));
        }
        if has_hidden_separator(url.path()) {
            return Err(bad("the path has `;`, `%2f` or `%5c`"));
        }
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Err(bad("has no host"));
        };
        Ok(HttpPrefix {
            host: host.to_owned(),
            port,
            path: url.path().to_owned(),
        })
    }
}

impl fmt::Display for HttpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(HTTPS)?;
        f.write_str(&self.host)?;
        if self.port != 443 {
            write!(f, ":{}", self.port)?;
        }
        f.write_str(&self.path)
    }
}

const HTTPS: &str = "https://";

/// `text` as an `https` URL without user info. Refused before parsing: another scheme
/// spelling, backslashes (a path separator to browsers, not to every HTTP client), spaces and
/// control characters (which the WHATWG parser drops), and `@` in the authority.
fn parse_https(text: &str) -> Result<Url, &'static str> {
    let Some(rest) = text.strip_prefix(HTTPS) else {
        return Err("is not an https:// URL");
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
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("is not an https:// URL without user info");
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
fn is_symbolic_name(name: &str) -> bool {
    (1..=MAX_SYMBOLIC_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
