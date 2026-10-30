//! The ports of `plugins/`: each `plugins/<short>` holds the port's `plugin.toml` and its
//! registry entry, `registry.toml` — the original bundle it replaces, how far the port is
//! and what differs from the original. [`load`] reads and checks them all; this module is
//! the only reader of `registry.toml`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use oncl_plugin::{MAX_MANIFEST, Manifest, is_symbolic_name};
use serde::{Deserialize, Serialize};

use crate::plugin::{port_names, read_limited};

/// The prefix of a port's plugin id; the port's short name follows.
const PORT_ID_PREFIX: &str = "io.github.arynyklas.openncalayer.port.";
/// Longest `original.vendor`, in characters.
const MAX_VENDOR: usize = 256;
/// Most `[[differences]]` of one port.
const MAX_DIFFERENCES: usize = 64;
/// Longest difference, in characters.
const MAX_DIFFERENCE: usize = 2048;

/// A port's `registry.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    /// The plugin's id, as in `plugin.toml`.
    pub id: String,
    /// The modules, as in `plugin.toml`.
    pub modules: Vec<String>,
    /// The original bundle.
    pub original: Original,
    /// How far the port is.
    pub port: PortState,
    /// What differs from the original.
    #[serde(default)]
    pub differences: Vec<Difference>,
}

/// `[original]`: the bundle of the original NCALayer the port replaces.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Original {
    /// The bundle's symbolic name, as `replaces.symname`.
    pub symname: String,
    /// Its live version, as `replaces.version`.
    pub version: String,
    /// Its publisher.
    pub vendor: String,
}

/// `[port]`: how far the port is.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortState {
    /// What of the original the port does.
    pub status: PortStatus,
    /// How its behaviour was compared with the original's.
    pub conformance: Conformance,
}

/// `[[differences]]`: one way the port differs from the original.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Difference {
    /// The difference, in Russian.
    pub ru: String,
}

/// What of the original a port does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortStatus {
    /// Everything.
    Full,
    /// Part of it; the differences say what is missing.
    Partial,
    /// Everything, but some of it needs hardware tokens to be checked.
    NeedsTokens,
}

/// How a port's behaviour was compared with the original's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Conformance {
    /// From the original's code.
    Computed,
    /// Against the running original.
    Confirmed,
}

/// A port: `plugins/<short>`.
#[derive(Debug, Clone)]
pub struct Port {
    /// The directory name under `plugins`.
    pub short: String,
    /// Its `plugin.toml`.
    pub manifest: Manifest,
    /// Its `registry.toml`.
    pub registry: RegistryEntry,
}

/// Every port of `plugins` ([`port_names`]), sorted by short name, each manifest and
/// registry entry checked against the other.
///
/// # Errors
///
/// Every port that is invalid, together (`<short>/registry.toml: …`), or an unreadable
/// `plugins`.
pub fn load(plugins: &Path) -> anyhow::Result<Vec<Port>> {
    let mut ports = Vec::new();
    let mut errors = Vec::new();
    for short in port_names(plugins)? {
        match load_port(plugins, &short) {
            Ok(port) => ports.push(port),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    let mut owners: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for port in &ports {
        owners
            .entry(&port.registry.original.symname)
            .or_default()
            .push(&port.short);
    }
    for (symname, shorts) in owners.iter().filter(|(_, s)| s.len() > 1) {
        errors.push(format!(
            "{}/registry.toml: original.symname {symname:?} is also the original of {}",
            shorts[0],
            shorts[1..].join(", ")
        ));
    }
    if !errors.is_empty() {
        bail!("invalid ports:\n{}", errors.join("\n"));
    }
    Ok(ports)
}

/// `plugins/<short>`, checked.
fn load_port(plugins: &Path, short: &str) -> anyhow::Result<Port> {
    if !is_short_name(short) {
        bail!("{short}: the directory name is not ^[a-z0-9][a-z0-9-]{{0,62}}$");
    }
    let dir = plugins.join(short);
    let manifest = String::from_utf8(read_limited(&dir.join("plugin.toml"), MAX_MANIFEST)?)
        .map_err(anyhow::Error::from)
        .and_then(|text| Ok(Manifest::from_toml(&text)?))
        .with_context(|| format!("{short}/plugin.toml"))?;
    let registry = String::from_utf8(read_limited(&dir.join("registry.toml"), MAX_MANIFEST)?)
        .map_err(anyhow::Error::from)
        .and_then(|text| Ok(toml::from_str::<RegistryEntry>(&text)?))
        .and_then(|registry| {
            check(&manifest, &registry, short)?;
            Ok(registry)
        })
        .with_context(|| format!("{short}/registry.toml"))?;
    Ok(Port {
        short: short.to_owned(),
        manifest,
        registry,
    })
}

/// Whether `registry` and `manifest` agree, and `registry` keeps its own rules.
fn check(manifest: &Manifest, registry: &RegistryEntry, short: &str) -> anyhow::Result<()> {
    let id = format!("{PORT_ID_PREFIX}{short}");
    if manifest.id != id {
        bail!("plugin.toml id {:?} is not {id:?}", manifest.id);
    }
    if registry.id != manifest.id {
        bail!(
            "id {:?} is not plugin.toml's {:?}",
            registry.id,
            manifest.id
        );
    }
    if registry.modules != manifest.modules {
        bail!(
            "modules {:?} are not plugin.toml's {:?}",
            registry.modules,
            manifest.modules
        );
    }
    let original = &registry.original;
    let Some(replaces) = &manifest.replaces else {
        bail!("plugin.toml has no [replaces]");
    };
    if replaces.symname != original.symname || replaces.version != original.version {
        bail!(
            "original {} {} is not plugin.toml's replaces {} {}",
            original.symname,
            original.version,
            replaces.symname,
            replaces.version
        );
    }
    if !is_symbolic_name(&original.symname) {
        bail!("original.symname {:?} is not valid", original.symname);
    }
    if !(1..=MAX_VENDOR).contains(&original.vendor.chars().count())
        || original.vendor.chars().any(char::is_control)
    {
        bail!("original.vendor must be 1 to {MAX_VENDOR} characters without control characters");
    }
    if registry.differences.len() > MAX_DIFFERENCES {
        bail!("more than {MAX_DIFFERENCES} differences");
    }
    for (i, difference) in registry.differences.iter().enumerate() {
        let text = &difference.ru;
        if !(1..=MAX_DIFFERENCE).contains(&text.chars().count())
            || text.chars().any(|c| c.is_control() && c != '\n')
        {
            bail!(
                "differences[{i}] must be 1 to {MAX_DIFFERENCE} characters without control \
                 characters other than line breaks"
            );
        }
    }
    Ok(())
}

/// `^[a-z0-9][a-z0-9-]{0,62}$`.
fn is_short_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const EXAMPLE: &str = r#"
id = "io.github.arynyklas.openncalayer.port.nursign"
modules = ["NURSign"]
[original]
symname = "kz.ecc.NurSignBundle"
version = "5.1.2"
vendor = "АО «Центр электронных финансов»"
[port]
status = "partial"
conformance = "computed"
[[differences]]
ru = "Окно выбора ключа — общее окно OpenNCALayer."
"#;

    fn manifest(short: &str, module: &str, symname: &str) -> String {
        format!(
            r#"id = "{PORT_ID_PREFIX}{short}"
version = "1.0.0"
min_core = "0.1.0"
modules = ["{module}"]

[name]
ru = "Порт"
kk = "Порт"
en = "Port"

[replaces]
symname = "{symname}"
version = "1.0.0"
"#
        )
    }

    fn registry(short: &str, module: &str, symname: &str) -> String {
        format!(
            r#"id = "{PORT_ID_PREFIX}{short}"
modules = ["{module}"]

[original]
symname = "{symname}"
version = "1.0.0"
vendor = "АО «Пример»"

[port]
status = "full"
conformance = "computed"

[[differences]]
ru = "Окно — общее окно OpenNCALayer."
"#
        )
    }

    /// A `plugins` directory with the ports `(short, plugin.toml, registry.toml)`.
    fn plugins(ports: &[(&str, String, String)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("common")).unwrap();
        for (short, manifest, registry) in ports {
            let port = dir.path().join(short);
            fs::create_dir(&port).unwrap();
            fs::write(port.join("plugin.toml"), manifest).unwrap();
            fs::write(port.join("registry.toml"), registry).unwrap();
        }
        dir
    }

    fn port(short: &str) -> (&str, String, String) {
        let symname = format!("kz.example.{short}");
        (
            short,
            manifest(short, "kz.example.m", &symname),
            registry(short, "kz.example.m", &symname),
        )
    }

    fn error(ports: &[(&str, String, String)]) -> String {
        let dir = plugins(ports);
        format!("{:#}", load(dir.path()).unwrap_err())
    }

    #[test]
    fn loads_every_committed_port() {
        let ports = load(&oncl_testkit::workspace_root().join("plugins")).unwrap();
        assert_eq!(ports.len(), 34);
        let mut shorts: Vec<&str> = ports.iter().map(|p| p.short.as_str()).collect();
        shorts.sort_unstable();
        assert!(shorts.iter().eq(ports.iter().map(|p| &p.short)));
        for port in &ports {
            let state = &port.registry.port;
            assert!(matches!(
                state.status,
                PortStatus::Full | PortStatus::Partial | PortStatus::NeedsTokens
            ));
            assert!(matches!(
                state.conformance,
                Conformance::Computed | Conformance::Confirmed
            ));
        }
    }

    #[test]
    fn schema_reads_the_example_entry() {
        let entry: RegistryEntry = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(entry.differences.len(), 1);
        assert_eq!(entry.port.status, PortStatus::Partial);
        assert_eq!(entry.port.conformance, Conformance::Computed);
        let dir = plugins(&[(
            "nursign",
            manifest("nursign", "NURSign", "kz.ecc.NurSignBundle")
                .replace("1.0.0\"\n", "5.1.2\"\n"),
            EXAMPLE.to_owned(),
        )]);
        let ports = load(dir.path()).unwrap();
        assert_eq!(
            ports[0].registry.original.vendor,
            "АО «Центр электронных финансов»"
        );
        assert!(toml::from_str::<RegistryEntry>("id = 1").is_err());
        assert_eq!(
            serde_json::to_value(PortStatus::NeedsTokens).unwrap(),
            "needs-tokens"
        );
        assert_eq!(
            serde_json::to_value(Conformance::Confirmed).unwrap(),
            "confirmed"
        );
    }

    #[test]
    fn rejects_unknown_status() {
        let (short, m, r) = port("a");
        let r = r.replace("status = \"full\"", "status = \"done\"");
        assert!(error(&[(short, m, r)]).contains("a/registry.toml"));
    }

    #[test]
    fn rejects_unknown_key() {
        let (short, m, r) = port("a");
        let r = r.replace("[port]", "homepage = \"x\"\n[port]");
        let r2 = port("b")
            .2
            .replace("conformance =", "extra = 1\nconformance =");
        assert!(error(&[(short, m, r)]).contains("a/registry.toml"));
        assert!(error(&[("b", port("b").1, r2)]).contains("b/registry.toml"));
    }

    #[test]
    fn rejects_id_mismatch() {
        let (short, m, r) = port("a");
        let r = r.replace("port.a\"", "port.b\"");
        assert!(error(&[(short, m, r)]).contains("a/registry.toml: id"));
        // plugin.toml names another port.
        let (_, m, r) = port("b");
        assert!(error(&[("a", m, r)]).contains("a/registry.toml: plugin.toml id"));
    }

    #[test]
    fn rejects_modules_mismatch() {
        let (short, m, r) = port("a");
        let r = r.replace("kz.example.m", "kz.example.other");
        assert!(error(&[(short, m, r)]).contains("a/registry.toml: modules"));
    }

    #[test]
    fn rejects_replaces_mismatch() {
        let (short, m, r) = port("a");
        let r = r.replace("version = \"1.0.0\"", "version = \"1.0.1\"");
        assert!(error(&[(short, m, r)]).contains("a/registry.toml: original"));
    }

    #[test]
    fn rejects_missing_replaces() {
        let (short, m, r) = port("a");
        let m = m.split("[replaces]").next().unwrap().to_owned();
        assert!(error(&[(short, m, r)]).contains("a/registry.toml: plugin.toml has no [replaces]"));
    }

    #[test]
    fn rejects_bad_short_name() {
        for bad in ["Acbank", "-x"] {
            let (_, m, r) = port("a");
            assert!(error(&[(bad, m, r)]).contains(bad), "{bad}");
        }
    }

    #[test]
    fn rejects_duplicate_symname() {
        let (a, ma, ra) = port("a");
        let mb = manifest("b", "kz.example.m", "kz.example.a");
        let rb = registry("b", "kz.example.m", "kz.example.a");
        let text = error(&[(a, ma, ra), ("b", mb, rb)]);
        assert!(text.contains("\"kz.example.a\""), "{text}");
        assert!(
            text.contains("a/registry.toml") && text.contains('b'),
            "{text}"
        );
    }

    #[test]
    fn rejects_control_characters_in_difference() {
        let (short, m, r) = port("a");
        let ok = r.replace("общее окно", "общее\\nокно");
        assert!(load(plugins(&[(short, m.clone(), ok)]).path()).is_ok());
        let bad = r.replace("общее окно", "общее\\u001bокно");
        assert!(error(&[(short, m, bad)]).contains("a/registry.toml: differences[0]"));
    }

    #[test]
    fn reports_every_bad_port_at_once() {
        let (a, ma, ra) = port("alpha");
        let (b, mb, rb) = port("beta");
        let (c, mc, rc) = port("gamma");
        let ra = ra.replace("status = \"full\"", "status = \"done\"");
        let rc = rc.replace("kz.example.m", "kz.example.other");
        let text = error(&[(a, ma, ra), (b, mb, rb), (c, mc, rc)]);
        assert!(text.contains("alpha/registry.toml"), "{text}");
        assert!(text.contains("gamma/registry.toml"), "{text}");
        assert!(!text.contains("beta/"), "{text}");
    }
}
