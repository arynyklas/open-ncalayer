//! `facts.json`: the public facts of the original NCALayer. Collections are sorted maps and
//! sets, and no time of a run, `ETag` or `Last-Modified` is kept, so the same world gives
//! the same bytes; `key8` names a set of facts by the first 8 hex digits of their SHA-256.

use std::collections::{BTreeMap, BTreeSet};

use oncl_pki::cert::Certificate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::artifact::Format;
use super::http::Downloaded;
use super::inventory::{FileKind, Inventory, JreFacts};
use super::jar::{jar_entries, jar_facts};
use super::manifest::{Bundle, DistUrl, SignerFacts, Verified, rfc3339};
use super::meta::{DistMeta, inno_meta, mac_meta, tzdb_meta};
use super::sources::{Source, SourceKind, without_query};
use super::unpack::{Limits, TreeRoot, Unpacked};
use super::{pretty_json, sha256_hex};

/// The schema version of `facts.json`.
pub const FACTS_SCHEMA: u32 = 1;

/// `facts.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    /// [`FACTS_SCHEMA`].
    pub schema: u32,
    /// The manifest.
    pub manifest: ManifestFacts,
    /// Bundles by symbolic name.
    pub bundles: BTreeMap<String, BundleFacts>,
    /// Distributions by source id.
    pub distributions: BTreeMap<String, DistFacts>,
    /// JARs by SHA-256.
    pub jars: BTreeMap<String, JarFacts>,
}

/// The manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFacts {
    /// SHA-256 of `ncalayer.der`.
    pub sha256: String,
    /// Its size.
    pub size: u64,
    /// `version`.
    pub version: String,
    /// `info`.
    pub info: String,
    /// `updurl`.
    pub updurl: String,
    /// `syspkgs`.
    pub syspkgs: BTreeSet<String>,
    /// `disturls`.
    pub disturls: Vec<DistUrl>,
    /// The signer.
    pub signer: SignerFacts,
    /// The signingTime, RFC 3339.
    pub signing_time: Option<String>,
    /// Unknown keys.
    pub extra: BTreeMap<String, Value>,
}

/// A bundle of the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFacts {
    /// `name`.
    pub name: String,
    /// `version`.
    pub version: String,
    /// `required`.
    pub required: bool,
    /// `hidden`.
    pub hidden: bool,
    /// `banned`.
    pub banned: bool,
    /// `info`.
    pub info: String,
    /// `url`.
    pub url: String,
    /// `hash`.
    pub hash: String,
    /// `csernum`.
    pub csernum: String,
    /// `chash`.
    pub chash: String,
    /// Unknown keys.
    pub extra: BTreeMap<String, Value>,
    /// Whether the JAR was fetched.
    pub fetch: FetchStatus,
    /// SHA-256 of the JAR (a key of [`Facts::jars`]).
    pub jar: Option<String>,
    /// Whether `csernum` and `chash` name the JAR's signing certificate.
    pub signer_matches: Option<bool>,
}

/// Whether a file was fetched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchStatus {
    /// Fetched and checked.
    Ok,
    /// Not yet (failed fewer than three times in a row).
    Pending,
    /// Failed three times in a row.
    Unreachable,
    /// Its address is not public: never requested.
    Refused,
    /// Its SHA-256 is not the manifest's.
    HashMismatch,
}

/// A distribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistFacts {
    /// The URL (for a page link, `download.php` without its key).
    pub url: String,
    /// For a page link: the page, where a fresh key is.
    pub page: Option<String>,
    /// For a page link: its label.
    pub label: Option<String>,
    /// The file name.
    pub filename: Option<String>,
    /// Size.
    pub size: Option<u64>,
    /// SHA-256.
    pub sha256: Option<String>,
    /// The SHA-1 published on the page.
    pub published_sha1: Option<String>,
    /// The format.
    pub format: Option<Format>,
    /// Whether it was fetched.
    pub status: FetchStatus,
    /// Whether it was unpacked.
    pub unpack: UnpackStatus,
    /// Its files.
    pub files: BTreeMap<String, FileFact>,
    /// Its Java runtime.
    pub jre: Option<JreFacts>,
    /// Its JARs: path → SHA-256 (a key of [`Facts::jars`]).
    pub jars: BTreeMap<String, String>,
    /// Manifests inside it.
    pub embedded_manifests: BTreeMap<String, EmbeddedManifest>,
    /// Installer metadata.
    pub meta: DistMeta,
}

/// Whether a distribution was unpacked.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UnpackStatus {
    /// Unpacked.
    Ok,
    /// Not unpacked (no tool, a format not unpacked).
    Skipped {
        /// Why.
        reason: String,
    },
    /// Unpacking failed.
    Failed {
        /// Why.
        reason: String,
    },
}

/// A file of a distribution.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFact {
    /// Size.
    pub size: u64,
    /// SHA-256.
    pub sha256: String,
    /// Kind.
    pub kind: FileKind,
}

/// A manifest found inside a file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedManifest {
    /// SHA-256.
    pub sha256: String,
    /// `version`.
    pub version: String,
    /// Number of bundles.
    pub bundles: u32,
    /// SHA-256 of the signer's certificate.
    pub signer_sha256: Option<String>,
    /// Whether it verified against the trusted CAs.
    pub verified: bool,
}

/// A certificate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertRef {
    /// Serial, lowercase hex.
    pub serial: String,
    /// SHA-256.
    pub sha256: String,
    /// Subject (RFC 4514).
    pub subject: String,
}

/// A JAR.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JarFacts {
    /// Size.
    pub size: u64,
    /// `Bundle-SymbolicName` without parameters.
    pub symname: Option<String>,
    /// `Bundle-Version` (else `Implementation-Version`).
    pub version: Option<String>,
    /// Number of entries.
    pub entries: u32,
    /// SHA-256 of the sorted `path\0sha256\n` lines of all entries but the manifest and the
    /// signature files: the same for a repacked or re-signed JAR.
    pub content_sha256: String,
    /// The allowed headers of `META-INF/MANIFEST.MF`.
    pub manifest_mf: BTreeMap<String, String>,
    /// Signature blocks (`META-INF/*.RSA|DSA|EC`): their signer.
    pub signers: BTreeMap<String, CertRef>,
    /// The API of its own classes.
    pub api: ApiSurface,
    /// Classes of other packages, by 2-level package.
    pub libraries: BTreeMap<String, u32>,
    /// Native libraries: path → SHA-256.
    pub natives: BTreeMap<String, String>,
    /// Keystores by path.
    pub keystores: BTreeMap<String, KeystoreFacts>,
    /// Manifests inside it.
    pub embedded_manifests: BTreeMap<String, EmbeddedManifest>,
}

/// The API of a JAR's own classes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSurface {
    /// Public classes by name (`a.b.C`).
    pub classes: BTreeMap<String, ClassApi>,
    /// Methods annotated `NCALayerMethod`: `a.b.C.m(desc)`.
    pub ncalayer_methods: BTreeSet<String>,
    /// Dotted names among the string constants.
    pub names: BTreeSet<String>,
    /// Error codes among the string constants.
    pub error_codes: BTreeSet<String>,
    /// URLs among the string constants.
    pub urls: BTreeSet<String>,
    /// Integer constants in the range of NCALayer's ports.
    pub ports: BTreeSet<u16>,
}

/// A public class.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassApi {
    /// `class`, `interface`, `enum` or `annotation`.
    pub kind: String,
    /// Superclass.
    pub super_name: Option<String>,
    /// Interfaces.
    pub interfaces: BTreeSet<String>,
    /// Public and protected methods: `name(desc)`.
    pub methods: BTreeSet<String>,
    /// Public and protected fields: `name:desc`.
    pub fields: BTreeSet<String>,
}

/// A keystore: aliases and certificates, never keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreFacts {
    /// Trusted certificates by alias.
    pub trusted: BTreeMap<String, CertRef>,
    /// Private key entries by alias: their chains.
    pub private: BTreeMap<String, Vec<CertRef>>,
}

/// A certificate as [`CertRef`].
pub fn cert_ref(cert: &Certificate) -> CertRef {
    let s = super::manifest::signer_facts(cert);
    CertRef {
        serial: s.serial,
        sha256: s.sha256,
        subject: s.subject,
    }
}

/// The facts of a manifest.
pub fn manifest_facts(v: &Verified) -> ManifestFacts {
    let m = &v.manifest;
    ManifestFacts {
        sha256: v.sha256.clone(),
        size: v.size,
        version: m.version.clone(),
        info: m.info.clone(),
        updurl: m.updurl.clone(),
        syspkgs: m.syspkgs.iter().cloned().collect(),
        disturls: m.disturls.clone(),
        signer: v.signer.clone(),
        signing_time: v.signing_time.map(rfc3339),
        extra: m.extra.clone(),
    }
}

/// The facts of a bundle: the manifest's fields, the fetch outcome and its JAR (SHA-256 and
/// facts) if fetched.
pub fn jar_entry_bundle(
    b: &Bundle,
    jar: Option<(&str, &JarFacts)>,
    fetch: FetchStatus,
) -> BundleFacts {
    let signer_matches = jar.and_then(|(_, j)| {
        if b.csernum.is_empty() && b.chash.is_empty() {
            return None;
        }
        let plain = |s: &str| s.trim_start_matches('0').to_ascii_lowercase();
        Some(j.signers.values().any(|c| {
            (b.csernum.is_empty() || plain(&c.serial) == plain(&b.csernum))
                && (b.chash.is_empty() || c.sha256.eq_ignore_ascii_case(&b.chash))
        }))
    });
    BundleFacts {
        name: b.name.clone(),
        version: b.version.clone(),
        required: b.required,
        hidden: b.hidden,
        banned: b.banned,
        info: b.info.clone(),
        url: b.url.clone(),
        hash: b.hash.to_ascii_lowercase(),
        csernum: b.csernum.clone(),
        chash: b.chash.to_ascii_lowercase(),
        extra: b.extra.clone(),
        fetch,
        jar: jar.map(|(sha, _)| sha.to_owned()),
        signer_matches,
    }
}

/// A manifest inside a file, summarised: verified against `trusted`, else only read.
pub fn embedded_manifest(bytes: &[u8], trusted: &[Certificate]) -> Option<EmbeddedManifest> {
    let sha256 = sha256_hex(bytes);
    if let Ok(v) = super::manifest::verify_and_parse(bytes, trusted) {
        return Some(EmbeddedManifest {
            sha256,
            version: v.manifest.version,
            bundles: u32::try_from(v.manifest.bundles.len()).unwrap_or(u32::MAX),
            signer_sha256: Some(v.signer.sha256),
            verified: true,
        });
    }
    let content = oncl_pki::cms::content(bytes).ok()??;
    let m = super::manifest::parse_json(&content).ok()?;
    let signer_sha256 = oncl_pki::cms::certificates(bytes)
        .ok()
        .and_then(|c| c.first().map(|c| cert_ref(c).sha256));
    Some(EmbeddedManifest {
        sha256,
        version: m.version,
        bundles: u32::try_from(m.bundles.len()).unwrap_or(u32::MAX),
        signer_sha256,
        verified: false,
    })
}

/// What a run learnt about a distribution.
pub struct DistInput<'a> {
    /// The source.
    pub source: &'a Source,
    /// The page of a page link.
    pub page: Option<&'a str>,
    /// The download, if it succeeded.
    pub downloaded: Option<&'a Downloaded>,
    /// Its format.
    pub format: Option<Format>,
    /// The fetch outcome.
    pub status: FetchStatus,
    /// The unpacking.
    pub unpacked: Result<&'a Unpacked, String>,
    /// The inventory.
    pub inventory: Option<&'a Inventory>,
}

/// The facts of a distribution and of its JARs (by SHA-256).
pub fn dist_facts(
    input: &DistInput<'_>,
    trusted: &[Certificate],
    limits: &Limits,
) -> (DistFacts, BTreeMap<String, JarFacts>) {
    let source = input.source;
    let (label, published_sha1) = match &source.kind {
        SourceKind::Page {
            label,
            published_sha1,
        } => (Some(label.clone()), published_sha1.clone()),
        _ => (None, None),
    };
    let mut facts = DistFacts {
        url: without_query(&source.url),
        page: input.page.map(str::to_owned),
        label,
        filename: input.downloaded.and_then(|d| d.filename.clone()),
        size: input.downloaded.map(|d| d.size),
        sha256: input.downloaded.map(|d| d.sha256.clone()),
        published_sha1,
        format: input.format,
        status: input.status,
        unpack: UnpackStatus::Skipped {
            reason: "not fetched".to_owned(),
        },
        files: BTreeMap::new(),
        jre: None,
        jars: BTreeMap::new(),
        embedded_manifests: BTreeMap::new(),
        meta: DistMeta::default(),
    };
    let mut jars = BTreeMap::new();
    if input.downloaded.is_none() {
        return (facts, jars);
    }
    let tree: Option<&super::unpack::Tree> = match &input.unpacked {
        Err(reason) => {
            facts.unpack = UnpackStatus::Failed {
                reason: reason.clone(),
            };
            return (facts, jars);
        }
        Ok(Unpacked::Skipped { reason }) => {
            facts.unpack = UnpackStatus::Skipped {
                reason: reason.clone(),
            };
            None
        }
        Ok(Unpacked::Tree(tree)) => {
            facts.unpack = UnpackStatus::Ok;
            facts.meta = tree.meta.clone();
            Some(tree)
        }
    };
    if let Some(d) = input.downloaded
        && source.id == "fixed:tzdb.dat"
        && let Ok(bytes) = std::fs::read(&d.path)
    {
        facts.meta.tzdb = tzdb_meta(&bytes);
    }
    if let Some(inv) = input.inventory {
        facts.files = inv
            .files
            .iter()
            .map(|(p, f)| {
                (
                    p.clone(),
                    FileFact {
                        size: f.size,
                        sha256: f.sha256.clone(),
                        kind: f.kind,
                    },
                )
            })
            .collect();
        facts.jre = inv.jre.clone();
        for (path, bytes) in &inv.nested {
            let sha = sha256_hex(bytes);
            if let Ok(entries) = jar_entries(bytes, limits) {
                jars.insert(
                    sha.clone(),
                    jar_facts(&entries, bytes.len() as u64, trusted),
                );
            }
            facts.jars.insert(path.clone(), sha);
        }
        for (path, bytes) in &inv.blobs {
            let base = path
                .rsplit(['/', '!'])
                .next()
                .unwrap_or(path)
                .to_ascii_lowercase();
            match base.as_str() {
                "ncalayer.der" => {
                    if let Some(m) = embedded_manifest(bytes, trusted) {
                        facts.embedded_manifests.insert(path.clone(), m);
                    }
                }
                "install_script.iss" => {
                    facts.meta.inno = Some(inno_meta(&String::from_utf8_lossy(bytes)));
                }
                "info.plist" if path.contains("Contents/") => {
                    facts.meta.macos = Some(mac_meta(&String::from_utf8_lossy(bytes)));
                }
                _ => {}
            }
        }
    }
    // A root archive that is itself a JAR (the payload of the `.sh`, the dropper's program).
    if let Some(tree) = tree
        && let TreeRoot::Archive(path) = &tree.root
        && let Ok(bytes) = std::fs::read(path)
        && let Ok(entries) = jar_entries(&bytes, limits)
        && entries.contains_key("META-INF/MANIFEST.MF")
    {
        let (name, jar_bytes): (&str, &[u8]) = match (&tree.meta.sh, &tree.meta.lite) {
            (Some(sh), _) => (
                "payload.jar",
                bytes
                    .get(usize::try_from(sh.payload_offset).unwrap_or(usize::MAX)..)
                    .unwrap_or_default(),
            ),
            (_, Some(_)) => ("embedded.exe", &bytes),
            _ => (
                input
                    .downloaded
                    .and_then(|d| d.filename.as_deref())
                    .unwrap_or("file.jar"),
                &bytes,
            ),
        };
        let sha = sha256_hex(jar_bytes);
        jars.insert(
            sha.clone(),
            jar_facts(&entries, jar_bytes.len() as u64, trusted),
        );
        facts.jars.insert(name.to_owned(), sha);
    }
    (facts, jars)
}

/// What a run changes in the facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Updates {
    /// Bundles fetched or tried: symbolic name → outcome.
    pub bundles: BTreeMap<String, BundleUpdate>,
    /// Distributions by source id: new facts, or `None` when the source is gone.
    pub distributions: BTreeMap<String, Option<DistFacts>>,
    /// JARs by SHA-256.
    pub jars: BTreeMap<String, JarFacts>,
}

/// The outcome of fetching a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleUpdate {
    /// The outcome.
    pub fetch: FetchStatus,
    /// SHA-256 of the JAR.
    pub jar: Option<String>,
}

/// The facts after a run: the manifest's, the updates, and the rest carried over from
/// `prev`; JARs nothing refers to any more are dropped.
pub fn merge(prev: Option<&Facts>, manifest: &Verified, updates: Updates) -> Facts {
    let mut jars: BTreeMap<String, JarFacts> = prev.map(|p| p.jars.clone()).unwrap_or_default();
    jars.extend(updates.jars);
    let mut bundles = BTreeMap::new();
    for b in &manifest.manifest.bundles {
        if b.symname.is_empty() {
            continue;
        }
        let before = prev.and_then(|p| p.bundles.get(&b.symname));
        let (fetch, jar) = match updates.bundles.get(&b.symname) {
            Some(u) => (u.fetch, u.jar.clone()),
            None => match before {
                Some(p) if p.hash.eq_ignore_ascii_case(&b.hash) && p.url == b.url => {
                    (p.fetch, p.jar.clone())
                }
                _ => (FetchStatus::Pending, None),
            },
        };
        let jar_ref = jar
            .as_deref()
            .and_then(|sha| jars.get(sha).map(|j| (sha, j)));
        let mut facts = jar_entry_bundle(b, jar_ref, fetch);
        facts.jar = jar;
        bundles.insert(b.symname.clone(), facts);
    }
    let mut distributions = prev.map(|p| p.distributions.clone()).unwrap_or_default();
    for (id, d) in updates.distributions {
        match d {
            Some(d) => {
                distributions.insert(id, d);
            }
            None => {
                distributions.remove(&id);
            }
        }
    }
    let used: BTreeSet<&String> = bundles
        .values()
        .filter_map(|b| b.jar.as_ref())
        .chain(distributions.values().flat_map(|d| d.jars.values()))
        .collect();
    let jars = jars
        .into_iter()
        .filter(|(sha, _)| used.contains(sha))
        .collect();
    Facts {
        schema: FACTS_SCHEMA,
        manifest: manifest_facts(manifest),
        bundles,
        distributions,
        jars,
    }
}

/// `facts.json` bytes.
pub fn to_json(f: &Facts) -> Vec<u8> {
    pretty_json(f)
}

/// The first 8 hex digits of the SHA-256 of `json`.
pub fn key8(json: &[u8]) -> String {
    sha256_hex(json)[..8].to_owned()
}
