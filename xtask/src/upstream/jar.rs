//! The facts of one JAR: `META-INF/MANIFEST.MF`, the signers of its signature blocks, the
//! API of its own classes, its libraries, native files, keystores and embedded manifests.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use oncl_pki::cert::Certificate;
use oncl_pki::jks::{self, JksEntryKind};

use super::classfile::{
    ACC_ANNOTATION, ACC_ENUM, ACC_INTERFACE, ACC_PROTECTED, ACC_PUBLIC, ACC_SYNTHETIC, ClassInfo,
    parse_class,
};
use super::facts::{ApiSurface, ClassApi, JarFacts, KeystoreFacts, cert_ref, embedded_manifest};
use super::inventory::{FileKind, file_kind, normalize};
use super::sha256_hex;
use super::unpack::{Limits, UnpackError};

/// The `MANIFEST.MF` headers kept.
pub const MANIFEST_HEADERS: [&str; 10] = [
    "Bundle-SymbolicName",
    "Bundle-Version",
    "Bundle-Name",
    "Bundle-Activator",
    "Export-Package",
    "Import-Package",
    "Bundle-ClassPath",
    "Bundle-NativeCode",
    "Main-Class",
    "Implementation-Version",
];

/// The NCALayer ports (13579 and the next hundred).
const PORTS: std::ops::RangeInclusive<i32> = 13579..=13679;

/// The main section of a `MANIFEST.MF`: continuation lines (starting with a space) joined,
/// CRLF or LF.
pub fn manifest_mf(bytes: &[u8]) -> BTreeMap<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if let Some(cont) = line.strip_prefix(' ') {
            if let Some((_, v)) = &mut current {
                v.push_str(cont);
            }
            continue;
        }
        if let Some((k, v)) = current.take() {
            out.insert(k, v);
        }
        if let Some((k, v)) = line.split_once(':') {
            current = Some((k.trim().to_owned(), v.trim_start().to_owned()));
        }
    }
    if let Some((k, v)) = current {
        out.insert(k, v);
    }
    out
}

/// The entries of a JAR in memory: normalized path → bytes.
///
/// # Errors
///
/// [`UnpackError`]: not a ZIP or a limit.
pub fn jar_entries(
    bytes: &[u8],
    limits: &Limits,
) -> Result<BTreeMap<String, Vec<u8>>, UnpackError> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| UnpackError::Malformed(format!("JAR: {e}")))?;
    let mut out = BTreeMap::new();
    let mut total = 0u64;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UnpackError::Malformed(format!("JAR entry: {e}")))?;
        if entry.is_dir() || entry.is_symlink() {
            continue;
        }
        let name = normalize(
            &entry
                .name()
                .map_err(|e| UnpackError::Malformed(format!("JAR entry name: {e}")))?,
        );
        let mut data = Vec::new();
        (&mut entry)
            .take(limits.entry_bytes + 1)
            .read_to_end(&mut data)
            .map_err(|e| UnpackError::Malformed(format!("JAR entry {name}: {}", e.kind())))?;
        if data.len() as u64 > limits.entry_bytes {
            return Err(UnpackError::Limit("entry_bytes"));
        }
        total += data.len() as u64;
        if total > limits.total_bytes {
            return Err(UnpackError::Limit("total_bytes"));
        }
        if !name.is_empty() {
            out.insert(name, data);
        }
    }
    Ok(out)
}

/// Whether `path` is the manifest or a signature file, which repacking and re-signing change.
fn is_signature_or_manifest(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    upper == "META-INF/MANIFEST.MF"
        || upper.starts_with("META-INF/")
            && !upper["META-INF/".len()..].contains('/')
            && [".SF", ".RSA", ".DSA", ".EC"]
                .iter()
                .any(|ext| upper.ends_with(ext))
}

/// The facts of a JAR whose entries are `entries`; embedded manifests are verified against
/// `trusted`.
pub fn jar_facts(
    entries: &BTreeMap<String, Vec<u8>>,
    size: u64,
    trusted: &[Certificate],
) -> JarFacts {
    let mf = entries
        .get("META-INF/MANIFEST.MF")
        .map(|b| manifest_mf(b))
        .unwrap_or_default();
    let symname = mf
        .get("Bundle-SymbolicName")
        .map(|s| s.split(';').next().unwrap_or_default().trim().to_owned())
        .filter(|s| !s.is_empty());
    let version = mf
        .get("Bundle-Version")
        .or_else(|| mf.get("Implementation-Version"))
        .cloned();

    let mut lines: Vec<String> = entries
        .iter()
        .filter(|(p, _)| !is_signature_or_manifest(p))
        .map(|(p, b)| format!("{p}\0{}\n", sha256_hex(b)))
        .collect();
    lines.sort();
    let content_sha256 = sha256_hex(lines.concat().as_bytes());

    let mut signers = BTreeMap::new();
    for (path, bytes) in entries {
        let upper = path.to_ascii_uppercase();
        if is_signature_or_manifest(path)
            && !upper.ends_with(".SF")
            && upper != "META-INF/MANIFEST.MF"
            && let Ok(certs) = oncl_pki::cms::certificates(bytes)
            && let Some(first) = certs.first()
        {
            signers.insert(path.clone(), cert_ref(first));
        }
    }

    // Own packages: the first two segments of the symbolic name (else of Main-Class) and the
    // activator's package.
    let mut own: BTreeSet<String> = BTreeSet::new();
    let two = |dotted: &str| {
        let parts: Vec<&str> = dotted.split('.').filter(|p| !p.is_empty()).collect();
        (parts.len() >= 2).then(|| format!("{}/{}/", parts[0], parts[1]))
    };
    if let Some(p) = symname
        .as_deref()
        .or(mf.get("Main-Class").map(String::as_str))
        .and_then(two)
    {
        own.insert(p);
    }
    if let Some(activator) = mf.get("Bundle-Activator")
        && let Some((pkg, _)) = activator.trim().rsplit_once('.')
    {
        own.insert(format!("{}/", pkg.replace('.', "/")));
    }

    let mut api = ApiSurface::default();
    let mut libraries: BTreeMap<String, u32> = BTreeMap::new();
    let mut natives = BTreeMap::new();
    let mut keystores = BTreeMap::new();
    let mut embedded_manifests = BTreeMap::new();
    for (path, bytes) in entries {
        let kind = file_kind(path, &bytes[..bytes.len().min(4096)]);
        match kind {
            FileKind::Class => {
                let Ok(class) = parse_class(bytes) else {
                    continue;
                };
                if own.iter().any(|p| class.name.starts_with(p.as_str())) {
                    add_class(&mut api, &class);
                } else {
                    let package: Vec<&str> = class.name.split('/').collect();
                    let key = if package.len() > 2 {
                        format!("{}.{}", package[0], package[1])
                    } else if package.len() == 2 {
                        package[0].to_owned()
                    } else {
                        String::new()
                    };
                    *libraries.entry(key).or_default() += 1;
                }
            }
            FileKind::Native => {
                natives.insert(path.clone(), sha256_hex(bytes));
            }
            FileKind::Keystore => {
                if let Ok(list) = jks::entries(bytes) {
                    let mut facts = KeystoreFacts::default();
                    for e in list {
                        match e.kind {
                            JksEntryKind::TrustedCert(c) => {
                                facts.trusted.insert(e.alias, cert_ref(&c));
                            }
                            JksEntryKind::PrivateKey { chain } => {
                                facts
                                    .private
                                    .insert(e.alias, chain.iter().map(cert_ref).collect());
                            }
                        }
                    }
                    keystores.insert(path.clone(), facts);
                }
            }
            FileKind::Manifest => {
                if let Some(m) = embedded_manifest(bytes, trusted) {
                    embedded_manifests.insert(path.clone(), m);
                }
            }
            _ => {}
        }
    }
    JarFacts {
        size,
        symname,
        version,
        entries: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        content_sha256,
        manifest_mf: mf
            .into_iter()
            .filter(|(k, _)| MANIFEST_HEADERS.contains(&k.as_str()))
            .collect(),
        signers,
        api,
        libraries,
        natives,
        keystores,
        embedded_manifests,
    }
}

fn visible(access: u16) -> bool {
    access & (ACC_PUBLIC | ACC_PROTECTED) != 0 && access & ACC_SYNTHETIC == 0
}

fn generated(name: &str) -> bool {
    name.starts_with("lambda$") || name == "$values" || name.starts_with("$SWITCH_TABLE$")
}

fn dotted(internal: &str) -> String {
    internal.replace('/', ".")
}

fn add_class(api: &mut ApiSurface, class: &ClassInfo) {
    let name = dotted(&class.name);
    for m in &class.methods {
        if m.annotations
            .iter()
            .any(|a| a.ends_with("/NCALayerMethod;"))
        {
            api.ncalayer_methods
                .insert(format!("{name}.{}{}", m.name, m.descriptor));
        }
    }
    for s in &class.strings {
        if is_name(s) {
            api.names.insert(s.clone());
        }
        if is_error_code(s) {
            api.error_codes.insert(s.clone());
        }
        if is_url(s) {
            api.urls.insert(s.clone());
        }
    }
    for v in &class.ints {
        if PORTS.contains(v) {
            api.ports
                .insert(u16::try_from(*v).expect("in the port range"));
        }
    }
    if class.access & ACC_PUBLIC == 0 || class.access & ACC_SYNTHETIC != 0 {
        return;
    }
    let kind = if class.access & ACC_ANNOTATION != 0 {
        "annotation"
    } else if class.access & ACC_INTERFACE != 0 {
        "interface"
    } else if class.access & ACC_ENUM != 0 {
        "enum"
    } else {
        "class"
    };
    api.classes.insert(
        name,
        ClassApi {
            kind: kind.to_owned(),
            super_name: class.super_name.as_deref().map(dotted),
            interfaces: class.interfaces.iter().map(|i| dotted(i)).collect(),
            methods: class
                .methods
                .iter()
                .filter(|m| visible(m.access) && !generated(&m.name))
                .map(|m| format!("{}{}", m.name, m.descriptor))
                .collect(),
            fields: class
                .fields
                .iter()
                .filter(|f| visible(f.access) && !generated(&f.name))
                .map(|f| format!("{}:{}", f.name, f.descriptor))
                .collect(),
        },
    );
}

/// `^[a-z][a-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_$]*){2,}$`, not of the JDK.
fn is_name(s: &str) -> bool {
    if ["java.", "javax.", "sun.", "com.sun."]
        .iter()
        .any(|p| s.starts_with(p))
    {
        return false;
    }
    let mut parts = s.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let first_ok = first.starts_with(|c: char| c.is_ascii_lowercase())
        && first
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    let rest: Vec<&str> = parts.collect();
    first_ok
        && rest.len() >= 2
        && rest.iter().all(|p| {
            p.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        })
}

/// `^[A-Z][A-Z0-9_]{3,}$` with an error word.
fn is_error_code(s: &str) -> bool {
    const WORDS: [&str; 10] = [
        "ERROR",
        "FAIL",
        "INVALID",
        "UNKNOWN",
        "NOT_FOUND",
        "DENIED",
        "EXPIRED",
        "REVOKED",
        "TIMEOUT",
        "WRONG",
    ];
    s.len() >= 4
        && s.starts_with(|c: char| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && WORDS.iter().any(|w| s.contains(w))
}

/// `^(https?|ldap)://\S+$`.
fn is_url(s: &str) -> bool {
    ["http://", "https://", "ldap://"].iter().any(|p| {
        s.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && !rest.chars().any(char::is_whitespace))
    })
}
