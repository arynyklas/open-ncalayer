//! Metadata of installers: the Inno Setup script's `[Setup]` keys, registry values and run
//! entries, the macOS bundle's `Info.plist`, the payload offset of the `.sh` installer, the
//! Go dropper's embedded program and the versions of a `tzdb.dat`. Only names, versions and
//! hashes: no script text.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Metadata of a distribution; absent parts are `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistMeta {
    /// An Inno Setup installer.
    pub inno: Option<InnoMeta>,
    /// A macOS disk image.
    pub macos: Option<MacMeta>,
    /// A `.sh` installer.
    pub sh: Option<ShMeta>,
    /// The Windows lite dropper.
    pub lite: Option<LiteMeta>,
    /// A `tzdb.dat`.
    pub tzdb: Option<TzdbMeta>,
}

/// From `install_script.iss`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnoMeta {
    /// The `[Setup]` keys of [`INNO_SETUP_KEYS`].
    pub setup: BTreeMap<String, String>,
    /// `Root\Subkey\ValueName` of `[Registry]`.
    pub registry: BTreeSet<String>,
    /// `Filename` of `[Run]`.
    pub run: BTreeSet<String>,
}

/// The `[Setup]` keys kept.
pub const INNO_SETUP_KEYS: [&str; 9] = [
    "AppId",
    "AppName",
    "AppVersion",
    "AppPublisher",
    "PrivilegesRequired",
    "DefaultDirName",
    "ArchitecturesAllowed",
    "ArchitecturesInstallIn64BitMode",
    "MinVersion",
];

/// From `Contents/Info.plist`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacMeta {
    /// `CFBundleIdentifier`.
    pub bundle_id: Option<String>,
    /// `CFBundleVersion`.
    pub bundle_version: Option<String>,
    /// `CFBundleShortVersionString`.
    pub short_version: Option<String>,
    /// `LSMinimumSystemVersion`.
    pub minimum_system: Option<String>,
}

/// The `.sh` installer: a script, then a ZIP payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShMeta {
    /// Where the payload starts.
    pub payload_offset: u64,
    /// SHA-256 of the script before it.
    pub header_sha256: String,
}

/// The Go dropper: a Go program carrying a gzip stream of the real installer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiteMeta {
    /// The Go version string (`go1.…`).
    pub go_version: Option<String>,
    /// SHA-256 of the embedded program.
    pub embedded_exe_sha256: String,
}

/// A `tzdb.dat`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TzdbMeta {
    /// The region versions (`2026a`, …).
    pub versions: Vec<String>,
}

/// The allowed `[Setup]` keys, `[Registry]` values and `[Run]` file names of an Inno Setup
/// script (`innounp -m` writes it as `install_script.iss`).
pub fn inno_meta(script: &str) -> InnoMeta {
    let mut meta = InnoMeta::default();
    let mut section = String::new();
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_ascii_lowercase();
            continue;
        }
        match section.as_str() {
            "setup" => {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    if let Some(k) = INNO_SETUP_KEYS.iter().find(|k| k.eq_ignore_ascii_case(key)) {
                        meta.setup.insert((*k).to_owned(), value.trim().to_owned());
                    }
                }
            }
            "registry" => {
                let p = params(line);
                if let (Some(root), Some(subkey)) = (p.get("root"), p.get("subkey")) {
                    let name = p.get("valuename").map_or("", String::as_str);
                    meta.registry.insert(format!("{root}\\{subkey}\\{name}"));
                }
            }
            "run" => {
                if let Some(file) = params(line).get("filename") {
                    meta.run.insert(file.clone());
                }
            }
            _ => {}
        }
    }
    meta
}

/// `Name: value; Name: "value"` parameters of an Inno Setup line, lowercase names.
fn params(line: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = line;
    while !rest.is_empty() {
        let Some((name, after)) = rest.split_once(':') else {
            break;
        };
        let after = after.trim_start();
        let (value, next) = if let Some(quoted) = after.strip_prefix('"') {
            // `""` is a quote inside a quoted value.
            let mut value = String::new();
            let mut chars = quoted.char_indices().peekable();
            let mut end = quoted.len();
            while let Some((i, c)) = chars.next() {
                if c == '"' {
                    if chars.peek().map(|(_, c)| *c) == Some('"') {
                        value.push('"');
                        chars.next();
                    } else {
                        end = i + 1;
                        break;
                    }
                } else {
                    value.push(c);
                }
            }
            (value, &quoted[end..])
        } else {
            let end = after.find(';').unwrap_or(after.len());
            (after[..end].trim().to_owned(), &after[end..])
        };
        out.insert(name.trim().to_ascii_lowercase(), value);
        rest = next.trim_start().trim_start_matches(';').trim_start();
    }
    out
}

/// `CFBundle…` keys of an XML `Info.plist` (`<key>…</key><string>…</string>`).
pub fn mac_meta(plist: &str) -> MacMeta {
    let value = |key: &str| {
        let at = plist.find(&format!("<key>{key}</key>"))?;
        let rest = &plist[at..];
        let start = rest.find("<string>")? + "<string>".len();
        let end = rest[start..].find("</string>")? + start;
        Some(rest[start..end].trim().to_owned())
    };
    MacMeta {
        bundle_id: value("CFBundleIdentifier"),
        bundle_version: value("CFBundleVersion"),
        short_version: value("CFBundleShortVersionString"),
        minimum_system: value("LSMinimumSystemVersion"),
    }
}

/// The versions of a `tzdb.dat`: byte 1, the UTF `TZDB`, a `u16` count of versions and the
/// versions (Java modified UTF-8, as `DataOutput.writeUTF`).
pub fn tzdb_meta(bytes: &[u8]) -> Option<TzdbMeta> {
    let mut pos = 0;
    let byte = |pos: &mut usize| {
        let b = *bytes.get(*pos)?;
        *pos += 1;
        Some(b)
    };
    let u16_at = |pos: &mut usize| {
        let v = u16::from_be_bytes([*bytes.get(*pos)?, *bytes.get(*pos + 1)?]);
        *pos += 2;
        Some(v)
    };
    let utf = |pos: &mut usize| {
        let len = usize::from(u16_at(pos)?);
        let s = std::str::from_utf8(bytes.get(*pos..*pos + len)?)
            .ok()?
            .to_owned();
        *pos += len;
        Some(s)
    };
    if byte(&mut pos)? != 1 || utf(&mut pos)? != "TZDB" {
        return None;
    }
    let count = u16_at(&mut pos)?;
    let versions = (0..count)
        .map(|_| utf(&mut pos))
        .collect::<Option<Vec<_>>>()?;
    Some(TzdbMeta { versions })
}
