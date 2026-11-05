//! The multi-file WinGet manifest (schema 1.12.0) of OpenNCALayer: how it is written, and the
//! checks a written one must pass.
//!
//! [`render`] turns published, proven facts ([`Plan`]) into the three files. [`check_dir`]
//! reads a directory back and applies the pinned schemas (`schema.rs`) and the invariants of
//! the package that a schema cannot express: exactly one package, exactly the two Windows
//! installers at their version-specific URLs, per-user scope, no elevation, the proven
//! `--silent` and no generic `/S`, the explicit-upgrade policy, and an Apps & Features mapping
//! that equals the package version. A directory that fails is not a stable manifest.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde_json::Value;

use super::release::{REPOSITORY, StableRelease, asset_url};
use super::schema::{self, Kind, MANIFEST_VERSION};
use super::yaml::{self, Yaml};
use super::{Arch, probe::ArpIdentity};

/// The package identifier. Whether it is free in `microsoft/winget-pkgs` is checked by the
/// maintainer before the first submission (`docs/dev/winget.md`), not assumed here.
pub const PACKAGE_IDENTIFIER: &str = "arynyklas.OpenNCALayer";
/// The locale of the default-locale manifest.
pub const DEFAULT_LOCALE: &str = "en-US";
/// Windows 10 version 1809.
pub const MINIMUM_OS_VERSION: &str = "10.0.17763.0";
/// The one switch the installer entry takes, for `Silent` and `SilentWithProgress`.
pub const SILENT_SWITCH: &str = "--silent";
/// The exit code of the entry for a busy program (an active signature): not a success.
pub const BUSY_EXIT_CODE: i64 = 4;
/// `Publisher` before the Apps & Features entry of a real installation is known (a candidate).
pub const CANDIDATE_PUBLISHER: &str = "OpenNCALayer contributors";

/// What a manifest is made of.
#[derive(Clone, Debug)]
pub struct Plan<'a> {
    /// The published stable release.
    pub release: &'a StableRelease,
    /// `(arch, lowercase SHA-256)` of the bytes downloaded from the release.
    pub sha256: &'a [(Arch, String)],
    /// The Apps & Features identity proven by the probe; `None` for a candidate.
    pub identity: Option<&'a ArpIdentity>,
    /// The inputs are synthetic test fixtures.
    pub synthetic: bool,
}

/// The files of a manifest: `(file name, text)`.
pub type Files = Vec<(String, String)>;

/// File names of a manifest of [`PACKAGE_IDENTIFIER`].
pub fn file_names() -> [String; 3] {
    [
        format!("{PACKAGE_IDENTIFIER}.yaml"),
        format!("{PACKAGE_IDENTIFIER}.locale.{DEFAULT_LOCALE}.yaml"),
        format!("{PACKAGE_IDENTIFIER}.installer.yaml"),
    ]
}

fn header(kind: Kind, plan: &Plan<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    if plan.identity.is_none() {
        lines.push(
            "CANDIDATE for the installation proof run: it has no Apps & Features mapping yet. NOT FOR SUBMISSION."
                .to_owned(),
        );
    } else if plan.synthetic {
        lines.push(
            "SYNTHETIC TEST FIXTURE: made from inputs of a test, not from a real release. NOT FOR SUBMISSION."
                .to_owned(),
        );
    }
    lines.push(
        "Made by `cargo xtask winget` (docs/dev/winget.md); not submitted anywhere.".to_owned(),
    );
    lines.push(format!(
        "yaml-language-server: $schema=https://aka.ms/winget-manifest.{}.{MANIFEST_VERSION}.schema.json",
        match kind {
            Kind::Version => "version",
            Kind::DefaultLocale => "defaultLocale",
            Kind::Installer => "installer",
        }
    ));
    lines
}

fn common(plan: &Plan<'_>, kind: Kind) -> Vec<(&'static str, Yaml)> {
    let version = plan.release.version.to_string();
    let mut items = vec![
        ("PackageIdentifier", Yaml::s(PACKAGE_IDENTIFIER)),
        ("PackageVersion", Yaml::s(version)),
    ];
    if kind == Kind::DefaultLocale {
        items.push(("PackageLocale", Yaml::s(DEFAULT_LOCALE)));
    }
    items
}

fn tail(kind: Kind) -> Vec<(&'static str, Yaml)> {
    vec![
        ("ManifestType", Yaml::s(kind.manifest_type())),
        ("ManifestVersion", Yaml::s(MANIFEST_VERSION)),
    ]
}

/// Writes the three files of the manifest of `plan`.
///
/// # Panics
///
/// `plan.sha256` lacks an architecture of the release.
pub fn render(plan: &Plan<'_>) -> Files {
    let release = plan.release;
    let publisher = plan
        .identity
        .map_or(CANDIDATE_PUBLISHER, |id| id.publisher.as_str());

    // <id>.yaml
    let mut version_file = common(plan, Kind::Version);
    version_file.push(("DefaultLocale", Yaml::s(DEFAULT_LOCALE)));
    version_file.extend(tail(Kind::Version));

    // <id>.locale.en-US.yaml
    let mut locale = common(plan, Kind::DefaultLocale);
    locale.extend([
        ("Publisher", Yaml::s(publisher)),
        ("PublisherUrl", Yaml::s("https://github.com/arynyklas")),
        (
            "PublisherSupportUrl",
            Yaml::s(format!("https://github.com/{REPOSITORY}/issues")),
        ),
        ("PackageName", Yaml::s("OpenNCALayer")),
        ("PackageUrl", Yaml::s(format!("https://github.com/{REPOSITORY}"))),
        ("License", Yaml::s("Apache-2.0")),
        (
            "LicenseUrl",
            Yaml::s(format!("https://github.com/{REPOSITORY}/blob/{}/LICENSE", release.tag)),
        ),
        ("ShortDescription", Yaml::s("Open-source replacement for NCALayer, the signing daemon of Kazakhstan's e-government services")),
        (
            "Description",
            Yaml::s("OpenNCALayer is an open-source Rust replacement for NCALayer. Sites that talk to the original over wss://127.0.0.1:13579 are meant to work with it unchanged: the same protocol and modules, with PKCS#12 keys, NCA certificate validation, a browser extension and a tray program. It is an independent project and is not affiliated with the National Certification Authority of the Republic of Kazakhstan."),
        ),
        ("Moniker", Yaml::s("openncalayer")),
        (
            "Tags",
            Yaml::strings(["ncalayer", "kazakhstan", "egov", "digital-signature", "pki"]),
        ),
        ("ReleaseNotesUrl", Yaml::s(release.page())),
    ]);
    locale.extend(tail(Kind::DefaultLocale));

    // <id>.installer.yaml
    let mut installer = common(plan, Kind::Installer);
    installer.extend([
        ("Platform", Yaml::strings(["Windows.Desktop"])),
        ("MinimumOSVersion", Yaml::s(MINIMUM_OS_VERSION)),
        ("InstallerType", Yaml::s("exe")),
        ("Scope", Yaml::s("user")),
        // The entry has no interactive mode: `winget install --interactive` would start it
        // without `--silent` and it refuses (docs/dev/winget-installer.md).
        (
            "InstallModes",
            Yaml::strings(["silent", "silentWithProgress"]),
        ),
        (
            "InstallerSwitches",
            Yaml::map(vec![
                ("Silent", Yaml::s(SILENT_SWITCH)),
                ("SilentWithProgress", Yaml::s(SILENT_SWITCH)),
            ]),
        ),
        // The busy code is an answer, never a success: InstallerSuccessCodes stays unset.
        (
            "ExpectedReturnCodes",
            Yaml::Seq(vec![Yaml::map(vec![
                ("InstallerReturnCode", Yaml::Int(BUSY_EXIT_CODE)),
                ("ReturnResponse", Yaml::s("packageInUse")),
            ])]),
        ),
        ("UpgradeBehavior", Yaml::s("install")),
        ("ElevationRequirement", Yaml::s("elevationProhibited")),
        ("RequireExplicitUpgrade", Yaml::Bool(true)),
        ("UnsupportedArguments", Yaml::strings(["log", "location"])),
        ("ReleaseDate", Yaml::s(release.release_date())),
    ]);
    if let Some(identity) = plan.identity {
        installer.push((
            "AppsAndFeaturesEntries",
            Yaml::Seq(vec![Yaml::map(vec![
                ("DisplayName", Yaml::s(identity.display_name.as_str())),
                ("Publisher", Yaml::s(identity.publisher.as_str())),
                (
                    "DisplayVersion",
                    Yaml::s(identity.display_version.to_string()),
                ),
                ("ProductCode", Yaml::s(identity.key_name.as_str())),
                ("InstallerType", Yaml::s("exe")),
            ])]),
        ));
    }
    let installers = [Arch::X64, Arch::X86]
        .into_iter()
        .map(|arch| {
            let asset = release.installer(arch);
            let sha = plan
                .sha256
                .iter()
                .find(|(a, _)| *a == arch)
                .map(|(_, sha)| sha.to_ascii_uppercase())
                .expect("a hash for every architecture");
            Yaml::map(vec![
                ("Architecture", Yaml::s(arch.to_string())),
                ("InstallerUrl", Yaml::s(asset.url.as_str())),
                ("InstallerSha256", Yaml::s(sha)),
            ])
        })
        .collect();
    installer.push(("Installers", Yaml::Seq(installers)));
    installer.extend(tail(Kind::Installer));

    let [version_name, locale_name, installer_name] = file_names();
    vec![
        (
            version_name,
            yaml::emit(&header(Kind::Version, plan), &Yaml::map(version_file)),
        ),
        (
            locale_name,
            yaml::emit(&header(Kind::DefaultLocale, plan), &Yaml::map(locale)),
        ),
        (
            installer_name,
            yaml::emit(&header(Kind::Installer, plan), &Yaml::map(installer)),
        ),
    ]
}

/// What is expected of a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A manifest for the proof run: no Apps & Features mapping yet.
    Candidate,
    /// A manifest that may be submitted: the mapping is there and equals the package version.
    Final,
}

/// The facts of a checked manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// `PackageVersion`.
    pub version: String,
    /// `(arch, URL, uppercase SHA-256)` of each installer.
    pub installers: Vec<(Arch, String, String)>,
}

/// The problems of a manifest directory, one sentence each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestError(pub Vec<String>);

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the manifest is not acceptable:")?;
        for problem in &self.0 {
            write!(f, "\n  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ManifestError {}

/// Reads and checks the manifest directory `dir`.
///
/// # Errors
///
/// Every problem found: files, YAML subset, schema (1.12.0) and the invariants of the package.
pub fn check_dir(dir: &Path, mode: Mode) -> Result<Checked, ManifestError> {
    let mut problems = Vec::new();
    let expected = file_names();
    let mut names = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        Err(e) => {
            return Err(ManifestError(vec![format!(
                "{} cannot be read: {e}",
                dir.display()
            )]));
        }
    }
    names.sort();
    for name in &names {
        if !expected.contains(name) {
            problems.push(format!(
                "{name} does not belong to a multi-file manifest of {PACKAGE_IDENTIFIER}"
            ));
        }
    }
    let mut documents: BTreeMap<&str, Value> = BTreeMap::new();
    for (name, kind) in expected
        .iter()
        .zip([Kind::Version, Kind::DefaultLocale, Kind::Installer])
    {
        let path = dir.join(name);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                problems.push(format!("{name} cannot be read: {e}"));
                continue;
            }
        };
        let value = match yaml::parse(&text) {
            Ok(value) => value,
            Err(e) => {
                problems.push(format!("{name}: {e}"));
                continue;
            }
        };
        if value["ManifestType"] != kind.manifest_type() {
            problems.push(format!(
                "{name}: ManifestType is {} not {}",
                value["ManifestType"],
                kind.manifest_type()
            ));
        }
        for error in schema::validate(kind, &value) {
            problems.push(format!("{name}: {error}"));
        }
        documents.insert(kind.manifest_type(), value);
    }
    if !problems.is_empty() {
        return Err(ManifestError(problems));
    }
    let checked = invariants(&documents, mode, &mut problems);
    match (problems.is_empty(), checked) {
        (true, Some(checked)) => Ok(checked),
        _ => Err(ManifestError(problems)),
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// A key of an installer entry: its own value, else the manifest's (the root holds defaults).
fn effective<'a>(root: &'a Value, entry: &'a Value, key: &str) -> Option<&'a Value> {
    entry
        .get(key)
        .or_else(|| root.get(key))
        .filter(|v| !v.is_null())
}

fn invariants(
    documents: &BTreeMap<&str, Value>,
    mode: Mode,
    problems: &mut Vec<String>,
) -> Option<Checked> {
    let version_doc = &documents["version"];
    let locale = &documents["defaultLocale"];
    let installer = &documents["installer"];

    let version = text(installer, "PackageVersion")
        .unwrap_or_default()
        .to_owned();
    for (name, document) in documents {
        if text(document, "PackageIdentifier") != Some(PACKAGE_IDENTIFIER) {
            problems.push(format!(
                "{name}: PackageIdentifier is not {PACKAGE_IDENTIFIER}"
            ));
        }
        if text(document, "PackageVersion") != Some(version.as_str()) {
            problems.push(format!(
                "{name}: PackageVersion differs from the installer manifest's"
            ));
        }
        if text(document, "ManifestVersion") != Some(MANIFEST_VERSION) {
            problems.push(format!("{name}: ManifestVersion is not {MANIFEST_VERSION}"));
        }
    }
    let stable = version.split('.').count() == 3
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if !stable {
        problems.push(format!(
            "PackageVersion {version:?} is not a stable <major>.<minor>.<patch> version"
        ));
    }
    if text(version_doc, "DefaultLocale") != Some(DEFAULT_LOCALE)
        || text(locale, "PackageLocale") != Some(DEFAULT_LOCALE)
    {
        problems.push(format!("the default locale is not {DEFAULT_LOCALE}"));
    }

    // Installer entries.
    let root = installer;
    let items = installer["Installers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut found = Vec::new();
    for entry in &items {
        let arch = match text(entry, "Architecture") {
            Some("x64") => Arch::X64,
            Some("x86") => Arch::X86,
            other => {
                problems.push(format!(
                    "an installer for {other:?}: only x64 and x86 are packaged"
                ));
                continue;
            }
        };
        let url = text(entry, "InstallerUrl").unwrap_or_default().to_owned();
        let sha = text(entry, "InstallerSha256")
            .unwrap_or_default()
            .to_owned();
        let name = format!("openncalayer-{version}-win-{arch}-winget-setup.exe");
        if url != asset_url(&format!("v{version}"), &name) {
            problems.push(format!(
                "the {arch} InstallerUrl is not the version-specific release URL of {name} (mutable or foreign URLs are refused)"
            ));
        }
        let want = |key: &str, value: &str, problems: &mut Vec<String>| {
            if effective(root, entry, key).and_then(Value::as_str) != Some(value) {
                problems.push(format!("the {arch} installer: {key} is not {value}"));
            }
        };
        want("InstallerType", "exe", problems);
        want("Scope", "user", problems);
        want("ElevationRequirement", "elevationProhibited", problems);
        want("MinimumOSVersion", MINIMUM_OS_VERSION, problems);
        want("UpgradeBehavior", "install", problems);
        if effective(root, entry, "RequireExplicitUpgrade") != Some(&Value::Bool(true)) {
            problems.push(format!(
                "the {arch} installer: RequireExplicitUpgrade is not true"
            ));
        }
        match effective(root, entry, "InstallerSwitches").and_then(Value::as_object) {
            Some(switches) => {
                for key in ["Silent", "SilentWithProgress"] {
                    if switches.get(key).and_then(Value::as_str) != Some(SILENT_SWITCH) {
                        problems.push(format!(
                            "the {arch} installer: {key} is not the proven {SILENT_SWITCH}"
                        ));
                    }
                }
                if let Some(other) = switches
                    .keys()
                    .find(|key| !matches!(key.as_str(), "Silent" | "SilentWithProgress"))
                {
                    problems.push(format!(
                        "the {arch} installer: the switch {other} was never tested"
                    ));
                }
            }
            None => problems.push(format!("the {arch} installer has no InstallerSwitches")),
        }
        if effective(root, entry, "InstallerSuccessCodes").is_some() {
            problems.push(format!("the {arch} installer widens InstallerSuccessCodes"));
        }
        if let Some(modes) = effective(root, entry, "InstallModes").and_then(Value::as_array)
            && modes.iter().any(|mode| mode == "interactive")
        {
            problems.push(format!(
                "the {arch} installer offers an interactive mode, which the entry refuses"
            ));
        }
        found.push((arch, url, sha.to_ascii_uppercase()));
    }
    let mut archs: Vec<Arch> = found.iter().map(|(arch, _, _)| *arch).collect();
    archs.sort();
    if archs != [Arch::X64, Arch::X86] {
        problems.push("the manifest must have exactly one x64 and one x86 installer".to_owned());
    }
    if let Some(codes) = installer
        .get("ExpectedReturnCodes")
        .and_then(Value::as_array)
    {
        for code in codes {
            if code["InstallerReturnCode"] != BUSY_EXIT_CODE {
                problems.push(format!(
                    "ExpectedReturnCodes names the code {}, which was not proven",
                    code["InstallerReturnCode"]
                ));
            }
        }
    }

    // The Apps & Features mapping.
    match (
        mode,
        installer
            .get("AppsAndFeaturesEntries")
            .and_then(Value::as_array),
    ) {
        (Mode::Candidate, Some(_)) => {
            problems.push(
                "a candidate manifest has an Apps & Features mapping that no probe proved"
                    .to_owned(),
            );
        }
        (Mode::Candidate, None) => {}
        (Mode::Final, None) => {
            problems.push(
                "there is no AppsAndFeaturesEntries: the ARP mapping is not proven".to_owned(),
            );
        }
        (Mode::Final, Some(entries)) => {
            if entries.len() != 1 {
                problems.push("exactly one Apps & Features entry is proven".to_owned());
            }
            for entry in entries {
                if text(entry, "DisplayVersion") != Some(version.as_str()) {
                    problems.push(
                        "the Apps & Features DisplayVersion is not the PackageVersion".to_owned(),
                    );
                }
                for key in ["DisplayName", "Publisher", "ProductCode"] {
                    if text(entry, key).is_none_or(str::is_empty) {
                        problems.push(format!("the Apps & Features entry has no {key}"));
                    }
                }
                if text(locale, "Publisher") != text(entry, "Publisher") {
                    problems.push(
                        "the Publisher of the locale file is not the Apps & Features publisher"
                            .to_owned(),
                    );
                }
            }
        }
    }
    problems.is_empty().then_some(Checked {
        version,
        installers: found,
    })
}
