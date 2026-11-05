//! The installer probe report: what a real run of the published WinGet installer on clean
//! Windows machines found, as a typed structure the generator refuses to use unless every
//! claim is present and consistent with the bytes that were published.
//!
//! A report is one cell of the matrix (`docs/dev/winget.md`: installer architecture × Windows ×
//! account), written by `scripts/winget/Invoke-WingetProbe.ps1` inside the machine and merged
//! into a [`ProbeSet`] by `Merge-ProbeCells.ps1`. Nothing in it is a guess the generator
//! fills in: an absent field fails to parse, a field that says "not proven" is an error, and
//! the manifest's installer hashes, switches and Apps & Features mapping come from here only
//! after [`ProbeSet::prove`] accepted them.

use std::collections::BTreeSet;
use std::fmt;

use oncl_update::Version;
use serde::Deserialize;

use super::Arch;
use super::release::{StableRelease, is_utc_time};

/// The only format of the report this tool reads.
pub const REPORT_FORMAT: u32 = 1;

/// What the Windows 10 version 1809 build is: the oldest the installer is for.
pub const MIN_BUILD: u32 = 17763;
/// The first build of Windows 11.
const WINDOWS_11_BUILD: u32 = 22000;

/// The exit code of `winget upgrade` when no upgrade applies (0x8A15002B).
pub const NO_APPLICABLE_UPGRADE: i32 = -1_978_335_189;

/// What the probe flags WinGet was started with: nothing that skips a check.
const ALLOWED_FLAGS: [&str; 6] = [
    "--manifest",
    "--architecture",
    "--silent",
    "--accept-package-agreements",
    "--accept-source-agreements",
    "--disable-interactivity",
];

/// Where a report comes from.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// Run by the maintainer's script on clean machines.
    VmRun,
    /// Made by the tests of this repository, for no real release.
    SyntheticFixture,
}

/// The reports of one release.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSet {
    /// [`REPORT_FORMAT`].
    pub report_format: u32,
    /// Where they come from.
    pub origin: Origin,
    /// Who says the run happened. The reports are operator attestations: the generator checks
    /// them against the published bytes and against each other, it cannot see the machines.
    pub attestation: Attestation,
    /// One report per cell of the matrix, run on the candidate manifest.
    pub reports: Vec<InstallerProbeReport>,
    /// Cells that installed, upgraded and uninstalled from the FINAL manifest.
    pub final_cells: Vec<FinalManifestCell>,
}

/// The operator's statement about the run.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// Who ran the matrix.
    pub attested_by: String,
    /// An identifier of the run (a ticket, a date and a name).
    pub run_id: String,
}

/// The machine and the script of one cell.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunInfo {
    /// A hash identifying the machine (not its name).
    pub vm_id: String,
    /// SHA-256 of the `Invoke-WingetProbe.ps1` that produced the cell; equal in all cells.
    pub script_sha256: String,
}

/// A cell that used the final manifest: the correlation of the shipped manifest with an
/// installed entry (upgrade finds it, uninstall removes it).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalManifestCell {
    /// The installer architecture.
    pub installer_arch: Arch,
    /// 10 or 11.
    pub windows: u32,
    /// SHA-256 of the `installer.yaml` of the final manifest that was used.
    pub installer_yaml_sha256: String,
    /// `winget install --manifest` exit code.
    pub install_exit_code: i32,
    /// `winget upgrade --manifest` over an older version: exit code.
    pub upgrade_exit_code: i32,
    /// The older version.
    pub upgrade_from_version: Version,
    /// `DisplayVersion` after that upgrade.
    pub arp_display_version_after_upgrade: Version,
    /// WinGet matched the older installation to the manifest (it upgraded, not installed beside).
    pub upgrade_correlated_installed_entry: bool,
    /// `winget uninstall` exit code.
    pub uninstall_exit_code: i32,
    /// The entry was gone afterwards.
    pub uninstall_removed_entry: bool,
}

/// One cell of the matrix.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerProbeReport {
    /// The cell is a synthetic fixture (a test's), not a run.
    pub synthetic: bool,
    /// The machine and script.
    pub run: RunInfo,
    /// The version the cell tested.
    pub package_version: Version,
    /// When the cell finished, `YYYY-MM-DDTHH:MM:SSZ`.
    pub recorded_at: String,
    /// The published file that was run.
    pub installer: PublishedInstaller,
    /// The machine and the user.
    pub environment: Environment,
    /// What WinGet passed to the installer.
    pub tested_switches: TestedSwitches,
    /// Which manifest WinGet installed from.
    pub tested_manifest: TestedManifest,
    /// What the installation turned out to be.
    pub identity: InstalledIdentity,
    /// Whether it needed anything installed first.
    pub prerequisite_free: PrerequisiteFree,
    /// Install, upgrade, reinstall, uninstall, self-update.
    pub lifecycle: Lifecycle,
    /// What must not happen, and did not.
    pub safety: Safety,
}

/// The file the machine ran, as published.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedInstaller {
    /// The asset name.
    pub asset_name: String,
    /// The URL it was downloaded from.
    pub url: String,
    /// Its architecture.
    pub arch: Arch,
    /// SHA-256 of the downloaded bytes, hex.
    pub sha256: String,
    /// Their number.
    pub size: u64,
    /// The result of `Get-AuthenticodeSignature` on exactly these bytes.
    pub authenticode: Authenticode,
}

/// Authenticode state of the installer.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authenticode {
    /// `SignatureStatus`.
    pub status: AuthenticodeStatus,
    /// The signer certificate's subject.
    pub signer_subject: String,
    /// Its thumbprint (SHA-1, hex).
    pub signer_thumbprint: String,
    /// Whether the signature carries a trusted timestamp.
    pub timestamped: bool,
}

/// `SignatureStatus` of PowerShell.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticodeStatus {
    /// Signed and trusted.
    Valid,
    /// Not signed.
    NotSigned,
    /// The file changed after signing.
    HashMismatch,
    /// Signed by a certificate that is not trusted.
    NotTrusted,
    /// Anything else PowerShell reports.
    UnknownError,
}

/// The kind of Windows account the cell ran WinGet as.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Account {
    /// A standard user.
    Standard,
    /// A member of Administrators with the ordinary (not elevated) token.
    AdminNonElevated,
}

/// Where the cell ran.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    /// A virtual machine.
    Vm,
    /// Windows Sandbox.
    Sandbox,
}

/// The machine.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    /// 10 or 11.
    pub windows: u32,
    /// The build number.
    pub build: u32,
    /// The architecture of the operating system.
    pub os_arch: Arch,
    /// The account.
    pub account: Account,
    /// A virtual machine or Sandbox.
    pub host: Host,
    /// The image was clean: nothing of the program, no developer tools, no redistributables.
    pub clean_image: bool,
    /// `HKCU` and `%LOCALAPPDATA%` that the installation changed belong to the SID of the
    /// account the cell ran as, not to another profile, SYSTEM or an elevated admin.
    pub profile_belongs_to_account_sid: bool,
    /// The version of WinGet.
    pub winget_version: String,
}

/// What was passed on.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestedSwitches {
    /// The flags of `winget install` (names only: no paths).
    pub winget_flags: Vec<String>,
    /// The value of `--architecture` that was passed: the installer's own.
    pub winget_architecture: Arch,
    /// The command line the installer was started with in a `--silent` install, as observed.
    pub silent_argv: Vec<String>,
    /// The same in an install without a mode flag (WinGet's `SilentWithProgress`).
    pub silent_with_progress_argv: Vec<String>,
}

/// The manifest the cell used.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestedManifest {
    /// The manifest schema version.
    pub manifest_version: String,
    /// SHA-256 of the `installer.yaml` of the candidate manifest the cell installed from.
    pub installer_yaml_sha256: String,
}

/// What `Apps & Features` and the installation say.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledIdentity {
    /// The name of the key under `HKCU\...\Uninstall`.
    pub arp_key_name: String,
    /// `DisplayName`.
    pub display_name: String,
    /// `Publisher`.
    pub publisher: String,
    /// `DisplayVersion`.
    pub display_version: Version,
    /// What `openncalayer --version` says.
    pub program_version: Version,
    /// The version in the installation's own manifest (`current\sq.version`).
    pub package_manifest_version: Version,
    /// The architecture of the installed program.
    pub program_arch: Arch,
    /// `InstallLocation` is under the account's `%LOCALAPPDATA%`.
    pub install_location_in_account_profile: bool,
    /// `UninstallString` runs the installation's own `Update.exe`.
    pub uninstall_runs_update_exe: bool,
}

/// Whether anything had to be installed first.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrerequisiteFree {
    /// No Visual C++ Redistributable (or anything else) was on the clean image.
    pub no_redistributable_on_image: bool,
    /// The installation succeeded without installing a prerequisite.
    pub installed_without_prerequisite_step: bool,
}

/// One install or reinstall, checked after the native process ended.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallStep {
    /// The exit code of `winget`.
    pub winget_exit_code: i32,
    /// The exit code of the installer entry as WinGet saw it.
    pub installer_exit_code: i32,
    /// After both processes had ended, the installation was looked at (not just the codes).
    pub postcondition_verified_after_exit: bool,
    /// `DisplayVersion` then.
    pub arp_display_version: Version,
    /// `openncalayer --version` then.
    pub program_version: Version,
}

/// An upgrade of an older version.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeStep {
    /// The version installed before, by its ordinary installer.
    pub from_version: Version,
    /// The result, checked after the processes ended.
    pub result: InstallStep,
    /// `%APPDATA%\OpenNCALayer` (settings, keys) was the same before and after.
    pub user_data_preserved: bool,
}

/// An uninstall.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallStep {
    /// The exit code of `winget`.
    pub winget_exit_code: i32,
    /// The `Apps & Features` entry was gone afterwards.
    pub arp_entry_removed: bool,
    /// The installation directory was gone afterwards.
    pub install_directory_removed: bool,
}

/// What the program's own update (or, when no newer release exists yet, its absence) did to the
/// installation WinGet made.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUpdateStep {
    /// The version WinGet installed.
    pub start_version: Version,
    /// `DisplayVersion` after the program's own update check; the version of the newer release
    /// when one was installed, else the version WinGet installed.
    pub arp_display_version: Version,
    /// `openncalayer --version` after it.
    pub program_version: Version,
    /// A newer release was installed by the program itself in this cell. False means the
    /// self-update is NOT PROVEN: only the absence of a downgrade was seen.
    pub newer_release_tested: bool,
    /// The exit code of `winget upgrade --manifest` afterwards.
    pub winget_exit_code: i32,
    /// An installer process was started by that `winget upgrade`.
    pub winget_installer_ran: bool,
    /// `winget upgrade --manifest` offered no downgrade or reinstall afterwards.
    pub no_downgrade_loop: bool,
}

/// The lifecycle.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    /// Clean install.
    pub install: InstallStep,
    /// Upgrade of an older version.
    pub upgrade: UpgradeStep,
    /// Uninstall, then install again with no mode flag (WinGet's silent-with-progress).
    pub reinstall: InstallStep,
    /// Uninstall.
    pub uninstall: UninstallStep,
    /// The program's self-update.
    pub self_update: SelfUpdateStep,
}

/// The installer refused an elevated token.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevatedRefusal {
    /// The exit code.
    pub exit_code: i32,
    /// No file, directory or registry key of the program exists in the account's, the other
    /// admin's or SYSTEM's profile or in HKLM afterwards.
    pub no_artifacts_in_any_profile: bool,
    /// Started with other credentials through UAC, it did not install into another profile.
    pub other_credentials_install_refused: bool,
}

/// The installer found a busy program and left everything as it was.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningHold {
    /// The exit code while a signature was in progress.
    pub busy_exit_code: i32,
    /// The signature finished correctly.
    pub signature_completed_correctly: bool,
    /// The installation was unchanged.
    pub installation_unchanged: bool,
}

/// What did not happen.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    /// The elevated run.
    pub elevated: ElevatedRefusal,
    /// The signing hold.
    pub signing_hold: SigningHold,
    /// No CA was added to any trust store.
    pub no_ca_trust_added: bool,
    /// The program's own HTTP API stayed disabled.
    pub http_api_stayed_disabled: bool,
}

/// Why a probe report set is not used. Every variant is a claim that is missing or false.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Not JSON of the report format, a field is missing or unknown.
    Malformed(String),
    /// The reports were not made by a real run.
    Synthetic,
    /// The report is not about the published bytes (name, URL, hash, size, version).
    NotThePublishedFile(String),
    /// The installer is not validly signed and timestamped.
    Unsigned(String),
    /// The machine or the account is not a valid clean-install condition.
    Environment(String),
    /// The tested switches are not exactly the proven `--silent`.
    Switches(String),
    /// The cell did not install from the manifest the generator makes.
    ManifestNotTested(String),
    /// The Apps & Features mapping is not proven.
    ArpMapping(String),
    /// The installer is not prerequisite-free.
    Prerequisite(String),
    /// The result after the native process exit is not proven.
    Postcondition(String),
    /// Upgrade, reinstall, uninstall or self-update is not proven.
    Lifecycle(String),
    /// A safety property is not proven.
    Safety(String),
    /// The final manifest was not proven by installation.
    FinalManifest(String),
    /// Cells of the matrix are missing.
    Coverage(String),
    /// Cells contradict each other.
    Inconsistent(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (what, detail) = match self {
            ProbeError::Malformed(d) => ("the probe report is malformed", d.as_str()),
            ProbeError::Synthetic => (
                "the probe report is a synthetic fixture, not a real run",
                "",
            ),
            ProbeError::NotThePublishedFile(d) => {
                ("the probe did not test the published file", d.as_str())
            }
            ProbeError::Unsigned(d) => ("the installer is not validly signed", d.as_str()),
            ProbeError::Environment(d) => ("the test environment is not acceptable", d.as_str()),
            ProbeError::Switches(d) => ("the installer switches are not proven", d.as_str()),
            ProbeError::ManifestNotTested(d) => {
                ("the manifest was not what was tested", d.as_str())
            }
            ProbeError::ArpMapping(d) => ("the Apps & Features mapping is not proven", d.as_str()),
            ProbeError::Prerequisite(d) => ("the installer is not prerequisite-free", d.as_str()),
            ProbeError::Postcondition(d) => (
                "the result after the installer exited is not proven",
                d.as_str(),
            ),
            ProbeError::Lifecycle(d) => ("the install lifecycle is not proven", d.as_str()),
            ProbeError::Safety(d) => ("a safety property is not proven", d.as_str()),
            ProbeError::FinalManifest(d) => ("the final manifest is not proven", d.as_str()),
            ProbeError::Coverage(d) => ("the test matrix is incomplete", d.as_str()),
            ProbeError::Inconsistent(d) => ("the probe reports contradict each other", d.as_str()),
        };
        if detail.is_empty() {
            f.write_str(what)
        } else {
            write!(f, "{what}: {detail}")
        }
    }
}

impl std::error::Error for ProbeError {}

/// The installation identity the reports agree on: what the manifest's Apps & Features
/// entry says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpIdentity {
    /// The key name under `Uninstall`: WinGet's `ProductCode` of an `exe` package.
    pub key_name: String,
    /// `DisplayName`.
    pub display_name: String,
    /// `Publisher`.
    pub publisher: String,
    /// `DisplayVersion`, equal to the package version.
    pub display_version: Version,
}

/// The bytes of one installer as they were actually downloaded, and what the file says about
/// itself. Computed by the generator from one stream, never read from a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The architecture.
    pub arch: Arch,
    /// SHA-256, lowercase hex.
    pub sha256: String,
    /// Bytes.
    pub size: u64,
}

/// What a set of reports proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The Apps & Features identity.
    pub identity: ArpIdentity,
    /// How many cells there were.
    pub cells: usize,
    /// Whether the reports are synthetic fixtures.
    pub synthetic: bool,
    /// Every cell saw the program's own update install a newer release. When false the
    /// self-update is NOT PROVEN and the manifest is not ready.
    pub self_update_proven: bool,
}

/// Reads a set of reports.
///
/// # Errors
///
/// [`ProbeError::Malformed`].
pub fn parse(json: &str) -> Result<ProbeSet, ProbeError> {
    let set: ProbeSet =
        serde_json::from_str(json).map_err(|e| ProbeError::Malformed(e.to_string()))?;
    if set.report_format != REPORT_FORMAT {
        return Err(ProbeError::Malformed(format!(
            "report_format {} is not {REPORT_FORMAT}",
            set.report_format
        )));
    }
    Ok(set)
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|b| b.is_ascii_hexdigit())
}

impl ProbeSet {
    /// Checks every claim of the reports against the published release and the bytes that were
    /// actually downloaded (`published`, one per architecture), and against the candidate
    /// manifest the generator makes (`candidate_installer_sha256`).
    ///
    /// Synthetic reports are refused unless `allow_synthetic`.
    ///
    /// # Errors
    ///
    /// The first [`ProbeError`], in the order: origin, then every cell, then the matrix.
    pub fn prove(
        &self,
        release: &StableRelease,
        published: &[Published],
        candidate_installer_sha256: &str,
        allow_synthetic: bool,
    ) -> Result<Proof, ProbeError> {
        let synthetic = self.origin == Origin::SyntheticFixture;
        if synthetic && !allow_synthetic {
            return Err(ProbeError::Synthetic);
        }
        if self.reports.is_empty() {
            return Err(ProbeError::Coverage("there are no reports".to_owned()));
        }
        for report in &self.reports {
            report.prove(release, published, candidate_installer_sha256)?;
        }
        let identity = self.agree()?;
        self.cover()?;
        self.attested()?;
        Ok(Proof {
            identity,
            cells: self.reports.len(),
            synthetic,
            self_update_proven: self
                .reports
                .iter()
                .all(|r| r.lifecycle.self_update.newer_release_tested),
        })
    }

    /// The statement of the operator and the identity of the script and machines.
    fn attested(&self) -> Result<(), ProbeError> {
        let who = &self.attestation;
        if who.attested_by.trim().is_empty() || who.run_id.trim().is_empty() {
            return Err(ProbeError::Inconsistent(
                "the run has no attested_by and run_id".to_owned(),
            ));
        }
        let script = &self.reports[0].run.script_sha256;
        for report in &self.reports {
            if report.synthetic != (self.origin == Origin::SyntheticFixture) {
                return Err(ProbeError::Synthetic);
            }
            if !is_hex(&report.run.script_sha256, 64)
                || !report.run.script_sha256.eq_ignore_ascii_case(script)
            {
                return Err(ProbeError::Inconsistent(
                    "the cells were not all made by the same script".to_owned(),
                ));
            }
            if report.run.vm_id.trim().is_empty() {
                return Err(ProbeError::Inconsistent("a cell has no vm_id".to_owned()));
            }
        }
        Ok(())
    }

    /// The final manifest, as it will be submitted, was installed, upgraded and uninstalled:
    /// at least one cell per installer architecture, each with the final `installer.yaml`.
    ///
    /// # Errors
    ///
    /// [`ProbeError::FinalManifest`].
    pub fn prove_final(
        &self,
        release: &StableRelease,
        final_installer_sha256: &str,
    ) -> Result<(), ProbeError> {
        let fail = |why: String| Err(ProbeError::FinalManifest(why));
        for arch in [Arch::X64, Arch::X86] {
            let cells: Vec<_> = self
                .final_cells
                .iter()
                .filter(|c| c.installer_arch == arch)
                .collect();
            if cells.is_empty() {
                return fail(format!("no cell installed the final {arch} manifest"));
            }
            for cell in cells {
                if cell.installer_yaml_sha256.to_ascii_lowercase() != final_installer_sha256 {
                    return fail(
                        "a final-manifest cell used another installer.yaml than the one generated"
                            .to_owned(),
                    );
                }
                if cell.install_exit_code != 0
                    || cell.upgrade_exit_code != 0
                    || cell.uninstall_exit_code != 0
                {
                    return fail(format!(
                        "a {arch} final-manifest cell had a non-zero WinGet exit code"
                    ));
                }
                if cell.upgrade_from_version >= release.version
                    || cell.arp_display_version_after_upgrade != release.version
                    || !cell.upgrade_correlated_installed_entry
                    || !cell.uninstall_removed_entry
                {
                    return fail(format!(
                        "a {arch} final-manifest cell did not upgrade the older entry to {} and remove it",
                        release.version
                    ));
                }
            }
        }
        Ok(())
    }

    /// The reports describe one installation identity. (That every cell ran the published bytes
    /// was checked against the download, cell by cell.)
    fn agree(&self) -> Result<ArpIdentity, ProbeError> {
        let first = &self.reports[0].identity;
        for report in &self.reports {
            let id = &report.identity;
            if id.arp_key_name != first.arp_key_name
                || id.display_name != first.display_name
                || id.publisher != first.publisher
            {
                return Err(ProbeError::Inconsistent(
                    "the Apps & Features identity (key, name, publisher) differs between cells"
                        .to_owned(),
                ));
            }
        }
        Ok(ArpIdentity {
            key_name: first.arp_key_name.clone(),
            display_name: first.display_name.clone(),
            publisher: first.publisher.clone(),
            display_version: self.reports[0].package_version.clone(),
        })
    }

    /// Windows 10 and 11, standard and administrator accounts, for each installer; the x86
    /// installer on a 32-bit Windows 10 as well.
    fn cover(&self) -> Result<(), ProbeError> {
        let cells: BTreeSet<(Arch, Account, u32, Arch)> = self
            .reports
            .iter()
            .map(|r| {
                (
                    r.installer.arch,
                    r.environment.account,
                    r.environment.windows,
                    r.environment.os_arch,
                )
            })
            .collect();
        for arch in [Arch::X64, Arch::X86] {
            for account in [Account::Standard, Account::AdminNonElevated] {
                for windows in [10, 11] {
                    if !cells
                        .iter()
                        .any(|(a, acc, w, _)| *a == arch && *acc == account && *w == windows)
                    {
                        return Err(ProbeError::Coverage(format!(
                            "no cell of the {arch} installer on Windows {windows} as {account:?}"
                        )));
                    }
                }
            }
        }
        for account in [Account::Standard, Account::AdminNonElevated] {
            if !cells
                .iter()
                .any(|(a, acc, _, os)| *a == Arch::X86 && *acc == account && *os == Arch::X86)
            {
                return Err(ProbeError::Coverage(format!(
                    "no cell of the x86 installer on a 32-bit Windows as {account:?}"
                )));
            }
        }
        Ok(())
    }
}

impl InstallerProbeReport {
    fn prove(
        &self,
        release: &StableRelease,
        published: &[Published],
        candidate_installer_sha256: &str,
    ) -> Result<(), ProbeError> {
        let version = &release.version;
        let arch = self.installer.arch;
        let asset = release.installer(arch);
        let actual = published.iter().find(|p| p.arch == arch).ok_or_else(|| {
            ProbeError::NotThePublishedFile(format!("no downloaded {arch} installer"))
        })?;

        // The published file.
        let file = &self.installer;
        if self.package_version != *version {
            return Err(ProbeError::NotThePublishedFile(format!(
                "the cell tested {}, the release is {version}",
                self.package_version
            )));
        }
        if file.asset_name != asset.name || file.url != asset.url {
            return Err(ProbeError::NotThePublishedFile(format!(
                "{} at {} is not the release's {}",
                file.asset_name, file.url, asset.name
            )));
        }
        if !is_hex(&file.sha256, 64) || file.sha256.to_ascii_lowercase() != actual.sha256 {
            return Err(ProbeError::NotThePublishedFile(format!(
                "the {arch} installer the cell ran has another SHA-256 than the published file"
            )));
        }
        if file.size != actual.size {
            return Err(ProbeError::NotThePublishedFile(format!(
                "the {arch} installer the cell ran has {} bytes, the published file {}",
                file.size, actual.size
            )));
        }
        if !is_utc_time(&self.recorded_at) || self.recorded_at < release.published_at {
            return Err(ProbeError::NotThePublishedFile(format!(
                "recorded_at {:?} is not a time after the publication ({})",
                self.recorded_at, release.published_at
            )));
        }

        // Signing state.
        let signature = &file.authenticode;
        if signature.status != AuthenticodeStatus::Valid {
            return Err(ProbeError::Unsigned(format!(
                "the {arch} installer's signature is {:?}",
                signature.status
            )));
        }
        if signature.signer_subject.trim().is_empty()
            || !is_hex(&signature.signer_thumbprint, 40)
            || !signature.timestamped
        {
            return Err(ProbeError::Unsigned(format!(
                "the {arch} installer has no named signer, thumbprint or timestamp"
            )));
        }

        // The machine.
        let env = &self.environment;
        let build_ok = match env.windows {
            10 => (MIN_BUILD..WINDOWS_11_BUILD).contains(&env.build),
            11 => env.build >= WINDOWS_11_BUILD,
            _ => false,
        };
        if !build_ok {
            return Err(ProbeError::Environment(format!(
                "Windows {} build {} is not a supported release (10 from {MIN_BUILD}, 11)",
                env.windows, env.build
            )));
        }
        if env.windows == 11 && env.os_arch != Arch::X64 {
            return Err(ProbeError::Environment(
                "Windows 11 is not 32-bit".to_owned(),
            ));
        }
        if arch == Arch::X64 && env.os_arch != Arch::X64 {
            return Err(ProbeError::Environment(
                "the x64 installer cannot be tested on a 32-bit Windows".to_owned(),
            ));
        }
        if !env.clean_image {
            return Err(ProbeError::Environment(
                "the image was not clean".to_owned(),
            ));
        }
        if !env.profile_belongs_to_account_sid {
            return Err(ProbeError::Environment(
                "HKCU/LOCALAPPDATA were not proven to belong to the account's SID".to_owned(),
            ));
        }
        if env.winget_version.trim().is_empty() {
            return Err(ProbeError::Environment(
                "the WinGet version is not recorded".to_owned(),
            ));
        }

        // The switches.
        let switches = &self.tested_switches;
        let silent = ["--silent".to_owned()];
        if switches.silent_argv != silent {
            return Err(ProbeError::Switches(format!(
                "the installer was started with {:?} in a silent install, not exactly --silent",
                switches.silent_argv
            )));
        }
        if switches.silent_with_progress_argv != silent {
            return Err(ProbeError::Switches(format!(
                "the installer was started with {:?} in a silent-with-progress install, not exactly --silent",
                switches.silent_with_progress_argv
            )));
        }
        if switches.winget_architecture != arch {
            return Err(ProbeError::Switches(format!(
                "WinGet was asked for {} but the installer under test is {arch}",
                switches.winget_architecture
            )));
        }
        if !switches.winget_flags.contains(&"--architecture".to_owned()) {
            return Err(ProbeError::Switches(
                "the cell did not pass --architecture, so WinGet chose the installer itself"
                    .to_owned(),
            ));
        }
        if !switches.winget_flags.contains(&"--manifest".to_owned()) {
            return Err(ProbeError::Switches(
                "the cell did not install from a manifest".to_owned(),
            ));
        }
        if let Some(flag) = switches
            .winget_flags
            .iter()
            .find(|flag| !ALLOWED_FLAGS.contains(&flag.as_str()))
        {
            return Err(ProbeError::Switches(format!(
                "WinGet was started with {flag}, which this proof does not allow"
            )));
        }

        // The manifest.
        if self.tested_manifest.manifest_version != super::schema::MANIFEST_VERSION {
            return Err(ProbeError::ManifestNotTested(format!(
                "manifest version {}",
                self.tested_manifest.manifest_version
            )));
        }
        if self
            .tested_manifest
            .installer_yaml_sha256
            .to_ascii_lowercase()
            != candidate_installer_sha256
        {
            return Err(ProbeError::ManifestNotTested(
                "the installer.yaml the cell used is not the candidate this release's inputs produce"
                    .to_owned(),
            ));
        }

        // The identity.
        let id = &self.identity;
        if id.arp_key_name.trim().is_empty()
            || id.display_name.trim().is_empty()
            || id.publisher.trim().is_empty()
        {
            return Err(ProbeError::ArpMapping(
                "the Apps & Features key, name or publisher is empty".to_owned(),
            ));
        }
        for (what, shown) in [
            ("DisplayVersion", &id.display_version),
            ("openncalayer --version", &id.program_version),
            ("the installation manifest", &id.package_manifest_version),
        ] {
            if shown != version {
                return Err(ProbeError::ArpMapping(format!(
                    "{what} is {shown}, the package version is {version}"
                )));
            }
        }
        if id.program_arch != arch {
            return Err(ProbeError::ArpMapping(format!(
                "the installed program is {}, the installer is {arch}",
                id.program_arch
            )));
        }
        if !id.install_location_in_account_profile || !id.uninstall_runs_update_exe {
            return Err(ProbeError::ArpMapping(
                "the entry is not a per-user installation with its own uninstaller".to_owned(),
            ));
        }

        // Prerequisites.
        let pre = &self.prerequisite_free;
        if !pre.no_redistributable_on_image || !pre.installed_without_prerequisite_step {
            return Err(ProbeError::Prerequisite(
                "a clean image without a redistributable did not install without a prerequisite step"
                    .to_owned(),
            ));
        }

        // The lifecycle, each step after the native exit.
        let life = &self.lifecycle;
        life.install.prove("install", version)?;
        life.reinstall.prove("reinstall", version)?;
        life.upgrade.result.prove("upgrade", version)?;
        if life.upgrade.from_version >= *version {
            return Err(ProbeError::Lifecycle(format!(
                "the upgrade started from {}, which is not older than {version}",
                life.upgrade.from_version
            )));
        }
        if !life.upgrade.user_data_preserved {
            return Err(ProbeError::Lifecycle(
                "the user's data did not survive the upgrade".to_owned(),
            ));
        }
        if life.uninstall.winget_exit_code != 0
            || !life.uninstall.arp_entry_removed
            || !life.uninstall.install_directory_removed
        {
            return Err(ProbeError::Lifecycle(
                "the uninstall did not remove the entry and the installation".to_owned(),
            ));
        }
        let update = &life.self_update;
        if update.start_version != *version
            || update.arp_display_version < *version
            || update.arp_display_version != update.program_version
            || !update.no_downgrade_loop
            || update.winget_installer_ran
            || update.winget_exit_code != NO_APPLICABLE_UPGRADE
        {
            return Err(ProbeError::Lifecycle(
                "the self-update did not end at the version the entry shows, or WinGet offers a downgrade"
                    .to_owned(),
            ));
        }

        // Safety.
        let safety = &self.safety;
        if safety.elevated.exit_code != 8
            || !safety.elevated.no_artifacts_in_any_profile
            || !safety.elevated.other_credentials_install_refused
        {
            return Err(ProbeError::Safety(
                "the elevated installer did not refuse with code 8 before writing".to_owned(),
            ));
        }
        if safety.signing_hold.busy_exit_code != 4
            || !safety.signing_hold.signature_completed_correctly
            || !safety.signing_hold.installation_unchanged
        {
            return Err(ProbeError::Safety(
                "an active signature was not held with code 4 and finished unharmed".to_owned(),
            ));
        }
        if !safety.no_ca_trust_added || !safety.http_api_stayed_disabled {
            return Err(ProbeError::Safety(
                "a CA was trusted or the HTTP API was enabled by the installation".to_owned(),
            ));
        }
        Ok(())
    }
}

impl InstallStep {
    fn prove(&self, name: &str, version: &Version) -> Result<(), ProbeError> {
        if !self.postcondition_verified_after_exit {
            return Err(ProbeError::Postcondition(format!(
                "{name}: the installation was not inspected after the native exit"
            )));
        }
        if self.winget_exit_code != 0 || self.installer_exit_code != 0 {
            return Err(ProbeError::Lifecycle(format!(
                "{name}: WinGet ended with {} and the installer with {}",
                self.winget_exit_code, self.installer_exit_code
            )));
        }
        if self.arp_display_version != *version || self.program_version != *version {
            return Err(ProbeError::Postcondition(format!(
                "{name}: after the exit the entry shows {} and the program {}, not {version}",
                self.arp_display_version, self.program_version
            )));
        }
        Ok(())
    }
}
