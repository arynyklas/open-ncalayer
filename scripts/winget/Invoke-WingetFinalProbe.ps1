<#
.SYNOPSIS
  One final-manifest cell: runs INSIDE a clean Windows 10/11 virtual machine (or Sandbox) as an
  ordinary non-elevated user and proves that the FINAL manifest (the one that will be
  submitted, with its Apps & Features mapping) installs, upgrades an older installation and
  uninstalls through WinGet's own correlation. Writes a "final_cells" entry of the probe set.

.DESCRIPTION
  Run it with the directory made by `cargo xtask winget generate` for the probe reports of the
  main matrix. The generator later refuses a set whose final cells did not use exactly the
  installer.yaml it makes. Needs at least one cell per installer architecture.
  Refuses to run outside a VM/Sandbox or with an elevated token.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ManifestDir,
  [Parameter(Mandatory)][ValidateSet('x64', 'x86')][string]$InstallerArch,
  [Parameter(Mandatory)][string]$Tag,
  [Parameter(Mandatory)][string]$OldSetup,
  [Parameter(Mandatory)][string]$OldVersion,
  [Parameter(Mandatory)][string]$OutFile
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'
if ($Tag -notmatch '^v\d+\.\d+\.\d+$') { throw "-Tag must be a stable tag v<major>.<minor>.<patch>, not '$Tag'" }
$Version = $Tag.Substring(1)
$ArpRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'the token is elevated: run as an ordinary user'
}
$model = (Get-CimInstance Win32_ComputerSystem).Model + ' ' + (Get-CimInstance Win32_BIOS).Manufacturer
if (-not ($env:USERNAME -eq 'WDAGUtilityAccount' -or $model -match 'Virtual|VMware|KVM|QEMU|Hyper-V|Xen|Parallels')) {
  throw 'this machine is not a virtual machine or Windows Sandbox: refusing to install anything here'
}
if (Get-ChildItem $ArpRoot | Where-Object { (Get-ItemProperty $_.PSPath).DisplayName -match 'OpenNCALayer' }) {
  throw 'OpenNCALayer is already installed: revert to a clean snapshot'
}

function Get-OpenNcaKeys { @(Get-ChildItem $ArpRoot | Where-Object { (Get-ItemProperty $_.PSPath).DisplayName -match 'OpenNCALayer' } | ForEach-Object { $_.PSChildName }) }
function Run-Winget([string[]]$WingetArgs) {
  $quoted = @($WingetArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } })
  $p = Start-Process -FilePath 'winget' -ArgumentList $quoted -PassThru -Wait -NoNewWindow
  [int]$p.ExitCode
}
$common = @('--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')

# Install from the final manifest, then remove, so the upgrade starts from the older version only.
$install = Run-Winget (@('install', '--manifest', $ManifestDir, '--architecture', $InstallerArch, '--silent') + $common)
$keys = Get-OpenNcaKeys
$name = $null
if ($keys.Count -eq 1) { $name = (Get-ItemProperty (Join-Path $ArpRoot $keys[0])).DisplayName }
if ($install -ne 0 -or -not $name) { throw "install from the final manifest failed (exit $install, entries: $($keys.Count))" }
$null = Run-Winget @('uninstall', '--name', $name, '--exact', '--silent', '--disable-interactivity')
Get-Process -Name openncalayer, nmhost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Upgrade: the older version by its ordinary installer, then WinGet with the final manifest.
$old = Start-Process -FilePath $OldSetup -ArgumentList '--silent' -PassThru -Wait
if ($old.ExitCode -ne 0) { throw "the old installer exited $($old.ExitCode)" }
$oldKeys = Get-OpenNcaKeys
if ($oldKeys.Count -ne 1 -or (Get-ItemProperty (Join-Path $ArpRoot $oldKeys[0])).DisplayVersion -ne $OldVersion) { throw "the old installation is not exactly $OldVersion" }
$upgrade = Run-Winget (@('upgrade', '--manifest', $ManifestDir, '--architecture', $InstallerArch, '--silent') + $common)
$newKeys = Get-OpenNcaKeys
$shown = if ($newKeys.Count -ge 1) { (Get-ItemProperty (Join-Path $ArpRoot $newKeys[0])).DisplayVersion } else { '' }
# WinGet matched the older entry: still exactly one entry, now at the new version.
$correlated = ($newKeys.Count -eq 1 -and $shown -eq $Version)

$name = (Get-ItemProperty (Join-Path $ArpRoot $newKeys[0])).DisplayName
$uninstall = Run-Winget @('uninstall', '--name', $name, '--exact', '--silent', '--disable-interactivity')
$removed = ((Get-OpenNcaKeys).Count -eq 0)
Get-Process -Name openncalayer, nmhost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# One digest over all three files: the lines `<name> <sha256>` in ordinal name order.
$names = @(Get-ChildItem -LiteralPath $ManifestDir -File | ForEach-Object { $_.Name })
[Array]::Sort($names, [StringComparer]::Ordinal)
$digestText = ''
foreach ($n in $names) { $digestText += "$n $((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ManifestDir $n)).Hash.ToLowerInvariant())`n" }
$manifestDigest = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($digestText))) -replace '-', '').ToLowerInvariant()

$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
$cell = [ordered]@{
  installer_arch = $InstallerArch
  windows = $(if ($build -ge 22000) { 11 } else { 10 })
  manifest_files_sha256 = $manifestDigest
  install_exit_code = $install
  upgrade_exit_code = $upgrade
  upgrade_from_version = $OldVersion
  arp_display_version_after_upgrade = $shown
  upgrade_correlated_installed_entry = [bool]$correlated
  uninstall_exit_code = $uninstall
  uninstall_removed_entry = [bool]$removed
}
[IO.File]::WriteAllText($OutFile, ($cell | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
Write-Host "final-manifest cell written to $OutFile"
