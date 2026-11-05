<#
.SYNOPSIS
  One cell of the WinGet installation proof matrix: runs INSIDE a clean Windows 10/11 virtual
  machine (or Windows Sandbox) as the account under test, NOT elevated, and writes the cell's
  installer probe report (JSON, schema "report_format": 1 of `cargo xtask winget`).

.DESCRIPTION
  Never run this on a developer or production machine: it installs, upgrades and uninstalls
  OpenNCALayer, starts an elevated installer on purpose and enables nothing outside the VM.
  It refuses to start unless the machine is a virtual machine or Windows Sandbox, the token is
  not elevated, and the account kind matches -Account.

  What it does, in order (each step's result goes into the report; a failed expectation stops
  the script with an error, nothing is written as "proven" that was not observed):
    1. environment: Windows build/architecture, account kind, profile SID, clean image;
    2. the PUBLISHED installer: downloaded once from its release URL, SHA-256, size,
       Get-AuthenticodeSignature, and compared with the candidate manifest's InstallerSha256;
    3. elevated run (UAC prompt: the operator approves; a standard account is asked for admin
       credentials = "other credentials"): must exit 8 and write nothing;
    4. `winget install --manifest <dir> --silent`: the argv WinGet gives the installer is
       observed (polling the child's command line), then, after BOTH processes ended, the
       installation itself is inspected: Apps & Features entry, `openncalayer --version`, the
       installation manifest, program architecture, location and uninstaller;
    5. the same with no mode flag (WinGet's silent-with-progress);
    6. clean install, upgrade from -OldSetup (user data sentinel must survive), signing hold
       (operator starts a long signature, the installer must exit 4 and leave everything),
       uninstall, reinstall;
    7. self-update: waits for -SelfUpdateTargetVersion if one is available; otherwise records that
       the version stayed and that `winget upgrade --manifest` offers no downgrade;
    8. no CA was added to the machine or user root stores; no listener beyond loopback.

  Steps 6 (signature) and 7 (self-update trigger) need a person at the machine: they are marked
  in the output and what the operator answers is what the report says (operator-observed).

.EXAMPLE
  .\Invoke-WingetProbe.ps1 -ManifestDir .\candidate -InstallerArch x64 -Tag v0.3.0 `
      -OldSetup .\old\openncalayer-0.2.0-win-x64-setup.exe -OldVersion 0.2.0 `
      -Account standard -OtherAdminProfile (Join-Path $env:SystemDrive 'Users\proofadmin') `
      -CleanImageAttested -OutFile .\cell-x64-win10-standard.json
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ManifestDir,
  [Parameter(Mandatory)][ValidateSet('x64', 'x86')][string]$InstallerArch,
  [Parameter(Mandatory)][string]$Tag,
  [Parameter(Mandatory)][string]$OldSetup,
  [Parameter(Mandatory)][string]$OldVersion,
  [Parameter(Mandatory)][ValidateSet('standard', 'admin_non_elevated')][string]$Account,
  [Parameter(Mandatory)][string]$OutFile,
  [string]$Repository = 'arynyklas/open-ncalayer',
  [string]$OtherAdminProfile = '',
  [string]$SelfUpdateTargetVersion = '',
  [int]$SelfUpdateWaitMinutes = 15,
  [switch]$CleanImageAttested
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

$PackageId = 'arynyklas.OpenNCALayer'
$ArpRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$Version = $Tag.TrimStart('v')
$AssetName = "openncalayer-$Version-win-$InstallerArch-winget-setup.exe"
$AssetUrl = "https://github.com/$Repository/releases/download/$Tag/$AssetName"
$DataDir = Join-Path $env:APPDATA 'OpenNCALayer'
$InstallDir = Join-Path $env:LOCALAPPDATA 'OpenNCALayer'
$Work = Join-Path $env:TEMP ("oncl-winget-probe-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work | Out-Null

function Fail([string]$Message) { throw "PROBE FAILED: $Message" }
function Note([string]$Message) { Write-Host "[probe] $Message" }
function Sha256Of([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

# ---------------------------------------------------------------- environment

function Get-Elevated {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-IsAdminMember {
  # The filtered token of an administrator still lists Administrators (deny-only).
  [bool]((whoami /groups) -match 'S-1-5-32-544')
}

function Get-Environment {
  if (Get-Elevated) { Fail 'the token is elevated: run the script as an ordinary (not elevated) user' }
  $member = Get-IsAdminMember
  if ($Account -eq 'admin_non_elevated' -and -not $member) { Fail '-Account admin_non_elevated but the user is not an administrator' }
  if ($Account -eq 'standard' -and $member) { Fail '-Account standard but the user is a member of Administrators' }
  if ($Account -eq 'standard' -and [string]::IsNullOrEmpty($OtherAdminProfile)) {
    Fail 'a standard account needs -OtherAdminProfile (the profile directory of the admin whose credentials the UAC prompt will be given)'
  }

  $os = Get-CimInstance Win32_OperatingSystem
  $build = [int]$os.BuildNumber
  $osArch = if ($os.OSArchitecture -match '64') { 'x64' } else { 'x86' }
  $windows = if ($build -ge 22000) { 11 } else { 10 }

  $host_kind = $null
  if ($env:USERNAME -eq 'WDAGUtilityAccount') { $host_kind = 'sandbox' }
  else {
    $model = (Get-CimInstance Win32_ComputerSystem).Model + ' ' + (Get-CimInstance Win32_BIOS).Manufacturer
    if ($model -match 'Virtual|VMware|KVM|QEMU|Hyper-V|Xen|Parallels') { $host_kind = 'vm' }
  }
  if (-not $host_kind) { Fail 'this machine is not a virtual machine or Windows Sandbox: refusing to install anything here' }

  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $profileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
  $profilePath = [Environment]::ExpandEnvironmentVariables($profileList.ProfileImagePath)
  $belongs = $env:LOCALAPPDATA.StartsWith($profilePath, [StringComparison]::OrdinalIgnoreCase) -and
    $env:APPDATA.StartsWith($profilePath, [StringComparison]::OrdinalIgnoreCase)

  $vc = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName } |
    Where-Object { $_ -match 'Visual C\+\+.*Redistributable' })
  $noRedist = ($vc.Count -eq 0)
  $existing = (Test-Path $InstallDir) -or ((Get-ChildItem $ArpRoot | ForEach-Object { (Get-ItemProperty $_.PSPath).DisplayName }) -contains 'OpenNCALayer')
  if ($existing) { Fail 'OpenNCALayer is already installed on this image: revert to a clean snapshot' }

  @{
    windows = $windows; build = $build; os_arch = $osArch; account = $Account; host = $host_kind
    clean_image = [bool]($CleanImageAttested -and $noRedist -and -not $existing)
    profile_belongs_to_account_sid = [bool]$belongs
    winget_version = ((winget --version) | Out-String).Trim()
    _no_redistributable = $noRedist
  }
}

# ---------------------------------------------------------------- the published installer

function Get-Published {
  $path = Join-Path $Work $AssetName
  Note "downloading $AssetUrl"
  Invoke-WebRequest -Uri $AssetUrl -OutFile $path -UseBasicParsing
  $sig = Get-AuthenticodeSignature -LiteralPath $path
  $status = switch ($sig.Status.ToString()) {
    'Valid' { 'valid' } 'NotSigned' { 'not_signed' } 'HashMismatch' { 'hash_mismatch' }
    'NotTrusted' { 'not_trusted' } default { 'unknown_error' }
  }
  $sha = Sha256Of $path
  $installerYaml = Get-Content -Raw -LiteralPath (Join-Path $ManifestDir "$PackageId.installer.yaml")
  $declared = [regex]::Match($installerYaml, "(?ms)Architecture: $InstallerArch\s+InstallerUrl: \S+\s+InstallerSha256: ""?([0-9A-Fa-f]{64})""?")
  if (-not $declared.Success) { Fail "the candidate manifest has no $InstallerArch installer" }
  if ($declared.Groups[1].Value.ToLowerInvariant() -ne $sha) { Fail "the candidate manifest's $InstallerArch hash is not the hash of the published file" }
  @{
    path = $path
    report = @{
      asset_name = $AssetName; url = $AssetUrl; arch = $InstallerArch; sha256 = $sha
      size = (Get-Item -LiteralPath $path).Length
      authenticode = @{
        status = $status
        signer_subject = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' })
        signer_thumbprint = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint.ToLowerInvariant() } else { '' })
        timestamped = [bool]$sig.TimeStamperCertificate
      }
    }
  }
}

# ---------------------------------------------------------------- inspecting an installation

function Get-ArpKeys { @(Get-ChildItem $ArpRoot | ForEach-Object { $_.PSChildName }) }

function Get-PeMachine([string]$Path) {
  $bytes = [IO.File]::ReadAllBytes($Path)
  $peAt = [BitConverter]::ToInt32($bytes, 0x3c)
  $machine = [BitConverter]::ToUInt16($bytes, $peAt + 4)
  switch ($machine) { 0x8664 { 'x64' } 0x014c { 'x86' } default { "0x{0:x}" -f $machine } }
}

# What an installation is, looked at AFTER the installer processes ended.
function Get-Installation([string]$KeyName) {
  $arp = Get-ItemProperty (Join-Path $ArpRoot $KeyName) -ErrorAction SilentlyContinue
  if (-not $arp) { return $null }
  $location = $arp.InstallLocation
  $program = Join-Path $location 'current\openncalayer.exe'
  $said = $null
  if (Test-Path $program) {
    $p = Start-Process -FilePath $program -ArgumentList '--version' -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $Work 'version.txt')
    if ($p.WaitForExit(30000)) { $said = ((Get-Content (Join-Path $Work 'version.txt') -Raw) -replace '^\s*openncalayer\s+', '').Trim() } else { $p.Kill() }
  }
  $manifest = $null; $manifestArch = $null
  $sq = Join-Path $location 'current\sq.version'
  if (Test-Path $sq) {
    [xml]$nuspec = Get-Content -Raw $sq
    $manifest = $nuspec.package.metadata.version
  }
  $owner = $null
  if (Test-Path $location) { $owner = (Get-Acl $location).Owner }
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  @{
    key = $KeyName; display_name = $arp.DisplayName; publisher = $arp.Publisher
    display_version = $arp.DisplayVersion; install_location = $location
    uninstall = $arp.UninstallString; program_version = $said; manifest_version = $manifest
    program_arch = $(if (Test-Path $program) { Get-PeMachine $program } else { $null })
    location_in_profile = [bool]($location -and $location.StartsWith($env:LOCALAPPDATA, [StringComparison]::OrdinalIgnoreCase))
    owner_is_account = [bool]($owner -and ($owner -eq $me -or $owner -match 'Administrators') -and $location.StartsWith($env:LOCALAPPDATA, [StringComparison]::OrdinalIgnoreCase))
    uninstall_runs_update_exe = [bool]($arp.UninstallString -and $arp.UninstallString.ToLowerInvariant().Contains((Join-Path $location 'Update.exe').ToLowerInvariant()))
  }
}

function Find-NewKey([string[]]$Before) {
  $new = @(Get-ArpKeys | Where-Object { $Before -notcontains $_ })
  $named = @($new | Where-Object { (Get-ItemProperty (Join-Path $ArpRoot $_)).DisplayName -match 'OpenNCALayer' })
  if ($named.Count -ne 1) { Fail "expected exactly one new Apps & Features entry of OpenNCALayer, found $($named.Count)" }
  $named[0]
}

# ---------------------------------------------------------------- running winget with the installer's argv observed

# Starts `winget` with $WingetArgs, polls its child processes for their command lines (the installer
# is the child that carries the argv), waits for BOTH to end, and returns codes and the argv.
function Invoke-WingetObserved([string[]]$WingetArgs) {
  $log = Join-Path $Work ('winget-' + [guid]::NewGuid().ToString('N') + '.txt')
  $w = Start-Process -FilePath 'winget' -ArgumentList $WingetArgs -PassThru -NoNewWindow -RedirectStandardOutput $log
  $null = $w.Handle
  $seen = @{}
  while (-not $w.HasExited) {
    foreach ($c in @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($w.Id)" -ErrorAction SilentlyContinue)) {
      if ($c.Name -ne 'conhost.exe' -and -not $seen.ContainsKey($c.ProcessId)) {
        $handle = [Diagnostics.Process]::GetProcessById($c.ProcessId); $null = $handle.Handle
        $seen[$c.ProcessId] = @{ command_line = $c.CommandLine; proc = $handle }
      }
    }
    Start-Sleep -Milliseconds 40
  }
  $w.WaitForExit()
  $installer = @($seen.Values | Where-Object { $_.command_line -and $_.command_line -match 'winget-setup|\.exe' })
  if ($installer.Count -lt 1) { Fail 'the installer process of WinGet was not observed: the argv cannot be claimed' }
  $first = $installer[0]
  $first.proc.WaitForExit()
  $argv = @()
  $rest = $first.command_line.Trim()
  if ($rest.StartsWith('"')) { $rest = $rest.Substring($rest.IndexOf('"', 1) + 1) } else { $rest = ($rest -split '\s+', 2)[1] }
  if ($rest) { $argv = @($rest.Trim() -split '\s+' | Where-Object { $_ }) }
  @{ winget_exit_code = [int]$w.ExitCode; installer_exit_code = [int]$first.proc.ExitCode; argv = $argv; output = (Get-Content -Raw $log) }
}

function Install-Step([string[]]$ExtraArgs, [string[]]$Before) {
  $wingetArgs = @('install', '--manifest', $ManifestDir) + $ExtraArgs + @('--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  $run = Invoke-WingetObserved $wingetArgs
  $key = $null; $inst = $null
  if ($run.winget_exit_code -eq 0) { $key = Find-NewKey $Before; $inst = Get-Installation $key }
  @{ run = $run; key = $key; installation = $inst }
}

function Uninstall-Step([string]$KeyName, [string]$DisplayName) {
  $run = Invoke-WingetObserved @('uninstall', '--name', $DisplayName, '--exact', '--silent', '--disable-interactivity')
  $inst = Get-Installation $KeyName
  @{ winget_exit_code = $run.winget_exit_code; arp_entry_removed = ($null -eq $inst); install_directory_removed = -not (Test-Path $InstallDir) }
}

function To-InstallStep($Step, [string]$Expected) {
  $i = $Step.installation
  if (-not $i) { Fail "no installation was found after winget ended (winget exit code $($Step.run.winget_exit_code))" }
  @{
    winget_exit_code = $Step.run.winget_exit_code; installer_exit_code = $Step.run.installer_exit_code
    postcondition_verified_after_exit = $true
    arp_display_version = $i.display_version; program_version = [string]$i.program_version
  }
}

function Get-Roots {
  @(Get-ChildItem Cert:\CurrentUser\Root, Cert:\LocalMachine\Root | ForEach-Object { $_.Thumbprint })
}

function Get-NonLoopbackListeners {
  $pids = @(Get-Process -Name openncalayer -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
  @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
      $pids -contains $_.OwningProcess -and $_.LocalAddress -notin @('127.0.0.1', '::1')
    })
}

function Stop-Program { Get-Process -Name openncalayer, nmhost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }

# ---------------------------------------------------------------- the run

try {
  $environment = Get-Environment
  $noRedist = $environment['_no_redistributable']; $environment.Remove('_no_redistributable')
  $published = Get-Published
  $rootsBefore = Get-Roots
  Note "cell: Windows $($environment.windows) build $($environment.build) $($environment.os_arch), $Account, installer $InstallerArch"

  # 3. the elevated run refuses, before writing anything.
  Note 'ELEVATED RUN: approve the UAC prompt (a standard account: enter the administrator credentials)'
  $arpBefore = Get-ArpKeys
  $elevated = Start-Process -FilePath $published.path -ArgumentList '--silent' -Verb RunAs -PassThru -Wait
  $otherProfiles = @($env:LOCALAPPDATA)
  if ($OtherAdminProfile) { $otherProfiles += (Join-Path $OtherAdminProfile 'AppData\Local') }
  $otherProfiles += (Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local')
  $written = @($otherProfiles | Where-Object { Test-Path (Join-Path $_ 'OpenNCALayer') })
  $arpAfter = Get-ArpKeys
  $machineArp = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenNCALayer'
  $nothingWritten = ($written.Count -eq 0) -and (@($arpAfter | Where-Object { $arpBefore -notcontains $_ }).Count -eq 0) -and -not $machineArp
  $elevatedReport = @{
    exit_code = [int]$elevated.ExitCode; nothing_written = [bool]$nothingWritten
    other_credentials_install_refused = [bool]($elevated.ExitCode -eq 8 -and $nothingWritten)
  }
  if ($elevatedReport.exit_code -ne 8 -or -not $nothingWritten) { Fail "the elevated installer exited $($elevated.ExitCode) (expected 8) / wrote: $($written -join ', ')" }

  # 4. silent install through WinGet from the candidate manifest.
  $before = Get-ArpKeys
  $install = Install-Step @('--silent') $before
  $silentArgv = $install.run.argv
  $key = $install.key
  $inst = $install.installation
  $installStep = To-InstallStep $install $Version

  # 5. WinGet's silent-with-progress: no mode flag. Uninstall first, then install again.
  $u = Uninstall-Step $key $inst.display_name
  if (-not ($u.arp_entry_removed -and $u.winget_exit_code -eq 0)) { Fail 'uninstall before the second install failed' }
  Stop-Program
  $before = Get-ArpKeys
  $second = Install-Step @() $before
  $progressArgv = $second.run.argv
  $reinstallStep = To-InstallStep $second $Version

  # 6a. upgrade from an older version installed by its ordinary installer.
  $u = Uninstall-Step $key $inst.display_name
  if (-not ($u.arp_entry_removed -and $u.winget_exit_code -eq 0)) { Fail 'uninstall before the upgrade test failed' }
  Stop-Program
  $beforeOld = Get-ArpKeys
  $oldRun = Start-Process -FilePath $OldSetup -ArgumentList '--silent' -PassThru -Wait
  if ($oldRun.ExitCode -ne 0) { Fail "the old installer exited $($oldRun.ExitCode)" }
  $oldKey = Find-NewKey $beforeOld
  $old = Get-Installation $oldKey
  if ($old.display_version -ne $OldVersion) { Fail "the old installation is $($old.display_version), not $OldVersion" }
  New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
  $sentinel = Join-Path $DataDir 'probe-sentinel.txt'
  [IO.File]::WriteAllText($sentinel, [guid]::NewGuid().ToString())
  $sentinelSha = Sha256Of $sentinel

  # 6b. signing hold: the operator starts a long signature, the installer must exit 4.
  Note 'SIGNING HOLD (operator): start a LONG signature in the running OpenNCALayer (a very large file in the Tools window, or a batch), then press Enter here'
  $null = Read-Host
  $holdRun = Invoke-WingetObserved @('upgrade', '--manifest', $ManifestDir, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  $unchanged = ((Get-Installation $oldKey).display_version -eq $OldVersion)
  Note 'Did the signature finish correctly and unharmed? (operator answers)'
  $answer = Read-Host 'y/n'
  $signingHold = @{
    busy_exit_code = [int]$holdRun.installer_exit_code
    signature_completed_correctly = [bool]($answer -eq 'y')
    installation_unchanged = [bool]$unchanged
  }
  if ($signingHold.busy_exit_code -ne 4) { Fail "the installer exited $($holdRun.installer_exit_code) during an active signature, expected 4" }

  # 6c. the upgrade with the program idle.
  Note 'Make sure no signature or window of OpenNCALayer is active, then press Enter'
  $null = Read-Host
  $up = Invoke-WingetObserved @('upgrade', '--manifest', $ManifestDir, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  $after = Get-Installation $oldKey
  if (-not $after) { $after = Get-Installation $key }
  if (-not $after) { Fail 'no installation after the upgrade' }
  $keepsData = (Test-Path $sentinel) -and ((Sha256Of $sentinel) -eq $sentinelSha)
  $upgradeStep = @{
    from_version = $OldVersion
    result = @{
      winget_exit_code = [int]$up.winget_exit_code; installer_exit_code = [int]$up.installer_exit_code
      postcondition_verified_after_exit = $true
      arp_display_version = $after.display_version; program_version = [string]$after.program_version
    }
    user_data_preserved = [bool]$keepsData
  }

  # 7. self-update and the WinGet view of it.
  $final = $after
  if ($SelfUpdateTargetVersion) {
    Note "waiting up to $SelfUpdateWaitMinutes min for the program's own update to $SelfUpdateTargetVersion (trigger it from the tray menu: Check for updates)"
    $deadline = (Get-Date).AddMinutes($SelfUpdateWaitMinutes)
    do { Start-Sleep -Seconds 10; $final = Get-Installation $after.key } until ($final.display_version -eq $SelfUpdateTargetVersion -or (Get-Date) -gt $deadline)
  }
  $null = Invoke-WingetObserved @('upgrade', '--manifest', $ManifestDir, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  $afterSelfInst = Get-Installation $after.key
  $selfUpdate = @{
    start_version = $Version
    arp_display_version = $afterSelfInst.display_version
    program_version = [string]$afterSelfInst.program_version
    # WinGet must not have changed the version back, installed over it, or looped.
    no_downgrade_loop = [bool]($afterSelfInst.display_version -eq $final.display_version)
  }

  # 8. uninstall; nothing was trusted, nothing listens beyond loopback.
  $listeners = Get-NonLoopbackListeners
  $rootsAfter = Get-Roots
  $newRoots = @($rootsAfter | Where-Object { $rootsBefore -notcontains $_ })
  $serverPresent = Test-Path (Join-Path $after.install_location 'oncl-server.exe')
  $uninstall = Uninstall-Step $after.key $after.display_name
  Stop-Program

  $report = @{
    package_version = $Version
    recorded_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    installer = $published.report
    environment = $environment
    tested_switches = @{
      winget_flags = @('--manifest', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
      silent_argv = @($silentArgv)
      silent_with_progress_argv = @($progressArgv)
    }
    tested_manifest = @{
      manifest_version = '1.12.0'
      installer_yaml_sha256 = (Sha256Of (Join-Path $ManifestDir "$PackageId.installer.yaml"))
    }
    identity = @{
      arp_key_name = $inst.key; display_name = $inst.display_name; publisher = $inst.publisher
      display_version = $inst.display_version; program_version = [string]$inst.program_version
      package_manifest_version = [string]$inst.manifest_version; program_arch = $inst.program_arch
      install_location_in_account_profile = [bool]($inst.location_in_profile -and $inst.owner_is_account)
      uninstall_runs_update_exe = [bool]$inst.uninstall_runs_update_exe
    }
    prerequisite_free = @{
      no_redistributable_on_image = [bool]$noRedist
      installed_without_prerequisite_step = [bool]($installStep.winget_exit_code -eq 0 -and $installStep.postcondition_verified_after_exit)
    }
    lifecycle = @{
      install = $installStep; upgrade = $upgradeStep; reinstall = $reinstallStep
      uninstall = @{ winget_exit_code = $uninstall.winget_exit_code; arp_entry_removed = $uninstall.arp_entry_removed; install_directory_removed = $uninstall.install_directory_removed }
      self_update = $selfUpdate
    }
    safety = @{
      elevated = $elevatedReport
      signing_hold = $signingHold
      no_ca_trust_added = [bool]($newRoots.Count -eq 0)
      http_api_stayed_disabled = [bool]($listeners.Count -eq 0 -and -not $serverPresent)
    }
  }
  $json = $report | ConvertTo-Json -Depth 12
  [IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
  Note "cell report written to $OutFile (validate and merge: Merge-ProbeCells.ps1, then cargo xtask winget generate)"
}
finally {
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
