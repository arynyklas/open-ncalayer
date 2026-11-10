<#
.SYNOPSIS
  The signing-hold check of the WinGet installer entry, scripted: while a signature is in
  flight in a running OpenNCALayer, the entry must exit 4 ("busy") and leave the installation
  untouched, the signature must finish intact, and after the quiet time the same entry must go
  through. No operator is needed.

.DESCRIPTION
  What it uses (nothing here is the release candidate's own program, which cannot be driven
  without a window):
    - the entry under test (-EntryExe): the released `openncalayer-<version>-win-<arch>-winget-setup.exe`;
    - a TEST build of the daemon (-DaemonExe): `cargo build --release -p openncalayer --features
      e2e-prompter`. With ONCL_E2E_PROMPTER=<steps.json> it answers the signing dialogs from a
      script and opens no window. It runs from a scratch directory, never from the
      installation, and is never installed;
    - the repository's synthetic CA and keystore (`fixtures/synthetic/root-rsa.cer`,
      `user-rsa-sign.p12`; public test keys, valid until 2099) -- no real key.

  The daemon serves the same per-user management endpoint as the installed program, so the
  entry asks it exactly as it asks the real one. A signature is a page's request over the
  daemon's bridge endpoint (what the browser extension's relay does): this script plays the
  relay on the named pipe. The first dialog of the signing is held by a `wait_file` step of the
  script until this script creates the gate file; that is how a signature stays in flight for
  as long as -HoldSeconds says (the same way `maintenance_e2e.rs` does it in-process).

  Steps (each result goes into result.json; a failed expectation makes the verdict FAIL):
    1. environment (not elevated; a virtual machine unless -SafeDryRun; the daemon is a test build);
    2. baseline: -BaselineSetup (a normal installer, e.g. the previous version's) or, without it,
       a clean install by the entry itself; skipped by -SafeDryRun;
    3. the daemon is started; an idle hold is granted and released;
    4. the signature is sent; the daemon answers "busy" on the management endpoint;
    5. the entry runs twice during the signature (--wait 2 and --wait -EntryWaitSeconds): exit 4
       both times; the installation (Apps & Features version, SHA-256 of every file) and the
       Windows trust stores are unchanged; the signature is not cut;
    6. after -HoldSeconds the gate opens: the signature finishes; it is checked by Windows
       (SignedCms.CheckSignature, not by this program's code), against the synthetic root, and a
       tampered copy is rejected;
    7. the quiet time: the entry runs with --wait 3 right after the signature: exit 4; after
       -QuietSeconds (the daemon's `update::QUIET`) + a margin the hold is granted again;
    8. the entry runs once more: exit 0 and the entry's version installed (-SafeDryRun: exit 1,
       "cannot prepare Setup", because the temporary directory of the entry is made unusable on
       purpose, so a granted hold can never install on the machine the script runs on);
    9. the hold is released with the entry's end; the daemon is stopped; secrets are removed.

  -SafeDryRun is for a developer machine: it installs nothing, never touches the default data
  directory (-DataDir is required) and cannot let the entry install. Its verdict is
  PASS-DRY-RUN at best, never PASS.

.EXAMPLE
  .\Invoke-WingetHold.ps1 -EntryExe .\openncalayer-0.1.0-alpha.7-win-x64-winget-setup.exe `
      -DaemonExe .\openncalayer-e2e-x64.exe -Keystore .\user-rsa-sign.p12 `
      -KeystorePassFile .\keystore-pass.txt -RootCert .\root-rsa.cer -StepsTemplate .\steps.json `
      -ExpectedVersion 0.1.0-alpha.7 -BaselineSetup .\old\openncalayer-0.1.0-alpha.6-win-x64-setup.exe `
      -BaselineVersion 0.1.0-alpha.6 -OutDir .\hold-x64-w10-std -RunAsInvoker
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$EntryExe,
  [Parameter(Mandatory)][string]$DaemonExe,
  [Parameter(Mandatory)][string]$Keystore,
  [Parameter(Mandatory)][string]$KeystorePassFile,
  [Parameter(Mandatory)][string]$RootCert,
  [Parameter(Mandatory)][string]$StepsTemplate,
  [Parameter(Mandatory)][string]$ExpectedVersion,
  [Parameter(Mandatory)][string]$OutDir,
  [string]$BaselineSetup = '',
  [string]$BaselineVersion = '',
  [string]$DataDir = '',
  [int]$HoldSeconds = 75,
  [int]$EntryWaitSeconds = 30,
  [int]$QuietSeconds = 30,
  [switch]$SafeDryRun,
  [switch]$RunAsInvoker,
  [switch]$UninstallAtEnd
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ArpKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenNCALayer'
$InstallDir = Join-Path $env:LOCALAPPDATA 'OpenNCALayer'
$Clock = [Diagnostics.Stopwatch]::StartNew()

# ------------------------------------------------------------------ small helpers

function Fail([string]$Message) { throw "HOLD CHECK FAILED: $Message" }
function Sha256Of([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Utf8NoBom { New-Object Text.UTF8Encoding $false }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).ProviderPath
$Work = Join-Path $OutDir 'work'
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$LogFile = Join-Path $OutDir 'log.txt'
$ResultFile = Join-Path $OutDir 'result.json'

function Note([string]$Message) {
  $line = '{0} [{1,6:N1}s] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Clock.Elapsed.TotalSeconds, $Message
  Write-Host $line
  [IO.File]::AppendAllText($LogFile, $line + "`r`n", (Utf8NoBom))
}

$Result = [ordered]@{
  scenario = 'signing-hold'
  format = 1
  mode = $(if ($SafeDryRun) { 'safe-dry-run' } else { 'vm' })
  started_utc = (Get-Date).ToUniversalTime().ToString('o')
  steps = [ordered]@{}
  expectations = [ordered]@{}
  verdict = 'INCOMPLETE'
}
function Save-Result {
  $text = $Result | ConvertTo-Json -Depth 10
  [IO.File]::WriteAllText($ResultFile, $text, (Utf8NoBom))
}

function Expect([string]$Name, [bool]$Value, [string]$Detail = '') {
  $Result.expectations[$Name] = [ordered]@{ ok = $Value; detail = $Detail }
  Note ("expect {0}: {1} {2}" -f $Name, $(if ($Value) { 'ok' } else { 'NOT OK' }), $Detail)
}

function Get-ArpVersion {
  try { [string](Get-ItemProperty -LiteralPath $ArpKey -ErrorAction Stop).DisplayVersion } catch { $null }
}

function Get-TreeDigest([string]$Dir) {
  if (-not (Test-Path -LiteralPath $Dir)) { return [ordered]@{ exists = $false; entries = 0; sha256 = $null } }
  $root = (Resolve-Path -LiteralPath $Dir).ProviderPath.TrimEnd('\')
  $lines = New-Object 'System.Collections.Generic.List[string]'
  $all = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object FullName)
  foreach ($item in $all) {
    $rel = $item.FullName.Substring($root.Length).ToLowerInvariant()
    if ($item.PSIsContainer) { $lines.Add($rel + '|dir') }
    else {
      $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName -ErrorAction SilentlyContinue)
      $lines.Add(('{0}|{1}|{2}' -f $rel, $item.Length, $(if ($h) { $h.Hash } else { 'unreadable' })))
    }
  }
  $sha = [Security.Cryptography.SHA256]::Create()
  $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $lines)))
  [ordered]@{ exists = $true; entries = $all.Count; sha256 = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant() }
}

# Names, sizes and write times of a directory, not its contents (the account's real data directory
# holds keys in a dry run: those bytes are never read).
function Get-ListingDigest([string]$Dir) {
  if (-not (Test-Path -LiteralPath $Dir)) { return [ordered]@{ exists = $false; entries = 0; sha256 = $null } }
  $root = (Resolve-Path -LiteralPath $Dir).ProviderPath.TrimEnd('\')
  $all = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object FullName)
  $lines = @($all | ForEach-Object { '{0}|{1}|{2}' -f $_.FullName.Substring($root.Length).ToLowerInvariant(), $(if ($_.PSIsContainer) { 'dir' } else { $_.Length }), $_.LastWriteTimeUtc.Ticks })
  $sha = [Security.Cryptography.SHA256]::Create()
  $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $lines)))
  [ordered]@{ exists = $true; entries = $all.Count; sha256 = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant() }
}

function Get-ProcessesUnder([string]$Dir) {
  $prefix = $Dir.TrimEnd('\') + '\'
  @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } |
      ForEach-Object { [ordered]@{ pid = [int]$_.ProcessId; image = [string]$_.ExecutablePath } })
}

function Get-RootThumbprints {
  @(Get-ChildItem Cert:\CurrentUser\Root, Cert:\LocalMachine\Root | ForEach-Object { $_.Thumbprint } | Sort-Object)
}

function Get-Snapshot {
  [ordered]@{
    arp_display_version = (Get-ArpVersion)
    install_tree = (Get-TreeDigest $InstallDir)
    root_thumbprints_sha256 = (& {
        $sha = [Security.Cryptography.SHA256]::Create()
        $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]::Join(',', (Get-RootThumbprints))))
        ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant()
      })
  }
}

function Same-Snapshot($A, $B) {
  ($A.arp_display_version -eq $B.arp_display_version) -and
  ($A.install_tree.sha256 -eq $B.install_tree.sha256) -and
  ($A.install_tree.entries -eq $B.install_tree.entries) -and
  ($A.root_thumbprints_sha256 -eq $B.root_thumbprints_sha256)
}

# A child process with a bounded run time; its output files are kept. $EntryEnv: the environment of
# an installer (the entry, the baseline Setup, the uninstaller): the data directory, RunAsInvoker and,
# in a safe dry run, an unusable temporary directory.
function Invoke-Child([string]$Exe, [string[]]$ChildArgs, [int]$TimeoutSeconds, [bool]$EntryEnv) {
  $o = Join-Path $Work ('child-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
  $saved = @{}
  foreach ($n in '__COMPAT_LAYER', 'TEMP', 'TMP', 'ONCL_DATA_DIR') { $saved[$n] = [Environment]::GetEnvironmentVariable($n, 'Process') }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    # The entry finds the program's management endpoint by the data directory it is given by the
    # environment (as the program does): the daemon of a dry run lives in -DataDir, so the entry
    # is told the same; without -DataDir both use the account's default directory.
    if ($EntryEnv -and $DataDir) { [Environment]::SetEnvironmentVariable('ONCL_DATA_DIR', $DataDir, 'Process') }
    if ($EntryEnv -and $RunAsInvoker) { [Environment]::SetEnvironmentVariable('__COMPAT_LAYER', 'RunAsInvoker', 'Process') }
    if ($EntryEnv -and $SafeDryRun) {
      [Environment]::SetEnvironmentVariable('TEMP', $UnusableTemp, 'Process')
      [Environment]::SetEnvironmentVariable('TMP', $UnusableTemp, 'Process')
    }
    $p = Start-Process -FilePath $Exe -ArgumentList $ChildArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput "$o.out" -RedirectStandardError "$o.err"
    $null = $p.Handle
  } finally {
    foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n], 'Process') }
  }
  $timedOut = $false
  if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    $timedOut = $true
    Note "TIMEOUT: $Exe (pid $($p.Id)) is stopped by its exact pid"
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $null = $p.WaitForExit(10000)
  }
  $text = (@((Get-Content -LiteralPath "$o.out" -ErrorAction SilentlyContinue), (Get-Content -LiteralPath "$o.err" -ErrorAction SilentlyContinue)) | ForEach-Object { $_ }) -join ' | '
  [ordered]@{
    exit = $(if ($timedOut) { 'timeout' } else { [int]$p.ExitCode })
    seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    output = $text
  }
}

function Invoke-Entry([int]$WaitSeconds) {
  Note "entry: --silent --wait $WaitSeconds"
  $r = Invoke-Child $EntryExe @('--silent', '--wait', "$WaitSeconds") ($WaitSeconds + 600) $true
  Note ("entry exit {0} after {1}s: {2}" -f $r.exit, $r.seconds, $r.output)
  $r
}

# ------------------------------------------------------------------ pipes and frames

function Get-Hex16([string]$Text) {
  $sha = [Security.Cryptography.SHA256]::Create()
  $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
  (@($h[0..7] | ForEach-Object { $_.ToString('x2') })) -join ''
}

function Open-Pipe([string]$Name, [int]$TimeoutMs) {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Name, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
  try { $c.Connect($TimeoutMs); $c } catch { $c.Dispose(); $null }
}

function Send-Frame($Stream, [byte[]]$Payload) {
  $header = [BitConverter]::GetBytes([uint32]$Payload.Length)
  $Stream.Write($header, 0, 4)
  $Stream.Write($Payload, 0, $Payload.Length)
  $Stream.Flush()
}

function New-FrameReader($Stream) {
  @{ Stream = $Stream; Buf = (New-Object byte[] 4); Phase = 'hdr'; Got = 0; Need = 4; Task = $null }
}

# One frame (u32 little-endian length, payload) as bytes, or $null if none is complete within
# the time; a started read is kept for the next call.
function Read-FrameBytes($R, [int]$TimeoutMs) {
  $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
  while ($true) {
    if ($null -eq $R.Task) { $R.Task = $R.Stream.ReadAsync($R.Buf, $R.Got, ($R.Need - $R.Got)) }
    $left = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $R.Task.Wait($left)) { return $null }
    $n = $R.Task.Result
    $R.Task = $null
    if ($n -le 0) { throw 'the pipe was closed by the daemon' }
    $R.Got += $n
    if ($R.Got -lt $R.Need) { continue }
    if ($R.Phase -eq 'hdr') {
      $len = [BitConverter]::ToUInt32($R.Buf, 0)
      if ($len -gt 67108864) { throw "frame of $len bytes" }
      if ($len -eq 0) { $R.Got = 0; return (New-Object byte[] 0) }
      $R.Buf = New-Object byte[] ([int]$len)
      $R.Need = [int]$len
      $R.Got = 0
      $R.Phase = 'body'
    } else {
      $body = $R.Buf
      $R.Buf = New-Object byte[] 4
      $R.Need = 4
      $R.Got = 0
      $R.Phase = 'hdr'
      return $body
    }
  }
}

function Read-FrameText($R, [int]$TimeoutMs) {
  $b = Read-FrameBytes $R $TimeoutMs
  if ($null -eq $b) { return $null }
  [Text.Encoding]::UTF8.GetString($b)
}

# One attempt to hold the program, as the entry makes it ("ONCLM", version 1, operation 1);
# a grant is given straight back (operation 2).
function Test-Hold([string]$PipeName) {
  $c = Open-Pipe $PipeName 5000
  if ($null -eq $c) { return [ordered]@{ result = 'no-endpoint' } }
  try {
    $r = New-FrameReader $c
    Send-Frame $c ([byte[]](0x4F, 0x4E, 0x43, 0x4C, 0x4D, 1, 1))
    $b = Read-FrameBytes $r 10000
    if ($null -eq $b) { return [ordered]@{ result = 'timeout' } }
    if ($b.Length -lt 7) { return [ordered]@{ result = 'invalid' } }
    if ($b[6] -eq 2) { return [ordered]@{ result = 'busy' } }
    if ($b[6] -eq 1) {
      $daemonPid = [BitConverter]::ToUInt32($b, 7)
      Send-Frame $c ([byte[]](0x4F, 0x4E, 0x43, 0x4C, 0x4D, 1, 2))
      $rel = Read-FrameBytes $r 10000
      return [ordered]@{ result = 'granted'; daemon_pid = [int]$daemonPid; released = [bool]($null -ne $rel -and $rel.Length -ge 7 -and $rel[6] -eq 3) }
    }
    [ordered]@{ result = ('status-' + $b[6]) }
  } finally { $c.Dispose() }
}

function ConvertFrom-PemBody([string]$Pem) {
  $body = (($Pem -split "`r?`n") | Where-Object { $_ -and -not $_.StartsWith('-----') }) -join ''
  [Convert]::FromBase64String(($body -replace '\s', ''))
}

# ------------------------------------------------------------------ environment

Note 'step 1: environment'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'the token is elevated: run as an ordinary (not elevated) user' }
foreach ($f in @($EntryExe, $DaemonExe, $Keystore, $KeystorePassFile, $RootCert, $StepsTemplate)) {
  if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Fail "no such file: $f" }
}
$EntryExe = (Resolve-Path -LiteralPath $EntryExe).ProviderPath
$DaemonExe = (Resolve-Path -LiteralPath $DaemonExe).ProviderPath
$Keystore = (Resolve-Path -LiteralPath $Keystore).ProviderPath
$RootCert = (Resolve-Path -LiteralPath $RootCert).ProviderPath
if ($HoldSeconds -lt 60) { Fail '-HoldSeconds is under 60: a signature in flight for less is no proof of the hold' }
if ($HoldSeconds -lt ($EntryWaitSeconds + 5)) { Fail '-HoldSeconds must exceed -EntryWaitSeconds by at least 5 (the signature has to outlast the waiting entry)' }

$os = Get-CimInstance Win32_OperatingSystem
$kind = $null
if ($env:USERNAME -eq 'WDAGUtilityAccount') { $kind = 'sandbox' }
else {
  $model = (Get-CimInstance Win32_ComputerSystem).Model + ' ' + (Get-CimInstance Win32_ComputerSystem).Manufacturer + ' ' + (Get-CimInstance Win32_BIOS).Manufacturer
  if ($model -match 'Virtual|VMware|KVM|QEMU|Hyper-V|Xen|Parallels') { $kind = 'vm' }
}
if ($SafeDryRun) {
  if (-not $DataDir) { Fail '-SafeDryRun needs -DataDir: the default data directory of this account is never used in a dry run' }
  if ($BaselineSetup) { Fail '-SafeDryRun installs nothing: no -BaselineSetup' }
  if ($UninstallAtEnd) { Fail '-SafeDryRun installs nothing: no -UninstallAtEnd' }
  $kind = $(if ($kind) { $kind } else { 'physical-or-unknown (safe dry run)' })
} elseif (-not $kind) {
  Fail 'this machine is not a virtual machine or Windows Sandbox: refusing to install anything here (use -SafeDryRun for a dry run)'
}

if ($DataDir) {
  $DataDir = [IO.Path]::GetFullPath($DataDir).TrimEnd('\')
  New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
  $dataShown = $DataDir
} else {
  $dataShown = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'OpenNCALayer')).TrimEnd('\')
}
$DefaultData = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'OpenNCALayer')).TrimEnd('\')
if ($SafeDryRun -and ($dataShown -ieq $DefaultData)) { Fail '-DataDir is the default data directory: refusing in a dry run' }

$sid = $identity.User.Value
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$RelayPipe = 'OpenNCALayer-' + (Get-Hex16 "$sid|$session|$dataShown")
$MaintPipe = 'OpenNCALayer-maintenance-' + (Get-Hex16 "$sid|$session|maintenance|$dataShown")

# The daemon must be a test build: only a build with `e2e-prompter` has the `e2e` command.
$probe = Invoke-Child $DaemonExe @('e2e', '--help') 60 $false
$isTestBuild = ($probe.exit -eq 0)
$version = Invoke-Child $DaemonExe @('--version') 60 $false

$Result.steps.env = [ordered]@{
  whoami = (whoami)
  is_admin_group = [bool]((whoami /groups) -match 'S-1-5-32-544')
  elevated = $false
  os_build = [string]$os.BuildNumber
  os_arch = [string]$os.OSArchitecture
  ps_version = $PSVersionTable.PSVersion.ToString()
  ps_is_64bit = [Environment]::Is64BitProcess
  machine_kind = $kind
  session_id = $session
  data_dir = $dataShown
  data_dir_is_default = ($dataShown -ieq $DefaultData)
  pipes = [ordered]@{ relay = $RelayPipe; maintenance = $MaintPipe }
  entry = [ordered]@{ file = (Split-Path -Leaf $EntryExe); sha256 = (Sha256Of $EntryExe); authenticode = [string](Get-AuthenticodeSignature -LiteralPath $EntryExe).Status }
  daemon = [ordered]@{ file = (Split-Path -Leaf $DaemonExe); sha256 = (Sha256Of $DaemonExe); is_e2e_test_build = $isTestBuild; version = $version.output }
  keystore_sha256 = (Sha256Of $Keystore)
  root_cert_sha256 = (Sha256Of $RootCert)
  steps_template_sha256 = (Sha256Of $StepsTemplate)
  script_sha256 = (Sha256Of $PSCommandPath)
  arp_before = (Get-ArpVersion)
  install_dir_before = (Test-Path -LiteralPath $InstallDir)
  hold_seconds = $HoldSeconds
  entry_wait_seconds = $EntryWaitSeconds
  quiet_seconds = $QuietSeconds
  run_as_invoker = [bool]$RunAsInvoker
}
Save-Result
Expect 'daemon_is_a_test_build' $isTestBuild 'the e2e command exists only with feature e2e-prompter'
if (-not $isTestBuild) { Fail 'the daemon is not an e2e-prompter test build' }

$UnusableTemp = Join-Path $Work 'not-a-directory.tmp'
[IO.File]::WriteAllText($UnusableTemp, 'this file stands where the entry would make its temporary directory', (Utf8NoBom))

# ------------------------------------------------------------------ baseline

if (-not $SafeDryRun) {
  Note 'step 2: baseline installation'
  if ((Get-ArpVersion) -or (Test-Path -LiteralPath (Join-Path $InstallDir 'current'))) { Fail 'OpenNCALayer is already installed on this image: revert to a clean snapshot' }
  if ($BaselineSetup) {
    if (-not (Test-Path -LiteralPath $BaselineSetup -PathType Leaf)) { Fail "no such file: $BaselineSetup" }
    $b = Invoke-Child ((Resolve-Path -LiteralPath $BaselineSetup).ProviderPath) @('--silent') 600 $true
    Start-Sleep -Seconds 8
  } else {
    $b = Invoke-Entry 30
    Start-Sleep -Seconds 2
  }
  # The installer may start the program: it is stopped by its exact pid (the e2e daemon takes its place).
  foreach ($p in @(Get-ProcessesUnder $InstallDir)) {
    Note "stopping the program the installer started: pid $($p.pid)"
    Stop-Process -Id $p.pid -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Seconds 3
  $Result.steps.baseline = [ordered]@{ installer = $(if ($BaselineSetup) { Split-Path -Leaf $BaselineSetup } else { 'the entry itself (clean install)' }); exit = $b.exit; display_version = (Get-ArpVersion); output = $b.output; processes_after = @(Get-ProcessesUnder $InstallDir) }
  Save-Result
  Expect 'baseline_installed' ((Get-ArpVersion) -and (($BaselineVersion -eq '') -or ((Get-ArpVersion) -eq $BaselineVersion))) ("display version " + (Get-ArpVersion))
  if (-not (Get-ArpVersion)) { Fail 'the baseline installation did not happen' }
} else {
  Note 'step 2: baseline skipped (-SafeDryRun installs nothing)'
}

$Before = Get-Snapshot
$Result.steps.snapshot_before = $Before
Save-Result
$DefaultDataBefore = $null
if ($SafeDryRun) { $DefaultDataBefore = Get-ListingDigest $DefaultData }

# ------------------------------------------------------------------ the daemon

Note 'step 3: the test daemon'
$Gate = Join-Path $Work 'sign-may-go-on'
if (Test-Path -LiteralPath $Gate) { Remove-Item -LiteralPath $Gate -Force }
$StepsFile = Join-Path $Work 'steps.rendered.json'
function Quote-Json([string]$Value) { ($Value | ConvertTo-Json) }
$password = ([IO.File]::ReadAllText($KeystorePassFile)).Trim()
$template = [IO.File]::ReadAllText($StepsTemplate)
$rendered = $template.Replace('"__GATE__"', (Quote-Json $Gate)).Replace('"__KEYSTORE__"', (Quote-Json $Keystore)).Replace('"__PASSWORD__"', (Quote-Json $password))
[IO.File]::WriteAllText($StepsFile, $rendered, (Utf8NoBom))
$password = $null; $rendered = $null

$daemon = $null
$bridge = $null
try {
  $savedEnv = @{}
  foreach ($n in 'ONCL_E2E_PROMPTER', 'ONCL_DATA_DIR', 'ONCL_UPDATE_INDEX_BASE') { $savedEnv[$n] = [Environment]::GetEnvironmentVariable($n, 'Process') }
  try {
    [Environment]::SetEnvironmentVariable('ONCL_E2E_PROMPTER', $StepsFile, 'Process')
    # The test daemon must not update itself or reach the network: its update index is a closed loopback port.
    [Environment]::SetEnvironmentVariable('ONCL_UPDATE_INDEX_BASE', 'https://127.0.0.1:9/oncl-hold-no-updates', 'Process')
    if ($DataDir) { [Environment]::SetEnvironmentVariable('ONCL_DATA_DIR', $DataDir, 'Process') }
    $daemon = Start-Process -FilePath $DaemonExe -ArgumentList @('run', '--allow-no-wss', '--no-tray') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $OutDir 'daemon.out.txt') -RedirectStandardError (Join-Path $OutDir 'daemon.err.txt')
    $null = $daemon.Handle
  } finally {
    foreach ($n in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($n, $savedEnv[$n], 'Process') }
  }
  Note "daemon pid $($daemon.Id)"
  $ready = $false
  $limit = [DateTime]::UtcNow.AddSeconds(60)
  while ([DateTime]::UtcNow -lt $limit) {
    if ($daemon.HasExited) { Fail ("the daemon ended with code {0}: {1}" -f $daemon.ExitCode, ((Get-Content -LiteralPath (Join-Path $OutDir 'daemon.err.txt') -ErrorAction SilentlyContinue) -join ' | ')) }
    $t = Test-Hold $MaintPipe
    if ($t.result -eq 'granted') { $ready = $true; $idleBefore = $t; break }
    Start-Sleep -Milliseconds 300
  }
  if (-not $ready) { Fail "the daemon's management endpoint did not answer in 60 s (pipe $MaintPipe)" }
  $Result.steps.daemon = [ordered]@{ pid = $daemon.Id; image = $DaemonExe; idle_hold_before_signature = $idleBefore }
  Expect 'idle_hold_granted_and_released_before' ($idleBefore.result -eq 'granted' -and $idleBefore.released -and $idleBefore.daemon_pid -eq $daemon.Id) ("granted by pid " + $idleBefore.daemon_pid)
  $listeners = 'not checked (Get-NetTCPConnection is missing)'
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $daemon.Id -ErrorAction SilentlyContinue | ForEach-Object { '{0}:{1}' -f $_.LocalAddress, $_.LocalPort })
  }
  $Result.steps.daemon.tcp_listeners = $listeners
  Expect 'daemon_has_no_tcp_listener' (($listeners -is [array]) -and ($listeners.Count -eq 0)) ([string]($listeners -join ','))

  # -------------------------------------------------------------- the signature

  Note 'step 4: the signature is sent over the bridge'
  $bridge = Open-Pipe $RelayPipe 15000
  if ($null -eq $bridge) { Fail "the daemon's bridge endpoint is not there (pipe $RelayPipe)" }
  $reader = New-FrameReader $bridge
  $hello = Read-FrameText $reader 15000
  if (-not $hello -or $hello -notmatch '"t"\s*:\s*"hello"') { Fail "no hello from the daemon: $hello" }
  Send-Frame $bridge ([Text.Encoding]::UTF8.GetBytes('{"t":"open","sid":1,"origin":"https://hold.test"}'))
  $opened = Read-FrameText $reader 15000
  $greeting = Read-FrameText $reader 15000
  if (-not $opened -or $opened -notmatch '"t"\s*:\s*"open"') { Fail "the socket was not opened: $opened" }

  $content = [Text.Encoding]::UTF8.GetBytes("OpenNCALayer signing hold scenario " + [guid]::NewGuid().ToString() + "`n")
  $request = @{
    module = 'kz.gov.pki.knca.basics'
    method = 'sign'
    args = @{
      allowedStorages = $null
      format = 'cms'
      data = [Convert]::ToBase64String($content)
      signingParams = @{ decode = $true; encapsulate = $false; digested = $false }
      signerParams = @{ extKeyUsageOids = @(); chain = @() }
      locale = 'ru'
    }
  } | ConvertTo-Json -Depth 6 -Compress
  $frame = @{ t = 'msg'; sid = 1; data = $request } | ConvertTo-Json -Compress
  $tSent = $Clock.Elapsed.TotalSeconds
  Send-Frame $bridge ([Text.Encoding]::UTF8.GetBytes($frame))

  $busy = $null
  $polls = 0
  $limit = [DateTime]::UtcNow.AddSeconds(60)
  while ([DateTime]::UtcNow -lt $limit) {
    $polls++
    $t = Test-Hold $MaintPipe
    if ($t.result -eq 'busy') { $busy = $t; break }
    Start-Sleep -Milliseconds 100
  }
  $tBusy = $Clock.Elapsed.TotalSeconds
  Expect 'busy_seen_while_signing' ($null -ne $busy) ("after $polls polls, " + [math]::Round($tBusy - $tSent, 1) + ' s')
  if ($null -eq $busy) { Fail 'the daemon never became busy: the signature did not start' }
  $Result.steps.signature_started = [ordered]@{ sent_at_s = [math]::Round($tSent, 1); busy_seen_at_s = [math]::Round($tBusy, 1); polls = $polls; content_sha256 = (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($content))).Replace('-', '').ToLowerInvariant()) }
  Save-Result

  # -------------------------------------------------------------- the hold

  Note 'step 5: the entry, twice, while the signature is in flight'
  function Check-Held([string]$Label) {
    $reply = Read-FrameText $reader 0
    $h = Test-Hold $MaintPipe
    $snap = Get-Snapshot
    [ordered]@{
      label = $Label
      signature_reply_arrived = ($null -ne $reply)
      daemon_alive = (-not $daemon.HasExited)
      hold_probe = $h.result
      installation_unchanged = (Same-Snapshot $Before $snap)
      arp_display_version = $snap.arp_display_version
      install_tree_sha256 = $snap.install_tree.sha256
    }
  }
  $short = Invoke-Entry 2
  if ($short.exit -ne 4) {
    # Not held: whatever the entry did, nothing more is started against this installation.
    $Result.steps.hold_during_signature = [ordered]@{ short = $short; short_state = (Check-Held 'after --wait 2') }
    Save-Result
    Expect 'hold_short_exit_4' $false "exit $($short.exit)"
    Fail 'the first entry run during the signature did not exit 4: the scenario stops here'
  }
  $afterShort = Check-Held 'after --wait 2'
  $full = Invoke-Entry $EntryWaitSeconds
  $afterFull = Check-Held "after --wait $EntryWaitSeconds"
  $Result.steps.hold_during_signature = [ordered]@{ short = $short; short_state = $afterShort; full = $full; full_state = $afterFull }
  Save-Result
  Expect 'hold_short_exit_4' ($short.exit -eq 4) "exit $($short.exit)"
  Expect 'hold_full_exit_4' ($full.exit -eq 4) "exit $($full.exit)"
  Expect 'hold_full_waited_about_the_wait' ($full.seconds -ge ($EntryWaitSeconds - 1)) "$($full.seconds) s of $EntryWaitSeconds"
  Expect 'hold_message_says_busy' (($short.output -match 'is busy') -and ($full.output -match 'is busy') -and ($full.output -match 'installation was not changed')) $full.output
  Expect 'installation_unchanged_during_hold' ($afterShort.installation_unchanged -and $afterFull.installation_unchanged) ("ARP " + $afterFull.arp_display_version + ', tree ' + $afterFull.install_tree_sha256)
  Expect 'signature_not_cut_while_held' (-not $afterShort.signature_reply_arrived -and -not $afterFull.signature_reply_arrived -and $afterFull.daemon_alive -and $afterFull.hold_probe -eq 'busy') ('probe ' + $afterFull.hold_probe)

  $remaining = ($tBusy + $HoldSeconds) - $Clock.Elapsed.TotalSeconds
  if ($remaining -gt 0) { Note ("the signature stays in flight for {0:N0} more seconds" -f $remaining); Start-Sleep -Seconds ([int][math]::Ceiling($remaining)) }
  $heldFor = $Clock.Elapsed.TotalSeconds - $tBusy
  Expect 'signature_in_flight_at_least_60s' ($heldFor -ge 60) ("busy for {0:N1} s before the gate opened" -f $heldFor)

  # -------------------------------------------------------------- the signature finishes

  Note 'step 6: the gate opens; the signature must finish'
  [IO.File]::WriteAllText($Gate, 'go', (Utf8NoBom))
  $replyText = Read-FrameText $reader 90000
  $tReply = $Clock.Elapsed.TotalSeconds
  if ($null -eq $replyText) { Fail 'no reply to the signature within 90 s after the gate opened' }
  $sigOk = $false; $detail = ''; $der = $null
  try {
    $outer = $replyText | ConvertFrom-Json
    $answer = $outer.data | ConvertFrom-Json
    if ($answer.status -eq $true) { $der = ConvertFrom-PemBody ([string]$answer.body.result[0]); $sigOk = $true } else { $detail = [string]$outer.data }
  } catch { $detail = "the reply is not understood: $($_.Exception.Message)" }
  Expect 'signature_reply_status_true' $sigOk $detail
  if (-not $sigOk) { $Result.steps.signature_result = [ordered]@{ reply_text = $replyText }; Save-Result; Fail 'the signature did not succeed' }

  Add-Type -AssemblyName System.Security
  $check = [ordered]@{ cms_bytes = $der.Length; verifier = 'System.Security.Cryptography.Pkcs.SignedCms.CheckSignature(verifySignatureOnly) of Windows, not of this program' }
  $contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo (, $content)
  $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($contentInfo, $true)
  $cms.Decode($der)
  # Kept so that the host can check them again with another verifier (openssl cms -verify -binary -inform DER -noverify).
  [IO.File]::WriteAllBytes((Join-Path $OutDir 'signature.p7s'), $der)
  [IO.File]::WriteAllBytes((Join-Path $OutDir 'content.bin'), $content)
  $valid = $false
  try { $cms.CheckSignature($true); $valid = $true } catch { $check.error = $_.Exception.Message }
  $check.signature_valid = $valid
  $check.signers = $cms.SignerInfos.Count
  $tampered = [byte[]]$content.Clone(); $tampered[0] = $tampered[0] -bxor 1
  $cmsBad = New-Object System.Security.Cryptography.Pkcs.SignedCms((New-Object System.Security.Cryptography.Pkcs.ContentInfo (, $tampered)), $true)
  $cmsBad.Decode($der)
  $rejected = $false
  try { $cmsBad.CheckSignature($true) } catch { $rejected = $true }
  $check.tampered_content_rejected = $rejected
  $root = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [IO.File]::ReadAllBytes($RootCert))
  $signer = $null
  if ($cms.SignerInfos.Count -ge 1) { $signer = $cms.SignerInfos[0].Certificate }
  $chainOk = $false
  if ($signer) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    $chain.ChainPolicy.UrlRetrievalTimeout = New-Object TimeSpan(0, 0, 3)
    [void]$chain.ChainPolicy.ExtraStore.Add($root)
    [void]$chain.Build($signer)
    $top = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    $chainOk = ($top.Thumbprint -eq $root.Thumbprint)
    $check.signer_subject = $signer.Subject
    $check.signer_sha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($signer.RawData))).Replace('-', '').ToLowerInvariant()
    $check.chain_length = $chain.ChainElements.Count
    $check.chain_top_is_the_synthetic_root = $chainOk
    $check.chain_status = @($chain.ChainStatus | ForEach-Object { [string]$_.Status })
  } else { $check.signer_certificate = 'not embedded in the CMS' }
  $check.synthetic_root_subject = $root.Subject
  $Result.steps.signature_result = $check
  Save-Result
  Expect 'signature_valid_by_windows' $valid ("signers " + $check.signers)
  Expect 'tampered_content_rejected' $rejected ''
  Expect 'signer_chains_to_synthetic_root' $chainOk ''

  # -------------------------------------------------------------- the quiet time

  Note 'step 7: the quiet time after the signature'
  $quietProbe = Test-Hold $MaintPipe
  $quiet = Invoke-Entry 3
  Expect 'quiet_probe_busy' ($quietProbe.result -eq 'busy') $quietProbe.result
  Expect 'quiet_entry_exit_4' ($quiet.exit -eq 4) "exit $($quiet.exit)"
  $afterQuiet = Get-Snapshot
  Expect 'installation_unchanged_in_quiet_time' (Same-Snapshot $Before $afterQuiet) ''
  $waitMore = ($tReply + $QuietSeconds + 6) - $Clock.Elapsed.TotalSeconds
  if ($waitMore -gt 0) { Note ("waiting {0:N0} s for the quiet time to pass" -f $waitMore); Start-Sleep -Seconds ([int][math]::Ceiling($waitMore)) }
  $idleAfter = Test-Hold $MaintPipe
  Expect 'hold_granted_after_quiet_time' ($idleAfter.result -eq 'granted' -and $idleAfter.released) $idleAfter.result
  $Result.steps.quiet_time = [ordered]@{ probe_right_after_signature = $quietProbe; entry = $quiet; probe_after_quiet_time = $idleAfter }
  Save-Result

  # -------------------------------------------------------------- the entry goes through

  Note 'step 8: the entry once more'
  $final = Invoke-Entry $EntryWaitSeconds
  $afterFinal = Get-Snapshot
  $processesAfter = @(Get-ProcessesUnder $InstallDir)
  $Result.steps.entry_after_quiet_time = [ordered]@{ entry = $final; arp_display_version = $afterFinal.arp_display_version; processes_under_installation = $processesAfter; install_tree_sha256 = $afterFinal.install_tree.sha256 }
  if ($SafeDryRun) {
    Expect 'final_entry_was_granted_but_could_not_install_in_a_dry_run' (($final.exit -eq 1) -and ($final.output -match 'cannot prepare Setup') -and (Same-Snapshot $Before $afterFinal)) "exit $($final.exit)"
  } else {
    Expect 'final_entry_exit_0' ($final.exit -eq 0) "exit $($final.exit)"
    Expect 'final_version_is_the_entrys' ($afterFinal.arp_display_version -eq $ExpectedVersion) ("ARP " + $afterFinal.arp_display_version + ' expected ' + $ExpectedVersion)
    $mainExe = Join-Path $InstallDir 'current\openncalayer.exe'
    if (Test-Path -LiteralPath $mainExe) {
      $v = Invoke-Child $mainExe @('--version') 60 $false
      $Result.steps.entry_after_quiet_time.program_version = $v.output
      Expect 'installed_program_reports_the_entrys_version' ($v.output -match [regex]::Escape($ExpectedVersion)) $v.output
    } else { Expect 'installed_program_reports_the_entrys_version' $false 'no installed program' }
  }
  Save-Result
  $released = Test-Hold $MaintPipe
  $Result.steps.hold_released_with_the_entry = $released
  Expect 'hold_released_when_the_entry_ended' ($released.result -eq 'granted' -and $released.released) $released.result
  Save-Result
  if (-not $SafeDryRun) {
    # The entry starts "the program that ran before" again (the installed one, which finds the endpoint
    # taken by the test daemon): whatever runs from the installation now is stopped by its exact pid.
    $restarted = @(Get-ProcessesUnder $InstallDir)
    foreach ($p in $restarted) { Note "stopping a program of the installation: pid $($p.pid)"; Stop-Process -Id $p.pid -Force -ErrorAction SilentlyContinue }
    $Result.steps.entry_after_quiet_time.processes_stopped_after = $restarted
    Save-Result
  }
  if ($SafeDryRun) {
    # The names, sizes and times of the account's real data directory (never its contents): untouched.
    $dataAfter = Get-ListingDigest $DefaultData
    $Result.steps.default_data_dir = [ordered]@{ before = $DefaultDataBefore; after = $dataAfter }
    Expect 'default_data_dir_untouched' ($dataAfter.sha256 -eq $DefaultDataBefore.sha256) ("{0} entries before, {1} after" -f $DefaultDataBefore.entries, $dataAfter.entries)
    Save-Result
  }

  # -------------------------------------------------------------- end

  if ($UninstallAtEnd -and -not $SafeDryRun) {
    foreach ($p in @(Get-ProcessesUnder $InstallDir)) { Stop-Process -Id $p.pid -Force -ErrorAction SilentlyContinue }
    $k = Get-ItemProperty -LiteralPath $ArpKey -ErrorAction SilentlyContinue
    $cmd = if ($k) { if ($k.QuietUninstallString) { [string]$k.QuietUninstallString } else { [string]$k.UninstallString } } else { '' }
    if ($cmd -match '^"([^"]+)"\s*(.*)$') {
      $u = Invoke-Child $Matches[1] @($Matches[2] -split '\s+' | Where-Object { $_ }) 180 $true
      Start-Sleep -Seconds 8
      $Result.steps.uninstall = [ordered]@{ exit = $u.exit; arp_after = (Get-ArpVersion); install_dir_exists_after = (Test-Path -LiteralPath $InstallDir) }
    }
  }
}
catch {
  $Result.error = $_.Exception.Message
  Note ("ERROR: " + $_.Exception.Message)
}
finally {
  if ($bridge) { $bridge.Dispose() }
  if ($daemon -and -not $daemon.HasExited) {
    Note "stopping the test daemon by its exact pid $($daemon.Id)"
    Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue
    $null = $daemon.WaitForExit(10000)
  }
  # The scripted answers carry the keystore password: not left behind.
  Remove-Item -LiteralPath $StepsFile -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $Gate -Force -ErrorAction SilentlyContinue
}

$failed = @($Result.expectations.Keys | Where-Object { -not $Result.expectations[$_].ok })
$total = @($Result.expectations.Keys).Count
if ($Result.Contains('error')) { $Result.verdict = 'FAIL' }
elseif ($failed.Count -gt 0) { $Result.verdict = 'FAIL' }
elseif ($SafeDryRun) { $Result.verdict = 'PASS-DRY-RUN' }
else { $Result.verdict = 'PASS' }
$Result.failed_expectations = $failed
$Result.finished_utc = (Get-Date).ToUniversalTime().ToString('o')
$Result.seconds = [math]::Round($Clock.Elapsed.TotalSeconds, 1)
Save-Result
Note ("verdict {0} ({1} of {2} expectations ok){3}" -f $Result.verdict, ($total - $failed.Count), $total, $(if ($failed.Count) { ': ' + ($failed -join ', ') } else { '' }))
if ($Result.verdict -eq 'FAIL') { exit 1 }
exit 0
