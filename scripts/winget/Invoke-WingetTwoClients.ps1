<#
.SYNOPSIS
  Step 8a of the WinGet VM runbook: two clients of the running program's management endpoint at
  the same time (the installer entry and a second maintainer, which is what the program's own
  updater is: both take the one activity gate of the process).

.DESCRIPTION
  Claim under test (docs/dev/winget-installer.md): while one maintainer holds the program, a second
  one is told "busy" (status 2) and nothing is broken for the first one; the entry that finds the
  program held by another maintainer exits 4 without touching the installation; and while the entry
  itself holds the program for its installation, a second maintainer is told busy too and the
  installation still ends with exit 0.

  The daemon is the e2e-prompter TEST build of the same tree (never installed), idle (no steps), in
  the account's default data directory, as in Invoke-WingetHold.ps1. The entry, the daemon and this
  script must be the same user in the same session (the pipe names contain the user SID and the
  session id, and its data directory: a probe of another user, session or data directory sees no
  endpoint at all; an earlier probe of this kind failed with a null pipe stream, which is what a
  failed connect gives when it is not checked). A non-elevated token is
  required; run it on a clean image (nothing installed). Windows PowerShell 5.1.

  Cases (each is an entry of result.json "expectations"):
    A  client 1 holds -> granted; client 2 (own connection) -> busy; client 2 again -> busy; client 2 releases
       (no hold of its own) and goes away -> client 1's hold is still there (asking again is granted
       at once on the same connection); only after client 1 releases does a new client get granted.
    B  client 1 holds -> the entry (--wait 2) -> exit 4, the installation does not exist yet; client 1
       is not disturbed (still holds).
    C  the entry runs for real (clean install) while client 2 asks every 100 ms: at least one busy,
       never an error; the entry ends 0; the ARP version is the entry's; a hold works afterwards.
#>
param(
  [Parameter(Mandatory)][string]$EntryExe,
  [Parameter(Mandatory)][string]$DaemonExe,
  [Parameter(Mandatory)][string]$ExpectedVersion,
  [Parameter(Mandatory)][string]$OutDir,
  [switch]$UninstallAtEnd
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ArpKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenNCALayer'
$InstallDir = Join-Path $env:LOCALAPPDATA 'OpenNCALayer'
$Clock = [Diagnostics.Stopwatch]::StartNew()

function Fail([string]$Message) { throw "STEP 8A FAILED: $Message" }
function Utf8NoBom { New-Object Text.UTF8Encoding $false }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).ProviderPath
$LogFile = Join-Path $OutDir 'log.txt'
$ResultFile = Join-Path $OutDir 'result.json'
$Work = Join-Path $OutDir 'work'
New-Item -ItemType Directory -Force -Path $Work | Out-Null

function Note([string]$Message) {
  $line = '{0} [{1,6:N1}s] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Clock.Elapsed.TotalSeconds, $Message
  Write-Host $line
  [IO.File]::AppendAllText($LogFile, $line + "`r`n", (Utf8NoBom))
}

$Result = [ordered]@{ scenario = 'two-maintenance-clients'; format = 1; started_utc = [DateTime]::UtcNow.ToString('o'); steps = [ordered]@{}; expectations = [ordered]@{}; verdict = 'RUNNING' }
function Save-Result { [IO.File]::WriteAllText($ResultFile, ($Result | ConvertTo-Json -Depth 10), (Utf8NoBom)) }
function Expect([string]$Name, [bool]$Value, [string]$Detail = '') {
  $Result.expectations[$Name] = [ordered]@{ ok = $Value; detail = $Detail }
  Note ('expect {0}: {1} {2}' -f $Name, $(if ($Value) { 'ok' } else { 'NOT OK' }), $Detail)
}

function Get-ArpVersion { try { [string](Get-ItemProperty -LiteralPath $ArpKey -ErrorAction Stop).DisplayVersion } catch { $null } }
function Get-Hex16([string]$Text) {
  $sha = [Security.Cryptography.SHA256]::Create()
  $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
  (@($h[0..7] | ForEach-Object { $_.ToString('x2') })) -join ''
}

# ----------------------------------------------------------------- a maintainer's connection
# One object per client: its own pipe connection and frame reader. A client that cannot connect
# is an error here (the probe of the first attempt went on with a null stream instead).
function New-Client([string]$PipeName) {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
  $c.Connect(5000)
  [pscustomobject]@{ Stream = $c; Buf = (New-Object byte[] 4) }
}

function Send-Op($Client, [byte]$Op) {
  $payload = [byte[]](0x4F, 0x4E, 0x43, 0x4C, 0x4D, 1, $Op)
  $header = [BitConverter]::GetBytes([uint32]$payload.Length)
  $Client.Stream.Write($header, 0, 4)
  $Client.Stream.Write($payload, 0, $payload.Length)
  $Client.Stream.Flush()
}

function Read-Exact($Client, [int]$Count, [int]$TimeoutMs) {
  $buf = New-Object byte[] $Count
  $got = 0
  $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
  while ($got -lt $Count) {
    $task = $Client.Stream.ReadAsync($buf, $got, $Count - $got)
    $left = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $task.Wait($left)) { throw "no answer within $TimeoutMs ms" }
    if ($task.Result -le 0) { throw 'the daemon closed the connection' }
    $got += $task.Result
  }
  , $buf
}

# The status byte of the reply to an operation (1 granted, 2 busy, 3 released, 4 refused) and the
# pid of a grant.
function Ask($Client, [byte]$Op, [int]$TimeoutMs = 15000) {
  Send-Op $Client $Op
  $len = [BitConverter]::ToUInt32((Read-Exact $Client 4 $TimeoutMs), 0)
  $body = Read-Exact $Client ([int]$len) $TimeoutMs
  if ($body.Length -lt 7) { throw "short reply: $($body.Length) bytes" }
  $out = [ordered]@{ status = [int]$body[6]; pid = $null }
  if ($body[6] -eq 1 -and $body.Length -ge 11) { $out.pid = [int][BitConverter]::ToUInt32($body, 7) }
  $out
}
function Name-Of([int]$Status) { switch ($Status) { 1 { 'granted' } 2 { 'busy' } 3 { 'released' } 4 { 'refused' } default { "status-$Status" } } }
function Close-Client($Client) { try { $Client.Stream.Dispose() } catch { } }

function Invoke-Child([string]$Exe, [string[]]$ChildArgs, [int]$TimeoutSeconds) {
  $o = Join-Path $Work ('child-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process -FilePath $Exe -ArgumentList $ChildArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput "$o.out" -RedirectStandardError "$o.err"
  $null = $p.Handle
  $timedOut = $false
  if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    $timedOut = $true
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $null = $p.WaitForExit(10000)
  }
  $text = (@((Get-Content -LiteralPath "$o.out" -ErrorAction SilentlyContinue), (Get-Content -LiteralPath "$o.err" -ErrorAction SilentlyContinue)) | ForEach-Object { $_ }) -join ' | '
  [ordered]@{ exit = $(if ($timedOut) { 'timeout' } else { [int]$p.ExitCode }); seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); output = $text }
}

# ----------------------------------------------------------------- environment
Note 'step 1: environment'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'the token is elevated: run it with a non-elevated token' }
$kind = $null
$model = (Get-WmiObject Win32_ComputerSystem).Model + ' ' + (Get-WmiObject Win32_ComputerSystem).Manufacturer
if ($model -match 'Virtual|VMware|KVM|QEMU|Hyper-V|Xen|Parallels|Standard PC') { $kind = 'vm' }
if (-not $kind) { Fail 'not a virtual machine: refusing to install anything here' }
if ((Get-ArpVersion) -or (Test-Path -LiteralPath (Join-Path $InstallDir 'current'))) { Fail 'OpenNCALayer is already installed on this image: revert to a clean snapshot' }

$dataDir = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'OpenNCALayer')).TrimEnd('\')
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$sid = $identity.User.Value
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$MaintPipe = 'OpenNCALayer-maintenance-' + (Get-Hex16 "$sid|$session|maintenance|$dataDir")
$probe = Invoke-Child $DaemonExe @('e2e', '--help') 60
$Result.steps.env = [ordered]@{
  whoami = (whoami); session_id = $session; data_dir = $dataDir; maintenance_pipe = $MaintPipe
  entry = [ordered]@{ file = (Split-Path -Leaf $EntryExe); sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $EntryExe).Hash.ToLowerInvariant() }
  daemon = [ordered]@{ file = (Split-Path -Leaf $DaemonExe); sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $DaemonExe).Hash.ToLowerInvariant(); is_e2e_test_build = ($probe.exit -eq 0) }
  script_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
  ps_version = $PSVersionTable.PSVersion.ToString()
}
Save-Result
if ($probe.exit -ne 0) { Fail 'the daemon is not an e2e-prompter test build' }

$StepsFile = Join-Path $Work 'steps.json'
[IO.File]::WriteAllText($StepsFile, '[]', (Utf8NoBom))
$daemon = $null
$restarted = @()
try {
  Note 'step 2: the idle test daemon'
  $saved = @{}
  foreach ($n in 'ONCL_E2E_PROMPTER', 'ONCL_UPDATE_INDEX_BASE') { $saved[$n] = [Environment]::GetEnvironmentVariable($n, 'Process') }
  try {
    [Environment]::SetEnvironmentVariable('ONCL_E2E_PROMPTER', $StepsFile, 'Process')
    [Environment]::SetEnvironmentVariable('ONCL_UPDATE_INDEX_BASE', 'https://127.0.0.1:9/oncl-8a-no-updates', 'Process')
    $daemon = Start-Process -FilePath $DaemonExe -ArgumentList @('run', '--allow-no-wss', '--no-tray') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $OutDir 'daemon.out.txt') -RedirectStandardError (Join-Path $OutDir 'daemon.err.txt')
    $null = $daemon.Handle
  } finally { foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n], 'Process') } }
  Note "daemon pid $($daemon.Id)"
  $limit = [DateTime]::UtcNow.AddSeconds(60)
  $ready = $false
  while ([DateTime]::UtcNow -lt $limit) {
    if ($daemon.HasExited) { Fail "the daemon ended with code $($daemon.ExitCode)" }
    try {
      $c = New-Client $MaintPipe
      $a = Ask $c 1
      if ($a.status -eq 1) { $null = Ask $c 2; $ready = $true }
      Close-Client $c
      if ($ready) { break }
    } catch { }
    Start-Sleep -Milliseconds 300
  }
  if (-not $ready) { Fail "the management endpoint did not answer in 60 s (pipe $MaintPipe)" }

  # ------------------------------------------------------------------ case A
  Note 'case A: two raw clients'
  $c1 = New-Client $MaintPipe
  $a1 = Ask $c1 1
  Expect 'A1_first_client_granted' ($a1.status -eq 1 -and $a1.pid -eq $daemon.Id) ("{0} by pid {1}" -f (Name-Of $a1.status), $a1.pid)
  $c2 = New-Client $MaintPipe
  $a2 = Ask $c2 1
  Expect 'A2_second_client_busy' ($a2.status -eq 2) (Name-Of $a2.status)
  $a2b = Ask $c2 1
  Expect 'A3_second_client_busy_again' ($a2b.status -eq 2) (Name-Of $a2b.status)
  $a2r = Ask $c2 2
  Expect 'A4_release_without_a_hold_is_harmless' ($a2r.status -eq 3) (Name-Of $a2r.status)
  Close-Client $c2
  Start-Sleep -Milliseconds 500
  $c3 = New-Client $MaintPipe
  $a3 = Ask $c3 1
  Expect 'A5_third_client_busy_after_second_left' ($a3.status -eq 2) (Name-Of $a3.status)
  Close-Client $c3
  $a1b = Ask $c1 1
  Expect 'A6_first_client_still_holds' ($a1b.status -eq 1) (Name-Of $a1b.status)
  $a1r = Ask $c1 2
  Expect 'A7_first_client_released' ($a1r.status -eq 3) (Name-Of $a1r.status)
  Close-Client $c1
  Start-Sleep -Milliseconds 300
  $c4 = New-Client $MaintPipe
  $a4 = Ask $c4 1
  Expect 'A8_new_client_granted_after_release' ($a4.status -eq 1) (Name-Of $a4.status)
  $null = Ask $c4 2
  Close-Client $c4
  Save-Result

  # ------------------------------------------------------------------ case B
  Note 'case B: a raw client holds, the entry asks'
  $b1 = New-Client $MaintPipe
  $ab = Ask $b1 1
  if ($ab.status -ne 1) { Fail "case B: client could not hold ($(Name-Of $ab.status))" }
  $entry = Invoke-Child $EntryExe @('--silent', '--wait', '2') 300
  Note ("entry exit {0} after {1}s: {2}" -f $entry.exit, $entry.seconds, $entry.output)
  $Result.steps.case_b = [ordered]@{ entry = $entry; arp_after = (Get-ArpVersion); install_dir_exists = (Test-Path -LiteralPath $InstallDir) }
  Expect 'B1_entry_exit_4_while_another_maintainer_holds' ($entry.exit -eq 4) ("exit " + $entry.exit)
  Expect 'B2_nothing_installed' (-not (Get-ArpVersion) -and -not (Test-Path -LiteralPath (Join-Path $InstallDir 'current'))) ''
  $ab2 = Ask $b1 1
  Expect 'B3_raw_client_still_holds_after_the_entry_gave_up' ($ab2.status -eq 1) (Name-Of $ab2.status)
  $null = Ask $b1 2
  Close-Client $b1
  Expect 'B4_daemon_alive' (-not $daemon.HasExited) ''
  Save-Result

  # ------------------------------------------------------------------ case C
  Note 'case C: the entry installs while a second client asks every 100 ms'
  Start-Sleep -Milliseconds 500
  $p = Start-Process -FilePath $EntryExe -ArgumentList @('--silent', '--wait', '60') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Work 'entryC.out') -RedirectStandardError (Join-Path $Work 'entryC.err')
  $null = $p.Handle
  $replies = New-Object 'System.Collections.Generic.List[string]'
  $errors = 0
  $firstBusy = $null
  $client = $null
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while (-not $p.HasExited -and $sw.Elapsed.TotalSeconds -lt 300) {
    try {
      if ($null -eq $client) { $client = New-Client $MaintPipe }
      $r = Ask $client 1 5000
      $name = Name-Of $r.status
      $replies.Add($name)
      if ($r.status -eq 1) { $null = Ask $client 2 5000; Close-Client $client; $client = $null }
      if ($name -eq 'busy' -and $null -eq $firstBusy) { $firstBusy = [math]::Round($sw.Elapsed.TotalSeconds, 1) }
    } catch {
      # The entry restarts the daemon at the end (its pipe goes away for a moment): a refused or
      # closed connection is counted, and the next round connects again.
      $errors++
      $replies.Add('error:' + $_.Exception.Message)
      Close-Client $client; $client = $null
    }
    Start-Sleep -Milliseconds 100
  }
  Close-Client $client
  $null = $p.WaitForExit(10000)
  $exitC = if ($p.HasExited) { [int]$p.ExitCode } else { 'running' }
  $summary = $replies | Group-Object | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
  Note ("entry C exit {0}; replies: {1}" -f $exitC, ($summary -join '; '))
  $Result.steps.case_c = [ordered]@{
    entry_exit = $exitC; entry_output = ((@((Get-Content -LiteralPath (Join-Path $Work 'entryC.out') -ErrorAction SilentlyContinue), (Get-Content -LiteralPath (Join-Path $Work 'entryC.err') -ErrorAction SilentlyContinue)) | ForEach-Object { $_ }) -join ' | ')
    polls = $replies.Count; summary = @($summary); first_busy_after_s = $firstBusy; errors = $errors
    arp_after = (Get-ArpVersion); seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
  }
  $busyCount = @($replies | Where-Object { $_ -eq 'busy' }).Count
  Expect 'C1_entry_exit_0' ($exitC -eq 0) ("exit $exitC")
  Expect 'C2_second_client_saw_busy_while_the_entry_held' ($busyCount -ge 1) ("busy x$busyCount of $($replies.Count) polls, first after $firstBusy s")
  Expect 'C3_installed_version_is_the_entrys' ((Get-ArpVersion) -eq $ExpectedVersion) ("ARP " + (Get-ArpVersion))
  Save-Result
} catch {
  Note ("ERROR: " + $_.Exception.Message)
  $Result.steps.error = [string]$_
} finally {
  # Only what this script started, by exact pid; then the installation of this run is removed.
  if ($null -ne $daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
  foreach ($proc in @(Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith(($InstallDir.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase) })) {
    Note "stopping the program started by the entry: pid $($proc.ProcessId)"
    Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
  }
  if ($UninstallAtEnd) {
    try {
      $q = [string](Get-ItemProperty -LiteralPath $ArpKey -ErrorAction Stop).QuietUninstallString
      if ($q) { Note "uninstall: $q"; Start-Process -FilePath cmd.exe -ArgumentList @('/c', $q) -WindowStyle Hidden -Wait; Start-Sleep -Seconds 5 }
    } catch { }
    $Result.steps.uninstall = [ordered]@{ arp_after = (Get-ArpVersion) }
  }
  $failed = @($Result.expectations.Keys | Where-Object { -not $Result.expectations[$_].ok })
  $Result.verdict = $(if ($Result.expectations.Count -ge 15 -and $failed.Count -eq 0 -and -not $Result.steps.Contains('error')) { 'PASS' } else { 'FAIL' })
  $Result.finished_utc = [DateTime]::UtcNow.ToString('o')
  Save-Result
  Note ("verdict: {0} ({1} expectations, failed: {2})" -f $Result.verdict, $Result.expectations.Count, ($failed -join ','))
}
if ($Result.verdict -eq 'PASS') { exit 0 } else { exit 1 }
