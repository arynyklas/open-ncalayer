<#
.SYNOPSIS
  Merges the cell reports of the WinGet proof matrix (one JSON per cell, written by
  Invoke-WingetProbe.ps1 inside the machines) and the final-manifest cells (written by
  Invoke-WingetFinalProbe.ps1) into the probe set that `cargo xtask winget generate --probe` reads.

.DESCRIPTION
  The set is an OPERATOR ATTESTATION: -AttestedBy and -RunId say who vouches for the run. The
  generator checks the cells against the published bytes and against each other; it cannot see
  the machines. If ANY cell says "synthetic": true the whole set is marked "synthetic-fixture",
  and the generator refuses it for a final manifest: this script cannot turn synthetic cells
  into a real run.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$Cells,
  [Parameter(Mandatory)][string[]]$FinalCells,
  [Parameter(Mandatory)][string]$AttestedBy,
  [Parameter(Mandatory)][string]$RunId,
  [Parameter(Mandatory)][string]$OutFile
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

function Read-Json($patterns) {
  $files = @(Get-ChildItem -Path $patterns -File | Sort-Object FullName)
  if ($files.Count -eq 0) { throw "no file matches $($patterns -join ', ')" }
  $items = @()
  foreach ($file in $files) {
    $text = [IO.File]::ReadAllText($file.FullName)
    try { $items += , ($text | ConvertFrom-Json) }
    catch { throw "$($file.FullName) is not JSON: $_" }
  }
  , $items
}

$reports = Read-Json $Cells
$final = Read-Json $FinalCells
$synthetic = @($reports | Where-Object { $_.synthetic -eq $true }).Count -gt 0
$origin = if ($synthetic) { 'synthetic-fixture' } else { 'vm-run' }
$set = [ordered]@{
  report_format = 1
  origin = $origin
  attestation = [ordered]@{ attested_by = $AttestedBy; run_id = $RunId }
  reports = $reports
  final_cells = $final
}
$json = $set | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host ("merged $($reports.Count) cell(s) and $($final.Count) final-manifest cell(s) into $OutFile as $origin; next: cargo xtask winget generate --probe $OutFile --release-json <release.json>")
