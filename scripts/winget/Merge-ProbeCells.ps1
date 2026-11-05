<#
.SYNOPSIS
  Merges the cell reports of the WinGet proof matrix (one JSON file per cell, written by
  Invoke-WingetProbe.ps1 inside the machines) into the probe set that
  `cargo xtask winget generate --probe` reads.

.DESCRIPTION
  The set is always marked "vm-run": the generator refuses a set marked as a synthetic fixture
  unless a test asks for it, and this script cannot make one. It does not decide whether the
  cells prove anything: that is the generator's job, against the bytes it downloads itself.

.EXAMPLE
  .\Merge-ProbeCells.ps1 -Cells .\cells\*.json -OutFile .\winget\probes\0.3.0.json
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$Cells,
  [Parameter(Mandatory)][string]$OutFile
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

$files = @(Get-ChildItem -Path $Cells -File | Sort-Object FullName)
if ($files.Count -eq 0) { throw "no cell report matches $($Cells -join ', ')" }

$reports = @()
foreach ($file in $files) {
  $text = [IO.File]::ReadAllText($file.FullName)
  try { $reports += , ($text | ConvertFrom-Json) }
  catch { throw "$($file.FullName) is not JSON: $_" }
}
$set = [ordered]@{ report_format = 1; origin = 'vm-run'; reports = $reports }
$json = $set | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host ("merged $($files.Count) cell report(s) into $OutFile; next: cargo xtask winget generate --probe $OutFile --release-json <release.json>")
