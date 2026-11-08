<#
Reads the program's secret fields with UI Automation, as an accessibility client would, and fails
when the throwaway secret typed into them is in any property it can read while the field is masked.

  scripts/uia-secret-probe.ps1 -Exe <path to uia_secret_probe.exe>

Build the probe: `cargo build -p oncl-ui --example uia_secret_probe`. Run it in an active
interactive desktop session (UIA does not see a disconnected one). For every window of the
probe: every string property of every element (Current.*), the Value pattern, the Text pattern's
document text, and MSAA (`IAccessible` accName/accValue/accDescription/accHelp: what the UIA
bridge gives the legacy clients). The 'Show password' check boxes of the dialogs are switched
on and off: the text is exposed while one is on (the user's own choice) and is not again after
it is off.

Exit code: 0 when no secret is exposed while masked, 1 otherwise.
#>
param(
    [Parameter(Mandatory)] [string] $Exe,
    [string] $Secret = 'UIA-probe-secret-4417'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -ReferencedAssemblies 'Accessibility' -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Accessibility;
public static class Msaa {
    [DllImport("oleacc.dll")]
    static extern int AccessibleObjectFromWindow(IntPtr hwnd, uint id, ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out object acc);
    [DllImport("oleacc.dll")]
    static extern int AccessibleChildren(IAccessible paccContainer, int iChildStart, int cChildren, [Out] object[] rgvarChildren, out int pcObtained);
    static Guid IID = new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
    public static string Walk(IntPtr hwnd) {
        object o;
        if (AccessibleObjectFromWindow(hwnd, 0xFFFFFFFC, ref IID, out o) != 0 || o == null) return "<no IAccessible>";
        var sb = new System.Text.StringBuilder();
        Visit((IAccessible)o, 0, sb, 0);
        return sb.ToString();
    }
    static string S(Func<string> f) { try { return f() ?? ""; } catch { return ""; } }
    static void Visit(IAccessible a, object child, System.Text.StringBuilder sb, int depth) {
        if (depth > 12) return;
        sb.AppendLine("name=" + S(() => a.get_accName(child)) + "|value=" + S(() => a.get_accValue(child)) + "|desc=" + S(() => a.get_accDescription(child)) + "|help=" + S(() => a.get_accHelp(child)));
        if (!(child is int) || (int)child != 0) return;
        int n = a.accChildCount; if (n == 0) return;
        var kids = new object[n]; int got;
        if (AccessibleChildren(a, 0, n, kids, out got) != 0) return;
        for (int i = 0; i < got; i++) {
            var k = kids[i];
            if (k is int) Visit(a, k, sb, depth + 1);
            else if (k is IAccessible) Visit((IAccessible)k, 0, sb, depth + 1);
        }
    }
}
'@

$root = [Windows.Automation.AutomationElement]::RootElement
$all = [Windows.Automation.Condition]::TrueCondition
$script:problems = 0
$script:found = $false

function Windows-Of($proc) {
    foreach ($w in $root.FindAll('Children', $all)) { if ($w.Current.ProcessId -eq $proc.Id) { $w } }
}

# Everything an accessibility client can read from an element, as lines of text.
function Read-Element($e) {
    $lines = @()
    foreach ($p in $e.Current.PsObject.Properties) {
        if ($p.Value -is [string] -and $p.Value) { $lines += "Current.$($p.Name)=$($p.Value)" }
    }
    $o = $null
    if ($e.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern, [ref]$o)) { $lines += "ValuePattern.Value=$($o.Current.Value)" }
    $o = $null
    if ($e.TryGetCurrentPattern([Windows.Automation.TextPattern]::Pattern, [ref]$o)) { $lines += "TextPattern.DocumentRange=$($o.DocumentRange.GetText(-1))" }
    $lines
}

# Reads every window of the process; sets $script:found when the secret is anywhere in it.
function Probe($proc, $phase, $expectSecret) {
    $script:found = $false
    $edits = 0
    foreach ($w in (Windows-Of $proc)) {
        $title = $w.Current.Name
        $hwnd = [IntPtr]$w.Current.NativeWindowHandle
        foreach ($e in (@($w) + @($w.FindAll('Descendants', $all)))) {
            $c = $e.Current
            $lines = Read-Element $e
            $hit = @($lines | Where-Object { $_ -like "*$Secret*" })
            if ($c.ControlType.ProgrammaticName -eq 'ControlType.Edit') {
                $edits++
                $value = ($lines | Where-Object { $_ -like 'ValuePattern.Value=*' }) -join ''
                Write-Host "  [$phase] '$title' Edit name='$($c.Name)' isPassword=$($c.IsPassword) $value exposing-lines=$($hit.Count)"
            }
            if ($hit.Count) { $script:found = $true; $hit | ForEach-Object { Write-Host "    exposes: $($c.ControlType.ProgrammaticName) '$($c.Name)': $_" } }
        }
        if ($hwnd -ne [IntPtr]::Zero) {
            $msaa = [Msaa]::Walk($hwnd)
            $hit = @($msaa -split "`n" | Where-Object { $_ -like "*$Secret*" })
            if ($hit.Count) { $script:found = $true; $hit | ForEach-Object { Write-Host "    MSAA exposes: $_" } }
            Write-Host "  [$phase] '$title' MSAA rows=$(@($msaa -split "`n").Count - 1) exposing-rows=$($hit.Count)"
        }
    }
    if ($edits -eq 0) { Write-Host "  [$phase] NO Edit ELEMENT FOUND"; $script:problems++ }
    if ($script:found -and -not $expectSecret) { $script:problems++; Write-Host "  [$phase] LEAK: the secret is exposed" }
    if (-not $script:found -and $expectSecret) { $script:problems++; Write-Host "  [$phase] UNEXPECTED: 'Show password' is on and the text is not exposed" }
}

foreach ($mode in 'dialogs', 'workspace-sign', 'workspace-inspect', 'workspace-plugins') {
    Write-Host "== $mode"
    $proc = Start-Process $Exe -ArgumentList $mode -PassThru
    Start-Sleep 5
    Probe $proc 'masked' $false
    if ($mode -eq 'dialogs') {
        $toggles = @()
        foreach ($w in (Windows-Of $proc)) {
            foreach ($e in $w.FindAll('Descendants', $all)) {
                if ($e.Current.ControlType.ProgrammaticName -eq 'ControlType.CheckBox' -and $e.Current.Name -like 'Show password*') { $toggles += $e }
            }
        }
        Write-Host "  'Show password' check boxes: $($toggles.Count)"
        if ($toggles.Count -eq 0) { $script:problems++ }
        foreach ($t in $toggles) { $t.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Toggle() }
        Start-Sleep 1
        Probe $proc 'shown-by-the-user' $true
        foreach ($t in $toggles) { $t.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Toggle() }
        Start-Sleep 1
        Probe $proc 'masked-again' $false
    }
    Stop-Process $proc -Force
}
if ($script:problems) { Write-Host "FAIL: $($script:problems) problem(s)"; exit 1 }
Write-Host 'PASS: the secret is exposed nowhere while masked'
exit 0
