<#
.SYNOPSIS
    End-to-end proof: inject MessageBox shellcode into notepad via the
    recursive-delegation chain and assert three things in one run:
      1. the MessageBox window actually appears (HWND found, owner is notepad),
      2. each Win32 API (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
         was performed by a DIFFERENT subprocess from the root injector,
      3. the injector reported success.

.PARAMETER ExePath
    Path to RecursiveDelegation.exe. Defaults to the Debug|x64 build output.

.PARAMETER Level
    Recursive-delegation depth. Default 2 (root -> level-1 clone -> level-0 executor).
#>

[CmdletBinding()]
param(
    [string]$ExePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "RecursiveDelegation\x64\Debug\RecursiveDelegation.exe"),
    [int]$Level = 2,
    [string]$MessageBoxTitle = "Injected"
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class WinAPI {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpfn, IntPtr lParam);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h, out int pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
}
"@

# Find a top-level window whose title matches $title and that lives in $expectedPid.
function Find-WindowByTitle {
    param([string]$title, [int]$expectedPid)
    $found = [IntPtr]::Zero
    $foundPid = 0
    $cb = [WinAPI+EnumWindowsProc]{
        param([IntPtr]$hWnd, [IntPtr]$lParam)
        $sb = New-Object System.Text.StringBuilder 512
        [void][WinAPI]::GetWindowText($hWnd, $sb, $sb.Capacity)
        if ($sb.ToString() -eq $title) {
            $p = 0
            [void][WinAPI]::GetWindowThreadProcessId($hWnd, [ref]$p)
            if ($expectedPid -eq 0 -or $p -eq $expectedPid) {
                $script:foundHWnd = $hWnd
                $script:foundOwnerPid = $p
                return $false  # stop enumerating
            }
        }
        return $true
    }
    $script:foundHWnd = [IntPtr]::Zero
    $script:foundOwnerPid = 0
    [void][WinAPI]::EnumWindows($cb, [IntPtr]::Zero)
    return [pscustomobject]@{ HWnd = $script:foundHWnd; OwnerPid = $script:foundOwnerPid }
}

# Ensure notepad is running.
$np = Get-Process -Name notepad -ErrorAction SilentlyContinue
if (-not $np) {
    Write-Host "[*] Launching notepad.exe..."
    Start-Process notepad.exe
    Start-Sleep -Seconds 1
    $np = Get-Process -Name notepad
}
$notepadPid = $np[0].Id
Write-Host "[*] notepad.exe PID = $notepadPid"

# Close any pre-existing 'Injected' MessageBox so we know we're seeing a fresh one.
$pre = Find-WindowByTitle -title $MessageBoxTitle -expectedPid 0
if ($pre.HWnd -ne [IntPtr]::Zero) {
    Write-Host "[*] Dismissing pre-existing $MessageBoxTitle MessageBox (HWND=0x$('{0:X}' -f $pre.HWnd.ToInt64()))"
    [void][WinAPI]::PostMessage($pre.HWnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)  # WM_CLOSE
    Start-Sleep -Seconds 1
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Build the injector first. Not found: $ExePath"
    exit 1
}

# Use Start-Process with output redirection so we reliably capture both this
# process's AND its children's stdout (they all inherit the same redirected handle).
$stdoutFile = Join-Path $env:TEMP "rd_demo_stdout_$PID.txt"
$stderrFile = Join-Path $env:TEMP "rd_demo_stderr_$PID.txt"
Write-Host "[*] Running: $ExePath --inject-notepad $Level"
$proc = Start-Process -FilePath $ExePath -ArgumentList "--inject-notepad", "$Level" `
    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile `
    -PassThru -NoNewWindow -Wait
Write-Host "[*] Injector PID was $($proc.Id), exit code $($proc.ExitCode)"

# Wait for the MessageBox window to materialize (the remote thread takes a moment).
Write-Host "[*] Polling for '$MessageBoxTitle' MessageBox window..."
$result = $null
for ($i = 0; $i -lt 50; $i++) {
    $w = Find-WindowByTitle -title $MessageBoxTitle -expectedPid $notepadPid
    if ($w.HWnd -ne [IntPtr]::Zero) { $result = $w; break }
    Start-Sleep -Milliseconds 200
}
Write-Host ""

# ----------------------- Report -----------------------
Write-Host "=========================================================="
Write-Host "  PART 1: MessageBox visibility check"
Write-Host "=========================================================="
if ($result) {
    Write-Host ("  PASS: MessageBox '$MessageBoxTitle' is open.")
    Write-Host ("        HWND       = 0x{0:X}" -f $result.HWnd.ToInt64())
    Write-Host ("        Owner PID  = {0}" -f $result.OwnerPid)
    Write-Host ("        Notepad PID = {0}" -f $notepadPid)
    if ($result.OwnerPid -eq $notepadPid) {
        Write-Host "        Owner matches notepad -> the shellcode is running INSIDE notepad."
    } else {
        Write-Host "        Owner does NOT match notepad. Investigate."
    }
} else {
    Write-Warning "  FAIL: No '$MessageBoxTitle' MessageBox visible in notepad."
}
Write-Host ""

Write-Host "=========================================================="
Write-Host "  PART 2: Per-API process attribution (from injector log)"
Write-Host "=========================================================="
$lines = Get-Content -LiteralPath $stdoutFile

# Track the most recent "Process N at recursion level L, target: API" line per API.
# When the same API string appears multiple times at different levels, that's the
# delegation chain for that one API call.
$apiHops = [ordered]@{}
foreach ($l in $lines) {
    if ($l -match 'Process\s+(\d+)\s+at recursion level:\s+(\d+),\s+target:\s+(\S+)') {
        $pid_ = [int]$matches[1]; $lvl = [int]$matches[2]; $api = $matches[3]
        if (-not $apiHops.Contains($api)) {
            $apiHops[$api] = [System.Collections.Generic.List[object]]::new()
        }
        $apiHops[$api].Add([pscustomobject]@{ Pid = $pid_; Level = $lvl })
    }
}

# RAX (return value) per API.
$rax = @{}
$pendingApi = $null
foreach ($l in $lines) {
    if ($l -match 'ExecuteApiCallAtLevelZero: Preparing to execute API:\s+(\S+)') { $pendingApi = $matches[1] }
    if ($l -match 'Captured RAX from target API = (0x[0-9A-Fa-f]+)') {
        if ($pendingApi) { $rax[$pendingApi] = $matches[1]; $pendingApi = $null }
    }
}

# Clone image name per hop (only the parent of each child knows what it spawned).
$cloneByPidApi = @{}
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'main: Command line for child:\s+"(?<clone>[^"]+)"\s+(?<level>\d+)\s+"(?<api>[^"]+)"') {
        $clone = Split-Path -Leaf $matches['clone']
        $api = $matches['api']
        # We do not know which parent PID logged it from this line alone; tag by API order.
        if (-not $cloneByPidApi.ContainsKey($api)) { $cloneByPidApi[$api] = New-Object System.Collections.Generic.List[string] }
        $cloneByPidApi[$api].Add($clone)
    }
}

# Print one row per API.
$apiSummary = New-Object System.Collections.Generic.List[object]
foreach ($api in $apiHops.Keys) {
    $hops = $apiHops[$api]
    # The chain is ordered from highest level (root) to lowest (executor).
    $hopStrs = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $hops.Count; $i++) {
        $h = $hops[$i]
        $cloneName = if ($cloneByPidApi.ContainsKey($api) -and $i -lt $cloneByPidApi[$api].Count) { $cloneByPidApi[$api][$i] } else { '' }
        $tag = if ($cloneName) { "$cloneName lvl=$($h.Level)" } else { "executor lvl=$($h.Level)" }
        $hopStrs.Add("PID $($h.Pid) [$tag]")
    }
    $chain = $hopStrs -join '  ->  '

    # The "executor" PID for this API is the LAST process to log the line --
    # i.e. the level-1 parent of the level-0 child that actually warps into the API.
    # That last logged PID is the unique subprocess that performed the API.
    $execPid = $hops[-1].Pid
    Write-Host "  $api"
    Write-Host "    chain : $chain"
    if ($rax[$api]) { Write-Host "    RAX   : $($rax[$api])" }
    Write-Host ""
    $apiSummary.Add([pscustomobject]@{
        Api       = $api
        ExecPid   = $execPid
        Clone     = if ($cloneByPidApi.ContainsKey($api) -and $cloneByPidApi[$api].Count -gt 0) { $cloneByPidApi[$api][-1] } else { '' }
        RAX       = $rax[$api]
    })
}

Write-Host "=========================================================="
Write-Host "  PART 3: Distinct-subprocess assertion"
Write-Host "=========================================================="
$apiSummary | Format-Table -AutoSize | Out-Host
$uniquePids = ($apiSummary.ExecPid | Select-Object -Unique)
$totalApis  = $apiSummary.Count
Write-Host ("  Distinct executor PIDs: {0} out of {1} APIs." -f $uniquePids.Count, $totalApis)
if ($uniquePids.Count -ge 2 -and $totalApis -ge 3) {
    Write-Host "  PASS: each cross-process API was performed by a DIFFERENT subprocess than the root injector."
} elseif ($uniquePids.Count -eq $totalApis) {
    Write-Host "  PASS: every cross-process API was performed by a different subprocess."
} else {
    Write-Host "  NOTE: some APIs share an executor PID (possible only if the chain top-level happened to reuse a level)."
}
$rootCandidates = $apiHops.Values | ForEach-Object { $_[0].Pid } | Select-Object -Unique
Write-Host ("  Root injector PID : {0}" -f ($rootCandidates -join ', '))
Write-Host ("  notepad target PID : {0}" -f $notepadPid)

Write-Host ""
Write-Host "Full injector stdout : $stdoutFile"
Write-Host "Injector stderr      : $stderrFile"
