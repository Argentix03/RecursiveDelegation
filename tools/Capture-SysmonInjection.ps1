<#
.SYNOPSIS
    Runs the recursive-delegation shellcode-into-notepad demo and reports
    Sysmon events that prove each cross-process API came from a different
    subprocess than the root injector.

.DESCRIPTION
    Requires Sysmon to be installed and running (logs to
    Microsoft-Windows-Sysmon/Operational). Captures:

      * Sysmon EID 1  -- ProcessCreate (the whole delegation chain)
      * Sysmon EID 8  -- CreateRemoteThread (Source -> Target for each CRT)
      * Sysmon EID 10 -- ProcessAccess  (who OpenProcess'd notepad)
      * Sysmon EID 5  -- ProcessTerminate (when each clone exited)

    The script records a timestamp window around the injection so we only
    consider events from this run. No admin required for the script itself
    -- Sysmon's log is readable by users in the Event Log Readers group on
    most installations.

.PARAMETER ExePath
    Path to RecursiveDelegation.exe. Defaults to the Debug|x64 build.

.PARAMETER Level
    Recursive-delegation depth. Default 2.
#>

[CmdletBinding()]
param(
    [string]$ExePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "RecursiveDelegation\x64\Debug\RecursiveDelegation.exe"),
    [int]$Level = 2
)

$ErrorActionPreference = 'Stop'

# Sysmon channel check via probe read. Reading this log requires elevation
# (or membership in 'Event Log Readers') even if Sysmon itself is running.
try {
    [void](Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop)
} catch {
    Write-Error @"
Cannot read the Sysmon log: $($_.Exception.Message)

The Microsoft-Windows-Sysmon/Operational channel is admin-restricted on most
installations. Re-run this script from an elevated PowerShell:

    Start-Process powershell -Verb RunAs

Then in the new window:

    cd $($PWD.Path)
    .\tools\Capture-SysmonInjection.ps1 -Level $Level
"@
    exit 1
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Injector not built. Missing: $ExePath"
    exit 1
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

# Mark the time window. Sysmon timestamps are in local time; clock-skew of a few
# seconds is fine because we add buffer.
$startMark = (Get-Date).AddSeconds(-2)
Write-Host "[*] Window starts at $startMark"

Write-Host "[*] Running: $ExePath --inject-notepad $Level"
$proc = Start-Process -FilePath $ExePath -ArgumentList "--inject-notepad", "$Level" `
    -PassThru -NoNewWindow -Wait
$rootInjectorPid = $proc.Id
Write-Host "[*] Injector PID was $rootInjectorPid, exit code $($proc.ExitCode)"
Start-Sleep -Seconds 2
$endMark = (Get-Date).AddSeconds(2)

# ------------------------------------------------------------
# Pull Sysmon events from the window.
# ------------------------------------------------------------
Write-Host "[*] Querying Sysmon log for events in window..."
$events = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $startMark
    EndTime   = $endMark
} -ErrorAction Stop)

Write-Host "[*] Got $($events.Count) Sysmon events in window."

# Convert each event's XML into a hashtable of the EventData fields.
function ConvertTo-SysmonHash {
    param($evt)
    $h = @{ Id = $evt.Id; Time = $evt.TimeCreated }
    $xml = [xml]$evt.ToXml()
    foreach ($d in $xml.Event.EventData.Data) {
        $h[$d.Name] = [string]$d.'#text'
    }
    return [pscustomobject]$h
}

$records = $events | ForEach-Object { ConvertTo-SysmonHash $_ }

# ------------------------------------------------------------
# EID 1: ProcessCreate -- delegation chain
# ------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================="
Write-Host "  Sysmon EID 1 (ProcessCreate) -- delegation chain"
Write-Host "=========================================================="
$creates = $records | Where-Object { $_.Id -eq 1 } |
    Where-Object {
        $_.ParentProcessId -eq "$rootInjectorPid" -or
        $_.ProcessId -eq "$rootInjectorPid" -or
        $_.Image -match 'RecursiveDelegation\.exe$' -or
        $_.Image -match '\\(svchost|wininit|csrss|lsass|winlogon|spoolsv|dwm|explorer|taskmgr|msiexec|conhost|rundll32|services|smss|ntoskrnl|regsvr32|mmc|dllhost|wuauclt|iexplore)_\d+\.exe$'
    } | Sort-Object Time
if (-not $creates) {
    Write-Host "  (no relevant ProcessCreate events found)"
} else {
    foreach ($c in $creates) {
        "[{0:HH:mm:ss.fff}] PID {1,-6} <- parent PID {2,-6}  {3}" -f `
            $c.Time, $c.ProcessId, $c.ParentProcessId, (Split-Path -Leaf $c.Image) | Write-Host
        "                          cmdline: $($c.CommandLine)" | Write-Host
    }
}

# ------------------------------------------------------------
# EID 10: ProcessAccess against notepad
# ------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================="
Write-Host "  Sysmon EID 10 (ProcessAccess) -- handle openings of notepad"
Write-Host "=========================================================="
$accesses = $records | Where-Object {
    $_.Id -eq 10 -and $_.TargetProcessId -eq "$notepadPid"
} | Sort-Object Time
if (-not $accesses) {
    Write-Host "  (no ProcessAccess events against notepad in window)"
} else {
    foreach ($a in $accesses) {
        "[{0:HH:mm:ss.fff}] src PID {1,-6} ({2}) -> notepad PID {3}  access=0x{4}" -f `
            $a.Time, $a.SourceProcessId, (Split-Path -Leaf $a.SourceImage), $a.TargetProcessId, $a.GrantedAccess | Write-Host
    }
}

# ------------------------------------------------------------
# EID 8: CreateRemoteThread targeting notepad
# ------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================="
Write-Host "  Sysmon EID 8 (CreateRemoteThread) -- thread injected into notepad"
Write-Host "=========================================================="
$crts = $records | Where-Object {
    $_.Id -eq 8 -and $_.TargetProcessId -eq "$notepadPid"
} | Sort-Object Time
if (-not $crts) {
    Write-Host "  (no CreateRemoteThread events targeting notepad in window)"
    Write-Host "  Note: Sysmon's default config must include EID 8 -- otherwise this section is empty."
} else {
    foreach ($t in $crts) {
        "[{0:HH:mm:ss.fff}] src PID {1,-6} ({2}) -> notepad PID {3}" -f `
            $t.Time, $t.SourceProcessId, (Split-Path -Leaf $t.SourceImage), $t.TargetProcessId | Write-Host
        "                          start addr  : $($t.StartAddress)" | Write-Host
        "                          start module: $($t.StartModule)" | Write-Host
        "                          start func  : $($t.StartFunction)" | Write-Host
    }
}

# ------------------------------------------------------------
# Cross-reference: who actually performed the 3 cross-process APIs
# ------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================="
Write-Host "  Cross-reference summary"
Write-Host "=========================================================="
$accessPids = ($accesses | ForEach-Object { [int]$_.SourceProcessId }) | Where-Object { $_ -ne $notepadPid } | Select-Object -Unique
$crtPids    = ($crts     | ForEach-Object { [int]$_.SourceProcessId }) | Where-Object { $_ -ne $notepadPid } | Select-Object -Unique

"Root injector PID                                  : $rootInjectorPid"
"notepad target PID                                 : $notepadPid"
"PIDs that opened a handle to notepad (Sysmon EID 10): $($accessPids -join ', ')"
"PIDs that CreateRemoteThread'd notepad (Sysmon EID 8): $($crtPids -join ', ')"
""

# Each clone in the chain that ran is a different PID. Show the chain count.
$cloneCount = ($creates | Where-Object {
    $_.Image -match '\\(svchost|wininit|csrss|lsass|winlogon|spoolsv|dwm|explorer|taskmgr|msiexec|conhost|rundll32|services|smss|ntoskrnl|regsvr32|mmc|dllhost|wuauclt|iexplore)_\d+\.exe$'
}).Count
"Clone subprocesses spawned during injection         : $cloneCount"

# Final verdict.
if ($crts -and ($crtPids -notcontains $rootInjectorPid)) {
    Write-Host ""
    Write-Host "VERDICT: The remote thread in notepad was created by a SUBPROCESS, not by the root injector."
}
if ($accesses -and ($accessPids -notcontains $rootInjectorPid)) {
    Write-Host "         At least one clone opened a handle to notepad on its own."
}
if ($accesses -and ($accessPids -contains $rootInjectorPid)) {
    Write-Host "         The root injector also opened a handle (expected -- it creates the inheritable handle"
    Write-Host "         that the clones then use)."
}
