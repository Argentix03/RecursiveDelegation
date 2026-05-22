<#
.SYNOPSIS
    Live ETW + Sysmon tail that prints every cross-process Win32 API used by the
    recursive-delegation injection into notepad.

.DESCRIPTION
    Combines two event sources:

      * NT Kernel Logger (process, thread, virtalloc flags) for VirtualAllocEx
        and the underlying CreateRemoteThread (NtCreateThread) events.
      * Microsoft-Windows-Sysmon/Operational for ProcessCreate (EID 1),
        CreateRemoteThread (EID 8) and ProcessAccess (EID 10).

    For VirtualAllocEx the kernel logger is the source of truth: every event
    includes the caller's PID (System.Execution.ProcessID) and the *target*
    process whose address space is being modified (Data['ProcessId']).

    For CreateRemoteThread the Sysmon EID 8 stream gives the cleanest signal
    (with source/target image names and start-function info).

    For WriteProcessMemory there is no event source available to non-PPL
    callers -- Microsoft-Windows-Threat-Intelligence has TgrWriteVirtualMemory
    but it requires PPL/anti-malware-protected attach. The chain context from
    Sysmon EID 1 lets you still attribute it to the right clone PID.

    Run this in an Administrator PowerShell window. In another window, run:

        D:\Projects\RecursiveDelegation\.claude\worktrees\amazing-dhawan-6c4d26\RecursiveDelegation\x64\Debug\RecursiveDelegation.exe --inject-notepad 2

    Press Ctrl+C to stop and clean up.
#>

# ---------- Admin check ----------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Please re-run this script inside an Administrator PowerShell prompt."
    Exit
}

# ---------- Sysmon log readable? ----------
$sysmonAvailable = $true
try {
    [void](Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop)
} catch {
    Write-Warning "[-] Sysmon log not readable ($($_.Exception.Message)). Continuing with kernel-logger only."
    $sysmonAvailable = $false
}

# ---------- Start NT Kernel Logger ----------
$kSession = "NT Kernel Logger"
$kEtl     = "C:\Windows\Temp\RDKernelTrace.etl"

logman stop $kSession -ets -ErrorAction SilentlyContinue | Out-Null
Remove-Item $kEtl -ErrorAction SilentlyContinue | Out-Null

Write-Host "[+] Starting NT Kernel Logger (process, thread, virtalloc) -> $kEtl" -ForegroundColor Cyan
# 16 MB circular buffer is plenty for a few minutes of (virtalloc+thread+process) events.
$lmOut = & logman create trace $kSession -ow -o $kEtl -p "Windows Kernel Trace" "(process,thread,virtalloc)" -f bincirc -max 16 -ets 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "[-] logman failed to start NT Kernel Logger:`n$lmOut"
    Exit
}

# ---------- Cleanup on Ctrl+C ----------
trap [System.Management.Automation.PipelineStoppedException] {
    Write-Host "`n[-] Stopping NT Kernel Logger and cleaning up..." -ForegroundColor Cyan
    logman stop $kSession -ets -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 1
    Remove-Item $kEtl -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] Cleanup complete." -ForegroundColor Green
    exit
}

# ---------- Resolve target ----------
function Get-NotepadPid {
    $p = Get-Process -Name notepad -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) { return $p.Id } else { return $null }
}
$notepadPid = Get-NotepadPid
if ($notepadPid) {
    Write-Host "[+] notepad.exe found at PID $notepadPid (filter target)" -ForegroundColor Green
} else {
    Write-Host "[!] notepad.exe not currently running -- I'll start filtering once it appears." -ForegroundColor Yellow
}

Write-Host "[+] Live watcher online. Sources:" -ForegroundColor Green
Write-Host "       [ETW]  NT Kernel Logger  VirtualAlloc + Thread.Start" -ForegroundColor DarkGray
if ($sysmonAvailable) {
    Write-Host "       [SYS]  Sysmon            EID 1 / 8 / 10"             -ForegroundColor DarkGray
}
Write-Host "[!] In another shell run:" -ForegroundColor Yellow
Write-Host "       .\RecursiveDelegation\x64\Debug\RecursiveDelegation.exe --inject-notepad 2" -ForegroundColor Yellow
Write-Host "[!] Press [Ctrl+C] to stop.`n" -ForegroundColor Yellow

# ---------- Helpers ----------
function Get-EventDataMap {
    param($evt)
    $h = @{}
    try {
        $xml = [xml]$evt.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $h[$d.Name] = [string]$d.'#text' }
        }
    } catch {}
    return $h
}

function Format-AccessRights {
    param([uint32]$mask)
    $r = @()
    if ($mask -band 0x0001)   { $r += 'TERMINATE' }
    if ($mask -band 0x0002)   { $r += 'CREATE_THREAD' }
    if ($mask -band 0x0008)   { $r += 'VM_OPERATION' }
    if ($mask -band 0x0010)   { $r += 'VM_READ' }
    if ($mask -band 0x0020)   { $r += 'VM_WRITE' }
    if ($mask -band 0x0040)   { $r += 'DUP_HANDLE' }
    if ($mask -band 0x0400)   { $r += 'QUERY_INFO' }
    if ($mask -band 0x1000)   { $r += 'QUERY_LIMITED' }
    if ($mask -band 0x100000) { $r += 'SYNCHRONIZE' }
    return ($r -join ' | ')
}

$PidCache = @{}
function Resolve-PidImage {
    param([int]$pid_)
    if ($PidCache.ContainsKey($pid_)) { return $PidCache[$pid_] }
    $p = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
    if ($p) { $PidCache[$pid_] = $p.ProcessName; return $p.ProcessName }
    return "<pid-$pid_>"
}

# ---------- Time boundaries (separate per source to avoid one stalling the other) ----------
$qSys = [DateTime]::Now
$qKrn = [DateTime]::Now

while ($true) {

    # Flush kernel-logger buffers to disk so we can read recent events.
    logman flush $kSession -ets -ErrorAction SilentlyContinue | Out-Null

    # Re-resolve notepad PID if we didn't have it yet.
    if (-not $notepadPid) {
        $notepadPid = Get-NotepadPid
        if ($notepadPid) {
            Write-Host "[+] notepad.exe appeared at PID $notepadPid" -ForegroundColor Green
        }
    }

    # ============================================================
    # Sysmon stream
    # ============================================================
    if ($sysmonAvailable) {
        $sysEvents = $null
        try {
            $sysEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-Sysmon/Operational'
                Id        = 1, 8, 10
                StartTime = $qSys
            } -Oldest -ErrorAction SilentlyContinue
        } catch {}

        foreach ($e in $sysEvents) {
            if ($e.TimeCreated -ge $qSys) { $qSys = $e.TimeCreated.AddMilliseconds(1) }
            $f = Get-EventDataMap $e

            switch ($e.Id) {
                1 {
                    $img  = $f['Image']
                    $leaf = if ($img) { Split-Path -Leaf $img } else { '<unknown>' }
                    if ($leaf -match '^(RecursiveDelegation\.exe|(svchost|wininit|csrss|lsass|winlogon|spoolsv|dwm|explorer|taskmgr|msiexec|conhost|rundll32|services|smss|ntoskrnl|regsvr32|mmc|dllhost|wuauclt|iexplore)_\d+\.exe)$') {
                        Write-Host ("[SYS-1]  ProcessCreate    PID {0} <- parent PID {1}  {2}" -f $f['ProcessId'], $f['ParentProcessId'], $leaf) -ForegroundColor Magenta
                        if ($f['CommandLine']) { Write-Host ("         cmdline: " + $f['CommandLine']) -ForegroundColor DarkGray }
                    }
                }
                8 {
                    Write-Host "[SYS-8]  CreateRemoteThread!" -ForegroundColor Red
                    Write-Host ("         Source : {0} (PID {1})" -f (Split-Path -Leaf $f['SourceImage']), $f['SourceProcessId'])
                    Write-Host ("         Target : {0} (PID {1})" -f (Split-Path -Leaf $f['TargetImage']), $f['TargetProcessId'])
                    Write-Host ("         New TID: {0}"             -f $f['NewThreadId'])
                    Write-Host ("         Start  : {0}  ({1}!{2})"  -f $f['StartAddress'], $f['StartModule'], $f['StartFunction'])
                    Write-Host ("-" * 60) -ForegroundColor DarkGray
                }
                10 {
                    $maskStr = $f['GrantedAccess']
                    $mask = 0
                    try { $mask = [Convert]::ToUInt32($maskStr, 16) } catch {}
                    if (($mask -band (0x0002 -bor 0x0008 -bor 0x0010 -bor 0x0020)) -ne 0) {
                        Write-Host "[SYS-10] ProcessAccess (hot handle)" -ForegroundColor Yellow
                        Write-Host ("         Source : {0} (PID {1})" -f (Split-Path -Leaf $f['SourceImage']), $f['SourceProcessId'])
                        Write-Host ("         Target : {0} (PID {1})" -f (Split-Path -Leaf $f['TargetImage']), $f['TargetProcessId'])
                        Write-Host ("         Access : {0}  ({1})"     -f $maskStr, (Format-AccessRights $mask))
                        Write-Host ("-" * 60) -ForegroundColor DarkGray
                    }
                }
            }
        }
    }

    # ============================================================
    # NT Kernel Logger stream
    # ============================================================
    if (Test-Path $kEtl) {
        $kEvents = $null
        try {
            $kEvents = Get-WinEvent -Path $kEtl -Oldest -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -ge $qKrn }
        } catch {}

        foreach ($e in $kEvents) {
            if ($e.TimeCreated -ge $qKrn) { $qKrn = $e.TimeCreated.AddTicks(1) }

            $task = $e.TaskDisplayName
            $opc  = $e.OpcodeDisplayName

            # VirtualAlloc cross-process -> VirtualAllocEx
            if ($task -eq 'PageFault' -and $opc -eq 'VirtualAlloc') {
                # MOF event property layout (Windows 10/11):
                #   [0] BaseAddress  (UInt64)
                #   [1] RegionSize   (UInt64)
                #   [2] ProcessId    (UInt32)  -- target process
                #   [3] Flags        (UInt32)
                try {
                    $tgtPid    = [int]$e.Properties[2].Value
                    $callerPid = [int]$e.ProcessId
                    $base      = [uint64]$e.Properties[0].Value
                    $size      = [uint64]$e.Properties[1].Value
                } catch { continue }

                if (-not $notepadPid)        { continue }
                if ($tgtPid -ne $notepadPid) { continue }
                if ($callerPid -eq $tgtPid)  { continue }   # in-process, not what we want

                $callerName = Resolve-PidImage $callerPid
                Write-Host "[ETW-VA] VirtualAlloc cross-process (== VirtualAllocEx)" -ForegroundColor Cyan
                Write-Host ("         Source : {0} (PID {1})" -f $callerName, $callerPid)
                Write-Host ("         Target : notepad (PID {0})" -f $tgtPid)
                Write-Host ("         Base   : 0x{0:X16}  Size: 0x{1:X}" -f $base, $size)
                Write-Host ("-" * 60) -ForegroundColor DarkGray
            }

            # Thread/Start cross-process -> CreateRemoteThread (kernel-level)
            elseif ($task -eq 'Thread' -and $opc -eq 'Start') {
                # MOF layout for Thread/Start:
                #   [0] ProcessId   (UInt32)  -- target process owning the new thread
                #   [1] TThreadId   (UInt32)
                try {
                    $tgtPid    = [int]$e.Properties[0].Value
                    $tidNew    = [int]$e.Properties[1].Value
                    $callerPid = [int]$e.ProcessId
                } catch { continue }

                if (-not $notepadPid)        { continue }
                if ($tgtPid -ne $notepadPid) { continue }
                if ($callerPid -eq $tgtPid)  { continue }

                $callerName = Resolve-PidImage $callerPid
                Write-Host "[ETW-CT] Thread/Start cross-process (== CreateRemoteThread)" -ForegroundColor Red
                Write-Host ("         Source : {0} (PID {1})" -f $callerName, $callerPid)
                Write-Host ("         Target : notepad (PID {0})" -f $tgtPid)
                Write-Host ("         New TID: {0}" -f $tidNew)
                Write-Host ("-" * 60) -ForegroundColor DarkGray
            }
        }
    }

    Start-Sleep -Milliseconds 500
}
