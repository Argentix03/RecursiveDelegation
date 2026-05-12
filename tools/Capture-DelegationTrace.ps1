<#
.SYNOPSIS
    Runs the RecursiveDelegation.exe shellcode-into-notepad demo and reports
    which child process performed each cross-process API call.
#>

[CmdletBinding()]
param(
    [string]$ExePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "RecursiveDelegation\x64\Debug\RecursiveDelegation.exe"),
    [int]$Level = 2,
    [string]$TraceDir = (Join-Path $env:TEMP "RDTrace")
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Returns text from a node whether the XML adapter handed us a string or an XmlElement.
function Get-XText {
    param($n)
    if ($null -eq $n) { return $null }
    if ($n -is [System.Xml.XmlElement]) { return $n.InnerText }
    return [string]$n
}

# Parses a PID-shaped string. Returns $null for empty or the kernel sentinel 0xFFFFFFFF.
function Convert-Pid {
    param($s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    try {
        $u = [uint32]$s
    } catch {
        return $null
    }
    if ($u -eq [uint32]::MaxValue) { return $null }
    return [int]$u
}

if (-not (Test-Path $ExePath)) {
    Write-Error "RecursiveDelegation.exe not found at: $ExePath. Build the Debug|x64 configuration first."
    exit 1
}

$np = Get-Process -Name notepad -ErrorAction SilentlyContinue
if (-not $np) {
    Write-Host "[*] Launching notepad.exe..."
    Start-Process notepad.exe
    Start-Sleep -Seconds 1
    $np = Get-Process -Name notepad
}
$notepadPid = $np[0].Id
Write-Host "[*] notepad.exe PID = $notepadPid"

# ------------------------------------------------------------------
# Path A: elevated -> NT Kernel Logger
# ------------------------------------------------------------------
if (Test-IsAdmin) {
    New-Item -ItemType Directory -Force -Path $TraceDir | Out-Null
    $etl = Join-Path $TraceDir "rd_inject.etl"
    $xml = Join-Path $TraceDir "rd_inject.xml"
    $sess = "NT Kernel Logger"

    & logman stop $sess -ets 2>$null | Out-Null
    Write-Host "[*] Starting NT Kernel Logger -> $etl"
    # Keyword names come from: logman query providers "Windows Kernel Trace"
    $startOut = & logman create trace $sess -ow -o $etl -p "Windows Kernel Trace" "(process,thread,virtalloc)" -ets 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "logman failed to start session:`n$startOut"
        exit 1
    }

    Write-Host "[*] Running $ExePath --inject-notepad $Level"
    & $ExePath --inject-notepad $Level 2>&1 | Tee-Object -Variable demoLog | Out-Null

    Start-Sleep -Seconds 1
    Write-Host "[*] Stopping trace..."
    & logman stop $sess -ets 2>&1 | Write-Host

    if (-not (Test-Path $etl)) {
        Write-Error "ETL file not created at $etl"
        exit 1
    }
    Write-Host "[*] ETL captured: $etl  ($((Get-Item $etl).Length) bytes)"

    Write-Host "[*] Decoding ETL -> XML with tracerpt..."
    & tracerpt $etl -o $xml -of XML -y 2>&1 | Write-Host

    $forceFallback = $false
    if (-not (Test-Path $xml)) {
        Write-Error "tracerpt did not produce $xml. Falling back to stdout-parse mode."
        $stdout = $demoLog
        $forceFallback = $true
    } else {
        Write-Host "[*] Decoded XML at $xml"
    }

    if (-not $forceFallback) {

        Write-Host "[*] Loading XML (large files can take a minute)..."
        $doc = New-Object System.Xml.XmlDocument
        $doc.PreserveWhitespace = $false
        $doc.Load($xml)
        $events = $doc.Events.Event
        Write-Host "[*] $($events.Count) events loaded."

        # One pass: extract minimal records using GetAttribute / RenderingInfo.
        Write-Host "[*] Indexing events..."
        $kernelEvents = New-Object 'System.Collections.Generic.List[object]'
        foreach ($e in $events) {
            $ri = $e.RenderingInfo
            if ($null -eq $ri) { continue }
            $evName = Get-XText $ri.EventName
            $opc    = Get-XText $ri.Opcode

            # Build a Name=value map from <EventData><Data Name="..">..</Data>
            $data = @{}
            if ($e.EventData -and $e.EventData.Data) {
                foreach ($d in $e.EventData.Data) {
                    if ($d -is [System.Xml.XmlElement]) {
                        $n = $d.GetAttribute('Name')
                        if ($n) { $data[$n] = $d.InnerText.Trim() }
                    }
                }
            }

            $callerPid = $null
            if ($e.System.Execution -and $e.System.Execution.ProcessID) {
                $callerPid = Convert-Pid $e.System.Execution.ProcessID
            }

            $kernelEvents.Add([pscustomobject]@{
                Time      = $e.System.TimeCreated.SystemTime
                EventName = $evName
                Opcode    = $opc
                CallerPid = $callerPid
                Data      = $data
            })
        }
        Write-Host "[*] Indexed $($kernelEvents.Count) events."

        Write-Host ""
        Write-Host "=== Top 20 (EventName, Opcode) pairs in trace ==="
        $kernelEvents |
            Group-Object EventName, Opcode |
            Sort-Object Count -Descending |
            Select-Object -First 20 Count, Name |
            Format-Table -AutoSize | Out-Host

        # Build PID -> Image map from Process Start/DCStart events.
        $procMap = @{}
        foreach ($e in $kernelEvents) {
            if ($e.EventName -ne 'Process') { continue }
            if ($e.Opcode -ne 'Start' -and $e.Opcode -ne 'DCStart') { continue }
            $pidInt = Convert-Pid $e.Data['ProcessId']
            if ($null -eq $pidInt) { continue }
            $parentInt = Convert-Pid $e.Data['ParentId']
            if ($null -eq $parentInt) { $parentInt = 0 }
            $procMap[$pidInt] = [pscustomobject]@{
                Pid       = $pidInt
                Image     = $e.Data['ImageFileName']
                ParentPid = $parentInt
                CmdLine   = $e.Data['CommandLine']
            }
        }
        Write-Host "[*] Built PID->Image map for $($procMap.Count) processes."

        # Quick schema dump: show a couple of sample VirtualAlloc events so we
        # know which Data field carries the target PID for THIS Windows build.
        Write-Host ""
        Write-Host "=== Sample VirtualAlloc event schema (first 2) ==="
        $vaSamples = $kernelEvents | Where-Object {
            $_.EventName -eq 'PageFault' -and $_.Opcode -eq 'VirtualAlloc'
        } | Select-Object -First 2
        foreach ($s in $vaSamples) {
            "EventName={0}  Opcode={1}  Caller={2}" -f $s.EventName, $s.Opcode, $s.CallerPid | Write-Host
            foreach ($k in $s.Data.Keys) { "    {0} = {1}" -f $k, $s.Data[$k] | Write-Host }
        }

        # On all modern Windows builds the NT Kernel Logger's per-alloc event is
        # EventName=PageFault, Opcode=VirtualAlloc. The event includes the
        # *target* PID in Data['ProcessId']; the *caller* is in
        # System.Execution.ProcessID (our CallerPid).
        Write-Host ""
        Write-Host "=== Cross-process VirtualAlloc events targeting notepad (PID $notepadPid) ==="
        $vaHits = 0
        foreach ($e in $kernelEvents) {
            if ($e.EventName -ne 'PageFault') { continue }
            if ($e.Opcode -ne 'VirtualAlloc') { continue }
            $tgt = Convert-Pid $e.Data['ProcessId']
            if ($null -eq $tgt) { continue }
            if ($tgt -ne $notepadPid) { continue }
            if ($null -eq $e.CallerPid -or $e.CallerPid -eq $notepadPid) { continue }
            $name = if ($procMap.ContainsKey($e.CallerPid)) { $procMap[$e.CallerPid].Image } else { '?' }
            "{0}  caller PID {1} ({2}) -> VirtualAlloc in notepad PID {3}  base={4} size={5}" -f `
                $e.Time, $e.CallerPid, $name, $tgt, $e.Data['BaseAddress'], $e.Data['RegionSize'] | Write-Host
            $vaHits++
        }
        if ($vaHits -eq 0) { Write-Host "  (none observed — see sample schema above for actual field names)" }

        # Thread Start events: filter to Opcode=Start only (DCStart events are
        # for pre-trace threads). Caller PID is System.Execution.ProcessID;
        # the new thread's owning process is in Data['ProcessId'].
        Write-Host ""
        Write-Host "=== Sample Thread Start event schema (first 2) ==="
        $thSamples = $kernelEvents | Where-Object {
            $_.EventName -eq 'Thread' -and $_.Opcode -eq 'Start'
        } | Select-Object -First 2
        foreach ($s in $thSamples) {
            "EventName={0}  Opcode={1}  Caller={2}" -f $s.EventName, $s.Opcode, $s.CallerPid | Write-Host
            foreach ($k in $s.Data.Keys) { "    {0} = {1}" -f $k, $s.Data[$k] | Write-Host }
        }

        Write-Host ""
        Write-Host "=== Remote threads created into notepad (PID $notepadPid) ==="
        $thHits = 0
        foreach ($e in $kernelEvents) {
            if ($e.EventName -ne 'Thread') { continue }
            if ($e.Opcode -ne 'Start') { continue }
            $tgt = Convert-Pid $e.Data['ProcessId']
            if ($null -eq $tgt) { continue }
            if ($tgt -ne $notepadPid) { continue }
            if ($null -eq $e.CallerPid -or $e.CallerPid -eq $notepadPid) { continue }
            $name = if ($procMap.ContainsKey($e.CallerPid)) { $procMap[$e.CallerPid].Image } else { '?' }
            "{0}  caller PID {1} ({2}) -> CreateRemoteThread in notepad PID {3}  tid={4}" -f `
                $e.Time, $e.CallerPid, $name, $tgt, $e.Data['TThreadId'] | Write-Host
            $thHits++
        }
        if ($thHits -eq 0) { Write-Host "  (none observed — see sample schema above for actual field names)" }

        Write-Host ""
        Write-Host "ETL: $etl"
        Write-Host "XML: $xml"
        exit 0
    }
}

# ------------------------------------------------------------------
# Path B: not elevated, or admin path failed to produce XML.
# ------------------------------------------------------------------
if (-not $demoLog) {
    Write-Host "[*] Not elevated. Running demo and parsing stdout for the chain."
    Write-Host "[*] (For real ETW traces, re-run this script from an admin PowerShell.)"
    Write-Host ""
    $stdout = & $ExePath --inject-notepad $Level 2>&1
} else {
    $stdout = $demoLog
}

$lines = $stdout -split "`r?`n"

$chains = New-Object System.Collections.Generic.List[object]
$current = $null
foreach ($l in $lines) {
    if ($l -match 'Process\s+(\d+)\s+at recursion level:\s+(\d+),\s+target:\s+(\S+)') {
        $pid_   = [int]$matches[1]
        $level_ = [int]$matches[2]
        $tgt_   = $matches[3]
        if ($null -eq $current -or $current.Target -ne $tgt_ -or $level_ -eq $current.RootLevel) {
            if ($current) { $chains.Add($current) }
            $current = [pscustomobject]@{
                Target    = $tgt_
                RootLevel = $level_
                Hops      = New-Object System.Collections.Generic.List[object]
                Result    = $null
            }
        }
        $current.Hops.Add([pscustomobject]@{ Pid = $pid_; Level = $level_ })
    }
    elseif ($l -match 'main: Command line for child:\s+"(?<clone>[^"]+)"\s+(?<level>\d+)\s+"(?<api>[^"]+)"') {
        if ($current -and $current.Target -eq $matches['api']) {
            $cloneBaseName = Split-Path -Leaf $matches['clone']
            $current.Hops[$current.Hops.Count - 1] | Add-Member -NotePropertyName CloneSpawned -NotePropertyValue $cloneBaseName -Force
        }
    }
    elseif ($l -match 'Captured RAX from target API = (0x[0-9A-Fa-f]+)') {
        if ($current) { $current.Result = $matches[1] }
    }
}
if ($current) { $chains.Add($current) }

$byApi = @{}
foreach ($c in $chains) {
    if (-not $byApi.ContainsKey($c.Target)) { $byApi[$c.Target] = $c }
}

Write-Host "=== Delegation chains observed (one per cross-process API) ==="
foreach ($key in @('Kernel32!VirtualAllocEx', 'Kernel32!WriteProcessMemory', 'Kernel32!CreateRemoteThread')) {
    $c = $byApi[$key]
    if (-not $c) { Write-Host ("  {0}: <not observed>" -f $key); continue }
    $chainStr = ($c.Hops | ForEach-Object {
        if ($_.CloneSpawned) { "PID $($_.Pid) [$($_.CloneSpawned) lvl=$($_.Level)]" }
        else                  { "PID $($_.Pid) [executor lvl=$($_.Level)]" }
    }) -join '  ->  '
    Write-Host ("  {0}" -f $key)
    Write-Host ("    {0}" -f $chainStr)
    if ($c.Result) { Write-Host ("    RAX (return value) = {0}" -f $c.Result) }
    Write-Host ""
}

Write-Host "=== Summary ==="
$rootPids = $byApi.Values | ForEach-Object { $_.Hops[0].Pid } | Select-Object -Unique
$leafPids = $byApi.Values | ForEach-Object { $_.Hops[-1].Pid } | Select-Object -Unique
Write-Host "Root injector PID(s)  : $($rootPids -join ', ')"
Write-Host "Executor PIDs (final) : $($leafPids -join ', ')"
Write-Host "notepad target PID    : $notepadPid"
Write-Host "Each Win32 API touching notepad was executed in a SEPARATE process from the root injector."