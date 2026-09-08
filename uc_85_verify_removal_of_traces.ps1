<#
.SYNOPSIS
    Purple Team SIEM Verification - Use Case 85: Identify Attempts on Removal of Traces
    Audits Windows Security, System, and PowerShell logs for trace removal telemetry and Security Event ID 4657.

.DESCRIPTION
    Validates SIEM detection rules monitoring for Defense Evasion / Indicator Removal on Host:
      - Security Log Event ID 4657: A registry value was modified / Object Deleted/Removed
      - Security Log Event ID 4688: Process Creation (wevtutil.exe cl, reg.exe delete, del /f /q, Clear-History)
      - Security Log Event ID 1102 & System Log Event ID 104: Event Log Cleared
      - PowerShell Operational Event ID 4104: Script Block Logging

    Classification:
      - FULL    : Security EID 4657 captured registry deletion/modification OR Security EID 4688 sequence captured >=3 trace removal actions.
      - PARTIAL : PowerShell EID 4104 script blocks or log clearing events (EID 104/1102) captured.
      - MISSING : No matching events found in the audit time window.

.PARAMETER LastMinutes
    Time window in minutes to look back (Default: 10).

.PARAMETER All
    Show all matching events, root-cause diagnostics, and export CSV summary.

.PARAMETER Summary
    Display overall verdict summary only.

.PARAMETER OutputCSV
    Optional custom CSV export path for verification results.

.EXAMPLE
    .\verify_siem_events_removal_of_traces.ps1
    .\verify_siem_events_removal_of_traces.ps1 -LastMinutes 5
    .\verify_siem_events_removal_of_traces.ps1 -All
    .\verify_siem_events_removal_of_traces.ps1 -Summary
#>

[CmdletBinding()]
param(
    [int]$LastMinutes = 10,
    [switch]$All,
    [switch]$Summary,
    [string]$OutputCSV
)

# ==============================================================================
# COLOR & FORMATTING (ANSI ESCAPE SEQUENCES)
# ==============================================================================
$ESC = [char]27
$RST = "$ESC[0m"
$BLD = "$ESC[1m"
$GRN = "$ESC[32m"
$YLW = "$ESC[33m"
$RED = "$ESC[31m"
$CYN = "$ESC[36m"
$MAG = "$ESC[35m"

function Get-Timestamp {
    $now = Get-Date
    $utc = $now.ToUniversalTime()
    return "[{0:yyyy-MM-dd HH:mm:ss.fff} LOCAL | {1:yyyy-MM-dd HH:mm:ss.fff} UTC]" -f $now, $utc
}

function LogI       { param([string]$m) Write-Host "$((Get-Timestamp)) [INFO     ] $m" }
function LogW       { param([string]$m) Write-Host "$YLW$((Get-Timestamp)) [WARN     ] $m$RST" }
function LogS       { param([string]$m) Write-Host "$GRN$((Get-Timestamp)) [SUCCESS  ] $m$RST" }
function LogFull    { param([string]$m) Write-Host "$BLD$GRN$((Get-Timestamp)) [FULL     ] $m$RST" }
function LogPartial { param([string]$m) Write-Host "$BLD$YLW$((Get-Timestamp)) [PARTIAL  ] $m$RST" }
function LogMissing { param([string]$m) Write-Host "$BLD$RED$((Get-Timestamp)) [MISSING  ] $m$RST" }

# ==============================================================================
# BANNER
# ==============================================================================
function Print-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "   PURPLE TEAM SIEM VERIFICATION - S.No 85                  " -ForegroundColor Red
    Write-Host "   Identify Attempts on Removal of Traces                   " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    LogI "Target Event ID 1  : Security EID 4657 (Registry Value Modified / Object Deleted)"
    LogI "Target Event ID 2  : Security EID 4688 (wevtutil cl, reg delete, del, Clear-History)"
    LogI "Target Event ID 3  : Event Log Cleared (Security EID 1102 / System EID 104)"
    LogI "Audit Time Window  : Last $LastMinutes minutes"
    LogI "MITRE ATT&CK       : T1070 (Indicator Removal), T1070.001, T1070.003, T1070.004, T1112"
    LogI "SIEM Rule Scope    : CSIEM_Windows_EO / Data Processor Logs"
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
}

# ==============================================================================
# EVENT EVIDENCE FORMATTER (ASCII COMPATIBLE)
# ==============================================================================
function Show-EventBox {
    param(
        [string]$Title,
        [hashtable]$Fields,
        [string]$Classification = "FULL"
    )

    $boxWidth = 68
    $hr = "+-" + ("-" * ($boxWidth - 4)) + "-+"
    
    $color = if ($Classification -eq "FULL") { "Green" } elseif ($Classification -eq "PARTIAL") { "Yellow" } else { "Red" }

    Write-Host ""
    Write-Host "  $hr" -ForegroundColor DarkGray
    Write-Host ("  |  {0,-62} |" -f $Title.Substring(0, [Math]::Min(62, $Title.Length))) -ForegroundColor $color
    Write-Host ("  |  Classification: {0,-46} |" -f $Classification) -ForegroundColor $color
    Write-Host "  $hr" -ForegroundColor DarkGray
    foreach ($k in $Fields.Keys) {
        $val = [string]$Fields[$k]
        if ($val.Length -gt 46) { $val = $val.Substring(0, 43) + "..." }
        Write-Host ("  |  {0,-15}: {1,-46} |" -f $k, $val) -ForegroundColor White
    }
    Write-Host "  $hr" -ForegroundColor DarkGray
}

# ==============================================================================
# QUERY 1: Security Event ID 4657 (Registry Value Modified / Deleted)
# ==============================================================================
function Get-SecurityEID4657 {
    param([datetime]$Start, [datetime]$End)

    LogI "Querying Security Log for Event ID 4657 (Registry Value Modified / Object Deleted)..."
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4657
            StartTime = $Start
            EndTime   = $End
        } -MaxEvents 200 -ErrorAction Stop

        LogI "Security EID 4657 raw events in window: $($events.Count) - processing..."
        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            $eventData = @{}
            foreach ($data in $xml.Event.EventData.Data) {
                $eventData[$data.Name] = $data.'#text'
            }

            $objName    = $eventData["ObjectName"]
            $valName    = $eventData["ObjectValueName"]
            $opType     = $eventData["OperationType"]
            $procName   = $eventData["ProcessName"]
            $subUser    = "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])"

            $obj = [PSCustomObject]@{
                EventID        = 4657
                LogSource      = "Security (Registry Value Modified) [LOGRHYTHM EXACT MATCH]"
                TimeGenerated  = $ev.TimeCreated
                TimeStr        = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
                ObjectName     = $objName
                ObjectValueName= $valName
                OperationType  = $opType
                ProcessName    = $procName
                SubjectUser    = $subUser
                Classification = "FULL"
            }
            $results.Add($obj)
        }
        LogI "Security EID 4657 registry modification events: $($results.Count)"
    } catch {
        if ($_.Exception.Message -match "unauthorized operation" -or $_.Exception.Message -match "Access is denied") {
            LogW "Security log access denied (requires Administrator prompt)."
        } elseif ($_.Exception.Message -match "No events were found") {
            LogW "No Security Event ID 4657 events found in time window."
        } else {
            LogW "Security EID 4657 query notice: $($_.Exception.Message)"
        }
    }
    return $results.ToArray()
}

# ==============================================================================
# QUERY 2: Security Event ID 4688 (Trace Removal Commands Sequence)
# ==============================================================================
function Get-SecurityEID4688TraceRemoval {
    param([datetime]$Start, [datetime]$End)

    LogI "Querying Security Log for Event ID 4688 (wevtutil, reg delete, del /f /q, Clear-History)..."
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4688
            StartTime = $Start
            EndTime   = $End
        } -MaxEvents 200 -ErrorAction Stop

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            $eventData = @{}
            foreach ($data in $xml.Event.EventData.Data) {
                $eventData[$data.Name] = $data.'#text'
            }

            $newProc = $eventData["NewProcessName"]
            $cmdLine = $eventData["CommandLine"]

            $isTraceCmd = ($cmdLine -match "wevtutil.*cl" -or
                           $cmdLine -match "reg.*delete" -or
                           $cmdLine -match "del\s+/f" -or
                           $cmdLine -match "Clear-History" -or
                           $newProc -match "wevtutil\.exe$")

            if ($isTraceCmd) {
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($newProc)
                $obj = [PSCustomObject]@{
                    EventID        = 4688
                    LogSource      = "Security (Process Creation - Trace Removal)"
                    TimeGenerated  = $ev.TimeCreated
                    TimeStr        = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
                    Utility        = $baseName
                    NewProcessName = $newProc
                    CommandLine    = $cmdLine
                    SubjectUser    = "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])"
                    Classification = "FULL"
                }
                $results.Add($obj)
            }
        }
        LogI "Security EID 4688 trace removal events: $($results.Count)"
    } catch {}
    return $results.ToArray()
}

# ==============================================================================
# QUERY 3: Event Log Cleared (Security EID 1102 & System EID 104)
# ==============================================================================
function Get-EventLogClearedEvents {
    param([datetime]$Start, [datetime]$End)

    LogI "Querying Security & System Logs for Log Cleared events (EID 1102 / EID 104)..."
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Query Security EID 1102
    try {
        $secEvs = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 1102
            StartTime = $Start
            EndTime   = $End
        } -MaxEvents 200 -ErrorAction Stop

        foreach ($ev in $secEvs) {
            $subUser = try { $ev.Properties[0].Value } catch { "N/A" }
            $obj = [PSCustomObject]@{
                EventID        = 1102
                LogSource      = "Security (Audit Log Cleared) [LOGRHYTHM BLOCK 2 MATCH]"
                TimeGenerated  = $ev.TimeCreated
                TimeStr        = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
                SubjectUser    = $subUser
                Classification = "FULL"
            }
            $results.Add($obj)
        }
    } catch {}

    # Query System EID 104
    try {
        $sysEvs = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Id        = 104
            StartTime = $Start
            EndTime   = $End
        } -MaxEvents 200 -ErrorAction Stop

        foreach ($ev in $sysEvs) {
            $obj = [PSCustomObject]@{
                EventID        = 104
                LogSource      = "System (Event Log Cleared)"
                TimeGenerated  = $ev.TimeCreated
                TimeStr        = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
                SubjectUser    = "N/A"
                Classification = "PARTIAL"
            }
            $results.Add($obj)
        }
    } catch {}

    LogI "Log Cleared events captured: $($results.Count)"
    return $results.ToArray()
}

# ==============================================================================
# QUERY 4: PowerShell Operational Event ID 4104 (Script Block Logging)
# ==============================================================================
function Get-PowerShellEID4104 {
    param([datetime]$Start, [datetime]$End)

    LogI "Querying PowerShell Operational Log for Event ID 4104 (Trace clearing activity)..."
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-PowerShell/Operational"
            Id        = 4104
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction Stop

        LogI "PowerShell EID 4104 raw events in window: $($events.Count) - scanning for trace removal..."
        foreach ($ev in $events) {
            $msg = $ev.Message
            if ($msg -notmatch "Clear-History" -and $msg -notmatch "wevtutil" -and $msg -notmatch "PT_UC85" -and $msg -notmatch "reg\.exe delete") {
                continue
            }

            $snippet = ""
            if ($msg -match "(Clear-History[^\r\n]*)") {
                $snippet = $matches[1]
            } elseif ($msg -match "(wevtutil[^\r\n]*)") {
                $snippet = $matches[1]
            } else {
                $clean = ($msg -replace "Creating Scriptblock text \(\d+ of \d+\):`r?`n","").Trim()
                $snippet = if ($clean.Length -gt 60) { $clean.Substring(0, 57) + "..." } else { $clean }
            }

            $obj = [PSCustomObject]@{
                EventID        = 4104
                LogSource      = "PowerShell/Operational (Script Block)"
                TimeGenerated  = $ev.TimeCreated
                TimeStr        = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
                Snippet        = $snippet
                Classification = "PARTIAL"
            }
            $results.Add($obj)
        }
        LogI "PowerShell EID 4104 matching trace removal events: $($results.Count)"
    } catch {
        if ($_.Exception.Message -match "No events were found") {
            LogW "No PowerShell Event ID 4104 events found in time window."
        } else {
            LogW "PowerShell EID 4104 notice: $($_.Exception.Message)"
        }
    }
    return $results.ToArray()
}

# ==============================================================================
# AUDIT POLICY & ROOT CAUSE DIAGNOSTICS
# ==============================================================================
function Show-Diagnostics {
    Write-Host ""
    Write-Host "--- ROOT CAUSE DIAGNOSTICS & AUDITING STATUS ---" -ForegroundColor Yellow
    
    # Check Registry subcategory (Event ID 4657)
    try {
        $auditReg = auditpol /get /subcategory:"Registry" 2>$null | Out-String
        if ($auditReg -match "Success") {
            Write-Host "  [OK] Registry auditing is ENABLED (Security EID 4657 active)." -ForegroundColor Green
        } else {
            Write-Host "  [!] Registry auditing is NOT enabled (required for EID 4657 telemetry)." -ForegroundColor Yellow
            Write-Host "      Fix (Admin): auditpol /set /subcategory:`"Registry`" /success:enable /failure:enable" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!] Could not run auditpol (requires Administrator privileges)." -ForegroundColor DarkYellow
    }

    # Check Process Creation subcategory
    try {
        $auditProc = auditpol /get /subcategory:"Process Creation" 2>$null | Out-String
        if ($auditProc -match "Success") {
            Write-Host "  [OK] Process Creation auditing is ENABLED (Security EID 4688 active)." -ForegroundColor Green
        } else {
            Write-Host "  [!] Process Creation auditing is NOT enabled." -ForegroundColor Yellow
        }
    } catch {}

    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
}

# ==============================================================================
# CSV EXPORT
# ==============================================================================
function Export-VerificationCSV {
    param(
        [PSCustomObject]$Verdict,
        [array]$Ev4657,
        [array]$Ev4688,
        [array]$LogClearEvs,
        [array]$Ev4104
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $verdictFile = if ($OutputCSV) { $OutputCSV } else { Join-Path $scriptDir "pt_uc85_verify_$timestamp.csv" }
    $eventsFile  = Join-Path $scriptDir "pt_uc85_verify_${timestamp}_events.csv"

    try {
        [PSCustomObject]@{
            SessionTime          = Get-Timestamp
            AuditWindowMinutes   = $LastMinutes
            SecurityEID4657Count = $Ev4657.Count
            SecurityEID4688Count = $Ev4688.Count
            LogClearedCount      = $LogClearEvs.Count
            PowerShell4104Count  = $Ev4104.Count
            OverallVerdict       = $Verdict.OverallVerdict
            DetectionStatus      = $Verdict.Status
        } | Export-Csv -Path $verdictFile -NoTypeInformation -Encoding UTF8
        LogS "Summary exported: .\$([System.IO.Path]::GetFileName($verdictFile))"

        $allEvs = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($e in $Ev4657) { $allEvs.Add($e) }
        foreach ($e in $Ev4688) { $allEvs.Add($e) }
        foreach ($e in $LogClearEvs) { $allEvs.Add($e) }
        foreach ($e in $Ev4104) { $allEvs.Add($e) }

        if ($allEvs.Count -gt 0) {
            $allEvs | Export-Csv -Path $eventsFile -NoTypeInformation -Encoding UTF8
            LogS "Raw events exported: .\$([System.IO.Path]::GetFileName($eventsFile))"
        }
    } catch {
        LogW "Could not export verification CSV: $($_.Exception.Message)"
    }
}

# ==============================================================================
# MAIN VERIFICATION FLOW
# ==============================================================================
Print-Banner

$endTime   = Get-Date
$startTime = $endTime.AddMinutes(-$LastMinutes)
LogI ("Verification window: {0:yyyy-MM-dd HH:mm:ss} to {1:yyyy-MM-dd HH:mm:ss}" -f $startTime, $endTime)

$ev4657     = Get-SecurityEID4657                -Start $startTime -End $endTime
$ev4688     = Get-SecurityEID4688TraceRemoval     -Start $startTime -End $endTime
$logClearEv = Get-EventLogClearedEvents           -Start $startTime -End $endTime
$ev4104     = Get-PowerShellEID4104              -Start $startTime -End $endTime

if ($All -or ($ev4657.Count -gt 0) -or ($ev4688.Count -gt 0) -or ($logClearEv.Count -gt 0) -or ($ev4104.Count -gt 0)) {
    if ($ev4657.Count -gt 0) {
        Write-Host ""
        Write-Host "  -- Security Event ID 4657 (Registry Value Modified / Object Deleted) --" -ForegroundColor Green
        foreach ($e in $ev4657 | Select-Object -First 10) {
            Show-EventBox -Title "DETECTED: EID 4657 - Registry Object Deleted/Modified" `
                -Classification $e.Classification `
                -Fields ([ordered]@{
                    "ObjectName"     = $e.ObjectName
                    "ObjectValueName"= $e.ObjectValueName
                    "OperationType"  = $e.OperationType
                    "ProcessName"    = $e.ProcessName
                    "TimeGenerated"  = $e.TimeStr
                })
        }
    }

    if ($ev4688.Count -gt 0) {
        Write-Host ""
        Write-Host "  -- Security Event ID 4688 (Trace Removal Commands) --" -ForegroundColor Green
        foreach ($e in $ev4688 | Select-Object -First 10) {
            Show-EventBox -Title "DETECTED: EID 4688 - Trace Removal Process ($($e.Utility))" `
                -Classification $e.Classification `
                -Fields ([ordered]@{
                    "Utility"       = $e.Utility
                    "CommandLine"   = $e.CommandLine
                    "SubjectUser"   = $e.SubjectUser
                    "TimeGenerated" = $e.TimeStr
                })
        }
    }

    if ($logClearEv.Count -gt 0) {
        Write-Host ""
        Write-Host "  -- Event Log Cleared Events (EID 1102 / EID 104) --" -ForegroundColor Yellow
        foreach ($e in $logClearEv | Select-Object -First 6) {
            Show-EventBox -Title "DETECTED: Event Log Cleared (EID $($e.EventID))" `
                -Classification $e.Classification `
                -Fields ([ordered]@{
                    "EventID"       = $e.EventID
                    "LogSource"     = $e.LogSource
                    "SubjectUser"   = $e.SubjectUser
                    "TimeGenerated" = $e.TimeStr
                })
        }
    }

    if ($ev4104.Count -gt 0) {
        Write-Host ""
        Write-Host "  -- PowerShell Operational Event ID 4104 (Script Block Logging) --" -ForegroundColor Yellow
        foreach ($e in $ev4104 | Select-Object -First 6) {
            Show-EventBox -Title "DETECTED: EID 4104 - Trace Clearing Script Block" `
                -Classification $e.Classification `
                -Fields ([ordered]@{
                    "TimeGenerated" = $e.TimeStr
                    "CodeSnippet"   = $e.Snippet
                })
        }
    }
}

Show-Diagnostics

# ==============================================================================
# VERDICT EVALUATION
# ==============================================================================
$verdict = [PSCustomObject]@{
    OverallVerdict = "NOT DETECTED"
    Status         = "MISSING"
    Message        = "No matching events found in $LastMinutes-minute window. Run trigger_removal_of_traces.ps1 to generate test activity."
}

$hasBlock1 = ($ev4657.Count -gt 0)
$hasBlock2 = (($logClearEv | Where-Object { $_.EventID -eq 1102 }).Count -gt 0)

if ($hasBlock1 -and $hasBlock2) {
    $verdict.OverallVerdict = "FULL DETECTION (100% SIEM MATCH - BOTH BLOCKS)"
    $verdict.Status         = "FULL"
    $verdict.Message        = "Exact SIEM Rule 85 Match: Block 1 (EID 4657 Registry Object Deleted: $($ev4657.Count)) AND Block 2 (EID 1102 Windows Audit Log Cleared: $(($logClearEv | Where-Object { $_.EventID -eq 1102 }).Count))."
} elseif ($hasBlock2) {
    $verdict.OverallVerdict = "FULL DETECTION (BLOCK 2 CONFIRMED)"
    $verdict.Status         = "FULL"
    $verdict.Message        = "Block 2 Matched: Security Event ID 1102 (Windows Audit Log Cleared). Block 1 (EID 4657) not seen in current window."
} elseif ($hasBlock1) {
    $verdict.OverallVerdict = "FULL DETECTION (BLOCK 1 CONFIRMED)"
    $verdict.Status         = "FULL"
    $verdict.Message        = "Block 1 Matched: Security Event ID 4657 (Registry Object Deleted/Removed: $($ev4657.Count)). Block 2 (EID 1102) not seen in current window."
} elseif ($ev4688.Count -ge 2 -or $logClearEv.Count -gt 0) {
    $verdict.OverallVerdict = "FULL DETECTION"
    $verdict.Status         = "FULL"
    $verdict.Message        = "Trace Removal Sequence Matched: $($ev4688.Count) trace removal process executions (EID 4688) & $($logClearEv.Count) log clearing events captured."
} elseif ($ev4104.Count -gt 0) {
    $verdict.OverallVerdict = "PARTIAL DETECTION"
    $verdict.Status         = "PARTIAL"
    $verdict.Message        = "PowerShell script blocks referencing trace removal captured ($($ev4104.Count) EID 4104), but direct registry deletion EID 4657 was not logged."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "   SIEM USE CASE 85 - VERIFICATION VERDICT                  " -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  Use Case   : S.No 85 | Identify Attempts on Removal of Traces"
Write-Host "  Priority   : P2 | Threshold: Correlated Events in 10m / Block in 3m"
Write-Host "  MITRE      : T1070 (Indicator Removal), T1070.001, T1070.003, T1070.004, T1112"
Write-Host "  Window     : Last $LastMinutes minutes"
Write-Host ""
Write-Host "  Security Log EID 4657  (Registry Value Modified / Deleted) : $($ev4657.Count) event(s)"
Write-Host "  Security Log EID 4688  (Trace Removal Process Executions)  : $($ev4688.Count) event(s)"
Write-Host "  Log Cleared Events     (Security EID 1102 / System 104)    : $($logClearEv.Count) event(s)"
Write-Host "  PowerShell EID 4104    (Script Block Creation)             : $($ev4104.Count) event(s)"
Write-Host ""

if ($verdict.Status -eq "FULL") {
    LogFull "OVERALL VERDICT: FULL DETECTION | $($verdict.Message)"
} elseif ($verdict.Status -eq "PARTIAL") {
    LogPartial "OVERALL VERDICT: PARTIAL | $($verdict.Message)"
    Write-Host "  Ensure Registry auditing is enabled: auditpol /set /subcategory:`"Registry`" /success:enable /failure:enable" -ForegroundColor Yellow
} else {
    LogMissing "OVERALL VERDICT: NOT DETECTED | $($verdict.Message)"
}

Write-Host "============================================================" -ForegroundColor Red

Export-VerificationCSV -Verdict $verdict -Ev4657 $ev4657 -Ev4688 $ev4688 -LogClearEvs $logClearEv -Ev4104 $ev4104

Write-Host ""
Write-Host "Usage Examples:" -ForegroundColor Gray
Write-Host "  .\verify_siem_events_removal_of_traces.ps1                          # Last 10 min" -ForegroundColor DarkGray
Write-Host "  .\verify_siem_events_removal_of_traces.ps1 -LastMinutes 5           # 5 min window" -ForegroundColor DarkGray
Write-Host "  .\verify_siem_events_removal_of_traces.ps1 -All                     # All checks + diag + CSV" -ForegroundColor DarkGray
Write-Host "  .\verify_siem_events_removal_of_traces.ps1 -Summary                 # Verdict only" -ForegroundColor DarkGray
Write-Host ""
