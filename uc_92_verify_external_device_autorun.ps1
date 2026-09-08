<#
.SYNOPSIS
    Purple Team SIEM Verification - Use Case 92: New External Device Connected Followed by Autorun Process Created
    Audits Windows Security, DriverFrameworks, and PowerShell logs for device arrival (Event ID 6416 / 20001)
    and correlated autorun process creation (Event ID 4688) within the 5-minute SIEM correlation threshold.

.DESCRIPTION
    Validates SIEM detection rules monitoring for Lateral Movement / Removable Media Exploitation:
      - Primary SIEM Rule Criteria:
          * Log Source Type    : MS Windows Event Logging XML - Security / DriverFrameworks
          * Vendor Message ID  : 6416 ("A new external device was recognized by the system")
          * Log Source         : UEBA_Windows_EO / Windows Security
          * Followed by        : Process Creation (Event ID 4688) of autorun-referenced binary
          * Correlation Window : Within 5 minutes on the same host
          * Group By           : Host (Impacted)
      - Secondary Correlated Telemetry:
          * DriverFrameworks-UserMode Event ID 20001: Device install completed
          * PowerShell Operational Event ID 4104: Script Block Logging

    Classification:
      - FULL    : Security EID 6416 (or 20001) captured AND EID 4688 captured on the same host within 5 minutes.
      - PARTIAL : EID 6416/20001 or EID 4688 captured, but correlation threshold or pairing is missing.
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
    .\verify_siem_events_device_autorun.ps1
    .\verify_siem_events_device_autorun.ps1 -LastMinutes 10
    .\verify_siem_events_device_autorun.ps1 -All
    .\verify_siem_events_device_autorun.ps1 -Summary
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

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "FAIL", "CRIT", "FULL", "PARTIAL", "MISSING")]
        [string]$Level = "INFO"
    )
    $ts = Get-Timestamp
    switch ($Level) {
        "INFO"    { Write-Host "$ts $CYN[INFO     ]$RST $Message" }
        "SUCCESS" { Write-Host "$ts $GRN[SUCCESS  ]$RST $Message" }
        "WARN"    { Write-Host "$ts $YLW[WARN     ]$RST $Message" }
        "FAIL"    { Write-Host "$ts $RED[FAIL     ]$RST $Message" }
        "CRIT"    { Write-Host "$ts $RED$BLD[CRITICAL ]$RST $Message" }
        "FULL"    { Write-Host "$ts $GRN$BLD[FULL     ]$RST $Message" }
        "PARTIAL" { Write-Host "$ts $YLW$BLD[PARTIAL  ]$RST $Message" }
        "MISSING" { Write-Host "$ts $RED$BLD[MISSING  ]$RST $Message" }
    }
}

function Print-Banner {
    Write-Host ""
    Write-Host "$CYN$BLD============================================================$RST"
    Write-Host "$CYN$BLD   PURPLE TEAM SIEM VERIFICATION - S.No 92                  $RST"
    Write-Host "$CYN$BLD   New External Device Connected Followed by Autorun Process$RST"
    Write-Host "$CYN$BLD============================================================$RST"
}

Print-Banner

$StartTime = (Get-Date).AddMinutes(-$LastMinutes)
$Hostname  = $env:COMPUTERNAME

Write-Log "Rule Name          : New External Device Connected Followed by Autorun Process Created" "INFO"
Write-Log "Platform / Category: Windows / Operating System" "INFO"
Write-Log "Priority / Window  : P2 | Correlated within 5 minutes" "INFO"
Write-Log "Device Group       : BGIL_Windows Devices" "INFO"
Write-Log "Log Source         : UEBA_Windows_EO (Security / DriverFrameworks)" "INFO"
Write-Log "Group By           : Host (Impacted)" "INFO"
Write-Log "Primary Criteria   : Event ID = 6416 (Device Arrival) -> Event ID = 4688 (Autorun Executable)" "INFO"
Write-Log "Audit Time Window  : Last $LastMinutes minutes (Since $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')))" "INFO"
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

$CapturedEID6416   = [System.Collections.Generic.List[PSCustomObject]]::new()
$CapturedEID20001  = [System.Collections.Generic.List[PSCustomObject]]::new()
$CapturedEID4688   = [System.Collections.Generic.List[PSCustomObject]]::new()
$CapturedEID4104   = [System.Collections.Generic.List[PSCustomObject]]::new()

# ==============================================================================
# CHECK 1: SECURITY LOG EVENT ID 6416 (External Device Recognized)
# ==============================================================================
Write-Host "`n[CHECK 1] Auditing Windows Security Log for Event ID 6416 (Device Arrival)..." -ForegroundColor Yellow

try {
    $raw6416 = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 6416
        StartTime = $StartTime
    } -MaxEvents 200 -ErrorAction Stop

    foreach ($ev in $raw6416) {
        $deviceId   = [string]$ev.Properties[4].Value
        $deviceName = [string]$ev.Properties[5].Value
        $classId    = [string]$ev.Properties[6].Value
        $className  = [string]$ev.Properties[7].Value
        $subject    = [string]$ev.Properties[1].Value

        $CapturedEID6416.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated
            EventID     = 6416
            DeviceID    = $deviceId
            DeviceName  = $deviceName
            ClassName   = $className
            ClassId     = $classId
            User        = $subject
            Computer    = $ev.MachineName
        })
    }

    Write-Log "Found $($CapturedEID6416.Count) matching Event ID 6416 external device arrival event(s)!" "SUCCESS"
    if ($All -or -not $Summary) {
        $CapturedEID6416 | Select-Object TimeCreated, EventID, ClassName, DeviceName, DeviceID, User | Format-Table -AutoSize
    }
} catch {
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Log "Zero Event ID 6416 events found in the last $LastMinutes minutes." "WARN"
    } else {
        Write-Log "Could not query Security log for Event ID 6416: $($_.Exception.Message)" "WARN"
    }
}

# ==============================================================================
# CHECK 2: DRIVERFRAMEWORKS LOG EVENT ID 20001 (Device Install)
# ==============================================================================
Write-Host "`n[CHECK 2] Auditing DriverFrameworks Log for Event ID 20001 (Device Install)..." -ForegroundColor Yellow

try {
    $raw20001 = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
        Id        = @(20001, 20003)
        StartTime = $StartTime
    } -MaxEvents 200 -ErrorAction Stop

    foreach ($ev in $raw20001) {
        $CapturedEID20001.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated
            EventID     = $ev.Id
            Message     = ($ev.Message -split "`r?`n")[0]
            Computer    = $ev.MachineName
        })
    }
    Write-Log "Found $($CapturedEID20001.Count) matching DriverFrameworks device install event(s)!" "SUCCESS"
    if ($All -or -not $Summary) {
        $CapturedEID20001 | Select-Object TimeCreated, EventID, Message | Format-Table -AutoSize -Wrap
    }
} catch {
    Write-Log "No Event ID 20001 events found in DriverFrameworks log (or channel disabled)." "INFO"
}

# ==============================================================================
# CHECK 3: SECURITY LOG EVENT ID 4688 (Autorun Process Creation)
# ==============================================================================
Write-Host "`n[CHECK 3] Auditing Windows Security Log for Event ID 4688 (Autorun Process Creation)..." -ForegroundColor Yellow

try {
    $raw4688 = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $StartTime
    } -MaxEvents 200 -ErrorAction Stop | Where-Object {
        $cmd = [string]$_.Properties[8].Value
        $proc = [string]$_.Properties[5].Value
        $cmd -match '(?i)USBPersistencePayload|autorun|PurpleTeam' -or $proc -match '(?i)USBPersistencePayload'
    }

    foreach ($ev in $raw4688) {
        $procName    = [string]$ev.Properties[5].Value
        $cmdLine     = [string]$ev.Properties[8].Value
        $parentProc  = [string]$ev.Properties[13].Value
        $subjectUser = [string]$ev.Properties[1].Value

        $CapturedEID4688.Add([PSCustomObject]@{
            TimeCreated       = $ev.TimeCreated
            EventID           = 4688
            ProcessName       = [System.IO.Path]::GetFileName($procName)
            CommandLine       = $cmdLine
            ParentProcessName = [System.IO.Path]::GetFileName($parentProc)
            SubjectUser       = $subjectUser
            Computer          = $ev.MachineName
        })
    }

    Write-Log "Found $($CapturedEID4688.Count) matching Event ID 4688 autorun process creation event(s)!" "SUCCESS"
    if ($All -or -not $Summary) {
        $CapturedEID4688 | Select-Object TimeCreated, EventID, ProcessName, CommandLine, SubjectUser | Format-Table -AutoSize
    }
} catch {
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Log "Zero Event ID 4688 autorun process events found in the last $LastMinutes minutes." "WARN"
    } else {
        Write-Log "Could not query Security log for Event ID 4688: $($_.Exception.Message)" "WARN"
    }
}

# ==============================================================================
# CHECK 4: POWERSHELL LOG EVENT ID 4104 (Script Block Logging)
# ==============================================================================
Write-Host "`n[CHECK 4] Auditing PowerShell Operational Log for Event ID 4104..." -ForegroundColor Yellow

try {
    $raw4104 = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $StartTime
    } -MaxEvents 200 -ErrorAction Stop

    foreach ($ev in $raw4104) {
        $msg = $ev.Message
        if ($msg -match 'trigger_external_device_autorun|USBPersistencePayload|VhdVirtualDeviceConnection|AutorunInfCreation') {
            $snippet = ($msg -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1)
            if ($snippet.Length -gt 90) { $snippet = $snippet.Substring(0, 87) + "..." }

            $CapturedEID4104.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated
                EventID     = 4104
                Snippet     = $snippet
            })
        }
    }

    if ($CapturedEID4104.Count -gt 0) {
        Write-Log "Found $($CapturedEID4104.Count) matching PowerShell Script Block event(s)!" "SUCCESS"
        if ($All -or -not $Summary) {
            $CapturedEID4104 | Select-Object TimeCreated, EventID, Snippet | Format-Table -AutoSize
        }
    } else {
        Write-Log "No simulation-specific PowerShell script block logs found." "INFO"
    }
} catch {
    Write-Log "Could not query PowerShell Operational log: $($_.Exception.Message)" "WARN"
}

# ==============================================================================
# TEMPORAL CORRELATION ENGINE (Within 5 Minutes)
# ==============================================================================
$CorrelationMet = $false
$CorrelationDeltaSeconds = 0

if (($CapturedEID6416.Count -gt 0 -or $CapturedEID20001.Count -gt 0) -and $CapturedEID4688.Count -gt 0) {
    $deviceTimes = [System.Collections.Generic.List[datetime]]::new()
    foreach ($d in $CapturedEID6416)  { $deviceTimes.Add($d.TimeCreated) }
    foreach ($d in $CapturedEID20001) { $deviceTimes.Add($d.TimeCreated) }
    
    $bestDelta = 999999
    foreach ($dTime in $deviceTimes) {
        foreach ($p in $CapturedEID4688) {
            $diff = [Math]::Abs(($p.TimeCreated - $dTime).TotalSeconds)
            if ($diff -lt $bestDelta) {
                $bestDelta = $diff
            }
        }
    }

    if ($bestDelta -le 300) { # 300 seconds = 5 minutes
        $CorrelationMet = $true
        $CorrelationDeltaSeconds = [int]$bestDelta
    }
}

# ==============================================================================
# SIEM DETECTION RULE COMPLIANCE VERDICT
# ==============================================================================
Write-Host ""
Write-Host "$CYN$BLD============================================================$RST"
Write-Host "$CYN$BLD   SIEM DETECTION RULE COMPLIANCE VERDICT (USE CASE 92)     $RST"
Write-Host "$CYN$BLD============================================================$RST"

$DeviceEventsCount = $CapturedEID6416.Count + $CapturedEID20001.Count
$ProcessEventsCount = $CapturedEID4688.Count

$Verdict = "MISSING"
$SiemCompliance = "NOT MET"

if ($CorrelationMet) {
    $Verdict = "FULL"
    $SiemCompliance = "MET (Correlated within $CorrelationDeltaSeconds seconds; Threshold <= 5 min)"
} elseif ($DeviceEventsCount -gt 0 -or $ProcessEventsCount -gt 0) {
    $Verdict = "PARTIAL"
    $SiemCompliance = "PARTIAL (One leg of correlation present; time delta > 5m or pairing incomplete)"
}

[PSCustomObject]@{
    Rule_SNo           = "92"
    Rule_Name          = "New External Device Connected Followed by Autorun Process Created"
    Device_EID_6416    = "$($CapturedEID6416.Count) events (PnP External Device recognized)"
    Device_EID_20001   = "$($CapturedEID20001.Count) events (DriverFrameworks install)"
    Process_EID_4688   = "$($CapturedEID4688.Count) events (Autorun payload execution)"
    Correlation_Delta  = if ($CorrelationMet) { "$CorrelationDeltaSeconds seconds" } else { "N/A" }
    SIEM_Rule_Criteria = $SiemCompliance
    Verdict            = $Verdict
} | Format-List

Write-Host ""
switch ($Verdict) {
    "FULL" {
        Write-Log "OVERALL VERDICT: FULL DETECTION!" "FULL"
        Write-Host "  -> Primary SIEM Rule Criteria completely satisfied." -ForegroundColor Green
        Write-Host "  -> Device Arrival (Event ID 6416/20001) correlated with Process Creation (Event ID 4688) within 5 minutes on host '$Hostname'." -ForegroundColor Green
    }
    "PARTIAL" {
        Write-Log "OVERALL VERDICT: PARTIAL DETECTION" "PARTIAL"
        Write-Host "  -> Telemetry captured, but correlation condition not fully satisfied." -ForegroundColor Yellow
        Write-Host "  -> Ensure both the virtual device attach and payload execution run within the same 5-minute window." -ForegroundColor Yellow
    }
    "MISSING" {
        Write-Log "OVERALL VERDICT: MISSING" "MISSING"
        Write-Host "  -> Neither Event ID 6416 nor Event ID 4688 was captured in the last $LastMinutes minutes." -ForegroundColor Red
        Write-Host "  -> Run '.\trigger_external_device_autorun.ps1 -All' in Administrator PowerShell to generate telemetry." -ForegroundColor Red
    }
}

# ==============================================================================
# CSV EXPORT
# ==============================================================================
$dateStr = (Get-Date).ToString("yyyyMMdd_HHmmss")
if (-not $OutputCSV) {
    $OutputCSV = Join-Path $PSScriptRoot "pt_uc92_verify_$dateStr.csv"
}

try {
    $scorecard = [PSCustomObject]@{
        Rule_SNo          = "92"
        Rule_Name         = "New External Device Connected Followed by Autorun Process Created"
        Host              = $Hostname
        Device_EID_6416   = $CapturedEID6416.Count
        Device_EID_20001  = $CapturedEID20001.Count
        Process_EID_4688  = $CapturedEID4688.Count
        Correlation_Met   = $CorrelationMet
        Correlation_Delta = "$CorrelationDeltaSeconds seconds"
        Verdict           = $Verdict
        Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    $scorecard | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
    Write-Log "Summary scorecard exported to: $OutputCSV" "INFO"

    $eventsFile = $OutputCSV.Replace(".csv", "_events.csv")
    $allEvents = @($CapturedEID6416) + @($CapturedEID4688)
    if ($allEvents.Count -gt 0) {
        $allEvents | Export-Csv -Path $eventsFile -NoTypeInformation -Encoding UTF8
        Write-Log "Detailed captured events exported to: $eventsFile" "INFO"
    }
} catch {}

Write-Host "============================================================`n"
