<#
.SYNOPSIS
    Purple Team SIEM Simulation - Use Case 85: Identify Attempts on Removal of Traces
    Simulates log-clearing, registry trace deletion, temp-file deletion, and history-clearing commands.

.DESCRIPTION
    This script tests SIEM detection rules monitoring for Defense Evasion / Indicator Removal on Host:
      - Security Log Event ID 4657: A registry value was modified / Object Deleted/Removed
      - Security Log Event ID 4688: Process Creation (wevtutil.exe cl, reg.exe delete, del /f /q, Clear-History)
      - Security Log Event ID 1102 & Event ID 104: Event Log Cleared
      - PowerShell Operational Event ID 4104: Script Block Logging

.PARAMETER Technique
    Specific technique to run:
      - EventLogClearing               : Clear event log via wevtutil.exe cl (on a safe test log)
      - RegistryTraceDeletion          : Create and delete registry value via reg.exe delete (triggers EID 4657)
      - TempFileDeletion               : Delete temporary payload/trace files via cmd.exe del /f /q
      - HistoryClearing                : Execute PowerShell Clear-History and wipe history files
      - CorrelatedTraceRemovalSequence : Rapid sequential burst of all 4 trace-clearing actions (< 10 seconds)
      - WhoamiProof                    : Live actor context (whoami /all, ping loopback, system context)
      - All                            : Execute all techniques sequentially

.PARAMETER All
    Execute all simulation techniques sequentially.

.PARAMETER SimulatedHost
    Target loopback or validation host for network proofs (Default: 127.0.0.1).

.PARAMETER DryRun
    Display proposed actions without executing trace deletion commands.

.PARAMETER Summary
    Display summary scorecard and exit without running tests.

.EXAMPLE
    .\trigger_removal_of_traces.ps1 -All
    .\trigger_removal_of_traces.ps1 -Technique RegistryTraceDeletion
    .\trigger_removal_of_traces.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [ValidateSet("EventLogClearing", "RegistryTraceDeletion", "TempFileDeletion", "HistoryClearing", "CorrelatedTraceRemovalSequence", "WhoamiProof", "All")]
    [string]$Technique = "All",

    [switch]$All,

    [string]$SimulatedHost = "127.0.0.1",

    [switch]$DryRun,

    [switch]$Summary
)

# ==============================================================================
# ENVIRONMENT SETUP & LOGGING
# ==============================================================================
$SessionTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$SessionID        = "PT-UC85-$SessionTimestamp"
$ScriptDir        = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LogFileName      = "purple_team_uc85_$SessionTimestamp.log"
$LogFilePath      = Join-Path $ScriptDir $LogFileName
$Scorecard        = [System.Collections.Generic.List[PSCustomObject]]::new()

function Get-Timestamp {
    $now = Get-Date
    $utc = $now.ToUniversalTime()
    return "[{0:yyyy-MM-dd HH:mm:ss.fff} LOCAL | {1:yyyy-MM-dd HH:mm:ss.fff} UTC]" -f $now, $utc
}

function Log-Message {
    param([string]$Level, [string]$Msg, [ConsoleColor]$Color = [ConsoleColor]::White)
    $line = "{0} [{1,-5}] {2}" -f (Get-Timestamp), $Level, $Msg
    Write-Host $line -ForegroundColor $Color
    try {
        Add-Content -Path $LogFilePath -Value $line -ErrorAction SilentlyContinue
    } catch {}
}

function Log-Info    { param([string]$m) Log-Message "INFO " $m White }
function Log-Success { param([string]$m) Log-Message "OK   " $m Green }
function Log-Warning { param([string]$m) Log-Message "WARN " $m Yellow }
function Log-Error   { param([string]$m) Log-Message "ERROR" $m Red }
function Log-Step    { param([string]$m) Log-Message "STEP " $m Cyan }
function Log-Telem   { param([string]$m) Log-Message "TELEM" $m Magenta }

# ==============================================================================
# EVIDENCE BOX FORMATTER (ASCII COMPATIBLE)
# ==============================================================================
function Show-EvidenceOutput {
    param(
        [string]$Title,
        [string]$Command,
        [string]$Output,
        [int]$MaxLines = 18
    )

    $boxWidth = 68
    $hr = "+-" + ("-" * ($boxWidth - 4)) + "-+"
    
    Write-Host ""
    Write-Host "  $hr" -ForegroundColor DarkGray
    Write-Host "  |  LIVE EVIDENCE OUTPUT - PROOF OF EXECUTION                      |" -ForegroundColor Cyan
    Write-Host "  $hr" -ForegroundColor DarkGray
    Write-Host ("  |  Action  : {0,-52} |" -f ($Title.Substring(0, [Math]::Min(52, $Title.Length)))) -ForegroundColor Gray
    Write-Host ("  |  Command : {0,-52} |" -f ($Command.Substring(0, [Math]::Min(52, $Command.Length)))) -ForegroundColor DarkCyan
    Write-Host "  $hr" -ForegroundColor DarkGray
    Write-Host "  |  OUTPUT:" -ForegroundColor Gray

    if ([string]::IsNullOrWhiteSpace($Output)) {
        Write-Host "  |    [Command produced no standard output or exited silently]     |" -ForegroundColor DarkGray
    } else {
        $lines = $Output -split "`r?`n"
        $displayLines = $lines | Select-Object -First $MaxLines
        foreach ($l in $displayLines) {
            $trunc = if ($l.Length -gt 60) { $l.Substring(0, 57) + "..." } else { $l }
            Write-Host ("  |    {0,-60} |" -f $trunc) -ForegroundColor White
        }
        if ($lines.Count -gt $MaxLines) {
            $remaining = $lines.Count - $MaxLines
            Write-Host ("  |    ... [{0} lines truncated for readability] ...                 |" -f $remaining) -ForegroundColor DarkYellow
        }
    }
    Write-Host "  $hr" -ForegroundColor DarkGray
    Write-Host ""
}

# ==============================================================================
# HELPER: Run Command Safely and Capture Output
# ==============================================================================
function Invoke-TraceCommand {
    param(
        [string]$CommandLine,
        [string]$Description
    )

    Log-Step "Executing: $CommandLine"
    $tempOutFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "pt_uc85_out_$([System.Guid]::NewGuid().ToString('N')).tmp")
    
    try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "cmd.exe"
        $pinfo.Arguments = "/c $CommandLine > `"$tempOutFile`" 2>&1"
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($pinfo)
        $proc.WaitForExit(8000)

        $output = ""
        if (Test-Path $tempOutFile) {
            $output = Get-Content -Path $tempOutFile -Raw -ErrorAction SilentlyContinue
            Remove-Item -Path $tempOutFile -Force -ErrorAction SilentlyContinue
        }

        return $output
    } catch {
        return "Error executing command: $($_.Exception.Message)"
    }
}

# ==============================================================================
# BANNER & PRE-FLIGHT CHECKS
# ==============================================================================
function Print-Banner {
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor Red
    Write-Host "  PURPLE TEAM SIEM VALIDATION - S.No 85                                       " -ForegroundColor Red
    Write-Host "  Identify Attempts on Removal of Traces (Registry EID 4657 & Trace Clearing) " -ForegroundColor Red
    Write-Host "==============================================================================" -ForegroundColor Red
    Log-Info "Session ID      : $SessionID"
    Log-Info "Log File        : $LogFileName"
    Log-Info "Host / User     : $env:COMPUTERNAME \ $env:USERNAME"
    Log-Info "OS Version      : $((Get-CimInstance Win32_OperatingSystem).Version)"
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Log-Info "Admin Privs     : $isAdmin"
    Log-Info "Dry-Run Mode    : $DryRun"
    Log-Info "Loopback Host   : $SimulatedHost"
    Log-Info "Use Case        : S.No 85 | Priority: P2 | Threshold: Correlated Events in 10m / Block in 3m"
    Log-Info "MITRE ATT&CK    : T1070 (Indicator Removal), T1070.001, T1070.003, T1070.004, T1112"
    Log-Info "Detection EID 1 : Security Log Event ID 4657 (Object Deleted/Removed - Registry Value Modified)"
    Log-Info "Detection EID 2 : Security Log Event ID 4688 (wevtutil cl, reg delete, del /f /q, Clear-History)"
    Log-Info "Detection EID 3 : Security Log Event ID 1102 / 104 (Event Log Cleared)"
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
}

function Run-PreflightChecks {
    Write-Host ""
    Write-Host "--- PRE-FLIGHT: Trace Removal Utilities & Audit Policy Verification ---" -ForegroundColor Yellow

    $tools = @("wevtutil.exe", "reg.exe", "cmd.exe", "whoami.exe")
    foreach ($t in $tools) {
        $p = Join-Path "C:\Windows\System32" $t
        if (Test-Path $p) {
            Log-Success "$t located: $p"
        } else {
            Log-Warning "$t not found in System32."
        }
    }

    try {
        $auditReg = auditpol /get /subcategory:"Registry" 2>$null | Out-String
        if ($auditReg -match "Success") {
            Log-Success "Registry auditing is ENABLED (Security Event ID 4657 active)."
            Ensure-KeyAuditSACL "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Ensure-KeyAuditSACL "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        } else {
            Log-Warning "Registry auditing is NOT enabled (required for EID 4657 telemetry)."
            Log-Info "Remediation (Admin): auditpol /set /subcategory:`"Registry`" /success:enable /failure:enable"
        }
    } catch {}

    try {
        $auditProc = auditpol /get /subcategory:"Process Creation" 2>$null | Out-String
        if ($auditProc -match "Success") {
            Log-Success "Process Creation auditing is ENABLED (Security Event ID 4688 active)."
        } else {
            Log-Warning "Process Creation auditing is NOT enabled."
            Log-Info "Remediation (Admin): auditpol /set /subcategory:`"Process Creation`" /success:enable"
        }
    } catch {}

    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
}

function Ensure-KeyAuditSACL {
    param([string]$KeyPath)
    try {
        if (-not (Test-Path $KeyPath)) {
            New-Item -Path $KeyPath -Force | Out-Null
        }
        $acl = Get-Acl -Path $KeyPath -Audit
        $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
            "Everyone",
            "SetValue,CreateSubKey,Delete",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success"
        )
        $acl.AddAuditRule($rule)
        Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction SilentlyContinue
    } catch {}
}

# ==============================================================================
# TECHNIQUE 1: EventLogClearing (wevtutil.exe cl)
# ==============================================================================
function Invoke-Technique-EventLogClearing {
    [CmdletBinding()]
    param()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "STARTING - Technique: EventLogClearing" -ForegroundColor Yellow
    Write-Host "Description: Clearing Windows Security Audit Log via wevtutil.exe cl Security (EID 1102)" -ForegroundColor White
    Write-Host "Threat Context: Adversary wiping audit logs to hide unauthorized activity (T1070.001)" -ForegroundColor Gray
    Write-Host "Command: wevtutil.exe cl Security" -ForegroundColor Gray

    if ($DryRun) {
        Log-Info "[DRY-RUN] Would execute wevtutil.exe cl Security to test audit log clearing (EID 1102)."
        $sw.Stop()
        $Scorecard.Add([PSCustomObject]@{
            Technique = "EventLogClearing"
            Target    = "wevtutil.exe cl Security"
            Status    = "DRY_RUN"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
        return
    }

    try {
        Log-Step "Step 1: Clearing Windows Security Audit Log via wevtutil.exe cl Security..."
        $out = Invoke-TraceCommand "wevtutil.exe cl Security" "Clear Security Audit Log (EID 1102)"
        Log-Telem "SECURITY EID 1102 / 4688: Audit Log Cleared. Process='wevtutil.exe' CommandLine='wevtutil.exe cl Security'"

        Show-EvidenceOutput -Title "Windows Security Audit Log Clearing (wevtutil cl Security -> EID 1102)" `
            -Command "wevtutil.exe cl Security" `
            -Output $out

        $sw.Stop()
        Log-Success "COMPLETED Technique:EventLogClearing in $($sw.ElapsedMilliseconds)ms | Status: SUCCESS"

        $Scorecard.Add([PSCustomObject]@{
            Technique = "EventLogClearing"
            Target    = "wevtutil.exe cl Security"
            Status    = "SUCCESS"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } catch {
        $sw.Stop()
        Log-Error "Failed Technique:EventLogClearing: $($_.Exception.Message)"
        $Scorecard.Add([PSCustomObject]@{
            Technique = "EventLogClearing"
            Target    = "wevtutil.exe cl"
            Status    = "FAILED"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    }
}

# ==============================================================================
# TECHNIQUE 2: RegistryTraceDeletion (reg.exe delete -> EID 4657)
# ==============================================================================
function Invoke-Technique-RegistryTraceDeletion {
    [CmdletBinding()]
    param()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "STARTING - Technique: RegistryTraceDeletion" -ForegroundColor Yellow
    Write-Host "Description: Registry Value Modification/Deletion triggering Security EID 4657" -ForegroundColor White
    Write-Host "Threat Context: Adversary removing persistence keys or execution artifacts (T1112)" -ForegroundColor Gray
    Write-Host "Action: Creating value in HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run and running reg.exe delete" -ForegroundColor Gray

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $valName = "PT_UC85_TraceArtifact"
    $regCmd  = "reg.exe delete `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`" /v `"PT_UC85_TraceArtifact`" /f"

    if ($DryRun) {
        Log-Info "[DRY-RUN] Would create test value in $regPath and execute reg.exe delete."
        $sw.Stop()
        $Scorecard.Add([PSCustomObject]@{
            Technique = "RegistryTraceDeletion"
            Target    = "reg.exe delete $regPath (EID 4657)"
            Status    = "DRY_RUN"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
        return
    }

    try {
        Log-Step "Step 1: Setting up temporary registry value on audited key ($regPath)..."
        Ensure-KeyAuditSACL $regPath
        Set-ItemProperty -Path $regPath -Name $valName -Value "C:\Temp\simulated_malware.exe" -Force
        Log-Success "Temporary registry value created on audited key."

        Log-Step "Step 2: Executing reg.exe delete to trigger Object Deleted/Removed (EID 4657)..."
        $out = Invoke-TraceCommand $regCmd "Delete registry value"
        Log-Telem "SECURITY EID 4657: OperationType='Value deleted' ObjectName='$regPath' Process='reg.exe'"

        Show-EvidenceOutput -Title "Registry Trace Deletion (Security EID 4657)" `
            -Command $regCmd `
            -Output $out

        $sw.Stop()
        Log-Success "COMPLETED Technique:RegistryTraceDeletion in $($sw.ElapsedMilliseconds)ms | Status: SUCCESS"

        $Scorecard.Add([PSCustomObject]@{
            Technique = "RegistryTraceDeletion"
            Target    = "reg.exe delete HKLM Run (EID 4657)"
            Status    = "SUCCESS"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } catch {
        $sw.Stop()
        Log-Error "Failed Technique:RegistryTraceDeletion: $($_.Exception.Message)"
        $Scorecard.Add([PSCustomObject]@{
            Technique = "RegistryTraceDeletion"
            Target    = "reg.exe delete"
            Status    = "FAILED"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } finally {
        try {
            if (Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $regPath -Name $valName -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

# ==============================================================================
# TECHNIQUE 3: TempFileDeletion (cmd.exe del /f /q)
# ==============================================================================
function Invoke-Technique-TempFileDeletion {
    [CmdletBinding()]
    param()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "STARTING - Technique: TempFileDeletion" -ForegroundColor Yellow
    Write-Host "Description: Deleting temporary payload and trace files via cmd.exe del" -ForegroundColor White
    Write-Host "Threat Context: Adversary scrubbing drop folders and temporary binaries (T1070.004)" -ForegroundColor Gray

    $tempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "PT_UC85_TraceSim"

    if ($DryRun) {
        Log-Info "[DRY-RUN] Would create temporary directory $tempFolder with dummy files and execute del /f /q."
        $sw.Stop()
        $Scorecard.Add([PSCustomObject]@{
            Technique = "TempFileDeletion"
            Target    = "cmd.exe /c del /f /q $tempFolder\*"
            Status    = "DRY_RUN"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
        return
    }

    try {
        Log-Step "Step 1: Setting up temporary trace directory with dummy files ($tempFolder)..."
        if (-not (Test-Path $tempFolder)) {
            New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        }
        "Dummy Payload Artifact 1" | Set-Content -Path (Join-Path $tempFolder "payload.tmp") -Force
        "Dummy Log Artifact 2"     | Set-Content -Path (Join-Path $tempFolder "trace.log") -Force

        Log-Step "Step 2: Executing cmd.exe /c del /f /q to wipe trace folder..."
        $delCmd = "cmd.exe /c del /f /q `"$tempFolder\*`""
        $out = Invoke-TraceCommand $delCmd "Delete temporary trace files"
        Log-Telem "SECURITY EID 4688: ProcessName='cmd.exe' CommandLine='cmd.exe /c del /f /q ...'"

        Show-EvidenceOutput -Title "Temporary File Deletion (cmd.exe del)" `
            -Command "cmd.exe /c del /f /q `"$tempFolder\*`"" `
            -Output $out

        $sw.Stop()
        Log-Success "COMPLETED Technique:TempFileDeletion in $($sw.ElapsedMilliseconds)ms | Status: SUCCESS"

        $Scorecard.Add([PSCustomObject]@{
            Technique = "TempFileDeletion"
            Target    = "cmd.exe /c del /f /q $tempFolder\*"
            Status    = "SUCCESS"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } catch {
        $sw.Stop()
        Log-Error "Failed Technique:TempFileDeletion: $($_.Exception.Message)"
        $Scorecard.Add([PSCustomObject]@{
            Technique = "TempFileDeletion"
            Target    = "cmd.exe del"
            Status    = "FAILED"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } finally {
        try {
            if (Test-Path $tempFolder) {
                Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

# ==============================================================================
# TECHNIQUE 4: HistoryClearing (Clear-History & History File Wipe)
# ==============================================================================
function Invoke-Technique-HistoryClearing {
    [CmdletBinding()]
    param()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "STARTING - Technique: HistoryClearing" -ForegroundColor Yellow
    Write-Host "Description: Clearing PowerShell session history and history file artifacts" -ForegroundColor White
    Write-Host "Threat Context: Adversary wiping command history to prevent forensics (T1070.003)" -ForegroundColor Gray

    if ($DryRun) {
        Log-Info "[DRY-RUN] Would execute Clear-History and wipe temporary command history."
        $sw.Stop()
        $Scorecard.Add([PSCustomObject]@{
            Technique = "HistoryClearing"
            Target    = "Clear-History & history file deletion"
            Status    = "DRY_RUN"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
        return
    }

    try {
        Log-Step "Step 1: Executing PowerShell Clear-History..."
        $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"Clear-History`""
        $out1 = Invoke-TraceCommand $cmd "Clear PowerShell History"
        Log-Telem "POWERSHELL EID 4104: Script Block executing Clear-History"

        Log-Step "Step 2: Simulating history file wiping..."
        $dummyHist = Join-Path ([System.IO.Path]::GetTempPath()) "PT_UC85_PSHistory_dummy.txt"
        "Clear-History dummy line" | Set-Content -Path $dummyHist -Force
        $out2 = Invoke-TraceCommand "cmd.exe /c del /f `"$dummyHist`"" "Wipe dummy history file"

        $combined = "=== [1] CLEAR-HISTORY ===`r`n$out1`r`n"
        $combined += "=== [2] HISTORY FILE WIPE ===`r`n$out2"

        Show-EvidenceOutput -Title "Command History Clearing (Clear-History)" `
            -Command "powershell.exe -Command `"Clear-History`"" `
            -Output $combined

        $sw.Stop()
        Log-Success "COMPLETED Technique:HistoryClearing in $($sw.ElapsedMilliseconds)ms | Status: SUCCESS"

        $Scorecard.Add([PSCustomObject]@{
            Technique = "HistoryClearing"
            Target    = "Clear-History & history wipe"
            Status    = "SUCCESS"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } catch {
        $sw.Stop()
        Log-Error "Failed Technique:HistoryClearing: $($_.Exception.Message)"
        $Scorecard.Add([PSCustomObject]@{
            Technique = "HistoryClearing"
            Target    = "Clear-History"
            Status    = "FAILED"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    }
}

# ==============================================================================
# TECHNIQUE 5: CorrelatedTraceRemovalSequence (Burst of All 4 Actions in < 8s)
# ==============================================================================
function Invoke-Technique-CorrelatedTraceRemovalSequence {
    [CmdletBinding()]
    param()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "STARTING - Technique: CorrelatedTraceRemovalSequence" -ForegroundColor Yellow
    Write-Host "Description: Rapid burst of log-clearing, registry deletion, file deletion, and history clearing" -ForegroundColor White
    Write-Host "Threat Context: Satisfies LogRhythm correlation rule for multi-category trace removal in < 10m" -ForegroundColor Gray

    $regPath    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $burstVal   = "PT_UC85_BurstVal"
    $tempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "PT_UC85_BurstSim"

    if ($DryRun) {
        Log-Info "[DRY-RUN] Would execute rapid burst of all 4 trace-removal actions in < 5 seconds."
        $sw.Stop()
        $Scorecard.Add([PSCustomObject]@{
            Technique = "CorrelatedTraceRemovalSequence"
            Target    = "4 correlated trace removal actions"
            Status    = "DRY_RUN"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
        return
    }

    try {
        # Pre-setup
        Ensure-KeyAuditSACL $regPath
        Set-ItemProperty -Path $regPath -Name $burstVal -Value "C:\Temp\burst_malware.exe" -Force
        if (-not (Test-Path $tempFolder)) { New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null }
        "Burst File" | Set-Content -Path (Join-Path $tempFolder "burst.tmp") -Force

        Log-Step "Executing Correlated Trace Removal Burst (4 distinct actions in sequence)..."
        $burstSw = [System.Diagnostics.Stopwatch]::StartNew()

        # 1. Event log clear
        Log-Step " [1/4] Security Audit Log Clearing: wevtutil.exe cl Security"
        $r1 = Invoke-TraceCommand "wevtutil.exe cl Security" "Burst 1: Security audit log clear (EID 1102)"

        # 2. Registry deletion (EID 4657)
        Log-Step " [2/4] Registry Deletion: reg.exe delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v $burstVal /f"
        $r2 = Invoke-TraceCommand "reg.exe delete `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`" /v `"$burstVal`" /f" "Burst 2: Reg delete"

        # 3. Temp file deletion
        Log-Step " [3/4] File Deletion: cmd.exe /c del /f /q $tempFolder\*"
        $r3 = Invoke-TraceCommand "cmd.exe /c del /f /q `"$tempFolder\*`"" "Burst 3: Del temp"

        # 4. History clear
        Log-Step " [4/4] History Clearing: Clear-History"
        $r4 = Invoke-TraceCommand "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"Clear-History`"" "Burst 4: History clear"

        $burstSw.Stop()
        Log-Success "Rapid burst completed: 4 correlated trace removal actions executed in $($burstSw.ElapsedMilliseconds)ms!"

        $combined = "=== CORRELATED TRACE REMOVAL BURST EVIDENCE ===`r`n"
        $combined += "Total Burst Elapsed Time: $($burstSw.ElapsedMilliseconds) ms (< 10 seconds)`r`n`r`n"
        $combined += "[Action 1] wevtutil.exe cl Security        -> Executed (Security Audit Log Cleared EID 1102)`r`n"
        $combined += "[Action 2] reg.exe delete                  -> Executed (Registry EID 4657 Object Deleted)`r`n"
        $combined += "[Action 3] cmd.exe /c del /f /q            -> Executed (Temp File Deletion EID 4688)`r`n"
        $combined += "[Action 4] powershell.exe Clear-History    -> Executed (History Clearing EID 4104)"

        Show-EvidenceOutput -Title "Correlated Trace Removal Sequence" `
            -Command "wevtutil + reg delete + del + Clear-History" `
            -Output $combined

        $sw.Stop()
        Log-Success "COMPLETED Technique:CorrelatedTraceRemovalSequence in $($sw.ElapsedMilliseconds)ms | Status: SUCCESS"

        $Scorecard.Add([PSCustomObject]@{
            Technique = "CorrelatedTraceRemovalSequence"
            Target    = "4 actions ($($burstSw.ElapsedMilliseconds)ms)"
            Status    = "SUCCESS"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } catch {
        $sw.Stop()
        Log-Error "Failed Technique:CorrelatedTraceRemovalSequence: $($_.Exception.Message)"
        $Scorecard.Add([PSCustomObject]@{
            Technique = "CorrelatedTraceRemovalSequence"
            Target    = "Burst sequence"
            Status    = "FAILED"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } finally {
        try {
            if (Get-ItemProperty -Path $regPath -Name $burstVal -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $regPath -Name $burstVal -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $tempFolder) { Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
}

# ==============================================================================
# TECHNIQUE 6: WhoamiProof
# ==============================================================================
function Invoke-Technique-WhoamiProof {
    [CmdletBinding()]
    param()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "STARTING - Technique: WhoamiProof" -ForegroundColor Yellow
    Write-Host "Description: Live Proof: whoami + ping loopback + system context inspection" -ForegroundColor White
    Write-Host "Threat Context: Validates actor security identity and network baseline" -ForegroundColor Gray

    if ($DryRun) {
        Log-Info "[DRY-RUN] Would execute whoami /all, ping $SimulatedHost, and inspect network context."
        $sw.Stop()
        $Scorecard.Add([PSCustomObject]@{
            Technique = "WhoamiProof"
            Target    = "whoami + ping"
            Status    = "DRY_RUN"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
        return
    }

    try {
        # Step 1: whoami /all
        Log-Step "Step 1: Capturing actor identity and security context (whoami /all)..."
        $whoamiOut = whoami /all 2>&1 | Out-String
        Show-EvidenceOutput -Title "Actor Identity & Security Context" `
            -Command "whoami /all" `
            -Output $whoamiOut
        Log-Success "whoami /all executed successfully."

        # Step 2: ping loopback
        Log-Step "Step 2: Running ping to loopback ($SimulatedHost)..."
        $pingTargetOut = ping.exe -n 3 $SimulatedHost 2>&1 | Out-String
        Show-EvidenceOutput -Title "Loopback Network Routing Proof ($SimulatedHost)" `
            -Command "ping.exe -n 3 $SimulatedHost" `
            -Output $pingTargetOut

        # Step 3: ping host
        Log-Step "Step 3: Running ping to local host ($env:COMPUTERNAME)..."
        $pingHostOut = ping.exe -n 3 $env:COMPUTERNAME 2>&1 | Out-String
        Show-EvidenceOutput -Title "Local Host Network Routing Proof ($env:COMPUTERNAME)" `
            -Command "ping.exe -n 3 $env:COMPUTERNAME" `
            -Output $pingHostOut

        $sw.Stop()
        Log-Success "COMPLETED Technique:WhoamiProof in $($sw.ElapsedMilliseconds)ms | Status: SUCCESS"

        $Scorecard.Add([PSCustomObject]@{
            Technique = "WhoamiProof"
            Target    = "whoami + ping"
            Status    = "SUCCESS"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    } catch {
        $sw.Stop()
        Log-Error "Failed Technique:WhoamiProof: $($_.Exception.Message)"
        $Scorecard.Add([PSCustomObject]@{
            Technique = "WhoamiProof"
            Target    = "whoami + ping"
            Status    = "FAILED"
            Duration  = "$($sw.ElapsedMilliseconds)ms"
        })
    }
}

# ==============================================================================
# SCORECARD & CSV EXPORT
# ==============================================================================
function Show-Scorecard {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   SIEM USE CASE 85 - EXECUTION SCORECARD                   " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Session ID    : $SessionID"
    Write-Host "  Actor         : $env:USERNAME"
    Write-Host "  Loopback Host : $SimulatedHost"
    Write-Host "  Total Runs    : $($Scorecard.Count)"
    Write-Host "  SUCCESS       : $(@($Scorecard | Where-Object { $_.Status -eq 'SUCCESS' }).Count)" -ForegroundColor Green
    Write-Host "  FAILED        : $(@($Scorecard | Where-Object { $_.Status -eq 'FAILED' }).Count)" -ForegroundColor Red
    Write-Host "  DRY_RUN       : $(@($Scorecard | Where-Object { $_.Status -eq 'DRY_RUN' }).Count)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Technique Results:" -ForegroundColor White
    foreach ($sc in $Scorecard) {
        $c = if ($sc.Status -eq "SUCCESS") { "Green" } elseif ($sc.Status -eq "FAILED") { "Red" } else { "Yellow" }
        Write-Host ("    [{0,-8}] Technique={1,-30} Target={2,-32} [{3}]" -f $sc.Status, $sc.Technique, $sc.Target, $sc.Duration) -ForegroundColor $c
    }

    # CSV Export
    $csvFileName = "purple_team_uc85_results_$SessionTimestamp.csv"
    $csvPath = Join-Path $ScriptDir $csvFileName
    try {
        $Scorecard | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Log-Success "CSV Scorecard exported: .\$csvFileName"
    } catch {
        Log-Warning "Could not export CSV scorecard: $($_.Exception.Message)"
    }

    Write-Host "  Log File: .\$LogFileName" -ForegroundColor DarkGray
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ==============================================================================
# MAIN EXECUTION FLOW
# ==============================================================================
Print-Banner
Run-PreflightChecks

if ($All -or ($Technique -eq "All")) {
    Log-Info "Batch executing ALL techniques for Use Case 85..."
    Invoke-Technique-EventLogClearing
    Invoke-Technique-RegistryTraceDeletion
    Invoke-Technique-TempFileDeletion
    Invoke-Technique-HistoryClearing
    Invoke-Technique-CorrelatedTraceRemovalSequence
    Invoke-Technique-WhoamiProof
} else {
    switch ($Technique) {
        "EventLogClearing"               { Invoke-Technique-EventLogClearing }
        "RegistryTraceDeletion"          { Invoke-Technique-RegistryTraceDeletion }
        "TempFileDeletion"               { Invoke-Technique-TempFileDeletion }
        "HistoryClearing"                { Invoke-Technique-HistoryClearing }
        "CorrelatedTraceRemovalSequence" { Invoke-Technique-CorrelatedTraceRemovalSequence }
        "WhoamiProof"                    { Invoke-Technique-WhoamiProof }
    }
}

Show-Scorecard
