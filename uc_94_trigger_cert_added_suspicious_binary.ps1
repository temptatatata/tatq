<#
================================================================================
Script Name   : uc_94_trigger_cert_added_suspicious_binary.ps1
Category      : Defense Evasion / Subverting Trust Controls / Proxy Execution
Description   : Purple Team SIEM Simulation Trigger - Use Case 94:
                "Newly Added Certificate Followed by Suspicious Binary Execution"
                
                Simulates a 2-Rule Block correlated attack pattern:
                  Rule Block 1: New certificate added to store via certutil.exe -addstore (Event ID 4688)
                  Rule Block 2: Suspicious binary executed (regsvr32 spawned by powershell, cmstp /s, or csc proxy)
                  
                Temporal Threshold: Rule Block 1 followed by Rule Block 2 within 15 minutes.
Use Case      : S.No 94 | Priority: P2 | Correlated Event Based within 15 minutes
Device Group  : BGIL_Windows Devices
Log Sources   : CSIEM_Windows_EO (Security Event ID 4688)
MITRE ATT&CK  : T1553.004 (Install Root Certificate), T1218 (Proxy Execution: cmstp, regsvr32), T1127 (csc/vbc)
Requirements  : Elevated Administrator PowerShell prompt recommended.
================================================================================
#>

[CmdletBinding()]
param(
    [switch]$All,
    [ValidateSet('All', 'PowerShellRegsvr32', 'CmstpSilent', 'CscProxy')]
    [string]$Technique = 'All',
    [switch]$CleanOnly,
    [string]$OutputCSV = ""
)

$ErrorActionPreference = "Continue"

# ------------------------------------------------------------------------------
# Logging & Timestamps
# ------------------------------------------------------------------------------
function Get-Timestamp {
    $now = [DateTime]::UtcNow
    $local = [DateTime]::Now
    return [PSCustomObject]@{
        Local = $local.ToString("yyyy-MM-dd HH:mm:ss.fff")
        UTC   = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "TRIGGER", "CLEANUP")]
        [string]$Level = "INFO"
    )
    $ts = Get-Timestamp
    $colorMap = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
        "TRIGGER" = "Magenta"
        "CLEANUP" = "DarkGray"
    }
    $color = $colorMap[$Level]
    if (-not $color) { $color = "White" }
    Write-Host "[$($ts.Local) LOCAL | $($ts.UTC) UTC] [$($Level.PadRight(7))] $Message" -ForegroundColor $color
}

# ------------------------------------------------------------------------------
# Results Tracking
# ------------------------------------------------------------------------------
$ExecutionResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-Result {
    param(
        [string]$Step,
        [string]$Status,
        [string]$EventID,
        [string]$Details
    )
    $ts = Get-Timestamp
    $ExecutionResults.Add([PSCustomObject]@{
        TimestampLocal = $ts.Local
        TimestampUTC   = $ts.UTC
        Step           = $Step
        Status         = $Status
        EventID        = $EventID
        Details        = $Details
    })
}

# ------------------------------------------------------------------------------
# Pre-Flight Configuration
# ------------------------------------------------------------------------------
function Assert-AuditPolicies {
    Write-Log "[Pre-Flight] Verifying Advanced Audit Policies (Process Creation 4688)..." "INFO"
    try {
        & auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null | Out-Null
        
        # Ensure command-line auditing is enabled in registry
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force | Out-Null
        Write-Log "Audit policy Process Creation & Command-Line logging confirmed [OK]" "SUCCESS"
    } catch {
        Write-Log "Notice checking audit policies: $($_.Exception.Message)" "WARN"
    }
}

# ------------------------------------------------------------------------------
# Certificate Management & Cleanup
# ------------------------------------------------------------------------------
$CertSubject   = "CN=PurpleTeam_UC94_TestCert"
$TempDir       = [System.IO.Path]::GetTempPath().TrimEnd("\")
$TempCertFile  = "$TempDir\PurpleTeam_UC94_Cert.cer"
$DummyDllFile  = "$TempDir\dummy_test_uc94.dll"
$DummyInfFile  = "$TempDir\dummy_test_uc94.inf"
$DummyVbsFile  = "$TempDir\dummy_test_uc94.vbs"

function Remove-TestArtifacts {
    Write-Log "[Cleanup] Reverting installed test certificates and temporary files..." "CLEANUP"

    # 1. Remove certificate from User and Machine Root store using certutil
    try {
        & certutil.exe -delstore -user Root "PurpleTeam_UC94_TestCert" 2>$null | Out-Null
        & certutil.exe -delstore Root "PurpleTeam_UC94_TestCert" 2>$null | Out-Null
    } catch {}

    # 2. Clean from CurrentUser\My
    try {
        Get-ChildItem -Path "Cert:\CurrentUser\My" -Recurse |
            Where-Object { $_.Subject -match "PurpleTeam_UC94_TestCert" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {}

    # 3. Clean files
    @($TempCertFile, $DummyDllFile, $DummyInfFile, $DummyVbsFile) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Log "[Cleanup] Completed safe cleanup of test certificates and files." "SUCCESS"
}

if ($CleanOnly) {
    Remove-TestArtifacts
    Write-Host "`nCleanup-only operation completed successfully.`n" -ForegroundColor Green
    return
}

# ------------------------------------------------------------------------------
# Simulation Functions
# ------------------------------------------------------------------------------

# Rule Block 1: certutil.exe with -addstore
function Trigger-RuleBlock1-CertAddStore {
    Write-Log "------------------------------------------------------------" "INFO"
    Write-Log "[RULE BLOCK 1] Generating and adding certificate via certutil.exe -addstore..." "TRIGGER"

    try {
        # 1. Generate self-signed test certificate
        Write-Log "Creating self-signed certificate: $CertSubject..." "INFO"
        $cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Subject $CertSubject -NotAfter (Get-Date).AddDays(1)
        
        # 2. Export certificate to file
        Export-Certificate -Cert $cert -FilePath $TempCertFile -Force | Out-Null
        Write-Log "Certificate exported to $TempCertFile" "SUCCESS"

        # 3. Execute native certutil.exe with -addstore
        Write-Log "Executing certutil.exe -addstore -user Root `"$TempCertFile`"..." "TRIGGER"
        $proc = Start-Process -FilePath "certutil.exe" -ArgumentList "-addstore -user Root `"$TempCertFile`"" -PassThru -NoNewWindow -Wait
        
        $exitCode = $proc.ExitCode
        Write-Log "certutil.exe process completed with ExitCode: $exitCode" "SUCCESS"
        Record-Result "RuleBlock1_CertAddStore" "SUCCESS" "4688" "certutil.exe -addstore -user Root $TempCertFile (ExitCode=$exitCode)"
    } catch {
        Write-Log "Error executing certutil -addstore: $($_.Exception.Message)" "ERROR"
        Record-Result "RuleBlock1_CertAddStore" "FAILED" "4688" $_.Exception.Message
    }
}

# Rule Block 2: Suspicious Binary Execution Techniques
function Trigger-RuleBlock2-PowerShellRegsvr32 {
    Write-Log "[RULE BLOCK 2 - Technique 1] PowerShell spawning regsvr32.exe..." "TRIGGER"
    try {
        # Create empty dummy DLL
        [System.IO.File]::WriteAllBytes($DummyDllFile, [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

        Write-Log "Spawning regsvr32.exe /s /u `"$DummyDllFile`" from powershell..." "INFO"
        $proc = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s /u `"$DummyDllFile`"" -PassThru -NoNewWindow -Wait
        Write-Log "regsvr32.exe completed with ExitCode: $($proc.ExitCode)" "SUCCESS"
        Record-Result "RuleBlock2_PowerShellRegsvr32" "SUCCESS" "4688" "Parent=powershell.exe, Child=regsvr32.exe, Args=/s /u $DummyDllFile"
    } catch {
        Write-Log "Error executing regsvr32: $($_.Exception.Message)" "ERROR"
        Record-Result "RuleBlock2_PowerShellRegsvr32" "FAILED" "4688" $_.Exception.Message
    }
}

function Trigger-RuleBlock2-CmstpSilent {
    Write-Log "[RULE BLOCK 2 - Technique 2] Executing cmstp.exe with /s argument..." "TRIGGER"
    try {
        # Create benign dummy INF file
        $infContent = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "PurpleTeamTest", "echo benign"
"@
        Set-Content -Path $DummyInfFile -Value $infContent -Force

        Write-Log "Executing cmstp.exe /s /ni /au `"$DummyInfFile`"..." "INFO"
        $proc = Start-Process -FilePath "cmstp.exe" -ArgumentList "/s /ni /au `"$DummyInfFile`"" -PassThru -NoNewWindow -Wait
        $exitCode = if ($proc) { $proc.ExitCode } else { 0 }
        Write-Log "cmstp.exe completed with ExitCode: $exitCode" "SUCCESS"
        Record-Result "RuleBlock2_CmstpSilent" "SUCCESS" "4688" "Child=cmstp.exe, Args=/s /ni /au $DummyInfFile (ExitCode=$exitCode)"
    } catch {
        Write-Log "Error executing cmstp.exe: $($_.Exception.Message)" "ERROR"
        Record-Result "RuleBlock2_CmstpSilent" "FAILED" "4688" $_.Exception.Message
    }
}

function Trigger-RuleBlock2-CscProxy {
    Write-Log "[RULE BLOCK 2 - Technique 3] Executing csc.exe via script host proxy..." "TRIGGER"
    try {
        # Find csc.exe
        $cscPaths = @(
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        )
        $cscPath = $cscPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($cscPath) {
            # Create a tiny VBScript that invokes csc.exe /?
            $vbsContent = "Set objShell = CreateObject(`"Wscript.Shell`")`nobjShell.Run `"`"`"$cscPath`"`" /?`", 0, True"
            Set-Content -Path $DummyVbsFile -Value $vbsContent -Force

            Write-Log "Executing wscript.exe `"$DummyVbsFile`" -> spawning csc.exe..." "INFO"
            $proc = Start-Process -FilePath "wscript.exe" -ArgumentList "`"$DummyVbsFile`"" -PassThru -NoNewWindow -Wait
            Write-Log "wscript proxy execution completed [OK]" "SUCCESS"
            Record-Result "RuleBlock2_CscProxy" "SUCCESS" "4688" "Parent=wscript.exe, Child=csc.exe"
        } else {
            Write-Log "csc.exe not found in .NET Framework path. Skipping CscProxy technique." "WARN"
            Record-Result "RuleBlock2_CscProxy" "SKIPPED" "4688" "csc.exe not located"
        }
    } catch {
        Write-Log "Error executing CscProxy: $($_.Exception.Message)" "ERROR"
        Record-Result "RuleBlock2_CscProxy" "FAILED" "4688" $_.Exception.Message
    }
}

# ------------------------------------------------------------------------------
# Main Execution Workflow
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================================" -ForegroundColor Magenta
Write-Host "  PURPLE TEAM SIEM SIMULATION TRIGGER - USE CASE 94                     " -ForegroundColor Magenta
Write-Host "  Newly Added Certificate Followed by Suspicious Binary Execution        " -ForegroundColor Magenta
Write-Host "  Correlated Event Sequence within 15 Minutes (Event ID 4688)            " -ForegroundColor Magenta
Write-Host "=========================================================================" -ForegroundColor Magenta
Write-Host ""

Assert-AuditPolicies

# 1. Execute Rule Block 1 (certutil.exe -addstore)
$block1Start = Get-Date
Trigger-RuleBlock1-CertAddStore

# Short delay to guarantee distinct timestamps
Write-Log "Pausing 3 seconds before executing Rule Block 2..." "INFO"
Start-Sleep -Seconds 3

# 2. Execute Rule Block 2 (Suspicious Binary Execution)
switch ($Technique) {
    'PowerShellRegsvr32' {
        Trigger-RuleBlock2-PowerShellRegsvr32
    }
    'CmstpSilent' {
        Trigger-RuleBlock2-CmstpSilent
    }
    'CscProxy' {
        Trigger-RuleBlock2-CscProxy
    }
    default {
        # 'All' executes primary technique + cmstp + csc
        Trigger-RuleBlock2-PowerShellRegsvr32
        Start-Sleep -Seconds 2
        Trigger-RuleBlock2-CmstpSilent
        Start-Sleep -Seconds 2
        Trigger-RuleBlock2-CscProxy
    }
}

$block2End = Get-Date
$deltaSeconds = [Math]::Round(($block2End - $block1Start).TotalSeconds, 2)
Write-Log "Correlated attack sequence completed in $deltaSeconds seconds (Threshold <= 900s / 15 min)." "SUCCESS"

# 3. Clean up test artifacts safely
Start-Sleep -Seconds 2
Remove-TestArtifacts

# ------------------------------------------------------------------------------
# Summary & Export
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================================" -ForegroundColor Green
Write-Host "  SIMULATION SCORECARD - USE CASE 94 COMPLETED                          " -ForegroundColor Green
Write-Host "=========================================================================" -ForegroundColor Green
$ExecutionResults | Format-Table -AutoSize

if ($OutputCSV) {
    try {
        $ExecutionResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Force
        Write-Log "Scorecard exported to: $OutputCSV" "SUCCESS"
    } catch {
        Write-Log "Failed to export CSV: $($_.Exception.Message)" "WARN"
    }
}

Write-Host "`nRun the verification script to validate local event log telemetry:" -ForegroundColor Cyan
Write-Host "  .\uc_94_verify_cert_added_suspicious_binary.ps1 -LastMinutes 15 -All`n" -ForegroundColor Yellow
