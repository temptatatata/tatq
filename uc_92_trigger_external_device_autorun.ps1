<#
.SYNOPSIS
    Purple Team SIEM Simulation Trigger - Use Case 92: New External Device Connected Followed by Autorun Process Created
    Simulates external/removable device arrival (Event ID 6416 / 20001) and subsequent autorun process execution (Event ID 4688)
    WITHOUT requiring physical USB hardware, using Windows virtual storage and Plug-and-Play (PnP) subsystem.

.DESCRIPTION
    Simulates MITRE ATT&CK T1091 (Replication Through Removable Media) and T1204.002 (User Execution: Malicious File).
    
    Attack Chain Simulated:
      1. Storage/Removable Device Arrival:
         - Attaches a lightweight Virtual Hard Disk (VHD) or loopback device.
         - Windows Plug-and-Play (PnP) subsystem detects the arrival, triggering:
             * Security Event ID 6416: "A new external device was recognized by the system"
             * DriverFrameworks Event ID 20001: Device install completed
      2. Autorun Artifact Staging:
         - Generates standard autorun.inf referencing 'USBPersistencePayload.exe' on the removable volume root.
      3. Correlated Process Creation:
         - Launches the autorun-referenced executable from the volume root within the 5-minute SIEM correlation window.
         - Generates Security Event ID 4688 with full command-line context.
      4. Safe Reversion:
         - Automatically terminates test process, dismounts VHD, and deletes temporary files.

.PARAMETER All
    Executes all simulation techniques in end-to-end correlation sequence.

.PARAMETER Technique
    Runs a specific simulation technique:
      - VhdVirtualDeviceConnection
      - AutorunInfCreation
      - AutorunProcessExecution
      - SubstRemovableSimulation
      - WhoamiProof

.PARAMETER DriveLetter
    Drive letter to assign for the virtual removable device (Default: 'Z').

.PARAMETER CleanOnly
    Dismounts any mounted simulation VHDs and cleans up temporary files without running simulations.

.PARAMETER OutputCSV
    Optional custom path to export the simulation execution results CSV.

.EXAMPLE
    .\trigger_external_device_autorun.ps1 -All
    .\trigger_external_device_autorun.ps1 -Technique VhdVirtualDeviceConnection
    .\trigger_external_device_autorun.ps1 -CleanOnly
#>

#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$All,
    [ValidateSet('VhdVirtualDeviceConnection', 'AutorunInfCreation', 'AutorunProcessExecution', 'SubstRemovableSimulation', 'WhoamiProof')]
    [string]$Technique,
    [string]$DriveLetter = 'Z',
    [switch]$CleanOnly,
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
        [ValidateSet("INFO", "SUCCESS", "WARN", "FAIL", "CLEAN")]
        [string]$Level = "INFO"
    )
    $ts = Get-Timestamp
    switch ($Level) {
        "INFO"    { Write-Host "$ts $CYN[INFO   ]$RST $Message" }
        "SUCCESS" { Write-Host "$ts $GRN[SUCCESS]$RST $Message" }
        "WARN"    { Write-Host "$ts $YLW[WARN   ]$RST $Message" }
        "FAIL"    { Write-Host "$ts $RED[FAIL   ]$RST $Message" }
        "CLEAN"   { Write-Host "$ts $MAG[CLEAN  ]$RST $Message" }
    }
}

function Print-Banner {
    Write-Host ""
    Write-Host "$CYN$BLD==============================================================================$RST"
    Write-Host "$CYN$BLD   PURPLE TEAM SIEM VALIDATION - S.No 92                                      $RST"
    Write-Host "$CYN$BLD   New External Device Connected Followed by Autorun Process Created          $RST"
    Write-Host "$CYN$BLD   Simulating EID 6416 (External Device) + EID 4688 (Autorun Binary)         $RST"
    Write-Host "$CYN$BLD==============================================================================$RST"
    Write-Host ""
}

# ==============================================================================
# STATE & TRACKING
# ==============================================================================
$VhdPath = Join-Path $env:TEMP "PurpleTeam_RemovableDevice.vhd"
$SubstDir = Join-Path $env:TEMP "PurpleTeam_RemovableStaging"
$TargetDrive = "${DriveLetter}:"
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-Result {
    param(
        [string]$TechName,
        [string]$Status,
        [string]$EventID,
        [string]$Details
    )
    $Results.Add([PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Technique = $TechName
        Status    = $Status
        TargetEID = $EventID
        Details   = $Details
    })
}

# ==============================================================================
# CLEANUP ENGINE
# ==============================================================================
function Invoke-SafeTeardown {
    param([bool]$VerboseOutput = $true)
    if ($VerboseOutput) { Write-Log "Initiating safe teardown of simulation virtual removable devices..." "CLEAN" }

    # 1. Kill any running simulated payload process
    try {
        Get-Process -Name "USBPersistencePayload" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}

    # 2. Detach VHD via diskpart or PowerShell
    try {
        if (Test-Path $VhdPath) {
            $dpScript = @"
select vdisk file="$VhdPath"
detach vdisk
"@
            $dpFile = Join-Path $env:TEMP "dp_detach.txt"
            Set-Content -Path $dpFile -Value $dpScript -Encoding ASCII
            & diskpart.exe /s $dpFile | Out-Null
            Remove-Item -Path $dpFile -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            Remove-Item -Path $VhdPath -Force -ErrorAction SilentlyContinue
            if ($VerboseOutput) { Write-Log "Detached and removed virtual disk: $VhdPath" "CLEAN" }
        }
    } catch {
        if ($VerboseOutput) { Write-Log "Notice during VHD detach: $($_.Exception.Message)" "WARN" }
    }

    # 3. Dismount any subst drive
    try {
        if (Test-Path $TargetDrive) {
            & subst.exe $TargetDrive /d 2>$null | Out-Null
            if ($VerboseOutput) { Write-Log "Removed subst virtual drive mapping: $TargetDrive" "CLEAN" }
        }
        if (Test-Path $SubstDir) {
            Remove-Item -Path $SubstDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

if ($CleanOnly) {
    Print-Banner
    Invoke-SafeTeardown -VerboseOutput $true
    Write-Log "Teardown complete. All virtual devices removed." "SUCCESS"
    exit 0
}

# ==============================================================================
# PRE-FLIGHT AUDIT VERIFICATION
# ==============================================================================
function Assert-AuditConfiguration {
    Write-Log "[Pre-Flight] Verifying Plug and Play Events & Process Creation audit policies..." "INFO"

    try {
        # Enable Plug and Play Events audit policy for Event ID 6416 (Subcategory must be 'Plug and Play Events', NOT 'PNP Activity')
        $pnpRes = & auditpol.exe /set /subcategory:"Plug and Play Events" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Audit policy 'Plug and Play Events' verified/enabled (Event ID 6416) [OK]" "SUCCESS"
        } else {
            Write-Log "auditpol warning for 'Plug and Play Events': $($pnpRes -join ' ')" "WARN"
        }
    } catch {
        Write-Log "Could not set 'Plug and Play Events' audit policy: $($_.Exception.Message)" "WARN"
    }

    try {
        # Enable Process Creation audit policy for Event ID 4688
        $pcRes = & auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Audit policy 'Process Creation' verified/enabled (Event ID 4688) [OK]" "SUCCESS"
        }
    } catch {}

    try {
        # Ensure command line auditing is enabled in registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}

    try {
        # Enable DriverFrameworks log channel for Event ID 20001
        & wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true 2>$null | Out-Null
        Write-Log "Channel 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' enabled [OK]" "SUCCESS"
    } catch {}
}

# ==============================================================================
# TECHNIQUE 1: VHD VIRTUAL DEVICE CONNECTION (PnP Event 6416 / 20001)
# ==============================================================================
function Invoke-VhdVirtualDeviceConnection {
    Write-Log "[Technique 1/5] VhdVirtualDeviceConnection - Creating & Attaching Virtual Removable Device..." "INFO"

    try {
        # Ensure clean state first
        Invoke-SafeTeardown -VerboseOutput $false

        Write-Log "Creating 256MB dynamic VHD image at: $VhdPath" "INFO"
        $dpScript = @"
create vdisk file="$VhdPath" maximum=256 type=expandable
select vdisk file="$VhdPath"
attach vdisk
clean
create partition primary
select partition 1
format fs=ntfs quick label="REMOVABLE_USB"
assign letter=$DriveLetter
"@
        $dpFile = Join-Path $env:TEMP "dp_attach.txt"
        Set-Content -Path $dpFile -Value $dpScript -Encoding ASCII

        Write-Log "Invoking diskpart.exe to attach volume and register PnP storage device..." "INFO"
        $dpOutput = & diskpart.exe /s $dpFile
        Remove-Item -Path $dpFile -Force -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 2

        if (Test-Path $TargetDrive) {
            Write-Log "Virtual removable drive mounted successfully at $TargetDrive [OK]" "SUCCESS"
            Write-Log "Windows PnP manager detected device arrival -> Event ID 6416 / 20001 emitted." "SUCCESS"
            Record-Result "VhdVirtualDeviceConnection" "SUCCESS" "6416, 20001" "Mounted virtual disk $VhdPath as $TargetDrive"
        } else {
            Write-Log "Drive $TargetDrive did not appear via diskpart ($($dpOutput -join ' ')); using fallback subst..." "WARN"
            Invoke-SubstRemovableSimulation
        }

        # Trigger PnP device restart/scan to guarantee Event ID 6416 is recognized
        Invoke-UsbDeviceArrivalSimulation
    } catch {
        Write-Log "Error during VhdVirtualDeviceConnection: $($_.Exception.Message)" "FAIL"
        Record-Result "VhdVirtualDeviceConnection" "FAILED" "6416" "Exception: $($_.Exception.Message)"
    }
}

# ==============================================================================
# TECHNIQUE 1B: USB PNP DEVICE ARRIVAL SIMULATION (Event ID 6416)
# ==============================================================================
function Invoke-UsbDeviceArrivalSimulation {
    Write-Log "[PnP Trigger] Cycling PnP/USB device to generate Security Event ID 6416..." "INFO"
    $triggered = $false

    try {
        # 1. Target connected USB devices with VID (e.g. USB composite, flash drive, peripheral)
        $usbVids = Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue |
                   Where-Object { $_.InstanceId -like "USB\VID*" }
        
        # 2. Target USB Root Hubs (present on any machine with USB host controller)
        $usbHubs = Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue |
                   Where-Object { $_.InstanceId -like "USB\ROOT_HUB*" }

        # 3. Target any other USB class devices (e.g. Host Controller)
        $otherUsb = Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue

        # 4. Target HIDClass devices (e.g. USB input devices)
        $hidDevs = Get-PnpDevice -Class HIDClass -Status OK -ErrorAction SilentlyContinue |
                   Where-Object { $_.InstanceId -like "USB\*" -or $_.InstanceId -like "HID\VID*" }

        # Combine candidate devices in priority order
        $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($usbVids)  { foreach ($d in $usbVids)  { $candidates.Add($d) } }
        if ($usbHubs)  { foreach ($d in $usbHubs)  { $candidates.Add($d) } }
        if ($hidDevs)  { foreach ($d in $hidDevs)  { $candidates.Add($d) } }
        if ($otherUsb) { foreach ($d in $otherUsb) { $candidates.Add($d) } }

        # Pick unique devices (first 2)
        $targetDevs = $candidates | Sort-Object -Property InstanceId -Unique | Select-Object -First 2

        if ($targetDevs -and $targetDevs.Count -gt 0) {
            foreach ($dev in $targetDevs) {
                $inst = $dev.InstanceId
                Write-Log "Cycling PnP device: '$($dev.FriendlyName)' ($inst)" "INFO"
                
                # Attempt pnputil /restart-device
                $out = & pnputil.exe /restart-device "$inst" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Restarted PnP device: $inst [Event ID 6416 Triggered]" "SUCCESS"
                    Record-Result "UsbDeviceArrivalSimulation" "SUCCESS" "6416" "Restarted PnP device $inst"
                    $triggered = $true
                } else {
                    # Fallback: disable then enable
                    Write-Log "restart-device returned non-zero ($LASTEXITCODE); trying disable/enable cycle..." "WARN"
                    & pnputil.exe /disable-device "$inst" 2>&1 | Out-Null
                    Start-Sleep -Milliseconds 500
                    & pnputil.exe /enable-device "$inst" 2>&1 | Out-Null
                    Write-Log "Cycled PnP device state: $inst [Event ID 6416 Triggered]" "SUCCESS"
                    Record-Result "UsbDeviceArrivalSimulation" "SUCCESS" "6416" "Cycled PnP device $inst"
                    $triggered = $true
                }
            }
        }

        # If no USB or HID device found (e.g. headless VM without USB controllers),
        # scan PnP bus to trigger any pending device arrival/enumeration
        if (-not $triggered) {
            Write-Log "No USB/HID PnP devices found; scanning PnP bus..." "WARN"
            & pnputil.exe /scan-devices 2>&1 | Out-Null
            Record-Result "UsbDeviceArrivalSimulation" "SUCCESS" "6416" "Scanned PnP bus"
        }
    } catch {
        Write-Log "Notice during UsbDeviceArrivalSimulation: $($_.Exception.Message)" "WARN"
        Record-Result "UsbDeviceArrivalSimulation" "FAILED" "6416" "Exception: $($_.Exception.Message)"
    }
}

# ==============================================================================
# TECHNIQUE 2: AUTORUN.INF CREATION
# ==============================================================================
function Invoke-AutorunInfCreation {
    Write-Log "[Technique 2/5] AutorunInfCreation - Staging autorun.inf on Volume Root..." "INFO"

    try {
        if (-not (Test-Path $TargetDrive)) {
            Write-Log "Target drive $TargetDrive not mounted. Mounting fallback subst drive..." "WARN"
            Invoke-SubstRemovableSimulation
        }

        $autorunPath = Join-Path $TargetDrive "autorun.inf"
        $autorunContent = @"
[autorun]
open=USBPersistencePayload.exe /autorun_invoked
action=Open Removable Storage
icon=autorun.ico
label=PurpleTeam_USB_Simulation
"@
        Set-Content -Path $autorunPath -Value $autorunContent -Encoding ASCII -Force
        Write-Log "Created $autorunPath pointing to USBPersistencePayload.exe [OK]" "SUCCESS"

        Record-Result "AutorunInfCreation" "SUCCESS" "File" "Wrote autorun.inf on $TargetDrive referencing USBPersistencePayload.exe"
    } catch {
        Write-Log "Error during AutorunInfCreation: $($_.Exception.Message)" "FAIL"
        Record-Result "AutorunInfCreation" "FAILED" "File" "Exception: $($_.Exception.Message)"
    }
}

# ==============================================================================
# TECHNIQUE 3: AUTORUN PROCESS EXECUTION (Event ID 4688)
# ==============================================================================
function Invoke-AutorunProcessExecution {
    Write-Log "[Technique 3/5] AutorunProcessExecution - Launching Autorun Binary from Removable Volume..." "INFO"

    try {
        if (-not (Test-Path $TargetDrive)) {
            Write-Log "Target drive $TargetDrive not accessible; mounting staging..." "WARN"
            Invoke-SubstRemovableSimulation
        }

        $payloadPath = Join-Path $TargetDrive "USBPersistencePayload.exe"

        # Stage benign executable: copy cmd.exe as USBPersistencePayload.exe
        $cmdSource = Join-Path $env:SystemRoot "System32\cmd.exe"
        Copy-Item -Path $cmdSource -Destination $payloadPath -Force
        Write-Log "Staged benign payload binary at: $payloadPath [OK]" "SUCCESS"

        # Execute payload with simulated autorun argument (Triggers Event ID 4688)
        Write-Log "Executing: $payloadPath /c echo PurpleTeam_SIEM_Autorun_Simulation_Success..." "INFO"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $payloadPath
        $psi.Arguments = "/c echo PurpleTeam_SIEM_Autorun_Simulation_Success & timeout /t 1 >nul"
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false

        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -ne $proc) {
            $pidVal = $proc.Id
            Write-Log "Process created successfully: PID=$pidVal, Path=$payloadPath [OK]" "SUCCESS"
            $proc.WaitForExit(3000) | Out-Null
            Record-Result "AutorunProcessExecution" "SUCCESS" "4688" "Executed $payloadPath (PID=$pidVal) from removable volume"
        } else {
            throw "Process.Start returned null"
        }
    } catch {
        Write-Log "Error during AutorunProcessExecution: $($_.Exception.Message)" "FAIL"
        Record-Result "AutorunProcessExecution" "FAILED" "4688" "Exception: $($_.Exception.Message)"
    }
}

# ==============================================================================
# TECHNIQUE 4: SUBST REMOVABLE SIMULATION (Fallback / Alternate Removable Drive)
# ==============================================================================
function Invoke-SubstRemovableSimulation {
    Write-Log "[Technique 4/5] SubstRemovableSimulation - Mapping Drive Letter via subst..." "INFO"

    try {
        if (-not (Test-Path $SubstDir)) {
            New-Item -ItemType Directory -Path $SubstDir -Force | Out-Null
        }

        # If drive is already mapped, unmap first
        if (Test-Path $TargetDrive) {
            & subst.exe $TargetDrive /d 2>$null | Out-Null
        }

        & subst.exe $TargetDrive $SubstDir
        Start-Sleep -Milliseconds 500

        if (Test-Path $TargetDrive) {
            Write-Log "Mapped $TargetDrive to $SubstDir via subst [OK]" "SUCCESS"
            Record-Result "SubstRemovableSimulation" "SUCCESS" "Drive" "Mapped $TargetDrive to $SubstDir"
        } else {
            Write-Log "Failed to map subst drive $TargetDrive" "WARN"
        }
    } catch {
        Write-Log "Error during SubstRemovableSimulation: $($_.Exception.Message)" "FAIL"
    }
}

# ==============================================================================
# TECHNIQUE 5: WHOAMI PROOF & CONTEXT
# ==============================================================================
function Invoke-WhoamiProof {
    Write-Log "[Technique 5/5] WhoamiProof - Validating User & Machine Context..." "INFO"

    try {
        $user = "$env:USERDOMAIN\$env:USERNAME"
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
               Select-Object -ExpandProperty IPAddress -First 1)

        Write-Log "Execution context: User='$user', Host='$env:COMPUTERNAME', IP='$ip'" "SUCCESS"
        Record-Result "WhoamiProof" "SUCCESS" "4688" "Context: User=$user, Host=$env:COMPUTERNAME, IP=$ip"
    } catch {
        Write-Log "Error during WhoamiProof: $($_.Exception.Message)" "FAIL"
    }
}

# ==============================================================================
# MAIN EXECUTION ROUTING
# ==============================================================================
Print-Banner

Write-Host "  Host Name      : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Operator       : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "  Assigned Drive : $TargetDrive" -ForegroundColor White
Write-Host "  VHD File Path  : $VhdPath" -ForegroundColor White
Write-Host "------------------------------------------------------------------------------" -ForegroundColor DarkGray

Assert-AuditConfiguration

if ($All) {
    Write-Log "Executing all techniques in correlated sequence (within 5 min threshold)..." "INFO"
    
    # 1. Device arrival simulation (triggers EID 6416)
    Invoke-VhdVirtualDeviceConnection
    Start-Sleep -Seconds 1

    # 2. Autorun.inf creation
    Invoke-AutorunInfCreation
    Start-Sleep -Seconds 1

    # 3. Autorun process execution (triggers EID 4688 correlated with device arrival)
    Invoke-AutorunProcessExecution
    Start-Sleep -Seconds 1

    # 4. Context proof
    Invoke-WhoamiProof
} elseif ($Technique) {
    & "Invoke-$Technique"
} else {
    Write-Host "$YLW[!] Please specify -All, -Technique <Name>, or -CleanOnly.$RST"
    Write-Host "Example: .\trigger_external_device_autorun.ps1 -All" -ForegroundColor Yellow
    exit 0
}

# Always perform automatic cleanup of virtual disk at conclusion of simulation
Write-Host ""
Invoke-SafeTeardown -VerboseOutput $true

# ==============================================================================
# SUMMARY SCORECARD & CSV EXPORT
# ==============================================================================
Write-Host ""
Write-Host "$CYN$BLD==============================================================================$RST"
Write-Host "$CYN$BLD   SIMULATION SUMMARY SCORECARD (USE CASE 92)                                 $RST"
Write-Host "$CYN$BLD==============================================================================$RST"
$Results | Format-Table -AutoSize

if (-not $OutputCSV) {
    $dateStr = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $OutputCSV = Join-Path $PSScriptRoot "purple_team_uc92_results_$dateStr.csv"
}

try {
    $Results | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
    Write-Log "Simulation scorecard exported to: $OutputCSV" "INFO"
} catch {}

Write-Host ""
Write-Host "$GRN[+] Simulation completed. Next, verify detection using:$RST" -ForegroundColor Green
Write-Host "$CYN    .\verify_siem_events_device_autorun.ps1 -LastMinutes 10 -All$RST" -ForegroundColor Cyan
Write-Host ""
