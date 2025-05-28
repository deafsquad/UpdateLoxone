<#
.SYNOPSIS
Automatically checks for Loxone Config updates, downloads, installs them, and updates MSs.

.DESCRIPTION
This script performs the following actions:
- Checks for the latest Loxone Config version from the official update XML.
- Compares the latest version with the currently installed version.
- If an update is needed:
  - Downloads the update ZIP file.
  - Verifies the download using CRC32 checksum and file size.
  - Extracts the installer.
  - Verifies the installers digital signature.
  - Optionally closes running Loxone applications (Config, Monitor, LiveView).
  - Runs the installer silently.
  - Updates all MSs listed in a configuration file.
- Provides notifications to logged-in users about the update status.
- Logs all actions to a file.
- Can be run interactively or as a scheduled task.

.PARAMETER Channel
Specifies the update channel ('Test' or 'Public'). Defaults to 'Test'.

.PARAMETER DebugMode
Enables verbose debug logging to the console and log file.

.PARAMETER EnableCRC
Enables CRC32 checksum verification for the downloaded ZIP file. Defaults to $true.

.PARAMETER InstallMode
Specifies the installer mode ('silent' or 'verysilent'). Defaults to 'verysilent'.

.PARAMETER CloseApplications
If specified, attempts to close Loxone Config, Monitor, and LiveView before installation.

.PARAMETER ScriptSaveFolder
Specifies the directory where the script saves downloads and logs. Defaults to the script's directory or "$env:USERPROFILE\UpdateLoxone".

.PARAMETER MaxLogFileSizeMB
The maximum size in MB for the log file before rotation. Defaults to 1 MB.

.PARAMETER ScheduledTaskIntervalMinutes
The interval in minutes for the scheduled task repetition. Defaults to 10. Used only during task registration.

.PARAMETER RegisterTask
If specified, the script will register/update the scheduled task and then exit. Requires Admin rights.

.PARAMETER SkipUpdateIfAnyProcessIsRunning
If specified, the script will skip the update if Loxone Config, Monitor, or LiveView is detected running, instead of closing them (even if -CloseApplications is set).

.EXAMPLE
.\UpdateLoxone.ps1 -Channel Public -DebugMode

.EXAMPLE
.\UpdateLoxone.ps1 -CloseApplications

.EXAMPLE
- Uses the BurntToast module for notifications. Installs it if not present (requires internet).
- MS list file ('UpdateLoxoneMSList.txt') should be in the ScriptSaveFolder, containing one entry per line (e.g., user:pass@192.168.1.77 or 192.168.1.78).
- Ensure the UpdateLoxoneUtils.psm1 module is in the same directory as this script.
#>
[CmdletBinding()]
param(
    [ValidateSet('Test', 'Public')]
    [string]$Channel = "Test",
    [switch]$DebugMode,
    [bool]$EnableCRC = $true, # Changed back to bool with default
    [ValidateSet('SILENT', 'VERYSILENT')] # Changed to uppercase to match InnoSetup standard, ValidateSet is case-insensitive by default
    [string]$InstallMode = "SILENT",    # Changed default
    [switch]$CloseApplications,
    [string]$ScriptSaveFolder = $null, # Default determined later
    [int]$MaxLogFileSizeMB = 1,
    [int]$ScheduledTaskIntervalMinutes = 10,
    [switch]$RegisterTask, # New switch to trigger task registration
    [switch]$SkipUpdateIfAnyProcessIsRunning, # New switch
    [bool]$UpdateLoxoneApp = $true, # Changed back to bool with default
    [ValidateSet('Test', 'Beta', 'Release', 'Internal', 'InternalV2', 'Latest')]
    [string]$UpdateLoxoneAppChannel = "Latest", # New parameter for App channel
    $PassedLogFile = $null, # Internal: Used when re-launching elevated to specify the log file
    [switch]$SkipCertificateCheck # New switch to bypass SSL/TLS certificate validation for MS connections
)
# XML Signature Verification Function removed - Test showed it's not feasible with current structure

$Global:PersistentToastInitialized = $false # Ensure toast is created fresh each run
# Determine script's own directory reliably
$script:MyScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:SystemRelaunchExitOccurred = $false # Flag to indicate if script is exiting due to system re-launch

# --- Early SYSTEM Context Check and Minimal Module Load for Re-launch ---
$script:IsRunningAsSystemEarlyCheck = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
$script:InitialSystemInvocation = $script:IsRunningAsSystemEarlyCheck -and (-not $PSBoundParameters.ContainsKey('PassedLogFile') -or [string]::IsNullOrWhiteSpace($PassedLogFile))

if ($script:InitialSystemInvocation) {
    Write-Host "INFO: (UpdateLoxone.ps1) Initial SYSTEM context detected. Performing minimal module load for re-launch." -ForegroundColor Yellow

    # Define minimal paths for essential modules
    $LoggingModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils\LoxoneUtils.Logging.psm1'
    $RunAsUserModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils\LoxoneUtils.RunAsUser.psm1'

    if (-not (Test-Path $LoggingModulePath)) {
        Write-Error "FATAL: Essential module LoxoneUtils.Logging.psm1 not found at '$LoggingModulePath'."
        exit 1
    }
    if (-not (Test-Path $RunAsUserModulePath)) {
        Write-Error "FATAL: Essential module LoxoneUtils.RunAsUser.psm1 not found at '$RunAsUserModulePath'."
        exit 1
    }

    # Minimal Log Setup for SYSTEM context re-launch
    $SystemLogDir = Join-Path -Path $PSScriptRoot -ChildPath "Logs" # Or a more appropriate SYSTEM log location
    if (-not (Test-Path -Path $SystemLogDir -PathType Container)) {
        try { New-Item -Path $SystemLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
        catch { Write-Error "FATAL: Failed to create SYSTEM log directory '$SystemLogDir'."; exit 1 }
    }
    $Global:LogFile = Join-Path -Path $SystemLogDir -ChildPath "UpdateLoxone_SYSTEM_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Add-Content -Path $Global:LogFile -Value "$(Get-Date -Format 'u') [INFO] SYSTEM context: Initializing for re-launch. LogFile: $Global:LogFile"

    try {
        Import-Module $LoggingModulePath -Force -ErrorAction Stop
        Import-Module $RunAsUserModulePath -Force -ErrorAction Stop
        Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) Minimal modules (Logging, RunAsUser) imported." -Level INFO
    } catch {
        $errMsg = "CRITICAL ERROR: (UpdateLoxone.ps1 - SYSTEM) Failed to import essential modules for re-launch. Error: $($_.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Red
        Add-Content -Path $Global:LogFile -Value "$(Get-Date -Format 'u') $errMsg -- Original Error Record: ($($_ | Out-String))"
        exit 1
    }

    # Re-launch Logic (copied and adapted from later in the script)
    Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) Attempting to re-launch as current user..." -Level INFO
    $forwardedArgs = @()
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -ne "WasLaunchedBySystem") {
            $value = $PSBoundParameters[$key]
            if ($value -is [switch]) {
                if ($value.IsPresent) { $forwardedArgs += "-$key" }
            } elseif ($null -ne $value) {
                $escapedValue = $value -replace '''', ''''''
                if ($value -match '[\s''`"]') { $forwardedArgs += "-$key '$escapedValue'" }
                else { $forwardedArgs += "-$key $value" }
            }
        }
    }
    # DO NOT pass -PassedLogFile, so the user process creates its own log.
    # $forwardedArgs += "-PassedLogFile '$($Global:LogFile -replace '''', '''''')'"

    $argumentString = $forwardedArgs -join " "
    $thisScriptPath = $MyInvocation.MyCommand.Definition

    Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) Re-launching '$thisScriptPath' as user with arguments: $argumentString" -Level DEBUG
    try {
        $powershellExePath = Get-Command powershell.exe | Select-Object -ExpandProperty Source
        $psArgsForUser = "-NoProfile -ExecutionPolicy Bypass -File `"$thisScriptPath`" $argumentString"
        Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) Re-launch command: '$powershellExePath' $psArgsForUser" -Level DEBUG
        Invoke-AsCurrentUser -FilePath $powershellExePath -Arguments $psArgsForUser -Visible:$false -Elevated:$true -ErrorAction Stop
        Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) Successfully initiated script re-launch in user session. Exiting SYSTEM process." -Level INFO
    } catch {
        Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) CRITICAL: Failed to re-launch script as user. Error: $($_.Exception.Message). Exiting SYSTEM process." -Level ERROR
        if ($Global:LogFile -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
            Invoke-LogFileRotation -LogFilePath $Global:LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue
        }
        $script:SystemRelaunchExitOccurred = $true # Set flag for main finally block
        exit 1
    }
    # If Invoke-AsCurrentUser succeeded, rotate the SYSTEM log now.
    if ($Global:LogFile -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
        Write-Log -Message "(UpdateLoxone.ps1 - SYSTEM) Re-launch successful. Rotating SYSTEM log: $Global:LogFile" -Level INFO
        Invoke-LogFileRotation -LogFilePath $Global:LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue
    }
    $script:SystemRelaunchExitOccurred = $true # Set flag for main finally block
    exit 0 # Exit SYSTEM process after successful re-launch initiation and its own log rotation
} else {
    # --- Full Module Load (Not initial SYSTEM invocation or already re-launched) ---
    Write-Host "INFO: (UpdateLoxone.ps1) Proceeding with full LoxoneUtils module manifest import." -ForegroundColor Cyan
    $UtilsModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils\LoxoneUtils.psd1'

    if (-not (Test-Path $UtilsModulePath)) {
        Write-Error "FATAL: Helper module manifest 'LoxoneUtils.psd1' not found at '$UtilsModulePath'. Script cannot continue."
        exit 1
    }

    # Attempt to forcefully remove any pre-existing LoxoneUtils modules to ensure a clean import
    Write-Host "INFO: (UpdateLoxone.ps1) Attempting to forcefully remove any existing LoxoneUtils modules before main import..." -ForegroundColor Cyan
    Get-Module -Name "LoxoneUtils*" | ForEach-Object {
        Write-Host "DEBUG: (UpdateLoxone.ps1) Removing pre-existing module: $($_.Name)" -ForegroundColor Gray
        Remove-Module -ModuleInfo $_ -Force -ErrorAction SilentlyContinue
    }

    # Import the main LoxoneUtils module using its manifest.
    Write-Host "INFO: (UpdateLoxone.ps1) Attempting to import LoxoneUtils manifest: '$UtilsModulePath'..." -ForegroundColor Cyan
    try {
        Import-Module $UtilsModulePath -Force -ErrorAction Stop -Verbose
        Write-Host "INFO: (UpdateLoxone.ps1) LoxoneUtils manifest import command completed." -ForegroundColor Cyan
        # Explicitly check if Write-Log is now available. This is a critical safeguard.
        if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            Write-Host "CRITICAL ERROR: (UpdateLoxone.ps1) Write-Log command is NOT available even after importing LoxoneUtils manifest. This suggests a profound problem within the LoxoneUtils module. Script cannot continue." -ForegroundColor Red
            exit 1
        }
        Write-Log -Message "(UpdateLoxone.ps1) Successfully loaded LoxoneUtils module via manifest. Write-Log is available." -Level INFO
    }
    catch {
        $errorMessage = "CRITICAL ERROR: (UpdateLoxone.ps1) Failed to import LoxoneUtils module manifest ('$UtilsModulePath'). Error details: $($_.Exception.Message)"
        Write-Host $errorMessage -ForegroundColor Red
        # Capture the full error record to a string first for safer inclusion in the log message
        $errorRecordString = $($_ | Out-String)
        # Attempt to log to a fallback file if $global:LogFile might have been set by a partial init
        if ($global:LogFile) { Add-Content -Path $global:LogFile -Value "$(Get-Date -Format 'u') $errorMessage -- Original Error Record: $errorRecordString" }
        else { Add-Content -Path (Join-Path $script:MyScriptRoot "UpdateLoxone_FallbackCritical.log") -Value "$(Get-Date -Format 'u') $errorMessage -- Original Error Record: $errorRecordString" }
        exit 1
    }

    # --- Sanitize PassedLogFile if provided (BEFORE Initialize-ScriptWorkflow) ---
    # This block is now part of the 'else' for full module load, as Write-Log is needed.
    if ($PSBoundParameters.ContainsKey('PassedLogFile') -and $null -ne $PassedLogFile) {
        Write-Log -Message "(UpdateLoxone.ps1) Initial PassedLogFile received: '$PassedLogFile'" -Level DEBUG
        $OriginalPassedLogFile = $PassedLogFile
        $CleanedLogFile = $PassedLogFile
        while ($CleanedLogFile.StartsWith("'") -and $CleanedLogFile.EndsWith("'") -and $CleanedLogFile.Length -ge 2) {
            $CleanedLogFile = $CleanedLogFile.Substring(1, $CleanedLogFile.Length - 2).Trim()
        }

        if ($CleanedLogFile -ne $OriginalPassedLogFile) {
            Write-Log -Message "(UpdateLoxone.ps1) Sanitized PassedLogFile from '$OriginalPassedLogFile' to '$CleanedLogFile'." -Level INFO
            $PassedLogFile = $CleanedLogFile
            $PSBoundParameters['PassedLogFile'] = $CleanedLogFile
        } else {
            Write-Log -Message "(UpdateLoxone.ps1) PassedLogFile '$OriginalPassedLogFile' did not require sanitization." -Level DEBUG
        }
    }

    # --- Initialize Script Workflow ---
    Write-Log -Message "(UpdateLoxone.ps1) Calling Initialize-ScriptWorkflow..." -Level INFO
    $scriptContext = Initialize-ScriptWorkflow -BoundParameters $PSBoundParameters -PSScriptRoot $script:MyScriptRoot -MyInvocation $MyInvocation
    if (-not $scriptContext.Succeeded) {
        Write-Log -Message "(UpdateLoxone.ps1) Initialize-ScriptWorkflow failed: $($scriptContext.Reason). Error: $($scriptContext.Error | Out-String)" -Level ERROR
        if (Get-Command Show-FinalStatusToast -ErrorAction SilentlyContinue) {
            Show-FinalStatusToast -StatusMessage "FATAL: Script initialization failed: $($scriptContext.Reason)" -Success $false -LogFileToShow $scriptContext.LogFile
        }
        exit 1
    }
    Write-Log -Message "(UpdateLoxone.ps1) Initialize-ScriptWorkflow completed. Reason: $($scriptContext.Reason)" -Level INFO

    # Handle specific reasons from Initialize-ScriptWorkflow
    # SystemRelaunchRequired should ideally not happen if this 'else' block is reached,
    # as the initial SYSTEM check should have handled it. But keep for robustness.
    if ($scriptContext.Reason -eq "SystemRelaunchRequired") {
        Write-Log -Message "(UpdateLoxone.ps1) SystemRelaunchRequired detected (unexpectedly after full module load). Attempting to re-launch as current user..." -Level WARN
        $forwardedArgs = @()
        foreach ($key in $PSBoundParameters.Keys) {
            if ($key -ne "WasLaunchedBySystem") {
                $value = $PSBoundParameters[$key]
                if ($value -is [switch]) {
                    if ($value.IsPresent) { $forwardedArgs += "-$key" }
                } elseif ($null -ne $value) {
                    $escapedValue = $value -replace '''', ''''''
                    if ($value -match '[\s''`"]') { $forwardedArgs += "-$key '$escapedValue'" }
                    else { $forwardedArgs += "-$key $value" }
                }
            }
        }
        if ($scriptContext.LogFile) {
            $forwardedArgs += "-PassedLogFile '$($scriptContext.LogFile -replace '''', '''''')'"
        }

        $argumentString = $forwardedArgs -join " "
        $thisScriptPath = $MyInvocation.MyCommand.Definition

        Write-Log -Message "(UpdateLoxone.ps1) Re-launching '$thisScriptPath' as user with arguments: $argumentString" -Level DEBUG
        try {
            $powershellExePath = Get-Command powershell.exe | Select-Object -ExpandProperty Source
            $psArgsForUser = "-NoProfile -ExecutionPolicy Bypass -File `"$thisScriptPath`" $argumentString"
            Write-Log -Message "(UpdateLoxone.ps1) Re-launch command: '$powershellExePath' $psArgsForUser" -Level DEBUG
            Invoke-AsCurrentUser -FilePath $powershellExePath -Arguments $psArgsForUser -Visible:$false -Elevated:$true -ErrorAction Stop
            Write-Log -Message "(UpdateLoxone.ps1) Successfully initiated script re-launch in user session. Exiting process." -Level INFO
        } catch {
            Write-Log -Message "(UpdateLoxone.ps1) CRITICAL: Failed to re-launch script as user (from full load context). Error: $($_.Exception.Message). Exiting process." -Level ERROR
            if ($scriptContext.LogFile -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
                Invoke-LogFileRotation -LogFilePath $scriptContext.LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue
            }
            $script:SystemRelaunchExitOccurred = $true
            exit 1
        }
        $script:SystemRelaunchExitOccurred = $true
        exit 0
    }
} # End of the main 'else' block for full module load vs minimal SYSTEM load

if ($scriptContext.Reason -eq "ActionRegisterTaskAndExit") {
    Write-Log -Message "(UpdateLoxone.ps1) -RegisterTask specified and confirmed by Initialize-ScriptWorkflow." -Level INFO
    if (-not $scriptContext.IsAdminRun) {
        Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Task registration requested via -RegisterTask, but script is not running as Admin. Please re-run as Admin."
        Show-FinalStatusToast -StatusMessage "Task registration requires Admin rights." -Success $false -LogFileToShow $scriptContext.LogFile
        exit 1
    }
    Write-Log -Message "(UpdateLoxone.ps1) Attempting to register/update scheduled task '$($scriptContext.TaskName)'..." -Level INFO
    try {
        Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition -TaskName $scriptContext.TaskName -ScheduledTaskIntervalMinutes $scriptContext.Params.ScheduledTaskIntervalMinutes -ErrorAction Stop
        Write-Log -Message "(UpdateLoxone.ps1) Task '$($scriptContext.TaskName)' registration/update successful. Exiting script." -Level INFO
        Show-FinalStatusToast -StatusMessage "Scheduled task '$($scriptContext.TaskName)' registered/updated." -Success $true -LogFileToShow $scriptContext.LogFile
        exit 0
    } catch {
        $taskRegErrorMsg = "(UpdateLoxone.ps1) Failed to register/update task '$($scriptContext.TaskName)': $($_.Exception.Message)"
        Write-Log -Message $taskRegErrorMsg -Level ERROR
        Write-Log -Message "Error Record: ($($_ | Out-String))" -Level DEBUG
        Show-FinalStatusToast -StatusMessage $taskRegErrorMsg -Success $false -LogFileToShow $scriptContext.LogFile
        exit 1
    }
}

if ($scriptContext.IsInteractive -and -not $scriptContext.IsAdminRun -and -not $scriptContext.IsRunningAsSystem -and -not $scriptContext.Params.RegisterTask) {
    Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Checking if task '$($scriptContext.TaskName)' needs registration (interactive, non-admin)."
    if (-not (Test-ScheduledTask -TaskName $scriptContext.TaskName -ErrorAction SilentlyContinue)) {
        Write-Log -Message "(UpdateLoxone.ps1) Task '$($scriptContext.TaskName)' not found or inaccessible. Interactive non-admin run. Suggesting elevation or -RegisterTask." -Level INFO
        Write-Host "INFO: (UpdateLoxone.ps1) Scheduled task '$($scriptContext.TaskName)' is not registered. To set it up, please run this script as Administrator with the -RegisterTask switch." -ForegroundColor Yellow
    }
}

$Global:PersistentToastInitialized = $false 
$script:ErrorOccurred = $false 
$script:LastErrorLine = 0

$scriptGlobalState = [pscustomobject]@{
    CurrentWeight    = 0
    TotalWeight      = 0 
    currentStep      = 0 
    totalSteps       = 1 
    currentDownload  = 0 
    totalDownloads   = 0 
    anyUpdatePerformed = $false 
    ErrorOccurred    = $false 
}
$scriptGlobalState.TotalWeight = $script:TotalWeight 
                                                 
                                                  

$UpdateTargetsInfo = @()


# --- Get Latest Version Info & Determine Update Needs ---
Write-Log -Message "(UpdateLoxone.ps1) Calling Get-LoxoneUpdatePrerequisites..." -Level INFO
$prerequisites = Get-LoxoneUpdatePrerequisites -WorkflowContext $scriptContext
if (-not $prerequisites.Succeeded) {
    Write-Log -Message "(UpdateLoxone.ps1) Get-LoxoneUpdatePrerequisites failed: $($prerequisites.Reason). Error: $($prerequisites.Error | Out-String)" -Level ERROR
    Show-FinalStatusToast -StatusMessage "FATAL: Failed to get update prerequisites: $($prerequisites.Reason)" -Success $false -LogFileToShow $scriptContext.LogFile
    exit 1
}
Write-Log -Message "(UpdateLoxone.ps1) Get-LoxoneUpdatePrerequisites completed." -Level INFO

$scriptContext.Constants.InstallerFileName = $prerequisites.ConfigInstallerFileName
$scriptContext.Constants.ZipFileName = $prerequisites.ConfigZipFileName
$scriptContext.Constants.ZipFilePath = Join-Path -Path $scriptContext.DownloadDir -ChildPath $prerequisites.ConfigZipFileName
$scriptContext.Constants.InstallerPath = Join-Path -Path $scriptContext.DownloadDir -ChildPath $prerequisites.ConfigInstallerFileName


# --- Initialize Update Pipeline Data (Targets, Weights, Steps) ---
Write-Log -Message "(UpdateLoxone.ps1) Calling Initialize-UpdatePipelineData..." -Level INFO
$pipelineDataResult = Initialize-UpdatePipelineData -WorkflowContext $scriptContext -Prerequisites $prerequisites
if (-not $pipelineDataResult.Succeeded) {
    Write-Log -Message "(UpdateLoxone.ps1) Initialize-UpdatePipelineData failed: $($pipelineDataResult.Reason). Error: $($pipelineDataResult.Error | Out-String)" -Level ERROR
    Show-FinalStatusToast -StatusMessage "FATAL: Failed to initialize pipeline data: $($pipelineDataResult.Reason)" -Success $false -LogFileToShow $scriptContext.LogFile
    exit 1
}
Write-Log -Message "(UpdateLoxone.ps1) Initialize-UpdatePipelineData completed." -Level INFO

$UpdateTargetsInfo = $pipelineDataResult.UpdateTargetsInfo
Write-Host "DEBUG: (UpdateLoxone.ps1) After Initialize-UpdatePipelineData - UpdateTargetsInfo Count: $($UpdateTargetsInfo.Count)"
$itemNumDebugInit = 0
foreach ($itemDebug in $UpdateTargetsInfo) {
    Write-Host "DEBUG: (UpdateLoxone.ps1) After Initialize-UpdatePipelineData - Item #$itemNumDebugInit Type: $($itemDebug.Type) - Name: $($itemDebug.Name)"
    $itemNumDebugInit++
}
$script:TotalWeight = $pipelineDataResult.TotalWeight
$script:totalSteps = $pipelineDataResult.TotalSteps
$script:totalDownloads = $pipelineDataResult.TotalDownloads
$script:CurrentWeight = $pipelineDataResult.InitialCheckWeight

$scriptGlobalState.TotalWeight = $script:TotalWeight
$scriptGlobalState.totalSteps = $script:totalSteps
$scriptGlobalState.totalDownloads = $script:totalDownloads
$scriptGlobalState.CurrentWeight = $script:CurrentWeight 

Write-Log -Message "(UpdateLoxone.ps1) Pipeline Data Initialized - TotalWeight: $($script:TotalWeight), TotalSteps: $($script:totalSteps), TotalDownloads: $($script:totalDownloads)" -Level DEBUG


# --- Conditional Toast Initialization (After initial checks and context setup) ---
$anySoftwareUpdateNeeded = ($UpdateTargetsInfo | Where-Object { ($_.Type -eq "Config" -or $_.Type -eq "App") -and $_.UpdateNeeded }).Count -gt 0
$anyMSPotentiallyNeedingUpdate = ($UpdateTargetsInfo | Where-Object { $_.Type -eq "Miniserver" }).Count -gt 0 

if (-not $anySoftwareUpdateNeeded -and -not $anyMSPotentiallyNeedingUpdate -and -not $scriptContext.IsInteractive -and $scriptContext.IsSelfInvokedForUpdateCheck) {
    Write-Log -Message "(UpdateLoxone.ps1) No software updates needed, no MS to check (or list empty), and script is self-invoked non-interactively. Exiting cleanly." -Level INFO
    if ($scriptContext.LogFile) { Invoke-LogFileRotation -LogFilePath $scriptContext.LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue }
    exit 0
}

if ($anySoftwareUpdateNeeded -or $anyMSPotentiallyNeedingUpdate) {
    Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) ENTERING initial toast display block. anySoftwareUpdateNeeded: $anySoftwareUpdateNeeded, anyMSPotentiallyNeedingUpdate: $anyMSPotentiallyNeedingUpdate, IsRunningAsSystem: $($scriptContext.IsRunningAsSystem)"
    if (-not $scriptContext.IsRunningAsSystem) { 
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Not running as SYSTEM. Proceeding with Initialize-LoxoneToastAppId and initial toast."
        Initialize-LoxoneToastAppId 
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Initialize-LoxoneToastAppId CALLED. ResolvedToastAppId: $($script:ResolvedToastAppId)"
        Initialize-LoxoneToastAppId 
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Initialize-LoxoneToastAppId CALLED. ResolvedToastAppId: $($script:ResolvedToastAppId)"
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Preparing to call Update-PersistentToast (Initial). Global:PersistentToastInitialized is currently: $($Global:PersistentToastInitialized)"
        Write-Log -Level DEBUG -Message "Attempting to update progress toast (Initial Call in UpdateLoxone.ps1). Initialized: $($Global:PersistentToastInitialized)"
        Write-Log -Level DEBUG -Message "Simplified: Params for Update-PersistentToast (Initial Call)"
        
        Write-Log -Level DEBUG -Message "Preparing to call Update-PersistentToast (around line 365)."
        Write-Log -Level DEBUG -Message "Checking if Update-PersistentToast is a known command: $(Get-Command Update-PersistentToast -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)"
        Write-Log -Level DEBUG -Message "Value of script:CurrentWeight before call: $($script:CurrentWeight)"
        Write-Log -Level DEBUG -Message "Value of scriptContext.IsInteractive before call: $($scriptContext.IsInteractive)"
        Write-Log -Level DEBUG -Message "Value of script:ErrorOccurred before call: $($script:ErrorOccurred)" 
        Write-Log -Level DEBUG -Message "Value of scriptGlobalState.anyUpdatePerformed before call: $($scriptGlobalState.anyUpdatePerformed)" 
        Write-Log -Level DEBUG -Message "Value of scriptContext.IsSelfInvokedForUpdateCheck before call: $($scriptContext.IsSelfInvokedForUpdateCheck)"
        Write-Log -Level DEBUG -Message "Value of script:TotalWeight before call: $($script:TotalWeight)"
        Write-Log -Level DEBUG -Message "Value of script:ResolvedToastAppId (used internally by BurntToast via Initialize-LoxoneToastAppId): $($script:ResolvedToastAppId)"

        Write-Log -Level DEBUG -Message "DEBUGGER: Preparing for Update-PersistentToast (pre-check toast)."
        Write-Log -Level DEBUG -Message "DEBUGGER: Value of scriptGlobalState.anyUpdatePerformed before call: '$($scriptGlobalState.anyUpdatePerformed)' (Type: $($scriptGlobalState.anyUpdatePerformed.GetType().FullName))"
        Write-Log -Level DEBUG -Message "DEBUGGER: Value of LoxoneConfigAppId before call (intended): '$($LoxoneConfigAppId)' (Note: This variable might not be scoped here. Check $script:ResolvedToastAppId or $env:LoxoneConfigAppId for toast context)"
        Write-Log -Level DEBUG -Message "DEBUGGER: Value of script:ResolvedToastAppId before call (actual for BurntToast init): '$($script:ResolvedToastAppId)'"
        Write-Log -Level DEBUG -Message "DEBUGGER: Value of scriptGlobalState.PreCheckToastTitle before call: '$($scriptGlobalState.PreCheckToastTitle)' (Note: This specific call may not use this parameter)"
        Write-Log -Level DEBUG -Message "DEBUGGER: Value of scriptGlobalState.PreCheckToastMessage before call: '$($scriptGlobalState.PreCheckToastMessage)' (Note: This specific call may not use this parameter)"
        Write-Log -Level DEBUG -Message "DEBUGGER: Checking command for Update-PersistentToast (subexpression removed for testing)"
Write-Log -Message "(UpdateLoxone.ps1) MAIN SCRIPT: Logging before Update-PersistentToast call (Initial Toast around line 381)." -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   script:CurrentWeight = $($script:CurrentWeight)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   script:TotalWeight = $($script:TotalWeight)" -Level DEBUG
        $statusTextForLogUpdateLoxoneInitial = "Initial Toast (No explicit step name)" 
        Write-Log -Message "(UpdateLoxone.ps1)   Constructed StatusText (Initial Toast) = '$statusTextForLogUpdateLoxoneInitial'" -Level DEBUG
        $progressValueForLogUpdateLoxoneInitial = if ($script:TotalWeight -gt 0) { [Math]::Round(($script:CurrentWeight / $script:TotalWeight) * 100) } else { 0 }
        Write-Log -Message "(UpdateLoxone.ps1)   Calculated ProgressValue (Initial Toast percentage) = $progressValueForLogUpdateLoxoneInitial %" -Level DEBUG
        try {
            Write-Log -Level DEBUG -Message "Attempting Update-PersistentToast call (around line 365)..."
            Write-Log -Level DEBUG -Message "DEBUGGER: Update-PersistentToast -AnyUpdatePerformed will be set to false (literal)"
            Update-PersistentToast -IsInteractive ([bool]$scriptContext.IsInteractive) -ErrorOccurred ([bool]$script:ErrorOccurred) -AnyUpdatePerformed ([bool]$false) -CallingScriptIsInteractive ([bool]$scriptContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$scriptContext.IsSelfInvokedForUpdateCheck) -CurrentWeight $script:CurrentWeight -TotalWeight $script:TotalWeight
            Write-Log -Level DEBUG -Message "Update-PersistentToast call (around line 365) completed without PowerShell error."
        }
        catch {
            Write-Log -Level ERROR -Message "ERROR during Update-PersistentToast call (around line 365): $($_.Exception.ToString())"
        }
                Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Update-PersistentToast (Initial) instrumentation block finished. Current Global:PersistentToastInitialized after call: $Global:PersistentToastInitialized"
            }

    # Set current step to 1 for the initial "Checks Complete" toast
    $script:currentStep = 1
    if ($null -ne $scriptGlobalState -and $scriptGlobalState.PSObject.Properties.Name -contains 'currentStep') {
        $scriptGlobalState.currentStep = 1
    }
    Write-Log -Message "(UpdateLoxone.ps1) Set currentStep to 1 for initial UI display (script:currentStep = $($script:currentStep), scriptGlobalState.Value.currentStep = $($scriptGlobalState.Value.currentStep))." -Level DEBUG

    $initialCheckStepName = "Initial Checks Complete. Updates Pending."
    Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Updating toast for step $($script:currentStep)/$($script:totalSteps): $initialCheckStepName. Current Global:PersistentToastInitialized: $Global:PersistentToastInitialized"
    if ($Global:PersistentToastInitialized) {
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Global:PersistentToastInitialized is TRUE. Preparing for Update-PersistentToast (Second call for initial check step)."
        Write-Log -Level DEBUG -Message "Intent: Update toast with initial check step name: '$initialCheckStepName'."
        Write-Log -Level DEBUG -Message "Relevant state: script:currentStep='$($script:currentStep)', script:totalSteps='$($script:totalSteps)', script:CurrentWeight='$($script:CurrentWeight)', script:TotalWeight='$($script:TotalWeight)', scriptGlobalState.PersistentToastInitialized='$($Global:PersistentToastInitialized)' (expected true)."
        Write-Log -Level DEBUG -Message ("All parameters for Update-PersistentToast (Second call): StepNumber='$($script:currentStep)', TotalSteps='$($script:totalSteps)', StepName='$($initialCheckStepName)', CurrentWeight='$($script:CurrentWeight)', TotalWeight='$($script:TotalWeight)', IsInteractive='$($scriptContext.IsInteractive)', ErrorOccurred='$($script:ErrorOccurred)', AnyUpdatePerformed='$($scriptGlobalState.anyUpdatePerformed)', CallingScriptIsInteractive='$($scriptContext.IsInteractive)', CallingScriptIsSelfInvoked='$($scriptContext.IsSelfInvokedForUpdateCheck)'")
        
Write-Log -Message "(UpdateLoxone.ps1) MAIN SCRIPT: Logging before Update-PersistentToast call (Second Initial Toast / Initial Checks Complete)." -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   script:currentStep = $($script:currentStep)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   script:totalSteps = $($script:totalSteps)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   script:CurrentWeight = $($script:CurrentWeight)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   script:TotalWeight = $($script:TotalWeight)" -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   toastParamsForSecondCall.StepName = '$($initialCheckStepName)' (derived from variable)" -Level DEBUG
        $statusTextForLogUpdateLoxoneSecond = "Step $($script:currentStep)/$($script:totalSteps): $initialCheckStepName"
        Write-Log -Message "(UpdateLoxone.ps1)   Constructed StatusText (Second Initial Toast) = '$statusTextForLogUpdateLoxoneSecond'" -Level DEBUG
        $progressValueForLogUpdateLoxoneSecond = if ($script:TotalWeight -gt 0) { [Math]::Round(($script:CurrentWeight / $script:TotalWeight) * 100) } else { 0 }
        Write-Log -Message "(UpdateLoxone.ps1)   Calculated ProgressValue (Second Initial Toast percentage) = $progressValueForLogUpdateLoxoneSecond %" -Level DEBUG
        try {
            Write-Log -Level DEBUG -Message "Attempting Update-PersistentToast call (Second call for initial check step)..."
            $toastParamsForSecondCall = @{
                StepNumber                 = $script:currentStep
                TotalSteps                 = $script:totalSteps
                StepName                   = $initialCheckStepName
                CurrentWeight              = $script:CurrentWeight
                TotalWeight                = $script:TotalWeight
                IsInteractive              = ([bool]$scriptContext.IsInteractive)
                ErrorOccurred              = ([bool]$script:ErrorOccurred)
                AnyUpdatePerformed         = $false 
                CallingScriptIsInteractive = ([bool]$scriptContext.IsInteractive)
                CallingScriptIsSelfInvoked = ([bool]$scriptContext.IsSelfInvokedForUpdateCheck)
            }
            Update-PersistentToast @toastParamsForSecondCall
            Write-Log -Level DEBUG -Message "Update-PersistentToast (Second call for initial check step) completed without PowerShell error."
        }
        catch {
            Write-Log -Level ERROR -Message "ERROR during Update-PersistentToast (Second call for initial check step): $($_.Exception.ToString())"
        }
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Update-PersistentToast (Second call for initial check step) instrumentation block finished. Current Global:PersistentToastInitialized: $Global:PersistentToastInitialized"
    } else { 
        Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Global:PersistentToastInitialized is FALSE after initial attempt. Second toast update SKIPPED for step: $initialCheckStepName."
    } 

} 
else { 
    Write-Log -Level INFO -Message "(UpdateLoxone.ps1) No software updates needed and no MS to check. Skipping initial toast display block."
} 
# --- Main Pipeline Definition ---
$scriptGlobalState.TotalWeight = $script:TotalWeight 
$scriptGlobalState.totalSteps = $script:totalSteps 
$scriptGlobalState.currentDownload = $script:currentDownload 
$scriptGlobalState.totalDownloads = $script:totalDownloads 


# --- Main Pipeline Definition ---
$steps = @(
    @{
        Name      = "Download Loxone Config"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            $foundConfigTargetNeedingUpdate = $false
            foreach ($targetItem in $UpdateTargetsInfoArg) {
                if ($targetItem.Type -eq "Config" -and ($targetItem.UpdateNeeded -eq $true -or $targetItem.UpdateNeeded -eq "True")) {
                    $foundConfigTargetNeedingUpdate = $true
                    break
                }
            }
            return $foundConfigTargetNeedingUpdate
        }
        Run       = {
            param($scriptCtx, $targets, $globalStateRef)
            $cfgTarget = $targets | Where-Object {$_.Type -eq "Config"} | Select-Object -First 1
            Invoke-DownloadLoxoneConfig -WorkflowContext $scriptCtx -ConfigTargetInfo $cfgTarget -ScriptGlobalState $globalStateRef
        }
        Component = "Config"
    },
    @{
        Name      = "Extract Loxone Config"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            $foundConfigTargetForExtract = $false
            foreach ($targetItem in $UpdateTargetsInfoArg) {
                if ($targetItem.Type -eq "Config" -and ($targetItem.UpdateNeeded -eq $true -or $targetItem.UpdateNeeded -eq "True") -and $targetItem.Status -ne "UpdateFailed (Download)") {
                    $foundConfigTargetForExtract = $true
                    break
                }
            }
            return $foundConfigTargetForExtract
        }
        Run       = {
            param($scriptCtx, $targets, $globalStateRef)
            $globalStateRef.Value.currentStep++
            $cfgTarget = $targets | Where-Object {$_.Type -eq "Config"} | Select-Object -First 1
            Invoke-ExtractLoxoneConfig -WorkflowContext $scriptCtx -ConfigTargetInfo $cfgTarget -ScriptGlobalState $globalStateRef
        }
        Component = "Config"
    },
    @{
        Name      = "Install Loxone Config"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            $foundConfigTargetForInstall = $false
            foreach ($targetItem in $UpdateTargetsInfoArg) {
                if ($targetItem.Type -eq "Config" -and ($targetItem.UpdateNeeded -eq $true -or $targetItem.UpdateNeeded -eq "True") -and $targetItem.Status -ne "UpdateFailed (Download)" -and $targetItem.Status -ne "UpdateFailed (Extraction)") {
                    $foundConfigTargetForInstall = $true
                    break
                }
            }
            return $foundConfigTargetForInstall
        }
        Run       = {
            param($scriptCtx, $targets, $globalStateRef)
            $globalStateRef.Value.currentStep++
            $cfgTarget = $targets | Where-Object {$_.Type -eq "Config"} | Select-Object -First 1
            Invoke-InstallLoxoneConfig -WorkflowContext $scriptCtx -ConfigTargetInfo $cfgTarget -ScriptGlobalState $globalStateRef
        }
        Component = "Config"
    },
# Loxone App Update Steps
    @{
        Name      = "Download Loxone App"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            Write-Host "DEBUG: (UpdateLoxone.ps1) [ShouldRun Write-Host - DownloadApp] Entered ShouldRun. PrerequisitesArg.AppUpdateNeeded: '$($prerequisitesArg.AppUpdateNeeded)' (Type: $($prerequisitesArg.AppUpdateNeeded.GetType().FullName))"
            return $prerequisitesArg.AppUpdateNeeded
        }
        Run       = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            Write-Host "DEBUG: (UpdateLoxone.ps1) Run - DownloadApp - Count of items in UpdateTargetsInfoArg: $($UpdateTargetsInfoArg.Count)"
            Write-Host "DEBUG: (UpdateLoxone.ps1) Run - DownloadApp - Type of UpdateTargetsInfoArg: $($UpdateTargetsInfoArg.GetType().FullName)"
            $itemNum = 0
            foreach ($item in $UpdateTargetsInfoArg) {
                Write-Host "DEBUG: (UpdateLoxone.ps1) Run - DownloadApp - Item #$itemNum Type: $($item.Type)"
                Write-Host "DEBUG: (UpdateLoxone.ps1) Run - DownloadApp - Item #$itemNum Full Object: $($item | Out-String)"
                $itemNum++
            }
            $appTarget = $UpdateTargetsInfoArg | Where-Object {$_.Type -eq "App"} | Select-Object -First 1
            if (-not $appTarget) { Write-Host "ERROR: (UpdateLoxone.ps1) Run - DownloadApp - AppTarget not found in UpdateTargetsInfoArg (after detailed logging)!" }
            else { Write-Host "DEBUG: (UpdateLoxone.ps1) Run - DownloadApp - AppTarget FOUND: $($appTarget | Out-String)" }
            Invoke-DownloadLoxoneApp -WorkflowContext $scriptCtxArg -AppTargetInfo $appTarget -ScriptGlobalState $globalStateRefArg
        }
        Component = "App"
        },
        @{
            Name      = "Install Loxone App"
            ShouldRun = {
                param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
                $appTarget = $null
                foreach ($item_app_install in $UpdateTargetsInfoArg) {
                    if ($item_app_install.Type -eq "App") {
                        $appTarget = $item_app_install
                        break
                    }
                }
                # Write-Host "DEBUG: (UpdateLoxone.ps1) [ShouldRun - InstallApp] AppUpdateNeeded: '$($prerequisitesArg.AppUpdateNeeded)', AppTarget Status: '$($appTarget.Status)'"
                $shouldRunInstall = $false
                if ($prerequisitesArg.AppUpdateNeeded) {
                    if ($appTarget) {
                        if ($appTarget.Status -notlike "*Failed*" -or $appTarget.Status -eq "DownloadSkippedExistingValid") {
                            $shouldRunInstall = $true
                        }
                    } else { # App not initially present, but update is flagged as needed
                        $shouldRunInstall = $true
                    }
                }
                return $shouldRunInstall
            }
            Run       = {
                param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
                $appTarget = $UpdateTargetsInfoArg | Where-Object {$_.Type -eq "App"} | Select-Object -First 1
                if (-not $appTarget) { Write-Host "ERROR: (UpdateLoxone.ps1) Run - InstallApp - AppTarget not found in UpdateTargetsInfoArg (this might be okay if app wasn't installed and download step ran based on prerequisites)!" }
                Invoke-InstallLoxoneApp -WorkflowContext $scriptCtxArg -AppTargetInfo $appTarget -ScriptGlobalState $globalStateRefArg
            }
            Component = "App"
        },
    # Miniserver Check & Update Steps
    @{
        Name      = "Check Miniserver Versions"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            $foundMiniserver = $false
            foreach ($item_ms_check in $UpdateTargetsInfoArg) {
                if ($item_ms_check.Type -eq "Miniserver") {
                    $foundMiniserver = $true
                    break
                }
            }
            return $foundMiniserver
        }
        Run       = {
            param($scriptCtx, $targets, $globalStateRef, $prereqs)
            Invoke-CheckMiniserverVersions -WorkflowContext $scriptCtx -Prerequisites $prereqs -UpdateTargetsToUpdate $targets -ScriptGlobalState $globalStateRef
        }
        Component = "MiniserverCheck"
    },
    @{
        Name      = "Update Miniservers"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            $foundMiniserverNeedingUpdate = $false
            foreach ($item_ms_update in $UpdateTargetsInfoArg) {
                if ($item_ms_update.Type -eq "Miniserver" -and ($item_ms_update.UpdateNeeded -eq $true -or $item_ms_update.UpdateNeeded -eq "True")) {
                    $foundMiniserverNeedingUpdate = $true
                    break
                }
            }
            return $foundMiniserverNeedingUpdate
        }
        Run       = {
            param($scriptCtx, $targets, $globalStateRef, $prereqs)
            Invoke-UpdateMiniserversInBulk -WorkflowContext $scriptCtx -Prerequisites $prereqs -UpdateTargetsToUpdate $targets -ScriptGlobalState $globalStateRef
        }
        Component = "MiniserverUpdate"
    }
)
# --- Enter Script Scope & Log Start (Moved after full initialization) ---
Enter-Function -FunctionName (Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf) -FilePath $PSCommandPath -LineNumber $MyInvocation.ScriptLineNumber
Write-Log -Message "Script main execution starting. PID: $PID. IsElevated: $($scriptContext.IsElevatedInstance). IsSystem: $($scriptContext.IsRunningAsSystem). IsInteractive: $($scriptContext.IsInteractive)" -Level DEBUG

# Main Execution Block (Outer Try/Catch for pipeline)
try {
    Write-Log -Message "Starting main update pipeline... Number of defined steps: $($steps.Count)" -Level INFO

    Write-Host "DEBUG: (UpdateLoxone.ps1) BEFORE step loop - UpdateTargetsInfo Count: $($UpdateTargetsInfo.Count)"
    $itemNumDebugLoop = 0
    foreach ($itemDebugBeforeLoop in $UpdateTargetsInfo) {
        Write-Host "DEBUG: (UpdateLoxone.ps1) BEFORE step loop - Item #$itemNumDebugLoop Type: $($itemDebugBeforeLoop.Type) - Name: $($itemDebugBeforeLoop.Name)"
        $itemNumDebugLoop++
    }

    foreach ($stepEntry in $steps) {
        Write-Log -Message "Evaluating step: $($stepEntry.Name)" -Level DEBUG
        $shouldRunThisStep = $false
        try {
            # Ensure all four arguments are passed to ShouldRun scriptblocks
            $utiForShouldRun = $UpdateTargetsInfo.Clone() # Create a shallow clone for this Invoke-Command
            Write-Log -Message "DEBUG: (UpdateLoxone.ps1) Cloned UpdateTargetsInfo for ShouldRun. Original count: $($UpdateTargetsInfo.Count), Clone count: $($utiForShouldRun.Count)" -Level DEBUG
            $shouldRunThisStep = Invoke-Command -ScriptBlock $stepEntry.ShouldRun -ArgumentList $scriptContext, $utiForShouldRun, ([ref]$scriptGlobalState), $prerequisites
            Write-Log -Message "Step '$($stepEntry.Name)' ShouldRun evaluated to: $shouldRunThisStep" -Level DEBUG
        } catch {
            Write-Log -Message "Error evaluating ShouldRun for step '$($stepEntry.Name)': $($_.Exception.Message)" -Level WARN
        }

        if (-not $shouldRunThisStep) {
            Write-Log -Message "Skipping step: $($stepEntry.Name) (ShouldRun returned false or errored)" -Level INFO
            continue
        }

        Write-Log -Message "Starting step: $($stepEntry.Name)" -Level INFO
        $stepResult = $null
        try {
            $utiForRun = $UpdateTargetsInfo.Clone() # Create a shallow clone for this Invoke-Command
            Write-Log -Message "DEBUG: (UpdateLoxone.ps1) Cloned UpdateTargetsInfo for Run. Original count: $($UpdateTargetsInfo.Count), Clone count: $($utiForRun.Count)" -Level DEBUG
            $stepResult = Invoke-Command -ScriptBlock $stepEntry.Run -ArgumentList $scriptContext, $utiForRun, ([ref]$scriptGlobalState), $prerequisites
            Write-Log -Message "Step '$($stepEntry.Name)' executed. Result Succeeded: $($stepResult.Succeeded)" -Level DEBUG
        } catch {
            $scriptGlobalState.ErrorOccurred = $true # Use .Value for ref types if modifying, but here it's direct assignment
            $errorMessage = "FATAL: Error EXECUTING step '$($stepEntry.Name)'. Exception: $($_.Exception.Message)"
            Write-Log -Message $errorMessage -Level ERROR
            Write-Log -Message "Full Error Record for step execution failure: ($($_ | Out-String))" -Level DEBUG
            $failedTarget = $UpdateTargetsInfo | Where-Object {$_.Type -eq $stepEntry.Component} | Select-Object -First 1
            if ($failedTarget) {
                $failedTarget.Status = "StepExecutionError"
                # $stepResult might be null here if Invoke-Command itself failed before scriptblock execution completed
                # So, don't rely on $stepResult.UpdatePerformed in this specific catch block.
                # Assume an update was attempted if we got this far into trying to run the step.
                $failedTarget.UpdatePerformed = $true
            }
            throw $errorMessage
        }
        
        if ($null -eq $stepResult) {
            $script:ErrorOccurred = $true
            $scriptGlobalState.ErrorOccurred = $true # Use .Value for ref types if modifying
            $errorMessageNull = "FATAL: Step '$($stepEntry.Name)' scriptblock returned NULL. This is unexpected."
            Write-Log -Message $errorMessageNull -Level ERROR
            throw $errorMessageNull
        }

        $targetInInfo = $UpdateTargetsInfo | Where-Object {$_.Type -eq $stepResult.Component} | Select-Object -First 1
        if ($targetInInfo) {
            $targetInInfo.Status = if ($stepResult.Succeeded) { "$($stepResult.Action)Successful" } else { "$($stepResult.Action)Failed ($($stepResult.Reason))" }
            if ($stepResult.PSObject.Properties | Where-Object {$_.Name -eq 'UpdatePerformed'}) { $targetInInfo.UpdatePerformed = $stepResult.UpdatePerformed }
            if ($stepResult.PSObject.Properties | Where-Object {$_.Name -eq 'VersionAfterUpdate'}) { $targetInInfo.VersionAfterUpdate = $stepResult.VersionAfterUpdate }
            if ($stepResult.Succeeded -and ($stepResult.Action -eq "Install" -or $stepResult.Action -eq "Update" -or $stepResult.Action -eq "Download")) {
                 $scriptGlobalState.anyUpdatePerformed = $true # Use .Value for ref types if modifying
            }
            if (($stepResult.PSObject.Properties | Where-Object {$_.Name -eq 'InstallSkipped'}) -and $stepResult.InstallSkipped) {
                $targetInInfo.Status = "InstallSkippedProcessRunning"
                $targetInInfo.UpdatePerformed = $false
            } elseif (($stepResult.PSObject.Properties | Where-Object {$_.Name -eq 'DownloadSkipped'}) -and $stepResult.DownloadSkipped) {
                 $targetInInfo.Status = "DownloadSkippedExistingValid"
            }

        } else {
            Write-Log -Message "WARN: Could not find matching target in UpdateTargetsInfo for component '$($stepResult.Component)' from step '$($stepEntry.Name)' to update its status." -Level WARN
        }

        if (-not $stepResult.Succeeded) {
            $script:ErrorOccurred = $true
            $scriptGlobalState.ErrorOccurred = $true # Use .Value for ref types if modifying
            $errorMessageStepFail = "FATAL: Step '$($stepEntry.Name)' failed. Reason: $($stepResult.Reason). Error: $($stepResult.Error | Out-String)"
            Write-Log -Message $errorMessageStepFail -Level ERROR
            throw $errorMessageStepFail
        }
        Write-Log -Message "Successfully completed step: $($stepEntry.Name)" -Level INFO
    } # This is the end of the foreach ($stepEntry in $steps) loop

    Write-Log -Message "Main update pipeline processing finished." -Level INFO
} # This is the end of the main try block for the pipeline
catch {
$script:ErrorOccurred = $true 
$script:LastErrorLine = if ($_.InvocationInfo) { try { $_.InvocationInfo.ScriptLineNumber } catch { 0 } } else { 0 }

$exceptionDetailsObject = if (Get-Command Format-ExceptionDetailsForLog -ErrorAction SilentlyContinue) {
    Format-ExceptionDetailsForLog -ErrorRecord $_
} else {
    $errMsg = $_.Exception.Message
    $errFullDetails = try { $_ | Out-String } catch { "Could not retrieve full error object." }
    $errStackTrace = if ($_.ScriptStackTrace) { try { $_.ScriptStackTrace } catch { "Could not retrieve stack trace." } } else { "N/A" }
    [pscustomobject]@{
        Message     = $errMsg
        FullDetails = $errFullDetails
        StackTrace  = $errStackTrace
    }
}

Write-Log -Message "FATAL SCRIPT ERROR in main pipeline: $($exceptionDetailsObject.Message)" -Level ERROR
Write-Log -Message "--- Error Details (Catch Block) ---`n$($exceptionDetailsObject.FullDetails)`n--- End Error Details ---" -Level ERROR
if ($exceptionDetailsObject.StackTrace -and $exceptionDetailsObject.StackTrace -ne "N/A") {
    Write-Log -Message "--- StackTrace (Catch Block) ---`n$($exceptionDetailsObject.StackTrace)`n--- End StackTrace ---" -Level ERROR
}

$finalErrorMsgForToast = "ERROR: Update process failed. Check logs. $($exceptionDetailsObject.Message) (Line: $script:LastErrorLine)"

if (Get-Command Show-FinalStatusToast -ErrorAction SilentlyContinue) {
    Show-FinalStatusToast -StatusMessage $finalErrorMsgForToast -Success $false -LogFileToShow $scriptContext.LogFile
} else {
    Write-Log -Message "Show-FinalStatusToast command not found. Cannot display error toast." -Level WARN
}
}
finally {
Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Main pipeline 'finally' block executing."

$anyUpdatePerformedActualInFinally = ($UpdateTargetsInfo | Where-Object {$_.UpdatePerformed -eq $true -or $_.Status -eq "UpdateSuccessful"}).Count -gt 0
Write-Log -Message "(Finally) AnyUpdatePerformedActualInFinally: $anyUpdatePerformedActualInFinally" -Level DEBUG

$logPathToShowFinally = $scriptContext.LogFile 
$logPathToShowFinally = $scriptContext.LogFile 

if (-not $script:SystemRelaunchExitOccurred) {
    if ($scriptContext.LogFile -and (Test-Path $scriptContext.LogFile) -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Attempting final log rotation in 'finally' block for '$($scriptContext.LogFile)' (SystemRelaunchExitOccurred is false)."
        try {
            $rotatedPath = Invoke-LogFileRotation -LogFilePath $scriptContext.LogFile -MaxArchiveCount 24 -MaxSizeKB ($scriptContext.Params.MaxLogFileSizeMB * 1024) -ErrorAction Stop
            if ($rotatedPath) { $logPathToShowFinally = $rotatedPath } 
            Write-Log -Message "(UpdateLoxone.ps1) Log rotation in 'finally' block completed. Effective log path for toast: $logPathToShowFinally" -Level DEBUG
        } catch {
            Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Error during log rotation in 'finally' block: $($_.Exception.Message)"
        }
    } elseif ($scriptContext.LogFile) {
        Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Invoke-LogFileRotation not found or LogFile path invalid. Skipping log rotation in 'finally' (SystemRelaunchExitOccurred is false)."
    } else {
        Write-Log -Level WARN -Message "(UpdateLoxone.ps1) LogFile path not set in scriptContext. Skipping log rotation in 'finally' (SystemRelaunchExitOccurred is false)."
    }
} else {
    Write-Log -Level INFO -Message "(UpdateLoxone.ps1) Skipping final log rotation in 'finally' block because SystemRelaunchExitOccurred is true."
}

if (-not $script:ErrorOccurred) {
    Write-Log -Message "(UpdateLoxone.ps1) Constructing final success/summary notification message in 'finally' block." -Level INFO
    $summaryLines = @()
    foreach ($targetInfo in $UpdateTargetsInfo) {
        $line = ""
        $processedName = $targetInfo.Name
        if (($targetInfo.Type -eq "App" -or $targetInfo.Type -eq "Config") -and $targetInfo.Name.StartsWith("Loxone ")) {
            $processedName = $targetInfo.Name.Substring("Loxone ".Length)
        }
        $channelInfo = if ($targetInfo.Channel) { "($($targetInfo.Channel))" } else { "" }
        $targetNameDisplay = "$processedName $channelInfo".Trim()

# --- Final Progress Toast Update to 100% ---
    if (-not $script:ErrorOccurred -and $Global:PersistentToastInitialized) {
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY: Preparing final progress toast update to 100%."
        $scriptGlobalState.currentStep = $scriptGlobalState.totalSteps # Ensure it's the last step
        $finalizingWeight = Get-StepWeight -StepID 'Finalize'
        $scriptGlobalState.CurrentWeight += $finalizingWeight
        $scriptGlobalState.CurrentWeight = [Math]::Min($scriptGlobalState.CurrentWeight, $scriptGlobalState.TotalWeight)

        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY: currentStep='$($scriptGlobalState.currentStep)', totalSteps='$($scriptGlobalState.totalSteps)', CurrentWeight='$($scriptGlobalState.CurrentWeight)', TotalWeight='$($scriptGlobalState.TotalWeight)'"
        
        $finalStepNameForToast = "Update Process Finalizing"
        
        [int]$stepNumToast = 0
        [int]$totalStepsToast = 0
        [double]$currentWeightToast = 0.0
        [double]$totalWeightToast = 0.0

        # Attempt to get values from $scriptGlobalState.Value, with type casting and logging
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY: Attempting to retrieve and cast values from scriptGlobalState.Value"
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY: Attempting to retrieve and cast values from scriptGlobalState"
        try { $stepNumToast = [int]$scriptGlobalState.currentStep } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.currentStep ('$($scriptGlobalState.currentStep)') to int. Defaulting."}
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (POST-CAST): stepNumToast='$stepNumToast' (Type: $($stepNumToast.GetType().FullName))"

        try { $totalStepsToast = [int]$scriptGlobalState.totalSteps } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.totalSteps ('$($scriptGlobalState.totalSteps)') to int. Defaulting."}
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (POST-CAST): totalStepsToast='$totalStepsToast' (Type: $($totalStepsToast.GetType().FullName))"
        
        try { $currentWeightToast = [double]$scriptGlobalState.CurrentWeight } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.CurrentWeight ('$($scriptGlobalState.CurrentWeight)') to double. Defaulting."}
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (POST-CAST): currentWeightToast='$currentWeightToast' (Type: $($currentWeightToast.GetType().FullName))"

        try { $totalWeightToast = [double]$scriptGlobalState.TotalWeight } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.TotalWeight ('$($scriptGlobalState.TotalWeight)') to double. Defaulting."}
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (POST-CAST): totalWeightToast='$totalWeightToast' (Type: $($totalWeightToast.GetType().FullName))"
        # Fallback logic using script-scoped variables if $scriptGlobalState.Value was problematic
        if ($totalStepsToast -eq 0) {
            $totalStepsToast = if ($script:totalSteps -gt 0) { $script:totalSteps } else { 1 } # Use script-scoped as fallback, then 1
            Write-Log -Level WARN -Message "FINALLY: totalStepsToast was 0, adjusted to '$totalStepsToast'."
        }
        if ($stepNumToast -eq 0 -or $stepNumToast -gt $totalStepsToast) {
            $stepNumToast = $totalStepsToast # Set to total to represent completion
            Write-Log -Level WARN -Message "FINALLY: stepNumToast was invalid or 0, adjusted to '$stepNumToast'."
        }
        
        if ($totalWeightToast -eq 0) {
            $totalWeightToast = if ($script:TotalWeight -gt 0) { [double]$script:TotalWeight } else { 1.0 } # Use script-scoped as fallback, then 1.0
            Write-Log -Level WARN -Message "FINALLY: totalWeightToast was 0, adjusted to '$totalWeightToast'."
        }
        if ($currentWeightToast -le 0 -or $currentWeightToast -gt $totalWeightToast) { # If current is 0, less than 0, or greater than total
            $currentWeightToast = $totalWeightToast # Make it 100%
             Write-Log -Level WARN -Message "FINALLY: currentWeightToast was invalid or 0, adjusted to '$currentWeightToast' for 100%."
        }
        
        Write-Log -Message "(UpdateLoxone.ps1) MAIN SCRIPT FINALLY: Logging before Update-PersistentToast call (Finalizing)." -Level DEBUG
        Write-Log -Message "(UpdateLoxone.ps1)   Attempting to pass: Step=${stepNumToast}/${totalStepsToast}, Weight=${currentWeightToast}/${totalWeightToast}" -Level DEBUG
        $statusTextForLogFinally = "Step ${stepNumToast}/${totalStepsToast}: ${finalStepNameForToast}"
        Write-Log -Message "(UpdateLoxone.ps1)   Constructed StatusText (Finally) = '$statusTextForLogFinally'" -Level DEBUG
        $progressValueForLogFinally = if ($totalWeightToast -gt 0) { [Math]::Round(($currentWeightToast / $totalWeightToast) * 100) } else { 100 } 
        Write-Log -Message "(UpdateLoxone.ps1)   Calculated ProgressValue (Finally percentage) = $progressValueForLogFinally %" -Level DEBUG

        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (PRE-CALL VALUES AND TYPES): stepNumToast='$($stepNumToast)' (Type: $($stepNumToast.GetType().FullName))"
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (PRE-CALL VALUES AND TYPES): totalStepsToast='$($totalStepsToast)' (Type: $($totalStepsToast.GetType().FullName))"
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (PRE-CALL VALUES AND TYPES): currentWeightToast='$($currentWeightToast)' (Type: $($currentWeightToast.GetType().FullName))"
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) FINALLY (PRE-CALL VALUES AND TYPES): totalWeightToast='$($totalWeightToast)' (Type: $($totalWeightToast.GetType().FullName))"
        try {
            Update-PersistentToast -StepNumber $stepNumToast `
                                   -TotalSteps $totalStepsToast `
                                   -StepName $finalStepNameForToast `
                                   -CurrentWeight $currentWeightToast `
                                   -TotalWeight $totalWeightToast `
                                   -IsInteractive $scriptContext.IsInteractive `
                                   -ErrorOccurred $script:ErrorOccurred `
                                   -AnyUpdatePerformed $scriptGlobalState.anyUpdatePerformed
            Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Updated toast to Finalizing/100% (Step ${stepNumToast}/${totalStepsToast}, Weight ${currentWeightToast}/${totalWeightToast})."
            Start-Sleep -Milliseconds 250 # Brief pause to allow toast to be visible
        } catch {
            Write-Log -Level WARN -Message "(UpdateLoxone.ps1) FINALLY: Error updating toast to 100% before summary: $($_.Exception.Message)"
        }
    }
        switch ($targetInfo.Status) {
            "UpdateSuccessful"              { $line = $targetNameDisplay + ": Updated to " + $targetInfo.VersionAfterUpdate }
            "InstallSuccessful"             { $line = $targetNameDisplay + ": Successfully installed " + $targetInfo.VersionAfterUpdate }
            "DownloadSuccessful"            { $line = $targetNameDisplay + ": Downloaded (Target: " + $targetInfo.TargetVersion + ")" }
            "ExtractSuccessful"             { $line = $targetNameDisplay + ": Extracted (Target: " + $targetInfo.TargetVersion + ")" }
            "UpToDate"                      { $line = $targetNameDisplay + ": Up-to-date " + $targetInfo.InitialVersion }
            "NotInstalled"                  { $line = $targetNameDisplay + ": Not found (Target: " + $targetInfo.TargetVersion + ")" }
            "NeedsUpdate"                   { $line = $targetNameDisplay + ": Update was pending (Target: " + $targetInfo.TargetVersion + ")" } # Should ideally not be seen if process completes
            "InstallSkippedProcessRunning"  { $line = $targetNameDisplay + ": Install skipped (Loxone process running)" }
            "DownloadSkippedExistingValid"  { $line = $targetNameDisplay + ": Using existing valid file (Version: " + $targetInfo.TargetVersion + ")" }
            default {
                if ($targetInfo.Status -like "*Failed*") { # More generic check for failure statuses
                    $reason = ($targetInfo.Status -split '\(|\)')[1]
                    $reasonText = if ($reason) { " - Reason: " + $reason } else { "" }
                    $stillAt = if ($targetInfo.VersionAfterUpdate -and $targetInfo.VersionAfterUpdate -ne $targetInfo.InitialVersion) { $targetInfo.VersionAfterUpdate } else { $targetInfo.InitialVersion }
                    $line = $targetNameDisplay + ": Action Failed (Target: " + $targetInfo.TargetVersion + ", Status: " + $targetInfo.Status + ", Initial: " + $stillAt + ")" + $reasonText
                } elseif ($targetInfo.UpdatePerformed -and $targetInfo.Status -eq "UpdateAttempted") {
                    $line = $targetNameDisplay + ": Update attempted, outcome: " + $targetInfo.Status + " (Initial: " + $targetInfo.InitialVersion + ", Target: " + $targetInfo.TargetVersion + ")"
                }
                else {
                    $line = $targetNameDisplay + ": Status '" + $targetInfo.Status + "' (Initial: " + $targetInfo.InitialVersion + ", Target: " + $targetInfo.TargetVersion + ")"
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($line)) { $summaryLines += $line }
    }
    # Lines 734-737 (original positions) logging variable types have been moved
    # into the if block starting at line 639 to ensure variables are initialized.
    # They are now integrated into the logs just before the Update-PersistentToast call (around line 694).
    $finalMessageText = "Loxone Update Process Finished." # Simplified initial message

    if ($summaryLines.Count -gt 0) {
        $finalMessageText += "`n" + ($summaryLines | Sort-Object | Out-String).Trim()
    }

    Write-Log -Message "Final Summary (Success/No Error):`n$finalMessageText" -Level INFO
    if (Get-Command Show-FinalStatusToast -ErrorAction SilentlyContinue) {
        # Only show success/summary toast if:
        # 1. Running in an interactive host AND
        # 2. EITHER an update was performed OR it wasn't a self-invoked check that found nothing.
        if ($scriptContext.IsInteractive -and ($anyUpdatePerformedActualInFinally -or -not $scriptContext.IsSelfInvokedForUpdateCheck)) {
            Show-FinalStatusToast -StatusMessage $finalMessageText -Success $true -LogFileToShow $logPathToShowFinally
        } else {
            Write-Log -Message "(UpdateLoxone.ps1) Suppressing final status toast. IsInteractive: $($scriptContext.IsInteractive), AnyUpdatePerformed: $anyUpdatePerformedActualInFinally, IsSelfInvoked: $($scriptContext.IsSelfInvokedForUpdateCheck)." -Level INFO
        }
    } else {
        Write-Log -Message "Show-FinalStatusToast command not found. Cannot display success toast." -Level WARN
    }
} elseif ($script:ErrorOccurred) {
    Write-Log -Message "(UpdateLoxone.ps1) 'finally' block executing after an error was caught. Error toast should have been displayed by catch block." -Level INFO
}


Write-Log -Message "(UpdateLoxone.ps1) Attempting final Exit-Function call from LoxoneUtils.Logging..." -Level DEBUG
if (Get-Command Exit-Function -ErrorAction SilentlyContinue) {
    Exit-Function 
} else {
    Write-Log -Message "(UpdateLoxone.ps1) Exit-Function not found in 'finally' block." -Level WARN
}

Write-Log -Message "(UpdateLoxone.ps1) Script final exit from 'finally' block. ErrorOccurred: $script:ErrorOccurred" -Level INFO
if ($script:ErrorOccurred) { exit 1 } else { exit 0 }
}
# End of script
