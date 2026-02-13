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
    [switch]$EnforceSSLCertificate, # New switch to enforce SSL/TLS certificate validation for MS connections (default is to skip validation)
    [switch]$Parallel, # Enable parallel execution mode
    [int]$MaxConcurrency = 10, # Maximum concurrent operations for downloads/installs
    [int]$MaxMSConcurrency = 10, # Maximum concurrent Miniserver updates

    # Monitor Testing Parameters
    [switch]$TestMonitor, # Test Monitor functionality only (no update performed)
    [int]$TestMonitorDurationSeconds = 120, # How long to run Monitor in test mode
    [switch]$KeepMonitorRunning, # Don't stop Monitor automatically (for manual testing)
    [switch]$MonitorDiscoveryMode # Enable extended .lxmon path discovery
)
# XML Signature Verification Function removed - Test showed it's not feasible with current structure

# Set up trap handler to clean up ThreadJobs on script termination
trap {
    Write-Host "ERROR: Script terminated unexpectedly: $_" -ForegroundColor Red
    Write-Host "Cleaning up ThreadJobs..." -ForegroundColor Yellow
    
    try {
        # Clean up all ThreadJobs
        $allJobs = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -match "ProgressWorker|MS Worker|Config Worker|App Worker|Download Worker|Install Worker" -or
            $_.Location -match "UpdateLoxone|LoxoneUtils"
        })
        
        if ($allJobs.Count -gt 0) {
            Write-Host "Found $($allJobs.Count) job(s) to clean up" -ForegroundColor Yellow
            foreach ($job in $allJobs) {
                Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }
        }
        
        if (Get-Command Remove-ThreadJobs -ErrorAction SilentlyContinue) {
            Remove-ThreadJobs -Context "Trap Handler Cleanup"
        }
    } catch {
        Write-Host "Error during trap cleanup: $_" -ForegroundColor Red
    }
    
    # Exit with error code
    exit 1
}

# Determine script's own directory reliably
$script:MyScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Configuration defaults (can be overridden by user settings)
$script:UseParallelExecution = $false  # Default to sequential execution unless explicitly enabled

# Load user configuration if exists
$configPath = Join-Path $script:MyScriptRoot "UpdateLoxone.config.json"
if (Test-Path $configPath) {
    try {
        $userConfig = Get-Content $configPath -Raw | ConvertFrom-Json
        if ($null -ne $userConfig.UseParallelExecution) {
            $script:UseParallelExecution = $userConfig.UseParallelExecution
            Write-Host "Loaded UseParallelExecution from config: $($script:UseParallelExecution)" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to load configuration from ${configPath}: $_"
    }
}

$Global:PersistentToastInitialized = $false # Ensure toast is created fresh each run
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
    # Record script start time for total runtime calculation
    $script:ScriptStartTime = Get-Date
    Write-Host "INFO: (UpdateLoxone.ps1) Proceeding with full LoxoneUtils module manifest import." -ForegroundColor Cyan
    $UtilsModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils\LoxoneUtils.psd1'

    if (-not (Test-Path $UtilsModulePath)) {
        Write-Error "FATAL: Helper module manifest 'LoxoneUtils.psd1' not found at '$UtilsModulePath'. Script cannot continue."
        exit 1
    }

    # Attempt to forcefully remove any pre-existing LoxoneUtils modules to ensure a clean import
    Write-Host "INFO: (UpdateLoxone.ps1) Attempting to forcefully remove any existing LoxoneUtils modules before main import..." -ForegroundColor Cyan
    
    # Remove all loaded LoxoneUtils modules
    $loadedModules = Get-Module -Name "LoxoneUtils*"
    if ($loadedModules) {
        Write-Host "INFO: (UpdateLoxone.ps1) Found $($loadedModules.Count) loaded LoxoneUtils module(s) to remove." -ForegroundColor Yellow
        $loadedModules | ForEach-Object {
            Write-Host "DEBUG: (UpdateLoxone.ps1) Removing loaded module: $($_.Name)" -ForegroundColor Gray
            Remove-Module -ModuleInfo $_ -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Also check for modules that might be available but not imported
    $availableModules = Get-Module -Name "LoxoneUtils*" -ListAvailable | Where-Object { $_.ModuleBase -like "$PSScriptRoot*" }
    if ($availableModules) {
        Write-Host "INFO: (UpdateLoxone.ps1) Found $($availableModules.Count) available LoxoneUtils module(s) in script directory." -ForegroundColor Yellow
        # Force PowerShell to forget about these modules
        $availableModules | ForEach-Object {
            $moduleName = $_.Name
            Write-Host "DEBUG: (UpdateLoxone.ps1) Clearing module cache for: $moduleName" -ForegroundColor Gray
            # Remove from module table if present
            if ($ExecutionContext.SessionState.Module.GetExportedCommands().ContainsKey($moduleName)) {
                $ExecutionContext.SessionState.Module.RemoveModule($moduleName)
            }
        }
    }
    
    # Clear any cached type data that might interfere
    Write-Host "INFO: (UpdateLoxone.ps1) Clearing cached type data for System.Security.AccessControl.ObjectSecurity..." -ForegroundColor Cyan
    try {
        # Remove the problematic type data if it exists
        $typeData = Get-TypeData -TypeName "System.Security.AccessControl.ObjectSecurity"
        if ($typeData) {
            Remove-TypeData -TypeData $typeData -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "DEBUG: (UpdateLoxone.ps1) Could not clear type data: $_" -ForegroundColor Gray
    }

    # Import the main LoxoneUtils module using its manifest.
    Write-Host "INFO: (UpdateLoxone.ps1) Checking for BurntToast module before LoxoneUtils import..." -ForegroundColor Cyan
    if (-not (Get-Module -ListAvailable -Name BurntToast)) {
        Write-Host "INFO: (UpdateLoxone.ps1) BurntToast module not found. Attempting to install..." -ForegroundColor Yellow
        try {
            Install-Module BurntToast -Scope CurrentUser -Force -Confirm:$false -SkipPublisherCheck -ErrorAction Stop
            Write-Host "INFO: (UpdateLoxone.ps1) BurntToast module installed successfully." -ForegroundColor Green
            try {
                Write-Host "INFO: (UpdateLoxone.ps1) Explicitly importing BurntToast into the current session..." -ForegroundColor Cyan
                Import-Module BurntToast -Force -ErrorAction Stop
                Write-Host "INFO: (UpdateLoxone.ps1) BurntToast imported successfully." -ForegroundColor Green
            } catch {
                Write-Error "CRITICAL ERROR: (UpdateLoxone.ps1) Failed to import BurntToast after installation. Error: $($_.Exception.Message)."
                exit 1
            }
        } catch {
            Write-Error "CRITICAL ERROR: (UpdateLoxone.ps1) Failed to install BurntToast module. Error: $($_.Exception.Message). Please install it manually and re-run the script."
            exit 1
        }
    } else {
        Write-Host "INFO: (UpdateLoxone.ps1) BurntToast module is already available." -ForegroundColor Cyan
        try {
            Write-Host "INFO: (UpdateLoxone.ps1) Explicitly importing BurntToast into the current session..." -ForegroundColor Cyan
            Import-Module BurntToast -Force -ErrorAction Stop
            Write-Host "INFO: (UpdateLoxone.ps1) BurntToast imported successfully." -ForegroundColor Green
        } catch {
            Write-Error "CRITICAL ERROR: (UpdateLoxone.ps1) Failed to import already available BurntToast module. Error: $($_.Exception.Message)."
            exit 1
        }
    }

    Write-Host "INFO: (UpdateLoxone.ps1) Attempting to import LoxoneUtils manifest: '$UtilsModulePath'..." -ForegroundColor Cyan
    try {
        # Remove any cached versions first
        Get-Module LoxoneUtils* | Remove-Module -Force -ErrorAction SilentlyContinue
        # Force fresh import with all flags to ensure no caching
        Import-Module $UtilsModulePath -Force -DisableNameChecking -Global -ErrorAction Stop
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

# ═══════════════════════════════════════════════════════════════════════════════
# TEST MONITOR MODE
# ═══════════════════════════════════════════════════════════════════════════════
if ($TestMonitor) {
    Write-Log -Message "╔════════════════════════════════════════════════════════════╗" -Level INFO
    Write-Log -Message "║          TEST MONITOR MODUS (Kein Update)                 ║" -Level INFO
    Write-Log -Message "╚════════════════════════════════════════════════════════════╝" -Level INFO

    try {
        # 1. Lade MS-Liste
        $msListPath = Join-Path $scriptContext.ScriptSaveFolder "UpdateLoxoneMSList.txt"

        if (-not (Test-Path $msListPath)) {
            Write-Log -Message "✗ MS-Liste nicht gefunden: $msListPath" -Level ERROR
            Write-Log -Message "Bitte erstellen Sie UpdateLoxoneMSList.txt im Verzeichnis: $($scriptContext.ScriptSaveFolder)" -Level ERROR
            Show-FinalStatusToast -StatusMessage "MS-Liste nicht gefunden" -Success $false -LogFileToShow $scriptContext.LogFile
            exit 1
        }

        Write-Log -Message "Lade Miniserver-Liste: $msListPath" -Level INFO

        # Einfacher Parser (wird später durch erweiterten ersetzt)
        $lines = Get-Content $msListPath | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
        $miniServers = @()

        foreach ($line in $lines) {
            $parts = $line -split ','
            $uri = [System.Uri]$parts[0]
            $msName = $uri.Host

            $msEntry = @{
                Url = $parts[0]
                Name = $msName
                EnableMonitor = if ($parts.Count -gt 3 -and $parts[3] -eq 'true') { $true } else { $false }
            }

            $miniServers += [PSCustomObject]$msEntry
        }

        $monitorMS = $miniServers | Where-Object { $_.EnableMonitor -eq $true }

        if ($monitorMS.Count -eq 0) {
            Write-Log -Message "✗ Keine Miniserver mit enable_monitor=true gefunden" -Level WARN
            # Empty log line removed
            Write-Log -Message "Bitte UpdateLoxoneMSList.txt anpassen:" -Level INFO
            Write-Log -Message "Format: URL,version,timestamp,enable_monitor" -Level INFO
            Write-Log -Message "Beispiel: https://admin:pass@192.168.1.77,,,true" -Level INFO
            Show-FinalStatusToast -StatusMessage "Keine Miniserver für Monitor konfiguriert" -Success $false -LogFileToShow $scriptContext.LogFile
            exit 0
        }

        Write-Log -Message "✓ Gefundene Miniserver für Monitor-Test: $($monitorMS.Count)" -Level INFO
        foreach ($ms in $monitorMS) {
            Write-Log -Message "  - $($ms.Name)" -Level INFO
        }
        # Empty log line removed

        # 2. Finde monitor.exe
        Write-Log -Message "Suche loxonemonitor.exe..." -Level INFO

        # Versuche Loxone Config Installation zu finden
        $configPath = Get-InstalledApplicationPath -AppName "Loxone Config"
        if (-not $configPath) {
            Write-Log -Message "✗ Loxone Config nicht installiert" -Level ERROR
            Show-FinalStatusToast -StatusMessage "Loxone Config nicht gefunden" -Success $false -LogFileToShow $scriptContext.LogFile
            exit 1
        }

        Write-Log -Message "Loxone Config gefunden: $configPath" -Level DEBUG
        $monitorExe = Find-LoxoneMonitorExe -LoxoneConfigInstallPath $configPath

        if (-not $monitorExe) {
            Write-Log -Message "✗ loxonemonitor.exe nicht gefunden in: $configPath" -Level ERROR
            Show-FinalStatusToast -StatusMessage "loxonemonitor.exe nicht gefunden" -Success $false -LogFileToShow $scriptContext.LogFile
            exit 1
        }

        Write-Log -Message "✓ loxonemonitor.exe: $monitorExe" -Level INFO
        # Empty log line removed

        # 3. Starte Monitor
        Write-Log -Message "Starte Monitor-Prozess..." -Level INFO
        $monitorProc = Start-LoxoneMonitorProcess -MonitorExePath $monitorExe -WorkingDirectory $scriptContext.ScriptSaveFolder

        Write-Log -Message "✓ Monitor gestartet (PID: $($monitorProc.Id))" -Level INFO
        # Empty log line removed

        # 4. Aktiviere Logging auf MS
        $localIP = Get-LocalIPAddress
        Write-Log -Message "Lokale IP für MS-Logging: $localIP" -Level INFO
        # Empty log line removed

        foreach ($ms in $monitorMS) {
            Write-Log -Message "Aktiviere Logging auf MS '$($ms.Name)'..." -Level INFO
            $success = Enable-MiniserverLogging -MiniserverUrl $ms.Url -TargetIP $localIP

            if ($success) {
                Write-Log -Message "✓ MS '$($ms.Name)' sendet jetzt Logs an $localIP" -Level INFO
            }
            else {
                Write-Log -Message "✗ Konnte Logging auf MS '$($ms.Name)' nicht aktivieren" -Level WARN
            }
        }

        # Empty log line removed
        Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
        Write-Log -Message "Monitor läuft - suche nach .lxmon Dateien..." -Level INFO
        Write-Log -Message "Dauer: $TestMonitorDurationSeconds Sekunden" -Level INFO
        if ($MonitorDiscoveryMode) {
            Write-Log -Message "Discovery-Modus: AKTIV (erweiterte Suche)" -Level INFO
        }
        Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
        # Empty log line removed

        # 5. Warte kurz bis Logs eintreffen
        Write-Log -Message "Warte 10 Sekunden bis erste Logs eintreffen..." -Level INFO
        Start-Sleep -Seconds 10

        # 6. Discovery ausführen
        Write-Log -Message "Starte .lxmon Discovery..." -Level INFO
        $foundPath = Find-LxmonFiles -MonitorProcessId $monitorProc.Id -DiscoveryMode:$MonitorDiscoveryMode

        if ($foundPath) {
            # Empty log line removed
            Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
            Write-Log -Message "✓✓✓ .lxmon Speicherort gefunden!" -Level INFO
            Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
            Write-Log -Message "Pfad: $foundPath" -Level INFO
            # Empty log line removed
            Write-Log -Message "WICHTIG: Diesen Pfad für finalen Code notieren!" -Level INFO
            # Empty log line removed

            # Zeige gefundene Dateien
            $files = Get-ChildItem -Path $foundPath -Filter "*.lxmon" -ErrorAction SilentlyContinue
            if ($files) {
                Write-Log -Message "Gefundene .lxmon Dateien: $($files.Count)" -Level INFO
                foreach ($file in $files) {
                    $sizeKB = [math]::Round($file.Length / 1KB, 2)
                    Write-Log -Message "  - $($file.Name) (${sizeKB} KB, LastWrite: $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))" -Level INFO
                }
            }
            else {
                Write-Log -Message "⚠ Verzeichnis existiert, aber noch keine .lxmon Dateien" -Level WARN
                Write-Log -Message "Tipp: Führe Aktionen auf dem Miniserver aus um Logs zu erzeugen" -Level INFO
            }
        }
        else {
            # Empty log line removed
            Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
            Write-Log -Message "✗✗✗ KEINE .lxmon Dateien gefunden!" -Level WARN
            Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
            # Empty log line removed
            Write-Log -Message "Mögliche Ursachen:" -Level INFO
            Write-Log -Message "1. Monitor hat noch keine Logs empfangen (Miniserver sendet nicht)" -Level INFO
            Write-Log -Message "2. Logs werden in unbekanntem Verzeichnis gespeichert" -Level INFO
            # Empty log line removed
            Write-Log -Message "Bitte manuell im Dateisystem suchen:" -Level INFO
            Write-Log -Message "  - C:\Windows\Temp (und Unterordner)" -Level INFO
            Write-Log -Message "  - %USERPROFILE%\AppData\Local\Temp" -Level INFO
            Write-Log -Message "  - %USERPROFILE%\Documents\Loxone" -Level INFO
            # Empty log line removed

            if (-not $MonitorDiscoveryMode) {
                Write-Log -Message "Tipp: Verwende -MonitorDiscoveryMode für erweiterte Suche" -Level INFO
            }
        }

        # 7. Ggf. weiterlaufen lassen
        if ($KeepMonitorRunning) {
            # Empty log line removed
            Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO
            Write-Log -Message "Monitor läuft weiter (KeepMonitorRunning aktiv)" -Level INFO
            Write-Log -Message "Drücke STRG+C zum Beenden" -Level INFO
            Write-Log -Message "═══════════════════════════════════════════════════════════" -Level INFO

            while ($true) {
                Start-Sleep -Seconds 10

                # Zeige periodisch Status
                $currentFiles = Get-ChildItem -Path $foundPath -Filter "*.lxmon" -ErrorAction SilentlyContinue
                if ($currentFiles) {
                    Write-Log -Message "[$(Get-Date -Format 'HH:mm:ss')] Monitor aktiv - $($currentFiles.Count) .lxmon Datei(en)" -Level INFO
                }
            }
        }
    }
    catch {
        Write-Log -Message "FEHLER im Test-Monitor Modus: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level DEBUG
    }
    finally {
        # 8. Cleanup
        # Empty log line removed
        Write-Log -Message "Beende Test-Monitor Modus..." -Level INFO

        # Deaktiviere Logging auf allen MS
        if ($monitorMS) {
            foreach ($ms in $monitorMS) {
                Write-Log -Message "Deaktiviere Logging auf MS '$($ms.Name)'..." -Level INFO
                Disable-MiniserverLogging -MiniserverUrl $ms.Url
            }
        }

        # Stoppe Monitor
        Stop-LoxoneMonitorProcess

        # Empty log line removed
        Write-Log -Message "╔════════════════════════════════════════════════════════════╗" -Level INFO
        Write-Log -Message "║          TEST MONITOR MODUS BEENDET                       ║" -Level INFO
        Write-Log -Message "╚════════════════════════════════════════════════════════════╝" -Level INFO

        if ($scriptContext -and $scriptContext.LogFile) {
            Show-FinalStatusToast -StatusMessage "Test-Monitor Modus abgeschlossen" -Success $true -LogFileToShow $scriptContext.LogFile
        }
    }

    exit 0
}
# ═══════════════════════════════════════════════════════════════════════════════
# END TEST MONITOR MODE
# ═══════════════════════════════════════════════════════════════════════════════

if ($scriptContext.IsInteractive -and -not $scriptContext.IsAdminRun -and -not $scriptContext.IsRunningAsSystem -and -not $scriptContext.Params.RegisterTask) {
    Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Checking if task '$($scriptContext.TaskName)' needs registration (interactive, non-admin)."
    if (-not (Test-ScheduledTask -TaskName $scriptContext.TaskName -ErrorAction SilentlyContinue)) {
        Write-Log -Message "(UpdateLoxone.ps1) Task '$($scriptContext.TaskName)' not found or inaccessible. Interactive non-admin run. Suggesting elevation or -RegisterTask." -Level INFO
        Write-Host "INFO: (UpdateLoxone.ps1) Scheduled task '$($scriptContext.TaskName)' is not registered. To set it up, please run this script as Administrator with the -RegisterTask switch." -ForegroundColor Yellow
    }
}

# Clean up any dead threads from previous runs before starting
Write-Log -Message "(UpdateLoxone.ps1) Checking for and cleaning up any dead threads from previous runs..." -Level INFO
try {
    # Get all existing jobs, especially ThreadJobs
    $existingJobs = @(Get-Job -ErrorAction SilentlyContinue)
    if ($existingJobs.Count -gt 0) {
        Write-Log -Message "Found $($existingJobs.Count) existing job(s). Analyzing..." -Level WARN
        
        # Filter for dead/orphaned jobs that might be from previous UpdateLoxone runs
        $suspiciousJobs = $existingJobs | Where-Object {
            # Look for jobs that match our typical naming patterns
            $_.Name -match "ProgressWorker|MS Worker|Config Worker|App Worker|Download Worker|Install Worker" -or
            # Also check for jobs that have been running for a suspiciously long time
            ($_.State -eq 'Running' -and $_.PSBeginTime -and ((Get-Date) - $_.PSBeginTime).TotalMinutes -gt 30) -or
            # Jobs in failed/stopped state from our modules
            ($_.State -in @('Failed', 'Stopped', 'Completed') -and $_.Location -match "UpdateLoxone|LoxoneUtils")
        }
        
        if ($suspiciousJobs.Count -gt 0) {
            Write-Log -Message "Found $($suspiciousJobs.Count) suspicious job(s) that appear to be from previous UpdateLoxone runs:" -Level WARN
            foreach ($job in $suspiciousJobs) {
                $jobInfo = "Job: $($job.Name), State: $($job.State), ID: $($job.Id)"
                if ($job.PSBeginTime) {
                    $runtime = (Get-Date) - $job.PSBeginTime
                    $jobInfo += ", Runtime: $($runtime.TotalMinutes.ToString('F1')) minutes"
                }
                Write-Log -Message "  - $jobInfo" -Level WARN
                
                # Force stop and remove the job
                try {
                    if ($job.State -eq 'Running') {
                        Write-Log -Message "    Stopping job $($job.Id)..." -Level INFO
                        Stop-Job -Job $job -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 500  # Give it time to stop
                    }
                    
                    Write-Log -Message "    Removing job $($job.Id)..." -Level INFO
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "    Successfully cleaned up job $($job.Id)" -Level INFO
                } catch {
                    Write-Log -Message "    Failed to clean up job $($job.Id): $_" -Level WARN
                }
            }
            
            # Verify cleanup
            $remainingJobs = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -match "ProgressWorker|MS Worker|Config Worker|App Worker|Download Worker|Install Worker"
            })
            if ($remainingJobs.Count -gt 0) {
                Write-Log -Message "WARNING: Still have $($remainingJobs.Count) UpdateLoxone-related jobs after cleanup!" -Level WARN
            } else {
                Write-Log -Message "All UpdateLoxone-related jobs cleaned up successfully." -Level INFO
            }
        } else {
            Write-Log -Message "No suspicious UpdateLoxone-related jobs found." -Level INFO
        }
    } else {
        Write-Log -Message "No existing jobs found. Starting with clean slate." -Level INFO
    }
} catch {
    Write-Log -Message "Error during thread cleanup: $_. Continuing anyway..." -Level WARN
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
                                                 
# Set up Ctrl+C handler to clean up running jobs when interrupted
trap {
    if ($_.Exception.GetType().Name -eq 'PipelineStoppedException' -or $_.Exception.Message -match 'pipeline.*stopped') {
        Write-Log -Message "(UpdateLoxone.ps1) Script interrupted by user (Ctrl+C). Cleaning up..." -Level WARN
        Write-Host "`nScript interrupted. Cleaning up running jobs..." -ForegroundColor Yellow
        
        # Clean up all running jobs
        $runningJobs = Get-Job | Where-Object { $_.State -eq 'Running' }
        if ($runningJobs.Count -gt 0) {
            Write-Log -Message "Stopping $($runningJobs.Count) running jobs..." -Level INFO
            Write-Host "Stopping $($runningJobs.Count) running jobs..." -ForegroundColor Yellow
            
            foreach ($job in $runningJobs) {
                try {
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Stopped job: $($job.Name)" -Level DEBUG
                } catch {
                    Write-Log -Message "Failed to stop job $($job.Name): $_" -Level DEBUG
                }
            }
        }
        
        # Clean up any remaining jobs
        Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
        
        # Force cleanup of thread pool
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        Write-Log -Message "Cleanup completed. Exiting." -Level INFO
        Write-Host "Cleanup completed." -ForegroundColor Green
        
        # Update toast if it was initialized (but not in parallel mode)
        if ($Global:PersistentToastInitialized -and -not $script:IsParallelMode -and $env:LOXONE_PARALLEL_MODE -ne "1") {
            try {
                Update-PersistentToast `
                    -StepName "Interrupted" `
                    -IsInteractive $true `
                    -ErrorOccurred $true `
                    -CurrentWeight $scriptGlobalState.CurrentWeight `
                    -TotalWeight $scriptGlobalState.TotalWeight
            } catch {}
        }
        
        exit 1
    } else {
        # Re-throw if not a pipeline stop
        throw $_
    }
}                                                  

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

# --- Smart Early Exit: Check software updates first, then miniserver cache ---
if (-not $prerequisites.ConfigUpdateNeeded -and -not $prerequisites.AppUpdateNeeded -and -not $ForceMiniserverUpdate) {
    Write-Log -Message "(UpdateLoxone.ps1) No software updates needed. Checking miniserver version cache..." -Level INFO
    
    # Check if we can skip miniserver checks using cached versions
    $msListPath = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt"
    $canSkipAllMS = $true
    $targetVersion = $prerequisites.LatestConfigVersion  # Use latest Config version as target for MS
    
    if (Test-Path $msListPath) {
        $msEntries = Get-MiniserverListWithCache -FilePath $msListPath
        $totalMS = ($msEntries | Measure-Object).Count
        $cachedMS = 0
        
        foreach ($msEntry in $msEntries) {
            # Check both cache age AND if MS needs update by passing target version (7 day cache)
            if (Test-MiniserverCacheValid -MSEntry $msEntry -TargetVersion $targetVersion -MaxCacheAgeHours 168) {
                $cachedMS++
                # Cache is valid and MS is at target version
                Write-Log -Message "(UpdateLoxone.ps1) MS $($msEntry.IP) is current at version $($msEntry.CachedVersion) (cache age: $([Math]::Round(((Get-Date) - $msEntry.LastChecked).TotalHours, 1))h)" -Level DEBUG
            } else {
                $canSkipAllMS = $false
                $reason = if (-not $msEntry.HasCache) { "no cache" } 
                         elseif (-not $msEntry.LastChecked) { "no timestamp" }
                         elseif ($msEntry.CachedVersion -ne $targetVersion) { "needs update: $($msEntry.CachedVersion) -> $targetVersion" }
                         else { "cache expired (age: $([Math]::Round(((Get-Date) - $msEntry.LastChecked).TotalHours, 1))h)" }
                Write-Log -Message "(UpdateLoxone.ps1) MS $($msEntry.IP) needs check: $reason" -Level DEBUG
            }
        }
        
        if ($canSkipAllMS -and $totalMS -gt 0) {
            Write-Log -Message "(UpdateLoxone.ps1) SMART EARLY EXIT: All $totalMS miniserver(s) are at target version $targetVersion. Skipping pipeline initialization." -Level INFO
            Write-Log -Message "(UpdateLoxone.ps1) Cache hit rate: $cachedMS/$totalMS (100%). All miniservers current." -Level INFO
        } else {
            Write-Log -Message "(UpdateLoxone.ps1) Cache hit rate: $cachedMS/$totalMS. Need to check $($totalMS - $cachedMS) miniserver(s)." -Level INFO
        }
    } else {
        Write-Log -Message "(UpdateLoxone.ps1) No miniserver list found at '$msListPath'. Proceeding with standard checks." -Level DEBUG
        $canSkipAllMS = $false
    }
    
    if ($canSkipAllMS) {
        # Create minimal pipeline data for "no work" scenario  
        $pipelineDataResult = @{
            Succeeded = $true
            UpdateTargetsInfo = [System.Collections.ArrayList]::new()
            WorkflowDefinition = @{
                TotalWeight = 0
                WorkflowSteps = @()
                ConfigUpdate = $false
                AppUpdate = $false
                MiniserverUpdates = @()
            }
        }
        
        Write-Log -Message "(UpdateLoxone.ps1) Smart early exit optimization active." -Level INFO
        $UpdateTargetsInfo = $pipelineDataResult.UpdateTargetsInfo
    } else {
        Write-Log -Message "(UpdateLoxone.ps1) Some miniservers need checking. Proceeding with full pipeline..." -Level INFO
        
        # CRITICAL FIX: Always call Initialize-UpdatePipelineData to run MS PreCheck
        # This will check actual versions and may find no updates are needed
        Write-Log -Message "(UpdateLoxone.ps1) Calling Initialize-UpdatePipelineData to run MS PreCheck..." -Level INFO
        
        # Call the pipeline data function which includes MS PreCheck
        $pipelineDataResult = Initialize-UpdatePipelineData -WorkflowContext $scriptContext -Prerequisites $prerequisites
        
        # If pipeline succeeded and no updates needed, we can exit early
        if ($pipelineDataResult.Succeeded) {
            $hasUpdates = $false
            Write-Log -Message "(UpdateLoxone.ps1) Checking UpdateTargetsInfo for updates needed..." -Level DEBUG
            foreach ($target in $pipelineDataResult.UpdateTargetsInfo) {
                Write-Log -Message "(UpdateLoxone.ps1) Target: $($target.Type) - $($target.Name), UpdateNeeded: $($target.UpdateNeeded), Status: $($target.Status)" -Level DEBUG
                if ($target.UpdateNeeded) {
                    Write-Log -Message "(UpdateLoxone.ps1) Found target with UpdateNeeded=true: $($target.Name)" -Level INFO
                    $hasUpdates = $true
                    break
                }
            }
            Write-Log -Message "(UpdateLoxone.ps1) Final hasUpdates value: $hasUpdates" -Level DEBUG
            
            if (-not $hasUpdates) {
                Write-Log -Message "(UpdateLoxone.ps1) MS PreCheck found all miniservers are current. No updates needed." -Level INFO
                
                # Check for connection errors even when no updates are needed
                $connectionErrors = @($pipelineDataResult.UpdateTargetsInfo | Where-Object { 
                    $_.Type -eq "Miniserver" -and 
                    $_.Status -eq "ErrorConnecting" 
                })
                
                if ($connectionErrors.Count -gt 0) {
                    Write-Log -Message "(UpdateLoxone.ps1) WARNING: $($connectionErrors.Count) miniserver(s) had connection errors" -Level WARN
                    foreach ($errorMS in $connectionErrors) {
                        Write-Log -Message "  - $($errorMS.Name): Connection failed" -Level WARN
                    }
                    # Set error flag even when no updates are needed
                    $script:ErrorOccurred = $true
                }
                
                # Update cache for all checked miniservers
                foreach ($target in $pipelineDataResult.UpdateTargetsInfo) {
                    if ($target.Type -eq "Miniserver" -and $target.InitialVersion -and $target.InitialVersion -ne "Unknown" -and $target.Status -ne "ErrorConnecting") {
                        $msListPath = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt"
                        
                        # Extract IP from Name (format: "MS 192.168.178.2")
                        $ip = $null
                        if ($target.Name -match '^MS\s+(.+)$') {
                            $ip = $matches[1].Trim()
                        } elseif ($target.IP) {
                            # Fallback to IP property if it exists
                            $ip = $target.IP
                        }
                        
                        if ($ip) {
                            Update-MiniserverListCache -FilePath $msListPath -IP $ip -Version $target.InitialVersion
                            Write-Log -Message "(UpdateLoxone.ps1) Updated cache for MS $($ip): $($target.InitialVersion)" -Level DEBUG
                        } else {
                            Write-Log -Message "(UpdateLoxone.ps1) Could not extract IP from target: $($target.Name)" -Level WARN
                        }
                    }
                }
                
                $UpdateTargetsInfo = $pipelineDataResult.UpdateTargetsInfo
                $canSkipAllMS = $true
            } else {
                Write-Log -Message "(UpdateLoxone.ps1) MS PreCheck found updates needed. Proceeding with pipeline." -Level INFO
                $UpdateTargetsInfo = $pipelineDataResult.UpdateTargetsInfo

                # Check if MS PreCheck jobs are running in parallel (early exit path)
                if ($pipelineDataResult.MSPreCheckJobsStarted -and $pipelineDataResult.MSPreCheckJobs) {
                    Write-Log -Message "(UpdateLoxone.ps1) [Parallel Mode - Early Exit] MS PreCheck jobs are running in background" -Level INFO
                    Write-Log -Message "(UpdateLoxone.ps1) [Parallel Mode - Early Exit] MS updates will be added dynamically as jobs complete" -Level INFO

                    # Store jobs for the parallel workflow to collect dynamically
                    $script:MSPreCheckJobs = $pipelineDataResult.MSPreCheckJobs
                    $script:MSPreCheckJobsActive = $true
                }

                # Check for connection errors in miniservers
                $connectionErrors = @($UpdateTargetsInfo | Where-Object { 
                    $_.Type -eq "Miniserver" -and 
                    $_.Status -eq "ErrorConnecting" 
                })
                
                if ($connectionErrors.Count -gt 0) {
                    Write-Log -Message "(UpdateLoxone.ps1) WARNING: $($connectionErrors.Count) miniserver(s) had connection errors" -Level WARN
                    foreach ($errorMS in $connectionErrors) {
                        Write-Log -Message "  - $($errorMS.Name): Connection failed" -Level WARN
                    }
                    # Set error flag but continue with other updates
                    $script:ErrorOccurred = $true
                }
            }
        } else {
            Write-Log -Message "(UpdateLoxone.ps1) Pipeline data collection failed. Creating fallback structure." -Level WARN
            
            # Fallback: Create minimal pipeline data if Initialize-UpdatePipelineData fails
            $pipelineDataResult = @{
                Succeeded = $false
                UpdateTargetsInfo = [System.Collections.ArrayList]::new()
                WorkflowDefinition = @{
                    TotalWeight = 0
                    WorkflowSteps = @()
                    ConfigUpdate = $false
                    AppUpdate = $false
                    MiniserverUpdates = @()
                }
            }
            
            # Only add miniserver entries if we're in fallback mode
            foreach ($msEntry in $msEntries) {
                if (-not (Test-MiniserverCacheValid -MSEntry $msEntry -TargetVersion $targetVersion -MaxCacheAgeHours 168)) {
                    # Uncached or expired - needs version checking
                    $msTarget = @{
                        Type = "Miniserver"
                        Name = "MS $($msEntry.IP)"  # Use just the IP for display name
                        UpdateNeeded = $true  # Need to check this one
                        Status = "NeedsVersionCheck"
                        OriginalEntry = $msEntry.Url  # Sequential mode expects URL string here
                        CacheEntry = $msEntry  # Store full cache entry for parallel mode processing
                        CachedVersion = $msEntry.CachedVersion
                        IP = $msEntry.IP
                        Url = $msEntry.Url
                        TargetVersion = $targetVersion
                        Channel = $Channel  # Add channel info
                    }
                    $null = $pipelineDataResult.UpdateTargetsInfo.Add($msTarget)
                    Write-Log -Message "(UpdateLoxone.ps1) Added MS $($msEntry.IP) to fallback pipeline for version checking (cached: $($msEntry.CachedVersion), target: $targetVersion)" -Level DEBUG
                } else {
                    # Cached and valid - already up-to-date but add for final summary
                    $msTarget = @{
                        Type = "Miniserver"
                        Name = "MS $($msEntry.IP)"  # Use just the IP for display name
                        UpdateNeeded = $false  # Already known to be current from cache
                        Status = "UpToDate"  # Mark as up-to-date for final summary
                        InitialVersion = $msEntry.CachedVersion
                        VersionAfterUpdate = $msEntry.CachedVersion
                        OriginalEntry = $msEntry.Url
                        CacheEntry = $msEntry
                        IP = $msEntry.IP
                        Url = $msEntry.Url
                        TargetVersion = $targetVersion
                        Channel = $Channel  # Add channel info
                    }
                    $null = $pipelineDataResult.UpdateTargetsInfo.Add($msTarget)
                    Write-Log -Message "(UpdateLoxone.ps1) Added cached MS $($msEntry.IP) as up-to-date in fallback (version: $($msEntry.CachedVersion))" -Level DEBUG
                }
            }
            
            $UpdateTargetsInfo = $pipelineDataResult.UpdateTargetsInfo
            Write-Log -Message "(UpdateLoxone.ps1) Fallback pipeline will check $($UpdateTargetsInfo.Count) miniserver(s) for version updates." -Level INFO
        }
    }
} else {
    Write-Log -Message "(UpdateLoxone.ps1) Updates detected or forced - proceeding with full pipeline initialization..." -Level INFO

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

    # Check if MS PreCheck jobs are running in parallel (parallel mode optimization)
    if ($pipelineDataResult.MSPreCheckJobsStarted -and $pipelineDataResult.MSPreCheckJobs) {
        Write-Log -Message "(UpdateLoxone.ps1) [Parallel Mode] MS PreCheck jobs are running in background" -Level INFO
        Write-Log -Message "(UpdateLoxone.ps1) [Parallel Mode] Config/App downloads will start IMMEDIATELY - MS jobs continue parallel" -Level INFO
        Write-Log -Message "(UpdateLoxone.ps1) [Parallel Mode] MS updates will be added dynamically as jobs complete" -Level INFO

        # Store jobs for the parallel workflow to collect dynamically
        $script:MSPreCheckJobs = $pipelineDataResult.MSPreCheckJobs
        $script:MSPreCheckJobsActive = $true

        # DO NOT wait for jobs here! Let the parallel workflow handle them dynamically
    }
}

# Common processing for both early exit and full pipeline paths
$itemNumDebugInit = 0
foreach ($itemDebug in $UpdateTargetsInfo) {
    Write-Host "DEBUG: (UpdateLoxone.ps1) After pipeline initialization - Item #$itemNumDebugInit Type: $($itemDebug.Type) - Name: $($itemDebug.Name)"
    $itemNumDebugInit++
}

# Set script variables (handle both early exit and full pipeline cases)
$script:TotalWeight = if ($pipelineDataResult.TotalWeight) { $pipelineDataResult.TotalWeight } else { 0 }
$script:totalSteps = if ($pipelineDataResult.TotalSteps) { $pipelineDataResult.TotalSteps } else { 0 }
$script:totalDownloads = if ($pipelineDataResult.TotalDownloads) { $pipelineDataResult.TotalDownloads } else { 0 }
$script:CurrentWeight = if ($pipelineDataResult.InitialCheckWeight) { $pipelineDataResult.InitialCheckWeight } else { 0 }

$scriptGlobalState.TotalWeight = $script:TotalWeight
$scriptGlobalState.totalSteps = $script:totalSteps
$scriptGlobalState.totalDownloads = $script:totalDownloads
$scriptGlobalState.CurrentWeight = $script:CurrentWeight 

Write-Log -Message "(UpdateLoxone.ps1) Pipeline Data Initialized - TotalWeight: $($script:TotalWeight), TotalSteps: $($script:totalSteps), TotalDownloads: $($script:totalDownloads)" -Level DEBUG


# --- Conditional Toast Initialization (After initial checks and context setup) ---
$anySoftwareUpdateNeeded = ($UpdateTargetsInfo | Where-Object { ($_.Type -eq "Config" -or $_.Type -eq "App") -and $_.UpdateNeeded }).Count -gt 0
# Only count MS that actually need updates, not just all MS entries
$anyMSPotentiallyNeedingUpdate = ($UpdateTargetsInfo | Where-Object { $_.Type -eq "Miniserver" -and $_.UpdateNeeded }).Count -gt 0 

# Determine effective parallel execution mode
# Priority: 1) Command-line switch (if explicitly set), 2) Configuration file, 3) Default (false)
# BUT: Never use parallel mode when running non-interactively (e.g., scheduled task)
if ($PSBoundParameters.ContainsKey('Parallel')) {
    # Command-line switch was explicitly provided, use it regardless of config
    $effectiveParallelMode = $Parallel
    Write-Log -Message "(UpdateLoxone.ps1) Using command-line -Parallel parameter: $Parallel (overrides configuration)" -Level DEBUG
} else {
    # No command-line switch, use configuration value
    $effectiveParallelMode = $script:UseParallelExecution
    Write-Log -Message "(UpdateLoxone.ps1) Using configuration UseParallelExecution: $($script:UseParallelExecution)" -Level DEBUG
}

# Override parallel mode if not interactive (scheduled task, etc.)
# BUT: If user explicitly specified -Parallel, respect their choice
if (-not $scriptContext.IsInteractive -and $effectiveParallelMode -and -not $PSBoundParameters.ContainsKey('Parallel')) {
    Write-Log -Message "(UpdateLoxone.ps1) Parallel mode disabled for non-interactive execution (scheduled task)" -Level WARN
    $effectiveParallelMode = $false
} elseif (-not $scriptContext.IsInteractive -and $PSBoundParameters.ContainsKey('Parallel') -and $Parallel) {
    Write-Log -Message "(UpdateLoxone.ps1) Running in parallel mode despite non-interactive context (explicitly requested via -Parallel switch)" -Level INFO
}

# Consolidated parallel mode detection (was 5 verbose log entries)
$parallelSwitchMsg = if ($PSBoundParameters.ContainsKey('Parallel')) { "$Parallel (explicit)" } else { "default" }
Write-Log -Message "(UpdateLoxone.ps1) Parallel mode: $effectiveParallelMode (switch: $parallelSwitchMsg, config: $($script:UseParallelExecution), interactive: $($scriptContext.IsInteractive))" -Level INFO
Write-Log -Message "(UpdateLoxone.ps1) Environment LOXONE_PARALLEL_MODE (before): '$($env:LOXONE_PARALLEL_MODE)'" -Level INFO

# Environment variables will be set later only if there's actual work to do

if (-not $anySoftwareUpdateNeeded -and -not $anyMSPotentiallyNeedingUpdate -and -not $scriptContext.IsInteractive -and $scriptContext.IsSelfInvokedForUpdateCheck) {
    Write-Log -Message "(UpdateLoxone.ps1) No software updates needed, no MS to check (or list empty), and script is self-invoked non-interactively. Exiting cleanly." -Level INFO
    if ($scriptContext.LogFile) { Invoke-LogFileRotation -LogFilePath $scriptContext.LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue }
    exit 0
}

if (
    ($scriptContext.IsSelfInvokedForUpdateCheck -and $anySoftwareUpdateNeeded) -or # For self-invoked (scheduled task), only if software update is needed
    (-not $scriptContext.IsSelfInvokedForUpdateCheck -and ($anySoftwareUpdateNeeded -or $anyMSPotentiallyNeedingUpdate)) # For non-self-invoked (e.g. direct run), if any update or MS check is pending
) {
    # Set LOXONE_PARALLEL_MODE early so toast can detect it
    if ($effectiveParallelMode) {
        Write-Log -Message "(UpdateLoxone.ps1) Setting LOXONE_PARALLEL_MODE environment variable early for toast initialization" -Level INFO
        $env:LOXONE_PARALLEL_MODE = "1"
        # Force file logging even in parallel mode so we can see what's happening
        $env:LOXONE_FORCE_FILE_LOGGING = "1"
        
        # Pre-calculate component information for toast
        $componentInfo = @{
            Config = $prerequisites.ConfigUpdateNeeded
            App = $prerequisites.AppUpdateNeeded
            Miniservers = $anyMSPotentiallyNeedingUpdate
        }
        [System.Environment]::SetEnvironmentVariable("LOXONE_PARALLEL_COMPONENTS", ($componentInfo | ConvertTo-Json -Compress), "Process")
        Write-Log -Message "(UpdateLoxone.ps1) Set LOXONE_PARALLEL_COMPONENTS early: $($componentInfo | ConvertTo-Json -Compress)" -Level DEBUG
    }
    
    Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) ENTERING initial toast display block. Conditions met: IsSelfInvokedForUpdateCheck=$($scriptContext.IsSelfInvokedForUpdateCheck), anySoftwareUpdateNeeded=$anySoftwareUpdateNeeded, anyMSPotentiallyNeedingUpdate=$anyMSPotentiallyNeedingUpdate, IsRunningAsSystem=$($scriptContext.IsRunningAsSystem)"
    if (-not $scriptContext.IsRunningAsSystem) {
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Not running as SYSTEM. Proceeding with Initialize-LoxoneToastAppId and initial toast."
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
        
        # Skip progress toast updates when no work to do (optimization)
        if ($script:TotalWeight -le 0) {
            Write-Log -Message "(UpdateLoxone.ps1) OPTIMIZATION: Skipping progress toast update - no work to do (TotalWeight: $($script:TotalWeight))" -Level DEBUG
        } else {
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
            } catch {
                Write-Log -Level ERROR -Message "ERROR during Update-PersistentToast (Second call for initial check step): $($_.Exception.ToString())"
            }
        }
        Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Update-PersistentToast (Second call for initial check step) instrumentation block finished. Current Global:PersistentToastInitialized: $Global:PersistentToastInitialized"
    } else { 
        Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Global:PersistentToastInitialized is FALSE after initial attempt. Second toast update SKIPPED for step: $initialCheckStepName."
    } 

} 
else { 
    Write-Log -Level INFO -Message "(UpdateLoxone.ps1) No software updates needed and no MS to check. Skipping initial toast display block."
} 
# --- Main Pipeline Execution ---
try {
    Write-Log -Message "Starting main pipeline execution" -Level INFO
    
    # Store parallel mode state for finally block
    $script:IsParallelMode = $effectiveParallelMode
    
    # Prepare global state
    $scriptGlobalState.TotalWeight = $script:TotalWeight 
    $scriptGlobalState.totalSteps = $script:totalSteps 
    $scriptGlobalState.currentDownload = $script:currentDownload 
    $scriptGlobalState.totalDownloads = $script:totalDownloads 

    # --- Check for Parallel Execution Mode ---
    if ($effectiveParallelMode) {
        # First check if there's any work to do before setting up parallel infrastructure
        # Quick pre-check to avoid unnecessary setup
        $hasConfigWork = $UpdateTargetsInfo | Where-Object { $_.Type -eq "Config" -and ($_.UpdateNeeded -eq $true -or $_.UpdateNeeded -eq "True") }
        $hasAppWork = $UpdateLoxoneApp -and ($UpdateTargetsInfo | Where-Object { $_.Type -eq "App" -and ($_.UpdateNeeded -eq $true -or $_.UpdateNeeded -eq "True") })
        $hasMSWork = $UpdateTargetsInfo | Where-Object { $_.Type -eq "Miniserver" -and ($_.UpdateNeeded -eq $true -or $_.UpdateNeeded -eq "True") }
        
        if (-not $hasConfigWork -and -not $hasAppWork -and -not $hasMSWork) {
            Write-Log -Message "No work detected for parallel workflow (Config: $($hasConfigWork -ne $null), App: $($hasAppWork -ne $null), MS: $($hasMSWork -ne $null)). Skipping parallel setup." -Level INFO
            # Skip to the no-work result
            $parallelResult = @{
                Success = $true
                Downloads = @()
                Installations = @()
                MiniserverResults = @()
                TotalDuration = 0
            }
            # Set a flag to skip the rest of parallel setup
            $skipParallelSetup = $true
        } else {
            # Consolidated parallel execution start (was 5 verbose log entries)
            Write-Log -Message "Starting parallel execution (MaxConcurrency: $MaxConcurrency, MaxMS: $MaxMSConcurrency)" -Level INFO
            $skipParallelSetup = $false
        }
        
        if (-not $skipParallelSetup) {
            # Build workflow definition for parallel execution
            $workflowDefinition = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @()  # Changed from Miniservers to MiniserverUpdates
                ScriptSaveFolder = $scriptContext.ScriptSaveFolder
                DownloadDir = $scriptContext.DownloadDir  # Add DownloadDir for parallel workflow
                EnableCRC = $EnableCRC
            }
    
    # Check Config update requirements
    $configTarget = $UpdateTargetsInfo | Where-Object { $_.Type -eq "Config" -and ($_.UpdateNeeded -eq $true -or $_.UpdateNeeded -eq "True") } | Select-Object -First 1
    if ($configTarget) {
        Write-Log -Message "Config update needed: $($configTarget.InitialVersion) -> $($configTarget.TargetVersion)" -Level INFO
        Write-Log -Message "ConfigTarget properties - DownloadUrl: '$($configTarget.DownloadUrl)', ExpectedCRC: '$($configTarget.ExpectedCRC)', ExpectedSize: '$($configTarget.ExpectedSize)'" -Level DEBUG
        
        # Debug: Check all properties
        $configTarget | Get-Member -MemberType Properties | ForEach-Object {
            Write-Log -Message "  ConfigTarget.$($_.Name) = '$($configTarget.$($_.Name))'" -Level DEBUG
        }
        
        $workflowDefinition.ConfigUpdate = @{
            Url = $configTarget.DownloadUrl  # Fixed property name casing
            Version = $configTarget.TargetVersion
            TargetVersion = $configTarget.TargetVersion  # Add this for parallel workflow
            InitialVersion = $configTarget.InitialVersion  # Track if it's a fresh install
            ExpectedCRC32 = $configTarget.ExpectedCRC
            FileSize = $configTarget.ExpectedSize
            OutputPath = $configTarget.ZipFilePath  # Use the pre-configured path from target
        }
        
        Write-Log -Message "WorkflowDefinition.ConfigUpdate.Url = '$($workflowDefinition.ConfigUpdate.Url)'" -Level DEBUG
    }
    
    # Check App update requirements
    Write-Log -Message "Checking App update requirements. UpdateLoxoneApp: $UpdateLoxoneApp" -Level DEBUG
    if ($UpdateLoxoneApp) {
        $appTarget = $UpdateTargetsInfo | Where-Object { $_.Type -eq "App" -and ($_.UpdateNeeded -eq $true -or $_.UpdateNeeded -eq "True") } | Select-Object -First 1
        Write-Log -Message "App target found: $($null -ne $appTarget), UpdateNeeded: $($appTarget.UpdateNeeded)" -Level DEBUG
        if ($appTarget) {
            Write-Log -Message "App update needed: $($appTarget.InitialVersion) -> $($appTarget.TargetVersion)" -Level INFO
            Write-Log -Message "AppTarget properties - DownloadUrl: '$($appTarget.DownloadUrl)', ExpectedCRC: '$($appTarget.ExpectedCRC)', ExpectedSize: '$($appTarget.ExpectedSize)'" -Level DEBUG
            
            $workflowDefinition.AppUpdate = @{
                Url = $appTarget.DownloadUrl  # Fixed property name casing
                Version = $appTarget.TargetVersion
                TargetVersion = $appTarget.TargetVersion  # Add this for parallel workflow
                InitialVersion = $appTarget.InitialVersion  # Track if it's a fresh install
                ExpectedCRC32 = $appTarget.ExpectedCRC
                FileSize = $appTarget.ExpectedSize
                OutputPath = $appTarget.InstallerPath  # Use the pre-configured path from target
            }
            
            Write-Log -Message "WorkflowDefinition.AppUpdate.Url = '$($workflowDefinition.AppUpdate.Url)'" -Level DEBUG
        }
    }
    
    # Check Miniserver update requirements
    # First check prerequisites.MSList
    if ($prerequisites.MSList -and $prerequisites.MSList.Count -gt 0) {
        # The parallel workflow expects MiniserverUpdates, not Miniservers
        $workflowDefinition.MiniserverUpdates = @()
        foreach ($msEntry in $prerequisites.MSList) {
            Write-Log -Message "Adding Miniserver to parallel workflow from prerequisites: $($msEntry.IP)" -Level DEBUG
            $workflowDefinition.MiniserverUpdates += @{
                IP = $msEntry.IP
                Credential = $msEntry.Credential
                UpdateLevel = $prerequisites.MSUpdateLevel
                TargetVersion = $prerequisites.MSTargetVersion  # Add target version for MS worker
            }
        }
    }
    # Also check UpdateTargetsInfo for miniservers that need updates
    else {
        # Debug: Show what's in UpdateTargetsInfo before filtering
        Write-Log -Message "UpdateTargetsInfo has $($UpdateTargetsInfo.Count) entries total" -Level DEBUG
        foreach ($target in $UpdateTargetsInfo) {
            Write-Log -Message "UpdateTarget: Type='$($target.Type)', Name='$($target.Name)', UpdateNeeded='$($target.UpdateNeeded)', HasOriginalEntry=$($null -ne $target.OriginalEntry)" -Level DEBUG
        }
        
        # Filter out miniservers with connection errors or network unreachable
        $msTargets = @($UpdateTargetsInfo | Where-Object { 
            $_.Type -eq "Miniserver" -and 
            $_.UpdateNeeded -and 
            $_.Status -ne "ErrorConnecting" -and
            $_.Status -ne "NetworkUnreachable"
        })
        Write-Log -Message "After filtering: Found $($msTargets.Count) miniserver(s) needing updates (excluding connection errors)" -Level INFO
        
        # Start MS Worker if: (1) MS targets exist OR (2) MS PreCheck jobs are running (parallel mode)
        if (($msTargets -and $msTargets.Count -gt 0) -or $script:MSPreCheckJobsActive) {
            if ($msTargets -and $msTargets.Count -gt 0) {
                Write-Log -Message "Found $($msTargets.Count) miniserver(s) needing updates in UpdateTargetsInfo" -Level INFO
            }
            if ($script:MSPreCheckJobsActive) {
                Write-Log -Message "[Parallel Mode] MS PreCheck jobs are running - MS Worker will collect them dynamically" -Level INFO
            }
            $workflowDefinition.MiniserverUpdates = @()
            foreach ($msTarget in $msTargets) {
                Write-Log -Message "Adding Miniserver to parallel workflow from UpdateTargetsInfo: $($msTarget.Name)" -Level DEBUG
                Write-Log -Message "MS Target properties: $($msTarget | ConvertTo-Json -Compress)" -Level DEBUG
                Write-Log -Message "MS InitialVersion value: '$($msTarget.InitialVersion)' (Type: $($msTarget.InitialVersion.GetType().Name))" -Level INFO
                
                # Parse the miniserver entry to get IP and credentials
                $entryToProcess = $null
                $entrySource = $null
                if ($msTarget.CacheEntry) {
                    # Smart cache format (new)
                    $entryToProcess = $msTarget.CacheEntry
                    $entrySource = "CacheEntry"
                    Write-Log -Message "CacheEntry found: $($msTarget.CacheEntry.Url -replace "([Pp]assword[=:])[^@;]+", '$1****')" -Level DEBUG
                } elseif ($msTarget.OriginalEntry) {
                    # Legacy format or string URL
                    $entryToProcess = $msTarget.OriginalEntry
                    $entrySource = "OriginalEntry"
                    Write-Log -Message "OriginalEntry found: $($msTarget.OriginalEntry -replace "([Pp]assword[=:])[^@;]+", '$1****')" -Level DEBUG
                }
                
                if ($entryToProcess) {
                    # Parse the MS entry (could be string URL or cache entry object)
                    $msEntry = $entryToProcess
                    $msIP = $null
                    $msCredential = $null
                    
                    if ($msEntry -is [string]) {
                        # Parse string format entry
                        # Extract IP - exclude colons, slashes, AND commas (for cached entries)
                        if ($msEntry -match '@([^:/,]+)') {
                            $msIP = $matches[1]
                        }
                        if ($msEntry -match '://([^@]+)@') {
                            $userPass = $matches[1]
                            if ($userPass -match '([^:]+):(.+)') {
                                $username = $matches[1]
                                $password = $matches[2]
                                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                                $msCredential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
                            }
                        }
                    }
                    elseif ($msEntry.IP -and $msEntry.Credential) {
                        # Already parsed format with credential object
                        $msIP = $msEntry.IP
                        $msCredential = $msEntry.Credential
                    }
                    elseif ($msEntry.IP -and $msEntry.Url) {
                        # Smart cache format - extract credential from URL
                        $msIP = $msEntry.IP
                        if ($msEntry.Url -match '://([^@]+)@') {
                            $userPass = $matches[1]
                            if ($userPass -match '([^:]+):(.+)') {
                                $username = $matches[1]
                                $password = $matches[2]
                                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                                $msCredential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
                            }
                        }
                    }
                    
                    # Create the miniserver update object with all required properties
                    if ($msIP -and $msCredential) {
                        # Use the channel from msTarget or fall back to prerequisites or script parameter
                        $updateChannel = if ($msTarget.Channel) { 
                            $msTarget.Channel 
                        } elseif ($prerequisites.MSUpdateLevel) { 
                            $prerequisites.MSUpdateLevel 
                        } else { 
                            $Channel  # Use the script parameter as final fallback
                        }
                        Write-Log -Message "MS UpdateLevel - msTarget.Channel: '$($msTarget.Channel)', prerequisites.MSUpdateLevel: '$($prerequisites.MSUpdateLevel)', script Channel: '$Channel', using: '$updateChannel'" -Level DEBUG
                        
                        $msUpdate = @{
                            IP = $msIP
                            Credential = $msCredential
                            UpdateLevel = $updateChannel
                            Name = $msTarget.Name
                            TargetVersion = $msTarget.TargetVersion
                            CurrentVersion = $msTarget.InitialVersion  # Pass pre-checked version to avoid re-checking
                            OriginalEntry = if ($msEntry -is [string]) { $msEntry } elseif ($msEntry -and $msEntry.Url) { $msEntry.Url } else { $null }  # Pass entry for fallback
                        }
                        
                        $workflowDefinition.MiniserverUpdates += $msUpdate
                        Write-Log -Message "Added miniserver $msIP to workflow (Channel: $updateChannel, CurrentVersion: '$($msUpdate.CurrentVersion)')" -Level INFO
                    }
                    else {
                        Write-Log -Message "Warning: Failed to parse miniserver entry - IP: $msIP, Has Credential: $($null -ne $msCredential)" -Level WARN
                    }
                }
                else {
                    Write-Log -Message "Warning: Miniserver target missing both CacheEntry and OriginalEntry properties - Available properties: $($msTarget.PSObject.Properties.Name -join ', ')" -Level WARN
                }
            }
        }
    }
    
            # Execute parallel workflow only if there's work to do
            Write-Log -Message "Checking if workflow has work - ConfigUpdate: $($null -ne $workflowDefinition.ConfigUpdate), AppUpdate: $($null -ne $workflowDefinition.AppUpdate), MiniserverUpdates: $($workflowDefinition.MiniserverUpdates.Count)" -Level DEBUG
            $hasWork = $workflowDefinition.ConfigUpdate -or 
                       $workflowDefinition.AppUpdate -or 
                       ($workflowDefinition.MiniserverUpdates -and $workflowDefinition.MiniserverUpdates.Count -gt 0)
            Write-Log -Message "Workflow has work: $hasWork" -Level INFO
            
            if ($hasWork) {
                # Update parallel mode environment variables with actual work information if not already set
                if ($effectiveParallelMode -and $env:LOXONE_PARALLEL_MODE -ne "1") {
                    Write-Log -Message "(UpdateLoxone.ps1) Setting LOXONE_PARALLEL_MODE environment variable to '1' for parallel execution" -Level INFO
                    $env:LOXONE_PARALLEL_MODE = "1"
                }
                
                if ($effectiveParallelMode) {
                    # Update component information with actual workflow data
                    $componentInfo = @{
                        Config = ($UpdateTargetsInfo | Where-Object { $_.Type -eq "Config" -and $_.UpdateNeeded }).Count -gt 0
                        App = ($UpdateTargetsInfo | Where-Object { $_.Type -eq "App" -and $_.UpdateNeeded }).Count -gt 0
                        Miniservers = ($workflowDefinition.MiniserverUpdates -and $workflowDefinition.MiniserverUpdates.Count -gt 0)
                    }
                    [System.Environment]::SetEnvironmentVariable("LOXONE_PARALLEL_COMPONENTS", ($componentInfo | ConvertTo-Json -Compress), "Process")
                    Write-Log -Message "(UpdateLoxone.ps1) Updated LOXONE_PARALLEL_COMPONENTS with workflow data: $($componentInfo | ConvertTo-Json -Compress)" -Level DEBUG
                }
                
                try {
                    Write-Log -Message "Starting parallel workflow execution..." -Level INFO
                    $parallelResult = Start-ParallelWorkflow -WorkflowDefinition $workflowDefinition `
                                                             -MaxConcurrency $MaxConcurrency `
                                                             -MaxMSConcurrency $MaxMSConcurrency `
                                                             -MSPreCheckJobs $script:MSPreCheckJobs `
                                                             -MSPreCheckJobsActive ($script:MSPreCheckJobsActive -eq $true)
        
        # Update target info based on parallel results
        foreach ($download in $parallelResult.Downloads.Values) {
            $targetType = if ($download.Component -eq 'Config') { 'Config' } else { 'App' }
            $target = $UpdateTargetsInfo | Where-Object { $_.Type -eq $targetType } | Select-Object -First 1
            
            if ($target -and $download.Status -eq 'Completed') {
                # Mark as download successful, but this will be overridden if installation happens
                $target.Status = 'DownloadSuccessful'
                # Store the file path for later use if needed (Config extraction, etc.)
                if ($download.FilePath) {
                    # Only certain target types have InstallerPath property
                    if ($target.PSObject.Properties.Name -contains 'InstallerPath') {
                        $target.InstallerPath = $download.FilePath
                    }
                }
                Write-Log -Message "$targetType download completed successfully" -Level INFO
            }
            elseif ($target -and $download.Status -eq 'Failed') {
                $target.Status = 'UpdateFailed (Download)'
                # Note: Target objects don't have Error property
                Write-Log -Message "$targetType download failed: $($download.Error)" -Level ERROR
            }
        }
        
        if ($parallelResult.Installations -and $parallelResult.Installations.Count -gt 0) {
            Write-Log -Message "Processing installation results. Count: $($parallelResult.Installations.Count)" -Level INFO
            foreach ($install in $parallelResult.Installations.Values) {
                Write-Log -Message "Processing install result - Component: $($install.Component), Status: $($install.Status), Version: $($install.Version)" -Level INFO
            $targetType = if ($install.Component -eq 'Config') { 'Config' } else { 'App' }
            $target = $UpdateTargetsInfo | Where-Object { $_.Type -eq $targetType } | Select-Object -First 1
            
            if ($target -and $install.Status -eq 'Completed') {
                # Check if this is a fresh install or update
                $isNewInstall = ($target.InitialVersion -eq $null -or $target.InitialVersion -eq "" -or $target.InitialVersion -eq "0.0.0.0")
                $target.Status = if ($isNewInstall) { 'InstallSuccessful' } else { 'UpdateSuccessful' }
                $target.UpdatePerformed = $true
                $scriptGlobalState.anyUpdatePerformed = $true
                
                # Get installed version
                if ($targetType -eq 'Config') {
                    $configExePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
                    $installedVersion = if ($configExePath) { Get-InstalledVersion -ExePath $configExePath -ErrorAction SilentlyContinue } else { $null }
                } else {
                    # Get app version from registry - need to provide the registry path
                    $appDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -ErrorAction SilentlyContinue
                    # Use DisplayVersion for UI, fall back to FileVersion
                    $installedVersion = if ($appDetails -and -not $appDetails.Error) {
                        if ($appDetails.DisplayVersion) { $appDetails.DisplayVersion } else { $appDetails.FileVersion }
                    } else { $null }
                }
                $target.VersionAfterUpdate = $installedVersion

                if ($install.RestartRequired) {
                    Write-Log -Message "$targetType installation completed successfully but SYSTEM RESTART IS REQUIRED (VC++ Redistributable). Version: $installedVersion" -Level WARN
                    $scriptGlobalState.RestartRequired = $true
                } else {
                    Write-Log -Message "$targetType installation completed successfully. Version: $installedVersion" -Level INFO
                }
            }
            elseif ($target -and $install.Status -eq 'Failed') {
                $target.Status = 'UpdateFailed (Install)'
                # Note: Target objects don't have Error property, and installation result may not have Error
                $errorMsg = if ($install.Error) { $install.Error } elseif ($install.ExitCode) { "Exit code: $($install.ExitCode)" } else { "Installation failed" }
                Write-Log -Message "$targetType installation failed: $errorMsg" -Level ERROR
            }
        }
        }
        
        # Check for components that were downloaded but not installed
        foreach ($target in $UpdateTargetsInfo) {
            if ($target.Status -eq 'DownloadSuccessful' -and $target.Type -in @('Config', 'App')) {
                # This means it was downloaded but installation was never attempted
                $target.Status = 'UpdateFailed (NotInstalled)'
                Write-Log -Message "$($target.Type) was downloaded but installation was not attempted - marking as failed" -Level WARN
            }
        }
        
        # Update MS results (only if we have valid results to process)
        if ($parallelResult.Miniservers -and $parallelResult.Miniservers.Count -gt 0) {
            # Process miniserver results from hashtable
            foreach ($msResultPair in $parallelResult.Miniservers.GetEnumerator()) {
                $msResult = $msResultPair.Value
            # Find MS target in UpdateTargetsInfo
            # Try multiple matching strategies to find the existing MS entry
            $msTarget = $UpdateTargetsInfo | Where-Object { 
                ($_.Type -eq "Miniserver" -or $_.Type -eq "MS") -and 
                ($_.IP -eq $msResult.IP -or 
                 $_.Name -eq "MS $($msResult.IP)" -or 
                 $_.Name -eq $msResult.IP -or
                 ($_.OriginalEntry -and $_.OriginalEntry -match "@$([regex]::Escape($msResult.IP))"))
            } | Select-Object -First 1
            
            if (-not $msTarget) {
                # Only create if truly doesn't exist (shouldn't happen if pre-check ran)
                Write-Log -Message "Warning: Creating new MS target for $($msResult.IP) - this shouldn't happen if pre-check ran" -Level WARN
                $msTarget = New-Object PSObject -Property @{
                    Type = "Miniserver"
                    Name = "MS $($msResult.IP)"
                    Status = ""
                    UpdatePerformed = $false
                    VersionAfterUpdate = $null
                    Error = $null
                    InitialVersion = $msResult.Version
                    IP = $msResult.IP
                }
                $UpdateTargetsInfo.Add($msTarget)
            }
            
            # Clear any previous error status if the update succeeded
            if ($msResult.Stage -eq 'Complete' -and $msTarget.Status -eq 'ErrorConnecting') {
                Write-Log -Message "MS $($msResult.IP) was previously unreachable but succeeded in parallel workflow" -Level INFO
            }
            
            if ($msResult.Success) {
                # Check if it was already up to date or actually updated
                if ($msResult.Status -eq "AlreadyCurrent") {
                    $msTarget.Status = 'UpToDate'
                    $msTarget.UpdatePerformed = $false
                    $msTarget.VersionAfterUpdate = $msResult.NewVersion
                    Write-Log -Message "MS $($msResult.IP) already at version $($msResult.NewVersion)" -Level INFO
                    
                    # Update cache with confirmed current version
                    $msListPath = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt"
                    Update-MiniserverListCache -FilePath $msListPath -IP $msResult.IP -Version $msResult.NewVersion
                } else {
                    $msTarget.Status = 'UpdateSuccessful'
                    $msTarget.UpdatePerformed = $true
                    $msTarget.VersionAfterUpdate = $msResult.NewVersion
                    $scriptGlobalState.anyUpdatePerformed = $true
                    Write-Log -Message "MS $($msResult.IP) updated successfully to version $($msResult.NewVersion)" -Level INFO
                    
                    # Update cache with new version after successful update
                    $msListPath = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt"
                    Update-MiniserverListCache -FilePath $msListPath -IP $msResult.IP -Version $msResult.NewVersion
                }
            }
            elseif (-not $msResult.Success) {
                $msTarget.Status = 'UpdateFailed'
                $msTarget.Error = $msResult.Error

                # DO NOT update cache on failure/timeout
                # The MS might have updated after we timed out
                # Let the next run's PreCheck verify the actual version

                try {
                    # Create a safe error message for logging
                    $errorMsg = if ($msResult.Error) {
                        # Remove or replace problematic characters
                        $msResult.Error -replace "[`'`"]", ""
                    } else {
                        "Unknown error"
                    }
                    # Safe string formatting to handle null/empty values
                    $ipAddress = if ($msResult.IP) { $msResult.IP } else { "Unknown IP" }
                    Write-Log -Message "MS $ipAddress update failed: $errorMsg" -Level ERROR

                    # Log that cache was NOT updated (important for debugging)
                    Write-Log -Message "Cache NOT updated for failed MS $ipAddress - will verify actual version on next run" -Level INFO
                } catch {
                    # If Write-Log fails, write to host as fallback
                    Write-Host "ERROR: MS $($msResult.IP) update failed - could not write to log" -ForegroundColor Red
                }
            }
            } # End foreach msResultPair
        } # End miniserver results processing
        
        Write-Log -Message "Parallel workflow completed. Success: $($parallelResult.Success), Duration: $([Math]::Round($parallelResult.TotalDuration, 1))s" -Level INFO
        
        if (-not $parallelResult.Success) {
            $script:ErrorOccurred = $true
            # Safe error count handling
            $errorCount = if ($parallelResult.Errors -and $parallelResult.Errors.Count) { $parallelResult.Errors.Count } else { "unknown number of" }
            Write-Log -Message "Parallel workflow completed with errors: $errorCount failures" -Level ERROR
        }
        
        # Send completion signal to progress worker now that we're done processing results
        # Only send signal if there was actually work to do (progress worker was started)
        $hadWork = $workflowDefinition.ConfigUpdate -or $workflowDefinition.AppUpdate -or 
                   ($workflowDefinition.MiniserverUpdates -and $workflowDefinition.MiniserverUpdates.Count -gt 0)
        
        if ($hadWork -and $parallelResult.Pipeline -and $parallelResult.Pipeline.ProgressQueue) {
            Write-Log -Message "Sending WorkflowComplete signal to progress worker" -Level INFO
            $completionMsg = @{
                Type = 'WorkflowComplete'
                Timestamp = Get-Date
                Message = 'All result processing complete'
            }
            [void]$parallelResult.Pipeline.ProgressQueue.Enqueue($completionMsg)
            
            # Give progress worker time to process the signal, dismiss its toast, and exit
            # Progress Worker needs time to dismiss its notification before we show the final toast
            Write-Log -Message "Waiting for Progress Worker to dismiss its toast notification..." -Level INFO
            Start-Sleep -Milliseconds 3500
            
            # Now clean up the progress worker and any other remaining jobs
            Write-Log -Message "Performing final cleanup of all ThreadJobs..." -Level INFO
        } elseif (-not $hadWork) {
            Write-Log -Message "No updates were needed, so no progress worker was started. Skipping completion signal." -Level INFO
            
            # But check for any ghost progress workers from previous runs
            $ghostProgressWorkers = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -match "ProgressWorker|Progress Worker" -and ($_.State -eq 'Running' -or $_.State -eq 'NotStarted')
            })
            
            if ($ghostProgressWorkers.Count -gt 0) {
                Write-Log -Message "WARNING: Found $($ghostProgressWorkers.Count) ghost progress worker(s) from previous runs!" -Level WARN
                foreach ($ghostJob in $ghostProgressWorkers) {
                    Write-Log -Message "  Ghost worker: $($ghostJob.Name), State: $($ghostJob.State), ID: $($ghostJob.Id), StartTime: $($ghostJob.PSBeginTime)" -Level WARN
                    try {
                        Stop-Job -Job $ghostJob -Force -ErrorAction SilentlyContinue
                        Remove-Job -Job $ghostJob -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "  Cleaned up ghost worker $($ghostJob.Id)" -Level INFO
                    } catch {
                        Write-Log -Message "  Failed to clean up ghost worker: $_" -Level ERROR
                    }
                }
            }
            
            # First, explicitly check for Progress Worker jobs that might still be running
            $progressWorkerJobs = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -match "ProgressWorker|Progress Worker" -and $_.State -eq 'Running' 
            })
            
            if ($progressWorkerJobs.Count -gt 0) {
                Write-Log -Message "Found $($progressWorkerJobs.Count) Progress Worker job(s) still running. Stopping them..." -Level WARN
                foreach ($job in $progressWorkerJobs) {
                    try {
                        Write-Log -Message "Stopping Progress Worker job: $($job.Name) (ID: $($job.Id))" -Level INFO
                        Stop-Job -Job $job -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 500  # Give it time to stop
                        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "Progress Worker job stopped and removed successfully" -Level INFO
                    } catch {
                        Write-Log -Message "Error stopping Progress Worker job: $_" -Level WARN
                    }
                }
            }
            
            # Now do the general cleanup
            if (Get-Command Remove-ThreadJobs -ErrorAction SilentlyContinue) {
                Remove-ThreadJobs -Context "Final Cleanup"
            }
            
            # Final verification - ensure no UpdateLoxone jobs remain
            $remainingJobs = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -match "ProgressWorker|MS Worker|Config Worker|App Worker|Download Worker|Install Worker" -or
                $_.Location -match "UpdateLoxone|LoxoneUtils"
            })
            
            if ($remainingJobs.Count -gt 0) {
                Write-Log -Message "WARNING: $($remainingJobs.Count) UpdateLoxone-related job(s) still exist after cleanup!" -Level WARN
                foreach ($job in $remainingJobs) {
                    Write-Log -Message "  - Remaining job: $($job.Name), State: $($job.State), ID: $($job.Id)" -Level WARN
                }
            } else {
                Write-Log -Message "All UpdateLoxone-related jobs cleaned up successfully" -Level INFO
            }
        }
        
                    # Skip sequential execution when parallel mode is used
                    Write-Log -Message "Skipping sequential pipeline execution (parallel mode completed)" -Level INFO
                    
                }
                catch {
                    $script:ErrorOccurred = $true
                    Write-Log -Message "Fatal error in parallel workflow: $_" -Level ERROR
                    throw
                }
            } else {
                Write-Log -Message "No work to do in parallel workflow (no updates needed)" -Level INFO
                $parallelResult = @{
                    Success = $true
                    Downloads = @()
                    Installations = @()
                    MiniserverResults = @()
                    TotalDuration = 0
                }
            }
        } # End of if (-not $skipParallelSetup)
    } # End of if ($effectiveParallelMode)
    else {
    # Original sequential execution
    Write-Log -Message "Using sequential execution mode" -Level INFO

    # --- Main Pipeline Definition ---
    $steps = @(
    @{
        Name      = "Download Loxone Config"
        ShouldRun = {
            param([PSCustomObject]$scriptCtxArg, [System.Collections.ArrayList]$UpdateTargetsInfoArg, [ref]$globalStateRefArg, [PSCustomObject]$prerequisitesArg)
            Test-PipelineStepShouldRun -TargetsInfo $UpdateTargetsInfoArg -ExpectedType "Config" -ConditionBlock {
                param($item) # This $item corresponds to $targetItem in the original loop
                ($item.UpdateNeeded -eq $true -or $item.UpdateNeeded -eq "True")
            }
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
            Test-PipelineStepShouldRun -TargetsInfo $UpdateTargetsInfoArg -ExpectedType "Config" -ConditionBlock {
                param($item)
                ($item.UpdateNeeded -eq $true -or $item.UpdateNeeded -eq "True") -and $item.Status -ne "UpdateFailed (Download)"
            }
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
            Test-PipelineStepShouldRun -TargetsInfo $UpdateTargetsInfoArg -ExpectedType "Config" -ConditionBlock {
                param($item)
                ($item.UpdateNeeded -eq $true -or $item.UpdateNeeded -eq "True") -and $item.Status -ne "UpdateFailed (Download)" -and $item.Status -ne "UpdateFailed (Extraction)"
            }
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

                if (-not $prerequisitesArg.AppUpdateNeeded) {
                    return $false
                }

                # Check if any "App" target exists
                $appTargetExists = $false
                foreach ($targetItemCheck in $UpdateTargetsInfoArg) {
                    if ($targetItemCheck.Type -eq "App") {
                        $appTargetExists = $true
                        break
                    }
                }

                if (-not $appTargetExists) {
                    # If AppUpdateNeeded is true and no App target exists (fresh install), then run.
                    return $true
                }

                # If AppUpdateNeeded is true AND an App target exists, use Test-PipelineStepShouldRun
                $shouldRunBasedOnTest = Test-PipelineStepShouldRun -TargetsInfo $UpdateTargetsInfoArg -ExpectedType "App" -ConditionBlock {
                    param($item)
                    ($item.Status -notlike "*Failed*" -or $item.Status -eq "DownloadSkippedExistingValid")
                }
                return $shouldRunBasedOnTest
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
            Test-PipelineStepShouldRun -TargetsInfo $UpdateTargetsInfoArg -ExpectedType "Miniserver" -ConditionBlock {
                param($item)
                $true # Condition is simply that an item of Type "Miniserver" exists
            }
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
            Test-PipelineStepShouldRun -TargetsInfo $UpdateTargetsInfoArg -ExpectedType "Miniserver" -ConditionBlock {
                param($item)
                ($item.UpdateNeeded -eq $true -or $item.UpdateNeeded -eq "True")
            }
        }
        Run       = {
            param($scriptCtx, $targets, $globalStateRef, $prereqs)
            $effectiveChannelForMS = if ($scriptCtx.Params.ContainsKey('Channel') -and -not ([string]::IsNullOrWhiteSpace($scriptCtx.Params.Channel))) {
                $scriptCtx.Params.Channel
            } else {
                # Default value of Channel parameter in UpdateLoxone.ps1, or if an empty string was passed
                Write-Log -Message "Channel for Miniserver update was not specified or was empty, defaulting to 'Test'." -Level DEBUG
                "Test"
            }
            Invoke-UpdateMiniserversInBulk -WorkflowContext $scriptCtx -Prerequisites $prereqs -UpdateTargetsToUpdate $targets -ScriptGlobalState $globalStateRef -ConfiguredUpdateChannel $effectiveChannelForMS
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
        
        # Send a toast update before starting each step to prevent auto-dismiss
        if ($Global:PersistentToastInitialized -and $scriptContext.IsInteractive -and -not $scriptContext.IsSelfInvokedForUpdateCheck) {
            try {
                $currentStepName = if ($scriptGlobalState.currentStep -le $scriptGlobalState.totalSteps) { 
                    $stepEntry.Name 
                } else { 
                    "Processing..."
                }
                Update-PersistentToast -StepNumber $scriptGlobalState.currentStep `
                    -TotalSteps $scriptGlobalState.totalSteps `
                    -StepName $currentStepName `
                    -CurrentWeight $scriptGlobalState.CurrentWeight `
                    -TotalWeight $scriptGlobalState.TotalWeight `
                    -IsInteractive $scriptContext.IsInteractive `
                    -ErrorOccurred $script:ErrorOccurred `
                    -AnyUpdatePerformed $scriptGlobalState.anyUpdatePerformed `
                    -CallingScriptIsInteractive $scriptContext.IsInteractive `
                    -CallingScriptIsSelfInvoked $scriptContext.IsSelfInvokedForUpdateCheck
                Write-Log -Level DEBUG -Message "Sent pre-step toast update for: $($stepEntry.Name)"
            } catch {
                Write-Log -Level WARN -Message "Failed to update toast before step: $_"
            }
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
            if (($stepResult.PSObject.Properties | Where-Object {$_.Name -eq 'RestartRequired'}) -and $stepResult.RestartRequired) {
                Write-Log -Message "Step '$($stepEntry.Name)' indicates system restart is required (VC++ Redistributable)." -Level WARN
                $scriptGlobalState.RestartRequired = $true
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

} # End of try block for sequential execution
catch {
    Write-Log -Message "Error in sequential execution: $_" -Level ERROR
    throw
}

    } # End of else block for sequential execution

} # End of if/else block for parallel vs sequential execution and main try block
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
Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY BLOCK START - Main pipeline 'finally' block executing."

try {
    # Clean up all ThreadJobs to prevent background processes from continuing - but only if we created any
    $allJobsToCheck = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
    $_.Name -match "ProgressWorker|Progress Worker|MS Worker|Config Worker|App Worker|Download Worker|Install Worker" -or
    $_.Location -match "UpdateLoxone|LoxoneUtils"
})

if ($allJobsToCheck.Count -gt 0) {
    Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Found $($allJobsToCheck.Count) job(s) to clean up"
    try {
        # First stop any progress workers
        $progressWorkers = @($allJobsToCheck | Where-Object { 
            $_.Name -match "ProgressWorker|Progress Worker" -and ($_.State -eq 'Running' -or $_.State -eq 'NotStarted')
        })
        
        if ($progressWorkers.Count -gt 0) {
        Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Found $($progressWorkers.Count) Progress Worker(s) to clean up"
        foreach ($job in $progressWorkers) {
            Write-Log -Level INFO -Message "  Stopping Progress Worker: $($job.Name) (ID: $($job.Id), State: $($job.State))"
            Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Then stop all other UpdateLoxone-related jobs
    $allJobs = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -match "MS Worker|Config Worker|App Worker|Download Worker|Install Worker|ProgressWorker" -or
        $_.Location -match "UpdateLoxone|LoxoneUtils"
    })
    
    if ($allJobs.Count -gt 0) {
        Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Found $($allJobs.Count) UpdateLoxone-related job(s) to clean up"
        foreach ($job in $allJobs) {
            Write-Log -Level INFO -Message "  Stopping job: $($job.Name) (ID: $($job.Id), State: $($job.State))"
            Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Use Remove-ThreadJobs if available
    if (Get-Command Remove-ThreadJobs -ErrorAction SilentlyContinue) {
        Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Running Remove-ThreadJobs for comprehensive cleanup"
        Remove-ThreadJobs -Context "Finally Block Cleanup"
    }
    
    # Final verification
    $remainingJobs = @(Get-Job -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -match "ProgressWorker|MS Worker|Config Worker|App Worker|Download Worker|Install Worker" -or
        $_.Location -match "UpdateLoxone|LoxoneUtils"
    })
    
    if ($remainingJobs.Count -gt 0) {
        Write-Log -Level WARN -Message "(UpdateLoxone.ps1) FINALLY: $($remainingJobs.Count) job(s) still exist after cleanup!"
        foreach ($job in $remainingJobs) {
            Write-Log -Level WARN -Message "  Remaining: $($job.Name) (ID: $($job.Id), State: $($job.State))"
        }
    } else {
        Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: All ThreadJobs cleaned up successfully"
    }
    } catch {
        Write-Log -Level ERROR -Message "(UpdateLoxone.ps1) FINALLY: Error during ThreadJob cleanup: $_"
    }
} else {
}
} catch {
    Write-Host "[ERROR IN FINALLY] $_" -ForegroundColor Red
    Write-Log -Level ERROR -Message "(UpdateLoxone.ps1) FINALLY: Unexpected error in job cleanup section: $_"
}


$anyUpdatePerformedActualInFinally = ($UpdateTargetsInfo | Where-Object {$_.UpdatePerformed -eq $true -or $_.Status -eq "UpdateSuccessful"}).Count -gt 0

$logPathToShowFinally = $scriptContext.LogFile

if (-not $script:ErrorOccurred) {
    Write-Log -Message "(UpdateLoxone.ps1) Constructing final success/summary notification message in 'finally' block." -Level INFO
    
    # --- Final Progress Toast Update to 100% ---
    # Skip toast update in parallel mode as the progress worker handles all toast updates
    # Consolidated finally block parallel check (was 5 verbose log entries)
    Write-Log -Level DEBUG -Message "(UpdateLoxone.ps1) Finally block: parallel=$($script:IsParallelMode), error=$($script:ErrorOccurred)"
    
    if ($script:IsParallelMode -or $env:LOXONE_PARALLEL_MODE -eq "1") {
        # Check if there was actually work done (progress worker was started)
        $hadWork = ($UpdateTargetsInfo | Where-Object { $_.UpdatePerformed -eq $true }).Count -gt 0
        if ($hadWork) {
            Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Parallel mode - progress worker handled toast updates"
        } else {
            Write-Log -Level INFO -Message "(UpdateLoxone.ps1) FINALLY: Parallel mode - no updates needed, skipping final toast"
        }
    }
    elseif (-not $script:ErrorOccurred -and $Global:PersistentToastInitialized) {
        $scriptGlobalState.currentStep = $scriptGlobalState.totalSteps # Ensure it's the last step
        $finalizingWeight = Get-StepWeight -StepID 'Finalize'
        $scriptGlobalState.CurrentWeight += $finalizingWeight
        $scriptGlobalState.CurrentWeight = [Math]::Min($scriptGlobalState.CurrentWeight, $scriptGlobalState.TotalWeight)

        
        $finalStepNameForToast = "Update Process Finalizing"
        
        [int]$stepNumToast = 0
        [int]$totalStepsToast = 0
        [double]$currentWeightToast = 0.0
        [double]$totalWeightToast = 0.0

        # Attempt to get values from $scriptGlobalState.Value, with type casting and logging
        try { $stepNumToast = [int]$scriptGlobalState.currentStep } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.currentStep ('$($scriptGlobalState.currentStep)') to int. Defaulting."}

        try { $totalStepsToast = [int]$scriptGlobalState.totalSteps } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.totalSteps ('$($scriptGlobalState.totalSteps)') to int. Defaulting."}
        
        try { $currentWeightToast = [double]$scriptGlobalState.CurrentWeight } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.CurrentWeight ('$($scriptGlobalState.CurrentWeight)') to double. Defaulting."}

        try { $totalWeightToast = [double]$scriptGlobalState.TotalWeight } catch { Write-Log -Level WARN -Message "FINALLY: Error casting scriptGlobalState.TotalWeight ('$($scriptGlobalState.TotalWeight)') to double. Defaulting."}
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
    
    # Build the summary lines
    $summaryLines = @()
    foreach ($targetInfo in $UpdateTargetsInfo) {
        $line = ""
        # Use Name directly as it already contains the short names ("Conf", "APP", etc.)
        $processedName = $targetInfo.Name
        
        # Add channel info for all component types
        $channelInfo = ""
        
        # Debug: Log what we have
        Write-Log -Message "Final notification - Type: $($targetInfo.Type), Name: $($targetInfo.Name), Channel: '$($targetInfo.Channel)'" -Level DEBUG
        
        # Always show channel if available (for Config, App, and MS)
        if ($targetInfo.Channel) {
            $channelInfo = "($($targetInfo.Channel))"
        } else {
            # Channel might not be set, try to get it from different sources
            switch ($targetInfo.Type) {
                "Config" {
                    # For Config, use the script parameter Channel (default is "Test")
                    $channelInfo = "($Channel)"
                }
                "Miniserver" {
                    # For MS, also use the script parameter Channel
                    $channelInfo = "($Channel)"
                }
                default {
                    # For other types, leave empty if no channel
                    $channelInfo = ""
                }
            }
        }
        
        # For Miniserver, ensure we use a short name with IP
        if ($targetInfo.Type -eq "Miniserver") {
            # Extract IP from the name or OriginalEntry to include in the display name
            $msIP = ""
            if ($targetInfo.Name -match '(\d+\.\d+\.\d+\.\d+)') {
                $msIP = $matches[1]
            } elseif ($targetInfo.OriginalEntry -match '@([\d.]+)') {
                $msIP = $matches[1]
            }
            # Use "MS IP" as the display name
            $processedName = if ($msIP) { "MS $msIP" } else { "MS" }
        }
        
        $targetNameDisplay = "$processedName $channelInfo".Trim()
        
        # Helper function to extract just the build date for APP
        $extractBuildDate = {
            param($versionString)
            if ($versionString -match '\(Build ([^)]+)\)') {
                # Format: "2025.07.15 (Build 2025-07-15)"
                return $matches[1]
            } elseif ($versionString -match '^(\d{4})\.(\d+)\.(\d+)') {
                # Format: "2025.7.15.0" - convert to date format
                $year = $matches[1]
                $month = $matches[2].PadLeft(2, '0')
                $day = $matches[3].PadLeft(2, '0')
                return "$year-$month-$day"
            }
            return $versionString
        }
        
        switch ($targetInfo.Status) {
            "UpdateSuccessful"              { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.VersionAfterUpdate } else { $targetInfo.VersionAfterUpdate }
                # Use consistent 🔄 symbol for all updates (Config, App, and Miniserver)
                $icon = "🔄"
                $line = "$icon " + $targetNameDisplay + " " + $displayVersion 
            }
            "InstallSuccessful"             { 
                # Use VersionAfterUpdate if available, otherwise fall back to TargetVersion
                $versionToUse = if ($targetInfo.VersionAfterUpdate) { $targetInfo.VersionAfterUpdate } else { $targetInfo.TargetVersion }
                $displayVersion = if ($targetInfo.Type -eq "App" -and $versionToUse) { & $extractBuildDate $versionToUse } else { $versionToUse }
                # Determine icon based on whether it's a fresh install or update
                # Check if it was a fresh install (no initial version or 0.0.0.0)
                $isFreshInstall = -not $targetInfo.InitialVersion -or $targetInfo.InitialVersion -eq "" -or $targetInfo.InitialVersion -eq "0.0.0.0"
                $icon = if ($isFreshInstall) { "🚀" } else { "🔄" }
                if ($displayVersion) {
                    $line = "$icon " + $targetNameDisplay + " " + $displayVersion
                } else {
                    $line = "$icon " + $targetNameDisplay
                }
            }
            "DownloadSuccessful"            { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.TargetVersion } else { $targetInfo.TargetVersion }
                $line = "⬇️ " + $targetNameDisplay + " " + $displayVersion 
            }
            "ExtractSuccessful"             { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.TargetVersion } else { $targetInfo.TargetVersion }
                $line = "📦 " + $targetNameDisplay + " " + $displayVersion 
            }
            "UpToDate"                      { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.InitialVersion } else { $targetInfo.InitialVersion }
                $line = "✓ " + $targetNameDisplay + " " + $displayVersion 
            }
            "NotInstalled"                  { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.TargetVersion } else { $targetInfo.TargetVersion }
                $line = "🔍 " + $targetNameDisplay + " " + $displayVersion 
            }
            "NeedsUpdate"                   { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.TargetVersion } else { $targetInfo.TargetVersion }
                $line = "🔄 " + $targetNameDisplay + " " + $displayVersion 
            } # Should ideally not be seen if process completes
            "ErrorConnecting"               { 
                $line = "✗ " + $targetNameDisplay + " Connection Error"
            }
            "ErrorConnecting_NoTargetVersion" { 
                $line = "✗ " + $targetNameDisplay + " Connection Error (No Target Version)"
            }
            "InstallSkippedProcessRunning"  { $line = "⚠️ " + $targetNameDisplay + " Skipped (process running)" }
            "DownloadSkippedExistingValid"  { 
                $displayVersion = if ($targetInfo.Type -eq "App") { & $extractBuildDate $targetInfo.TargetVersion } else { $targetInfo.TargetVersion }
                $line = "✓ " + $targetNameDisplay + " " + $displayVersion + " (cached)" 
            }
            default {
                if ($targetInfo.Status -like "*Failed*") { # More generic check for failure statuses
                    $reason = ($targetInfo.Status -split '\(|\)')[1]
                    $reasonText = if ($reason) { " - " + $reason } else { "" }
                    
                    # For miniserver failures, include the error details if available
                    if ($targetInfo.Type -eq "Miniserver" -and $targetInfo.Error) {
                        # Check if it's a DNS error
                        if ($targetInfo.Error -match "DNS lookup failed") {
                            $line = "✗ " + $targetNameDisplay + " DNS Error"
                            # Add a second line with the specific DNS error message
                            $summaryLines += $line
                            $line = "  ↳ " + $targetInfo.Error
                        } else {
                            # For other errors, show a shortened version
                            $errorMsg = if ($targetInfo.Error.Length -gt 50) { 
                                $targetInfo.Error.Substring(0, 47) + "..." 
                            } else { 
                                $targetInfo.Error 
                            }
                            $line = "✗ " + $targetNameDisplay + " Failed - " + $errorMsg
                        }
                    } else {
                        $stillAt = if ($targetInfo.VersionAfterUpdate -and $targetInfo.VersionAfterUpdate -ne $targetInfo.InitialVersion) { $targetInfo.VersionAfterUpdate } else { $targetInfo.InitialVersion }
                        $line = "✗ " + $targetNameDisplay + " " + $targetInfo.Status + $reasonText
                    }
                } elseif ($targetInfo.UpdatePerformed -and $targetInfo.Status -eq "UpdateAttempted") {
                    $line = "⚠️ " + $targetNameDisplay + " " + $targetInfo.Status
                }
                else {
                    $line = "⚠️ " + $targetNameDisplay + " " + $targetInfo.Status
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($line)) { $summaryLines += $line }
    }
    # Lines 734-737 (original positions) logging variable types have been moved
    # into the if block starting at line 639 to ensure variables are initialized.
    # They are now integrated into the logs just before the Update-PersistentToast call (around line 694).
    $finalMessageText = ""

    # Check if pre-flight validation failed (from pipelineDataResult)
    if ($pipelineDataResult -and
        ($pipelineDataResult.PSObject.Properties.Name -contains 'ValidationFailed') -and
        $pipelineDataResult.ValidationFailed) {

        $validationMsg = "⚠️ Pre-Flight Validation Failed`n"
        $validationMsg += "Config file on server doesn't match size in XML`n"
        if ($pipelineDataResult.ValidationExpectedSize -and $pipelineDataResult.ValidationActualSize) {
            $expectedMB = [Math]::Round($pipelineDataResult.ValidationExpectedSize / 1MB, 1)
            $actualMB = [Math]::Round($pipelineDataResult.ValidationActualSize / 1MB, 1)
            $validationMsg += "Expected: ${expectedMB}MB, Found: ${actualMB}MB`n"
        }
        $validationMsg += "Skipped all updates (Config + Miniserver)`n"
        $validationMsg += "Loxone XML updated before files uploaded.`n"
        $validationMsg += "Try again later."
        $summaryLines += $validationMsg
    }

    # Add restart required notice if any installer flagged it
    if ($scriptGlobalState.RestartRequired) {
        $summaryLines += "⚠ System restart required (VC++ Redistributable installed)"
        Write-Log -Message "SYSTEM RESTART REQUIRED: A component (likely VC++ Redistributable) requires a system restart to complete installation." -Level WARN
    }

    if ($summaryLines.Count -gt 0) {
        # Sort by the text after the emoji (first letter of component name)
        $sortedLines = $summaryLines | Sort-Object { ($_ -split ' ', 2)[1] }
        $finalMessageText = ($sortedLines | Out-String).Trim()
    } else {
        $finalMessageText = "Process complete, no updates."
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

# Fix Loxone App shortcut icons if App was installed
# This runs at the end regardless of installation method (parallel or sequential)
if ($UpdateTargetsInfo) {
    $appTarget = $UpdateTargetsInfo | Where-Object { $_.Type -eq "App" -and $_.UpdatePerformed -eq $true }
    if ($appTarget) {
        Write-Log -Message "(UpdateLoxone.ps1) App was installed, attempting to fix shortcut icons..." -Level INFO
        try {
            # Find the Loxone App executable
            $exePath = $null
            
            # Check common installation paths (both system and user)
            $possiblePaths = @(
                # The actual location where the App installs
                "${env:LOCALAPPDATA}\Programs\kerberos\Loxone.exe",
                # System-wide installations
                "C:\Program Files\Loxone\Loxone.exe",
                "C:\Program Files (x86)\Loxone\Loxone.exe",
                "${env:ProgramFiles}\Loxone\Loxone.exe",
                "${env:ProgramFiles(x86)}\Loxone\Loxone.exe",
                # User installations (AppData)
                "${env:LOCALAPPDATA}\Loxone\Loxone.exe",
                "${env:LOCALAPPDATA}\Programs\Loxone\Loxone.exe",
                "${env:APPDATA}\Loxone\Loxone.exe",
                # User installations (per-user Program Files)
                "${env:USERPROFILE}\AppData\Local\Programs\Loxone\Loxone.exe",
                "${env:USERPROFILE}\AppData\Local\Loxone\Loxone.exe"
            )
            
            foreach ($path in $possiblePaths) {
                if (Test-Path $path) {
                    $exePath = $path
                    Write-Log -Message "(UpdateLoxone.ps1) Found Loxone executable at: '$exePath'" -Level INFO
                    break
                }
            }
            
            # If not found, search Program Files directories
            if (-not $exePath) {
                Write-Log -Message "(UpdateLoxone.ps1) Searching for Loxone.exe in Program Files..." -Level DEBUG
                $searchPaths = @("${env:ProgramFiles}", "${env:ProgramFiles(x86)}")
                foreach ($searchPath in $searchPaths) {
                    if (Test-Path $searchPath) {
                        $loxoneFolders = Get-ChildItem -Path $searchPath -Directory -Filter "*Loxone*" -ErrorAction SilentlyContinue
                        foreach ($folder in $loxoneFolders) {
                            $found = Get-ChildItem -Path $folder.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | 
                                     Where-Object { $_.Name -like "*Loxone*" } | Select-Object -First 1
                            if ($found) {
                                $exePath = $found.FullName
                                Write-Log -Message "(UpdateLoxone.ps1) Found Loxone executable: '$exePath'" -Level INFO
                                break
                            }
                        }
                        if ($exePath) { break }
                    }
                }
            }
            
            # Try to get path from existing shortcuts
            if (-not $exePath) {
                Write-Log -Message "(UpdateLoxone.ps1) Trying to find executable from existing shortcuts..." -Level DEBUG
                $userProfile = [Environment]::GetFolderPath("UserProfile")
                $shortcutPaths = @(
                    (Join-Path $userProfile "Desktop\Loxone.lnk"),
                    (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"),
                    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"
                )
                
                foreach ($shortcutPath in $shortcutPaths) {
                    if (Test-Path $shortcutPath) {
                        try {
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($shortcutPath)
                            $targetPath = $shortcut.TargetPath
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                            
                            if ($targetPath -and (Test-Path $targetPath)) {
                                $exePath = $targetPath
                                Write-Log -Message "(UpdateLoxone.ps1) Found executable from shortcut: '$exePath'" -Level INFO
                                break
                            }
                        } catch {
                            Write-Log -Message "(UpdateLoxone.ps1) Error reading shortcut: $_" -Level DEBUG
                        }
                    }
                }
            }
            
            if ($exePath) {
                # Fix the shortcuts
                $userProfile = [Environment]::GetFolderPath("UserProfile")
                $shortcutsToFix = @(
                    (Join-Path $userProfile "Desktop\Loxone.lnk"),
                    (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"),
                    (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone\Loxone.lnk"),
                    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone.lnk",
                    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone\Loxone.lnk"
                )
                
                $fixedCount = 0
                foreach ($shortcutPath in $shortcutsToFix) {
                    if (Test-Path $shortcutPath) {
                        try {
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($shortcutPath)
                            
                            # Update shortcut properties
                            $shortcut.TargetPath = $exePath
                            $shortcut.WorkingDirectory = Split-Path $exePath -Parent
                            $shortcut.IconLocation = "$exePath,0"
                            $shortcut.Description = "Loxone Smart Home App"
                            $shortcut.Save()
                            
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                            
                            Write-Log -Message "(UpdateLoxone.ps1) Fixed shortcut at: $shortcutPath" -Level INFO
                            $fixedCount++
                        } catch {
                            Write-Log -Message "(UpdateLoxone.ps1) Error fixing shortcut at '$shortcutPath': $_" -Level WARN
                        }
                    }
                }
                
                if ($fixedCount -gt 0) {
                    Write-Log -Message "(UpdateLoxone.ps1) Successfully fixed $fixedCount Loxone App shortcut(s)" -Level INFO
                } else {
                    Write-Log -Message "(UpdateLoxone.ps1) No shortcuts found to fix" -Level WARN
                }
            } else {
                Write-Log -Message "(UpdateLoxone.ps1) Could not find Loxone executable - unable to fix shortcuts" -Level WARN
            }
        } catch {
            Write-Log -Message "(UpdateLoxone.ps1) Error during icon fixing: $_" -Level WARN
        }
    }
}

# Log rotation - Execute once before script exit
if (-not $script:SystemRelaunchExitOccurred) {
    # Use Global:LogFile as it's the actual file being written to
    $logFileToRotate = $Global:LogFile
    
    if ($logFileToRotate -and (Test-Path $logFileToRotate)) {
        try {
            # Use default of 1MB if MaxLogFileSizeMB is not available
            $maxSizeKB = if ($scriptContext.Params.MaxLogFileSizeMB) { 
                $scriptContext.Params.MaxLogFileSizeMB * 1024 
            } else { 
                1024  # Default 1MB
            }
            $rotatedPath = Invoke-LogFileRotation -LogFilePath $logFileToRotate -MaxArchiveCount 24 -MaxSizeKB $maxSizeKB -ErrorAction Stop
            if ($rotatedPath) {
                Write-Log -Message "(UpdateLoxone.ps1) Log rotated to: $rotatedPath" -Level INFO
            }
        } catch {
            if ($_.Exception.Message -notlike "*is not recognized*" -and $_.Exception.Message -notlike "*Der Begriff*") {
                Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Error during log rotation: $($_.Exception.Message)"
            }
        }
    }

    # Downloads folder cleanup - clean up old downloaded files
    if ($scriptContext.DownloadDir -and (Test-Path $scriptContext.DownloadDir)) {
        try {
            if (Get-Command Invoke-DownloadsFolderCleanup -ErrorAction SilentlyContinue) {
                Invoke-DownloadsFolderCleanup -DownloadsPath $scriptContext.DownloadDir -MaxAgeDays 7 -MaxFilesToKeep 10 -ErrorAction Stop
            }
        } catch {
            if ($_.Exception.Message -notlike "*is not recognized*" -and $_.Exception.Message -notlike "*Der Begriff*") {
                Write-Log -Level WARN -Message "(UpdateLoxone.ps1) Error during downloads cleanup: $($_.Exception.Message)"
            }
        }
    }
}

if (Get-Command Exit-Function -ErrorAction SilentlyContinue) {
    Exit-Function 
}

# Calculate total script runtime - MUST BE LAST
$totalRuntime = if ($script:ScriptStartTime) { 
    $endTime = Get-Date
    $duration = $endTime - $script:ScriptStartTime
    "{0:F1}s" -f $duration.TotalSeconds
} else { 
    "unknown" 
}

# THIS IS THE ABSOLUTE LAST LINE BEFORE EXIT
Write-Log -Message "(UpdateLoxone.ps1) Script final exit from 'finally' block. ErrorOccurred: $script:ErrorOccurred. Total runtime: $totalRuntime" -Level INFO

if ($script:ErrorOccurred) { exit 1 } else { exit 0 }
}
# End of script

