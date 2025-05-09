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
# Run to register the scheduled task (requires Admin rights)
.\UpdateLoxone.ps1 -RegisterTask -Channel Public -ScheduledTaskIntervalMinutes 60

.NOTES
- Requires PowerShell 5.1 or later.
- Requires administrator privileges to install software and register scheduled tasks.
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
    [ValidateSet('silent', 'verysilent')]
    [string]$InstallMode = "verysilent",
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

# $global:ScriptDebugMode = $DebugMode.IsPresent # Removed - Let standard -Debug switch control $Global:DebugPreference

# Explicitly set DebugPreference based ONLY on the -DebugMode switch
if ($DebugMode) { # Check boolean value directly
    $Global:DebugPreference = 'Continue'
    Write-Host "INFO: -DebugMode specified, setting Global:DebugPreference = 'Continue'" -ForegroundColor Green
} else {
    $Global:DebugPreference = 'SilentlyContinue'
    Write-Host "INFO: -DebugMode NOT specified, setting Global:DebugPreference = 'SilentlyContinue'" -ForegroundColor Green
}
# Write-Host "INITIAL Global:DebugPreference = '$($Global:DebugPreference)'" -ForegroundColor Magenta # Removed diagnostic

# --- Define Base Paths Early ---
# Determine script's own directory reliably
$script:MyScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- Determine Script Save Folder ---
# Write-Log -Level DEBUG -Message "Determining ScriptSaveFolder..." # Cannot log yet
if ([string]::IsNullOrWhiteSpace($ScriptSaveFolder)) {
    # Use $script:MyScriptRoot instead of $PSScriptRoot
    if ($script:MyScriptRoot) { $ScriptSaveFolder = $script:MyScriptRoot; Write-Host "INFO: Using Script Root for ScriptSaveFolder: '$ScriptSaveFolder'" -ForegroundColor Cyan }
    else { $ScriptSaveFolder = Join-Path -Path $env:USERPROFILE -ChildPath "UpdateLoxone"; Write-Host "INFO: Script Root not available. Falling back to UserProfile path for ScriptSaveFolder: '$ScriptSaveFolder'" -ForegroundColor Cyan }
} else { Write-Host "INFO: Using provided ScriptSaveFolder parameter: '$ScriptSaveFolder'" -ForegroundColor Cyan }
# Write-Host "INFO: Final ScriptSaveFolder set to: '$ScriptSaveFolder'" -ForegroundColor Cyan # Redundant

# --- Set Log Directory and Global Log File Path ---
$LogDir = Join-Path -Path $ScriptSaveFolder -ChildPath "Logs"
# Create Log Directory if it doesn't exist (needed before logging)
if (-not (Test-Path -Path $LogDir -PathType Container)) {
    Write-Host "INFO: Log directory '$LogDir' not found. Creating..." -ForegroundColor Cyan
    try { New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch { Write-Error "FATAL: Failed to create log directory '$LogDir'. Error: $($_.Exception.Message)"; exit 1 }
}

# Check if a log file path was passed in (elevated instance)
if (-not [string]::IsNullOrWhiteSpace($PassedLogFile)) {
    Write-Host "INFO: Using passed log file path: '$PassedLogFile'" -ForegroundColor Cyan
    # Ensure the directory for the passed log file exists (it should, but double-check)
    $PassedLogDir = Split-Path -Path $PassedLogFile -Parent
    if (-not (Test-Path -Path $PassedLogDir -PathType Container)) {
        Write-Host "WARN: Directory for passed log file '$PassedLogDir' not found. Attempting to create..." -ForegroundColor Yellow
        try { New-Item -Path $PassedLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch { Write-Error "FATAL: Failed to create directory for passed log file '$PassedLogDir'. Error: $($_.Exception.Message)"; exit 1 }
    }
    $global:LogFile = $PassedLogFile
} else {
    # Original logic: Generate a new log file path
    Write-Host "INFO: No log file passed. Generating new log file name." -ForegroundColor Cyan
    $userNameForFile = (([Security.Principal.WindowsIdentity]::GetCurrent()).Name -split '\\')[-1] -replace '[\\:]', '_'
    # Ensure the base log file name doesn't contain invalid chars from username, although the replace should handle most common ones.
    $baseLogName = "UpdateLoxone_$userNameForFile.log"
    # Further sanitize just in case: Remove characters not suitable for file names
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $regexInvalidChars = "[{0}]" -f [RegEx]::Escape($invalidChars)
    $sanitizedLogName = $baseLogName -replace $regexInvalidChars, '_'
    $global:LogFile = Join-Path -Path $LogDir -ChildPath $sanitizedLogName
}
Write-Host "INFO: Global LogFile path set to '$($global:LogFile)' (before logging module import)." -ForegroundColor Cyan

# Logging module is now imported via the main LoxoneUtils.psd1 manifest below.
# $PSBoundParameters logging moved after LoxoneUtils module import

# --- Script Initialization (Continues) ---
$script:ErrorOccurred = $false # Use script scope for trap accessibility
$script:LastErrorLine = 0
$script:IsAdminRun = $false # Assume not admin initially
$global:IsElevatedInstance = $false # Global flag accessible by module
# $global:LogFile = $null # Removed - Initialized earlier (line ~120) and should not be reset here
$script:configUpdated = $false # Flag to track if Config update occurred
$script:appUpdated = $false # Flag to track if App update occurred and verified
# Check if running as SYSTEM by comparing SIDs (S-1-5-18)
$script:isRunningAsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
$script:CurrentWeight = 0 # Initialize overall progress weight counter
$script:TotalWeight = 0   # Initialize total weight (will be calculated later)
$script:currentStep = 0
$script:totalSteps = 1 # Initial placeholder, calculated later
$script:currentDownload = 0
$script:totalDownloads = 0 # Calculated later
$script:totalDownloads = 0 # Calculated later
$script:InitialInstalledVersion = "" # Store initially detected version here

# --- Load Helper Module (Manifest Import) ---
$UtilsModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils\LoxoneUtils.psd1' # Use manifest exclusively

if (-not (Test-Path $UtilsModulePath)) {
    Write-Error "Helper module 'LoxoneUtils.psd1' not found at '$UtilsModulePath'. Script cannot continue."
    exit 1 # Critical dependency missing
}
# The -Force on Import-Module below handles reloading. Explicit Remove-Module is not needed here and removes the already loaded logging module.
# Write-Log -Message "Attempting to forcefully remove existing LoxoneUtils module (before import)..." -Level DEBUG # Removed
# Remove-Module LoxoneUtils -Force -ErrorAction SilentlyContinue # Removed
# Check for BurntToast dependency before attempting to load LoxoneUtils
Write-Host "INFO: Checking for required module 'BurntToast'..."
$burntToastAvailable = Get-Module -ListAvailable -Name BurntToast
if (-not $burntToastAvailable) {
    Write-Host "INFO: 'BurntToast' module not found. Attempting to install from PSGallery..."
    try {
        Install-Module -Name BurntToast -Scope CurrentUser -Repository PSGallery -Force -ErrorAction SilentlyContinue
        Write-Host "INFO: 'BurntToast' installed successfully."
        # Verify again after installation attempt
        $burntToastAvailable = Get-Module -ListAvailable -Name BurntToast
    } catch {
        Write-Warning "Failed to install 'BurntToast' module. Toast notifications will be unavailable. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "INFO: 'BurntToast' module found."
}

try {
    if ($script:isRunningAsSystem) {
        # Running as SYSTEM: Import the full module via manifest (includes RunAsUser)
        # Import LoxoneUtils module (SYSTEM context)
        $LoxoneUtilsModule = Import-Module $UtilsModulePath -Force -ErrorAction SilentlyContinue -PassThru
        # Handled by the surrounding try/catch now. If successful, it proceeds. If not, the catch block below handles it.
        Write-Log -Message "Running as SYSTEM. Importing full LoxoneUtils module via manifest '$UtilsModulePath'." -Level INFO
        Write-Log -Message "Successfully loaded LoxoneUtils module via manifest for SYSTEM context." -Level INFO

        # --- Log bound parameters (SYSTEM context) ---
        # Note: Logging parameters might be less relevant in pure SYSTEM context before re-launch, but keep for consistency.
        if ($PassedLogFile) { # Check if log file was passed (likely won't be in initial SYSTEM run)
            try {
                $BoundParamsString = $PSBoundParameters.Keys | ForEach-Object { "-$_ $($PSBoundParameters[$_])" } | Out-String
                Write-Log -Level DEBUG -Message "SYSTEM PSBoundParameters: $($BoundParamsString.Trim())" # Indicate SYSTEM context
            } catch {
                Write-Log -Level ERROR -Message "SYSTEM Failed to log PSBoundParameters: $($_.Exception.Message)"
            }
        }
        # --- End Log bound parameters ---

        # --- Skip Initial Version Check (SYSTEM context) ---
        Write-Log -Level DEBUG -Message "[Config] Skipping initial version check as running under SYSTEM context."
        $script:InstalledExePath = $null
        $script:InitialInstalledVersion = ""
        # --- End Skip Initial Version Check ---

    } else {
        # NOT running as SYSTEM: Import required modules individually, excluding RunAsUser
        # --- IMPORT LOGGING MODULE FIRST ---
        $LoxoneUtilsDir = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils' # Define dir first
        $LoggingModulePath = Join-Path -Path $LoxoneUtilsDir -ChildPath 'LoxoneUtils.Logging.psm1'
        try {
            if (Test-Path $LoggingModulePath) {
                Import-Module $LoggingModulePath -Force -ErrorAction Stop
                # Initial log message *after* importing the logging module
                Write-Log -Message "Not running as SYSTEM. Importing required LoxoneUtils modules individually..." -Level INFO
            } else {
                # Critical error if logging module is missing
                Write-Host "CRITICAL ERROR: Logging module not found at '$LoggingModulePath'. Cannot continue." -ForegroundColor Red
                exit 1 # Exit immediately
            }
        } catch {
            # Catch syntax errors specifically within the logging module itself
            Write-Host "CRITICAL ERROR: Failed to load essential logging module '$LoggingModulePath' due to a syntax error. Full Error Record Below:" -ForegroundColor Red
            Write-Host "-------------------- LOGGING MODULE ERROR START --------------------" -ForegroundColor Yellow; $_ | Out-String | Write-Host -ForegroundColor Yellow; Write-Host "-------------------- LOGGING MODULE ERROR END --------------------" -ForegroundColor Yellow
            Write-Host "Script cannot continue without logging." -ForegroundColor Red; exit 1
        }
        # --- END IMPORT LOGGING MODULE FIRST ---

        # Now import the rest of the modules
        $ModulesToImport = @(
            # 'LoxoneUtils.Logging.psm1', # Already imported first
            'LoxoneUtils.Utility.psm1',     # Import Utility functions (like Enter/Exit-Function) early
            'LoxoneUtils.ErrorHandling.psm1', # Import Error Handling early
            'LoxoneUtils.Installation.psm1',  # Depends on Utility/Logging
            'LoxoneUtils.Network.psm1',       # Depends on Utility/Logging
            'LoxoneUtils.System.psm1',        # Depends on Utility/Logging
            'LoxoneUtils.Toast.psm1',         # Depends on Utility/Logging
            'LoxoneUtils.Miniserver.psm1',    # Depends on Utility/Logging, Network, Toast
            'LoxoneUtils.UpdateCheck.psm1',   # Added: Contains Get-LoxoneUpdateData
            'LoxoneUtils.psm1'                  # Root module file (usually last)
        )

        foreach ($moduleFile in $ModulesToImport) {
            $modulePath = Join-Path -Path $LoxoneUtilsDir -ChildPath $moduleFile
            if (Test-Path $modulePath) {
                Write-Log -Message "Importing module: $modulePath" -Level DEBUG
                try {
                    Import-Module $modulePath -Force -ErrorAction Stop # Stop on error *within* this specific import
                    Write-Log -Message "Successfully imported module: $moduleFile" -Level DEBUG
                } catch {
                    # Catch syntax errors in the specific module being imported
                    Write-Log -Message "CRITICAL ERROR: Failed to load helper module '$moduleFile' from '$modulePath' due to a syntax error. Full Error Record Below:" -Level ERROR
                    Write-Log -Message "-------------------- MODULE LOAD ERROR START ($moduleFile) --------------------" -Level ERROR
                    $_ | Out-String | Write-Log -Level ERROR # Log the specific error
                    Write-Log -Message "-------------------- MODULE LOAD ERROR END ($moduleFile) --------------------" -Level ERROR
                    Write-Log -Message "Script cannot continue." -Level ERROR
                    # Attempt final toast before exiting
                    try { Show-FinalStatusToast -StatusMessage "FAILED: Error loading module '$moduleFile'. Check logs." -Success:$false -LogFileToShow $global:LogFile } catch {}
                    exit 1 # Exit immediately upon finding the faulty module
                }
            } else {
                Write-Log -Message "Module file not found: $modulePath. Skipping import." -Level WARN
                # Consider throwing an error if a critical module is missing
            }
        }
        Write-Log -Message "Successfully imported required LoxoneUtils modules individually." -Level INFO

# Force TLS 1.2 for all web requests
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Write-Log -Level INFO -Message "Applied TLS 1.2 globally."

# Removed global SSL/TLS certificate validation bypass (Original lines 284-299)
# Check if running non-interactively
# Interactivity check using [Environment]::UserInteractive removed as it was unreliable for Invoke-AsCurrentUser scenario.
# Environment variables will be logged below for comparison instead.

    # Check if running interactively via dot-sourcing
    $script:IsInteractiveRun = ($MyInvocation.InvocationName -eq '.')
    Write-Log -Level INFO -Message "Invocation Name Check: InvocationName='$($MyInvocation.InvocationName)', IsInteractiveRun=$script:IsInteractiveRun"
        # --- Log bound parameters (Non-SYSTEM context) ---
        # This is the primary place where parameter logging is useful (user/admin interactive/elevated runs)
        if ($PassedLogFile) { # Only log this in the elevated instance re-launched from SYSTEM
             try {
                 $BoundParamsString = $PSBoundParameters.Keys | ForEach-Object { "-$_ $($PSBoundParameters[$_])" } | Out-String
                 Write-Log -Level DEBUG -Message "ELEVATED PSBoundParameters: $($BoundParamsString.Trim())"
             } catch {
                 Write-Log -Level ERROR -Message "ELEVATED Failed to log PSBoundParameters: $($_.Exception.Message)"
             }
         } else { # Log parameters in the initial non-elevated run too, if debugging
             if ($DebugMode) { # Check boolean value directly
                 try {
                     $BoundParamsString = $PSBoundParameters.Keys | ForEach-Object { "-$_ $($PSBoundParameters[$_])" } | Out-String
                     Write-Log -Level DEBUG -Message "INITIAL PSBoundParameters: $($BoundParamsString.Trim())"
                 } catch {
                     Write-Log -Level ERROR -Message "INITIAL Failed to log PSBoundParameters: $($_.Exception.Message)"
                 }
             }
         }
        # --- End Log bound parameters ---

        # --- Get Installed Exe Path and Version (Non-SYSTEM context) ---
        # This logic now correctly runs only when NOT in SYSTEM context and after necessary modules are loaded.
        $script:InstalledExePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
        if ($script:InstalledExePath) {
            Write-Log -Level INFO -Message "[Config] Found installed Loxone Config path: $($script:InstalledExePath)"
            $script:InitialInstalledVersion = Get-InstalledVersion -ExePath $script:InstalledExePath -ErrorAction SilentlyContinue
            if ($script:InitialInstalledVersion) {
                Write-Log -Level INFO -Message "[Config] Determined initial installed version: $($script:InitialInstalledVersion)"
            } else {
                Write-Log -Level WARN -Message "[Config] Found path, but failed to determine initial installed version from '$($script:InstalledExePath)'."
            }
        } else {
            Write-Log -Level INFO -Message "[Config] Loxone Config installation path not found. Assuming no version installed."
            $script:InitialInstalledVersion = ""
        }
        # --- End Get Installed Exe Path and Version ---
    }
}
catch { # Catch block for the initial Import-Module $UtilsModulePath attempt (SYSTEM or non-SYSTEM)

    # Determine if logging is available. If Logging module failed earlier (non-SYSTEM path), Write-Log won't work.
    $canLog = Get-Command Write-Log -ErrorAction SilentlyContinue

    # Log/Write generic manifest load failure
    $manifestLoadErrorMsg = "CRITICAL ERROR: Failed to load the main helper module manifest '$UtilsModulePath'. This usually indicates a syntax error in the manifest itself OR one of the nested modules it tries to load. Attempting to identify the specific failing nested module..."
    if ($canLog) { Write-Log -Message $manifestLoadErrorMsg -Level ERROR } else { Write-Host $manifestLoadErrorMsg -ForegroundColor Red }

    # Log the original error from the manifest import attempt
    $originalManifestErrorRecord = $_ | Out-String
    $manifestErrorDetailMsg = "Original error from manifest load attempt:`n$originalManifestErrorRecord"
    if ($canLog) { Write-Log -Message $manifestErrorDetailMsg -Level DEBUG } else { Write-Host $manifestErrorDetailMsg -ForegroundColor Yellow }

    # --- Attempt Individual Module Imports to Pinpoint Error ---
    $LoxoneUtilsDirForCatch = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils'
    # Define ALL modules, including Logging and RunAsUser for SYSTEM context check
    $AllModulesForCatch = @(
        'LoxoneUtils.Utility.psm1',
        'LoxoneUtils.Logging.psm1',
        'LoxoneUtils.ErrorHandling.psm1',
        'LoxoneUtils.Installation.psm1',
        'LoxoneUtils.Network.psm1',
        'LoxoneUtils.System.psm1',
        'LoxoneUtils.Toast.psm1',
        'LoxoneUtils.Miniserver.psm1',
        'LoxoneUtils.RunAsUser.psm1',
        'LoxoneUtils.UpdateCheck.psm1',
        'LoxoneUtils.psm1'
    )

    foreach ($moduleFileToTest in $AllModulesForCatch) {
        $modulePathToTest = Join-Path -Path $LoxoneUtilsDirForCatch -ChildPath $moduleFileToTest
        if (Test-Path $modulePathToTest) {
            $testImportMsg = "Attempting to import '$moduleFileToTest' individually to check for syntax errors..."
            if ($canLog) { Write-Log -Message $testImportMsg -Level DEBUG } else { Write-Host $testImportMsg -ForegroundColor Cyan }
            try {
                Import-Module $modulePathToTest -Force -ErrorAction Stop # Stop on error within this specific import
                $testImportSuccessMsg = "Successfully imported '$moduleFileToTest' individually."
                if ($canLog) { Write-Log -Message $testImportSuccessMsg -Level DEBUG } else { Write-Host $testImportSuccessMsg -ForegroundColor Green }
            } catch {
                # THIS is the specific module causing the failure
                $specificModuleErrorMsg = "CRITICAL ERROR IDENTIFIED: Failed to load nested module '$moduleFileToTest' from '$modulePathToTest' due to a syntax error. This is the likely cause of the manifest load failure. Full Error Record Below:"
                if ($canLog) { Write-Log -Message $specificModuleErrorMsg -Level ERROR } else { Write-Host $specificModuleErrorMsg -ForegroundColor Red }

                $moduleLoadErrorRecord = $_ | Out-String
                $moduleLoadErrorDetailHeader = "-------------------- MODULE LOAD ERROR START ($moduleFileToTest) --------------------"
                $moduleLoadErrorDetailFooter = "-------------------- MODULE LOAD ERROR END ($moduleFileToTest) --------------------"

                if ($canLog) {
                    Write-Log -Message $moduleLoadErrorDetailHeader -Level ERROR
                    Write-Log -Message $moduleLoadErrorRecord -Level ERROR # Log the specific error
                    Write-Log -Message $moduleLoadErrorDetailFooter -Level ERROR
                    Write-Log -Message "Script cannot continue." -Level ERROR
                } else {
                    Write-Host $moduleLoadErrorDetailHeader -ForegroundColor Yellow
                    Write-Host $moduleLoadErrorRecord -ForegroundColor Yellow
                    Write-Host $moduleLoadErrorDetailFooter -ForegroundColor Yellow
                    Write-Host "Script cannot continue." -ForegroundColor Red
                }
                # Attempt final toast before exiting
                try { if ($canLog) { Show-FinalStatusToast -StatusMessage "FAILED: Error loading module '$moduleFileToTest'. Check logs." -Success:$false -LogFileToShow $global:LogFile } } catch {}
                exit 1 # Exit immediately upon finding the faulty module
            }
        } else {
            $moduleNotFoundMsg = "Module file not found during individual check: $modulePathToTest. Skipping test import."
            if ($canLog) { Write-Log -Message $moduleNotFoundMsg -Level WARN } else { Write-Host $moduleNotFoundMsg -ForegroundColor Yellow }
        }
    } # End foreach ($moduleFileToTest in $AllModulesForCatch)

    # If the loop completes without finding an error (which is unexpected if the manifest failed)
    $inconsistentErrorMsg = "ERROR: The manifest import failed, but subsequent individual module imports succeeded. This indicates an inconsistent state or an issue within the manifest (.psd1) file itself. Please review '$UtilsModulePath'."
    if ($canLog) { Write-Log -Message $inconsistentErrorMsg -Level ERROR } else { Write-Host $inconsistentErrorMsg -ForegroundColor Red }
    exit 1 # Exit with error as the state is problematic
}

# --- Determine if Running as Admin ---
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $script:IsAdminRun = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $global:IsElevatedInstance = $script:IsAdminRun
} catch {
    Write-WARN "Could not determine administrator status. Assuming non-admin. Error: $($_.Exception.Message)"
    $script:IsAdminRun = $false; $global:IsElevatedInstance = $false
}
# --- Determine Interactivity ---
# Use the standard RawUI check. The logic for using the workaround is now based purely on $script:isRunningAsSystem
$script:IsInteractive = $null -ne $Host.UI.RawUI
Write-Log -Message "DEBUG: Interactivity Check: IsInteractive=`$script:IsInteractive" -Level DEBUG

# --- Re-launch as User if Running as SYSTEM ---
if ($script:isRunningAsSystem) {
    Write-Log -Message "Detected script is running as SYSTEM. Attempting to re-launch in the current user's session..." -Level INFO

    # Ensure Invoke-AsCurrentUser is available (should be loaded via LoxoneUtils module)
    if (-not (Get-Command Invoke-AsCurrentUser -ErrorAction SilentlyContinue)) {
        Write-Log -Message "CRITICAL: Invoke-AsCurrentUser command not found (LoxoneUtils module issue?). Cannot re-launch as user. Exiting SYSTEM process." -Level ERROR
        # Consider adding an event log entry here as a fallback notification
        exit 1 # Exit the SYSTEM script with an error code
    }

    # Prepare arguments for the new process, forwarding all original parameters
    $forwardedArgs = @()
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [switch]) {
            # Only add the switch if it was present in the original call
            if ($value.IsPresent) { $forwardedArgs += "-$key" }
        } elseif ($null -ne $value) {
            # Quote arguments containing spaces or special characters for safety
            if ($value -match '[\s''`"]') { $forwardedArgs += "-$key `"$($value -replace '`"','``"')`"" } # Escape inner quotes
            else { $forwardedArgs += "-$key $value" }
        }
    }
    $argumentString = $forwardedArgs -join " "
    $scriptPath = $MyInvocation.MyCommand.Definition

    Write-Log -Message "Re-launching '$scriptPath' as current user with arguments: $argumentString" -Level DEBUG

    try {
        # Define PowerShell executable path
        $powershellExePath = Get-Command powershell.exe | Select-Object -ExpandProperty Source
        # Construct the command line arguments for powershell.exe
        $commandLineForPS = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $argumentString"
        Write-Log -Message "Re-launch command: '$powershellExePath' $commandLineForPS" -Level DEBUG

        # Execute the script as the current user and DO NOT wait (WaitTimeout 0)
        # Pass -Visible:$false and -Elevated:$false as defaults for background execution
        Invoke-AsCurrentUser -FilePath $powershellExePath -Arguments $commandLineForPS -Visible:$false -Elevated:$true -ErrorAction Stop
        Write-Log -Message "Successfully initiated script re-launch in user session via Invoke-AsCurrentUser. Exiting SYSTEM process." -Level INFO
    } catch {
        Write-Log -Message "CRITICAL: Failed to re-launch script as user via Invoke-AsCurrentUser. Error: $($_.Exception.Message). Exiting SYSTEM process." -Level ERROR
        # Consider adding an event log entry here
        exit 1 # Exit the SYSTEM script with an error code
    }

    # Exit the SYSTEM script. The user-context script is now responsible.
    Write-Log -Message "SYSTEM process exiting after initiating user-context re-launch." -Level DEBUG
    exit 0 # Use exit code 0 to indicate the SYSTEM part completed its task (re-launching)
}
# --- End Re-launch Logic ---
$TaskName = "LoxoneUpdateTask" # Define Task Name early for both registration paths
# --- Automatic Task Registration/Update for Interactive Runs ---
if ($script:IsInteractiveRun) {
    if ($script:IsInteractive -and -not $script:isRunningAsSystem -and -not $RegisterTask.IsPresent) {
        # This block handles interactive runs by a user (not SYSTEM) without the -RegisterTask switch.
        # FIRST: Check if the task needs updating WITHOUT requiring admin rights.
        # --- START: Pre-elevation Task Existence Check ---
        Write-Log -Level DEBUG -Message "Performing pre-elevation check for task '$TaskName' existence using schtasks.exe..."
        $taskExistsPreCheck = $false # Assume not found initially
        $schtasksCmd = "schtasks.exe /query /tn `"$TaskName`" 2>&1" # Quote task name, redirect stderr
        Write-Log -Level DEBUG -Message "Executing pre-check command: $schtasksCmd"
        $schtasksOutput = @() # Initialize as array to capture multi-line output properly
        try {
            $schtasksOutput = Invoke-Expression $schtasksCmd
            # Join array output into a single string for easier searching, handle potential null/empty output
            $schtasksOutputString = ($schtasksOutput | Out-String).Trim()
            Write-Log -Level DEBUG -Message "Raw schtasks.exe output:`n$schtasksOutputString"
        } catch {
            # Catch errors during Invoke-Expression itself (less likely for schtasks, but possible)
            $schtasksOutputString = "ERROR executing schtasks: $($_.Exception.Message)"
            Write-Log -Level ERROR -Message "Error executing schtasks.exe pre-check: $($_.Exception.Message)"
            Write-Log -Level DEBUG -Message "Raw schtasks.exe output (on error):`n$schtasksOutputString"
        }

        # Interpret the output
        $foundAccessDenied = $schtasksOutputString -like "*Access is denied.*"
        Write-Log -Level DEBUG -Message "Output contains 'Access is denied.': $foundAccessDenied"
        $foundCannotFind = $schtasksOutputString -like "*ERROR: The system cannot find the file specified.*"
        Write-Log -Level DEBUG -Message "Output contains 'cannot find the file specified.': $foundCannotFind"

        # Logic: Task likely exists if access is denied OR if no error is found (implies successful query)
        if ($foundAccessDenied -or (-not $foundCannotFind -and -not $foundAccessDenied)) {
             # If access denied, it exists but we can't query details.
             # If neither error is found, assume the query succeeded, meaning it exists.
            $taskExistsPreCheck = $true
            Write-Log -Level DEBUG -Message "Inferred task '$TaskName' exists based on schtasks output."
        } else {
            # If 'cannot find' error is present, it doesn't exist.
            $taskExistsPreCheck = $false
            Write-Log -Level DEBUG -Message "Inferred task '$TaskName' does NOT exist based on schtasks output."
        }
        Write-Log -Level DEBUG -Message "Final pre-check result: `$taskExistsPreCheck = $taskExistsPreCheck"
        # --- END: Pre-elevation Task Existence Check ---

        # Log message based on pre-check result
        if (-not $taskExistsPreCheck) {
            Write-Log -Message "Task '$TaskName' requires registration or update (based on pre-check)." -Level INFO
        }

        # SECOND: Proceed with admin check/elevation if running interactively as non-admin without -RegisterTask.
        # The elevated process will determine if action is needed.
            if ($script:IsAdminRun) {
                # User is Admin, register/update the task directly using the function
                Write-Log -Message "Running interactively as Admin user. Ensuring scheduled task '$TaskName' is registered/updated via function." -Level INFO
                try {
                    Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition -TaskName $TaskName -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes -ErrorAction Stop
                } catch {
                    Write-Log -Message "Failed to register/update task via function even as Admin: $($_.Exception.Message)" -Level ERROR
                    if ($script:IsInteractive) { Write-Host "ERROR: Failed to register/update the scheduled task '$TaskName' even though running as Admin. Check logs." -ForegroundColor Red }
                }
            } else {
                # User is NOT Admin. Check if elevation is required based on pre-check.
                if ($taskExistsPreCheck -eq $false) {
                    # Task likely doesn't exist, elevation is required. Original logic follows (now indented):
                # User is NOT Admin, elevation is required. Attempt to relaunch with elevation.
                Write-Log -Message "Running interactively as non-Admin user. Elevation is required to register/update the scheduled task '$TaskName'. Attempting to relaunch with elevation..." -Level WARN
                try {
                    # Construct the command string for the elevated process using -Command
                    $commandString = "& '$($MyInvocation.MyCommand.Definition)' -RegisterTask" # Call script, add mandatory switch
                    # Add string parameters with internal quoting
                    $commandString += " -Channel ""$Channel"""
                    $commandString += " -InstallMode ""$InstallMode"""
                    $commandString += " -ScriptSaveFolder ""$ScriptSaveFolder"""
                    $commandString += " -PassedLogFile ""$($global:LogFile)"""
                    # Add integer parameters directly
                    $commandString += " -MaxLogFileSizeMB $MaxLogFileSizeMB"
                    $commandString += " -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes"
                    # Add boolean parameters using 1/0
                    $commandString += " -EnableCRC $(if ($EnableCRC) { 1 } else { 0 })"
                    $commandString += " -UpdateLoxoneApp $(if ($UpdateLoxoneApp) { 1 } else { 0 })"
                    $commandString += " -DebugMode $(if ($DebugMode) { 1 } else { 0 })"
                    # Add switch parameters conditionally
                    if ($CloseApplications.IsPresent) { $commandString += " -CloseApplications" }
                    if ($SkipUpdateIfAnyProcessIsRunning.IsPresent) { $commandString += " -SkipUpdateIfAnyProcessIsRunning" }

                    Write-Log -Message "Constructed Command string for elevation: $commandString" -Level DEBUG
                    # Attempt to start the elevated process and wait for it
                    # --- START DEBUG: Log full elevation command ---
                    # Note: The log below shows the command string as passed to -Command.
                    Write-Log -Message "DEBUG: Elevating with: FilePath='powershell.exe', ArgumentList='-Command', ""$commandString"", Verb='RunAs', Wait=`$true" -Level DEBUG
                    # --- END DEBUG ---
                    # Use -Command with the constructed string
                    Start-Process powershell.exe -Verb RunAs -ArgumentList "-Command", $commandString -Wait -ErrorAction Stop
                    Write-Log -Message "Successfully launched and waited for elevated process to handle task registration for '$TaskName'." -Level INFO
                } catch {
                    # Log error if elevation fails
                    Write-Log -Message "Failed to launch or wait for elevated process for task registration. User may have cancelled UAC prompt or another error occurred: $($_.Exception.Message)" -Level ERROR
                    if ($script:IsInteractive) { Write-Host "ERROR: Could not elevate to register/update the scheduled task '$TaskName'. Please run the script as Administrator or use the '-RegisterTask' switch in an Administrator PowerShell session." -ForegroundColor Red }
                    # Do NOT exit here, allow the script to continue if possible, but log the failure.
                }
                } else {
                    # Task likely exists based on pre-check, skip elevation attempt.
                    Write-Log -Message "Running interactively as non-Admin user, but task pre-check indicates task '$TaskName' likely exists (`$taskExistsPreCheck` = $taskExistsPreCheck). Skipping elevation attempt." -Level INFO
                    # Decide what to do here. Maybe just proceed? Or exit? For now, just log and let the script continue.
                    # The main logic later might still fail if it needs admin rights for something else, but we avoid unnecessary elevation for the task check.
                }
            }
        # Removed closing brace for the removed 'if ($taskNeedsUpdate)' check above.
    }
}
# --- End Automatic Task Registration ---

# --- Register Scheduled Task Logic (-RegisterTask Switch) ---
if ($RegisterTask) {
    # This block handles the explicit -RegisterTask switch.
    if (-not $script:IsAdminRun) {
        # Cannot register without Admin rights
        Write-Log -Level WARN -Message "Registering the scheduled task requires Administrator privileges. Please re-run as Admin." # Fixed typo
        Write-Log -Message "Task registration requested via -RegisterTask but script is not running as Admin. Task registration skipped." -Level WARN
        # Exit with error because the primary requested action (-RegisterTask) cannot be performed.
        exit 1
    } else {
        # Is Admin, proceed with registration/update using the function
        Write-Log -Message "-RegisterTask switch detected. Registering/Updating the scheduled task '$TaskName' via function." -Level INFO
        Write-Log -Message "Attempting to call Register-ScheduledTaskForScript..." -Level DEBUG # <-- ADDED
        try {
            Write-Log -Message "Inside TRY block before calling Register-ScheduledTaskForScript for task '$TaskName'." -Level DEBUG # <-- ADDED
            # Call the dedicated function
            Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition -TaskName $TaskName -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes -ErrorAction Stop
            Write-Log -Message "Register-ScheduledTaskForScript completed successfully (within TRY block)." -Level INFO # <-- ADDED
            # If the function succeeds, exit cleanly as requested by -RegisterTask
            Write-Log -Message "Task registration process finished via function. Exiting script as -RegisterTask was specified." -Level INFO
            # --- START DEBUG: Add pause for elevated task registration window --- # Removed pause
            # Read-Host "Elevated task registration finished. Press Enter to close this window..." # Removed pause
            # --- END DEBUG --- # Removed pause
            exit 0
        } catch {
             # Log error if the function fails even with Admin rights
             $taskRegErrorMsg = "Failed to register/update task '$TaskName' via function even with -RegisterTask and Admin rights: $($_.Exception.Message)" # <-- ADDED
             Write-Log -Message $taskRegErrorMsg -Level ERROR # <-- ADDED
             Write-Log -Message "Error Record: ($($_ | Out-String))" -Level DEBUG # <-- ADDED
             Write-Log -Message "Failed to register/update task via function even with -RegisterTask and Admin rights: $($_.Exception.Message)" -Level ERROR
             if ($script:IsInteractive) { Write-Host "ERROR: Failed to register/update the scheduled task '$TaskName' even with -RegisterTask switch and Admin rights. Check logs." -ForegroundColor Red }
             # Exit with error because the requested action failed
             exit 1
        }
    }
}
# The elseif condition previously on line 788 is now redundant because the interactive admin case
# is handled earlier (around line 698+) which now also calls the Register-ScheduledTaskForScript function.
# --- End Register Scheduled Task Logic ---


# --- Set Download Directory (Moved earlier, after Log Dir) ---
$DownloadDir = Join-Path -Path $ScriptSaveFolder -ChildPath "Downloads"
Write-Log -Level DEBUG -Message "Download directory set to: '$DownloadDir'"

# --- Define Constants ---
$UpdateXmlUrl = "https://update.loxone.com/updatecheck.xml"
$MSListFileName = "UpdateLoxoneMSList.txt"
$MSListPath = Join-Path -Path $ScriptSaveFolder -ChildPath $MSListFileName
$ZipFileName = "LoxoneConfigSetup.zip"
$ZipFilePath = Join-Path -Path $DownloadDir -ChildPath $ZipFileName
$InstallerFileName = "loxoneconfigsetup.exe"
$InstallerPath = Join-Path -Path $DownloadDir -ChildPath $InstallerFileName

# --- Log Initial Admin Status ---
Write-Log -Level DEBUG -Message "Running as Admin: $script:IsAdminRun"

# --- Log Rotation ---
# Log rotation moved to the end of the script (in the finally block)

# --- Enter Script Scope & Log Start ---
Enter-Function -FunctionName (Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf) -FilePath $PSCommandPath -LineNumber $MyInvocation.ScriptLineNumber
Write-Log -Message "Script starting execution. PID: $PID. IsElevated: $global:IsElevatedInstance. IsSystem: $script:isRunningAsSystem. IsInteractive: $script:IsInteractive" -Level DEBUG

# --- Initialize Toast AppId (Call once) ---
Initialize-LoxoneToastAppId
# --- End Initialize Toast AppId ---

# --- Get Latest Version Info using Module Function ---
Write-Log -Message "Fetching Loxone update data using Get-LoxoneUpdateData function..." -Level INFO
$updateDataParams = @{
    UpdateXmlUrl         = $UpdateXmlUrl
    ConfigChannel        = $Channel
    CheckAppUpdate       = $UpdateLoxoneApp
    AppChannelPreference = $UpdateLoxoneAppChannel
    EnableCRC            = $EnableCRC
}
if ($DebugMode) { $updateDataParams.DebugMode = $true }

$updateData = Get-LoxoneUpdateData @updateDataParams

if ($updateData.Error) {
    Write-Log -Message "Error retrieving update data: $($updateData.Error)" -Level ERROR
    throw "Failed to retrieve update data. Cannot continue."
}

# Add check for essential Config version data
if ($null -eq $updateData.ConfigLatestVersion) {
    throw "CRITICAL: Could not determine the latest Loxone Config version from the update data. Cannot proceed."
}

# --- Assign results from $updateData to script variables ---
$LatestVersion              = $updateData.ConfigLatestVersion     # Normalized [version] object or null
$ZipUrl                     = $updateData.ConfigZipUrl
$ExpectedZipSize            = $updateData.ConfigExpectedZipSize
$ExpectedCRC                = $updateData.ConfigExpectedCRC       # Null if not found or not enabled

$latestLoxWindowsVersionRaw = $updateData.AppLatestVersionRaw     # Raw string or null
$latestLoxWindowsVersion    = $updateData.AppLatestVersion        # Normalized [version] object or null
$loxWindowsInstallerUrl     = $updateData.AppInstallerUrl
$expectedLoxWindowsSize     = $updateData.AppExpectedSize
$expectedLoxWindowsCRC      = $updateData.AppExpectedCRC          # Null if not found or not enabled
$selectedAppChannelName     = $updateData.SelectedAppChannelName  # Actual channel used for App

# Log summary (already logged within the function, but can add a confirmation here if needed)
Write-Log -Message "Successfully retrieved update data." -Level INFO
if ($LatestVersion) { Write-Log -Message "[Config] Latest: $LatestVersion, URL: $ZipUrl" -Level DEBUG }
if ($latestLoxWindowsVersion) { Write-Log -Message "[App] Latest ($selectedAppChannelName): $latestLoxWindowsVersion (Raw: $latestLoxWindowsVersionRaw), URL: $loxWindowsInstallerUrl" -Level DEBUG }

# Note: The detailed debug logging of the XML content (lines 595-635) is removed
# as the Get-LoxoneUpdateData function handles its own internal logging.
# Note: $ExpectedXmlSignature is no longer extracted or used.

# --- App Check: Check and Prepare Loxone Application ---
# Update Toast for App Check Start (Part of Step 1)
$toastParamsAppCheckStart = @{ StepNumber=1; TotalSteps=$script:totalSteps; StepName="Step 1/$($script:totalSteps): Checking Loxone App..."; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
# Only show initial check toasts in interactive (dot-sourced) runs.
if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppCheckStart }
Write-Log -Message "[App Check] Checking Loxone application status before update..." -Level INFO
$appDetails = $null
try {
    $appDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction Stop
    if ($appDetails.Error) { Write-Log -Message "[App Check] Failed to get Loxone application details from registry: $($appDetails.Error)" -Level WARN }
    else { Write-Log -Message ("[App Check] Found Loxone App: Name='{0}', Path='{1}', ProductVersion='{2}', FileVersion='{3}'" -f $appDetails.ShortcutName, $appDetails.InstallLocation, $appDetails.ProductVersion, $appDetails.FileVersion) -Level INFO }
} catch { Write-Log -Message "[App Check] An error occurred during initial application check: $($_.Exception.Message)" -Level ERROR }
 
# --- App Check: Loxone App Version Comparison and Update Logic ---
$appUpdateNeeded = $false # Initialize here
if ($appDetails -and -not $appDetails.Error) {
    if ($UpdateLoxoneApp -and $latestLoxWindowsVersion) {
        Write-Log -Message "[App Check] Comparing installed FileVersion '$($appDetails.FileVersion)' with latest available '$($latestLoxWindowsVersion)'..." -Level INFO
        $normalizedLatestApp = Convert-VersionString $latestLoxWindowsVersion; $normalizedInstalledApp = Convert-VersionString $appDetails.FileVersion
        try {
            if ([Version]$normalizedLatestApp -ne [Version]$normalizedInstalledApp) {
                 if ([Version]$normalizedLatestApp -gt [Version]$normalizedInstalledApp) { $appUpdateNeeded = $true; Write-Log -Message "[App Check] Comparison result: Update needed (Latest '$normalizedLatestApp' > Installed '$normalizedInstalledApp')." -Level DEBUG }
                 else { Write-Log -Message "[App Check] Comparison result: No update needed (Latest '$normalizedLatestApp' <= Installed '$normalizedInstalledApp')." -Level DEBUG }
            } else { Write-Log -Message "[App Check] Comparison result: Versions match ('$normalizedLatestApp'). No update needed." -Level DEBUG }
        } catch { Write-Log -Message "[App Check] Error comparing versions '$normalizedLatestApp' and '$normalizedInstalledApp': $($_.Exception.Message). Assuming no update needed." -Level WARN; $appUpdateNeeded = $false }
    }
 
    # This block executes only if $appUpdateNeeded was set to true above
    if ($appUpdateNeeded) {
        Write-Log -Message "[App Check] Update required for Loxone for Windows (Channel: $selectedAppChannelName, Installed FileVersion: '$($appDetails.FileVersion)', Available: '$latestLoxWindowsVersion')." -Level INFO

        # --- Step: Stop App (if running) ---
        # Note: Stopping the app isn't counted as a main step for the overall progress bar, but we update the status text.
        $script:wasLoxoneAppRunning = $false
        if (-not ([string]::IsNullOrWhiteSpace($appDetails.ShortcutName))) {
            Write-Log -Message "[App] Checking if process '$($appDetails.ShortcutName)' is running before update..." -Level DEBUG
            $script:wasLoxoneAppRunning = Get-ProcessStatus -ProcessName $appDetails.ShortcutName -StopProcess:$false
            if ($script:wasLoxoneAppRunning) {
                Write-Log -Message "[App] Process '$($appDetails.ShortcutName)' is running. Attempting to stop..." -Level INFO
                # Update status text without incrementing main step
                $toastParamsStopApp = @{
                    StepNumber = $script:currentStep # Use current step number
                    TotalSteps = $script:totalSteps
                    StepName   = "Stopping Loxone App"
                }
                if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsStopApp }
                if (Get-ProcessStatus -ProcessName $appDetails.ShortcutName -StopProcess:$true) { Write-Log -Message "[App] Successfully requested termination for process '$($appDetails.ShortcutName)'." -Level INFO; Start-Sleep -Seconds 2 }
                else { Write-Log -Message "[App] Get-ProcessStatus -StopProcess returned false for '$($appDetails.ShortcutName)'. It might have failed or was already stopped." -Level WARN }
            } else { Write-Log -Message "[App] Process '$($appDetails.ShortcutName)' is not running." -Level INFO }
        } else { Write-Log -Message "[App] ShortcutName not found in registry details. Cannot check/stop process by name." -Level WARN }

        # --- Step: Download App ---
        $script:currentStep++
        $script:currentDownload++
        $LoxoneWindowsInstallerFileName = Split-Path -Path $loxWindowsInstallerUrl -Leaf
        $LoxoneWindowsInstallerPath = Join-Path -Path $DownloadDir -ChildPath $LoxoneWindowsInstallerFileName
        Write-Log -Message "[App] Using original installer filename: '$LoxoneWindowsInstallerFileName'" -Level DEBUG

        # Check existing App installer using the generalized function
        $skipAppDownload = $false
        # Note: $latestLoxWindowsVersion is already normalized
        $appInstallerCheckResult = Test-ExistingInstaller -InstallerPath $LoxoneWindowsInstallerPath -TargetVersion $latestLoxWindowsVersion -ComponentName "App"

        if ($appInstallerCheckResult.IsValid) {
            $skipAppDownload = $true
            # No extraction step for App, so SkipExtraction is ignored
            # Update Toast
            $toastParamsAppSkipExisting = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Using Valid Existing App Installer"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppSkipExisting }
            # Add weight for skipped download step
            $script:CurrentWeight += Get-StepWeight -StepID 'DownloadApp'
            Write-Log -Message "[App] Added weight for skipped download based on valid existing installer. Current weight: $($script:CurrentWeight)." -Level DEBUG
        } elseif ($appInstallerCheckResult.Reason -ne "Not found") {
            # Installer exists but is invalid
            Write-Log -Message "[App] Existing installer '$LoxoneWindowsInstallerPath' is invalid ($($appInstallerCheckResult.Reason)). Removing and proceeding with download." -Level WARN
            Remove-Item -Path $LoxoneWindowsInstallerPath -Force -ErrorAction SilentlyContinue
        }
        # If Reason is "Not found", proceed with download.

        # Perform Download if not skipped
        if (-not $skipAppDownload) {
            Write-Log -Message "[App] Downloading Loxone for Windows installer from '$loxWindowsInstallerUrl' to '$LoxoneWindowsInstallerPath'..." -Level INFO
            if (-not (Test-Path -Path $DownloadDir -PathType Container)) { Write-Log -Message "[App] Download directory '$DownloadDir' not found. Creating..." -Level INFO; New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null }

            # Update Toast for App Download Start
            $toastParamsAppDownloadStart = @{
            StepNumber       = $script:currentStep
            TotalSteps       = $script:totalSteps
            StepName         = "Downloading Loxone App"
            DownloadFileName = $LoxoneWindowsInstallerFileName # Pass filename for progress bar status
            DownloadNumber   = $script:currentDownload
            TotalDownloads   = $script:totalDownloads
            CurrentWeight    = $script:CurrentWeight # Pass current weight for overall progress
            TotalWeight      = $script:TotalWeight
        }
        if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppDownloadStart }

        # Call Invoke-LoxoneDownload
        $appDownloadParams = @{
            Url              = $loxWindowsInstallerUrl
            DestinationPath  = $LoxoneWindowsInstallerPath
            ActivityName     = "Downloading Loxone App Update" # Used by Write-Progress
            ExpectedCRC32    = $expectedLoxWindowsCRC
            ExpectedFilesize = $expectedLoxWindowsSize
            MaxRetries       = 1
            IsSystem         = $script:isRunningAsSystem
            # Pass step info for toast updates *within* the download function
            StepNumber       = $script:currentStep
            TotalSteps       = $script:totalSteps
            StepName         = "Downloading Loxone App"
            DownloadNumber   = $script:currentDownload
            TotalDownloads   = $script:totalDownloads
            CurrentWeight    = $script:CurrentWeight # Pass weight for overall progress updates within download
            TotalWeight      = $script:TotalWeight
        }
        Write-Log -Message "[App] Calling Invoke-LoxoneDownload for App Update using stored command object and splatting." -Level DEBUG
        # $script:currentDownload += 1 # Increment before download - Incorrect, should be done once per download step
        $appDownloadSuccess = Invoke-LoxoneDownload @appDownloadParams
        if (-not $appDownloadSuccess) { throw "[App] Invoke-LoxoneDownload reported failure for Loxone App. Halting app update process." }
            $script:CurrentWeight += Get-StepWeight -StepID 'DownloadApp' # Increment weight AFTER successful download
            Write-Log -Message "[App] Loxone for Windows download completed successfully. Incremented weight to $($script:CurrentWeight)." -Level INFO
        } # End if (-not $skipAppDownload)

        # --- Step: Install App ---
        $script:currentStep++
        Write-Log -Message "[App] Running Loxone for Windows installer..." -Level INFO
        # Update Toast for App Install Start
        $toastParamsAppInstall = @{
            StepNumber    = $script:currentStep
            TotalSteps    = $script:totalSteps
            StepName      = "Installing Loxone App"
            CurrentWeight = $script:CurrentWeight # Pass current weight
            TotalWeight   = $script:TotalWeight
        }
        if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppInstall }
        $appInstallArgs = "/$InstallMode"
        Write-Log -Message "[App] Executing: Start-Process -FilePath '$LoxoneWindowsInstallerPath' -ArgumentList '$appInstallArgs' -Wait -PassThru" -Level DEBUG
        try {
            $appInstallProcess = Start-Process -FilePath $LoxoneWindowsInstallerPath -ArgumentList $appInstallArgs -Wait -PassThru -ErrorAction Stop
            Write-Log -Message "[App] Loxone for Windows installer process exited with code: $($appInstallProcess.ExitCode)" -Level INFO
            if ($appInstallProcess.ExitCode -ne 0) { Write-Log -Message "[App] Loxone for Windows installer returned non-zero exit code: $($appInstallProcess.ExitCode). Installation may have failed." -Level WARN }
            else {
                 Write-Log -Message "[App] Loxone for Windows installation command completed." -Level INFO
                 $anyUpdatePerformed = $true # Set flag: App update performed
                 $script:CurrentWeight += 1 # Increment weight AFTER successful install
                 Write-Log -Message "[App] Incremented weight to $($script:CurrentWeight)." -Level INFO

                 # Update Toast for Verification Start (Still part of Install Step conceptually)
                 $toastParamsAppVerify = @{
                     StepNumber    = $script:currentStep # Keep same step number
                     TotalSteps    = $script:totalSteps
                     StepName      = "Verifying Loxone App Installation"
                     CurrentWeight = $script:CurrentWeight # Pass current weight
                     TotalWeight   = $script:TotalWeight
                 }
                 if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppVerify }

                 Write-Log -Message "[App] Waiting 5 seconds before verification..." -Level DEBUG; Start-Sleep -Seconds 5
                 Write-Log -Message "[App] Verifying Loxone for Windows installation..." -Level INFO
                 $newAppDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction SilentlyContinue
                 if ($newAppDetails -and -not $newAppDetails.Error) {
                     $normalizedLatestAppVerify = Convert-VersionString $latestLoxWindowsVersion; $normalizedNewInstalledAppVerify = Convert-VersionString $newAppDetails.FileVersion; $verificationSuccess = $false
                     try { if ([Version]$normalizedNewInstalledAppVerify -eq [Version]$normalizedLatestAppVerify) { $verificationSuccess = $true }; Write-Log -Message "[App] Verification comparison result: Success = $verificationSuccess (Expected: '$normalizedLatestAppVerify', Found: '$normalizedNewInstalledAppVerify')" -Level DEBUG }
                     catch { Write-Log -Message "[App] Error comparing versions during verification: '$normalizedLatestAppVerify' vs '$normalizedNewInstalledAppVerify': $($_.Exception.Message). Verification failed." -Level WARN; $verificationSuccess = $false }

                     if ($verificationSuccess) {
                         Write-Log -Message "[App] Successfully updated Loxone App to FileVersion $($newAppDetails.FileVersion)." -Level INFO
                         $script:appUpdated = $true # Set flag for successful app update
                         # Update Toast for App Update Complete
                         $toastParamsAppComplete = @{
                             StepNumber    = $script:currentStep # Keep same step number
                             TotalSteps    = $script:totalSteps
                             StepName      = "Loxone App Update Complete (v$($newAppDetails.FileVersion))"
                             CurrentWeight = $script:CurrentWeight # Pass current weight
                             TotalWeight   = $script:TotalWeight
                         }
                         if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppComplete }

                         # --- Step: Restart App (if needed) ---
                         # Not counted as a main step, but update status text
                         if ($script:wasLoxoneAppRunning) {
                             Write-Log -Message "[App] Loxone App was running before the update. Attempting restart..." -Level INFO
                             $toastParamsAppRestart = @{
                                 StepNumber    = $script:currentStep # Keep same step number
                                 TotalSteps    = $script:totalSteps
                                 StepName      = "Restarting Loxone App"
                                 CurrentWeight = $script:CurrentWeight # Pass current weight
                                 TotalWeight   = $script:TotalWeight
                             }
                             if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppRestart }
                             $appPathToRestart = $newAppDetails.InstallLocation
                             if ($script:IsInteractive -and -not $script:isRunningAsSystem) {
                                 Write-Log -Message "[App] Restarting interactively using Start-Process..." -Level INFO
                                 try { Start-Process -FilePath $appPathToRestart -WindowStyle Minimized -ErrorAction Stop; Write-Log -Message "[App] Start-Process command issued for '$appPathToRestart'." -Level INFO }
                                 catch { Write-Log -Message "[App] Failed to restart Loxone App interactively using Start-Process: $($_.Exception.Message)" -Level ERROR; $toastParamsAppRestartFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Failed to restart Loxone App"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppRestartFail } }
                             } elseif ($script:isRunningAsSystem) { # This condition is now technically always false here due to re-launch logic, but keep structure for now
                                 Write-Log -Message "[App] Running as SYSTEM. Attempting restart via Invoke-AsCurrentUser function..." -Level INFO
                                 try { Write-Log -Message "[App] Calling Invoke-AsCurrentUser -FilePath '$appPathToRestart' -Visible -NoWait..." -Level DEBUG; Invoke-AsCurrentUser -FilePath $appPathToRestart -NoWait -ErrorAction Stop; Write-Log -Message "[App] Invoke-AsCurrentUser command issued for '$appPathToRestart'." -Level INFO }
                                 catch { Write-Log -Message "[App] Invoke-AsCurrentUser function failed to restart Loxone App: $($_.Exception.Message)" -Level ERROR; $toastParamsAppRestartFailSys = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Failed to restart Loxone App (System)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppRestartFailSys } }
                             } else { Write-Log -Message "[App] Unclear execution context (Not Interactive User, Not SYSTEM). Automatic restart not attempted." -Level WARN; $toastParamsAppRestartSkip = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="WARN: Loxone App restart skipped"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppRestartSkip } }
                         } else { Write-Log -Message "[App] Loxone App was not running before the update. No restart needed." -Level INFO }
                     # Removed duplicate line from previous failed diff
                 } else { Write-Log -Message "[App] Loxone App update verification failed! Expected FileVersion '$normalizedLatestAppVerify' but found '$normalizedNewInstalledAppVerify' after installation." -Level ERROR; $toastParamsAppVerifyFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Loxone App verification failed!"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppVerifyFail } }
             } else { Write-Log -Message "[App] Failed to get Loxone App details from registry after installation attempt. Verification failed. Error: $($newAppDetails.Error)" -Level ERROR; $toastParamsAppVerifyFailReg = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Loxone App verification failed (Registry)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsAppVerifyFailReg } }
            }
        } catch { Write-Log -Message "[App] Failed to run Loxone for Windows installer: $($_.Exception.Message)" -Level ERROR; $toastParamsAppInstallFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="FAILED: Loxone App installation failed"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppInstallFail; throw "[App] Failed to execute Loxone for Windows installer." }

    } else { # Corresponds to: if ($appUpdateNeeded)
        if ($appDetails -and -not $appDetails.Error) { Write-Log -Message "[App Check] Loxone for Windows (Channel: $selectedAppChannelName) is already up-to-date (FileVersion: $($appDetails.FileVersion))." -Level INFO } # Removed step increment and toast update here
    } # Closes: else corresponding to if ($appUpdateNeeded)
 
} # Closes: if ($appDetails -and -not $appDetails.Error)
elseif ($UpdateLoxoneApp -and -not $latestLoxWindowsVersion) { Write-Log -Message "[App Check] Skipping Loxone App update (Channel: $selectedAppChannelName) because latest version details could not be retrieved from XML (XML fetch/parse failed)." -Level WARN; $updateToastParams14 = @{ NewStatus = "WARN: Loxone App update skipped (failed to get latest version info)." }; if ($script:IsInteractiveRun) { Update-PersistentToast @updateToastParams14 } } # UseTaskWorkaround removed
elseif ($UpdateLoxoneApp -and (!$appDetails -or $appDetails.Error)) { Write-Log -Message "[App Check] Skipping Loxone App update check (Channel: $selectedAppChannelName) because installed application details could not be retrieved." -Level WARN; $updateToastParams15 = @{ StepName = "WARN: Loxone App update skipped (cannot find installed app)." }; if ($script:IsInteractiveRun) { Update-PersistentToast @updateToastParams15 } } # UseTaskWorkaround removed
# --- End App Check ---
 
 # --- Config Check: Compare Versions (Using Initially Detected Version) ---
 # Update Toast for Config Check Start (Part of Step 1)
 $toastParamsCfgCheckStart = @{ StepNumber=1; TotalSteps=$script:totalSteps; StepName="Step 1/$($script:totalSteps): Checking Loxone Config..."; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
 # Only show initial check toasts in interactive (dot-sourced) runs.
 if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgCheckStart }
 $LatestVersion = Convert-VersionString $LatestVersion # Normalize latest version from XML
 

# Use the $script:InitialInstalledVersion determined earlier (around line 195)
$normalizedInstalled = Convert-VersionString $script:InitialInstalledVersion # Normalize the initially found version

# Log the comparison versions
Write-Log -Level DEBUG -Message "[Config Check] Comparing versions - Latest (Normalized): '$LatestVersion', Installed (Initially Detected, Normalized): '$normalizedInstalled'"
 
# Determine if Config update is needed based on the initially detected version
$configUpdateNeeded = $false # Default to false
if ([string]::IsNullOrWhiteSpace($normalizedInstalled)) {
    # If no initial version was found (path missing or version retrieval failed), assume update is needed if a latest version exists
    if ($LatestVersion) {
        $configUpdateNeeded = $true
        Write-Log -Message "[Config Check] No initial installed version detected. Update required to latest version '$LatestVersion'." -Level INFO
    } else {
        Write-Log -Message "[Config Check] No initial installed version detected AND no latest version available. Cannot determine if update is needed." -Level WARN
    }
} elseif ($LatestVersion -ne $normalizedInstalled) {
    $configUpdateNeeded = $true
    Write-Log -Message "[Config Check] Loxone Config update required (Installed: '$($script:InitialInstalledVersion)', Available: '$LatestVersion'). Update process will proceed." -Level INFO
} else {
    # Versions match
    Write-Log -Message "[Config Check] Loxone Config is already up-to-date (Version: $($script:InitialInstalledVersion)). Config update will be skipped." -Level INFO
}

# Early exit removed - Proceed to MS checks even if Config/App are up-to-date


# --- Determine Loxone Icon Path (Uses $script:InstalledExePath) ---
$LoxoneIconPath = $null
if ($script:InstalledExePath -and (Test-Path $script:InstalledExePath)) {
    $InstallDir = Split-Path -Parent $script:InstalledExePath; $PotentialIconPath = Join-Path -Path $InstallDir -ChildPath "LoxoneConfig.ico"
    if (Test-Path $PotentialIconPath) { $LoxoneIconPath = $PotentialIconPath; Write-Log -Level DEBUG -Message "Found Loxone icon at: $LoxoneIconPath" }
    else { Write-Log -Level DEBUG -Message "LoxoneConfig.ico not found in $InstallDir. No icon will be used." }
}

# --- MS Check: Check MS Versions ---
# Update Toast for MS Check Start (Part of Step 1)
$toastParamsMSCheckStart = @{ StepNumber=1; TotalSteps=$script:totalSteps; StepName="Step 1/$($script:totalSteps): Checking MSs..."; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
# Only show initial check toasts in interactive (dot-sourced) runs.
if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsMSCheckStart }
Write-Log -Message "[MS Check] Starting MS version check..." -Level INFO
$MSUpdatePotentiallyNeeded = $false # Flag to track if any MS needs an update based on pre-check
$MSVersions = @{} # Store versions here (Host -> Version)
if (Test-Path $MSListPath) {
    try { # Outer try for reading/processing MS list
        $MSEntriesPreCheck = Get-Content $MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
        $totalMSsToCheck = $MSEntriesPreCheck.Count
        Write-Log -Message "[MS Check] Found $totalMSsToCheck MS entries in '$MSListPath'." -Level DEBUG
        $msPreCheckCounter = 0 # Initialize counter

        foreach ($msEntryPreCheck in $MSEntriesPreCheck) {
            $msPreCheckCounter++ # Increment counter
            # Update Toast for individual MS Check (Part of Step 1)
            $toastParamsMSCheckLoop = @{ StepNumber=1; TotalSteps=$script:totalSteps; StepName="Step 1/$($script:totalSteps): Checking MS $msPreCheckCounter/$totalMSsToCheck..."; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            # Only show initial check toasts in interactive (dot-sourced) runs.
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsMSCheckLoop }

            $redactedEntryForLogPreCheck = Get-RedactedPassword $msEntryPreCheck
            Write-Log -Message "[MS Check] Processing entry $msPreCheckCounter/${totalMSsToCheck}: ${redactedEntryForLogPreCheck}" -Level DEBUG
            $msIPPreCheck = $null; $versionUriPreCheck = $null; $credentialPreCheck = $null

            try { # Inner try for parsing entry
                $entryToParsePreCheck = $msEntryPreCheck # Assign here
                if ($entryToParsePreCheck -notmatch '^[a-zA-Z]+://') { $entryToParsePreCheck = "http://" + $entryToParsePreCheck }
                $uriBuilderPreCheck = [System.UriBuilder]$entryToParsePreCheck
                $msIPPreCheck = $uriBuilderPreCheck.Host

                if (-not ([string]::IsNullOrWhiteSpace($uriBuilderPreCheck.UserName))) {
                    $securePasswordPreCheck = $uriBuilderPreCheck.Password | ConvertTo-SecureString -AsPlainText -Force
                    $credentialPreCheck = New-Object System.Management.Automation.PSCredential($uriBuilderPreCheck.UserName, $securePasswordPreCheck)
                }

                $uriBuilderPreCheck.Path = "/dev/cfg/version"
                $uriBuilderPreCheck.Port = 80 # Default to HTTP port for version check URI construction
                $uriBuilderPreCheck.Password = $null
                $uriBuilderPreCheck.UserName = $null
                $versionUriPreCheck = $uriBuilderPreCheck.Uri.AbsoluteUri

            } catch { # Inner catch for parsing entry
                Write-Log -Message "[MS Check] Failed to parse MS entry '$redactedEntryForLogPreCheck' as URI: $($_.Exception.Message). Assuming IP/hostname." -Level WARN
                $credentialPreCheck = $null
                $msIPPreCheck = $msEntryPreCheck.Split('@')[-1].Split('/')[0]
                if ($msIPPreCheck) { $versionUriPreCheck = "http://${msIPPreCheck}/dev/cfg/version" }
                else { Write-Log -Message "[MS Check] Could not determine IP/Host from entry '$redactedEntryForLogPreCheck'. Skipping." -Level ERROR; continue }
            }

            $redactedVersionUriPreCheck = Get-RedactedPassword $versionUriPreCheck
            Write-Log -Message "[MS Check] Checking version for '$msIPPreCheck' via URI: ${redactedVersionUriPreCheck}" -Level DEBUG

            $responseObjectPreCheck = $null; $msVersionCheckSuccessPreCheck = $false; $currentVersionPreCheck = "Error"
            $iwrParamsBasePreCheck = @{ TimeoutSec = 10; ErrorAction = 'Stop'; Method = 'Get' }
            if ($credentialPreCheck) { $iwrParamsBasePreCheck.Credential = $credentialPreCheck }
            try { # Try HTTPS
                $httpsUriBuilderPreCheck = [System.UriBuilder]$versionUriPreCheck; $httpsUriBuilderPreCheck.Scheme = 'https'; $httpsUriBuilderPreCheck.Port = 443
                $httpsUriPreCheck = $httpsUriBuilderPreCheck.Uri.AbsoluteUri
                $httpsParamsPreCheck = $iwrParamsBasePreCheck.Clone(); $httpsParamsPreCheck.Uri = $httpsUriPreCheck
                Write-Log -Message "[MS Check] Attempting HTTPS connection to $msIPPreCheck..." -Level DEBUG
                $responseObjectPreCheck = Invoke-WebRequest @httpsParamsPreCheck
                Write-Log -Message "[MS Check] HTTPS connection successful for $msIPPreCheck." -Level DEBUG
                $msVersionCheckSuccessPreCheck = $true
            } catch { # Catch for HTTPS attempt
                Write-Log -Message "[MS Check] HTTPS failed for $msIPPreCheck ($($_.Exception.Message)). Falling back to HTTP." -Level DEBUG
                # Add more details in Debug mode
                if ($Global:DebugPreference -eq 'Continue') {
                    $exceptionDetails = "[MS Check] HTTPS Failure Details for ${msIPPreCheck}:"
                    if ($_.Exception -is [System.Net.WebException]) {
                        if ($_.Exception.Status) { $exceptionDetails += "`n  Status: $($_.Exception.Status)" }
                        if ($_.Exception.Response) {
                            $responseStream = $_.Exception.Response.GetResponseStream()
                            $streamReader = New-Object System.IO.StreamReader($responseStream)
                            $responseBody = $streamReader.ReadToEnd()
                            $streamReader.Close()
                            $responseStream.Close()
                            $exceptionDetails += "`n  Response: $($_.Exception.Response.StatusCode) / $($_.Exception.Response.StatusDescription)"
                            if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                                $exceptionDetails += "`n  Response Body: $($responseBody)"
                            }
                        }
                    }
                    $exceptionDetails += "`n  Full Exception: $($_.Exception | Out-String)" # Include full exception details
                    Write-Log -Message $exceptionDetails -Level DEBUG
                }
                try { # Try HTTP
                    $httpParamsPreCheck = $iwrParamsBasePreCheck.Clone(); $httpParamsPreCheck.Uri = $versionUriPreCheck # Use original HTTP URI
                    $headers = @{} # Initialize headers hashtable
                    Write-Log -Message "[MS Check] Attempting HTTP connection to $msIPPreCheck..." -Level DEBUG
                    if ($httpParamsPreCheck.ContainsKey('Credential')) {
                         Write-Log -Message "[MS Check] Attempting HTTP request to $msIPPreCheck (with credentials, using Authorization header)." -Level WARN
                         # Construct Basic Auth Header
                         $credentialObject = $httpParamsPreCheck.Credential
                         $userName = $credentialObject.UserName
                         $password = $credentialObject.GetNetworkCredential().Password
                         $encodedCredentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${userName}:${password}"))
                         $headers.Authorization = "Basic $encodedCredentials"
                         # Remove Credential from splatting params as we're using header auth
                         $httpParamsPreCheck.Remove('Credential')
                    } else {
                         Write-Log -Message "[MS Check] Attempting HTTP request to $msIPPreCheck (no credentials)." -Level DEBUG
                    }
                    # Use standard splatting, adding Headers parameter
                    $responseObjectPreCheck = Invoke-WebRequest @httpParamsPreCheck -Headers $headers
                    Write-Log -Message "[MS Check] HTTP connection successful for $msIPPreCheck." -Level DEBUG
                    $msVersionCheckSuccessPreCheck = $true
                } catch { # Catch for HTTP attempt (Invoke-WebRequest)
                    Write-Log -Message "[MS Check] Failed to get version for '$msIPPreCheck' via HTTP as well: $($_.Exception.Message)" -Level ERROR # Keep primary message as ERROR
                    # Add more details in Debug mode
                    if ($Global:DebugPreference -eq 'Continue') {
                        $exceptionDetails = "[MS Check] HTTP Failure Details for ${msIPPreCheck}:"
                        if ($_.Exception -is [System.Net.WebException]) {
                            if ($_.Exception.Status) { $exceptionDetails += "`n  Status: $($_.Exception.Status)" }
                            if ($_.Exception.Response) {
                                $responseStream = $_.Exception.Response.GetResponseStream()
                                $streamReader = New-Object System.IO.StreamReader($responseStream)
                                $responseBody = $streamReader.ReadToEnd()
                                $streamReader.Close()
                                $responseStream.Close()
                                $exceptionDetails += "`n  Response: $($_.Exception.Response.StatusCode) / $($_.Exception.Response.StatusDescription)"
                                if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                                    $exceptionDetails += "`n  Response Body: $($responseBody)"
                                }
                            }
                        }
                        $exceptionDetails += "`n  Full Exception: $($_.Exception | Out-String)" # Include full exception details
                        Write-Log -Message $exceptionDetails -Level DEBUG # Log extra details at DEBUG level
                    }
                    $script:ErrorOccurred = $true # Set error flag as connection failed
                    $msVersionCheckSuccessPreCheck = $false
                } # End HTTP catch
            } # End HTTPS catch

            # Process response if EITHER HTTPS or HTTP succeeded
            if ($msVersionCheckSuccessPreCheck -and $responseObjectPreCheck) {

                # --- BEGIN Raw Response Logging (Pre-Check) ---
                try {
                    # Construct a log prefix for clarity
                    $logPrefix = "[MS Pre-Check/$msIPPreCheck]"
                    # Access the raw content from the response object
                    $rawResponseContentForLog = $responseObjectPreCheck.Content
                    Write-Log -Level DEBUG -Message "$logPrefix Raw MS version check response content:`n--- RAW MS RESPONSE START ---`n$rawResponseContentForLog`n--- RAW MS RESPONSE END ---"
                } catch {
                    Write-Log -Level WARN -Message "$logPrefix Failed to log raw MS version check response content. Error: $($_.Exception.Message)"
                }
                # --- END Raw Response Logging (Pre-Check) ---

                try { # Try parsing XML
                    $xmlResponsePreCheck = [xml]$responseObjectPreCheck.Content
                    $currentVersionPreCheck = $xmlResponsePreCheck.LL.value
                    if ($null -eq $xmlResponsePreCheck -or $null -eq $xmlResponsePreCheck.LL -or $null -eq $xmlResponsePreCheck.LL.value) { throw "Could not find version value in parsed XML." }
                    Write-Log -Message "[MS Check] MS '$msIPPreCheck' current version: ${currentVersionPreCheck}" -Level INFO

                    # --- Log the comparison ---
                    Write-Log -Level INFO -Message "[MS Pre-Check] Comparing MS version for '$msIPPreCheck': Current='$currentVersionPreCheck', Desired='$LatestVersion'"

                    # --- Check if this version differs from the target ---
                    try {
                        if ([version](Convert-VersionString $currentVersionPreCheck) -ne [version]$LatestVersion) {
                            Write-Log -Message "[MS Check] MS '$msIPPreCheck' version '$currentVersionPreCheck' differs from target '$LatestVersion'. Update potentially needed." -Level INFO
                            $MSUpdatePotentiallyNeeded = $true
                        }
                    } catch {
                        Write-Log -Message "[MS Check] Error comparing version '$currentVersionPreCheck' with target '$LatestVersion' for '$msIPPreCheck': $($_.Exception.Message)" -Level WARN
                        # Treat comparison error as potentially needing update for safety
                        $MSUpdatePotentiallyNeeded = $true
                    }
                    # --- End version comparison ---

                } catch { # Catch for parsing XML
                    Write-Log -Message "[MS Check] Failed to parse version XML for '$msIPPreCheck': $($_.Exception.Message)" -Level ERROR
                    $currentVersionPreCheck = "Error Parsing XML"
                    # Treat parsing error as potentially needing update
                    $MSUpdatePotentiallyNeeded = $true
                } # End XML parsing catch
            } elseif (-not $msVersionCheckSuccessPreCheck) {
                $currentVersionPreCheck = "Error Connecting" # Already logged specific error
                # Treat connection error as potentially needing update
                Write-Log -Message "[MS Check] Connection failed for '$msIPPreCheck'. Assuming update potentially needed." -Level WARN
                $MSUpdatePotentiallyNeeded = $true
            } # End if/elseif for processing response
            $MSVersions[$msIPPreCheck] = $currentVersionPreCheck # Store result
        } # End foreach msEntryPreCheck
    } catch { # Catch for the outer try (started line 959)
        Write-Log -Message "[MS Check] Error reading or processing MS list '$MSListPath': $($_.Exception.Message). Skipping MS version pre-check." -Level WARN
    } # End outer catch
} else { # Else for the if (Test-Path $MSListPath) (line 958)
    Write-Log -Message "[MS Check] MS list '$MSListPath' not found. Skipping MS version pre-check." -Level INFO
}
# You can access the collected versions in the $MSVersions hashtable later if needed
Write-Log -Message "[MS Check] Finished MS version check." -Level INFO
# --- End MS Check: Check MS Versions ---

# Recalculate MSCount for step/weight calculations
$MSCount = 0
if (Test-Path $MSListPath) {
    try {
        $MSEntries = Get-Content $MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
        $MSCount = ($MSEntries | Measure-Object).Count
    } catch {
        Write-Log -Level WARN -Message "Error reading MS list '$MSListPath' during step/weight calculation: $($_.Exception.Message). Assuming 0 MSs."
    }
}

# --- Define Progress Steps (Moved before Try block) ---
$ProgressSteps = @(
    @{ ID = 'InitialCheck';   Description = 'Checking versions';              Weight = 1; Condition = { $true } };
    @{ ID = 'DownloadConfig'; Description = 'Downloading Loxone Config';      Weight = 2; Condition = { $configUpdateNeeded } };
    @{ ID = 'ExtractConfig';  Description = 'Extracting Loxone Config';       Weight = 1; Condition = { $configUpdateNeeded } }; # Weight applied even if download skipped
    @{ ID = 'InstallConfig';  Description = 'Installing Loxone Config';       Weight = 3; Condition = { $configUpdateNeeded } };
    @{ ID = 'VerifyConfig';   Description = 'Verifying Loxone Config install';Weight = 1; Condition = { $configUpdateNeeded } };
    @{ ID = 'DownloadApp';    Description = 'Downloading Loxone App';         Weight = 1; Condition = { $appUpdateNeeded } };
    @{ ID = 'InstallApp';     Description = 'Installing Loxone App';          Weight = 1; Condition = { $appUpdateNeeded } };
    @{ ID = 'UpdateMS';       Description = 'Updating MSs';           Weight = 0; Condition = { $MSCount -gt 0 -and $configUpdateNeeded } }; # Condition includes config update needed
    @{ ID = 'Finalize';       Description = 'Finalizing';                     Weight = 1; Condition = { $true } }
)
function Get-StepWeight { param([string]$StepID); $stepObject = $ProgressSteps | Where-Object { $_.ID -eq $StepID } | Select-Object -First 1; if ($stepObject) { if ($stepObject.ContainsKey('Weight')) { return $stepObject.Weight } else { Write-Log -Level WARN -Message "Get-StepWeight: Found step with ID '$StepID' but it lacked a 'Weight' key."; return 0 } } else { Write-Log -Level WARN -Message "Get-StepWeight: Could not find step with ID '$StepID'."; return 0 } }

try { # --- Start of Main Try Block ---
    # --- Calculate Total Weight ---
    Write-Log -Message "Calculating total progress weight..." -Level INFO; $script:TotalWeight = 0; $script:CurrentWeight = 0;
    # $MSCount already calculated above
    foreach ($step in $ProgressSteps) { $runStep = $false; try { $runStep = Invoke-Command -ScriptBlock $step.Condition } catch { Write-Log -Message "Error evaluating condition for step '$($step.ID)': $($_.Exception.Message)" -Level WARN; $runStep = $false }; if ($runStep) { if ($step.ID -eq 'UpdateMS') { $msWeightPerServer = 2; $script:TotalWeight += ($MSCount * $msWeightPerServer); Write-Log -Message "Condition TRUE for step '$($step.ID)'. Adding weight: $($MSCount * $msWeightPerServer) ($MSCount servers * $msWeightPerServer weight/server)." -Level DEBUG } else { $script:TotalWeight += $step.Weight; Write-Log -Message "Condition TRUE for step '$($step.ID)'. Adding weight: $($step.Weight)." -Level DEBUG } } else { Write-Log -Message "Condition FALSE for step '$($step.ID)'. Skipping weight: $($step.Weight)." -Level DEBUG } }
    $initialCheckStep = $ProgressSteps | Where-Object { $_.ID -eq 'InitialCheck' } | Select-Object -First 1; if ($initialCheckStep) { $script:CurrentWeight = $initialCheckStep.Weight; Write-Log -Message "Setting initial weight to $($script:CurrentWeight) for completed 'InitialCheck' step." -Level DEBUG }
    Write-Log -Message "Total calculated progress weight: $script:TotalWeight" -Level INFO

    # --- Calculate Total Steps/Downloads ---
    $script:totalSteps = 1 # Start count at 1 (for Initial Checks step)
    $script:totalDownloads = 0
    Write-Log -Level DEBUG -Message "Recalculating steps/downloads..."
    if ($configUpdateNeeded) {
        $script:totalSteps += 3 # Download (or skip), Extract, Install Config
        $script:totalDownloads += 1
        Write-Log -Level DEBUG -Message "Config update needed. Adding 3 steps, 1 download."
    } else {
         Write-Log -Level DEBUG -Message "Config update NOT needed. Skipping Config steps/download."
    }
    if ($appUpdateNeeded) {
        $script:totalSteps += 2 # Download, Install App
        $script:totalDownloads += 1
        Write-Log -Level DEBUG -Message "App update needed. Adding 2 steps, 1 download."
    } else {
         Write-Log -Level DEBUG -Message "App update NOT needed. Skipping App steps/download."
    }
    # Add MS step only if Config update is needed AND servers exist
    if ($configUpdateNeeded -and $MSCount -gt 0) {
        $script:totalSteps += 1 # MS Update Step
        Write-Log -Level DEBUG -Message "MS updates needed ($MSCount servers) because Config is updating. Adding 1 step."
    } elseif ($MSCount -gt 0) {
         Write-Log -Level DEBUG -Message "MS update step skipped because Config is not updating."
    } else {
         Write-Log -Level DEBUG -Message "No MS updates needed (list empty or error)."
    }
    # Step X: Finalization (Always performed)
    $script:totalSteps += 1
    Write-Log -Level DEBUG -Message "Adding 1 step for Finalization."
    Write-Log -Level INFO -Message "Recalculated Totals - Steps: $script:totalSteps, Downloads: $script:totalDownloads"
    # --- End Calculate Total Steps/Downloads ---

    # Update toast after calculations (This is Step 1: Initial Checks Complete)
    $script:currentStep = 1 # Start counting from Step 1
    $initialCheckStepName = "Initial Checks Complete"
    Write-Log -Level DEBUG -Message "Updating toast for step $($script:currentStep)/$($script:totalSteps): $initialCheckStepName"
    if ($script:IsInteractiveRun) { Update-PersistentToast -StepNumber $script:currentStep -TotalSteps $script:totalSteps -StepName $initialCheckStepName -CurrentWeight $script:CurrentWeight -TotalWeight $script:TotalWeight }
    # --- End Progress Calculation ---

    # Set path for potential MS update (use initially detected path)
    $LoxoneConfigExePathForMSUpdate = $script:InstalledExePath # Still needed for the check below, even if not passed to Update-MS
    Write-Log -Message "[MS] Using initially determined Loxone Config path for potential MS update check: '$LoxoneConfigExePathForMSUpdate'" -Level INFO

    # Check if Config update is needed (using $configUpdateNeeded determined earlier)
    if ($configUpdateNeeded) {
        # Log message already written earlier when $configUpdateNeeded was determined

        # --- Step: Download Config ---
        $script:currentStep++
        $script:currentDownload++
        $configDownloadStepName = "Downloading Loxone Config"
        Write-Log -Message "[Config] $configDownloadStepName (Step $($script:currentStep)/$($script:totalSteps), Download $($script:currentDownload)/$($script:totalDownloads))..." -Level INFO

        # Check running processes before download attempt
        $processesToCheck = @("LoxoneConfig", "loxonemonitor", "LoxoneLiveView"); $anyProcessRunning = $false
        foreach ($procName in $processesToCheck) { if (Get-ProcessStatus -ProcessName $procName -StopProcess:$false) { $anyProcessRunning = $true; Write-Log -Message "Detected running process: $procName" -Level INFO } }
        if ($anyProcessRunning -and $SkipUpdateIfAnyProcessIsRunning) {
            Write-Log -Message "Skipping update because one or more Loxone processes are running and -SkipUpdateIfAnyProcessIsRunning was specified." -Level WARN
            $toastParamsCfgSkipRunningPre = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Skipped: Loxone process running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgSkipRunningPre }
            exit 0 # Exit cleanly
        }

        # Check existing Config installer using the generalized function
        $skipDownload = $false
        $skipExtraction = $false
        $configInstallerCheckResult = Test-ExistingInstaller -InstallerPath $InstallerPath -TargetVersion $LatestVersion -ComponentName "Config"

        if ($configInstallerCheckResult.IsValid) {
            $skipDownload = $true
            $skipExtraction = $true # Function sets this correctly for Config
            # Update Toast
            $toastParamsCfgSkipExisting = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Using Valid Existing Config Installer"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgSkipExisting }
            # Add weights for skipped steps
            $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig'
            $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
            Write-Log -Message "[Config] Added weight for skipped download and extraction based on valid existing installer. Current weight: $($script:CurrentWeight)." -Level DEBUG
        } elseif ($configInstallerCheckResult.Reason -ne "Not found") {
            # Installer exists but is invalid (version mismatch or bad signature)
            Write-Log -Message "[Config] Existing installer '$InstallerPath' is invalid ($($configInstallerCheckResult.Reason)). Removing and proceeding with download." -Level WARN
            Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
        }
        # If Reason is "Not found", we just proceed with download naturally.

        # Perform Download if not skipped
        if (-not $skipDownload) {

            # Update Toast for Config Download Start
            $toastParamsCfgDownloadStart = @{
                StepNumber       = $script:currentStep
                TotalSteps       = $script:totalSteps
                StepName         = $configDownloadStepName
                DownloadFileName = $ZipFileName
                DownloadNumber   = $script:currentDownload
                TotalDownloads   = $script:totalDownloads
                CurrentWeight    = $script:CurrentWeight
                TotalWeight      = $script:TotalWeight
            }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgDownloadStart }

            # Call Invoke-LoxoneDownload
            $downloadParams = @{
                Url              = $ZipUrl
                DestinationPath  = $ZipFilePath
                ActivityName     = "Downloading Loxone Config Update"
                ExpectedCRC32    = $ExpectedCRC # Pass CRC if enabled
                ExpectedFilesize = $ExpectedZipSize
                MaxRetries       = 1
                IsSystem         = $script:isRunningAsSystem
                # Pass step info for toast updates *within* the download function
                StepNumber       = $script:currentStep
                TotalSteps       = $script:totalSteps
                StepName         = $configDownloadStepName
                DownloadNumber   = $script:currentDownload
                TotalDownloads   = $script:totalDownloads
                CurrentWeight    = $script:CurrentWeight
                TotalWeight      = $script:TotalWeight
            }
            Write-Log -Message "[Config] Calling Invoke-LoxoneDownload for Config Update using stored command object and splatting." -Level DEBUG
            # $script:currentDownload += 1 # Increment before download - Incorrect, should be done once per download step
            $downloadSuccess = Invoke-LoxoneDownload @downloadParams
            if (-not $downloadSuccess) { throw "Invoke-LoxoneDownload reported failure. Halting update process." }
            $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig' # Increment weight AFTER successful download
            Write-Log -Message "[Config] Loxone Config ZIP download completed successfully. Incremented weight to $($script:CurrentWeight)." -Level INFO

            # Update Toast for Download Complete / Verification (Still part of Download Step)
            $toastParamsCfgDownloadVerify = @{
                StepNumber    = $script:currentStep # Keep same step number
                TotalSteps    = $script:totalSteps
                StepName      = "Verifying Config Download"
                CurrentWeight = $script:CurrentWeight
                TotalWeight   = $script:TotalWeight
                DownloadFileName = $ZipFileName # Keep filename for context
                ProgressPercentage = 100 # Set download bar to 100%
            }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgDownloadVerify }
        }

        # --- Extract (Only if not skipped) ---
        if (-not $skipExtraction) {
            $extractStepName = "Extracting Config Installer"
            Write-Log -Message "[Config] $extractStepName..." -Level INFO
            $toastParamsCfgExtract = @{
                StepNumber    = $script:currentStep # Still conceptually part of download or pre-install
                TotalSteps    = $script:totalSteps
                StepName      = $extractStepName
                CurrentWeight = $script:CurrentWeight
                TotalWeight   = $script:TotalWeight
            }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgExtract }

            # Ensure installer isn't present from a previous failed run (should have been removed earlier if invalid)
            if (Test-Path $InstallerPath) {
                 Write-Log -Level DEBUG -Message "Removing existing installer file before extraction: $InstallerPath"
                 Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
            }

            # Temporarily suppress Write-Progress to avoid console buffer errors in non-interactive sessions
            $originalProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                Expand-Archive -Path $ZipFilePath -DestinationPath $DownloadDir -Force -ErrorAction Stop
            } finally {
                $ProgressPreference = $originalProgressPreference # Restore original preference
            }

            if (-not (Test-Path $InstallerPath)) { throw "Installer file '$InstallerPath' not found after extraction." }
            Write-Log -Message "[Config] Installer extracted successfully to $InstallerPath." -Level INFO
            # Add weight only if extraction actually happened (i.e., download wasn't skipped OR existing was invalid)
            $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
            Write-Log -Message "[Config] Added weight for extraction. Current weight: $($script:CurrentWeight)." -Level DEBUG

            # --- Verify Installer Signature (Only if extracted) ---
            $verifySigStepName = "Verifying Config Installer Signature"
            Write-Log -Message "[Config] $verifySigStepName (post-extraction)..." -Level INFO
            $toastParamsCfgVerifySig = @{
                StepNumber    = $script:currentStep # Still conceptually part of download or pre-install
                TotalSteps    = $script:totalSteps
                StepName      = $verifySigStepName
                CurrentWeight = $script:CurrentWeight
                TotalWeight   = $script:TotalWeight
            }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgVerifySig }
            # Use ExpectedXmlSignature fetched earlier
            if ($ExpectedXmlSignature) {
                 $sigCheckResult = Get-ExecutableSignature -ExePath $InstallerPath
                 # Robust check: Ensure result exists and status is valid
                 $validationFailed = $false
                 $failureReason = ""
                 if (-not $sigCheckResult) {
                     $validationFailed = $true
                     $failureReason = "Get-ExecutableSignature returned null."
                 } elseif ($sigCheckResult.Status -ne 'Valid') {
                     $validationFailed = $true
                     $failureReason = "Signature status is '$($sigCheckResult.Status)' (Expected 'Valid')."
                 }

                 # Add a note that XML signature itself isn't checked here
                 Write-Log -Level DEBUG -Message "Note: XML signature value ('$ExpectedXmlSignature') is present but not currently validated against the XML content."

                 if ($validationFailed) {
                     throw "CRITICAL: Extracted installer '$InstallerPath' failed signature validation. Reason: $failureReason"
                 }
                 Write-Log -Message "[Config] Extracted installer signature verified successfully." -Level INFO
            } else { Write-Log -Message "[Config] XML Signature was missing. Skipping installer signature validation (post-extraction)." -Level WARN }
        } else {
             Write-Log -Message "[Config] Skipping extraction and post-extraction signature check because a valid existing installer was found." -Level INFO
        }

        # --- Step: Install Config ---
        $script:currentStep++
        $configInstallStepName = "Installing Loxone Config"
        Write-Log -Message "[Config] $configInstallStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO

        # --- Close Running Applications (if requested, part of Install Step) ---
        $installationSkippedDueToRunningProcess = $false
        # Re-check processes right before install, even if checked before download
        $anyProcessRunning = $false
        foreach ($procName in $processesToCheck) { if (Get-ProcessStatus -ProcessName $procName -StopProcess:$false) { $anyProcessRunning = $true; Write-Log -Message "Detected running process before install: $procName" -Level INFO } }

        if ($anyProcessRunning -and $SkipUpdateIfAnyProcessIsRunning) {
            Write-Log -Message "Skipping installation because one or more Loxone processes are running and -SkipUpdateIfAnyProcessIsRunning was specified." -Level WARN
            $toastParamsCfgSkipRunningInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Skipped Install: Loxone process running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgSkipRunningInstall }
            $installationSkippedDueToRunningProcess = $true
            # Do not exit script here, allow potential MS update check later if needed? Or should we exit? For now, just skip install.
        } elseif ($CloseApplications) {
            if ($anyProcessRunning) { # Only close if actually running
                Write-Log -Message "[Config] Attempting to close running Loxone applications..." -Level INFO
                $toastParamsCfgCloseApps = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Closing Loxone Applications"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgCloseApps }
                foreach ($procName in $processesToCheck) { Get-ProcessStatus -ProcessName $procName -StopProcess:$true }
                Write-Log -Message "[Config] Close application requests sent." -Level INFO
                Start-Sleep -Seconds 2 # Give processes time to close
            } else { Write-Log -Message "[Config] No relevant Loxone processes found running. No need to close applications." -Level INFO }
        } elseif ($anyProcessRunning) { # Apps running, but CloseApps not specified
             Write-Log -Message "[Config] Loxone application(s) are running, but -CloseApplications was not specified. Installation might fail." -Level WARN
             $toastParamsCfgWarnRunning = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="WARN: Loxone process(es) running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
             if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgWarnRunning }
        }

        # --- Install (if not skipped) ---
        if (-not $installationSkippedDueToRunningProcess) {
            Write-Log -Message "[Config] Running Loxone Config installer..." -Level INFO
            $toastParamsCfgInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName=$configInstallStepName; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgInstall }

            $installArgs = "/$InstallMode"; Write-Log -Message "[Config] Executing: Start-Process -FilePath '$InstallerPath' -ArgumentList '$installArgs' -Wait -PassThru" -Level DEBUG
            $installProcess = Start-Process -FilePath $InstallerPath -ArgumentList $installArgs -Wait -PassThru -ErrorAction Stop
            Write-Log -Message "[Config] Loxone Config installer process exited with code: $($installProcess.ExitCode)" -Level INFO
            if ($installProcess.ExitCode -ne 0) { Write-Log -Message "[Config] Loxone Config installer returned non-zero exit code: $($installProcess.ExitCode). Installation may have failed." -Level WARN } # Don't throw, let verification handle it

            $script:CurrentWeight += Get-StepWeight -StepID 'InstallConfig' # Increment weight AFTER install attempt
            Write-Log -Message "[Config] Added weight for installation. Current weight: $($script:CurrentWeight)." -Level DEBUG

            # --- Verify Install (Part of Install Step) ---
            $verifyInstallStepName = "Verifying Loxone Config Installation"
             Write-Log -Message "[Config] $verifyInstallStepName..." -Level INFO
             $toastParamsCfgVerifyInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName=$verifyInstallStepName; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
             if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgVerifyInstall }

            $NewInstalledExePath = Get-LoxoneExePath; $NewInstalledVersion = if ($NewInstalledExePath -and (Test-Path $NewInstalledExePath)) { (Get-Item -Path $NewInstalledExePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion } else { "" }; $normalizedNewInstalled = Convert-VersionString $NewInstalledVersion
            if ($normalizedNewInstalled -eq $LatestVersion) {
                Write-Log -Message "[Config] Successfully updated Loxone Config to version $NewInstalledVersion." -Level INFO
                $anyUpdatePerformed = $true # Set flag: Config update performed
                $script:configUpdated = $true; $LoxoneConfigExePathForMSUpdate = $NewInstalledExePath; Write-Log -Message "[Config] Loxone Config path for MS update set to: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
                $script:CurrentWeight += Get-StepWeight -StepID 'VerifyConfig' # Add verification weight
                Write-Log -Message "[Config] Added weight for verification. Current weight: $($script:CurrentWeight)." -Level DEBUG

                $toastParamsCfgInstallComplete = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Loxone Config Update Complete (v$NewInstalledVersion)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgInstallComplete }
            } else {
                 $errorMessage = "Update verification failed! Expected version '$($LatestVersion)' but found '$($normalizedNewInstalled)' after installation."
                 Write-Log -Message "[Config] $errorMessage" -Level ERROR
                 $toastParamsCfgVerifyFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="FAILED: Config verification failed!"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                 if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsCfgVerifyFail }
                 throw $errorMessage
            }
        }
        # --- End Install ---

    } else { # Corresponds to if ($configUpdateNeeded)
         # Log message already written earlier when $configUpdateNeeded was determined
         # Write-Log -Message "[Config] Loxone Config is already up-to-date (Version: $($script:InitialInstalledVersion)). No update needed." -Level INFO # Redundant
         Write-Log -Message "[Config] Using initially determined installation path for potential MS update: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
         # $script:currentStep++ # Do NOT increment step counter when skipping
         # Remove toast update for skipped step
         # $toastParamsCfgSkip = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Loxone Config: Already up-to-date"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
         # Update-PersistentToast @toastParamsCfgSkip
         # Add weights for skipped steps
         $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig'
         $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
         $script:CurrentWeight += Get-StepWeight -StepID 'InstallConfig'
         $script:CurrentWeight += Get-StepWeight -StepID 'VerifyConfig'
         Write-Log -Message "[Config] Added weights for skipped steps. Current weight: $($script:CurrentWeight)." -Level DEBUG
    }

# --- Step: Update MSs ---
# Check if this step should run based on conditions calculated earlier
# Check if MSs exist in the list
$MSsExist = ($MSCount -gt 0)
$MSsUpdated = $false # Initialize to false before the check

if ($MSsExist) {
    # MSs exist, now check if an update is actually needed (Config OR any MS)
    if ($configUpdateNeeded -or $MSUpdatePotentiallyNeeded) {
        # --- PERFORM MS UPDATE ---
        $script:currentStep++
        $msUpdateStepName = "Updating MSs ($MSCount)"
        Write-Log -Message "[MS] $msUpdateStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
        Write-Log -Message "[MS] Reason: Config Update Needed = $configUpdateNeeded, MS Update Potentially Needed = $MSUpdatePotentiallyNeeded" -Level DEBUG

        # Update Toast for MS Update Start
        $toastParamsMSUpdateStart = @{
            StepNumber    = $script:currentStep
            TotalSteps    = $script:totalSteps
            StepName      = $msUpdateStepName
            CurrentWeight = $script:CurrentWeight # Pass current weight
            TotalWeight   = $script:TotalWeight
        }
        if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsMSUpdateStart }

        # Pass StepNumber and TotalSteps to Update-MS
        $MSsUpdated = Update-MS -DesiredVersion $LatestVersion -MSListPath $MSListPath -LogFile $global:LogFile -MaxLogFileSizeMB $MaxLogFileSizeMB -DebugMode:$DebugMode -ScriptSaveFolder $ScriptSaveFolder -StepNumber $script:currentStep -TotalSteps $script:totalSteps -SkipCertificateCheck:$SkipCertificateCheck
        # Add weight based on the number of servers AFTER the update attempt
        if (-not $script:ErrorOccurred) {
             $msWeightPerServer = 2 # Define weight per server directly here as it's only used in this block
             $msTotalWeight = $MSCount * $msWeightPerServer
             $script:CurrentWeight += $msTotalWeight
             Write-Log -Message "[MS] Added weight for MS updates. Current weight: $($script:CurrentWeight)." -Level DEBUG

             # Update Toast for MS Update Complete
             $toastParamsMSUpdateComplete = @{
                 StepNumber    = $script:currentStep
                 TotalSteps    = $script:totalSteps
                 StepName      = "MS Updates Complete"
                 CurrentWeight = $script:CurrentWeight
                 TotalWeight   = $script:TotalWeight
             }
             if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsMSUpdateComplete }
        }
        # --- END PERFORM MS UPDATE ---
    } else {
        # --- SKIP MS UPDATE (Already up-to-date) ---
        Write-Log -Message "[MS] Skipping MS update step because Loxone Config is up-to-date (`$configUpdateNeeded`=$false) AND all checked MSs match the target version (`$MSUpdatePotentiallyNeeded`=$false)." -Level INFO
        # Add weight for the skipped step
        $msWeightPerServer = 2 # Weight per server
        $msTotalWeight = $MSCount * $msWeightPerServer
        $script:CurrentWeight += $msTotalWeight
        Write-Log -Message "[MS] Added weight for skipped MS update step. Current weight: $($script:CurrentWeight)." -Level DEBUG
        # Optionally update toast to show skipped status
        $toastParamsMSSkip = @{
            StepNumber    = $script:currentStep # Use current step number before incrementing
            TotalSteps    = $script:totalSteps
            StepName      = "MSs: Already up-to-date"
            CurrentWeight = $script:CurrentWeight
            TotalWeight   = $script:TotalWeight
        }
        # --- END SKIP MS UPDATE ---
    }
} else { # Corresponds to if ($MSsExist) - i.e., no servers in list
     Write-Log -Message "[MS] Skipping MS update step because the MS list was empty or could not be read." -Level INFO
     # Add weight for skipped step (weight is 0 if count is 0, so this is safe)
     $msWeightPerServer = 2; $msTotalWeight = $MSCount * $msWeightPerServer; $script:CurrentWeight += $msTotalWeight
     Write-Log -Message "[MS] Added weight for skipped MS update step (due to no servers). Current weight: $($script:CurrentWeight)." -Level DEBUG
}
# --- Finalization Step ---
# Set the current step to the total for the finalization step
$script:currentStep = $script:totalSteps
$finalStepName = "Finalizing"
# Use the potentially incremented step number
Write-Log -Message "[Main] $finalStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
$anyUpdatePerformed = $script:configUpdated -or $MSsUpdated # Re-evaluate here
Write-Log -Message "Update Status - Config Updated: $($script:configUpdated), MSs Updated: $($MSsUpdated), Any Update Performed: $anyUpdatePerformed" -Level INFO

if (-not $script:ErrorOccurred) {
     $script:CurrentWeight += Get-StepWeight -StepID 'Finalize'
     # Ensure current weight doesn't exceed total, especially if steps were skipped
     $script:CurrentWeight = [Math]::Min($script:CurrentWeight, $script:TotalWeight)
     Write-Log -Message "[Main] Added weight for finalization. Final weight: $($script:CurrentWeight)/$($script:TotalWeight)." -Level DEBUG

     # Final Toast Update before showing the result toast
     $toastParamsFinal = @{
         StepNumber    = $script:currentStep
         TotalSteps    = $script:totalSteps
         StepName      = "Loxone Update Process Finished"
         CurrentWeight = $script:CurrentWeight
         TotalWeight   = $script:TotalWeight
     }
     if ($script:IsInteractiveRun) { Update-PersistentToast @toastParamsFinal }
}
# --- End Finalization Step ---

} # --- End of Main Try Block ---
catch {
    $script:ErrorOccurred = $true
    # Safely get error details, checking for null InvocationInfo
    $script:LastErrorLine = if ($_.InvocationInfo) { try { $_.InvocationInfo.ScriptLineNumber } catch { 0 } } else { 0 }
    $exceptionMessage = try { $_ | Out-String } catch { "Could not retrieve full error object." }
    $commandName = if ($_.InvocationInfo) { try { $_.InvocationInfo.MyCommand.ToString() -as [string] } catch { "N/A" } } else { "N/A" }
    $scriptName = if ($_.InvocationInfo) { try { $_.InvocationInfo.ScriptName -as [string] } catch { "N/A" } } else { "N/A" }
    $lineContent = if ($_.InvocationInfo) { try { $_.InvocationInfo.Line -as [string] } catch { "N/A" } } else { "N/A" }
    $errorMessage = "An unexpected error occurred during the update process: $exceptionMessage"; $errorDetails = @"
Error: $exceptionMessage
Script: $scriptName
Line: $script:LastErrorLine
Command: $commandName
Line Content: $lineContent
"@; Write-Log -Message $errorMessage -Level ERROR; Write-Log -Message "--- Error Details ---`n$errorDetails`n--- End Error Details ---" -Level ERROR
    if ($_.ScriptStackTrace) { $exceptionStackTrace = try { $_.ScriptStackTrace -as [string] } catch { "Could not retrieve stack trace." }; Write-Log -Message "--- StackTrace ---`n$exceptionStackTrace`n--- End StackTrace ---" -Level ERROR }
    # Use the new final status toast function for errors (no workaround needed)
    $finalErrorMsg = "FAILED: An unexpected error occurred. Check logs. (Line: $script:LastErrorLine)"
    # Rotate log before showing toast and pass the archive path
    $logPathToShowOnError = $null
    if ($global:LogFile) { try { $logPathToShowOnError = Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount 24 -ErrorAction Stop } catch { Write-Log -Level WARN -Message "Error during log rotation in CATCH block: $($_.Exception.Message)" } }
    Show-FinalStatusToast -StatusMessage $finalErrorMsg -Success:$false -LogFileToShow $logPathToShowOnError
    # Add a small delay to allow the toast notification process to potentially complete
    Write-Log -Level Debug -Message "Pausing briefly after failure toast update..."
    Start-Sleep -Seconds 3
    exit 1
} finally {
    Write-Log -Level DEBUG -Message "Executing Finally block."
# Log rotation moved to just before final toast notification calls in exit handling

    # if ($script:ErrorOccurred -and -not (Test-ScheduledTask)) { Write-Host "`n--- SCRIPT PAUSED DUE TO ERROR (Finally Block) ---" -ForegroundColor Yellow; Write-Host "An error occurred during script execution (Last known error line: $script:LastErrorLine)." -ForegroundColor Yellow; Write-Host "Check the log file '$($global:LogFile)' for details." -ForegroundColor Yellow } # Commented out: Write-Host in finally block might cause issues in non-interactive sessions. Error is logged anyway.
    Write-Log -Message "Attempting final download job cleanup..." -Level DEBUG; Write-Log -Message "Final download job cleanup finished." -Level DEBUG
    Exit-Function # Exit the main script scope logging
} # Closing brace for the finally block

# --- Final Exit Code Handling ---

# Always attempt final notification; toast function handles context
Write-Log -Message "Preparing final status notification." -Level DEBUG

# --- Final Log Rotation (Moved Here) ---
$logPathToShow = $null
if ($global:LogFile) {
    Write-Log -Level DEBUG -Message "Attempting final log rotation before success/summary toast..."
    try {
        $maxArchives = 24 # Default archive count
        if ($PSBoundParameters.ContainsKey('MaxLogFileSizeMB')) { Write-Log -Level DEBUG -Message "Using default MaxArchiveCount: $maxArchives" }
        $logPathToShow = Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount $maxArchives -ErrorAction Stop
        Write-Log -Level DEBUG -Message "Log rotation returned archive path: '$($logPathToShow)'"
    } catch {
        Write-Log -Level WARN -Message "Error during final log rotation: $($_.Exception.Message). Archive path might be null."
    }
} else {
    Write-Log -Level WARN -Message "Skipping final log rotation as Global:LogFile is not set."
}
# --- End Final Log Rotation ---

# --- Construct Final Summary Message ---
Write-Log -Message "Constructing final summary notification message." -Level INFO
$summaryLines = @()

# Config Status
$configVersionString = if ($script:InitialInstalledVersion) { $script:InitialInstalledVersion } else { "N/A" }
if ($script:configUpdated) {
    $summaryLines += "Config ${Channel}: Updated $NewInstalledVersion"
} elseif ($script:InitialInstalledVersion -and $LatestVersion -eq (Convert-VersionString $script:InitialInstalledVersion)) {
    $summaryLines += "Config ${Channel}: Up-to-date $configVersionString"
} elseif ($script:InitialInstalledVersion) {
    $summaryLines += "Config ${Channel}: Update skipped $LatestVersion (Installed: $configVersionString)"
} else {
    $summaryLines += "Config ${Channel}: Not Found"
}

# App Status
if ($UpdateLoxoneApp) {
    $appVersionString = if ($appDetails -and -not $appDetails.Error) { $appDetails.FileVersion } else { "N/A" }
    if ($script:appUpdated) {
        $summaryLines += "App ${selectedAppChannelName}: Updated $newAppDetails.FileVersion"
    } elseif ($appDetails -and -not $appDetails.Error -and -not $appUpdateNeeded) { # Already up-to-date
        $summaryLines += "App ${selectedAppChannelName}: Up-to-date $appVersionString"
    } elseif ($appUpdateNeeded) { # Update was needed but failed or skipped
        $summaryLines += "App ${selectedAppChannelName}: Update failed/skipped $latestLoxWindowsVersion (Installed: $appVersionString)"
    } elseif ($latestLoxWindowsVersion) { # App not found initially or error checking
        $summaryLines += "App ${selectedAppChannelName}: Not Found/Error checking"
    } else { # XML details unavailable
        $summaryLines += "App ${selectedAppChannelName}: Check skipped (details unavailable)"
    }
} else {
    $summaryLines += "App: Check disabled"
}

# MS Status (Detailed)
if (Test-Path $MSListPath) {
    if ($MSVersions.Count -gt 0) { # Check if the results hashtable has entries instead of relying on $miniserverCount
        # Iterate through the results of the initial check stored in $miniserverVersions
        foreach ($msHost in ($MSVersions.Keys | Sort-Object)) {
            $msStatus = $MSVersions[$msHost]
            $msLine = "MS ${Channel} ${msHost}: " # Add Channel, ensure correct interpolation with {}
            if ($msStatus -eq "Error Connecting" -or $msStatus -eq "Error Parsing XML") {
                $msLine += $msStatus
            } elseif ((Convert-VersionString $msStatus) -eq $LatestVersion) {
                $msLine += "Up-to-date $msStatus"
            } else {
                $msLine += "Needs Update (Current: $msStatus, Target: $LatestVersion)"
            }
            # Indicate if the update function was actually run
            if ($MSsUpdated) { # Use the correct variable $MSsUpdated
                $msLine += " (Update Attempted)"
            }
            $summaryLines += $msLine
        }
    } else {
        $summaryLines += "MS ${Channel}: List empty or check failed" # Clarify message with {}
    }
} else {
    $summaryLines += "MS: List not found"
}

# Sort the summary lines alphabetically before joining
$summaryLines = $summaryLines | Sort-Object

$finalMessage = $summaryLines -join "`n"
$finalSuccess = (-not $script:ErrorOccurred)

# Ensure weight is maxed out on success
if ($finalSuccess -and $script:CurrentWeight -lt $script:TotalWeight) {
    $script:CurrentWeight = $script:TotalWeight
}

# --- Log Final Summary ---
Write-Log -Message "Final Summary:`n$finalMessage" -Level Info

# --- Show Final Toast (Conditional) ---
# Show toast if:
# 1. An error occurred OR
# 2. Running interactively OR
# 3. Running non-interactively AND an update was performed
$isInteractiveEnv = [Environment]::UserInteractive
Write-Log -Message "Toast Conditions Check: ErrorOccurred=$($script:ErrorOccurred), IsInteractiveEnv=$isInteractiveEnv, AnyUpdatePerformed=$anyUpdatePerformed" -Level DEBUG
if ($script:ErrorOccurred -or $isInteractiveEnv -or (-not $isInteractiveEnv -and $anyUpdatePerformed)) {
    Write-Log -Message "Showing final status toast based on conditions." -Level INFO
    Show-FinalStatusToast -StatusMessage $finalMessage -Success $finalSuccess -LogFileToShow $logPathToShow
} else {
    Write-Log -Message "Skipping final status toast (Non-interactive, no error, no update performed)." -Level INFO
}

# --- Determine Exit Code ---
if ($script:ErrorOccurred) {
    Write-Log -Message "Script finished with errors. Exit Code: 1" -Level ERROR
    Exit 1
} else {
    Write-Log -Level INFO -Message "Script finished successfully. Exit Code: 0"
    Exit 0
}
# End of script
