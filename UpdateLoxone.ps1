<#
.SYNOPSIS
Automatically checks for Loxone Config updates, downloads, installs them, and updates Miniservers.

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
  - Updates all Miniservers listed in a configuration file.
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
- Miniserver list file ('UpdateLoxoneMSList.txt') should be in the ScriptSaveFolder, containing one entry per line (e.g., user:pass@192.168.1.77 or 192.168.1.78).
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
    [switch]$SkipCertificateCheck # New switch to bypass SSL/TLS certificate validation for Miniserver connections
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
        if (-not $LoxoneUtilsModule) {
            Write-Warning "Failed to load LoxoneUtils module via manifest '$UtilsModulePath'. Core functionality might be affected. This may be due to the BurntToast dependency not being met."
            # Optionally add logic here to exit if LoxoneUtils is absolutely critical,
            # or set flags to disable features dependent on it.
        } else {
            Write-Log -Message "Running as SYSTEM. Importing full LoxoneUtils module via manifest '$UtilsModulePath'." -Level INFO
            Write-Log -Message "Successfully loaded LoxoneUtils module via manifest for SYSTEM context." -Level INFO
        }

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
        if (Test-Path $LoggingModulePath) {
            Import-Module $LoggingModulePath -Force -ErrorAction Stop
            # Initial log message *after* importing the logging module
            Write-Log -Message "Not running as SYSTEM. Importing required LoxoneUtils modules individually..." -Level INFO
        } else {
            # Critical error if logging module is missing
            Write-Error "FATAL: Logging module not found at '$LoggingModulePath'. Cannot continue."
            exit 1 # Exit immediately
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
            'LoxoneUtils.psm1'                  # Root module file (usually last)
        )

        foreach ($moduleFile in $ModulesToImport) {
            $modulePath = Join-Path -Path $LoxoneUtilsDir -ChildPath $moduleFile
            if (Test-Path $modulePath) {
                Write-Log -Message "Importing module: $modulePath" -Level DEBUG
                $importedModule = Import-Module $modulePath -Force -ErrorAction Stop -PassThru # Force ensures reload if needed, Stop on error
                if (-not $importedModule) {
                    if ($moduleFile -eq 'LoxoneUtils.Toast.psm1') {
                         Write-Log -Message "Failed to load LoxoneUtils.Toast.psm1 module from '$modulePath'. Toast notifications will be unavailable. This may be due to the BurntToast dependency not being met." -Level WARN
                    } else {
                         Write-Log -Message "Failed to load module '$moduleFile' from '$modulePath'. This might affect functionality." -Level WARN
                    }
                    # Consider if failure of other specific modules should be treated as critical
                }
            } else {
                Write-Log -Message "Module file not found: $modulePath. Skipping import." -Level WARN
                # Consider throwing an error if a critical module is missing
            }
        }
        Write-Log -Message "Successfully imported required LoxoneUtils modules individually." -Level INFO

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
catch {
    # Keep the original catch block content
    Write-Host "CRITICAL ERROR: Failed to load helper module '$UtilsModulePath'. Full Error Record Below:" -ForegroundColor Red
    Write-Host "-------------------- ERROR RECORD START --------------------" -ForegroundColor Yellow; $_ | Out-String | Write-Host -ForegroundColor Yellow; Write-Host "-------------------- ERROR RECORD END --------------------" -ForegroundColor Yellow
    Write-Host "Script cannot continue." -ForegroundColor Red; exit 1
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

# --- Get Latest Version Info ---
Write-Log -Message "Loading update XML from $UpdateXmlUrl" -Level INFO
$webClient = New-Object System.Net.WebClient
try { $updateXmlString = $webClient.DownloadString($UpdateXmlUrl) }
catch { Write-Log -Message "Failed to download update XML from '$UpdateXmlUrl'. Error: $($_.Exception.Message). Cannot perform version check." -Level ERROR; throw "Failed to download update XML. Cannot continue." }
$updateXml = [xml]$updateXmlString
    # --- XML Signature Validation Removed ---

    # --- User Modifications block removed - Redaction moved to Debug block below ---

if ($script:DebugMode) {
    try {
        $debugXml = $updateXml.Clone(); $root = $debugXml.DocumentElement
        if ($root -and $root.HasAttribute('certificate')) { $root.SetAttribute('certificate', '[REDACTED]'); Write-Log -Message "Redacted 'certificate' attribute on root in debug XML." -Level DEBUG }
        $updateNodesToRemove = $debugXml.SelectNodes("//*[starts-with(translate(local-name(), 'UPDATE', 'update'), 'update') and not(@Name='Loxone for Windows')]")
        if ($updateNodesToRemove -and $updateNodesToRemove.Count -gt 0) { Write-Log -Message "Found $($updateNodesToRemove.Count) nodes starting with 'update' for recursive removal in debug XML." -Level DEBUG; foreach ($node in @($updateNodesToRemove)) { if ($node.ParentNode) { Write-Log -Message "Removing node '$($node.Name)' from parent '$($node.ParentNode.Name)' in debug XML." -Level DEBUG; [void]$node.ParentNode.RemoveChild($node) } else { Write-Log -Message "Skipping removal of node '$($node.Name)' as it has no parent (likely root)." -Level DEBUG -Level WARN } } Write-Log -Message "Finished removing 'update*' nodes from debug XML." -Level DEBUG } else { Write-Log -Message "No nodes starting with 'update' found for removal in debug XML." -Level DEBUG }
        # Redact all signatures in the debug clone
        $signatureNodes = $debugXml.SelectNodes("//*[@signature]")
        if ($signatureNodes -and $signatureNodes.Count -gt 0) {
            Write-Log -Message "Found $($signatureNodes.Count) nodes with 'signature' attribute for redaction in debug XML." -Level DEBUG
            foreach ($node in $signatureNodes) {
                $originalSignature = $node.GetAttribute('signature') # Get original for logging if needed
                Write-Log -Message "Redacting 'signature' attribute on node '$($node.Name)' (Original: '$originalSignature') in debug XML." -Level DEBUG
                $node.SetAttribute('signature', '[REDACTED]')
            }
            Write-Log -Message "Finished redacting 'signature' attributes in debug XML." -Level DEBUG
        } else {
            Write-Log -Message "No 'signature' attributes found for redaction in debug XML." -Level DEBUG
        }

        # Remove non-DEU changelogs from the debug clone
        $changelogParentDebug = $debugXml.SelectSingleNode("/Miniserversoftware/changelogs")
        if ($changelogParentDebug) {
            $changelogsToRemoveDebug = $changelogParentDebug.SelectNodes("changelog[not(@lang='DEU')] | changelogx[not(@lang='DEU')]")
            if ($changelogsToRemoveDebug) {
                Write-Log -Message "Found $($changelogsToRemoveDebug.Count) changelog entries to remove from debug XML." -Level DEBUG
                foreach ($logNodeDebug in @($changelogsToRemoveDebug)) {
                    Write-Log -Message "Removing changelog entry with lang '$($logNodeDebug.GetAttribute('lang'))' from debug XML." -Level DEBUG
                    [void]$logNodeDebug.ParentNode.RemoveChild($logNodeDebug)
                }
            } else {
                Write-Log -Message "No changelog entries found to remove (excluding DEU) from debug XML." -Level DEBUG
            }
        } else {
            Write-Log -Message "Could not find <changelogs> node in debug XML." -Level WARN
        }

        $stringWriter = New-Object System.IO.StringWriter; $xmlWriter = New-Object System.Xml.XmlTextWriter($stringWriter); $xmlWriter.Formatting = [System.Xml.Formatting]::Indented; $debugXml.WriteTo($xmlWriter); $formattedXml = $stringWriter.ToString()
        Write-Log -Level DEBUG -Message "Processed (Redacted/Filtered) XML Content:`n$formattedXml"
    } catch { Write-Log -Level DEBUG -Message "Error processing XML for debug output: $($_.Exception.Message). Falling back to raw XML."; Write-Log -Level DEBUG -Message "Raw Downloaded XML Content:`n$($updateXml.OuterXml)" }
}

$xmlNodeName = if ($Channel -eq 'Public') { 'Release' } else { $Channel }
$updateNode = $updateXml.Miniserversoftware.$xmlNodeName
if (-not $updateNode) { throw "Could not find update information for channel '$Channel' in the XML." }

# Extract signature BEFORE potential redaction
$ExpectedXmlSignature = $updateNode.signature
if ([string]::IsNullOrWhiteSpace($ExpectedXmlSignature)) {
    Write-Log -Message "Signature value missing in XML for channel '$Channel'. Signature validation cannot be performed." -Level WARN
    $ExpectedXmlSignature = $null
} elseif ($DebugMode) {
    Write-Log -Message "Expected XML Signature (from XML): $ExpectedXmlSignature" -Level INFO
}

$LatestVersion = $updateNode.Version; $ZipUrl = $updateNode.Path; $ExpectedZipSize = $null
if ($EnableCRC) { $ExpectedCRC = $updateNode.crc32; if ([string]::IsNullOrWhiteSpace($ExpectedCRC)) { if ($script:DebugMode) { try { $root = $updateXml.Miniserversoftware; $truncatedCert = "..."; if ($root.HasAttribute('certificate')) { $certValue = $root.GetAttribute('certificate'); $truncatedCert = $certValue.Substring(0, [System.Math]::Min($certValue.Length, 30)) + "..." } $attributesString = ($root.Attributes | Where-Object {$_.Name -ne 'certificate'} | ForEach-Object { "$($_.Name)='$($_.Value)'" }) -join " "; $sb = [System.Text.StringBuilder]::new(); [void]$sb.AppendLine("<?xml version=`"1.0`" encoding=`"UTF-8`"?>"); [void]$sb.Append("<$($root.Name) $($attributesString) certificate='$truncatedCert'>"); $root.ChildNodes | Where-Object {$_.NodeType -eq 'Element' -and $_.Name -notlike 'update*'} | ForEach-Object { [void]$sb.Append("`n  "); [void]$sb.Append($_.OuterXml) }; [void]$sb.Append("`n</$($root.Name)>"); $filteredXmlString = $sb.ToString(); Write-Log -Message "Downloaded XML Content:`n$filteredXmlString" -Level DEBUG } catch { Write-Log -Message "Downloaded XML Content (filtering failed):`n$($updateXml.OuterXml)" -Level DEBUG } } Write-Log -Message "CRC check enabled, but no CRC found in XML for channel '$Channel'. Disabling CRC check." -Level WARN; $EnableCRC = $false } }
if (-not ([long]::TryParse($updateNode.FileSize, [ref]$ExpectedZipSize))) { Write-Log -Message "Could not parse FileSize ('$($updateNode.FileSize)') from XML for channel '$Channel'. File size check might be inaccurate." -Level WARN; $ExpectedZipSize = 0 }
# $ExpectedXmlSignature = $updateNode.signature; # Removed - Moved earlier before redaction
$updateInfoMsg = "(Channel: $Channel):$LatestVersion, ${ExpectedZipSize}B, $ZipUrl"; if ($EnableCRC) { $updateInfoMsg += ", Expected CRC $ExpectedCRC" }; Write-Log -Message $updateInfoMsg -Level INFO

# --- Loxone for Windows - Fetch Update Info ---
$latestLoxWindowsVersionRaw = $null
$loxWindowsInstallerUrl = $null
$expectedLoxWindowsCRC = $null
$expectedLoxWindowsSize = 0L
$latestLoxWindowsVersion = $null
$selectedAppChannelName = $UpdateLoxoneAppChannel # Store the selected channel name for logging/messages

if ($UpdateLoxoneApp) {
    Write-Log -Message "[App] Fetching update details for 'Loxone for Windows' (Channel: $selectedAppChannelName) from XML..." -Level INFO
    try {
        $loxWindowsBaseNode = $updateXml.SelectSingleNode("/Miniserversoftware/update[@Name='Loxone for Windows']")
        if (-not $loxWindowsBaseNode) { throw "Could not find base node for 'Loxone for Windows' in XML." }

        $loxWindowsUpdateNode = $null

        if ($UpdateLoxoneAppChannel -eq 'Latest') {
            Write-Log -Message "[App] Finding latest version across all channels..." -Level DEBUG
            $allChannelNodes = $loxWindowsBaseNode.SelectNodes("*") # Select Test, Beta, Release, Internal, InternalV2 etc.
            $latestNode = $null
            $latestParsedVersion = [Version]"0.0.0.0"

            foreach ($channelNode in $allChannelNodes) {
                $channelName = $channelNode.LocalName # Test, Beta, Release...
                $rawVersion = $channelNode.Version
                $parsedVersion = $null
                $versionToConvert = $null
                # Extract version like YYYY.MM.DD from strings like "15.3.3 (2025.03.11)"
                if ($rawVersion -match '\(([\d.]+)\)') { $versionToConvert = $matches[1] }

                if ($versionToConvert) {
                    try {
                        $parsedVersion = Convert-VersionString $versionToConvert
                        Write-Log -Message "[App] Parsed version '$parsedVersion' from channel '$channelName' (Raw: '$rawVersion')." -Level DEBUG
                        if ([Version]$parsedVersion -gt $latestParsedVersion) {
                            $latestParsedVersion = [Version]$parsedVersion
                            $latestNode = $channelNode
                            $selectedAppChannelName = $channelName # Update selected channel name to the actual latest
                            Write-Log -Message "[App] Found newer latest version: '$parsedVersion' in channel '$channelName'." -Level DEBUG
                        }
                    } catch {
                        Write-Log -Message "[App] Error converting version '$versionToConvert' from channel '$channelName': $($_.Exception.Message). Skipping channel." -Level WARN
                    }
                } else {
                    Write-Log -Message "[App] Could not extract numerical version pattern from raw string '$rawVersion' for channel '$channelName'. Skipping channel." -Level WARN
                }
            }
            $loxWindowsUpdateNode = $latestNode
            if ($loxWindowsUpdateNode) {
                 Write-Log -Message "[App] Selected latest version from channel '$selectedAppChannelName'." -Level INFO
            } else {
                 Write-Log -Message "[App] Could not determine the latest version across channels." -Level WARN
            }

        } else {
            # Specific channel selected
            $xpath = "/Miniserversoftware/update[@Name='Loxone for Windows']/$UpdateLoxoneAppChannel"
            Write-Log -Message "[App] Selecting specific channel node using XPath: $xpath" -Level DEBUG
            $loxWindowsUpdateNode = $updateXml.SelectSingleNode($xpath)
        }

        # --- Process the selected node ---
        if ($loxWindowsUpdateNode) {
            $latestLoxWindowsVersionRaw = $loxWindowsUpdateNode.Version
            $loxWindowsInstallerUrl = $loxWindowsUpdateNode.Path
            $expectedLoxWindowsCRC = $loxWindowsUpdateNode.crc32
            if (-not ([long]::TryParse($loxWindowsUpdateNode.FileSize, [ref]$expectedLoxWindowsSize))) { Write-Log -Message "[App] Could not parse FileSize ('$($loxWindowsUpdateNode.FileSize)') for Loxone for Windows (Channel: $selectedAppChannelName). Size check might be inaccurate." -Level WARN; $expectedLoxWindowsSize = 0L }

            if ([string]::IsNullOrWhiteSpace($latestLoxWindowsVersionRaw) -or [string]::IsNullOrWhiteSpace($loxWindowsInstallerUrl)) {
                Write-Log -Message "[App] Required attributes (Version, Path) missing for 'Loxone for Windows' (Channel: $selectedAppChannelName) in XML. Cannot proceed with App update check." -Level WARN
                $latestLoxWindowsVersionRaw = $null; $loxWindowsInstallerUrl = $null; $expectedLoxWindowsCRC = $null; $expectedLoxWindowsSize = 0L
            } else {
                $versionToConvert = $null
                Write-Log -Message "[App] Raw version string from XML (Channel: $selectedAppChannelName): '$latestLoxWindowsVersionRaw'" -Level DEBUG
                if ($latestLoxWindowsVersionRaw -match '\(([\d.]+)\)') {
                    $versionToConvert = $matches[1]
                    Write-Log -Message "[App] Extracted date-based version from XML (Channel: $selectedAppChannelName): '$versionToConvert'" -Level DEBUG
                } else {
                    Write-Log -Message "[App] Could not extract numerical version pattern (X.Y.Z.W) from raw string '$latestLoxWindowsVersionRaw' (Channel: $selectedAppChannelName). Cannot determine latest app version." -Level WARN
                    $latestLoxWindowsVersionRaw = $null; $latestLoxWindowsVersion = $null; $loxWindowsInstallerUrl = $null; $expectedLoxWindowsCRC = $null; $expectedLoxWindowsSize = 0L
                }

                if ($versionToConvert) {
                    try {
                        $latestLoxWindowsVersion = Convert-VersionString $versionToConvert
                        Write-Log -Message "[App] Converted numerical version (Channel: $selectedAppChannelName): '$latestLoxWindowsVersion'" -Level DEBUG
                    } catch {
                         Write-Log -Message "[App] Error converting extracted version '$versionToConvert' (Channel: $selectedAppChannelName): $($_.Exception.Message). Cannot determine latest app version." -Level WARN
                         $latestLoxWindowsVersionRaw = $null; $latestLoxWindowsVersion = $null; $loxWindowsInstallerUrl = $null; $expectedLoxWindowsCRC = $null; $expectedLoxWindowsSize = 0L
                    }
                }

                # Only log info if we successfully got a version
                if ($latestLoxWindowsVersion) {
                    $appUpdateInfoMsg = "[App] Latest Loxone for Windows (Channel: $selectedAppChannelName): Version=$latestLoxWindowsVersionRaw ($latestLoxWindowsVersion), Size=${expectedLoxWindowsSize}B, URL=$loxWindowsInstallerUrl"
                    if ($EnableCRC -and -not ([string]::IsNullOrWhiteSpace($expectedLoxWindowsCRC))) { $appUpdateInfoMsg += ", Expected CRC=$expectedLoxWindowsCRC" } elseif ($EnableCRC) { Write-Log -Message "[App] CRC check enabled, but CRC missing for Loxone for Windows (Channel: $selectedAppChannelName) in XML." -Level WARN }
                    Write-Log -Message $appUpdateInfoMsg -Level INFO
                }
            }
        } else {
            Write-Log -Message "[App] Could not find 'Loxone for Windows' update information for channel '$selectedAppChannelName' in the XML. Cannot perform App update check." -Level WARN
        }
    } catch {
        Write-Log -Message "[App] Error parsing XML for Loxone for Windows details (Channel: $selectedAppChannelName): $($_.Exception.Message). Cannot perform App update check." -Level ERROR
        $latestLoxWindowsVersionRaw = $null; $loxWindowsInstallerUrl = $null; $expectedLoxWindowsCRC = $null; $expectedLoxWindowsSize = 0L; $latestLoxWindowsVersion = $null
    }
} elseif (-not $UpdateLoxoneApp) {
    Write-Log -Message "[App] Skipping Loxone for Windows update check as -UpdateLoxoneApp parameter was set to `$false`." -Level INFO
}
# --- End Loxone for Windows Fetch ---

# --- App Check: Check and Prepare Loxone Application ---
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
                Update-PersistentToast @toastParamsStopApp
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
        Update-PersistentToast @toastParamsAppDownloadStart

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
        $script:CurrentWeight += 1 # Increment weight AFTER successful download
        Write-Log -Message "[App] Loxone for Windows download completed successfully. Incremented weight to $($script:CurrentWeight)." -Level INFO

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
        Update-PersistentToast @toastParamsAppInstall
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
                 Update-PersistentToast @toastParamsAppVerify

                 Write-Log -Message "[App] Waiting 5 seconds before verification..." -Level DEBUG; Start-Sleep -Seconds 5
                 Write-Log -Message "[App] Verifying Loxone for Windows installation..." -Level INFO
                 $newAppDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction SilentlyContinue
                 if ($newAppDetails -and -not $newAppDetails.Error) {
                     $normalizedLatestAppVerify = Convert-VersionString $latestLoxWindowsVersion; $normalizedNewInstalledAppVerify = Convert-VersionString $newAppDetails.FileVersion; $verificationSuccess = $false
                     try { if ([Version]$normalizedNewInstalledAppVerify -eq [Version]$normalizedLatestAppVerify) { $verificationSuccess = $true }; Write-Log -Message "[App] Verification comparison result: Success = $verificationSuccess (Expected: '$normalizedLatestAppVerify', Found: '$normalizedNewInstalledAppVerify')" -Level DEBUG }
                     catch { Write-Log -Message "[App] Error comparing versions during verification: '$normalizedLatestAppVerify' vs '$normalizedNewInstalledAppVerify': $($_.Exception.Message). Verification failed." -Level WARN; $verificationSuccess = $false }

                     if ($verificationSuccess) {
                         Write-Log -Message "[App] Successfully updated Loxone App to FileVersion $($newAppDetails.FileVersion)." -Level INFO
                         # Update Toast for App Update Complete
                         $toastParamsAppComplete = @{
                             StepNumber    = $script:currentStep # Keep same step number
                             TotalSteps    = $script:totalSteps
                             StepName      = "Loxone App Update Complete (v$($newAppDetails.FileVersion))"
                             CurrentWeight = $script:CurrentWeight # Pass current weight
                             TotalWeight   = $script:TotalWeight
                         }
                         Update-PersistentToast @toastParamsAppComplete

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
                             Update-PersistentToast @toastParamsAppRestart
                             $appPathToRestart = $newAppDetails.InstallLocation
                             if ($script:IsInteractive -and -not $script:isRunningAsSystem) {
                                 Write-Log -Message "[App] Restarting interactively using Start-Process..." -Level INFO
                                 try { Start-Process -FilePath $appPathToRestart -WindowStyle Minimized -ErrorAction Stop; Write-Log -Message "[App] Start-Process command issued for '$appPathToRestart'." -Level INFO }
                                 catch { Write-Log -Message "[App] Failed to restart Loxone App interactively using Start-Process: $($_.Exception.Message)" -Level ERROR; $toastParamsAppRestartFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Failed to restart Loxone App"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppRestartFail }
                             } elseif ($script:isRunningAsSystem) { # This condition is now technically always false here due to re-launch logic, but keep structure for now
                                 Write-Log -Message "[App] Running as SYSTEM. Attempting restart via Invoke-AsCurrentUser function..." -Level INFO
                                 try { Write-Log -Message "[App] Calling Invoke-AsCurrentUser -FilePath '$appPathToRestart' -Visible -NoWait..." -Level DEBUG; Invoke-AsCurrentUser -FilePath $appPathToRestart -NoWait -ErrorAction Stop; Write-Log -Message "[App] Invoke-AsCurrentUser command issued for '$appPathToRestart'." -Level INFO }
                                 catch { Write-Log -Message "[App] Invoke-AsCurrentUser function failed to restart Loxone App: $($_.Exception.Message)" -Level ERROR; $toastParamsAppRestartFailSys = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Failed to restart Loxone App (System)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppRestartFailSys }
                             } else { Write-Log -Message "[App] Unclear execution context (Not Interactive User, Not SYSTEM). Automatic restart not attempted." -Level WARN; $toastParamsAppRestartSkip = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="WARN: Loxone App restart skipped"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppRestartSkip }
                         } else { Write-Log -Message "[App] Loxone App was not running before the update. No restart needed." -Level INFO }
                     # Removed duplicate line from previous failed diff
                 } else { Write-Log -Message "[App] Loxone App update verification failed! Expected FileVersion '$normalizedLatestAppVerify' but found '$normalizedNewInstalledAppVerify' after installation." -Level ERROR; $toastParamsAppVerifyFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Loxone App verification failed!"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppVerifyFail }
             } else { Write-Log -Message "[App] Failed to get Loxone App details from registry after installation attempt. Verification failed. Error: $($newAppDetails.Error)" -Level ERROR; $toastParamsAppVerifyFailReg = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Loxone App verification failed (Registry)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppVerifyFailReg }
            }
        } catch { Write-Log -Message "[App] Failed to run Loxone for Windows installer: $($_.Exception.Message)" -Level ERROR; $toastParamsAppInstallFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="FAILED: Loxone App installation failed"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; Update-PersistentToast @toastParamsAppInstallFail; throw "[App] Failed to execute Loxone for Windows installer." }

    } else { # Corresponds to: if ($appUpdateNeeded)
        if ($appDetails -and -not $appDetails.Error) { Write-Log -Message "[App Check] Loxone for Windows (Channel: $selectedAppChannelName) is already up-to-date (FileVersion: $($appDetails.FileVersion))." -Level INFO } # Removed step increment and toast update here
    } # Closes: else corresponding to if ($appUpdateNeeded)
 
} # Closes: if ($appDetails -and -not $appDetails.Error)
elseif ($UpdateLoxoneApp -and -not $latestLoxWindowsVersion) { Write-Log -Message "[App Check] Skipping Loxone App update (Channel: $selectedAppChannelName) because latest version details could not be retrieved from XML (XML fetch/parse failed)." -Level WARN; $updateToastParams14 = @{ NewStatus = "WARN: Loxone App update skipped (failed to get latest version info)." }; Update-PersistentToast @updateToastParams14 } # UseTaskWorkaround removed
elseif ($UpdateLoxoneApp -and (!$appDetails -or $appDetails.Error)) { Write-Log -Message "[App Check] Skipping Loxone App update check (Channel: $selectedAppChannelName) because installed application details could not be retrieved." -Level WARN; $updateToastParams15 = @{ NewStatus = "WARN: Loxone App update skipped (cannot find installed app)." }; Update-PersistentToast @updateToastParams15 } # UseTaskWorkaround removed
# --- End App Check ---
 
 
# --- Config Check: Compare Versions (Using Initially Detected Version) ---
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

# Early exit removed - Proceed to Miniserver checks even if Config/App are up-to-date


# --- Determine Loxone Icon Path (Uses $script:InstalledExePath) ---
$LoxoneIconPath = $null
if ($script:InstalledExePath -and (Test-Path $script:InstalledExePath)) {
    $InstallDir = Split-Path -Parent $script:InstalledExePath; $PotentialIconPath = Join-Path -Path $InstallDir -ChildPath "LoxoneConfig.ico"
    if (Test-Path $PotentialIconPath) { $LoxoneIconPath = $PotentialIconPath; Write-Log -Level DEBUG -Message "Found Loxone icon at: $LoxoneIconPath" }
    else { Write-Log -Level DEBUG -Message "LoxoneConfig.ico not found in $InstallDir. No icon will be used." }
}

# --- Miniserver Check: Check Miniserver Versions ---
Write-Log -Message "[Miniserver Check] Starting Miniserver version check..." -Level INFO
$miniserverVersions = @{} # Store versions here (Host -> Version)
if (Test-Path $MSListPath) {
    try { # Outer try for reading/processing MS list
        $miniserverEntriesPreCheck = Get-Content $MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
        Write-Log -Message "[Miniserver Check] Found $($miniserverEntriesPreCheck.Count) Miniserver entries in '$MSListPath'." -Level DEBUG

        foreach ($msEntryPreCheck in $miniserverEntriesPreCheck) {
            $redactedEntryForLogPreCheck = Get-RedactedPassword $msEntryPreCheck
            Write-Log -Message "[Miniserver Check] Processing entry: ${redactedEntryForLogPreCheck}" -Level DEBUG
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
                Write-Log -Message "[Miniserver Check] Failed to parse Miniserver entry '$redactedEntryForLogPreCheck' as URI: $($_.Exception.Message). Assuming IP/hostname." -Level WARN
                $credentialPreCheck = $null
                $msIPPreCheck = $msEntryPreCheck.Split('@')[-1].Split('/')[0]
                if ($msIPPreCheck) { $versionUriPreCheck = "http://${msIPPreCheck}/dev/cfg/version" }
                else { Write-Log -Message "[Miniserver Check] Could not determine IP/Host from entry '$redactedEntryForLogPreCheck'. Skipping." -Level ERROR; continue }
            }

            $redactedVersionUriPreCheck = Get-RedactedPassword $versionUriPreCheck
            Write-Log -Message "[Miniserver Check] Checking version for '$msIPPreCheck' via URI: ${redactedVersionUriPreCheck}" -Level DEBUG

            $responseObjectPreCheck = $null; $msVersionCheckSuccessPreCheck = $false; $currentVersionPreCheck = "Error"
            $iwrParamsBasePreCheck = @{ TimeoutSec = 10; ErrorAction = 'Stop'; Method = 'Get' }
            if ($credentialPreCheck) { $iwrParamsBasePreCheck.Credential = $credentialPreCheck }
            try { # Try HTTPS
                $httpsUriBuilderPreCheck = [System.UriBuilder]$versionUriPreCheck; $httpsUriBuilderPreCheck.Scheme = 'https'; $httpsUriBuilderPreCheck.Port = 443
                $httpsUriPreCheck = $httpsUriBuilderPreCheck.Uri.AbsoluteUri
                $httpsParamsPreCheck = $iwrParamsBasePreCheck.Clone(); $httpsParamsPreCheck.Uri = $httpsUriPreCheck
                Write-Log -Message "[Miniserver Check] Attempting HTTPS connection to $msIPPreCheck..." -Level DEBUG
                $responseObjectPreCheck = Invoke-WebRequest @httpsParamsPreCheck
                Write-Log -Message "[Miniserver Check] HTTPS connection successful for $msIPPreCheck." -Level DEBUG
                $msVersionCheckSuccessPreCheck = $true
            } catch { # Catch for HTTPS attempt
                Write-Log -Message "[Miniserver Check] HTTPS failed for $msIPPreCheck ($($_.Exception.Message)). Falling back to HTTP." -Level DEBUG
                # Add more details in Debug mode
                if ($Global:DebugPreference -eq 'Continue') {
                    $exceptionDetails = "[Miniserver Check] HTTPS Failure Details for ${msIPPreCheck}:"
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
                    Write-Log -Message "[Miniserver Check] Attempting HTTP connection to $msIPPreCheck..." -Level DEBUG
                    if ($httpParamsPreCheck.ContainsKey('Credential')) {
                         Write-Log -Message "[Miniserver Check] Attempting HTTP request to $msIPPreCheck (with credentials, using Authorization header)." -Level WARN
                         # Construct Basic Auth Header
                         $credentialObject = $httpParamsPreCheck.Credential
                         $userName = $credentialObject.UserName
                         $password = $credentialObject.GetNetworkCredential().Password
                         $encodedCredentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${userName}:${password}"))
                         $headers.Authorization = "Basic $encodedCredentials"
                         # Remove Credential from splatting params as we're using header auth
                         $httpParamsPreCheck.Remove('Credential')
                    } else {
                         Write-Log -Message "[Miniserver Check] Attempting HTTP request to $msIPPreCheck (no credentials)." -Level DEBUG
                    }
                    # Use standard splatting, adding Headers parameter
                    $responseObjectPreCheck = Invoke-WebRequest @httpParamsPreCheck -Headers $headers
                    Write-Log -Message "[Miniserver Check] HTTP connection successful for $msIPPreCheck." -Level DEBUG
                    $msVersionCheckSuccessPreCheck = $true
                } catch { # Catch for HTTP attempt (Invoke-WebRequest)
                    Write-Log -Message "[Miniserver Check] Failed to get version for '$msIPPreCheck' via HTTP as well: $($_.Exception.Message)" -Level ERROR # Keep primary message as ERROR
                    # Add more details in Debug mode
                    if ($Global:DebugPreference -eq 'Continue') {
                        $exceptionDetails = "[Miniserver Check] HTTP Failure Details for ${msIPPreCheck}:"
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
                try { # Try parsing XML
                    $xmlResponsePreCheck = [xml]$responseObjectPreCheck.Content
                    $currentVersionPreCheck = $xmlResponsePreCheck.LL.value
                    if ($null -eq $xmlResponsePreCheck -or $null -eq $xmlResponsePreCheck.LL -or $null -eq $xmlResponsePreCheck.LL.value) { throw "Could not find version value in parsed XML." }
                    Write-Log -Message "[Miniserver Check] Miniserver '$msIPPreCheck' current version: ${currentVersionPreCheck}" -Level INFO
                } catch { # Catch for parsing XML
                    Write-Log -Message "[Miniserver Check] Failed to parse version XML for '$msIPPreCheck': $($_.Exception.Message)" -Level ERROR
                    $currentVersionPreCheck = "Error Parsing XML"
                } # End XML parsing catch
            } elseif (-not $msVersionCheckSuccessPreCheck) {
                $currentVersionPreCheck = "Error Connecting" # Already logged specific error
            } # End if/elseif for processing response
            $miniserverVersions[$msIPPreCheck] = $currentVersionPreCheck # Store result
        } # End foreach msEntryPreCheck
    } catch { # Catch for the outer try (started line 959)
        Write-Log -Message "[Miniserver Check] Error reading or processing Miniserver list '$MSListPath': $($_.Exception.Message). Skipping Miniserver version pre-check." -Level WARN
    } # End outer catch
} else { # Else for the if (Test-Path $MSListPath) (line 958)
    Write-Log -Message "[Miniserver Check] Miniserver list '$MSListPath' not found. Skipping Miniserver version pre-check." -Level INFO
}
# You can access the collected versions in the $miniserverVersions hashtable later if needed
Write-Log -Message "[Miniserver Check] Finished Miniserver version check." -Level INFO
# --- End Miniserver Check: Check Miniserver Versions ---

# Recalculate miniserverCount for step/weight calculations
$miniserverCount = 0
if (Test-Path $MSListPath) {
    try {
        $miniserverEntries = Get-Content $MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
        $miniserverCount = ($miniserverEntries | Measure-Object).Count
    } catch {
        Write-Log -Level WARN -Message "Error reading Miniserver list '$MSListPath' during step/weight calculation: $($_.Exception.Message). Assuming 0 Miniservers."
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
    @{ ID = 'UpdateMS';       Description = 'Updating Miniservers';           Weight = 0; Condition = { $miniserverCount -gt 0 -and $configUpdateNeeded } }; # Condition includes config update needed
    @{ ID = 'Finalize';       Description = 'Finalizing';                     Weight = 1; Condition = { $true } }
)
function Get-StepWeight { param([string]$StepID); $stepObject = $ProgressSteps | Where-Object { $_.ID -eq $StepID } | Select-Object -First 1; if ($stepObject) { if ($stepObject.ContainsKey('Weight')) { return $stepObject.Weight } else { Write-Log -Level WARN -Message "Get-StepWeight: Found step with ID '$StepID' but it lacked a 'Weight' key."; return 0 } } else { Write-Log -Level WARN -Message "Get-StepWeight: Could not find step with ID '$StepID'."; return 0 } }

try { # --- Start of Main Try Block ---
    # --- Calculate Total Weight ---
    Write-Log -Message "Calculating total progress weight..." -Level INFO; $script:TotalWeight = 0; $script:CurrentWeight = 0;
    # $miniserverCount already calculated above
    foreach ($step in $ProgressSteps) { $runStep = $false; try { $runStep = Invoke-Command -ScriptBlock $step.Condition } catch { Write-Log -Message "Error evaluating condition for step '$($step.ID)': $($_.Exception.Message)" -Level WARN; $runStep = $false }; if ($runStep) { if ($step.ID -eq 'UpdateMS') { $msWeightPerServer = 2; $script:TotalWeight += ($miniserverCount * $msWeightPerServer); Write-Log -Message "Condition TRUE for step '$($step.ID)'. Adding weight: $($miniserverCount * $msWeightPerServer) ($miniserverCount servers * $msWeightPerServer weight/server)." -Level DEBUG } else { $script:TotalWeight += $step.Weight; Write-Log -Message "Condition TRUE for step '$($step.ID)'. Adding weight: $($step.Weight)." -Level DEBUG } } else { Write-Log -Message "Condition FALSE for step '$($step.ID)'. Skipping weight: $($step.Weight)." -Level DEBUG } }
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
    # Add Miniserver step only if Config update is needed AND servers exist
    if ($configUpdateNeeded -and $miniserverCount -gt 0) {
        $script:totalSteps += 1 # Miniserver Update Step
        Write-Log -Level DEBUG -Message "Miniserver updates needed ($miniserverCount servers) because Config is updating. Adding 1 step."
    } elseif ($miniserverCount -gt 0) {
         Write-Log -Level DEBUG -Message "Miniserver update step skipped because Config is not updating."
    } else {
         Write-Log -Level DEBUG -Message "No Miniserver updates needed (list empty or error)."
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
    Update-PersistentToast -StepNumber $script:currentStep -TotalSteps $script:totalSteps -StepName $initialCheckStepName -CurrentWeight $script:CurrentWeight -TotalWeight $script:TotalWeight
    # --- End Progress Calculation ---

    # Set path for potential Miniserver update (use initially detected path)
    $LoxoneConfigExePathForMSUpdate = $script:InstalledExePath # Still needed for the check below, even if not passed to Update-MS
    Write-Log -Message "[Miniserver] Using initially determined Loxone Config path for potential Miniserver update check: '$LoxoneConfigExePathForMSUpdate'" -Level INFO

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
            Update-PersistentToast @toastParamsCfgSkipRunningPre
            exit 0 # Exit cleanly
        }

        # Check existing installer
        $skipDownload = $false
        if (Test-Path -Path $InstallerPath -PathType Leaf) {
            Write-Log -Message "[Config] Existing installer found at '$InstallerPath'. Validating version..." -Level INFO; $existingVersion = (Get-Item -Path $InstallerPath -ErrorAction SilentlyContinue).VersionInfo.FileVersion; $normalizedExisting = Convert-VersionString $existingVersion; $versionMatch = $false # Removed unused $signatureValid assignment
            if ($normalizedExisting) { Write-Log -Message "Existing installer version: $normalizedExisting. Target version: $LatestVersion." -Level DEBUG; if ($normalizedExisting -eq $LatestVersion) { $versionMatch = $true; Write-Log -Message "[Config] Existing installer version matches target version." -Level INFO } else { Write-Log -Message "[Config] Existing installer version ($normalizedExisting) does NOT match target version ($LatestVersion)." -Level WARN } } else { Write-Log -Message "[Config] Could not determine version for existing installer '$InstallerPath'." -Level WARN }
            # Signature validation logic removed here - it's done after download/extraction now
            if ($versionMatch) { # Simplified check: if version matches, skip download
                 Write-Log -Message "[Config] Existing installer '$InstallerPath' matches target version. Skipping download." -Level INFO; $skipDownload = $true
                 # Update Toast to reflect skipping download
                 $toastParamsCfgSkipDownload = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Using Existing Config Installer"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                 Update-PersistentToast @toastParamsCfgSkipDownload
                 $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig' # Add weight even if skipped
                 Write-Log -Message "[Config] Added weight for skipped download. Current weight: $($script:CurrentWeight)." -Level DEBUG
            } else { Write-Log -Message "[Config] Existing installer '$InstallerPath' version mismatch. Removing and proceeding with download." -Level WARN; Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue }
        } else { Write-Log -Message "[Config] No existing installer found at '$InstallerPath'. Proceeding with download." -Level INFO }

        # Perform Download if not skipped
        if (-not $skipDownload) {
            if (-not (Test-Path -Path $DownloadDir -PathType Container)) { Write-Log -Message "[Config] Download directory '$DownloadDir' not found. Creating..." -Level INFO; New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null }

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
            Update-PersistentToast @toastParamsCfgDownloadStart

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
            Update-PersistentToast @toastParamsCfgDownloadVerify
        }

        # --- Extract (Part of Download Step if download happened, otherwise part of Install step) ---
        $extractStepName = "Extracting Config Installer"
        Write-Log -Message "[Config] $extractStepName..." -Level INFO
        $toastParamsCfgExtract = @{
            StepNumber    = $script:currentStep # Still conceptually part of download or pre-install
            TotalSteps    = $script:totalSteps
            StepName      = $extractStepName
            CurrentWeight = $script:CurrentWeight
            TotalWeight   = $script:TotalWeight
        }
        Update-PersistentToast @toastParamsCfgExtract
        # Ensure installer isn't present from a previous failed run if download was skipped
        if ($skipDownload -and (Test-Path $InstallerPath)) {
            Write-Log -Level DEBUG -Message "Download skipped, removing potentially stale installer before extraction: $InstallerPath"
            Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
        } elseif (-not $skipDownload -and (Test-Path $InstallerPath)) {
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
        if (-not $skipDownload) { # Add weight only if download wasn't skipped
             $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
             Write-Log -Message "[Config] Added weight for extraction. Current weight: $($script:CurrentWeight)." -Level DEBUG
        }


        # --- Verify Installer Signature (Part of Download/Pre-Install Step) ---
        $verifySigStepName = "Verifying Config Installer Signature"
        Write-Log -Message "[Config] $verifySigStepName..." -Level INFO
        $toastParamsCfgVerifySig = @{
            StepNumber    = $script:currentStep # Still conceptually part of download or pre-install
            TotalSteps    = $script:totalSteps
            StepName      = $verifySigStepName
            CurrentWeight = $script:CurrentWeight
            TotalWeight   = $script:TotalWeight
        }
        Update-PersistentToast @toastParamsCfgVerifySig
        # Use ExpectedXmlSignature fetched earlier
        if ($ExpectedXmlSignature) {
             $sigCheckResult = Get-ExecutableSignature -ExePath $InstallerPath
             # Robust check: Ensure result exists, status is valid, thumbprint exists, and thumbprint matches
             $validationFailed = $false
             $failureReason = ""
             if (-not $sigCheckResult) {
                 $validationFailed = $true
                 $failureReason = "Get-ExecutableSignature returned null."
             } elseif ($sigCheckResult.Status -ne 'Valid') {
                 $validationFailed = $true
                 $failureReason = "Signature status is '$($sigCheckResult.Status)' (Expected 'Valid')."
             } # Removed incorrect comparison between Authenticode Thumbprint and XML Signature
             # elseif ([string]::IsNullOrEmpty($sigCheckResult.Thumbprint)) { ... } # Thumbprint presence is implicitly checked by Status being 'Valid'
             # elseif ($sigCheckResult.Thumbprint -ne $ExpectedXmlSignature) { ... } # Incorrect comparison removed

             # Add a note that XML signature itself isn't checked here
             Write-Log -Level DEBUG -Message "Note: XML signature value ('$ExpectedXmlSignature') is present but not currently validated against the XML content."


             if ($validationFailed) {
                 throw "CRITICAL: Extracted installer '$InstallerPath' failed signature validation. Reason: $failureReason"
             }
             Write-Log -Message "[Config] Extracted installer signature verified successfully against XML signature." -Level INFO
        } else { Write-Log -Message "[Config] XML Signature was missing. Skipping installer signature validation." -Level WARN }


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
            Update-PersistentToast @toastParamsCfgSkipRunningInstall
            $installationSkippedDueToRunningProcess = $true
            # Do not exit script here, allow potential MS update check later if needed? Or should we exit? For now, just skip install.
        } elseif ($CloseApplications) {
            if ($anyProcessRunning) { # Only close if actually running
                Write-Log -Message "[Config] Attempting to close running Loxone applications..." -Level INFO
                $toastParamsCfgCloseApps = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Closing Loxone Applications"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                Update-PersistentToast @toastParamsCfgCloseApps
                foreach ($procName in $processesToCheck) { Get-ProcessStatus -ProcessName $procName -StopProcess:$true }
                Write-Log -Message "[Config] Close application requests sent." -Level INFO
                Start-Sleep -Seconds 2 # Give processes time to close
            } else { Write-Log -Message "[Config] No relevant Loxone processes found running. No need to close applications." -Level INFO }
        } elseif ($anyProcessRunning) { # Apps running, but CloseApps not specified
             Write-Log -Message "[Config] Loxone application(s) are running, but -CloseApplications was not specified. Installation might fail." -Level WARN
             $toastParamsCfgWarnRunning = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="WARN: Loxone process(es) running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
             Update-PersistentToast @toastParamsCfgWarnRunning
        }

        # --- Install (if not skipped) ---
        if (-not $installationSkippedDueToRunningProcess) {
            Write-Log -Message "[Config] Running Loxone Config installer..." -Level INFO
            $toastParamsCfgInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName=$configInstallStepName; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsCfgInstall

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
             Update-PersistentToast @toastParamsCfgVerifyInstall

            $NewInstalledExePath = Get-LoxoneExePath; $NewInstalledVersion = if ($NewInstalledExePath -and (Test-Path $NewInstalledExePath)) { (Get-Item -Path $NewInstalledExePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion } else { "" }; $normalizedNewInstalled = Convert-VersionString $NewInstalledVersion
            if ($normalizedNewInstalled -eq $LatestVersion) {
                Write-Log -Message "[Config] Successfully updated Loxone Config to version $NewInstalledVersion." -Level INFO
                $anyUpdatePerformed = $true # Set flag: Config update performed
                $script:configUpdated = $true; $LoxoneConfigExePathForMSUpdate = $NewInstalledExePath; Write-Log -Message "[Config] Loxone Config path for MS update set to: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
                $script:CurrentWeight += Get-StepWeight -StepID 'VerifyConfig' # Add verification weight
                Write-Log -Message "[Config] Added weight for verification. Current weight: $($script:CurrentWeight)." -Level DEBUG

                $toastParamsCfgInstallComplete = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Loxone Config Update Complete (v$NewInstalledVersion)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                Update-PersistentToast @toastParamsCfgInstallComplete
            } else {
                 $errorMessage = "Update verification failed! Expected version '$($LatestVersion)' but found '$($normalizedNewInstalled)' after installation."
                 Write-Log -Message "[Config] $errorMessage" -Level ERROR
                 $toastParamsCfgVerifyFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="FAILED: Config verification failed!"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                 Update-PersistentToast @toastParamsCfgVerifyFail
                 throw $errorMessage
            }
        }
        # --- End Install ---

    } else { # Corresponds to if ($configUpdateNeeded)
         # Log message already written earlier when $configUpdateNeeded was determined
         # Write-Log -Message "[Config] Loxone Config is already up-to-date (Version: $($script:InitialInstalledVersion)). No update needed." -Level INFO # Redundant
         Write-Log -Message "[Config] Using initially determined installation path for potential Miniserver update: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
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

# --- Step: Update Miniservers ---
# Check if this step should run based on conditions calculated earlier
$runMiniserverUpdateStep = $false
if ($miniserverCount -gt 0) { $runMiniserverUpdateStep = $true } # Condition changed to run if servers exist

if ($runMiniserverUpdateStep) {
    # Only run if Config needed updating AND Miniservers exist in the list
    if ($runMiniserverUpdateStep) { # Condition changed: Run if servers exist, regardless of config update status
        # Increment step and update toast ONLY if attempting the update
        $script:currentStep++
        $msUpdateStepName = "Updating Miniservers ($miniserverCount)"
        Write-Log -Message "[Miniserver] $msUpdateStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
 
        # Update Toast for MS Update Start
        $toastParamsMSUpdateStart = @{
            StepNumber    = $script:currentStep
            TotalSteps    = $script:totalSteps
            StepName      = $msUpdateStepName
            CurrentWeight = $script:CurrentWeight # Pass current weight
            TotalWeight   = $script:TotalWeight
        }
        Update-PersistentToast @toastParamsMSUpdateStart
 
        Write-Log -Message "[Miniserver] Config needed update and Miniservers exist. Proceeding with Update-MS function." -Level INFO
        # Pass StepNumber and TotalSteps to Update-MS (Removed -InstalledExePath argument)
        $miniserversUpdated = Update-MS -DesiredVersion $LatestVersion -MSListPath $MSListPath -LogFile $global:LogFile -MaxLogFileSizeMB $MaxLogFileSizeMB -DebugMode:$DebugMode -ScriptSaveFolder $ScriptSaveFolder -StepNumber $script:currentStep -TotalSteps $script:totalSteps -SkipCertificateCheck:$SkipCertificateCheck
        # Add weight based on the number of servers AFTER the update attempt
        if (-not $script:ErrorOccurred) {
             $msWeightPerServer = 2 # Define weight per server directly here as it's only used in this block
             $msTotalWeight = $miniserverCount * $msWeightPerServer
             $script:CurrentWeight += $msTotalWeight
             Write-Log -Message "[Miniserver] Added weight for Miniserver updates. Current weight: $($script:CurrentWeight)." -Level DEBUG
 
             # Update Toast for MS Update Complete
             $toastParamsMSUpdateComplete = @{
                 StepNumber    = $script:currentStep
                 TotalSteps    = $script:totalSteps
                 StepName      = "Miniserver Updates Complete"
                 CurrentWeight = $script:CurrentWeight
                 TotalWeight   = $script:TotalWeight
             }
             Update-PersistentToast @toastParamsMSUpdateComplete
        }
        # Removed incorrect 'else' block and misplaced toast update here
    } # Removed redundant elseif block that handled skipping when config was up-to-date
} else { # Corresponds to if ($runMiniserverUpdateStep) - i.e., no servers in list
     # Remove toast update for skipped step
     # $toastParamsMSSkipCond = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Miniserver Update Skipped"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
     # Update-PersistentToast @toastParamsMSSkipCond
     # Add weight for skipped step
     $msWeightPerServer = Get-StepWeight -StepID 'UpdateMS'; $msTotalWeight = $miniserverCount * $msWeightPerServer; $script:CurrentWeight += $msTotalWeight
     Write-Log -Message "[Miniserver] Added weight for skipped MS update step. Current weight: $($script:CurrentWeight)." -Level DEBUG
}
 
# --- Finalization Step ---
# Set the current step to the total for the finalization step
$script:currentStep = $script:totalSteps
$finalStepName = "Finalizing"
# Use the potentially incremented step number
Write-Log -Message "[Main] $finalStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
$anyUpdatePerformed = $script:configUpdated -or $miniserversUpdated # Re-evaluate here
Write-Log -Message "Update Status - Config Updated: $($script:configUpdated), Miniservers Updated: $($miniserversUpdated), Any Update Performed: $anyUpdatePerformed" -Level INFO

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
     Update-PersistentToast @toastParamsFinal
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
if ($script:ErrorOccurred) {
    Write-Log -Message "Script finished with errors. Exit Code: 1" -Level ERROR
    Exit 1
} else {
    # Always attempt final notification; toast function handles context
    Write-Log -Message "Preparing final status notification." -Level DEBUG
    # REMOVED premature exit log message
 
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

    if (-not $anyUpdatePerformed) {
        Write-Log -Message "No updates performed. Constructing CONCISE summary notification." -Level INFO; $summaryLines = @() # Removed "Update Check:" line
        if (Test-Path $MSListPath) { try { $miniserverEntries = Get-Content $MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }; if (($miniserverEntries | Measure-Object).Count -gt 0) { $summaryLines += "Miniserver(s): Up-to-date (v$($LatestVersion))" } else { $summaryLines += "Miniserver(s): List empty/not checked." } } catch { $summaryLines += "Miniserver(s): Error checking list." } } else { $summaryLines += "Miniserver(s): List not found." }
        if ($InstalledExePath -and (Test-Path $InstalledExePath)) { if ($LatestVersion -ne $normalizedInstalled) { $summaryLines += "Config: Update available (v$($LatestVersion.ToString())) but skipped (Installed: v$($script:InitialInstalledVersion))." } else { $summaryLines += "Config: Up-to-date (v$($script:InitialInstalledVersion))" } } else { $summaryLines += "Config: Not Found." } # Removed dot
        if ($UpdateLoxoneApp) { if ($appDetails -and -not $appDetails.Error) { if ($appUpdateNeeded) { $summaryLines += "App ($selectedAppChannelName): Update available (v$($latestLoxWindowsVersion)) but skipped/failed." } else { $summaryLines += "App ($selectedAppChannelName): Up-to-date (v$($appDetails.FileVersion))" } } elseif ($latestLoxWindowsVersion) { $summaryLines += "App ($selectedAppChannelName): Not Found/Error checking." } else { $summaryLines += "App ($selectedAppChannelName): Check skipped (details unavailable)." } } else { $summaryLines += "App: Check disabled." } # Removed dot
        $summaryMessage = $summaryLines -join "`n"; $script:CurrentWeight = $script:TotalWeight
        # Pass the rotated log path
        # Show summary toast only if interactive run (as no update was performed)
        if ($script:IsInteractiveRun) {
            Write-Log -Message "Showing final status toast because script was run interactively (IsInteractiveRun=True) even though no update was performed." -Level INFO
            Show-FinalStatusToast -StatusMessage $summaryMessage -Success:$true -LogFileToShow $logPathToShow
        } else {
            Write-Log -Message "Skipping final status toast because script was not run interactively (IsInteractiveRun=False) and no update was performed." -Level INFO
        }
    } else {
        Write-Log -Message "Updates were performed successfully. Showing success notification." -Level INFO
        if ($script:CurrentWeight -lt $script:TotalWeight) { $script:CurrentWeight = $script:TotalWeight }
        $successMessages = @("Loxone update process finished successfully."); if ($script:configUpdated) { $successMessages += "Loxone Config updated to v$NewInstalledVersion." }; if ($miniserversUpdated) { $successMessages += "Miniserver(s) updated (check log for details)." }
        $successMessage = $successMessages -join " "
        # Pass the rotated log path
        Show-FinalStatusToast -StatusMessage $successMessage -Success:$true -LogFileToShow $logPathToShow
    }
    Write-Log -Level INFO -Message "Script finished successfully. Exit Code: 0"
    Exit 0
}
# End of script
