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

# Explicitly set DebugPreference based ONLY on the -DebugMode switch
if ($DebugMode) { # Check boolean value directly
    $Global:DebugPreference = 'Continue'
    Write-Host "INFO: -DebugMode specified, setting Global:DebugPreference = 'Continue'" -ForegroundColor Green
} else {
    $Global:DebugPreference = 'SilentlyContinue'
    Write-Host "INFO: -DebugMode NOT specified, setting Global:DebugPreference = 'SilentlyContinue'" -ForegroundColor Green
}

# --- Define Base Paths Early ---
$script:MyScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- Determine Script Save Folder ---
if ([string]::IsNullOrWhiteSpace($ScriptSaveFolder)) {
    if ($script:MyScriptRoot) { $ScriptSaveFolder = $script:MyScriptRoot; Write-Host "INFO: Using Script Root for ScriptSaveFolder: '$ScriptSaveFolder'" -ForegroundColor Cyan }
    else { $ScriptSaveFolder = Join-Path -Path $env:USERPROFILE -ChildPath "UpdateLoxone"; Write-Host "INFO: Script Root not available. Falling back to UserProfile path for ScriptSaveFolder: '$ScriptSaveFolder'" -ForegroundColor Cyan }
} else { Write-Host "INFO: Using provided ScriptSaveFolder parameter: '$ScriptSaveFolder'" -ForegroundColor Cyan }

# --- Set Log Directory and Global Log File Path ---
$LogDir = Join-Path -Path $ScriptSaveFolder -ChildPath "Logs"
if (-not (Test-Path -Path $LogDir -PathType Container)) {
    Write-Host "INFO: Log directory '$LogDir' not found. Creating..." -ForegroundColor Cyan
    try { New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch { Write-Error "FATAL: Failed to create log directory '$LogDir'. Error: $($_.Exception.Message)"; exit 1 }
}

if (-not [string]::IsNullOrWhiteSpace($PassedLogFile)) {
    Write-Host "INFO: Using passed log file path: '$PassedLogFile'" -ForegroundColor Cyan
    $PassedLogDir = Split-Path -Path $PassedLogFile -Parent
    if (-not (Test-Path -Path $PassedLogDir -PathType Container)) {
        Write-Host "WARN: Directory for passed log file '$PassedLogDir' not found. Attempting to create..." -ForegroundColor Yellow
        try { New-Item -Path $PassedLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch { Write-Error "FATAL: Failed to create directory for passed log file '$PassedLogDir'. Error: $($_.Exception.Message)"; exit 1 }
    }
    $global:LogFile = $PassedLogFile
} else {
    Write-Host "INFO: No log file passed. Generating new log file name." -ForegroundColor Cyan
    $userNameForFile = (([Security.Principal.WindowsIdentity]::GetCurrent()).Name -split '\\')[-1] -replace '[\\:]', '_'
    $baseLogName = "UpdateLoxone_$userNameForFile.log"
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $regexInvalidChars = "[{0}]" -f [RegEx]::Escape($invalidChars)
    $sanitizedLogName = $baseLogName -replace $regexInvalidChars, '_'
    $global:LogFile = Join-Path -Path $LogDir -ChildPath $sanitizedLogName
}
Write-Host "INFO: Global LogFile path set to '$($global:LogFile)' (before logging module import)." -ForegroundColor Cyan

# --- Script Initialization (Continues) ---
$script:ErrorOccurred = $false 
$script:LastErrorLine = 0
$script:IsAdminRun = $false 
$global:IsElevatedInstance = $false 
$script:configUpdated = $false # This specific flag might become redundant if using $UpdateTargetsInfo status
$script:appUpdated = $false   # This specific flag might become redundant if using $UpdateTargetsInfo status
$script:isRunningAsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
$script:CurrentWeight = 0 
$script:TotalWeight = 0   
$script:currentStep = 0
$script:totalSteps = 1 
$script:currentDownload = 0
$script:totalDownloads = 0 
$script:InitialInstalledVersion = "" # For Loxone Config, specifically
$anyUpdatePerformed = $false # Overall flag, can be derived from $UpdateTargetsInfo at the end
$script:CurrentInvocationTrace = $null
$script:isSelfInvokedForUpdateCheck = $false

# CENTRALIZED DATA STRUCTURE for update targets
$UpdateTargetsInfo = @()

# --- Load Helper Module (Manifest Import) ---
$UtilsModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'LoxoneUtils\LoxoneUtils.psd1' 

if (-not (Test-Path $UtilsModulePath)) {
    Write-Error "Helper module 'LoxoneUtils.psd1' not found at '$UtilsModulePath'. Script cannot continue."
    exit 1 
}
Write-Host "INFO: Checking for required module 'BurntToast'..."
$burntToastAvailable = Get-Module -ListAvailable -Name BurntToast
if (-not $burntToastAvailable) {
    Write-Host "INFO: 'BurntToast' module not found. Attempting to install from PSGallery..."
    try {
        Install-Module -Name BurntToast -Scope CurrentUser -Repository PSGallery -Force -ErrorAction SilentlyContinue
        Write-Host "INFO: 'BurntToast' installed successfully."
        $burntToastAvailable = Get-Module -ListAvailable -Name BurntToast
    } catch {
        Write-Warning "Failed to install 'BurntToast' module. Toast notifications will be unavailable. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "INFO: 'BurntToast' module found."
}

function Get-InvocationTrace {
    try {
        $stack   = Get-PSCallStack         # always safe
        $self    = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
        $parent  = Get-CimInstance Win32_Process -Filter "ProcessId=$($self.ParentProcessId)"
        [pscustomobject]@{
            CallStack       = $stack.Command
            ThisProcessCLI  = $self.CommandLine
            ParentProcessCLI= $parent.CommandLine
        }
    }
    catch {
        Write-Warning "While collecting invocation info: $_"
        # Return an object with empty/error values so the calling code doesn't break
        [pscustomobject]@{
            CallStack       = @("Error collecting call stack: $($_.Exception.Message)")
            ThisProcessCLI  = "Error collecting this process CLI: $($_.Exception.Message)"
            ParentProcessCLI= "Error collecting parent process CLI: $($_.Exception.Message)"
        }
    }
}

try {
    if ($script:isRunningAsSystem) {
        # When running as SYSTEM, the script's primary role is to re-launch as the user.
        # For the duration of this SYSTEM context, it should be considered non-interactive.
        $script:IsInteractive = $false
        
        Write-Host "DEBUG: (SYSTEM) Attempting to forcefully remove existing LoxoneUtils module (SYSTEM context)..." -ForegroundColor Gray
        Remove-Module LoxoneUtils -Force -ErrorAction SilentlyContinue
        # Try to import the module to make logging and rotation functions available for the SYSTEM part.
        try {
            Import-Module $UtilsModulePath -Force -ErrorAction Stop
            $systemCanLog = Get-Command Write-Log -ErrorAction SilentlyContinue # Check if Write-Log is available after import
            if ($systemCanLog) { Write-Log -Message "Running as SYSTEM. Successfully imported LoxoneUtils. Forcing non-interactive." -Level INFO }
            else { Write-Host "INFO: (SYSTEM) Running as SYSTEM. LoxoneUtils imported but Write-Log not found. Forcing non-interactive." -ForegroundColor Yellow }
        } catch {
            $systemCanLog = $false # Ensure it's false if import fails
            Write-Host "WARN: (SYSTEM) Failed to import LoxoneUtils module in SYSTEM context: $($_.Exception.Message). Log rotation might be skipped for SYSTEM log." -ForegroundColor Yellow
        }
        
        if ($systemCanLog) { Write-Log -Message "SYSTEM context: Successfully verified LoxoneUtils module load." -Level INFO }
        else { Write-Host "INFO: (SYSTEM) SYSTEM context: Successfully verified LoxoneUtils module load (Write-Log unavailable)." -ForegroundColor Green }

        if ($PassedLogFile) {
            try {
                $BoundParamsString = $PSBoundParameters.Keys | ForEach-Object { "-$_ $($PSBoundParameters[$_])" } | Out-String
                if ($systemCanLog) { Write-Log -Level DEBUG -Message "SYSTEM PSBoundParameters: $($BoundParamsString.Trim())" }
                else { Write-Host "DEBUG: (SYSTEM) PSBoundParameters: $($BoundParamsString.Trim())" -ForegroundColor Gray }
            } catch {
                if ($systemCanLog) { Write-Log -Level ERROR -Message "SYSTEM Failed to log PSBoundParameters: $($_.Exception.Message)" }
                else { Write-Host "ERROR: (SYSTEM) Failed to log PSBoundParameters: $($_.Exception.Message)" -ForegroundColor Red }
            }
        }
        if ($systemCanLog) { Write-Log -Level DEBUG -Message "[Config] Skipping initial version check as running under SYSTEM context." }
        else { Write-Host "DEBUG: (SYSTEM) [Config] Skipping initial version check as running under SYSTEM context." -ForegroundColor Gray }
        $script:InstalledExePath = $null
        $script:InitialInstalledVersion = ""
    } else {
        # Non-SYSTEM context: Load LoxoneUtils module via manifest
        Write-Host "INFO: Non-SYSTEM context. Attempting to load LoxoneUtils module via manifest." -ForegroundColor Cyan # Initial message before Write-Log is available

        # Attempt to forcefully remove any pre-existing LoxoneUtils modules to ensure a clean import
        # Using Write-Host here as Write-Log might not be available if a previous LoxoneUtils module was corrupt or partially loaded prior to this script's execution of this block.
        Write-Host "INFO: Attempting to forcefully remove any existing LoxoneUtils modules (Non-SYSTEM context)..." -ForegroundColor Cyan
        Get-Module -Name "LoxoneUtils*" | ForEach-Object {
            Write-Host "DEBUG: Removing module: $($_.Name)" -ForegroundColor Gray 
            Remove-Module -ModuleInfo $_ -Force -ErrorAction SilentlyContinue
        }

        # Import the main LoxoneUtils module using its manifest.
        # ErrorAction Stop will cause the script to jump to the main try/catch block (around original line 314) if this import fails.
        # The main try/catch block is designed to handle manifest load failures and attempt to identify problematic nested modules.
        Write-Host "INFO: Attempting to import LoxoneUtils manifest: '$UtilsModulePath'..." -ForegroundColor Cyan
        Import-Module $UtilsModulePath -Force -ErrorAction Stop -Verbose
        Write-Host "INFO: LoxoneUtils manifest import command completed (may or may not have succeeded if errors were handled internally by Import-Module without terminating)." -ForegroundColor Cyan

        # After a successful manifest import, Write-Log command from LoxoneUtils.Logging should be available.
        # If Write-Log is not available here, it indicates a fundamental issue with the LoxoneUtils module
        # (e.g., manifest not loading/exporting logging, or logging module itself is broken).
        
        # Explicitly check if Write-Log is now available after manifest import.
        # This is a critical safeguard. If Import-Module -ErrorAction Stop succeeded but Write-Log is still missing, 
        # it's a severe problem with the module structure or export that the manifest didn't catch.
        if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            # Write-Host is used here because Write-Log is confirmed to be unavailable.
            Write-Host "CRITICAL ERROR: Write-Log command is NOT available even after attempting to import the LoxoneUtils manifest ('$UtilsModulePath') with -ErrorAction Stop. This suggests a profound problem within the LoxoneUtils module itself (e.g., the Logging module is not being exported correctly by the manifest, or has critical errors preventing its load, or the manifest itself is corrupt in a way that doesn't throw an error but fails to load nested modules). Script cannot continue." -ForegroundColor Red
            exit 1 # Critical failure, cannot proceed without logging.
        }
        Write-Log -Message "Running as Non-SYSTEM. Successfully loaded LoxoneUtils module via manifest '$UtilsModulePath'. Write-Log is available." -Level INFO
        
        # Get Invocation trace information early and determine if self-invoked
        $script:CurrentInvocationTrace = Get-InvocationTrace
        if ($script:CurrentInvocationTrace -and $script:CurrentInvocationTrace.ParentProcessCLI -like "*UpdateLoxone.ps1*") {
            $script:isSelfInvokedForUpdateCheck = $true
            Write-Log -Level INFO -Message "Script appears to be self-invoked for update check (Parent CLI contains 'UpdateLoxone.ps1')."
        } else {
            $script:isSelfInvokedForUpdateCheck = $false
            # Log ParentProcessCLI only if DebugMode is on and it's not already covered by the full Invocation Trace log
            if ($DebugMode -and ($null -eq $script:CurrentInvocationTrace -or -not $script:CurrentInvocationTrace.ParentProcessCLI)) {
                 Write-Log -Level DEBUG -Message "Script does not appear to be self-invoked. ParentProcessCLI: $($script:CurrentInvocationTrace.ParentProcessCLI)"
            } elseif ($null -ne $script:CurrentInvocationTrace) {
                 Write-Log -Level DEBUG -Message "Script does not appear to be self-invoked. ParentProcessCLI was: $($script:CurrentInvocationTrace.ParentProcessCLI)"
            } else {
                 Write-Log -Level DEBUG -Message "Script does not appear to be self-invoked. CurrentInvocationTrace was null."
            }
        }

        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Log -Level INFO -Message "Applied TLS 1.2 globally."

        # Log Invocation Trace if in DebugMode
        if ($DebugMode) {
            Write-Log -Level DEBUG -Message "--- Invocation Trace (from script:CurrentInvocationTrace) ---"
            if ($script:CurrentInvocationTrace) {
                if ($script:CurrentInvocationTrace.CallStack) {
                    Write-Log -Level DEBUG -Message "CallStack:"
                    $script:CurrentInvocationTrace.CallStack | ForEach-Object { Write-Log -Level DEBUG -Message "  $_" }
                } else {
                    Write-Log -Level DEBUG -Message "CallStack: (Not available or Get-InvocationTrace failed to populate it)"
                }
                Write-Log -Level DEBUG -Message "ThisProcessCLI: $($script:CurrentInvocationTrace.ThisProcessCLI)"
                Write-Log -Level DEBUG -Message "ParentProcessCLI: $($script:CurrentInvocationTrace.ParentProcessCLI)"
            } else {
                Write-Log -Level WARN -Message "script:CurrentInvocationTrace is null. Cannot log detailed invocation details."
            }
Write-Log -Level DEBUG -Message "--- End Invocation Trace ---"
        }
        $script:IsInteractiveRun = ($MyInvocation.InvocationName -eq '.')
        if ($PassedLogFile) {
             try {
                 $BoundParamsString = $PSBoundParameters.Keys | ForEach-Object { "-$_ $($PSBoundParameters[$_])" } | Out-String
                 Write-Log -Level DEBUG -Message "ELEVATED PSBoundParameters: $($BoundParamsString.Trim())"
             } catch {
                 Write-Log -Level ERROR -Message "ELEVATED Failed to log PSBoundParameters: $($_.Exception.Message)"
             }
         } else {
             if ($DebugMode) {
                 $BoundParamsString = $PSBoundParameters.Keys | ForEach-Object { "-$_ $($PSBoundParameters[$_])" } | Out-String
                 Write-Log -Level DEBUG -Message "INITIAL PSBoundParameters: $($BoundParamsString.Trim())"
                }
             }
        $script:InstalledExePath = Get-LoxoneExePath # Removed -ErrorAction SilentlyContinue
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
    }
} # Closing brace for the try block starting on line 180
catch {
    # Simplified CATCH block for the module loading TRY (lines 180-274)
    $errorMessage = "CRITICAL ERROR during LoxoneUtils module manifest import ('$UtilsModulePath'). Error details: $($_.Exception.Message)"
    Write-Host $errorMessage -ForegroundColor Red
    
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "$errorMessage -- Original Error Record: ($($_ | Out-String))" -Level ERROR
    }
    throw $_
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
# Determine interactivity:
$IsDirectPathInvocation = $MyInvocation.InvocationName -match '^[A-Za-z]:\\' -or $MyInvocation.InvocationName -match '^\\\\'
$script:IsInteractive = (-not $IsDirectPathInvocation) -and ($null -ne $Host.UI.RawUI)
# Determine $invokedByRunAsUserLogic based on call stack for now. This will be reviewed.
# $invokedByRunAsUserLogic determination via callstack is removed as $script:isSelfInvokedForUpdateCheck based on ParentProcessCLI is preferred.
Write-Log -Message ("DEBUG: Interactivity Check (post-module load): IsInteractive='$($script:IsInteractive)', InvocationName='$($MyInvocation.InvocationName)', IsSelfInvokedForUpdateCheck='$($script:isSelfInvokedForUpdateCheck)'") -Level DEBUG
# --- Re-launch as User if Running as SYSTEM ---
if ($script:isRunningAsSystem) {
    Write-Log -Message "Detected script is running as SYSTEM. Attempting to re-launch in the current user's session..." -Level INFO
    if (-not (Get-Command Invoke-AsCurrentUser -ErrorAction SilentlyContinue)) {
        if ($systemCanLog) { Write-Log -Message "CRITICAL: Invoke-AsCurrentUser command not found (LoxoneUtils module issue?). Cannot re-launch as user. Exiting SYSTEM process." -Level ERROR }
        else { Write-Host "CRITICAL: (SYSTEM) Invoke-AsCurrentUser command not found. Cannot re-launch. Exiting." -ForegroundColor Red }
        if ($global:LogFile -and $systemCanLog -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
            Write-Log -Message "SYSTEM: Attempting log rotation for '$($global:LogFile)' before critical exit (Invoke-AsCurrentUser not found)." -Level DEBUG
            Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue
        } elseif ($global:LogFile) { Write-Host "SYSTEM: Log rotation skipped before critical exit (Write-Log or Invoke-LogFileRotation not available)." }
        exit 1
    }
    $forwardedArgs = @()
    foreach ($key in $PSBoundParameters.Keys) {
        # Do not forward -WasLaunchedBySystem if it somehow exists in SYSTEM context's $PSBoundParameters
        if ($key -ne "WasLaunchedBySystem") {
            $value = $PSBoundParameters[$key]
            if ($value -is [switch]) {
                if ($value.IsPresent) { $forwardedArgs += "-$key" }
            } elseif ($null -ne $value) {
                if ($value -match '[\s''`"]') { $forwardedArgs += "-$key `"$($value -replace '`"','``"')`"" }
                else { $forwardedArgs += "-$key $value" }
            }
        }
    }
    $argumentString = $forwardedArgs -join " "
    $scriptPath = $MyInvocation.MyCommand.Definition
    Write-Log -Message "Re-launching '$scriptPath' as current user with arguments: $argumentString" -Level DEBUG
    try {
        $powershellExePath = Get-Command powershell.exe | Select-Object -ExpandProperty Source
        $commandLineForPS = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $argumentString"
        Write-Log -Message "Re-launch command: '$powershellExePath' $commandLineForPS" -Level DEBUG
        Invoke-AsCurrentUser -FilePath $powershellExePath -Arguments $commandLineForPS -Visible:$false -Elevated:$true -ErrorAction Stop
        Write-Log -Message "Successfully initiated script re-launch in user session via Invoke-AsCurrentUser. Exiting SYSTEM process." -Level INFO
    } catch {
        if ($systemCanLog) { Write-Log -Message "CRITICAL: Failed to re-launch script as user via Invoke-AsCurrentUser. Error: $($_.Exception.Message). Exiting SYSTEM process." -Level ERROR }
        else { Write-Host "CRITICAL: (SYSTEM) Failed to re-launch script as user. Error: $($_.Exception.Message). Exiting." -ForegroundColor Red }
        if ($global:LogFile -and $systemCanLog -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
            Write-Log -Message "SYSTEM: Attempting log rotation for '$($global:LogFile)' before critical exit (re-launch failed)." -Level DEBUG
            Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue
        } elseif ($global:LogFile) { Write-Host "SYSTEM: Log rotation skipped before critical exit (Write-Log or Invoke-LogFileRotation not available)." }
        exit 1
    }
    if ($systemCanLog) { Write-Log -Message "SYSTEM process exiting after initiating user-context re-launch." -Level DEBUG }
    else { Write-Host "INFO: (SYSTEM) SYSTEM process exiting after initiating user-context re-launch." }
    if ($global:LogFile -and $systemCanLog -and (Get-Command Invoke-LogFileRotation -ErrorAction SilentlyContinue)) {
        Write-Log -Message "SYSTEM: Attempting log rotation for '$($global:LogFile)' before normal exit." -Level DEBUG
        Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount 24 -ErrorAction SilentlyContinue
    } elseif ($global:LogFile) { Write-Host "SYSTEM: Log rotation skipped before normal exit (Write-Log or Invoke-LogFileRotation not available)." }
    exit 0
}
# --- End Re-launch Logic ---
$TaskName = "LoxoneUpdateTask" 
# --- Automatic Task Registration/Update for Interactive Runs ---
if ($script:IsInteractiveRun) {
    if ($script:IsInteractive -and -not $script:isRunningAsSystem -and -not $RegisterTask.IsPresent) {
        Write-Log -Level DEBUG -Message "Performing pre-elevation check for task '$TaskName' existence using schtasks.exe..."
        $taskExistsPreCheck = $false 
        $schtasksCmd = "schtasks.exe /query /tn `"$TaskName`" 2>&1" 
        Write-Log -Level DEBUG -Message "Executing pre-check command: $schtasksCmd"
        $schtasksOutput = @() 
        try {
            $schtasksOutput = Invoke-Expression $schtasksCmd
            $schtasksOutputString = ($schtasksOutput | Out-String).Trim()
            Write-Log -Level DEBUG -Message "Raw schtasks.exe output:`n$schtasksOutputString"
        } catch {
            $schtasksOutputString = "ERROR executing schtasks: $($_.Exception.Message)"
            Write-Log -Level ERROR -Message "Error executing schtasks.exe pre-check: $($_.Exception.Message)"
            Write-Log -Level DEBUG -Message "Raw schtasks.exe output (on error):`n$schtasksOutputString"
        }
        $foundAccessDenied = $schtasksOutputString -like "*Access is denied.*"
        Write-Log -Level DEBUG -Message "Output contains 'Access is denied.': $foundAccessDenied"
        $foundCannotFind = $schtasksOutputString -like "*ERROR: The system cannot find the file specified.*"
        Write-Log -Level DEBUG -Message "Output contains 'cannot find the file specified.': $foundCannotFind"
        if ($foundAccessDenied -or (-not $foundCannotFind -and -not $foundAccessDenied)) {
            $taskExistsPreCheck = $true
            Write-Log -Level DEBUG -Message "Inferred task '$TaskName' exists based on schtasks output."
        } else {
            $taskExistsPreCheck = $false
            Write-Log -Level DEBUG -Message "Inferred task '$TaskName' does NOT exist based on schtasks output."
        }
        Write-Log -Level DEBUG -Message "Final pre-check result: `$taskExistsPreCheck = $taskExistsPreCheck"
        if (-not $taskExistsPreCheck) {
            Write-Log -Message "Task '$TaskName' requires registration or update (based on pre-check)." -Level INFO
        }
            if ($script:IsAdminRun) {
                Write-Log -Message "Running interactively as Admin user. Ensuring scheduled task '$TaskName' is registered/updated via function." -Level INFO
                try {
                    Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition -TaskName $TaskName -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes -ErrorAction Stop
                } catch {
                    Write-Log -Message "Failed to register/update task via function even as Admin: $($_.Exception.Message)" -Level ERROR
                    if ($script:IsInteractive) { Write-Host "ERROR: Failed to register/update the scheduled task '$TaskName' even though running as Admin. Check logs." -ForegroundColor Red }
                }
            } else {
                if ($taskExistsPreCheck -eq $false) {
                Write-Log -Message "Running interactively as non-Admin user. Elevation is required to register/update the scheduled task '$TaskName'. Attempting to relaunch with elevation..." -Level WARN
                try {
                    $commandString = "& '$($MyInvocation.MyCommand.Definition)' -RegisterTask" 
                    $commandString += " -Channel ""$Channel"""
                    $commandString += " -InstallMode ""$InstallMode"""
                    $commandString += " -ScriptSaveFolder ""$ScriptSaveFolder"""
                    $commandString += " -PassedLogFile ""$($global:LogFile)"""
                    $commandString += " -MaxLogFileSizeMB $MaxLogFileSizeMB"
                    $commandString += " -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes"
                    $commandString += " -EnableCRC $(if ($EnableCRC) { 1 } else { 0 })" # Ensure boolean to int conversion
                    $commandString += " -UpdateLoxoneApp $(if ($UpdateLoxoneApp) { 1 } else { 0 })" # Ensure boolean to int conversion
                    $commandString += " -DebugMode $(if ($DebugMode) { 1 } else { 0 })" # Ensure boolean to int conversion
                    if ($CloseApplications.IsPresent) { $commandString += " -CloseApplications" }
                    if ($SkipUpdateIfAnyProcessIsRunning.IsPresent) { $commandString += " -SkipUpdateIfAnyProcessIsRunning" }
                    Write-Log -Message "Constructed Command string for elevation: $commandString" -Level DEBUG
                    Write-Log -Message "DEBUG: Elevating with: FilePath='powershell.exe', ArgumentList='-Command', ""$commandString"", Verb='RunAs', Wait=`$true" -Level DEBUG
                    Start-Process powershell.exe -Verb RunAs -ArgumentList "-Command", $commandString -Wait -ErrorAction Stop
                    Write-Log -Message "Successfully launched and waited for elevated process to handle task registration for '$TaskName'." -Level INFO
                } catch {
                    Write-Log -Message "Failed to launch or wait for elevated process for task registration. User may have cancelled UAC prompt or another error occurred: $($_.Exception.Message)" -Level ERROR
                    if ($script:IsInteractive) { Write-Host "ERROR: Could not elevate to register/update the scheduled task '$TaskName'. Please run the script as Administrator or use the '-RegisterTask' switch in an Administrator PowerShell session." -ForegroundColor Red }
                }
                } else {
                    Write-Log -Message "Running interactively as non-Admin user, but task pre-check indicates task '$TaskName' likely exists (`$taskExistsPreCheck` = $taskExistsPreCheck). Skipping elevation attempt." -Level INFO
                }
            }
    }
}
# --- End Automatic Task Registration ---

# --- Register Scheduled Task Logic (-RegisterTask Switch) ---
if ($RegisterTask) {
    if (-not $script:IsAdminRun) {
        Write-Log -Level WARN -Message "Registering the scheduled task requires Administrator privileges. Please re-run as Admin." 
        Write-Log -Message "Task registration requested via -RegisterTask but script is not running as Admin. Task registration skipped." -Level WARN
        exit 1
    } else {
        Write-Log -Message "-RegisterTask switch detected. Registering/Updating the scheduled task '$TaskName' via function." -Level INFO
        Write-Log -Message "Attempting to call Register-ScheduledTaskForScript..." -Level DEBUG 
        try {
            Write-Log -Message "Inside TRY block before calling Register-ScheduledTaskForScript for task '$TaskName'." -Level DEBUG 
            Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition -TaskName $TaskName -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes -ErrorAction Stop
            Write-Log -Message "Register-ScheduledTaskForScript completed successfully (within TRY block)." -Level INFO 
            Write-Log -Message "Task registration process finished via function. Exiting script as -RegisterTask was specified." -Level INFO
            exit 0
        } catch {
             $taskRegErrorMsg = "Failed to register/update task '$TaskName' via function even with -RegisterTask and Admin rights: $($_.Exception.Message)" 
             Write-Log -Message $taskRegErrorMsg -Level ERROR 
             Write-Log -Message "Error Record: ($($_ | Out-String))" -Level DEBUG 
             Write-Log -Message "Failed to register/update task via function even with -RegisterTask and Admin rights: $($_.Exception.Message)" -Level ERROR
             if ($script:IsInteractive) { Write-Host "ERROR: Failed to register/update the scheduled task '$TaskName' even with -RegisterTask switch and Admin rights. Check logs." -ForegroundColor Red }
             exit 1
        }
    }
}
# --- End Register Scheduled Task Logic ---

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

Write-Log -Level DEBUG -Message "Running as Admin: $script:IsAdminRun"

# --- Enter Script Scope & Log Start ---
Enter-Function -FunctionName (Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf) -FilePath $PSCommandPath -LineNumber $MyInvocation.ScriptLineNumber
Write-Log -Message "Script starting execution. PID: $PID. IsElevated: $global:IsElevatedInstance. IsSystem: $script:isRunningAsSystem. IsInteractive: $script:IsInteractive" -Level DEBUG

# Initialize Toast AppId early if not running as SYSTEM (SYSTEM context won't show user toasts)
if (-not $script:isRunningAsSystem) {
    Initialize-LoxoneToastAppId # Sets $script:ResolvedToastAppId
}

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
if ($null -eq $updateData.ConfigLatestVersion) {
    throw "CRITICAL: Could not determine the latest Loxone Config version from the update data. Cannot proceed."
}

$LatestVersion              = $updateData.ConfigLatestVersion
$ZipUrl                     = $updateData.ConfigZipUrl
$ExpectedZipSize            = $updateData.ConfigExpectedZipSize
$ExpectedCRC                = $updateData.ConfigExpectedCRC
$latestLoxWindowsVersionRaw = $updateData.AppLatestVersionRaw
$latestLoxWindowsVersion    = $updateData.AppLatestVersion
$loxWindowsInstallerUrl     = $updateData.AppInstallerUrl
$expectedLoxWindowsSize     = $updateData.AppExpectedSize
$expectedLoxWindowsCRC      = $updateData.AppExpectedCRC
$selectedAppChannelName     = $updateData.SelectedAppChannelName

Write-Log -Message "Successfully retrieved update data." -Level INFO
if ($LatestVersion) { Write-Log -Message "[Config] Latest: $LatestVersion, URL: $ZipUrl" -Level DEBUG }
if ($latestLoxWindowsVersion) { Write-Log -Message "[App] Latest ($selectedAppChannelName): $latestLoxWindowsVersion (Raw: $latestLoxWindowsVersionRaw), URL: $loxWindowsInstallerUrl" -Level DEBUG }

# --- App Check: Check and Prepare Loxone Application ---
Write-Log -Message "[App Check] Checking Loxone application status before update..." -Level INFO
$script:completedPreChecks++
Update-PreCheckToast -CheckName "Pre-Check: Reading App Registry" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed

$appDetails = $null
try {
    $appDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction Stop
    if ($appDetails.Error) { Write-Log -Message "[App Check] Failed to get Loxone application details from registry: $($appDetails.Error)" -Level WARN }
    else { Write-Log -Message ("[App Check] Found Loxone App: Name='{0}', Path='{1}', ProductVersion='{2}', FileVersion='{3}'" -f $appDetails.ShortcutName, $appDetails.InstallLocation, $appDetails.ProductVersion, $appDetails.FileVersion) -Level INFO }
} catch { Write-Log -Message "[App Check] An error occurred during initial application check: $($_.Exception.Message)" -Level ERROR }
 
$appUpdateNeeded = $false
$appInitialVersion = if ($appDetails -and -not $appDetails.Error) { $appDetails.FileVersion } else { $null }

if ($appDetails -and -not $appDetails.Error) {
    if ($UpdateLoxoneApp -and $latestLoxWindowsVersion) {
        $script:completedPreChecks++
        Update-PreCheckToast -CheckName "Pre-Check: Comparing App Version" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed
        Write-Log -Message "[App Check] Comparing installed FileVersion '$($appDetails.FileVersion)' with latest available '$($latestLoxWindowsVersion)'..." -Level INFO
        $normalizedLatestApp = Convert-VersionString $latestLoxWindowsVersion; $normalizedInstalledApp = Convert-VersionString $appDetails.FileVersion
        try {
            if ([Version]$normalizedLatestApp -ne [Version]$normalizedInstalledApp) {
                 if ([Version]$normalizedLatestApp -gt [Version]$normalizedInstalledApp) { $appUpdateNeeded = $true; Write-Log -Message "[App Check] Comparison result: Update needed (Latest '$normalizedLatestApp' > Installed '$normalizedInstalledApp')." -Level DEBUG }
                 else { Write-Log -Message "[App Check] Comparison result: No update needed (Latest '$normalizedLatestApp' <= Installed '$normalizedInstalledApp')." -Level DEBUG }
            } else { Write-Log -Message "[App Check] Comparison result: Versions match ('$normalizedLatestApp'). No update needed." -Level DEBUG }
        } catch { Write-Log -Message "[App Check] Error comparing versions '$normalizedLatestApp' and '$normalizedInstalledApp': $($_.Exception.Message). Assuming no update needed." -Level WARN; $appUpdateNeeded = $false }
    }
}

$appTargetEntry = [PSCustomObject]@{
    Name                = "Loxone App"
    Type                = "App"
    InitialVersion      = $appInitialVersion
    TargetVersion       = if ($latestLoxWindowsVersion) { $latestLoxWindowsVersion.ToString() } else { $null }
    UpdateNeeded        = $appUpdateNeeded
    Status              = if ($appUpdateNeeded) { "NeedsUpdate" } elseif ($appInitialVersion) { "UpToDate" } else { "NotInstalled" }
    UpdatePerformed     = $false
    VersionAfterUpdate  = $null
}
$UpdateTargetsInfo += $appTargetEntry
Write-Log -Message "[App Check] Added Loxone App to UpdateTargetsInfo: Name='$($appTargetEntry.Name)', Initial='$($appTargetEntry.InitialVersion)', Target='$($appTargetEntry.TargetVersion)', UpdateNeeded='$($appTargetEntry.UpdateNeeded)', Status='$($appTargetEntry.Status)'" -Level DEBUG

if ($appUpdateNeeded) {
    $currentAppTarget = $UpdateTargetsInfo | Where-Object {$_.Type -eq "App"} | Select-Object -First 1
    if ($currentAppTarget) { $currentAppTarget.Status = "UpdateAttempted" }

    Write-Log -Message "[App Check] Update required for Loxone for Windows (Channel: $selectedAppChannelName, Installed FileVersion: '$($appDetails.FileVersion)', Available: '$latestLoxWindowsVersion')." -Level INFO
    $script:wasLoxoneAppRunning = $false
    if (-not ([string]::IsNullOrWhiteSpace($appDetails.ShortcutName))) {
        Write-Log -Message "[App] Checking if process '$($appDetails.ShortcutName)' is running before update..." -Level DEBUG
        $script:wasLoxoneAppRunning = Get-ProcessStatus -ProcessName $appDetails.ShortcutName -StopProcess:$false
        if ($script:wasLoxoneAppRunning) {
            Write-Log -Message "[App] Process '$($appDetails.ShortcutName)' is running. Attempting to stop..." -Level INFO
            $toastParamsStopApp = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName   = "Stopping Loxone App" }
            if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsStopApp -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
            if (Get-ProcessStatus -ProcessName $appDetails.ShortcutName -StopProcess:$true) { Write-Log -Message "[App] Successfully requested termination for process '$($appDetails.ShortcutName)'." -Level INFO; Start-Sleep -Seconds 2 }
            else { Write-Log -Message "[App] Get-ProcessStatus -StopProcess returned false for '$($appDetails.ShortcutName)'. It might have failed or was already stopped." -Level WARN }
        } else { Write-Log -Message "[App] Process '$($appDetails.ShortcutName)' is not running." -Level INFO }
    } else { Write-Log -Message "[App] ShortcutName not found in registry details. Cannot check/stop process by name." -Level WARN }

    $script:currentStep++; $script:currentDownload++
    $LoxoneWindowsInstallerFileName = Split-Path -Path $loxWindowsInstallerUrl -Leaf
    $LoxoneWindowsInstallerPath = Join-Path -Path $DownloadDir -ChildPath $LoxoneWindowsInstallerFileName
    Write-Log -Message "[App] Using original installer filename: '$LoxoneWindowsInstallerFileName'" -Level DEBUG
    $skipAppDownload = $false
    $appInstallerCheckResult = Test-ExistingInstaller -InstallerPath $LoxoneWindowsInstallerPath -TargetVersion $latestLoxWindowsVersion -ComponentName "App"
    if ($appInstallerCheckResult.IsValid) {
        $skipAppDownload = $true
        $toastParamsAppSkipExisting = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Using Valid Existing App Installer"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
        if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppSkipExisting -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
        $script:CurrentWeight += Get-StepWeight -StepID 'DownloadApp'
        Write-Log -Message "[App] Added weight for skipped download based on valid existing installer. Current weight: $($script:CurrentWeight)." -Level DEBUG
    } elseif ($appInstallerCheckResult.Reason -ne "Not found") {
        Write-Log -Message "[App] Existing installer '$LoxoneWindowsInstallerPath' is invalid ($($appInstallerCheckResult.Reason)). Removing and proceeding with download." -Level WARN
        Remove-Item -Path $LoxoneWindowsInstallerPath -Force -ErrorAction SilentlyContinue
    }
    if (-not $skipAppDownload) {
        Write-Log -Message "[App] Downloading Loxone for Windows installer from '$loxWindowsInstallerUrl' to '$LoxoneWindowsInstallerPath'..." -Level INFO
        if (-not (Test-Path -Path $DownloadDir -PathType Container)) { Write-Log -Message "[App] Download directory '$DownloadDir' not found. Creating..." -Level INFO; New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null }
        $toastParamsAppDownloadStart = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Downloading Loxone App"; DownloadFileName = $LoxoneWindowsInstallerFileName; DownloadNumber = $script:currentDownload; TotalDownloads = $script:totalDownloads; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
        if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppDownloadStart -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
        $appDownloadParams = @{ Url = $loxWindowsInstallerUrl; DestinationPath = $LoxoneWindowsInstallerPath; ActivityName = "Downloading Loxone App Update"; ExpectedCRC32 = $expectedLoxWindowsCRC; ExpectedFilesize = $expectedLoxWindowsSize; MaxRetries = 1; IsInteractive = $script:IsInteractive; StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Downloading Loxone App"; DownloadNumber = $script:currentDownload; TotalDownloads = $script:totalDownloads; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
        Write-Log -Message "[App] Calling Invoke-LoxoneDownload for App Update using stored command object and splatting." -Level DEBUG
        $appDownloadSuccess = Invoke-LoxoneDownload @appDownloadParams
        if (-not $appDownloadSuccess) {
            if ($currentAppTarget) { $currentAppTarget.Status = "UpdateFailed (Download)"; $currentAppTarget.UpdatePerformed = $true }
            throw "[App] Invoke-LoxoneDownload reported failure for Loxone App. Halting app update process."
        }
        $script:CurrentWeight += Get-StepWeight -StepID 'DownloadApp'
        Write-Log -Message "[App] Loxone for Windows download completed successfully. Incremented weight to $($script:CurrentWeight)." -Level INFO
    }
    $script:currentStep++
    Write-Log -Message "[App] Running Loxone for Windows installer..." -Level INFO
    $toastParamsAppInstall = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Installing Loxone App"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
    if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppInstall -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
    $appInstallArgs = "/$InstallMode"
    Write-Log -Message "[App] Executing: Start-Process -FilePath '$LoxoneWindowsInstallerPath' -ArgumentList '$appInstallArgs' -Wait -PassThru" -Level DEBUG
    try { # Try for Start-Process app installer
        $appInstallProcess = Start-Process -FilePath $LoxoneWindowsInstallerPath -ArgumentList $appInstallArgs -Wait -PassThru -ErrorAction Stop
        Write-Log -Message "[App] Loxone for Windows installer process exited with code: $($appInstallProcess.ExitCode)" -Level INFO
        if ($currentAppTarget) { $currentAppTarget.UpdatePerformed = $true }
        if ($appInstallProcess.ExitCode -ne 0) {
            Write-Log -Message "[App] Loxone for Windows installer returned non-zero exit code: $($appInstallProcess.ExitCode). Installation may have failed." -Level WARN
            if ($currentAppTarget) { $currentAppTarget.Status = "UpdateFailed (InstallerExitCode: $($appInstallProcess.ExitCode))" }
        } else {
            Write-Log -Message "[App] Loxone for Windows installation command completed." -Level INFO
            $anyUpdatePerformed = $true
            $script:CurrentWeight += Get-StepWeight -StepID 'InstallApp'
            Write-Log -Message "[App] Incremented weight to $($script:CurrentWeight)." -Level INFO
            $toastParamsAppVerify = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Verifying Loxone App Installation"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
            if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppVerify -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
            Write-Log -Message "[App] Waiting 5 seconds before verification..." -Level DEBUG; Start-Sleep -Seconds 5
            Write-Log -Message "[App] Verifying Loxone for Windows installation..." -Level INFO
            $newAppDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction SilentlyContinue
            if ($newAppDetails -and -not $newAppDetails.Error) {
                $normalizedLatestAppVerify = Convert-VersionString $latestLoxWindowsVersion; $normalizedNewInstalledAppVerify = Convert-VersionString $newAppDetails.FileVersion; $verificationSuccess = $false
                try { if ([Version]$normalizedNewInstalledAppVerify -eq [Version]$normalizedLatestAppVerify) { $verificationSuccess = $true }; Write-Log -Message "[App] Verification comparison result: Success = $verificationSuccess (Expected: '$normalizedLatestAppVerify', Found: '$normalizedNewInstalledAppVerify')" -Level DEBUG }
                catch { Write-Log -Message "[App] Error comparing versions during verification: '$normalizedLatestAppVerify' vs '$normalizedNewInstalledAppVerify': $($_.Exception.Message). Verification failed." -Level WARN; $verificationSuccess = $false }
                if ($verificationSuccess) {
                    Write-Log -Message "[App] Successfully updated Loxone App to FileVersion $($newAppDetails.FileVersion)." -Level INFO
                    $script:appUpdated = $true
                    if ($currentAppTarget) { $currentAppTarget.VersionAfterUpdate = $newAppDetails.FileVersion; $currentAppTarget.Status = "UpdateSuccessful" }
                    $toastParamsAppComplete = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Loxone App Update Complete (v$($newAppDetails.FileVersion))"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
                    if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppComplete -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
                    if ($script:wasLoxoneAppRunning) {
                        Write-Log -Message "[App] Loxone App was running before the update. Attempting restart..." -Level INFO
                        $toastParamsAppRestart = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Restarting Loxone App"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
                        if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppRestart -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
                        $appPathToRestart = $newAppDetails.InstallLocation
                        if ($script:IsInteractive -and -not $script:isRunningAsSystem) {
                            Write-Log -Message "[App] Restarting interactively using Start-Process..." -Level INFO
                            try { Start-Process -FilePath $appPathToRestart -WindowStyle Minimized -ErrorAction Stop; Write-Log -Message "[App] Start-Process command issued for '$appPathToRestart'." -Level INFO }
                            catch { Write-Log -Message "[App] Failed to restart Loxone App interactively using Start-Process: $($_.Exception.Message)" -Level ERROR; $toastParamsAppRestartFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Failed to restart Loxone App"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppRestartFail -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed } }
                        } elseif ($script:isRunningAsSystem) {
                            Write-Log -Message "[App] Running as SYSTEM. Attempting restart via Invoke-AsCurrentUser function..." -Level INFO
                            try { Write-Log -Message "[App] Calling Invoke-AsCurrentUser -FilePath '$appPathToRestart' -Visible -NoWait..." -Level DEBUG; Invoke-AsCurrentUser -FilePath $appPathToRestart -NoWait -ErrorAction Stop; Write-Log -Message "[App] Invoke-AsCurrentUser command issued for '$appPathToRestart'." -Level INFO }
                            catch { Write-Log -Message "[App] Invoke-AsCurrentUser function failed to restart Loxone App: $($_.Exception.Message)" -Level ERROR; $toastParamsAppRestartFailSys = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Failed to restart Loxone App (System)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppRestartFailSys -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed } }
                        } else { Write-Log -Message "[App] Unclear execution context (Not Interactive User, Not SYSTEM). Automatic restart not attempted." -Level WARN; $toastParamsAppRestartSkip = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="WARN: Loxone App restart skipped"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppRestartSkip -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed } }
                    } else { Write-Log -Message "[App] Loxone App was not running before the update. No restart needed." -Level INFO }
                } else {
                    Write-Log -Message "[App] Loxone App update verification failed! Expected FileVersion '$normalizedLatestAppVerify' but found '$normalizedNewInstalledAppVerify' after installation." -Level ERROR
                    if ($currentAppTarget) { $currentAppTarget.Status = "UpdateFailed (Verification)" }
                    $toastParamsAppVerifyFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Loxone App verification failed!"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppVerifyFail -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
                }
            } else {
                Write-Log -Message "[App] Failed to get Loxone App details from registry after installation attempt. Verification failed. Error: $($newAppDetails.Error)" -Level ERROR
                if ($currentAppTarget) { $currentAppTarget.Status = "UpdateFailed (RegistryReadErrorAfterInstall)" }
                $toastParamsAppVerifyFailReg = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="ERROR: Loxone App verification failed (Registry)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }; if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppVerifyFailReg -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
            }
        } # End of else for if ($appInstallProcess.ExitCode -ne 0)
    } catch { # Catch for Start-Process app installer
        Write-Log -Message "[App] Failed to run Loxone for Windows installer: $($_.Exception.Message)" -Level ERROR
        if ($currentAppTarget) { $currentAppTarget.Status = "UpdateFailed (InstallerException)"; $currentAppTarget.UpdatePerformed = $true }
        $toastParamsAppInstallFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="FAILED: Loxone App installation failed"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
        if ($Global:PersistentToastInitialized) { Update-PersistentToast @toastParamsAppInstallFail -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
        throw "[App] Failed to execute Loxone for Windows installer."
    } # End of try/catch for Start-Process for app installation
} elseif ($appDetails -and -not $appDetails.Error) { # This elseif corresponds to `if ($appUpdateNeeded)`
    Write-Log -Message "[App Check] Loxone for Windows (Channel: $selectedAppChannelName) is already up-to-date (FileVersion: $($appDetails.FileVersion))." -Level INFO
} elseif ($UpdateLoxoneApp -and -not $latestLoxWindowsVersion) {
    Write-Log -Message "[App Check] Skipping Loxone App update (Channel: $selectedAppChannelName) because latest version details could not be retrieved from XML (XML fetch/parse failed)." -Level WARN
    $updateToastParams14 = @{ StepName = "WARN: App update skipped (no latest version)." }
    if ($Global:PersistentToastInitialized) { Update-PersistentToast @updateToastParams14 -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
} elseif ($UpdateLoxoneApp -and (!$appDetails -or $appDetails.Error)) {
    Write-Log -Message "[App Check] Skipping Loxone App update check (Channel: $selectedAppChannelName) because installed application details could not be retrieved." -Level WARN
    $updateToastParams15 = @{ StepName = "WARN: Loxone App update skipped (cannot find installed app)." }
    if ($Global:PersistentToastInitialized) { Update-PersistentToast @updateToastParams15 -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed }
}
# End of the main if/elseif chain for app updates.

# --- Config Check: Compare Versions (Using Initially Detected Version) ---
 $LatestVersionNormalized = Convert-VersionString $LatestVersion 

$script:completedPreChecks++
Update-PreCheckToast -CheckName "Pre-Check: Reading Config Version" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed

$normalizedInstalled = Convert-VersionString $script:InitialInstalledVersion 
Write-Log -Level DEBUG -Message "[Config Check] Comparing versions - Latest (Normalized): '$LatestVersionNormalized', Installed (Initially Detected, Normalized): '$normalizedInstalled'"

$script:completedPreChecks++
Update-PreCheckToast -CheckName "Pre-Check: Comparing Config Version" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed
 
$configUpdateNeeded = $false 
if ([string]::IsNullOrWhiteSpace($normalizedInstalled)) {
    if ($LatestVersionNormalized) {
        $configUpdateNeeded = $true
        Write-Log -Message "[Config Check] No initial installed version detected. Update required to latest version '$LatestVersionNormalized'." -Level INFO
    } else {
        Write-Log -Message "[Config Check] No initial installed version detected AND no latest version available. Cannot determine if update is needed." -Level WARN
    }
} elseif ($LatestVersionNormalized -ne $normalizedInstalled) {
    $configUpdateNeeded = $true
    Write-Log -Message "[Config Check] Loxone Config update required (Installed: '$($script:InitialInstalledVersion)', Available: '$LatestVersionNormalized'). Update process will proceed." -Level INFO
} else {
    Write-Log -Message "[Config Check] Loxone Config is already up-to-date (Version: $($script:InitialInstalledVersion)). Config update will be skipped." -Level INFO
}

$configTargetEntry = $UpdateTargetsInfo | Where-Object {$_.Type -eq "Config"} | Select-Object -First 1
if ($configTargetEntry) {
    $configTargetEntry.UpdateNeeded = $configUpdateNeeded
    $configTargetEntry.Status = if ($configUpdateNeeded) { "NeedsUpdate" } elseif ($script:InitialInstalledVersion) { "UpToDate" } else { "NotInstalled" }
} else { # Should not happen if initialized correctly, but as a fallback
    $configTargetEntry = [PSCustomObject]@{
        Name                = "Loxone Config"
        Type                = "Config"
        InitialVersion      = $script:InitialInstalledVersion
        TargetVersion       = if ($LatestVersionNormalized) { $LatestVersionNormalized.ToString() } else { $null }
        UpdateNeeded        = $configUpdateNeeded
        Status              = if ($configUpdateNeeded) { "NeedsUpdate" } elseif ($script:InitialInstalledVersion) { "UpToDate" } else { "NotInstalled" }
        UpdatePerformed     = $false
        VersionAfterUpdate  = $null
    }
    $UpdateTargetsInfo += $configTargetEntry
}
Write-Log -Message "[Config Check] Updated Loxone Config in UpdateTargetsInfo: Name='$($configTargetEntry.Name)', Initial='$($configTargetEntry.InitialVersion)', Target='$($configTargetEntry.TargetVersion)', UpdateNeeded='$($configTargetEntry.UpdateNeeded)', Status='$($configTargetEntry.Status)'" -Level DEBUG

$LoxoneIconPath = $null
if ($script:InstalledExePath -and (Test-Path $script:InstalledExePath)) {
    $InstallDir = Split-Path -Parent $script:InstalledExePath; $PotentialIconPath = Join-Path -Path $InstallDir -ChildPath "LoxoneConfig.ico"
    if (Test-Path $PotentialIconPath) { $LoxoneIconPath = $PotentialIconPath; Write-Log -Level DEBUG -Message "Found Loxone icon at: $LoxoneIconPath" }
    else { Write-Log -Level DEBUG -Message "LoxoneConfig.ico not found in $InstallDir. No icon will be used." }
}

# --- MS Check: Check MS Versions ---
Write-Log -Message "[MS Check] Starting MS version pre-check and populating UpdateTargetsInfo..." -Level INFO
if (Test-Path $MSListPath) {
    try { 
        $MSEntriesPreCheck = Get-Content $MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
        $script:completedPreChecks++
        Update-PreCheckToast -CheckName "Pre-Check: Reading MS List" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed
        $totalMSsToCheck = $MSEntriesPreCheck.Count
        Write-Log -Message "[MS Check] Found $totalMSsToCheck MS entries in '$MSListPath'." -Level DEBUG
        $msPreCheckCounter = 0 

        foreach ($msEntryPreCheck in $MSEntriesPreCheck) {
            $msPreCheckCounter++ 
            $toastParamsMSCheckLoop = @{ StepName="Checking MS $msPreCheckCounter/$totalMSsToCheck..."; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsMSCheckLoop -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            $redactedEntryForLogPreCheck = Get-RedactedPassword $msEntryPreCheck
            Write-Log -Message "[MS Check] Processing entry $msPreCheckCounter/${totalMSsToCheck}: ${redactedEntryForLogPreCheck}" -Level DEBUG
            $msIPPreCheck = $null; $versionUriPreCheck = $null; $credentialPreCheck = $null
            $currentMSInitialVersion = "Error" 
            $msUpdateNeededForThis = $false
            $msStatusForThis = "ErrorConnecting"
            try { 
                $entryToParsePreCheck = $msEntryPreCheck 
                if ($entryToParsePreCheck -notmatch '^[a-zA-Z]+://') { $entryToParsePreCheck = "http://" + $entryToParsePreCheck }
                $uriBuilderPreCheck = [System.UriBuilder]$entryToParsePreCheck
                $msIPPreCheck = $uriBuilderPreCheck.Host
                if (-not ([string]::IsNullOrWhiteSpace($uriBuilderPreCheck.UserName))) {
                    $securePasswordPreCheck = $uriBuilderPreCheck.Password | ConvertTo-SecureString -AsPlainText -Force
                    $credentialPreCheck = New-Object System.Management.Automation.PSCredential($uriBuilderPreCheck.UserName, $securePasswordPreCheck)
                }
                $uriBuilderPreCheck.Path = "/dev/cfg/version"
                $uriBuilderPreCheck.Port = if ($uriBuilderPreCheck.Scheme -eq "https") { 443 } else { 80 } 
                $uriBuilderPreCheck.Password = $null
                $uriBuilderPreCheck.UserName = $null
                $versionUriPreCheck = $uriBuilderPreCheck.Uri.AbsoluteUri
                $script:completedPreChecks++
                Update-PreCheckToast -CheckName "Pre-Check: Checking Reachability $msIPPreCheck ($msPreCheckCounter/$totalMSsToCheck)" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed
                $responseObjectPreCheck = $null; $msVersionCheckSuccessPreCheck = $false
                $iwrParamsBasePreCheck = @{ TimeoutSec = 10; ErrorAction = 'Stop'; Method = 'Get' }
                if ($credentialPreCheck) { $iwrParamsBasePreCheck.Credential = $credentialPreCheck }
                $originalCallbackMSPre = $null; $callbackChangedMSPre = $false
                if ($SkipCertificateCheck.IsPresent) {
                    $originalCallbackMSPre = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                    $callbackChangedMSPre = $true
                }
                $oldProgressPreference = $ProgressPreference
                try {
                    $ProgressPreference = 'SilentlyContinue' # Suppress IWR progress for non-interactive
                    $iwrParamsPre = $iwrParamsBasePreCheck.Clone(); $iwrParamsPre.Uri = $versionUriPreCheck
                    Write-Log -Message "[MS Check] Attempting $($uriBuilderPreCheck.Scheme.ToUpper()) connection to $msIPPreCheck for version (Progress Silenced)..." -Level DEBUG
                    
                    # Conditionally add AllowUnencryptedAuthentication
                    if ($credentialPreCheck -and $uriBuilderPreCheck.Scheme -eq 'http') {
                        if ($PSVersionTable.PSVersion.Major -ge 6) {
                            $iwrParamsPre.AllowUnencryptedAuthentication = $true
                            Write-Log -Message "[MS Check] PS version >= 6. Adding -AllowUnencryptedAuthentication for HTTP pre-check for $msIPPreCheck." -Level DEBUG
                        } else {
                            Write-Log -Message "[MS Check] PS version < 6. Not adding -AllowUnencryptedAuthentication for HTTP pre-check for $msIPPreCheck. Basic Auth over HTTP might fail or be insecure." -Level WARN
                        }
                    }
                    $responseObjectPreCheck = Invoke-WebRequest @iwrParamsPre
                    $msVersionCheckSuccessPreCheck = $true
                } catch {
                     Write-Log -Message "[MS Check] Initial scheme $($uriBuilderPreCheck.Scheme.ToUpper()) failed for $msIPPreCheck ($($_.Exception.Message))." -Level DEBUG
                } finally {
                    if ($callbackChangedMSPre) {
                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallbackMSPre
                    }
                    $ProgressPreference = $oldProgressPreference # Restore original preference
                }
                if ($msVersionCheckSuccessPreCheck -and $responseObjectPreCheck) {
                    $script:completedPreChecks++
                    Update-PreCheckToast -CheckName "Pre-Check: Getting Version $msIPPreCheck ($msPreCheckCounter/$totalMSsToCheck)" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed
                    $xmlResponsePreCheck = [xml]$responseObjectPreCheck.Content
                    $currentMSInitialVersion = $xmlResponsePreCheck.LL.value
                    if ($null -eq $xmlResponsePreCheck -or $null -eq $xmlResponsePreCheck.LL -or $null -eq $currentMSInitialVersion) { 
                        $currentMSInitialVersion = "ErrorParsingXml"
                        throw "Could not find version value in parsed XML for $msIPPreCheck." 
                    }
                    Write-Log -Message "[MS Check] MS '$msIPPreCheck' current version: ${currentMSInitialVersion}" -Level INFO
                    $msStatusForThis = "UpToDate" 
                    $script:completedPreChecks++
                    Update-PreCheckToast -CheckName "Pre-Check: Comparing Version $msIPPreCheck ($msPreCheckCounter/$totalMSsToCheck)" -CurrentCheckNum $script:completedPreChecks -TotalChecks $script:totalPreChecks -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed
                    try {
                        if ([version](Convert-VersionString $currentMSInitialVersion) -ne [version]$LatestVersionNormalized) {
                            Write-Log -Message "[MS Check] MS '$msIPPreCheck' version '$currentMSInitialVersion' differs from target '$LatestVersionNormalized'. Update potentially needed." -Level INFO
                            $msUpdateNeededForThis = $true
                            $msStatusForThis = "NeedsUpdate"
                        }
                    } catch {
                        Write-Log -Message "[MS Check] Error comparing version '$currentMSInitialVersion' with target '$LatestVersionNormalized' for '$msIPPreCheck': $($_.Exception.Message)" -Level WARN
                        $msUpdateNeededForThis = $true 
                        $msStatusForThis = "ErrorComparingVersion"
                    }
                } else {
                    $currentMSInitialVersion = "ErrorConnecting" 
                    $msUpdateNeededForThis = $true 
                    $msStatusForThis = "ErrorConnecting"
                    Write-Log -Message "[MS Check] Connection failed for '$msIPPreCheck'. Assuming update potentially needed." -Level WARN
                }
            } catch { 
                Write-Log -Message "[MS Check] Error processing entry '$redactedEntryForLogPreCheck': $($_.Exception.Message)" -Level ERROR
                $msIPPreCheck = if ($msIPPreCheck) { $msIPPreCheck } else { $redactedEntryForLogPreCheck } 
                $currentMSInitialVersion = "ErrorProcessingEntry"
                $msUpdateNeededForThis = $true 
                $msStatusForThis = "ErrorProcessingEntry"
            }
            $msTargetEntry = [PSCustomObject]@{
                Name                = "MS $msIPPreCheck"
                Type                = "Miniserver"
                InitialVersion      = $currentMSInitialVersion
                TargetVersion       = if ($LatestVersionNormalized) { $LatestVersionNormalized.ToString() } else { $null }
                UpdateNeeded        = $msUpdateNeededForThis
                Status              = $msStatusForThis 
                UpdatePerformed     = $false
                VersionAfterUpdate  = $null
            }
            $UpdateTargetsInfo += $msTargetEntry
            Write-Log -Message "[MS Check] Added MS '$($msTargetEntry.Name)' to UpdateTargetsInfo: Initial='$($msTargetEntry.InitialVersion)', Target='$($msTargetEntry.TargetVersion)', UpdateNeeded='$($msTargetEntry.UpdateNeeded)', Status='$($msTargetEntry.Status)'" -Level DEBUG
        } 
    } catch { 
        Write-Log -Message "[MS Check] Error reading or processing MS list '$MSListPath': $($_.Exception.Message). Skipping MS version pre-check." -Level WARN
    } 
} else { 
    Write-Log -Message "[MS Check] MS list '$MSListPath' not found. Skipping MS version pre-check." -Level INFO
}
Write-Log -Message "[MS Check] Finished MS version pre-check." -Level INFO

$MSCount = ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver"}).Count

$script:totalPreChecks = 0; $script:completedPreChecks = 0
$preCheckChecksApp = 2; $preCheckChecksConfig = 2; $preCheckChecksMSList = 1; $preCheckChecksPerMS = 4  
$script:totalPreChecks += $preCheckChecksApp; Write-Log -Level DEBUG -Message "Pre-Checks: Added $preCheckChecksApp App checks."
$script:totalPreChecks += $preCheckChecksConfig; Write-Log -Level DEBUG -Message "Pre-Checks: Added $preCheckChecksConfig Config checks."
if (Test-Path $MSListPath) { $script:totalPreChecks += $preCheckChecksMSList; Write-Log -Level DEBUG -Message "Pre-Checks: Added $preCheckChecksMSList MS List read check."}
if ($MSCount -gt 0) { $script:totalPreChecks += ($MSCount * $preCheckChecksPerMS); Write-Log -Level DEBUG -Message "Pre-Checks: Added $($MSCount * $preCheckChecksPerMS) MS checks ($MSCount servers * $preCheckChecksPerMS checks/server)." } 
else { Write-Log -Level DEBUG -Message "Pre-Checks: No MS servers, skipping MS pre-check count." }
Write-Log -Level INFO -Message "Pre-Checks: Estimated total granular pre-checks: $($script:totalPreChecks)"

$ProgressSteps = @(
    @{ ID = 'InitialCheck';   Description = 'Checking versions';              Weight = 1; Condition = { $true } };
    @{ ID = 'DownloadConfig'; Description = 'Downloading Loxone Config';      Weight = 2; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
    @{ ID = 'ExtractConfig';  Description = 'Extracting Loxone Config';       Weight = 1; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
    @{ ID = 'InstallConfig';  Description = 'Installing Loxone Config';       Weight = 3; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
    @{ ID = 'VerifyConfig';   Description = 'Verifying Loxone Config install';Weight = 1; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
    @{ ID = 'DownloadApp';    Description = 'Downloading Loxone App';         Weight = 1; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded}).Count -gt 0 } };
    @{ ID = 'InstallApp';     Description = 'Installing Loxone App';          Weight = 1; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded}).Count -gt 0 } };
    @{ ID = 'UpdateMS';       Description = 'Updating Miniservers';           Weight = 0; Condition = { ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count -gt 0 } }; 
    @{ ID = 'Finalize';       Description = 'Finalizing';                     Weight = 1; Condition = { $true } }
)
function Get-StepWeight { param([string]$StepID); $stepObject = $ProgressSteps | Where-Object { $_.ID -eq $StepID } | Select-Object -First 1; if ($stepObject) { if ($stepObject.ContainsKey('Weight')) { return $stepObject.Weight } else { Write-Log -Level WARN -Message "Get-StepWeight: Found step with ID '$StepID' but it lacked a 'Weight' key."; return 0 } } else { Write-Log -Level WARN -Message "Get-StepWeight: Could not find step with ID '$StepID'."; return 0 } }

try { 
    Write-Log -Message "Calculating total progress weight..." -Level INFO; $script:TotalWeight = 0; $script:CurrentWeight = 0;
    foreach ($step in $ProgressSteps) { 
        $runStep = $false; try { $conditionResult = Invoke-Command -ScriptBlock $step.Condition; if ($step.ID -eq 'UpdateMS' -or ($step.Type -eq "Config" -or $step.Type -eq "App")) { $runStep = ($null -ne $conditionResult -and $conditionResult.Count -gt 0) } else { $runStep = [bool]$conditionResult } } catch { Write-Log -Message "Error evaluating condition for step '$($step.ID)': $($_.Exception.Message)" -Level WARN; $runStep = $false };
        if ($runStep) { 
            if ($step.ID -eq 'UpdateMS') { 
                $msToUpdateCount = ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count
                $msWeightPerServer = 2
                $script:TotalWeight += ($msToUpdateCount * $msWeightPerServer)
                Write-Log -Message "Condition TRUE for step '$($step.ID)'. Adding weight: $($msToUpdateCount * $msWeightPerServer) ($msToUpdateCount servers * $msWeightPerServer weight/server)." -Level DEBUG
            } else { $script:TotalWeight += $step.Weight; Write-Log -Message "Condition TRUE for step '$($step.ID)'. Adding weight: $($step.Weight)." -Level DEBUG } 
        } else { Write-Log -Message "Condition FALSE for step '$($step.ID)'. Skipping weight: $($step.Weight)." -Level DEBUG } 
    }
    $initialCheckStep = $ProgressSteps | Where-Object { $_.ID -eq 'InitialCheck' } | Select-Object -First 1; if ($initialCheckStep) { $script:CurrentWeight = $initialCheckStep.Weight; Write-Log -Message "Setting initial weight to $($script:CurrentWeight) for completed 'InitialCheck' step." -Level DEBUG }
    Write-Log -Message "Total calculated progress weight: $script:TotalWeight" -Level INFO

    $script:totalSteps = 1; $script:totalDownloads = 0
    Write-Log -Level DEBUG -Message "Recalculating steps/downloads..."
    if (($UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0) { $script:totalSteps += 3; $script:totalDownloads += 1; Write-Log -Level DEBUG -Message "Config update needed. Adding 3 steps, 1 download." } 
    else { Write-Log -Level DEBUG -Message "Config update NOT needed. Skipping Config steps/download." }
    if (($UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded}).Count -gt 0) { $script:totalSteps += 2; $script:totalDownloads += 1; Write-Log -Level DEBUG -Message "App update needed. Adding 2 steps, 1 download." } 
    else { Write-Log -Level DEBUG -Message "App update NOT needed. Skipping App steps/download." }
    if (($UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count -gt 0) { $script:totalSteps += 1; $msToUpdateForStepCount = ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count; Write-Log -Level DEBUG -Message "MS updates needed ($msToUpdateForStepCount servers). Adding 1 step for MS updates." } 
    else { Write-Log -Level DEBUG -Message "No MS updates needed." }
    $script:totalSteps += 1
    Write-Log -Level DEBUG -Message "Adding 1 step for Finalization."
    Write-Log -Level INFO -Message "Recalculated Totals - Steps: $script:totalSteps, Downloads: $script:totalDownloads"
    
    $LoxoneConfigExePathForMSUpdate = $script:InstalledExePath
    Write-Log -Message "[MS] Using initially determined Loxone Config path for potential MS update check: '$LoxoneConfigExePathForMSUpdate'" -Level INFO

    # --- Conditional Toast Initialization ---
    # Only initialize and show the first toast if an update is actually needed for Config or App, or if MS updates are pending.
    $anySoftwareUpdateNeeded = ($UpdateTargetsInfo | Where-Object { ($_.Type -eq "Config" -or $_.Type -eq "App") -and $_.UpdateNeeded }).Count -gt 0
    $anyMSUpdateNeeded = ($UpdateTargetsInfo | Where-Object { $_.Type -eq "Miniserver" -and $_.UpdateNeeded -and $_.Status -ne "AlreadyUpToDate" -and $_.Status -ne "UpToDate"}).Count -gt 0
# Conditional Early Exit: If no updates, non-interactive, and identified as launched by RunAsUser (via $invokedByRunAsUserLogic)
if (-not $anySoftwareUpdateNeeded -and -not $anyMSUpdateNeeded -and -not $script:IsInteractive -and $script:isSelfInvokedForUpdateCheck) {
    Write-Log -Message "No updates required and script is self-invoked non-interactively (ParentProcessCLI indicates 'UpdateLoxone.ps1'). Exiting script cleanly." -Level INFO
    Write-Log -Level DEBUG -Message "Executing minimal non-interactive (RunAsUser context) exit cleanup."
    Write-Log -Message "Attempting final download job cleanup..." -Level DEBUG; Write-Log -Message "Final download job cleanup finished." -Level DEBUG
    if ($global:LogFile) {
        Write-Log -Level DEBUG -Message "Attempting log rotation before non-interactive (RunAsUser context) exit..."
        try { Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount 24 -ErrorAction Stop | Out-Null }
        catch { Write-Log -Level WARN -Message ("Error during log rotation in non-interactive (RunAsUser context) exit: {0}" -f $_.Exception.Message) }
    }
    Exit-Function
    Exit 0
}
# --- End Conditional Early Exit ---

# --- Conditional Toast Initialization (Moved AFTER early exit) ---
if ($anySoftwareUpdateNeeded -or $anyMSUpdateNeeded) {
    # AppId should be initialized if Loxone Config is installed (done around line 532).
        # Now display the first persistent toast.
        Update-PersistentToast -IsInteractive $script:IsInteractive `
                               -ErrorOccurred $script:ErrorOccurred `
                               -AnyUpdatePerformed $anyUpdatePerformed `
                               -CallingScriptIsInteractive $script:IsInteractive `
                               -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck `
                               -StepName "Initializing Update Process..." `
                               -CurrentWeight 0 `
                               -TotalWeight $script:TotalWeight
        $script:currentStep = 1
        $initialCheckStepName = "Initial Checks Complete. Updates Pending."
        Write-Log -Level DEBUG -Message "Updating toast for step $($script:currentStep)/$($script:totalSteps): $initialCheckStepName"
        Update-PersistentToast -StepNumber $script:currentStep -TotalSteps $script:totalSteps -StepName $initialCheckStepName -CurrentWeight $script:CurrentWeight -TotalWeight $script:TotalWeight -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
    } else {
        Write-Log -Message "No updates required for Config, App, or Miniservers. Script will exit (after early exit check)." -Level INFO
        # No need to display progress toast if no updates are happening and script would have exited.
    }
    # --- End Conditional Toast Initialization ---

    $configTargetToUpdate = $UpdateTargetsInfo | Where-Object {$_.Type -eq "Config"} | Select-Object -First 1
    if ($configTargetToUpdate -and $configTargetToUpdate.UpdateNeeded) { # Ensure target exists before using
        $configTargetToUpdate.Status = "UpdateAttempted"
        $script:currentStep++; $script:currentDownload++
        $configDownloadStepName = "Downloading Loxone Config"
        Write-Log -Message "[Config] $configDownloadStepName (Step $($script:currentStep)/$($script:totalSteps), Download $($script:currentDownload)/$($script:totalDownloads))..." -Level INFO
        $processesToCheck = @("LoxoneConfig", "loxonemonitor", "LoxoneLiveView"); $anyProcessRunning = $false
        foreach ($procName in $processesToCheck) { if (Get-ProcessStatus -ProcessName $procName -StopProcess:$false) { $anyProcessRunning = $true; Write-Log -Message "Detected running process: $procName" -Level INFO } }
        if ($anyProcessRunning -and $SkipUpdateIfAnyProcessIsRunning) {
            Write-Log -Message "Skipping update because one or more Loxone processes are running and -SkipUpdateIfAnyProcessIsRunning was specified." -Level WARN
            $configTargetToUpdate.Status = "UpdateSkipped (ProcessRunning)"
            $toastParamsCfgSkipRunningPre = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Skipped: Loxone process running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsCfgSkipRunningPre -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            exit 0 
        }
        $skipDownload = $false; $skipExtraction = $false
        $configInstallerCheckResult = Test-ExistingInstaller -InstallerPath $InstallerPath -TargetVersion $LatestVersionNormalized -ComponentName "Config"
        if ($configInstallerCheckResult.IsValid) {
            $skipDownload = $true; $skipExtraction = $true 
            $toastParamsCfgSkipExisting = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Using Valid Existing Config Installer"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsCfgSkipExisting -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig'; $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
            Write-Log -Message "[Config] Added weight for skipped download and extraction based on valid existing installer. Current weight: $($script:CurrentWeight)." -Level DEBUG
        } elseif ($configInstallerCheckResult.Reason -ne "Not found") {
            Write-Log -Message "[Config] Existing installer '$InstallerPath' is invalid ($($configInstallerCheckResult.Reason)). Removing and proceeding with download." -Level WARN
            Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
        }
        if (-not $skipDownload) {
            $toastParamsCfgDownloadStart = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = $configDownloadStepName; DownloadFileName = $ZipFileName; DownloadNumber = $script:currentDownload; TotalDownloads = $script:totalDownloads; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
            Update-PersistentToast @toastParamsCfgDownloadStart -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            $downloadParams = @{ Url = $ZipUrl; DestinationPath = $ZipFilePath; ActivityName = "Downloading Loxone Config Update"; ExpectedCRC32 = $ExpectedCRC; ExpectedFilesize = $ExpectedZipSize; MaxRetries = 1; IsInteractive = $script:IsInteractive; StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = $configDownloadStepName; DownloadNumber = $script:currentDownload; TotalDownloads = $script:totalDownloads; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
            Write-Log -Message "[Config] Calling Invoke-LoxoneDownload for Config Update..." -Level DEBUG
            $downloadSuccess = Invoke-LoxoneDownload @downloadParams
            if (-not $downloadSuccess) { 
                $configTargetToUpdate.Status = "UpdateFailed (Download)"
                $configTargetToUpdate.UpdatePerformed = $true
                throw "Invoke-LoxoneDownload reported failure." 
            }
            $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig' 
            Write-Log -Message "[Config] Loxone Config ZIP download completed. Weight: $($script:CurrentWeight)." -Level INFO
            $toastParamsCfgDownloadVerify = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Verifying Config Download"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight; DownloadFileName = $ZipFileName; ProgressPercentage = 100 }
            Update-PersistentToast @toastParamsCfgDownloadVerify -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
        }
        if (-not $skipExtraction) {
            $extractStepName = "Extracting Config Installer"
            Write-Log -Message "[Config] $extractStepName..." -Level INFO
            $toastParamsCfgExtract = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = $extractStepName; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
            Update-PersistentToast @toastParamsCfgExtract -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            if (Test-Path $InstallerPath) { Write-Log -Level DEBUG -Message "Removing existing installer: $InstallerPath"; Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue }
            $originalProgressPreference = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'; try { Expand-Archive -Path $ZipFilePath -DestinationPath $DownloadDir -Force -ErrorAction Stop } finally { $ProgressPreference = $originalProgressPreference }
            if (-not (Test-Path $InstallerPath)) { $configTargetToUpdate.Status = "UpdateFailed (Extraction)"; $configTargetToUpdate.UpdatePerformed = $true; throw "Installer file '$InstallerPath' not found after extraction." }
            Write-Log -Message "[Config] Installer extracted to $InstallerPath." -Level INFO
            $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
            Write-Log -Message "[Config] Extraction weight added. Current: $($script:CurrentWeight)." -Level DEBUG
            $verifySigStepName = "Verifying Config Installer Signature"
            Write-Log -Message "[Config] $verifySigStepName (post-extraction)..." -Level INFO
            $toastParamsCfgVerifySig = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = $verifySigStepName; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
            Update-PersistentToast @toastParamsCfgVerifySig -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            if ($ExpectedXmlSignature) {
                 $sigCheckResult = Get-ExecutableSignature -ExePath $InstallerPath; $validationFailed = $false; $failureReason = ""
                 if (-not $sigCheckResult) { $validationFailed = $true; $failureReason = "Get-ExecutableSignature returned null." } 
                 elseif ($sigCheckResult.Status -ne 'Valid') { $validationFailed = $true; $failureReason = "Signature status is '$($sigCheckResult.Status)'." }
                 Write-Log -Level DEBUG -Message "Note: XML signature value ('$ExpectedXmlSignature') not validated against XML content."
                 if ($validationFailed) { $configTargetToUpdate.Status = "UpdateFailed (Signature)"; $configTargetToUpdate.UpdatePerformed = $true; throw "CRITICAL: Installer '$InstallerPath' signature validation failed: $failureReason" }
                 Write-Log -Message "[Config] Installer signature verified." -Level INFO
            } else { Write-Log -Message "[Config] XML Signature missing. Skipping installer signature validation." -Level WARN }
        } else { Write-Log -Message "[Config] Skipping extraction and signature check (valid existing installer)." -Level INFO }
        
        $script:currentStep++
        $configInstallStepName = "Installing Loxone Config"
        Write-Log -Message "[Config] $configInstallStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
        $installationSkippedDueToRunningProcess = $false
        $anyProcessRunning = $false
        foreach ($procName in $processesToCheck) { if (Get-ProcessStatus -ProcessName $procName -StopProcess:$false) { $anyProcessRunning = $true; Write-Log -Message "Detected process before install: $procName" -Level INFO } }
        if ($anyProcessRunning -and $SkipUpdateIfAnyProcessIsRunning) {
            Write-Log -Message "Skipping install: Loxone process running & -SkipUpdateIfAnyProcessIsRunning." -Level WARN
            $configTargetToUpdate.Status = "UpdateSkipped (ProcessRunningAtInstall)"
            $toastParamsCfgSkipRunningInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Skipped Install: Process running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsCfgSkipRunningInstall -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            $installationSkippedDueToRunningProcess = $true
        } elseif ($CloseApplications) {
            if ($anyProcessRunning) { 
                Write-Log -Message "[Config] Closing Loxone applications..." -Level INFO
                $toastParamsCfgCloseApps = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Closing Loxone Apps"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                Update-PersistentToast @toastParamsCfgCloseApps -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
                foreach ($procName in $processesToCheck) { Get-ProcessStatus -ProcessName $procName -StopProcess:$true }
                Write-Log -Message "[Config] Close requests sent." -Level INFO; Start-Sleep -Seconds 2 
            } else { Write-Log -Message "[Config] No relevant processes running." -Level INFO }
        } elseif ($anyProcessRunning) { 
             Write-Log -Message "[Config] Processes running, -CloseApplications not set. Install might fail." -Level WARN
             $toastParamsCfgWarnRunning = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="WARN: Processes running"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
             Update-PersistentToast @toastParamsCfgWarnRunning -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
        }
        if (-not $installationSkippedDueToRunningProcess) {
            Write-Log -Message "[Config] Running Loxone Config installer..." -Level INFO
            $toastParamsCfgInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName=$configInstallStepName; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsCfgInstall -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            $installArgs = "/$InstallMode"; Write-Log -Message "[Config] Executing: Start-Process '$InstallerPath' -Arg '$installArgs' -Wait" -Level DEBUG
            $installProcess = Start-Process -FilePath $InstallerPath -ArgumentList $installArgs -Wait -PassThru -ErrorAction Stop
            Write-Log -Message "[Config] Installer exited: $($installProcess.ExitCode)" -Level INFO
            $configTargetToUpdate.UpdatePerformed = $true
            if ($installProcess.ExitCode -ne 0) { 
                Write-Log -Message "[Config] Installer non-zero exit: $($installProcess.ExitCode)." -Level WARN
                $configTargetToUpdate.Status = "UpdateFailed (InstallerExitCode: $($installProcess.ExitCode))"
            } # Error status will be set here, verification will confirm or override
            $script:CurrentWeight += Get-StepWeight -StepID 'InstallConfig' 
            Write-Log -Message "[Config] Install weight added. Current: $($script:CurrentWeight)." -Level DEBUG
            $verifyInstallStepName = "Verifying Loxone Config Installation"
            Write-Log -Message "[Config] $verifyInstallStepName..." -Level INFO
            $toastParamsCfgVerifyInstall = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName=$verifyInstallStepName; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
            Update-PersistentToast @toastParamsCfgVerifyInstall -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            $NewInstalledExePath = Get-LoxoneExePath; $NewInstalledVersion = if ($NewInstalledExePath -and (Test-Path $NewInstalledExePath)) { (Get-Item $NewInstalledExePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion } else { "" }; $normalizedNewInstalled = Convert-VersionString $NewInstalledVersion
            if ($normalizedNewInstalled -eq $LatestVersionNormalized) {
                Write-Log -Message "[Config] Successfully updated Config to $NewInstalledVersion." -Level INFO
                $anyUpdatePerformed = $true; $script:configUpdated = $true; $LoxoneConfigExePathForMSUpdate = $NewInstalledExePath
                $configTargetToUpdate.VersionAfterUpdate = $NewInstalledVersion
                $configTargetToUpdate.Status = "UpdateSuccessful"
                $script:CurrentWeight += Get-StepWeight -StepID 'VerifyConfig' 
                Write-Log -Message "[Config] Verification weight added. Current: $($script:CurrentWeight)." -Level DEBUG
                $toastParamsCfgInstallComplete = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="Config Update Complete (v$NewInstalledVersion)"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                Update-PersistentToast @toastParamsCfgInstallComplete -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
            } else { # Verification failed even if installer exit code was 0
                 $errorMessage = "Config update verification failed! Expected '$($LatestVersionNormalized)', found '$($normalizedNewInstalled)'."
                 Write-Log -Message "[Config] $errorMessage" -Level ERROR
                 $configTargetToUpdate.Status = "UpdateFailed (Verification)"
                 $toastParamsCfgVerifyFail = @{ StepNumber=$script:currentStep; TotalSteps=$script:totalSteps; StepName="FAILED: Config verification!"; CurrentWeight=$script:CurrentWeight; TotalWeight=$script:TotalWeight }
                 Update-PersistentToast @toastParamsCfgVerifyFail -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
                 throw $errorMessage
            }
        }
    } else { 
         Write-Log -Message "[Config] Using existing installation for MS update: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
         $script:CurrentWeight += Get-StepWeight -StepID 'DownloadConfig'; $script:CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'; $script:CurrentWeight += Get-StepWeight -StepID 'InstallConfig'; $script:CurrentWeight += Get-StepWeight -StepID 'VerifyConfig'
         Write-Log -Message "[Config] Skipped steps weights added. Current: $($script:CurrentWeight)." -Level DEBUG
    }

# --- Step: Update MSs ---
$miniserversToUpdate = $UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}
$anyMSNeedsUpdateBasedOnTargets = ($null -ne $miniserversToUpdate -and $miniserversToUpdate.Count -gt 0)

if ($anyMSNeedsUpdateBasedOnTargets) {
    $script:currentStep++
    $msUpdateStepName = "Updating Miniservers ($($miniserversToUpdate.Count))"
    Write-Log -Message "[MS] $msUpdateStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
    $toastParamsMSUpdateStart = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = $msUpdateStepName; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
    Update-PersistentToast @toastParamsMSUpdateStart -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
    
    $updateMSResults = Update-MS -DesiredVersion $LatestVersionNormalized -MSListPath $MSListPath -LogFile $global:LogFile -MaxLogFileSizeMB $MaxLogFileSizeMB -DebugMode:$DebugMode -ScriptSaveFolder $ScriptSaveFolder -StepNumber $script:currentStep -TotalSteps $script:totalSteps -SkipCertificateCheck:$SkipCertificateCheck -IsInteractive $script:IsInteractive
    
    if ($null -ne $updateMSResults) {
        foreach ($msResult in $updateMSResults) {
            $targetToUpdate = $UpdateTargetsInfo | Where-Object { $_.Type -eq "Miniserver" -and $_.Name -eq "MS $($msResult.MSIP)" } | Select-Object -First 1
            if ($targetToUpdate) {
                $targetToUpdate.UpdatePerformed = $msResult.AttemptedUpdate # From Update-MS's internal logic
                $targetToUpdate.VersionAfterUpdate = $msResult.VersionAfterUpdate # From Update-MS
                
                if ($msResult.UpdateSucceeded) {
                    $targetToUpdate.Status = "UpdateSuccessful"
                    $anyUpdatePerformed = $true 
                } elseif ($msResult.StatusMessage -eq "AlreadyUpToDate") {
                     $targetToUpdate.Status = "UpToDate" 
                     $targetToUpdate.VersionAfterUpdate = $msResult.InitialVersion 
                     $targetToUpdate.UpdatePerformed = $false # Explicitly set as no update was performed by Update-MS
                } else { 
                    $targetToUpdate.Status = if ($msResult.StatusMessage) { $msResult.StatusMessage } else { "UpdateFailed" } # Use detailed or generic
                }
                Write-Log -Message "[MS Update] Processed result for $($targetToUpdate.Name): Initial='$($targetToUpdate.InitialVersion)', Target='$($targetToUpdate.TargetVersion)', Status='$($targetToUpdate.Status)', VersionAfterUpdate='$($targetToUpdate.VersionAfterUpdate)'" -Level DEBUG
            } else {
                Write-Log -Message "[MS Update] Could not find MS '$($msResult.MSIP)' in UpdateTargetsInfo to update status." -Level WARN
            }
        }
    }

    if (-not $script:ErrorOccurred) { 
         $msWeightPerServer = 2 
         $processedMSCount = if ($updateMSResults) { $updateMSResults.Count } else { 0 } 
         $msTotalWeight = $processedMSCount * $msWeightPerServer
         $script:CurrentWeight += $msTotalWeight
         Write-Log -Message "[MS] Added weight for MS updates ($processedMSCount servers). Current weight: $($script:CurrentWeight)." -Level DEBUG
         $toastParamsMSUpdateComplete = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "MS Updates Processed"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
         Update-PersistentToast @toastParamsMSUpdateComplete -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
    }
} else {
    Write-Log -Message "[MS] Skipping MS update step: No Miniservers identified as needing an update." -Level INFO
    $msCheckedCount = ($UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver"}).Count
    if ($msCheckedCount -gt 0) {
        $msWeightPerServer = 2; $msTotalSkippedWeight = $msCheckedCount * $msWeightPerServer
        $script:CurrentWeight += $msTotalSkippedWeight
        Write-Log -Message "[MS] Added weight for skipped MS update step ($msCheckedCount servers checked). Current weight: $($script:CurrentWeight)." -Level DEBUG
    }
    $toastParamsMSSkip = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "MSs: No updates needed"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
    Update-PersistentToast @toastParamsMSSkip -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
}

# --- Finalization Step ---
$script:currentStep = $script:totalSteps 
$finalStepName = "Finalizing"
Write-Log -Message "[Main] $finalStepName (Step $($script:currentStep)/$($script:totalSteps))..." -Level INFO
$anyUpdatePerformed = ($UpdateTargetsInfo | Where-Object {$_.UpdatePerformed -eq $true}).Count -gt 0
Write-Log -Message "Update Status - Any Update Performed (based on UpdateTargetsInfo): $anyUpdatePerformed" -Level INFO

# --- DEBUG: Inspect UpdateTargetsInfo for Miniservers before filtering ---
        Write-Log -Level DEBUG -Message "[MS Update Decision] Inspecting `$UpdateTargetsInfo for Miniservers..."
        $allMSInTargets = $UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver"}
        Write-Log -Level DEBUG -Message "[MS Update Decision] Total MS entries in `$UpdateTargetsInfo: $($allMSInTargets.Count)"
        foreach ($msEntryDebug in $allMSInTargets) {
            Write-Log -Level DEBUG -Message ("[MS Update Decision] Entry: Name='{0}', Type='{1}', InitialVersion='{2}', TargetVersion='{3}', UpdateNeeded='{4}', Status='{5}'" -f $msEntryDebug.Name, $msEntryDebug.Type, $msEntryDebug.InitialVersion, $msEntryDebug.TargetVersion, $msEntryDebug.UpdateNeeded, $msEntryDebug.Status)
        }
        if ($DebugMode) {
            Write-Log -Level DEBUG -Message ("[MS Update Decision] Full `$UpdateTargetsInfo object dump:`n" + ($UpdateTargetsInfo | Format-List | Out-String))
        }
        # --- END DEBUG ---
if (-not $script:ErrorOccurred) {
     $script:CurrentWeight += Get-StepWeight -StepID 'Finalize'
     $script:CurrentWeight = [Math]::Min($script:CurrentWeight, $script:TotalWeight)
     Write-Log -Message "[Main] Added weight for finalization. Final weight: $($script:CurrentWeight)/$($script:TotalWeight)." -Level DEBUG
     $toastParamsFinal = @{ StepNumber = $script:currentStep; TotalSteps = $script:totalSteps; StepName = "Loxone Update Process Finished"; CurrentWeight = $script:CurrentWeight; TotalWeight = $script:TotalWeight }
     Update-PersistentToast @toastParamsFinal -IsInteractive $script:IsInteractive -ErrorOccurred $script:ErrorOccurred -AnyUpdatePerformed $anyUpdatePerformed -CallingScriptIsInteractive $script:IsInteractive -CallingScriptIsSelfInvoked $script:isSelfInvokedForUpdateCheck
}

} # --- End of Main Try Block ---
catch {
    $script:ErrorOccurred = $true
    $script:LastErrorLine = if ($_.InvocationInfo) { try { $_.InvocationInfo.ScriptLineNumber } catch { 0 } } else { 0 }
    $exceptionMessage = try { $_ | Out-String } catch { "Could not retrieve full error object." }
    $commandName = if ($_.InvocationInfo) { try { $_.InvocationInfo.MyCommand.ToString() -as [string] } catch { "N/A" } } else { "N/A" }
    $scriptName = if ($_.InvocationInfo) { try { $_.InvocationInfo.ScriptName -as [string] } catch { "N/A" } } else { "N/A" }
    $lineContent = if ($_.InvocationInfo) { try { $_.InvocationInfo.Line -as [string] } catch { "N/A" } } else { "N/A" }
    $errorMessage = "An unexpected error occurred: $exceptionMessage"; $errorDetails = "Error: $exceptionMessage`nScript: $scriptName`nLine: $script:LastErrorLine`nCommand: $commandName`nLine Content: $lineContent"
    Write-Log -Message $errorMessage -Level ERROR; Write-Log -Message "--- Error Details ---`n$errorDetails`n--- End Error Details ---" -Level ERROR
    if ($_.ScriptStackTrace) { $exceptionStackTrace = try { $_.ScriptStackTrace -as [string] } catch { "Could not retrieve stack trace." }; Write-Log -Message "--- StackTrace ---`n$exceptionStackTrace`n--- End StackTrace ---" -Level ERROR }
    $finalErrorMsg = "FAILED: An unexpected error occurred. Check logs. (Line: $script:LastErrorLine)"
    $logPathToShowOnError = $null
    if ($global:LogFile) { try { $logPathToShowOnError = Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount 24 -ErrorAction Stop } catch { Write-Log -Level WARN -Message "Error during log rotation in CATCH block: $($_.Exception.Message)" } }
    Show-FinalStatusToast -StatusMessage $finalErrorMsg -Success:$false -LogFileToShow $logPathToShowOnError
    Write-Log -Level Debug -Message "Pausing briefly after failure toast update..."
    Start-Sleep -Seconds 3
    exit 1
} finally {
    Write-Log -Level DEBUG -Message "Executing Finally block."
    Write-Log -Message "Attempting final download job cleanup..." -Level DEBUG; Write-Log -Message "Final download job cleanup finished." -Level DEBUG
    Exit-Function 
} 

# --- Final Exit Code Handling ---
Write-Log -Message "Preparing final status notification." -Level DEBUG
$logPathToShow = $null
if ($global:LogFile) {
    Write-Log -Level DEBUG -Message "Attempting final log rotation before success/summary toast..."
    try {
        $maxArchives = 24 
        if ($PSBoundParameters.ContainsKey('MaxLogFileSizeMB')) { Write-Log -Level DEBUG -Message "Using default MaxArchiveCount: $maxArchives" }
        $logPathToShow = Invoke-LogFileRotation -LogFilePath $global:LogFile -MaxArchiveCount $maxArchives -ErrorAction Stop
        Write-Log -Level DEBUG -Message "Log rotation returned archive path: '$($logPathToShow)'"
    } catch {
        Write-Log -Level WARN -Message "Error during final log rotation: $($_.Exception.Message). Archive path might be null."
    }
} else {
    Write-Log -Level WARN -Message "Skipping final log rotation as Global:LogFile is not set."
}

# --- Construct Final Summary Message ---
Write-Log -Message "Constructing final summary notification message using UpdateTargetsInfo." -Level INFO
$summaryLines = @()

foreach ($target in $UpdateTargetsInfo) {
    $line = ""
    $processedName = $target.Name
    if (($target.Type -eq "App" -or $target.Type -eq "Config") -and $target.Name.StartsWith("Loxone ")) {
        $processedName = $target.Name.Substring("Loxone ".Length)
    }
    $targetNameDisplay = if ($target.Type -eq "Miniserver") { "$($processedName) ($Channel)" } elseif ($target.Type -eq "App") { "$($processedName) ($selectedAppChannelName)" } else { "$($processedName) ($Channel)" }

    switch ($target.Status) {
        "UpdateSuccessful" {
            $line = "${targetNameDisplay}: Updated to $($target.VersionAfterUpdate)"
        }
        "UpToDate" {
            $line = "${targetNameDisplay}: Up-to-date $($target.InitialVersion)"
        }
        "NeedsUpdate" { 
            if ($target.UpdatePerformed -eq $false) {
                 $line = "${targetNameDisplay}: Update skipped (Target: $($target.TargetVersion), Was: $($target.InitialVersion))"
            } else { 
                 $line = "${targetNameDisplay}: Status pending (Initial: $($target.InitialVersion), Target: $($target.TargetVersion))"
            }
        }
        "UpdateFailed" { 
             $line = "${targetNameDisplay}: Update Failed (Target: $($target.TargetVersion), Still at: $($target.VersionAfterUpdate))"
        }
        {$_ -like "UpdateFailed*"} { 
             $line = "${targetNameDisplay}: Update Failed (Target: $($target.TargetVersion), Still at: $($target.VersionAfterUpdate)) - Reason: $($target.Status)"
        }
        "NotInstalled" {
            $line = "${targetNameDisplay}: Not found (Target: $($target.TargetVersion))"
        }
        "ErrorConnecting" {
             $line = "${targetNameDisplay}: Error connecting (Target: $($target.TargetVersion))"
        }
        "ErrorParsingXml" {
             $line = "${targetNameDisplay}: Error parsing version XML (Target: $($target.TargetVersion))"
        }
        "ErrorComparingVersion" {
             $line = "${targetNameDisplay}: Error comparing versions (Initial: $($target.InitialVersion), Target: $($target.TargetVersion))"
        }
         "ErrorProcessingEntry" {
             $line = "${targetNameDisplay}: Error processing entry (Target: $($target.TargetVersion))"
        }
        "UpdateSkipped (ProcessRunning)" {
            $line = "${targetNameDisplay}: Update skipped (Loxone process was running)"
        }
        "UpdateAttempted" { 
            $line = "${targetNameDisplay}: Update attempted, outcome unclear (Target: $($target.TargetVersion), Initial: $($target.InitialVersion), After: $($target.VersionAfterUpdate))"
        }
        default {
            $line = "${targetNameDisplay}: Status '$($target.Status)' (Initial: $($target.InitialVersion), Target: $($target.TargetVersion), After: $($target.VersionAfterUpdate))"
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($line)) {
        $summaryLines += $line
    }
}

$summaryLines = $summaryLines | Sort-Object
$finalMessage = $summaryLines -join "`n"
$finalSuccess = (-not $script:ErrorOccurred)

if ($finalSuccess -and $script:CurrentWeight -lt $script:TotalWeight) {
    $script:CurrentWeight = $script:TotalWeight
}

Write-Log -Message "Final Summary:`n$finalMessage" -Level Info

$isInteractiveEnv = [Environment]::UserInteractive
Write-Log -Message "Toast Conditions Check: ErrorOccurred=$($script:ErrorOccurred), IsInteractiveEnv=$isInteractiveEnv, AnyUpdatePerformed=$anyUpdatePerformed" -Level DEBUG
if ($script:ErrorOccurred -or $script:IsInteractive -or (-not $script:IsInteractive -and $anyUpdatePerformed)) {
    Write-Log -Message "Showing final status toast based on conditions." -Level INFO
    Show-FinalStatusToast -StatusMessage $finalMessage -Success $finalSuccess -LogFileToShow $logPathToShow
} else {
    Write-Log -Message "Skipping final status toast (Non-interactive, no error, no update performed)." -Level INFO
}

if ($script:ErrorOccurred) {
    Write-Log -Message "Script finished with errors. Exit Code: 1" -Level ERROR
    Exit 1
} else {
    Write-Log -Level INFO -Message "Script finished successfully. Exit Code: 0"
    Exit 0
}
# End of script

