[CmdletBinding()]
param(
    [Parameter()][ValidateSet("Release", "Beta", "Test", IgnoreCase = $true)] [string]$Channel = "Test",
    [Parameter()] [object]$DebugMode = $false,
    [Parameter()] [object]$EnableCRC = $true,
    [Parameter()][ValidateSet("silent", "verysilent", IgnoreCase = $true)] [string]$InstallMode = "verysilent",
    [Parameter()] [object]$CloseApplications = $false,
    # Default will be overridden below by the script's own location.
    [Parameter()] [string]$ScriptSaveFolder = "$env:USERPROFILE\Scripts",
    [Parameter()] [int]$MaxLogFileSizeMB = 1,
    [Parameter()] [int]$ScheduledTaskIntervalMinutes = 10,
    [Parameter()] [object]$SkipUpdateIfAnyProcessIsRunning = $false,
    [Parameter()] [switch]$TestNotifications = $false,
    [Parameter()] [int]$MonitorLogWatchTimeoutMinutes = 240,
    [Parameter()] [switch]$TestMonitor = $false,
    [Parameter()] [string]$MonitorSourceLogDirectory = $null, # Optional: Specify custom path for monitor logs
    [Parameter()] [switch]$TestKill = $false, # Pause script for external termination test
    [Parameter()] [switch]$SetupSystemMonitor = $false # Special mode to start monitor as SYSTEM for testing
)

# Immediately convert parameters to proper Boolean types.
$DebugMode = [bool]$DebugMode
$EnableCRC = [bool]$EnableCRC
$CloseApplications = [bool]$CloseApplications
$SkipUpdateIfAnyProcessIsRunning = [bool]$SkipUpdateIfAnyProcessIsRunning

# Set VerbosePreference based on DebugMode.
if ($DebugMode) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

###############################################################################
#                           FUNCTION DEFINITIONS                              #
###############################################################################

#region Logging Functions
function Write-DebugLog {
    param(
        [string]$Message,
        [switch]$ErrorMessage
    )
    if (-not $DebugMode) { return }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = "DEBUG"
    if ($ErrorMessage) { $prefix = "ERROR" }
    $logEntry = "$timestamp [$prefix] $Message"
    if ($ErrorMessage) {
        Write-Host "ERROR: $Message" -ForegroundColor Red
    }
    else {
        Write-Host "DEBUG: $Message"
    }
    if ($global:LogFile) {
        try {
            $logEntry | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
        }
        catch {
            Write-Host "ERROR: Could not write to log file '${global:LogFile}'. Exception: ${($_.Exception.Message)}" -ForegroundColor Red
        }
    }
}

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [int]$ErrorCode = $null
    )
    if ([string]::IsNullOrWhiteSpace($Message)) { $Message = "<Empty Message>" }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    try {
        if (-not (Test-Path $global:LogFile)) {
            $logEntry | Out-File -FilePath $global:LogFile -Encoding UTF8 -Force
        }
        else {
            $logEntry | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
        }
    }
    catch {
        Write-Host "ERROR: Failed to write to log file '${global:LogFile}': $($_.Exception.Message)}" -ForegroundColor Red
    }
    switch ($Level.ToUpper()) {
        "DEBUG" { if ($DebugMode) { Write-Verbose $logEntry } }
        "INFO"  { Write-Host $logEntry -ForegroundColor Green }
        "WARN"  { Write-Warning $logEntry }
        # Use Write-Warning for ERROR level to avoid script termination by default Write-Error behavior
        "ERROR" { Write-Warning "ERROR: $Message" } # Prepend ERROR to distinguish from normal warnings
    }
}

# -----------------------------------------------------------
# Force the script’s own folder as the base.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ScriptSaveFolder = $scriptDir
Write-DebugLog -Message "Script directory determined as: ${scriptDir}"
# -----------------------------------------------------------

# Ensure ScriptSaveFolder is defined.
if ([string]::IsNullOrWhiteSpace($ScriptSaveFolder)) {
    $ScriptSaveFolder = "$env:USERPROFILE\Scripts"
}

# Initialize the global log file path early.
$global:LogFile = Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxone.log"
$global:ErrorOccurred = $false  # Correctly initialized *OUTSIDE* the try block
$global:LastErrorLine = "N/A"    # Correctly initialized *OUTSIDE* the try block
$global:UacCancelled = $false # Flag for UAC prompt cancellation
$global:ScriptInterrupted = $false # Flag for Ctrl+C


#region Log Rotation
function Invoke-LogFileRotation {
    param(
        [string]$LogPath,
        [int]$MaxArchives = 24
    )
    if (Test-Path $LogPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $archivePath = ($LogPath -replace "\.log$", "_${timestamp}.log")
        try {
            Rename-Item -Path $LogPath -NewName $archivePath -Force
            Write-DebugLog -Message "Log file rotated to '${archivePath}'."
        }
        catch {
            Write-DebugLog -Message "Error rotating log file: ${($_.Exception.Message)}" -ErrorMessage
        }
    }
    $logDir = Split-Path -Path $LogPath
    $pattern = [System.IO.Path]::GetFileNameWithoutExtension($LogPath) + "_*.log"
    $archives = Get-ChildItem -Path $logDir -Filter $pattern | Sort-Object LastWriteTime
    if ($archives.Count -gt $MaxArchives) {
        $toDelete = $archives | Select-Object -First ($archives.Count - $MaxArchives)
        foreach ($file in $toDelete) {
            try {
                Remove-Item -Path $file.FullName -Force
            }
            catch {
                Write-DebugLog -Message "Failed to remove old archive '${file.FullName}': ${($_.Exception.Message)}" -ErrorMessage
            }
        }
    }
}
#endregion

#region Get-InstalledVersion Function
function Get-InstalledVersion {
    param([string]$ExePath)
    if (-not $ExePath.EndsWith(".exe")) {
        $ExePath = Join-Path -Path $ExePath -ChildPath "LoxoneConfig.exe"
    }
    if (Test-Path $ExePath) {
        try {
            $version = (Get-Item $ExePath).VersionInfo.FileVersion
            $version = $version.Trim()
            Write-LogMessage "Found version of ${ExePath}: ${version}" -Level "INFO"
            return $version
        }
        catch {
            Write-LogMessage "Error retrieving version from ${ExePath}: ${($_.Exception.Message)}" -Level "WARN"
           # throw $_ #Removed to continue if file not found
		   Return $null
        }
    }
    else {
        Write-LogMessage "Installed application not found at ${ExePath}." -Level "WARN" #changed to warn
        #throw "Installed application not found at ${ExePath}." #Removed to continue if file not found
		Return $null    # <<< CHANGED: Return $null
    }
}
#endregion

#region Start-LoxoneUpdateInstaller Function
function Start-LoxoneUpdateInstaller {
    param(
        [string]$InstallerPath,
        [string]$InstallMode
    )
    Write-LogMessage "Starting update installer: ${InstallerPath} with install mode ${InstallMode}." -Level "INFO"
    try {
        Start-Process -FilePath $InstallerPath -ArgumentList "/${InstallMode}" -Wait
        Write-LogMessage "Update installer executed successfully." -Level "INFO"
    }
    catch {
        Write-LogMessage "Error executing update installer: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}
#endregion

#region CRC32 Class and Get-CRC32 Function
$crc32Code = @"
using System;
public class CRC32
{
    private static readonly uint[] Table;
    static CRC32()
    {
        uint polynomial = 0xedb88320;
        Table = new uint[256];
        uint crc;
        for (uint i = 0; i < Table.Length; ++i)
        {
            crc = i;
            for (int j = 0; j < 8; ++j)
            {
                if ((crc & 1) == 1)
                    crc = (crc >> 1) ^ polynomial;
                else
                    crc >>= 1;
            }
        }
    }
    public static uint Compute(byte[] bytes)
    {
        uint crc = 0xffffffff;
        foreach (byte b in bytes)
        {
            byte index = (byte)((crc & 0xff) ^ b);
            crc = (crc >> 8) ^ Table[index];
        }
        return ~crc;
    }
}
"@
if (-not ([System.Management.Automation.PSTypeName]"CRC32").Type) {
    try {
        Add-Type -TypeDefinition $crc32Code -Language CSharp -ErrorAction Stop
        Write-LogMessage "Successfully loaded CRC32 class." "DEBUG"
    }
    catch {
        Write-LogMessage "Failed to load CRC32 class: $($_.Exception.Message)" "ERROR" -ErrorCode 1
        throw $_
    }
} else {
    Write-DebugLog -Message "CRC32 class already loaded. Skipping Add-Type."
}

function Get-CRC32 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile
    )
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($InputFile)
        Write-DebugLog -Message "Read $($fileBytes.Length) bytes from file '${InputFile}'."
        $crc = [CRC32]::Compute($fileBytes)
        $crcString = $crc.ToString("X8")
        Write-DebugLog -Message "Calculated CRC32 for '${InputFile}': ${crcString}"
        return $crcString
    }
    catch {
        Write-LogMessage "Error calculating CRC32 for ${InputFile}: ${($_.Exception.Message)}" -Level "ERROR" -ErrorCode 2
        throw $_
    }
}
#endregion

#region Show-NotificationToLoggedInUsers Function
function Show-NotificationToLoggedInUsers {
    param(
        [string]$Title,
        [string]$Message,
        [int]$Timeout = 0, # Timeout parameter is no longer directly used by BurntToast via task
        [string]$AppId = 'WindowsPowerShell' # AppId parameter is no longer directly used by BurntToast via task
    )

    # Check if running interactively (not as scheduled task)
    $isRunningAsTask = Test-ScheduledTask
    Write-DebugLog "Is running as scheduled task: $isRunningAsTask"

    if (-not $isRunningAsTask) {
        # Running interactively, try direct notification
        Write-LogMessage "Running interactively. Attempting direct notification." -Level "INFO"
        try {
            # Ensure BurntToast is available in the current session
             if (-not (Get-Module -ListAvailable -Name BurntToast)) {
                 Write-LogMessage "BurntToast module not found. Attempting to install for current user." -Level "WARN"
                 # Note: This might require internet access and permissions
                 Install-Module -Name BurntToast -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction SilentlyContinue
             }
             Import-Module BurntToast -ErrorAction SilentlyContinue
             $appLogoPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe" # Use PowerShell icon
             New-BurntToastNotification -AppLogo $appLogoPath -Text $Title, $Message -ErrorAction Stop
             Write-LogMessage "Direct notification sent successfully." -Level "INFO"
             return # Exit function after successful direct notification
        } catch {
            Write-LogMessage "Direct notification failed: $($_.Exception.Message). Falling back to scheduled task method." -Level "WARN"
            # Proceed to the scheduled task method below if direct fails
        }
    }

    # --- Existing Logic for Scheduled Task or Fallback ---
    Write-LogMessage "Attempting notification via scheduled task method." -Level "INFO"
    # Find active, interactive user sessions
    $activeSessions = @()
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType = 2" # LogonType 2 = Interactive
        foreach ($session in $sessions) {
            $assocAccounts = Get-CimAssociatedInstance -InputObject $session -ResultClassName Win32_Account -ErrorAction SilentlyContinue
            if ($assocAccounts) {
                # Check if the session is actually active using quser (more reliable for state)
                $quserOutput = quser.exe $session.LogonId 2>$null | Out-String
                if ($quserOutput -match '\s+Active\s*$') {
                    $userPrincipal = New-Object System.Security.Principal.NTAccount($assocAccounts[0].Domain, $assocAccounts[0].Name)
                    $activeSessions += [PSCustomObject]@{
                        SessionId = $session.LogonId
                        UserName = $assocAccounts[0].Name
                        Domain = $assocAccounts[0].Domain
                        UserSID = $userPrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        Principal = "$($assocAccounts[0].Domain)\$($assocAccounts[0].Name)"
                    }
                    Write-DebugLog "Found active interactive session: $($assocAccounts[0].Domain)\$($assocAccounts[0].Name) (Session ID: $($session.LogonId))"
                }
            }
        }
    } catch {
        Write-LogMessage "Error querying user sessions: $($_.Exception.Message)" -Level "WARN"
        # Fallback or decide how to handle if session query fails
    }


    if ($activeSessions.Count -gt 0) {
        # Ensure BurntToast module is available (best effort check, user context install might differ)
        if (-not (Get-Module -ListAvailable -Name BurntToast)) {
             Write-LogMessage "BurntToast module not found. Notifications may fail if not installed for target users." -Level "WARN"
             # Attempting install here as SYSTEM likely won't help the user context.
             # Consider adding prerequisite checks/documentation instead.
        }

        $appLogoPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

        foreach ($userSession in $activeSessions) {
            $taskName = "TempLoxoneToastNotification_$($userSession.UserName)_$(Get-Date -Format 'yyyyMMddHHmmssfff')"
            $principal = $userSession.Principal
            Write-LogMessage "Attempting to send notification to user '$principal' via temporary scheduled task '$taskName'." -Level "INFO"

            # Escape single quotes for the command string
            $escapedTitle = $Title -replace "'", "''"
            $escapedMessage = $Message -replace "'", "''"

            # Define the action for the temporary task
            $actionCommand = "Import-Module BurntToast -ErrorAction SilentlyContinue; New-BurntToastNotification -AppLogo '$appLogoPath' -Text '$escapedTitle', '$escapedMessage' -ErrorAction SilentlyContinue"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -Command `"$actionCommand`""

            # Define the trigger (run immediately)
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)

            # Define settings
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

            try {
                # Register the task to run as the target user
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -RunLevel Limited -Force -ErrorAction Stop
                Write-DebugLog "Registered temporary task '$taskName' for user '$principal'."

                # Start the task immediately
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                Write-LogMessage "Triggered temporary notification task '$taskName' for user '$principal'." -Level "INFO"

            } catch {
                Write-LogMessage "Failed to register or start temporary notification task '$taskName' for user '$principal': $($_.Exception.Message)" -Level "ERROR"
            } finally {
                # IMPORTANT: Clean up the temporary task regardless of success/failure
                Start-Sleep -Seconds 1 # Brief pause to allow task scheduler service to potentially catch up
                try {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                    Write-DebugLog "Unregistered temporary task '$taskName'."
                } catch {
                    Write-LogMessage "Failed to unregister temporary task '$taskName': $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
    }
    else {
         Write-LogMessage "No active interactive user sessions found to display the notification." -Level "WARN"
    }
}
#endregion

#region Invoke-ScriptErrorHandling Function # Changed from Handle-ScriptError
function Invoke-ScriptErrorHandling { # Changed from Handle-ScriptError
    param(
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )
    if (-not $ErrorRecord) { $ErrorRecord = $Error[0] }
    $invInfo = $ErrorRecord.InvocationInfo
    $command = if ($invInfo -and $invInfo.MyCommand) { $invInfo.MyCommand.ToString() } else { "N/A" }
    $scriptName = if ($invInfo -and $invInfo.ScriptName) { $invInfo.ScriptName } else { "N/A" }
    $lineNumber = if ($invInfo -and $invInfo.ScriptLineNumber) { $invInfo.ScriptLineNumber } else { "N/A" }
    $line = if ($invInfo -and $invInfo.Line) { $invInfo.Line } else { "N/A" }
    $position = if ($invInfo -and $invInfo.PositionMessage) { $invInfo.PositionMessage } else { "N/A" }
    $fullCommandLine = if ($line) { $line.Trim() } else { "N/A" }
    
    # Retrieve all local variables from caller scope
    $localVars = Get-Variable -Scope 1 | ForEach-Object { "$($_.Name) = $($_.Value)" } | Out-String

    Write-DebugLog -Message "ERROR in command: ${command}" -ErrorMessage
    Write-DebugLog -Message "Script: ${scriptName}" -ErrorMessage
    Write-DebugLog -Message "Line number: ${lineNumber}" -ErrorMessage
    Write-DebugLog -Message "Offending line: ${line}" -ErrorMessage
    Write-DebugLog -Message "Position details: ${position}" -ErrorMessage
    Write-DebugLog -Message "Full command line: ${fullCommandLine}" -ErrorMessage
    Write-DebugLog -Message "Local variables in scope:`n${localVars}" -ErrorMessage

    Show-NotificationToLoggedInUsers -Title "Loxone AutoUpdate Failed!" -Message "Error: ${($ErrorRecord.Exception.Message)}`nCommand: ${command}`nLine: ${lineNumber}`nCommandLine: ${fullCommandLine}`nLocal Variables:`n${localVars}" -Timeout 0

    Write-LogMessage "SCRIPT ERROR: ${($ErrorRecord.Exception.Message)}" -Level "ERROR"
    if ($invInfo) {
        Write-LogMessage "Error occurred in command: ${command} at ${scriptName} : line ${lineNumber}" -Level "ERROR"
        Write-LogMessage "Offending line: ${line}" -Level "ERROR"
        Write-LogMessage "Position: ${position}" -Level "ERROR"
        Write-LogMessage "Full command line: ${fullCommandLine}" -Level "ERROR"
        Write-LogMessage "Local variables in scope:`n${localVars}" -Level "ERROR"
    }
    if ($ErrorRecord.Exception.StackTrace) {
        Write-LogMessage "Stack Trace:`n${($ErrorRecord.Exception.StackTrace)}" -Level "ERROR"
    }
    else {
        Write-LogMessage "No .NET stack trace available." -Level "ERROR"
    }
    
	$global:ErrorOccurred = $true # Added back
    $global:LastErrorLine = $lineNumber # Added back
    
    Write-LogMessage "Script execution terminated = $global:ErrorOccurred due to the above error on line $global:LastErrorLine." -Level "ERROR"
    exit 1
}
#endregion

#region Get-ProcessStatus, Test-ScheduledTask, Start-ProcessInteractive  # Changed from Check-ProcessRunning, Is-RunningAsScheduledTask, Start-ProcessInteractive
function Get-ProcessStatus {  # Changed from Check-ProcessRunning
    param(
        [Parameter(Mandatory = $true)] [string]$ProcessName,
        [switch]$StopProcess
    )
    try {
        $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        if ($processes) {
            Write-LogMessage "Process '${ProcessName}' is running." -Level "INFO"
            if ($StopProcess) {
                foreach ($proc in $processes) {
                    try {
                        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                        Write-LogMessage "Process '${ProcessName}' (PID: $($proc.Id)) stopped." -Level "INFO"
                    }
                    catch {
                        Write-LogMessage "Failed to stop process '${ProcessName}' (PID: $($proc.Id)): ${($_.Exception.Message)}" -Level "ERROR"
                        throw $_
                    }
                }
            }
            return $true
        }
        else {
            Write-LogMessage "Process '${ProcessName}' is not running." -Level "INFO"
            return $false
        }
    }
    catch {
        Write-LogMessage "Error checking process '${ProcessName}': ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}

function Test-ScheduledTask { # Changed from Is-RunningAsScheduledTask
    try {
        $parentProcessId = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId
        $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId"
        $parentProcessName = $parentProcess.Name
        Write-DebugLog -Message "Parent process for PID $PID is ${parentProcessName} (PID: ${parentProcessId})"
        if ($parentProcessName -ieq "taskeng.exe" -or $parentProcessName -ieq "svchost.exe") { return $true } else { return $false }
    }
    catch { return $false }
}

function Start-ProcessInteractive {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$Arguments = ""
    )
    try {
        $shell = New-Object -ComObject "Shell.Application"
        $shell.ShellExecute($FilePath, $Arguments, "", "open", 1)
    }
    catch {
        throw "Failed to launch process interactively: ${($_.Exception.Message)}"
    }
}
#endregion

#region Stub Functions for Missing External Calls
function Invoke-ZipFileExtraction { # Changed from Extract-ZipFileWithLogging
    param(
        [string]$ZipPath,
        [string]$DestinationPath
    )
    try {
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
        Write-LogMessage "Extraction of ZIP file '${ZipPath}' completed successfully." -Level "INFO"
    }
    catch {
        throw "Error extracting ZIP file '${ZipPath}': ${($_.Exception.Message)}"
    }
}

function Get-ExecutableSignature { # Changed from Verify-ExecutableSignatureAndCertificate
    param(
        [string]$ExePath,
        [string]$TrustedThumbprintFile
    )
    try {
        $signature = Get-AuthenticodeSignature -FilePath $ExePath
        if ($signature.Status -eq "Valid") {
            Write-LogMessage "Executable '${ExePath}' is digitally signed and valid." -Level "INFO"
        }
        else {
            Write-LogMessage "Executable '${ExePath}' signature status: ${($signature.Status)}" -Level "WARN"
        }
    }
    catch {
        Write-LogMessage "Error verifying digital signature of '${ExePath}': ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}

#region UPDATED Convert-VersionString Function # Changed from Normalize-VersionString
function Convert-VersionString { # Changed from Normalize-VersionString
    param([string]$VersionString)
    if ($VersionString -and $VersionString -match "\.") {
        $parts = $VersionString -split "\."
        $normalizedParts = foreach ($part in $parts) { [int]$part }
        return ($normalizedParts -join ".")
    }
    return $VersionString
}
#endregion

#region UPDATED Wait-For-Ping Functions
function Wait-For-PingTimeout {
    param(
        [string]$IPAddress,
        [int]$TimeoutSeconds = 300,
        [int]$IntervalSeconds = 5
    )
    $timeout = New-TimeSpan -Seconds $TimeoutSeconds
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed -lt $timeout) {
        if (-not (Test-NetConnection -ComputerName $IPAddress -Port 80 -InformationLevel Quiet)) {
            Write-LogMessage "Ping timeout: $IPAddress became unreachable." -Level "DEBUG"
            $stopwatch.Stop()
            return $true  # Unreachable within timeout
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    $stopwatch.Stop()
    Write-LogMessage "Ping timeout: $IPAddress remained reachable for $($TimeoutSeconds) seconds." -Level "DEBUG"
    return $false  # Reachable, timed out
}

function Wait-For-PingSuccess {
    param(
        [string]$IPAddress,
        [int]$TimeoutSeconds = 300,
        [int]$IntervalSeconds = 5
    )
    $timeout = New-TimeSpan -Seconds $TimeoutSeconds
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed -lt $timeout) {
        if (Test-NetConnection -ComputerName $IPAddress -Port 80 -InformationLevel Quiet) {
            Write-LogMessage "Ping success: $IPAddress is reachable." -Level "DEBUG"
            $stopwatch.Stop()
            return $true  # Reachable within timeout
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    $stopwatch.Stop()
    Write-LogMessage "Ping success: $IPAddress remained unreachable for $($TimeoutSeconds) seconds." -Level "DEBUG"
    return $false  # Unreachable, timed out
}
#endregion

#region File Lookup Function
function Get-FileRecursive { # Changed from Lookup-FileRecursive
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    try {
        $file = Get-ChildItem -Path $Path -Filter $Name -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($file) {
            Write-DebugLog -Message "File '${Name}' found at: ${($file.FullName)}"
            return $file.FullName
        }
        else {
            Write-DebugLog -Message "File '${Name}' not found in path: ${Path}" -ErrorMessage
            return $null
        }
    }
    catch {
        Write-LogMessage "Error in Get-FileRecursive: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}
#endregion

#region Save-Notification and Constants
function Get-LoggedInUserNames {
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType = 2 OR LogonType = 3 OR LogonType = 10"
        $users = @()
        foreach ($session in $sessions) {
            $associations = Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -ResultClassName Win32_Account
            foreach ($user in $associations) {
                $username = "$($user.Domain)\$($user.Name)"
                $users += $username
            }
        }
        if ($DebugMode) {
            Write-LogMessage "Registry user query returned: ${($users -join ', ')}" -Level "DEBUG"
        }
        return $users | Select-Object -Unique
    }
    catch {
        Write-LogMessage "Error retrieving logged-in users: ${($_.Exception.Message)}" -Level "WARN"
        throw $_
    }
}

function Format-DoubleCharacter {
    param(
        [char]$Character,
        [string]$Text
    )
    return $Text -replace [regex]::Escape($Character), "$&$&"
}
#region Password Redaction
function Get-RedactedPassword { # Changed from Redact-Password to an approved verb
    param (
        [string]$InputString
    )
    # This regex matches the pattern :<password>@ in a URL and replaces the password
    return $InputString -replace ':\w+@', ':********@'
}
#endregion
function Set-ConstantVariable {
    param(
        [string]$Name,
        [object]$Value
    )
    $variablePath = "Variable:Script:$Name"
    $needsSet = $true # Assume we need to set it

    # Use try/catch around Get-Variable to handle both existence and permissions issues
    try {
        $existingVariable = Get-Variable -Name $Name -Scope Script -ErrorAction Stop
        # Variable exists, check if it's constant
        if ($existingVariable.Options -contains 'Constant') {
            Write-LogMessage "Constant variable '${Name}' already exists." -Level "DEBUG"
            $needsSet = $false
        } else {
            # Exists but not constant, remove it
            Write-LogMessage "Variable '${Name}' exists but is not constant. Removing before setting." -Level "DEBUG"
            # Use -ErrorAction SilentlyContinue to prevent errors if variable doesn't exist in this scope run
            Remove-Variable -Name $Name -Scope Script -Force -ErrorAction SilentlyContinue
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        # Variable does not exist, which is fine, we need to set it
        Write-LogMessage "Variable '${Name}' does not exist. Setting as constant." -Level "DEBUG"
    } catch {
        # Other error getting variable (e.g., permissions), log warning but proceed to try setting
        Write-LogMessage "Error checking existing variable '${Name}': $($_.Exception.Message). Attempting to set anyway." -Level "WARN"
    }

    # Set the variable if needed
    if ($needsSet) {
        try {
            Set-Variable -Name $Name -Value $Value -Option Constant -Scope Script -ErrorAction Stop
            Write-LogMessage "Constant variable '${Name}' set." -Level "DEBUG"
        } catch {
            Write-LogMessage "Failed to set constant variable '${Name}': $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

Set-ConstantVariable -Name 'NOTIFICATION_TASK_NAME' -Value 'LoxoneUpdateNotificationTask'
Set-ConstantVariable -Name 'NOTIFICATION_TASK_DESCRIPTION' -Value 'Temporary task to show a notification to the currently logged-in user. Should be manually dismissed.'
Set-ConstantVariable -Name 'POWERSHELL_APP_ID' -Value 'WindowsPowerShell'
#endregion

#region Installation & Utility Functions
function Get-InstalledApplicationPath {
    param([string]$ApplicationName = "Loxone Config")

    $registryKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $foundPaths = @()

    foreach ($key in $registryKeys) {
        try {
            Write-DebugLog -Message "Searching registry key: ${key}"
            # Use Get-Item instead of Get-ItemProperty for more flexibility
            $installedApps = Get-Item -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    # Get the properties of each subkey
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if ($props -and $props.DisplayName -like "*Loxone*") {  # Wildcard search!
                        return $props
                    }
                }
                catch {
                    Write-LogMessage "Error reading properties of $($_.PSPath): $($_.Exception.Message)" -Level "WARN"
                }
            }

            foreach ($app in $installedApps) {
                if ($DebugMode) {
                    Write-LogMessage "Registry entry: DisplayName='${($app.DisplayName)}', InstallLocation='${($app.InstallLocation)}', UninstallString='${($app.UninstallString)}'" -Level "DEBUG"
                }
                if ($app.InstallLocation) {
                    Write-DebugLog -Message "Returning InstallLocation: ${($app.InstallLocation)}"
                    $foundPaths += $app.InstallLocation.TrimEnd("\")
                }
                elseif ($app.UninstallString) {
                    $uninstallPath = Split-Path $app.UninstallString
                    if (Test-Path $uninstallPath) {
                        Write-DebugLog -Message "Returning UninstallString-derived path: ${uninstallPath}"
                        $foundPaths += $uninstallPath.TrimEnd("\")
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Error searching registry key: ${key}: ${($_.Exception.Message)}" -Level "WARN"
        }
    }

     if ($foundPaths.Count -eq 0) {
        Write-LogMessage "The application '$ApplicationName' was not found in the registry." -Level "WARN" # Changed to WARN

        # --- FALLBACK: Try to find the executable directly ---
        Write-LogMessage "Attempting to find LoxoneConfig.exe directly." -Level "WARN"
        $exePath = Get-FileRecursive -Path "$env:ProgramFiles" -Name "LoxoneConfig.exe"
        if (-not $exePath) {
            $exePath = Get-FileRecursive -Path "$env:ProgramFiles(x86)" -Name "LoxoneConfig.exe"
        }

        if ($exePath) {
            Write-LogMessage "Found LoxoneConfig.exe at: $exePath" -Level "WARN"
            return Split-Path -Path $exePath -Parent
        }
        else{
            Write-LogMessage "LoxoneConfig.exe not found in Program Files." -Level "WARN" # Changed to WARN
             Return $null # return null if not found
        }
    }
    else {
        if ($DebugMode) {
            Write-LogMessage "Found installed paths: ${($foundPaths -join ', ')}" -Level "DEBUG"
        }
        return $foundPaths[0]
    }
}

function Update-MS {
    param(
        [string]$DesiredVersion,
        [string]$MSListPath = (Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt")
    )
    Write-LogMessage "Starting Update-MS function..." -Level "INFO"
    Write-DebugLog -Message "Parameters: DesiredVersion='${DesiredVersion}', MSListPath='${MSListPath}', InstalledExePath='${InstalledExePath}', ScriptSaveFolder='${ScriptSaveFolder}'"
    if (-not (Test-Path $MSListPath)) {
        Write-LogMessage "Miniserver list file not found at path: ${MSListPath}" -Level "WARN" # Changed level

        if (-not (Test-ScheduledTask)) { # Check if interactive
            Write-Host "Miniserver list file '$MSListPath' not found." -ForegroundColor Yellow
            $yes = [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Configure the first Miniserver now.")
            $no = [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Skip Miniserver configuration and updates for this run.")
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $choice = $Host.UI.PromptForChoice("Configure Miniserver?", "Would you like to configure the first Miniserver now?", $options, 1) # Default No

            if ($choice -eq 0) { # User chose Yes
                $msIP = Read-Host -Prompt "Enter Miniserver IP Address or Hostname"
                $msUser = Read-Host -Prompt "Enter Miniserver Username"
                Write-Warning "Storing passwords in plain text in the list file is insecure. Consider alternative access methods if possible."
                $msPassSecure = Read-Host -Prompt "Enter Miniserver Password" -AsSecureString
                # Convert SecureString to plain text (INSECURE, but matches file format)
                $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($msPassSecure)
                $msPassPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($Ptr)

                if (-not ([string]::IsNullOrWhiteSpace($msIP)) -and -not ([string]::IsNullOrWhiteSpace($msUser)) -and -not ([string]::IsNullOrWhiteSpace($msPassPlain))) {
                    # Assuming HTTP for simplicity, user can edit later
                    $msUrl = "http://${msUser}:${msPassPlain}@${msIP}"
                    try {
                        Set-Content -Path $MSListPath -Value $msUrl -Encoding UTF8 -Force
                        Write-LogMessage "Created Miniserver list file '$MSListPath' with entry: $(Get-RedactedPassword -InputString $msUrl)" -Level "INFO"
                        Write-Host "Miniserver list file created at '$MSListPath' with the first entry." -ForegroundColor Green
                        # File now exists, let the rest of the function proceed
                    } catch {
                        Write-LogMessage "Failed to create Miniserver list file '$MSListPath': $($_.Exception.Message)" -Level "ERROR"
                        Write-Warning "Failed to create the file. Miniserver updates will be skipped."
                        return # Exit function if file creation failed
                    }
                } else {
                    Write-Warning "Invalid input provided. Miniserver configuration skipped."
                    Write-LogMessage "User skipped Miniserver configuration due to invalid input." -Level "WARN"
                    return # Exit function
                }
            } else { # User chose No or cancelled
                Write-LogMessage "User chose not to configure Miniserver list. Skipping Miniserver updates." -Level "WARN"
                Write-Host "Skipping Miniserver updates for this run." -ForegroundColor Yellow
                return # Exit function
            }
        } else { # Running as scheduled task and file not found
            Write-LogMessage "Running as scheduled task and Miniserver list file not found. Skipping Miniserver updates." -Level "WARN"
            return # Exit function
        }
    }
    try {
        $miniserverList = Get-Content -Path $MSListPath | Where-Object { $_ -and $_.Trim() -ne "" }
        Write-LogMessage "Loaded Miniserver list with ${($miniserverList.Count)} entries." -Level "INFO"
    }
    catch {
        Write-LogMessage "Error reading Miniserver list file: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
    foreach ($ms in $miniserverList) {
       # Write-LogMessage "Processing Miniserver: ${ms}" -Level "INFO" #Removed unnessary Code
        try {
            Invoke-MiniserverUpdate -URL $ms -DesiredVersion $DesiredVersion -InstalledExePath $InstalledExePath -ScriptSaveFolder $ScriptSaveFolder # Added parameters
        }
        catch {
			# Redact the password in the URL before logging the error
            Write-LogMessage "Error processing Miniserver $(Get-RedactedPassword -InputString $ms): ${($_.Exception.Message)}" -Level "ERROR"
            throw $_
        }
    }
    Write-LogMessage "Update-MS function completed. All Miniservers have been processed." -Level "INFO"
}
#region Miniserver Update with Wait and Retry
function Invoke-MiniserverUpdate {
    param(
        [string]$URL,
        [string]$DesiredVersion,
        [string]$InstalledExePath,  # Add these parameters back
        [string]$ScriptSaveFolder
    )
    
	# --- Password Redaction ---
	$redactedURL = Get-RedactedPassword -InputString $URL  # Use the function
    Write-DebugLog -Message "Entering Invoke-MiniserverUpdate with URL='${redactedURL}' and DesiredVersion='${DesiredVersion}'"
	Write-DebugLog -Message "Redacted URL for logging: '$redactedURL'"
	# ---
    $uri = [System.Uri]::new($URL)
    $Protocol = $uri.Scheme
    $Username, $Password = $uri.UserInfo.Split(":", 2)
    $MSHost = $uri.Host
    $BasePath = $uri.AbsolutePath.TrimEnd('/')
    Write-LogMessage "Processing Basepath: ${BasePath}" -Level "DEBUG"
    Write-LogMessage "Processing Miniserver: ${MSHost}" -Level "DEBUG"
    $versionCheckUrl = "${Protocol}://${MSHost}/dev/cfg/version"
    Write-LogMessage "Checking current Miniserver version via URI: $(Get-RedactedPassword -InputString $versionCheckUrl)" -Level "INFO"

    try {
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
        $Headers = @{ Authorization = "Basic ${base64AuthInfo}" }
        $versionResponse = Invoke-WebRequest -Uri $versionCheckUrl -Headers $Headers -Method GET -UseBasicParsing -ErrorAction Stop
        $versionXml = [xml]$versionResponse.Content
        if ($DebugMode) {
            Write-LogMessage "XML Root: ${($versionXml.DocumentElement.Name)}" -Level "DEBUG"
            Write-LogMessage "Available update channels:" -Level "DEBUG"
            foreach ($node in $versionXml.DocumentElement.ChildNodes) {
                Write-LogMessage "- ${($node.Name)}" -Level "DEBUG"
            }
        }
        else {
            Write-LogMessage "Update XML loaded. Channels are available." -Level "INFO"
        }
        if ($versionXml.LL -and $versionXml.LL.value) {
            $currentVersionString = $versionXml.LL.value
            Write-LogMessage "Current Miniserver Version: ${currentVersionString}" -Level "INFO"
        }
        else {
            Write-LogMessage "XML response does not contain 'value' attribute. Full response: ${($versionResponse.Content)}" -Level "DEBUG"
            throw "Version extraction failed due to missing 'value' attribute."
        }
        try {
            $currentVersionString = Convert-VersionString $currentVersionString
            $DesiredVersion = Convert-VersionString $DesiredVersion
            $currentVersion = [version]$currentVersionString
            $desiredVersionObj = [version]$DesiredVersion
            Write-LogMessage "Comparing current version (${currentVersion}) with desired version (${desiredVersionObj})." -Level "DEBUG"
        }
        catch {
            Write-LogMessage "Error converting version strings: ${($_.Exception.Message)}" -Level "ERROR"
            throw $_
        }
        if ($currentVersion -ge $desiredVersionObj) {
            Write-LogMessage "Mininiserver is already up-to-date (Version: ${currentVersion}). Skipping update." -Level "INFO"
            return
        }
        else {
            Write-LogMessage "Miniserver version (${currentVersion}) is older than desired version (${desiredVersionObj}). Proceeding with update." -Level "INFO"
            # Start LoxoneMonitor *if* Loxone Config is installed AND the Miniserver needs an update.
            if ($null -ne $installedExePath -and (Get-Command Start-LoxoneMonitor -ErrorAction SilentlyContinue)) {
                try {
                    Start-LoxoneMonitor -InstalledExePath $installedExePath -ScriptSaveFolder $ScriptSaveFolder
                    Write-LogMessage "loxonemonitor started." -Level "INFO"
                }
                catch {
                    Write-LogMessage "Error Executing Loxone Monitor $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
    }
    catch {
        Write-LogMessage "Error fetching or comparing Miniserver version: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
    try {
        $clientIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "172.*" } | Select-Object -First 1).IPAddress
        if (-not $clientIP) {
            Write-LogMessage "Failed to retrieve the client IP address." -Level "ERROR"
            throw "Client IP not found."
        }
        $modifiedPath = $BasePath -replace "sys/autoupdate", "sps/log/$clientIP"
        $CleanURL = "${Protocol}://${MSHost}${modifiedPath}"
        #$HeadersUpdate = @{ Authorization = "Basic ${base64AuthInfo}"; "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }  <<< CHANGED: Removed unused variable
        Write-LogMessage "Invoking modified URI: $(Get-RedactedPassword -InputString $CleanURL)" -Level "DEBUG" # <<< CHANGED: Redact password
        $Response = Invoke-WebRequest -Uri $CleanURL -Headers $Headers -Method GET -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
        if ($Response.StatusCode -eq 200) {
            Write-LogMessage "Successfully invoked modified URI: $(Get-RedactedPassword -InputString $CleanURL)" -Level "INFO" # <<< CHANGED: Redact password
        }
        else {
            Write-LogMessage "URL $(Get-RedactedPassword -InputString $CleanURL) returned status code ${($Response.StatusCode)}." -Level "WARN" # <<< CHANGED: Redact password
            throw "Modified URI returned status code ${($Response.StatusCode)}."
        }
		$redactedURL = Get-RedactedPassword -InputString $URL
        Write-LogMessage "Invoking URI: $redactedURL" -Level "DEBUG" # <<< CHANGED: Redact Password
        $Response = Invoke-WebRequest -Uri $URL -Headers $Headers -Method GET -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
        if ($Response.StatusCode -eq 200) {
            Write-LogMessage "Successfully invoked URI: $(Get-RedactedPassword -InputString $BasePath)" -Level "INFO" # <<< CHANGED: Redact password
        }
        else {
            Write-LogMessage "URL $(Get-RedactedPassword -InputString $BasePath) returned status code ${($Response.StatusCode)}." -Level "WARN" # <<< CHANGED: Redact
            throw "Base URI returned status code ${($Response.StatusCode)}."
        }
		

        # --- Wait and Retry Logic ---
        Write-LogMessage "Waiting for Miniserver ($MSHost) to become unreachable (2 consecutive failed pings)..." -Level "INFO"
        $failedPings = 0
        while ($failedPings -lt 2) {
            if (-not (Test-NetConnection -ComputerName $MSHost -Port 80 -InformationLevel Quiet)) {
                $failedPings++
                Write-LogMessage "Ping failed ($failedPings/2)." -Level "DEBUG"
            } else {
                $failedPings = 0  # Reset on successful ping
                Write-LogMessage "Ping successful, resetting counter." -Level "DEBUG"
            }
            Start-Sleep -Seconds 2 # check every 2 seconds
        }
        Write-LogMessage "Miniserver ($MSHost) is unreachable. Waiting for it to become reachable again..." -Level "INFO"
		

        #$pingTimeoutResult = Wait-For-PingTimeout -IPAddress ${MSHost} -TimeoutSeconds 300 -IntervalSeconds 5  <<< CHANGED: Removed unused variable and call
        #if (-not $pingTimeoutResult) {
        #    Write-LogMessage "Client IP ${clientIP} did not become unreachable in time. Continuing update." -Level "WARN"
        #}
        $pingSuccessResult = Wait-For-PingSuccess -IPAddress ${MSHost} -TimeoutSeconds 300 -IntervalSeconds 5
        if (-not $pingSuccessResult) {
            Write-LogMessage "Client IP ${clientIP} is not reachable after update. Update may have failed." -Level "WARN"
        }
		# Wait for Miniserver to respond to ping
        Write-LogMessage "Waiting 1 Minute..." -Level "INFO"
		Start-Sleep -Seconds 60 #wait 1 min.
		
		 Write-LogMessage "Waiting for Miniserver ($MSHost) to become reachable..." -Level "INFO"
        $pingSuccess = Wait-For-PingSuccess -IPAddress $MSHost
		

        if (-not $pingSuccess) {
            Write-LogMessage "Miniserver ($MSHost) did not become reachable after update.  Version check aborted." -Level "ERROR"
            throw "Miniserver unreachable after update."
        }
		

        # Miniserver is reachable, now check the version repeatedly
        Write-LogMessage "Miniserver ($MSHost) is reachable.  Starting version check loop..." -Level "INFO"
        $versionCheckTimeout = New-TimeSpan -Minutes 8  # 8-minute timeout for version check
        $versionCheckStart = Get-Date
        $versionMatchFound = $false
		$attempt = 0;
        while (((Get-Date) - $versionCheckStart) -lt $versionCheckTimeout) {
			$attempt++
            try {
                Write-LogMessage "Checking Miniserver version (attempt $($attempt))..." -Level "DEBUG"
                $versionResponse = Invoke-WebRequest -Uri $versionCheckUrl -Headers $Headers -Method GET -UseBasicParsing -ErrorAction Stop
				

                if ($versionResponse.StatusCode -eq 200) {
                    $versionXml = [xml]$versionResponse.Content
                    if ($versionXml.LL -and $versionXml.LL.value) {
                        $currentVersionString = $versionXml.LL.value
                        $currentVersion = [version](Convert-VersionString $currentVersionString)
						

                        if ($currentVersion -ge $desiredVersionObj) {
                            Write-LogMessage "Miniserver version check successful. Current version: $currentVersion" -Level "INFO"
                            $versionMatchFound = $true
							Remove-Variable versionXml -Scope Script  # <<< ADDED: Clean up
                            break  # Exit loop on successful version match
                        }
                        else {
                            Write-LogMessage "Miniserver version ($currentVersion) is still older than desired ($desiredVersionObj)." -Level "WARN"
                        }
                    }
                    else {
                        Write-LogMessage "Version check: XML response does not contain 'value' attribute." -Level "WARN"
                    }
                }
                else {
                    Write-LogMessage "Version check:  Unexpected status code: $($versionResponse.StatusCode)" -Level "WARN"
                }
            }
            catch {
                Write-LogMessage "Version check: Error during version check: $($_.Exception.Message)" -Level "WARN"
            }
			

            Start-Sleep -Seconds 10  # Wait 10 seconds before retrying
        }
		Remove-Variable versionResponse -Scope Script # <<< ADDED: Clean up
        if (-not $versionMatchFound) {
            Write-LogMessage "Version check timed out after 8 minutes.  Miniserver may not have updated correctly." -Level "ERROR"
            throw "Version check timeout."
        }
    }
    catch {
        Write-LogMessage "Error during update process for Miniserver ${MSHost}: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
    Write-DebugLog -Message "Exiting Invoke-MiniserverUpdate."
}
#endregion

function Save-ScriptToUserLocation {
    param(
        [string]$DestinationDir,
        [string]$ScriptName = "UpdateLoxone.ps1"
    )
    try {
        Write-DebugLog -Message "Entering Save-ScriptToUserLocation with DestinationDir='${DestinationDir}', ScriptName='${ScriptName}'."
        if (-not (Test-Path $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir | Out-Null
            Write-LogMessage "Custom script directory created at ${DestinationDir}." -Level "INFO"
        }
        $destinationPath = Join-Path -Path $DestinationDir -ChildPath $ScriptName
        Write-DebugLog -Message "Computed destinationPath = '${destinationPath}'."
        if ($MyInvocation.MyCommand.Path -eq $destinationPath) {
            Write-LogMessage "The script is already in the target directory: ${destinationPath}. Skipping copy." -Level "INFO"
            return $destinationPath
        }
        if ($psISE -and $psISE.CurrentFile -and $psISE.CurrentFile.Editor.Text) {
            $scriptContent = $psISE.CurrentFile.Editor.Text
            Set-Content -Path $destinationPath -Value $scriptContent -Force
            Write-LogMessage "Script copied to ${destinationPath} (from ISE Editor)." -Level "INFO"
        }
        else {
            if ($MyInvocation.MyCommand.Definition -and (Test-Path $MyInvocation.MyCommand.Definition)) {
                Copy-Item -Path $MyInvocation.MyCommand.Definition -Destination $destinationPath -Force
                Write-LogMessage "Script copied to ${destinationPath} (from script file)." -Level "INFO"
            }
            else {
                $scriptContent = Get-Content -Path $PSCommandPath -ErrorAction Stop
                Set-Content -Path $destinationPath -Value $scriptContent -Force
                Write-LogMessage "Script copied to ${destinationPath} (from script content)." -Level "INFO"
            }
        }
        Write-DebugLog -Message "Exiting Save-ScriptToUserLocation; returning destinationPath='${destinationPath}'."
        return $destinationPath
    }
    catch {
        Write-LogMessage "Error saving the script: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}

function Invoke-AdminAndCorrectPathCheck { # Changed from Ensure-Admin-And-CorrectPath
    param()
    if ([string]::IsNullOrWhiteSpace($ScriptSaveFolder)) {
        # $ScriptSaveFolder should be set globally based on script location at the start
        # If it's still empty here, something is wrong, but fallback just in case.
        Write-LogMessage "ScriptSaveFolder is unexpectedly empty in Invoke-AdminAndCorrectPathCheck. Falling back to default." -Level "WARN"
        $ScriptSaveFolder = "$env:USERPROFILE\Scripts" 
    }
    $targetPath = Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxone.ps1"
    Write-DebugLog -Message "Invoke-AdminAndCorrectPathCheck: targetPath = '${targetPath}'."
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        # Construct arguments, ensuring all relevant parameters are passed
        $relaunchArgsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", """$targetPath""")
        # Add parameters that were passed to the original script
        if ($PSBoundParameters.ContainsKey('Channel')) { $relaunchArgsList += "-Channel", """$Channel""" }
        if ($PSBoundParameters.ContainsKey('DebugMode')) { $relaunchArgsList += "-DebugMode", ('$true' -eq $DebugMode.ToString()) } # Pass boolean correctly
        if ($PSBoundParameters.ContainsKey('EnableCRC')) { $relaunchArgsList += "-EnableCRC", ('$true' -eq $EnableCRC.ToString()) } # Pass boolean correctly
        if ($PSBoundParameters.ContainsKey('InstallMode')) { $relaunchArgsList += "-InstallMode", """$InstallMode""" }
        if ($PSBoundParameters.ContainsKey('CloseApplications')) { $relaunchArgsList += "-CloseApplications", ('$true' -eq $CloseApplications.ToString()) } # Pass boolean correctly
        if ($PSBoundParameters.ContainsKey('ScriptSaveFolder')) { $relaunchArgsList += "-ScriptSaveFolder", """$ScriptSaveFolder""" }
        if ($PSBoundParameters.ContainsKey('MaxLogFileSizeMB')) { $relaunchArgsList += "-MaxLogFileSizeMB", $MaxLogFileSizeMB }
        if ($PSBoundParameters.ContainsKey('ScheduledTaskIntervalMinutes')) { $relaunchArgsList += "-ScheduledTaskIntervalMinutes", $ScheduledTaskIntervalMinutes }
        if ($PSBoundParameters.ContainsKey('SkipUpdateIfAnyProcessIsRunning')) { $relaunchArgsList += "-SkipUpdateIfAnyProcessIsRunning", ('$true' -eq $SkipUpdateIfAnyProcessIsRunning.ToString()) } # Pass boolean correctly
        if ($PSBoundParameters.ContainsKey('TestNotifications')) { $relaunchArgsList += "-TestNotifications" }
        if ($PSBoundParameters.ContainsKey('MonitorLogWatchTimeoutMinutes')) { $relaunchArgsList += "-MonitorLogWatchTimeoutMinutes", $MonitorLogWatchTimeoutMinutes }
        if ($PSBoundParameters.ContainsKey('TestMonitor')) { $relaunchArgsList += "-TestMonitor" }
        if ($PSBoundParameters.ContainsKey('MonitorSourceLogDirectory')) { $relaunchArgsList += "-MonitorSourceLogDirectory", """$MonitorSourceLogDirectory""" }
        if ($PSBoundParameters.ContainsKey('TestKill')) { $relaunchArgsList += "-TestKill" }
        if ($PSBoundParameters.ContainsKey('SetupSystemMonitor')) { $relaunchArgsList += "-SetupSystemMonitor" }
        
        $relaunchArgs = $relaunchArgsList -join " "
        Write-DebugLog -Message "Invoke-AdminAndCorrectPathCheck: Relaunch Args = '$relaunchArgs'."
        
        try {
             Start-Process -FilePath "PowerShell.exe" -ArgumentList $relaunchArgs -Verb RunAs -WindowStyle Normal -ErrorAction Stop
             Write-LogMessage "Re-launched script as Admin. Exiting current non-admin instance." -Level "INFO"
             exit 0 # Exit the non-admin instance successfully
        } catch {
             $exceptionMessage = $_.Exception.Message
             Write-LogMessage "Failed to re-launch script as Admin: $exceptionMessage." -Level "ERROR"
             # Check if the error indicates UAC cancellation
             if ($exceptionMessage -like "*The operation was canceled by the user*") {
                 $global:UacCancelled = $true # Set flag just in case finally still runs
                 Write-LogMessage "UAC prompt was likely cancelled by the user. Exiting with code 131." -Level "WARN"
                 exit 131 # Exit immediately with specific code
             }
             # Exit with a generic error code if elevation failed for other reasons
             exit 1 
        }
    }
    Write-LogMessage "Script is running from the target directory and with administrator privileges." -Level "INFO"
}


function Register-ScheduledTaskForScript {
    param(
        [string]$ScriptPath,
        [string]$TaskName = "LoxoneUpdateTask"
    )
    Write-LogMessage "Register-ScheduledTaskForScript: ScriptPath = '$ScriptPath', TaskName = '$TaskName'" -Level "DEBUG"
    try {
        Write-LogMessage "Checking if the scheduled task '$TaskName' exists." -Level "INFO"
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-LogMessage "Scheduled task '$TaskName' already exists. Overwriting the task." -Level "INFO"
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            Write-LogMessage "Existing scheduled task '$TaskName' has been unregistered." -Level "INFO"
        }
        else {
            Write-LogMessage "Scheduled task '$TaskName' does not exist. Creating the task." -Level "INFO"
        }
        $triggerInterval = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $ScheduledTaskIntervalMinutes)
        # Construct arguments for the scheduled task, ensuring boolean switches are handled correctly
        $actionArgsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", """$ScriptPath""")
        if ($Channel) { $actionArgsList += "-Channel", """$Channel""" }
        # Pass boolean parameters explicitly as $true/$false for clarity in task definition
        if ($DebugMode) { $actionArgsList += "-DebugMode", "`$true" } else { $actionArgsList += "-DebugMode", "`$false" }
        if ($EnableCRC) { $actionArgsList += "-EnableCRC", "`$true" } else { $actionArgsList += "-EnableCRC", "`$false" }
        if ($InstallMode) { $actionArgsList += "-InstallMode", """$InstallMode""" }
        if ($CloseApplications) { $actionArgsList += "-CloseApplications", "`$true" } else { $actionArgsList += "-CloseApplications", "`$false" }
        if ($ScriptSaveFolder) { $actionArgsList += "-ScriptSaveFolder", """$ScriptSaveFolder""" }
        if ($MaxLogFileSizeMB) { $actionArgsList += "-MaxLogFileSizeMB", $MaxLogFileSizeMB }
        if ($ScheduledTaskIntervalMinutes) { $actionArgsList += "-ScheduledTaskIntervalMinutes", $ScheduledTaskIntervalMinutes }
        if ($SkipUpdateIfAnyProcessIsRunning) { $actionArgsList += "-SkipUpdateIfAnyProcessIsRunning", "`$true" } else { $actionArgsList += "-SkipUpdateIfAnyProcessIsRunning", "`$false" }
        # Do not pass test switches to the scheduled task
        
        $actionArgs = $actionArgsList -join " "
        Write-DebugLog -Message "Scheduled Task Action Args: $actionArgs"

        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $actionArgs
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden -WakeToRun:$false
        Write-LogMessage "Registering scheduled task '$TaskName' with detailed parameters." -Level "DEBUG"
        Register-ScheduledTask -Force -TaskName $TaskName -Trigger $triggerInterval -Action $action -Settings $settings -Description "Automatic Loxone Config Update" -RunLevel Highest -User "SYSTEM" -ErrorAction Stop
        Write-LogMessage "Scheduled task '$TaskName' successfully created or updated." -Level "INFO"
    }
    catch {
        $errorMessage = ${($_.Exception.Message)}
        $lineNumber = ${($_.InvocationInfo.ScriptLineNumber)}
        $scriptLine = ${($_.InvocationInfo.Line)}
        Write-LogMessage "Error creating the scheduled task: ${errorMessage}. At line ${lineNumber}: ${scriptLine}" -Level "ERROR"
        throw $_
    }
}

$downloadDir = Join-Path -Path $ScriptSaveFolder -ChildPath "LoxoneUpdate"
if (-not (Test-Path $downloadDir)) {
    try {
        New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
        Write-LogMessage "Download directory created: ${downloadDir}" -Level "INFO"
    }
    catch {
        Write-LogMessage "Could not create download directory ${downloadDir}: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}
#endregion

#region Download and Verification Functions
function Invoke-FileDownloadWithProgress { # Changed from Download-FileWithProgressManual
    param(
        [string]$ZipUrl,
        [string]$DestinationPath,
        [string]$Activity = "Downloading File"
    )
    Write-DebugLog -Message "Invoke-FileDownloadWithProgress: ZipUrl='${ZipUrl}', DestinationPath='${DestinationPath}', Activity='${Activity}'"
    try {
        Write-LogMessage "${Activity}: ${ZipUrl}" -Level "INFO"
        Write-LogMessage "Destination file: ${DestinationPath}" -Level "INFO"
        Write-LogMessage "Attempting to download to path: ${DestinationPath}" -Level "DEBUG"
        if (Test-Path $DestinationPath) {
            $existingFileSize = (Get-Item $DestinationPath).Length
            # Need $expectedFilesize defined in this scope or passed as parameter
            # Assuming it might be defined globally or passed implicitly for now
            if ($expectedFilesize -and $existingFileSize -ne $expectedFilesize) { 
                Write-LogMessage "Existing ZIP file size (${existingFileSize} Bytes) does not match expected (${expectedFilesize} Bytes). Removing file to force redownload." -Level "WARN"
                Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-LogMessage "ZIP file already exists and size is as expected (or expected size unknown). Skipping download." -Level "INFO"
                return $false
            }
        }
        $request = [System.Net.WebRequest]::Create($ZipUrl)
        $response = $request.GetResponse()
        $totalBytes = $response.ContentLength
        $stream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::OpenWrite($DestinationPath)
        $buffer = New-Object byte[] 8192
        $bytesRead = 0
        $totalRead = 0
        $lastProgress = 0
        $startTime = Get-Date
        $isScheduledTask = Test-ScheduledTask
        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $bytesRead)
            $totalRead += $bytesRead
            if ($totalBytes -gt 0) {
                $percent = ($totalRead / $totalBytes) * 100
                $elapsed = (Get-Date) - $startTime
                $speed = if ($elapsed.TotalSeconds -gt 0) { ($totalRead / 1MB) / $elapsed.TotalSeconds } else { 0 }
                $remainingBytes = $totalBytes - $totalRead # Calculate remaining bytes
                $remainingTime = if ($speed -gt 0) { [TimeSpan]::FromSeconds($remainingBytes / ($speed * 1MB)) } else { [TimeSpan]::Zero }
                if ($percent -ge $lastProgress + 1) {
                    if (-not $isScheduledTask) {
                        Write-Progress -Activity $Activity -Status ("$([math]::Round($percent,2))% Complete - Speed: $([math]::Round($speed,2)) MB/s - Remaining Time: $($remainingTime.ToString('hh\:mm\:ss'))") -PercentComplete $percent
                    }
                    else {
                        Write-LogMessage "Download progress: $([math]::Round($percent,2))% Complete - Speed: $([math]::Round($speed,2)) MB/s - Remaining Time: $($remainingTime.ToString('hh\:mm\:ss'))" -Level "DEBUG"
                    }
                    $lastProgress = [math]::Floor($percent)
                }
            }
        }
        if (-not $isScheduledTask) {
            Write-Progress -Activity $Activity -Status "Completed" -Completed
        }
        $fileStream.Close()
        $stream.Close()
        $response.Close()
        Write-LogMessage "Download completed: ${DestinationPath}" -Level "INFO"
        return $true
    }
    catch {
        Write-LogMessage "Error downloading ${ZipUrl} to ${DestinationPath}: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}

function Invoke-ZipDownloadAndVerification { # Changed from Download-And-Verify-Zip
    param(
        [string]$ZipUrl,
        [string]$DestinationPath,
        [string]$ExpectedCRC32,
        [int64]$ExpectedFilesize, # Made explicit for clarity
        [int]$MaxRetries = 2
    )
    $success = $false
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-LogMessage "Starting download of the ZIP file (Attempt ${attempt} of ${MaxRetries})..." -Level "INFO"
            # Pass $ExpectedFilesize to the download function
            $zipDownloadResult = Invoke-FileDownloadWithProgress -ZipUrl $ZipUrl -DestinationPath $DestinationPath -Activity "Download ZIP File" -expectedFilesize $ExpectedFilesize 
            if (-not $zipDownloadResult) {
                Write-LogMessage "ZIP file already exists. Skipping download." -Level "INFO"
            }
            if (-not (Test-Path $DestinationPath)) {
                throw "The downloaded ZIP file was not found at ${DestinationPath}."
            }
            $actualFilesize = (Get-Item $DestinationPath).Length
            Write-LogMessage "Actual ZIP file size: ${actualFilesize} Bytes" -Level "INFO"
            if ($actualFilesize -ne $ExpectedFilesize) {
                throw "The downloaded ZIP file size (${actualFilesize} Bytes) does not match the expected size (${ExpectedFilesize} Bytes)."
            }
            else {
                Write-LogMessage "ZIP file size verification passed." -Level "INFO"
            }
            if ($EnableCRC -and (![string]::IsNullOrEmpty($ExpectedCRC32))) {
                Write-LogMessage "Starting CRC32 checksum verification of the ZIP file..." -Level "INFO"
                $ExpectedCRC32 = $ExpectedCRC32.PadLeft(8, '0').ToUpper()
                Write-LogMessage "Padded Expected CRC32: ${ExpectedCRC32}" -Level "DEBUG"
                $actualCRC32 = Get-CRC32 -InputFile $DestinationPath
                if ([string]::IsNullOrEmpty($actualCRC32)) {
                    Write-LogMessage "Calculated CRC32 is null or empty. Skipping CRC32 verification." -Level "WARN"
                    $success = $true
                }
                else {
                    Write-LogMessage "Expected CRC32: ${ExpectedCRC32}" -Level "INFO"
                    Write-LogMessage "Actual CRC32: ${actualCRC32}" -Level "INFO"
                    if ($actualCRC32 -ne $ExpectedCRC32) {
                        Write-LogMessage "CRC32 checksum does not match (Expected: ${ExpectedCRC32}, Actual: ${actualCRC32})." -Level "WARN"
                        $success = $false
                    }
                    else {
                        Write-LogMessage "CRC32 checksum verification passed." -Level "INFO"
                        $success = $true
                    }
                }
            }
            else {
                Write-LogMessage "CRC32 checksum verification is disabled or not available." -Level "INFO"
                $success = $true
            }
            if ($success) {
                return $true
            }
            }
        catch {
            Write-LogMessage "Error downloading or verifying the ZIP file: ${($_.Exception.Message)}" -Level "ERROR"
            if (Test-Path $DestinationPath) {
                Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
                Write-LogMessage "Removed corrupted ZIP file ${DestinationPath}." -Level "DEBUG"
            }
            if ($attempt -eq $MaxRetries) {
                throw $_
            }
        }
    }
    Write-LogMessage "Maximum attempts (${$MaxRetries}) reached. Update failed." -Level "ERROR"
    throw "Maximum download attempts reached."
}
#endregion

#region Helper to Start Process in Interactive Session
function Start-ProcessInInteractiveSession {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    # Look for explorer.exe which runs in the interactive session.
    $explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $explorer) {
        Write-LogMessage "No interactive explorer.exe process found. Cannot determine interactive session." -Level "ERROR"
        throw "Interactive session not found."
    }
    $sessionId = $explorer.SessionId
    Write-LogMessage "Interactive session id is ${sessionId}" -Level "INFO"
    try {
        $shell = New-Object -ComObject "Shell.Application"
        $shell.ShellExecute($FilePath, "", "", "open", 1)
        Write-LogMessage "${FilePath} launched in interactive session." -Level "INFO"
    }
    catch {
        Write-LogMessage "Error launching ${FilePath} in interactive session: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }
}
#endregion

#region Helper Function to Find loxonemonitor.exe Recursively
function Find-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )
    try {
        # Corrected function call
        $monitorPath = Get-FileRecursive -Path $BasePath -Name "loxonemonitor.exe" 
        if ($monitorPath) {
            Write-DebugLog -Message "Found loxonemonitor.exe at: $monitorPath"
            return $monitorPath
        }
        else {
            Write-DebugLog -Message "loxonemonitor.exe not found in path: $BasePath" -ErrorMessage
            return $null
        }
    }
    catch {
        # Corrected function name in log message
        Write-LogMessage "Error in Find-File: $($_.Exception.Message)" -Level "ERROR" 
        throw $_
    }
}
#endregion

#region Updated Start-LoxoneMonitor Function
function Start-LoxoneMonitor {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstalledExePath,
        [Parameter(Mandatory = $true)]
        [string]$ScriptSaveFolder
    )
	
	# Check if loxonemonitor is already running
    $existingMonitorProcess = Get-Process -Name "loxonemonitor" -ErrorAction SilentlyContinue
    if ($existingMonitorProcess) {
        Write-LogMessage "loxonemonitor.exe is already running (PID: $($existingMonitorProcess.Id)). Skipping start." -Level "INFO"
        return # Exit the function if already running
    }

	if (-not [string]::IsNullOrEmpty($InstalledExePath)){
		# Use Find-File to search for loxonemonitor.exe in all subfolders.
		$loxoneMonitorExePath = Find-File -BasePath $InstalledExePath

		if (-not $loxoneMonitorExePath) {
			Write-LogMessage "loxonemonitor.exe not found under path: ${InstalledExePath}" -Level "ERROR"
			throw "loxonemonitor.exe not found in ${InstalledExePath}."
		}

		# Stop any running loxonemonitor process.
		try {
			$process = Get-Process -Name "loxonemonitor" -ErrorAction SilentlyContinue
			if ($process) {
				Stop-Process -Id $process.Id -Force
				Write-LogMessage "Existing loxonemonitor.exe was terminated." -Level "INFO"
			}
		}
		catch {
			Write-LogMessage "Error stopping loxonemonitor.exe: $($_.Exception.Message)" -Level "ERROR"
			throw $_
		}

		# Copy the monitor executable to the ScriptSaveFolder.
		try {
			Copy-Item -Path $loxoneMonitorExePath -Destination $ScriptSaveFolder -Force
			Write-LogMessage "loxonemonitor.exe was copied to ${ScriptSaveFolder}." -Level "INFO"
		}
		catch {
			Write-LogMessage "Error copying loxonemonitor.exe: $($_.Exception.Message)`nValues: loxonemonitorExePath='${loxoneMonitorExePath}', ScriptSaveFolder='${ScriptSaveFolder}'" -Level "ERROR"
			throw $_
		}

		# Copy related DLLs.
		try {
			$dllSource = Join-Path -Path $InstalledExePath -ChildPath "LoxoneConfigres_*.dll"
			Copy-Item -Path $dllSource -Destination $ScriptSaveFolder -Force
			Write-LogMessage "LoxoneConfigres_*.dll files were copied to ${ScriptSaveFolder}." -Level "INFO"
		}
		catch {
			Write-LogMessage "Error copying LoxoneConfigres_*.dll: $($_.Exception.Message)" -Level "ERROR"
			throw $_
		}

		# Start the monitor in the interactive user context.
		try {
			$monitorPath = Join-Path -Path $ScriptSaveFolder -ChildPath "loxonemonitor.exe"
			Start-ProcessInInteractiveSession -FilePath $monitorPath
		}
		catch {
			Write-LogMessage "Error starting loxonemonitor.exe: $($_.Exception.Message)" -Level "ERROR"
			throw $_
		}
	}
	else{
		Write-LogMessage "InstalledExePath is null or empty skipping Start-LoxoneMonitor" -Level "INFO"
	}
}
#endregion

#region Stop Loxone Monitor Function
function Stop-LoxoneMonitor {
    Write-LogMessage "Attempting to stop loxonemonitor.exe..." -Level "INFO"
    try {
        $monitorProcess = Get-Process -Name "loxonemonitor" -ErrorAction SilentlyContinue
        if ($monitorProcess) {
            Stop-Process -Id $monitorProcess.Id -Force -ErrorAction Stop
            Write-LogMessage "loxonemonitor.exe (PID: $($monitorProcess.Id)) stopped successfully." -Level "INFO"
        }
        else {
            Write-LogMessage "loxonemonitor.exe was not running." -Level "INFO"
        }
    }
    catch {
        Write-LogMessage "Error stopping loxonemonitor.exe: $($_.Exception.Message)" -Level "ERROR"
        # Don't throw here, allow script to continue if stopping fails
    }
}
#endregion

#region Watch and Move Monitor Logs Function
function Watch-And-Move-MonitorLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceLogDir,
        [Parameter(Mandatory = $true)]
        [string]$DestinationLogDir,
        [Parameter(Mandatory = $true)]
        [int]$TimeoutMinutes,
        [Parameter()]
        [switch]$CreateTestFile # New parameter
    )

    Write-LogMessage "Starting to watch for new logs in '$SourceLogDir' for $TimeoutMinutes minutes (Polling Method)." -Level "INFO"
    Write-LogMessage "New logs will be moved to '$DestinationLogDir'." -Level "INFO" # Corrected trailing backslash

    if (-not (Test-Path $SourceLogDir)) {
        Write-LogMessage "Source log directory '$SourceLogDir' does not exist. Cannot watch for logs." -Level "WARN"
        return $false
    }

    # Ensure destination directory exists
    try {
        if (-not (Test-Path $DestinationLogDir)) {
            New-Item -ItemType Directory -Path $DestinationLogDir -Force | Out-Null
            Write-LogMessage "Created destination log directory '$DestinationLogDir'." -Level "INFO"
        }
    }
    catch {
        Write-LogMessage "Error creating destination directory '$DestinationLogDir': $($_.Exception.Message)" -Level "ERROR"
        return $false # Cannot proceed without destination
    }
    
    # Ensure any previous test file in destination is removed
    $testFileName = "_TestMonitorFile.log"
    $destTestFilePath = Join-Path -Path $DestinationLogDir -ChildPath $testFileName
    if (Test-Path $destTestFilePath) {
        Remove-Item -Path $destTestFilePath -Force -ErrorAction SilentlyContinue
        Write-DebugLog "Removed existing test file from destination: $destTestFilePath"
    }

    $timeout = New-TimeSpan -Minutes $TimeoutMinutes
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $watchStartTime = Get-Date # Capture start time for comparison
    $testFileCreated = $false # Flag to create test file only once

    Write-DebugLog "Polling for new log files..."

    while ($stopwatch.Elapsed -lt $timeout) {
        # Create test file after a short delay if requested
        if ($CreateTestFile -and (-not $testFileCreated) -and $stopwatch.Elapsed.TotalSeconds -ge 5) {
            $testFilePath = Join-Path -Path $SourceLogDir -ChildPath $testFileName
            try {
                Set-Content -Path $testFilePath -Value "This is a test file created by UpdateLoxone.ps1 at $(Get-Date)" -Encoding UTF8 -Force -ErrorAction Stop
                Write-LogMessage "Created test file: $testFilePath" -Level "INFO"
                $testFileCreated = $true
            } catch {
                Write-LogMessage "Failed to create test file '$testFilePath': $($_.Exception.Message)" -Level "ERROR"
                # Don't stop the watch, maybe permissions change or real file appears
            }
        }

        # Check for Ctrl+C attempt (less reliable in loops with sleep)
        if ($Host.UI.RawUI.KeyAvailable) {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($key.Character -eq 'c' -and $key.Control) {
                Write-LogMessage "Ctrl+C detected during log watch loop. Setting interruption flag." -Level "WARN"
                $global:ScriptInterrupted = $true
                $stopwatch.Stop() # Stop the timer
                return $false # Exit the watch function, indicating interruption/failure
            }
        }

        try { # Inner try block for file operations
            # Get current files, handle potential access errors gracefully
            try {
                 $currentFiles = Get-ChildItem -Path $SourceLogDir -Filter "*.log" -ErrorAction Stop
            } catch {
                 Write-LogMessage "Error accessing source log directory '$SourceLogDir' during check: $($_.Exception.Message)" -Level "WARN"
                 $currentFiles = @() # Treat as no files found on error
            }
            
            # Detect files modified *after* the watch started
            Write-DebugLog "Comparing file LastWriteTime against WatchStartTime: $watchStartTime"
            $newOrUpdatedFiles = $currentFiles | Where-Object { $_.LastWriteTime -ge $watchStartTime }
            if ($newOrUpdatedFiles) { Write-DebugLog "Found $($newOrUpdatedFiles.Count) new/updated files."} else { Write-DebugLog "No new/updated files found based on timestamp."}


            if ($newOrUpdatedFiles) {
                Write-LogMessage "New or updated log file(s) detected since watch started." -Level "INFO"
                
                foreach ($file in $newOrUpdatedFiles) {
                    # If in test mode and this is the test file, just log detection and exit successfully
                    if ($CreateTestFile -and $file.Name -eq $testFileName) {
                        Write-LogMessage "Test file '$($file.Name)' detected successfully." -Level "INFO"
                        $stopwatch.Stop()
                        Write-LogMessage "Finished watching for logs after detecting test file." -Level "INFO"
                        return $true # Indicate test success
                    }

                    # Otherwise (not test file or not in test mode), proceed with copy/remove
                    $destinationFile = Join-Path -Path $DestinationLogDir -ChildPath $file.Name
                    try {
                        # Explicitly remove destination file before moving, just in case -Force isn't enough
                        if (Test-Path $destinationFile) {
                             Remove-Item -Path $destinationFile -Force -ErrorAction SilentlyContinue
                             Write-DebugLog "Preemptively removed existing destination file: $destinationFile"
                        }
                        # Use Copy-Item then Remove-Item instead of Move-Item
                        Copy-Item -Path $file.FullName -Destination $destinationFile -Force -ErrorAction Stop
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop # Delete source after successful copy
                        Write-LogMessage "Copied and removed log file '$($file.Name)' to '$DestinationLogDir'." -Level "INFO"
                    }
                    catch {
                        Write-LogMessage "Error copying/removing log file '$($file.FullName)': $($_.Exception.Message)" -Level "ERROR"
                        # Continue trying to move other files if one fails
                    }
                }
                # If the loop finished without returning (meaning test file wasn't the one moved, or not in test mode)
                # Stop after processing the first batch of new/updated files found (unless it was the test file, which returned earlier)
                if ($newOrUpdatedFiles.Count -gt 0) { # Corrected variable name check
                     $stopwatch.Stop()
                     Write-LogMessage "Finished watching for logs after processing first batch of new/updated file(s)." -Level "INFO"
                     return $true # Indicate success (found files)
                }
            }
        } catch { # Inner catch block for file operation errors
             Write-LogMessage "CRITICAL ERROR during log watch file operations: $($_.Exception.Message). Stopping watch." -Level "ERROR"
             $stopwatch.Stop()
             return $false # Indicate failure
        }

        # Wait before checking again
        Start-Sleep -Seconds 5
        Write-DebugLog "Still watching... Elapsed: $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
    }

    # If loop finishes, timeout occurred
    $stopwatch.Stop()
    Write-LogMessage "Stopped watching for logs after timeout ($TimeoutMinutes minutes). No new log files were detected or moved." -Level "WARN"
    return $false
}
#endregion


#region Main Script Execution
Invoke-LogFileRotation -LogPath $global:LogFile

    # --- Setup System Monitor Mode --- 
    if ($SetupSystemMonitor) {
        Write-LogMessage "Running in Setup System Monitor mode." -Level "INFO"
        # This mode requires Admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-LogMessage "Setup System Monitor mode requires Administrator privileges. Please re-run from an elevated prompt." -Level "ERROR"
            exit 1
        }

        # Find monitor executable
        # Ensure $installedExePath is determined first (it should be now)
        $loxoneMonitorExePath = $null
        # Re-determine installed path here just in case it wasn't done before main try
        if (-not $installedExePath) {
             $installedExePath = Get-InstalledApplicationPath -ErrorAction SilentlyContinue
        }
        if ($installedExePath) { 
            $loxoneMonitorExePath = Find-File -BasePath $installedExePath
        }
        if (-not $loxoneMonitorExePath) {
             Write-LogMessage "loxonemonitor.exe not found. Cannot set up SYSTEM process." -Level "ERROR"
             exit 1
        }


        # Stop existing monitor process (if any)
        Write-LogMessage "Stopping any existing loxonemonitor.exe process..." -Level "INFO"
        Stop-Process -Name loxonemonitor -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2 # Give it a moment

        # Create and run a temporary scheduled task as SYSTEM
        $taskName = "TempStartLoxoneMonitorAsSystem"
        $action = New-ScheduledTaskAction -Execute $loxoneMonitorExePath
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
        # Use -Interactive switch if available and desired for visibility, otherwise it runs hidden
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5) 
        
        try {
            Write-LogMessage "Registering temporary task '$taskName' to run monitor as SYSTEM." -Level "INFO"
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop
            Write-LogMessage "Running temporary task '$taskName'." -Level "INFO"
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-LogMessage "Loxone Monitor should now be running as SYSTEM. Waiting a few seconds..." -Level "INFO"
            Start-Sleep -Seconds 5
        } catch {
            Write-LogMessage "Failed to create or run scheduled task '$taskName': $($_.Exception.Message)" -Level "ERROR"
        } finally {
            # Clean up the temporary task
            Write-LogMessage "Unregistering temporary task '$taskName'." -Level "INFO"
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-LogMessage "Setup System Monitor mode finished." -Level "INFO"
        exit 0 # Exit after setting up the monitor
    }

#$totalStopwatch = [System.Diagnostics.Stopwatch]::StartNew() # Removed unused variable

try {
    trap [System.Management.Automation.PipelineStoppedException] {
        # Set flag and let the exception terminate the script naturally
        # The finally block should execute during termination.
        Write-LogMessage "PipelineStoppedException trapped (likely Ctrl+C). Setting interrupt flag." -Level "WARN"
        $global:ScriptInterrupted = $true
        # DO NOT use break or continue here
    }

    Write-DebugLog -Message "Beginning main update process."

    # --- Check for Existing Installation (Moved Up) ---
    try {
        $installedExePath = Get-InstalledApplicationPath
    }
    catch{
        $installedExePath = $null
        Write-LogMessage "Loxone Config installation not found: $($_.Exception.Message)" -Level "INFO"
    }


    if ($installedExePath) {
        Write-DebugLog -Message "Installed application path = '${installedExePath}'"
        $localAppExe = Join-Path -Path $installedExePath -ChildPath "LoxoneConfig.exe"
        $installedVersion = Get-InstalledVersion -ExePath $localAppExe #This will now not throw if not installed
  if ($null -ne $installedVersion){ # <<< CHANGED: Correct comparison
   Write-LogMessage "Installed version: ${installedVersion}" -Level "INFO"
  }
        $normalizedInstalledVersion = Convert-VersionString $installedVersion
    }
     else {
        Write-LogMessage "No existing Loxone Config installation found. Cannot run Monitor test without installation." -Level "WARN" # Updated message
        $normalizedInstalledVersion = ""  # No version to compare
        # We might want to exit here if TestMonitor requires an installation, or let Start-LoxoneMonitor handle the null path
    }

     # --- Test Kill Mode --- 
    if ($TestKill) {
        Write-LogMessage "Running in Test Kill mode. Pausing indefinitely. Terminate PID $PID externally." -Level "WARN"
        Read-Host "Script paused for external termination test (PID $PID). Press Enter here AFTER terminating to see if finally block runs (unlikely)"
        # Script will likely never reach here if terminated forcefully
        Write-LogMessage "Read-Host completed after pause. This is unexpected if script was killed." -Level "WARN"
        exit 99 # Use a distinct exit code if it somehow continues
    }

     # --- Test Monitor Mode ---
    if ($TestMonitor) {
        Write-LogMessage "Running in Test Monitor mode." -Level "INFO"

        # Define potential source and destination log directories
        $userDocuments = [Environment]::GetFolderPath('MyDocuments')
        $userMonitorLogDir = Join-Path -Path $userDocuments -ChildPath "Loxone\Loxone Config\Monitor"
        $systemMonitorLogDir = "C:\Windows\SysWOW64\config\systemprofile\Documents\Loxone\Loxone Config\Monitor"
        $monitorDestinationLogDir = Join-Path -Path $ScriptSaveFolder -ChildPath "MonitorLogs"
        $monitorSourceLogDir = $null # Initialize

        # Check if user specified a source directory
        if (-not ([string]::IsNullOrWhiteSpace($MonitorSourceLogDirectory))) {
            $monitorSourceLogDir = $MonitorSourceLogDirectory
            Write-LogMessage "Using specified Monitor Source Log Directory: $monitorSourceLogDir" -Level "INFO"
        } else {
            # Default logic: Check if monitor is running, determine owner, decide path, or start it
            $existingMonitorProcess = Get-Process -Name "loxonemonitor" -ErrorAction SilentlyContinue

            if ($existingMonitorProcess) {
                Write-LogMessage "loxonemonitor.exe is already running (PID: $($existingMonitorProcess.Id)). Checking process SessionId..." -Level "INFO"
                try {
                    # Get process SessionId using CIM (more reliable than GetOwner across contexts)
                    $processCim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($existingMonitorProcess.Id)" -ErrorAction Stop
                    $processSessionId = $processCim.SessionId
                    Write-LogMessage "Detected SessionId of running loxonemonitor.exe: $processSessionId" -Level "INFO"

                    # Session 0 typically indicates SYSTEM or other non-interactive service accounts
                    if ($processSessionId -eq 0) {
                        $monitorSourceLogDir = $systemMonitorLogDir
                        Write-LogMessage "Running monitor detected in Session 0 (likely SYSTEM). Watching SYSTEM log path: $monitorSourceLogDir" -Level "INFO"
                    } else {
                        $monitorSourceLogDir = $userMonitorLogDir
                        Write-LogMessage "Running monitor detected in Session $processSessionId (likely User). Watching USER log path: $monitorSourceLogDir" -Level "INFO"
                    }
                } catch {
                    # If Get-CimInstance fails (often due to permissions when script user != process owner),
                    # deduce negatively: assume it's the SYSTEM process we can't query.
                    $exceptionMessage = $_.Exception.Message
                    Write-LogMessage "Could not query running loxonemonitor.exe details: $exceptionMessage" -Level "WARN"
                    Write-LogMessage "Assuming monitor process is running as SYSTEM due to query failure." -Level "WARN"
                    $monitorSourceLogDir = $systemMonitorLogDir
                    Write-LogMessage "Watching SYSTEM log path based on assumption: $monitorSourceLogDir" -Level "INFO"
                    Write-LogMessage "(Use -MonitorSourceLogDirectory parameter to specify the correct path if this assumption is wrong)" -Level "WARN"
                } # End of Catch block for Get-CimInstance
            } # End of if ($existingMonitorProcess)
            else { # Start of Else block (monitor not running)
                Write-LogMessage "loxonemonitor.exe not running. Attempting to start it directly..." -Level "INFO"
                # Find the executable first (logic adapted from Start-LoxoneMonitor)
                $loxoneMonitorExePath = $null
                if ($installedExePath) {
                    $loxoneMonitorExePath = Find-File -BasePath $installedExePath
                }

                if (-not $loxoneMonitorExePath) {
                    Write-LogMessage "loxonemonitor.exe not found under path: ${installedExePath}. Cannot start for test." -Level "ERROR"
                    # Skip watch if we can't start it
                } else {
                    try {
                        # Use Start-Process directly instead of Start-LoxoneMonitor/Start-ProcessInInteractiveSession
                        Start-Process -FilePath $loxoneMonitorExePath -ErrorAction Stop
                        Write-LogMessage "Started loxonemonitor.exe directly (PID: Check Task Manager)." -Level "INFO"
                        # Since we started it directly as the current user, watch the user path
                        $monitorSourceLogDir = $userMonitorLogDir
                        Write-LogMessage "Watching USER monitor log path after starting: $monitorSourceLogDir" -Level "INFO"
                    } catch {
                        Write-LogMessage "Failed to start Loxone Monitor directly: $($_.Exception.Message). Cannot proceed with log watch." -Level "ERROR"
                    }
                }
            }
        }

        # Removed self-elevation logic from TestMonitor mode.
        # Assumes monitor is already running as correct user (e.g., via -SetupSystemMonitor or manually)
        # or that the script is being run with appropriate privileges for the detected path.

        # Only proceed if we have a source directory determined (and didn't fail elevation)
        if ($monitorSourceLogDir) {
             $watchResult = Watch-And-Move-MonitorLogs -SourceLogDir $monitorSourceLogDir -DestinationLogDir $monitorDestinationLogDir -TimeoutMinutes $MonitorLogWatchTimeoutMinutes -CreateTestFile
             if ($watchResult) {
                 Write-LogMessage "Log watch completed successfully (likely found test file)." -Level "INFO"
             } else {
                 Write-LogMessage "Log watch finished without finding test file (or was interrupted/timed out)." -Level "WARN"
             }
        } else {
             Write-LogMessage "Could not determine or access Monitor Source Log Directory. Skipping log watch." -Level "WARN"
        }

        Stop-LoxoneMonitor

        Write-LogMessage "Test Monitor mode finished." -Level "INFO"
        exit 0
    }
	
    # --- Test Notifications Mode --- 
    if ($TestNotifications) {
        Write-LogMessage "Running in Test Notifications mode." -Level "INFO"
        Show-NotificationToLoggedInUsers -Title "Loxone Update Test" -Message "This is the START notification test."
        Start-Sleep -Seconds 5 # Pause briefly between notifications
        Show-NotificationToLoggedInUsers -Title "Loxone Update Test" -Message "This is the END notification test."
        Write-LogMessage "Test Notifications mode finished." -Level "INFO"
        exit 0
    }

    # --- Scheduled Task Setup (Run this first) ---
    $scheduledTaskName = "LoxoneUpdateTask"
    if (-not (Test-ScheduledTask)) {
        $scriptDestination = Save-ScriptToUserLocation -DestinationDir $ScriptSaveFolder -ScriptName "UpdateLoxone.ps1"
        Invoke-AdminAndCorrectPathCheck
        Register-ScheduledTaskForScript -ScriptPath $scriptDestination -TaskName $scheduledTaskName
    }
    else {
        Write-LogMessage "Called by scheduler, skipping scheduler creation." -Level "INFO"
    }

    # --- Installation Check Block Moved Up ---


    if ($SkipUpdateIfAnyProcessIsRunning -and $installedExePath) {
        $isRunning = Get-ProcessStatus -ProcessName "loxoneconfig" # Changed from Check-ProcessRunning
        if ($isRunning) {
            Write-LogMessage "LoxoneConfig.exe is running. Skipping update." -Level "INFO"
            exit 0  # Exit if Loxone Config is running and skip is enabled
        }
        else {
            Write-LogMessage "LoxoneConfig.exe is not running. Proceeding with update." -Level "INFO"
        }
    }

    $xmlUrl = "https://update.loxone.com/updatecheck.xml"
    Write-LogMessage "Loading update XML from ${xmlUrl}" -Level "INFO"
    try {
        $xmlContent = Invoke-WebRequest -Uri $xmlUrl -UseBasicParsing -ErrorAction Stop
        $xml = [xml]$xmlContent.Content
        Write-LogMessage "XML downloaded and parsed." -Level "INFO"
		Remove-Variable xmlContent -Scope Script # <<< ADDED: Clean up large variable
    }
    catch {
        Write-LogMessage "Error downloading/parsing XML: ${($_.Exception.Message)}" -Level "ERROR"
        throw $_
    }

    if ($DebugMode) {
        Write-LogMessage "XML Root: $($xml.DocumentElement.Name)" -Level "DEBUG"
        Write-LogMessage "Available update channels:" -Level "DEBUG"
        foreach ($node in $xml.DocumentElement.ChildNodes) {
            Write-LogMessage "- $($node.name)" -Level "DEBUG"
        }
    }
    else {
        Write-LogMessage "Update XML loaded. Channels are available." -Level "INFO"
    }

    $channelNode = $xml.Miniserversoftware.$Channel
    if (-not $channelNode) {
        Write-LogMessage "Channel '${Channel}' not found in XML." -Level "ERROR"
        throw "Channel '${Channel}' not found."
    }

    $zipUrl = $channelNode.Path
    $updateVersion = $channelNode.Version.Trim()
    $expectedFilesize = [int64]$channelNode.Filesize
    $expectedCRC32 = $channelNode.crc32
    if (-not $zipUrl) {
        Write-LogMessage "Path for channel '${Channel}' not found." -Level "ERROR"
        throw "ZIP path for channel '${Channel}' not found."
    }

    Write-LogMessage "Channel: ${Channel}" -Level "INFO"
    Write-LogMessage "Version: ${updateVersion}" -Level "INFO"
    Write-LogMessage "ZIP URL: ${zipUrl}" -Level "INFO"
    Write-LogMessage "Expected ZIP size: ${expectedFilesize} Bytes" -Level "INFO"

    $normalizedUpdateVersion = Convert-VersionString $updateVersion


    # --- Main Update Logic ---
    if ($installedExePath -and $normalizedInstalledVersion -eq $normalizedUpdateVersion) {
        Write-LogMessage "Installed version (${normalizedInstalledVersion}) is already up-to-date. Skipping installer update process." -Level "INFO"
    }
    else {
        # Either no installation, or version mismatch.  Proceed with download/install.

        $zipDestinationPath = Join-Path -Path $downloadDir -ChildPath "LoxoneConfigSetup.zip"
        Invoke-ZipDownloadAndVerification -ZipUrl $zipUrl -DestinationPath $zipDestinationPath -ExpectedCRC32 $expectedCRC32 -ExpectedFilesize $expectedFilesize -MaxRetries 2

        Write-LogMessage "Extracting .exe from ZIP..." -Level "INFO"
        try {
            Invoke-ZipFileExtraction -ZipPath $zipDestinationPath -DestinationPath $downloadDir # Changed from Extract-ZipFileWithLogging
        }
        catch {
            Write-LogMessage "Error extracting ZIP: ${($_.Exception.Message)}" -Level "ERROR"
            throw $_
        }

        $extractedExe = Get-ChildItem -Path $downloadDir -Filter "*.exe" -Recurse | Where-Object { $_.Name -like "LoxoneConfigSetup*" } | Select-Object -First 1
        if (-not $extractedExe) {
            Write-LogMessage ".exe installer not found in ZIP." -Level "ERROR"
            throw ".exe installer not found in ZIP."
        }
        Write-LogMessage ".exe installer extracted to ${($extractedExe.FullName)}." -Level "INFO"

         # Verify Signature (even for initial install)
        Get-ExecutableSignature -ExePath $extractedExe.FullName -TrustedThumbprintFile (Join-Path -Path $ScriptSaveFolder -ChildPath "TrustedCertThumbprint.txt") # Changed from Verify-ExecutableSignatureAndCertificate

        Write-LogMessage "Starting Loxone Config installer..." -Level "INFO"
        Start-LoxoneUpdateInstaller -InstallerPath $extractedExe.FullName -InstallMode $InstallMode
		 # --- Miniserver Update (Always runs after LoxoneConfig install/update) ---
		Write-LogMessage "Proceeding with Miniserver update." -Level "INFO"
		  Update-MS -DesiredVersion $updateVersion `
				  -MSListPath (Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt") `
				  -LogFile $global:LogFile `
				  -MaxLogFileSizeMB $MaxLogFileSizeMB `
				  -DebugMode $DebugMode `
				  -InstalledExePath $installedExePath `
				  -ScriptSaveFolder $ScriptSaveFolder

		Write-LogMessage "Loxone Config installation finished." -Level "INFO"
        Show-NotificationToLoggedInUsers -Title "Loxone Config Update Finished" -Message "Loxone Config has been updated to version ${updateVersion}."
		Write-LogMessage "Miniserver update processing completed." -Level "INFO"
        Show-NotificationToLoggedInUsers -Title "Loxone Update Finished" -Message "Loxone Config update to ${updateVersion} and Miniserver updates completed."
		exit 0  # Exit after Miniserver update, even if Loxone Config was updated/installed
    }
	 # --- Miniserver Update (Always runs) ---
    Write-LogMessage "Proceeding with Miniserver update." -Level "INFO"
      Update-MS -DesiredVersion $updateVersion `
              -MSListPath (Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt") `
              -LogFile $global:LogFile `
              -MaxLogFileSizeMB $MaxLogFileSizeMB `
              -DebugMode $DebugMode `
              -InstalledExePath $installedExePath `
              -ScriptSaveFolder $ScriptSaveFolder

    Write-LogMessage "Miniserver update processing completed." -Level "INFO"
    Show-NotificationToLoggedInUsers -Title "Loxone Update Finished" -Message "Miniserver updates completed (Loxone Config version ${normalizedInstalledVersion} was already up-to-date)."


    exit 0  # Normal exit
}
catch {
	$global:ErrorOccurred = $true # Set error flag.  This is now in the correct scope.
    $global:LastErrorLine = $_.InvocationInfo.ScriptLineNumber  # Capture the line number.
    Invoke-ScriptErrorHandling $_ # Changed from Handle-ScriptError
}
finally {
    # Check flags in order of precedence: Interruption > UAC Cancel > Caught Error > Success
    $exitCodeMsg = if ($LASTEXITCODE -ne $null) { "Last Exit Code: $LASTEXITCODE" } else { "Last Exit Code: (Not Set)" }

    if ($global:ScriptInterrupted) {
         Write-LogMessage "Script execution INTERRUPTED by user (Ctrl+C detected). $exitCodeMsg" -Level "WARN"
         # Optionally pause if interrupted interactively
         # if (-not (Test-ScheduledTask)) { Read-Host "Script interrupted. Press Enter to exit" }
    }
    elseif ($global:UacCancelled) {
         Write-LogMessage "Script execution finished after UAC prompt was cancelled. $exitCodeMsg" -Level "WARN"
         # Optionally pause if cancelled interactively
         # if (-not (Test-ScheduledTask)) { Read-Host "UAC cancelled. Press Enter to exit" }
    }
    elseif ($global:ErrorOccurred) {
        Write-LogMessage "Script execution finished with an ERROR on line $global:LastErrorLine. $exitCodeMsg" -Level "ERROR"
        # Only pause if running interactively AND an error occurred:
        if (-not (Test-ScheduledTask)) {
            Read-Host "An error occurred on line $($global:LastErrorLine). Press Enter to exit"
        }
    } else {
         # Log normal completion
         Write-LogMessage "Script execution finished successfully. $exitCodeMsg" -Level "INFO"
    }
}
#endregion
