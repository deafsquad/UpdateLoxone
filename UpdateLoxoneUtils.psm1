<#
.SYNOPSIS
Provides helper functions for the UpdateLoxone.ps1 script, handling tasks like logging, version checking, installation, Miniserver updates, notifications, and utility operations.

.DESCRIPTION
This module encapsulates reusable logic used by the main Loxone update script. Functions cover:
- Logging with call stack tracing and mutex protection.
- Log file rotation.
- Retrieving installed application versions and paths.
- Downloading files with progress, verification (CRC32, size), and retries.
- Calculating CRC32 checksums.
- Executing installers.
- Updating Loxone Miniservers based on a list.
- Sending user notifications via BurntToast (handling interactive vs. scheduled task context).
- Checking process status and scheduled task context.
- Validating executable signatures.
- Waiting for network connectivity.
- Parsing and handling credentials securely.

.NOTES
- Requires PowerShell 5.1 or later.
- Uses a mutex ('Global\UpdateLoxoneLogMutex') for log file access synchronization.
- Depends on the BurntToast module for notifications (will attempt install if missing).
- Exports numerous functions for use by the main script.
#>

# Global Mutex for Log File Access (using a unique name)
$script:LogMutex = New-Object System.Threading.Mutex($false, 'Global\UpdateLoxoneLogMutex')
$script:CallStack = [System.Collections.Generic.Stack[object]]::new() # Corrected type to hold objects
#region Utility Helpers
function GetScriptSaveFolder {
    [CmdletBinding()]
    param(
        # The $MyInvocation automatic variable (contains info about the caller). Use [object] for easier testing/mocking.
        [Parameter(Mandatory=$true)]
        [object]$InvocationInfo,
        
        # The $PSBoundParameters automatic variable (a dictionary of parameters passed to the caller).
        [Parameter(Mandatory=$true)]
        [hashtable]$BoundParameters,

        # The path to the user's profile directory (defaults to $env:USERPROFILE). Used as a fallback.
        [string]$UserProfilePath = $env:USERPROFILE
    )

    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    WriteLog -Message "Get-ScriptSaveFolder: Invocation Command Definition = '$($InvocationInfo.MyCommand.Definition)'" -Level DEBUG
    try {
    WriteLog -Message "Get-ScriptSaveFolder: BoundParameters contains ScriptSaveFolder = $($BoundParameters.ContainsKey('ScriptSaveFolder'))" -Level DEBUG
    if ($BoundParameters.ContainsKey('ScriptSaveFolder')) {
        WriteLog -Message "Get-ScriptSaveFolder: ScriptSaveFolder Parameter Value = '$($BoundParameters['ScriptSaveFolder'])'" -Level DEBUG
    }

    $determinedSaveFolder = $null

    # 1. Check if ScriptSaveFolder parameter was explicitly provided
    if ($BoundParameters.ContainsKey('ScriptSaveFolder')) {
        $determinedSaveFolder = $BoundParameters['ScriptSaveFolder']
        WriteLog -Message "Get-ScriptSaveFolder: Using provided parameter value: '$determinedSaveFolder'" -Level DEBUG
    } 
    # 2. If not provided, determine from InvocationInfo
    else {
        try {
            $scriptDir = Split-Path -Parent $InvocationInfo.MyCommand.Definition -ErrorAction Stop
            if (-not ([string]::IsNullOrWhiteSpace($scriptDir))) {
                $determinedSaveFolder = $scriptDir
                WriteLog -Message "Get-ScriptSaveFolder: Determined from script path: '$determinedSaveFolder'" -Level DEBUG
            } else {
                 WriteLog -Message "Get-ScriptSaveFolder: Split-Path returned empty/whitespace." -Level DEBUG
            }
        } catch {
            WriteLog -Message "Get-ScriptSaveFolder: Error splitting path from InvocationInfo: $($_.Exception.Message)" -Level WARN
            # Continue to fallback
        }
    }

    # 3. Fallback if still not determined (e.g., empty path from Split-Path, or parameter was provided but empty)
    if ([string]::IsNullOrWhiteSpace($determinedSaveFolder)) {
        WriteLog -Message "Get-ScriptSaveFolder: Could not determine path from parameter or invocation. Falling back to UserProfile path." -Level WARN
        $determinedSaveFolder = Join-Path -Path $UserProfilePath -ChildPath "UpdateLoxone" # Use parameter for fallback
        WriteLog -Message "Get-ScriptSaveFolder: Using fallback path: '$determinedSaveFolder'" -Level DEBUG
    }

    WriteLog -Message "Get-ScriptSaveFolder: Final determined path: '$determinedSaveFolder'" -Level INFO
    return $determinedSaveFolder
    }
    finally {
        ExitFunction # No change needed here, function name is correct
    }
}

#endregion

#region Logging Functions

#region Breadcrumb Helpers
function EnterFunction {
    param(
        # The name of the function being entered.
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,
        # The path to the script file containing the function.
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        # The line number where the function is defined or called from.
        [Parameter(Mandatory = $true)]
        [int]$LineNumber
    )
    # Store a custom object with more details
    $callInfo = [PSCustomObject]@{ Name = $FunctionName; Path = $FilePath; Line = $LineNumber }
    $script:CallStack.Push($callInfo)
    # Optional: Log entry with breadcrumb
    # WriteLog -Message "Entering $($callInfo.Name) ($($callInfo.Path):$($callInfo.Line))" -Level DEBUG
}

function ExitFunction {
    if ($script:CallStack.Count -gt 0) {
        $exitingFunction = $script:CallStack.Pop()
        # Optional: Log exit with breadcrumb (before popping)
        # WriteLog -Message "Exiting $exitingFunction" -Level DEBUG
    } else {
        WriteLog -Message "ExitFunction called but CallStack is empty!" -Level WARN
    }
}
#endregion Breadcrumb Helpers


# NEW WriteLog Function
# Re-entry guard flag for WriteLog
$script:InsideWriteLog = $false

function WriteLog {
    [CmdletBinding()]
    param(
        # The log message content.
        [Parameter(Mandatory=$true)]
        [string]$Message,

        # The severity level of the log message.
        [Parameter()]
        [ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',

        # Optional hashtable of parameters to include in DEBUG level messages.
        [Parameter()]
        [hashtable]$Parameters
        # Removed CallingScriptPath and CallingLineNumber parameters
    )
        # Suppress DEBUG messages if ScriptDebugMode is not active
        if ($Level -eq 'DEBUG' -and (-not $script:ScriptDebugMode)) {
            return # Do not log DEBUG messages when not in debug mode
        }

    # --- Re-entry Guard Start ---
    if ($script:InsideWriteLog) { return } # Prevent recursion
    $script:InsideWriteLog = $true


    try {
    # --- New Logic Start ---

    # --- Derive Full Call Stack Trace from Native Stack ---
    $nativeStack = Get-PSCallStack
    $fullTraceParts = [System.Collections.Generic.List[string]]::new()

    # Iterate from the top of the stack down to the immediate caller (index 1)
    # Optionally skip the very top frame (index Count - 1) if it's just the script entry point
    $startIndex = $nativeStack.Count - 1
    if ($startIndex -ge 1) { # Ensure there's more than just WriteLog itself
        $topFrame = $nativeStack[$startIndex]
        # Skip if it's the top-level script with no specific function (often line 0 or 1)
        if (($topFrame.FunctionName -eq '<ScriptBlock>' -or [string]::IsNullOrWhiteSpace($topFrame.FunctionName)) -and $topFrame.ScriptLineNumber -le 1) {
             $startIndex-- # Start from the next frame down
        }
    }

    for ($i = $startIndex; $i -ge 1; $i--) {
        $frame = $nativeStack[$i]
        # Extract components for the desired format: ScriptName:LineNumber FunctionName
        $scriptLeaf = if (-not ([string]::IsNullOrWhiteSpace($frame.ScriptName))) {
            Split-Path -Path $frame.ScriptName -Leaf
        } else {
            "<NoScript>" # Placeholder if ScriptName is missing
        }
        $frameLine = $frame.ScriptLineNumber
        $funcName = if (-not ([string]::IsNullOrWhiteSpace($frame.FunctionName)) -and $frame.FunctionName -ne '<ScriptBlock>') {
            $frame.FunctionName # Use FunctionName if valid and not just <ScriptBlock>
        } else {
            "" # Use empty string if FunctionName is not useful
        }

        # Determine the function name part (with leading space if it exists)
        $funcNamePart = if ($funcName) { " $funcName" } else { "" }

        # Format the string
        $frameString = "{0}:{1}{2}" -f $scriptLeaf, $frameLine, $funcNamePart
        $fullTraceParts.Add($frameString)
    }

    # Join the parts with ' -> ' (Oldest Caller -> ... -> Immediate Caller)
    $fullTraceString = $fullTraceParts -join ' -> '

    # --- Get Process/User Info ---
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $elevationStatus = if ($isAdmin) { "ADMIN" } else { "USER" }
    $currentUsername = $env:USERNAME
    $currentPID = $PID

    # --- Construct Final Log Prefix (New Format) ---
    $timestamp = Get-Date -Format "yyMMdd HH:mm:ss.fff" # Changed format to include milliseconds
    $logPrefix = "[$timestamp] [$currentPID`:$elevationStatus`:$currentUsername] [$($Level.ToUpper())]" # New base format

    # --- Get Immediate Caller Info ---
    $callerInfoString = "<UnknownCaller>" # Default
    if ($nativeStack.Count -ge 2) {
        $callerFrame = $nativeStack[1]
        $callerScriptLeaf = if (-not ([string]::IsNullOrWhiteSpace($callerFrame.ScriptName))) { Split-Path -Path $callerFrame.ScriptName -Leaf } else { "<NoScript>" }
        $callerFrameLine = $callerFrame.ScriptLineNumber
        $callerFuncName = if (-not ([string]::IsNullOrWhiteSpace($callerFrame.FunctionName)) -and $callerFrame.FunctionName -ne '<ScriptBlock>') { $callerFrame.FunctionName } else { "" }
        $callerFuncNamePart = if ($callerFuncName) { " $callerFuncName" } else { "" }
        $callerInfoString = "{0}:{1}{2}" -f $callerScriptLeaf, $callerFrameLine, $callerFuncNamePart
    } else {
        # Handle cases where stack is too shallow (e.g., direct call from console)
        $callerInfoString = "<DirectCall>"
        # Log this as DEBUG instead of writing directly to host
        # Use try-catch to prevent infinite loop if WriteLog calls itself here
        try { WriteLog -Message "Call stack depth insufficient for caller info in WriteLog." -Level DEBUG -ErrorAction SilentlyContinue } catch {}
    }

    # --- Construct Final Log Prefix (Modified) ---
    # $timestamp and base $logPrefix are constructed just before this block (lines 181-182)
    # Now, append the caller info string unconditionally
    $logPrefix += " [$callerInfoString]" # ALWAYS include immediate caller

    # Conditionally add FULL trace if in DebugMode AND trace is available
    if ($script:DebugMode -and $fullTraceString) {
        $logPrefix += " (Full Trace: $fullTraceString)" # Add full trace separately for debug
    }
# --- New Logic End ---

    # Base log entry
    $logEntry = "$logPrefix $Message"

    # Add parameter details if Level is DEBUG and Parameters are provided
    if ($Level -eq 'DEBUG' -and $Parameters -ne $null -and $Parameters.Count -gt 0) {
        $paramDetails = $Parameters.GetEnumerator() | ForEach-Object { "$($_.Name) = '$($_.Value)'" } | Join-String -Separator '; '
        $logEntry += " | Parameters: { $paramDetails }"
    }

    # --- Console Output ---
    # Always output ERROR and WARN
    # Output INFO unless $VerbosePreference is SilentlyContinue
    # Output DEBUG only if $DebugPreference is Continue
    # Use Write-Host with color coding based on level
    switch ($Level.ToUpper()) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARN' { Write-Host $logEntry -ForegroundColor Yellow }
        'DEBUG'   {
            # Only write DEBUG if $DebugPreference is 'Continue'
            if ($DebugPreference -eq 'Continue') {
                Write-Host $logEntry -ForegroundColor Cyan
            }
        }
        'INFO'    { Write-Host $logEntry -ForegroundColor Green } # Use Green for INFO
        default   { Write-Host $logEntry } # Fallback for safety or unknown levels
    }

    # --- File Output ---
    # Write all levels to the log file if $global:LogFile is defined
    if ($global:LogFile) {
        $lockAcquired = $false
        try {
            # Attempt to acquire the mutex with a timeout (e.g., 5000ms)
            if ($script:LogMutex.WaitOne(5000)) {
                $lockAcquired = $true
                # Ensure log directory exists
                $logDir = Split-Path -Path $global:LogFile -Parent
                if (-not (Test-Path $logDir)) {
                    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                }
                # Append to log file using StreamWriter for better handle management
                $stream = $null
                try {
                    # Open in append mode, specify UTF8 encoding, default buffer size
                    $stream = [System.IO.StreamWriter]::new($global:LogFile, $true, [System.Text.Encoding]::UTF8)
                    $stream.WriteLine($logEntry)
                }
                catch {
                    # Handle stream write error specifically
                    Write-Error "WriteLog: StreamWriter failed for log file '$($global:LogFile)': $($_.Exception.Message)" -ErrorAction Continue
                    # Re-throw or handle more gracefully if needed, but continue for now
                }
                finally {
                    # Ensure stream is closed/disposed even if error occurs during write
                    if ($stream -ne $null) {
                        $stream.Dispose()
                    }
                }
            } else {
                # Failed to acquire lock within timeout - Write directly to error stream to avoid recursion
                Write-Error "WriteLog: Timed out waiting for log file mutex for message: $Message" -ErrorAction Continue
            }
        }
        catch {
            # Write error to console if file logging fails (even with lock)
            Write-Error "WriteLog: Failed to write to log file '$($global:LogFile)' (lock acquired: $lockAcquired): $($_.Exception.Message)" -ErrorAction Continue
        }
        finally {
            # Release the mutex ONLY if it was acquired
            if ($lockAcquired) {
                $script:LogMutex.ReleaseMutex()
            }
        }
    } # End if ($global:LogFile)
    # --- Add System Notification for ERROR level ---
    if ($Level -eq 'ERROR') {
        try {
            # Use the existing notification function to handle user context
            ShowNotificationToLoggedInUsers -Title "Loxone Update Error" -Message $Message -ErrorAction SilentlyContinue
        } catch {
            # Log if notification fails, but don't stop the logging process
            # Use Write-Error directly to avoid potential recursion if ShowNotificationToLoggedInUsers calls WriteLog
            Write-Error "WriteLog: Failed to send system notification for error: $($_.Exception.Message)" -ErrorAction Continue
        }
    }
    # --- End Notification ---

    } # End outer try block for re-entry guard
    finally {
        # Ensure the guard flag is reset even if errors occur
        $script:InsideWriteLog = $false
    }
    # --- Re-entry Guard End ---
}
# END NEW WriteLog Function


#endregion Logging Functions

#region Log Rotation
function InvokeLogFileRotation {
    param(
        # The full path to the log file to rotate.
        [string]$LogPath,
        # The maximum number of archive files to keep.
        [int]$MaxArchives = 24,
        # Switch to enable detailed debug logging for the rotation process.
        [Parameter(Mandatory=$false)][switch]$DebugMode
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    if ($DebugMode) { WriteLog -Message "Starting log rotation check for '$(Split-Path -Leaf $LogPath)'." -Level INFO } # Already correct
    WriteLog -Message "Checking if log path '$(Split-Path -Leaf $LogPath)' exists." -Level DEBUG # Already correct
    if (Test-Path $LogPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logDir = Split-Path -Path $LogPath -Parent
        $archiveFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogPath) + "_${timestamp}.log"
        $archivePath = Join-Path -Path $logDir -ChildPath $archiveFileName
        WriteLog -Message "Generating archive filename: '$archiveFileName'." -Level DEBUG # Already correct
        
        # Note: The size check happens *before* calling this function. Rotation is attempted if size exceeds limit.
        if ($DebugMode) { WriteLog -Message "Log file meets rotation criteria (size or forced). Proceeding with rotation attempt for '$(Split-Path -Leaf $LogPath)'." -Level INFO } # Already correct
        # Removed the old DEBUG message here as the INFO one above is more comprehensive for the start of the attempt.
        
        $lockAcquired = $false
        $renameSuccess = $false
        $maxRenameAttempts = 3
        $renameAttemptDelayMs = 500 # Wait 0.5 seconds between attempts
        $archivedFilePath = $null # Variable to store the successful archive path

        try {
            WriteLog -Message "Attempting to acquire log mutex..." -Level DEBUG # Already correct
            # Attempt to acquire the mutex with a timeout (e.g., 10000ms)
            if ($script:LogMutex.WaitOne(10000)) {
                $lockAcquired = $true
                WriteLog -Message "Acquired log mutex." -Level DEBUG # Already correct

                for ($attempt = 1; $attempt -le $maxRenameAttempts; $attempt++) {
                    try {
                        WriteLog -Message "$(Split-Path -Leaf $LogPath) > $(Split-Path -Leaf $archivePath) (${attempt}/${maxRenameAttempts})" -Level INFO # Already correct
                        # Try renaming the log file
                        Rename-Item -Path $LogPath -NewName $archivePath -Force -ErrorAction Stop
                        if ($DebugMode) { WriteLog -Message "Successfully renamed log file to '$(Split-Path -Leaf $archivePath)' on attempt $attempt." -Level INFO } # Already correct
                        $renameSuccess = $true
                        $archivedFilePath = $archivePath # Store the successful path
                        break # Exit loop on success
                    }
                    catch {
                        WriteLog -Message "Attempt ${attempt}/${maxRenameAttempts}: Failed to rename $(Split-Path -Leaf $LogPath) > $(Split-Path -Leaf $archivePath). Error: $($_.Exception.Message)." -Level WARN # Already correct
                        if ($attempt -lt $maxRenameAttempts) {
                            Start-Sleep -Milliseconds $renameAttemptDelayMs
                        }
                    }
                } # End for loop
            } else {
                WriteLog -Message "Timed out waiting for log mutex after 10 seconds. Rotation skipped for '$(Split-Path -Leaf $LogPath)'." -Level WARN # Already correct
            }
        } catch {
             # Catch unexpected errors during mutex handling or loop
             WriteLog -Message "InvokeLogFileRotation: Unexpected error during rotation attempt: $($_.Exception.Message)" -Level ERROR
        } finally {
            # Release the mutex ONLY if it was acquired
            if ($lockAcquired) {
                $script:LogMutex.ReleaseMutex()
                WriteLog -Message "Released log mutex." -Level DEBUG # Already correct
            }
        }
        # Continue to cleanup logic regardless of rename success/failure
        if (-not $renameSuccess) {
             WriteLog -Message "Failed to rename log file '$(Split-Path -Leaf $LogPath)' after $maxRenameAttempts attempts. Proceeding with cleanup." -Level WARN # Already correct
        }
   }
   $deletedFilesList = $null # Variable to store the list of files marked for deletion
   if ($DebugMode) { WriteLog -Message "Starting cleanup of old archives in '$logDir' (Max: $MaxArchives)." -Level INFO } # Already correct
   $logDir = Split-Path -Path $LogPath
   $pattern = [System.IO.Path]::GetFileNameWithoutExtension($LogPath) + "_*.log"
    $archives = Get-ChildItem -Path $logDir -Filter $pattern | Sort-Object LastWriteTime
    WriteLog -Message "Found $($archives.Count) archive files matching pattern '$pattern'." -Level DEBUG # Already correct
    if ($archives.Count -gt $MaxArchives) {
        $toDelete = $archives | Select-Object -First ($archives.Count - $MaxArchives)
        $deletedFilesList = $toDelete # Store the list before deletion attempts
        WriteLog -Message "Will delete $($toDelete.Count) oldest archive(s)." -Level DEBUG # Already correct
        foreach ($file in $toDelete) {
            try {
                WriteLog -Message "Deleting $($file.Name)." -Level DEBUG # Already correct
                Remove-Item -Path $file.FullName -Force
            }
            catch {
                WriteLog -Message "Failed to delete old archive '$($file.Name)': $($_.Exception.Message)." -Level ERROR # Already correct
            }
        }
    }
    if ($DebugMode) { WriteLog -Message "Log rotation and cleanup finished for '$(Split-Path -Leaf $LogPath)'." -Level INFO } # Already correct

    # Construct and log the summary message
    $summaryMessage = ""
    if ($archivedFilePath) {
    } else {
        $originalLogName = Split-Path -Leaf $LogPath
        $summaryMessage += "Archiving failed for $originalLogName. "
    }

    if ($deletedFilesList -and $deletedFilesList.Count -gt 0) {
        $deletedNames = ($deletedFilesList | ForEach-Object { $_.Name }) -join ', '
        $summaryMessage += "$($deletedFilesList.Count) deleted [$deletedNames]"
    } else {
        $summaryMessage += "No old archives deleted."
    }
    WriteLog -Level INFO -Message $summaryMessage # Already correct

    ExitFunction # Already correct
}
#endregion Log Rotation

#region Installation Helpers
function GetInstalledVersion {
    param(
        # The path to the executable file or its installation directory.
        [string]$ExePath
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    if (-not $ExePath.EndsWith(".exe")) {
        $ExePath = Join-Path -Path $ExePath -ChildPath "LoxoneConfig.exe"
    }
    if (Test-Path $ExePath) {
        try {
            $version = (Get-Item $ExePath).VersionInfo.FileVersion
            $version = $version.Trim()
            WriteLog -Message "Found version of '${ExePath}': ${version}" -Level INFO # Already correct
            return $version
        }
        catch {
            WriteLog -Message "Error retrieving version from '${ExePath}': ${($_.Exception.Message)}" -Level WARN # Already correct
		   Return $null
        }
    }
    else {
        WriteLog -Message "Installed application not found at '${ExePath}'." -Level WARN # Already correct
		Return $null
    }
    finally {
        ExitFunction # Already correct
    }
}

function StartLoxoneUpdateInstaller {
    param(
        # The full path to the Loxone installer executable.
        [string]$InstallerPath,
        # The installation mode ('silent' or 'verysilent').
        [string]$InstallMode,
        # The script's save folder (used for potential logging by the installer, though not directly used here).
        [string]$ScriptSaveFolder
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    WriteLog -Message "Starting update installer: ${InstallerPath} with install mode ${InstallMode}." -Level INFO
    try {
    try {
        Start-Process -FilePath $InstallerPath -ArgumentList "/${InstallMode}" -Wait
        WriteLog -Message "Update installer executed successfully." -Level INFO
    }
    catch {
        WriteLog -Message "Error executing update installer: ${($_.Exception.Message)}" -Level ERROR
        throw $_
    }
    }
    finally {
        ExitFunction # Already correct
    }
}
  

#endregion Installation Helpers

#region Notification Helper
function ShowNotificationToLoggedInUsers {
    param(
        # The title of the toast notification.
        [string]$Title,
        # The main message body of the toast notification.
        [string]$Message,
        # Duration in seconds the toast should be displayed (0 for default). Not directly used by BurntToast.
        [int]$Timeout = 0,
        # The Application ID to associate with the notification (defaults to PowerShell).
        [string]$AppId = 'WindowsPowerShell'
    )

    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber

    # Capture caller context for breadcrumbs to pass to WriteLog
    $callerStackInfo = (Get-PSCallStack)[1] # Get info about the function/script that CALLED Show-NotificationToLoggedInUsers
    $callerPathForLog = $callerStackInfo.ScriptName
    $callerLineForLog = $callerStackInfo.ScriptLineNumber

    # $callerFrame is no longer needed as WriteLog determines the stack automatically
    WriteLog -Message "Entering ShowNotificationToLoggedInUsers" -Level DEBUG # Removed invalid -CallingScriptPath and -CallingLineNumber parameters
    try {
    $isRunningAsTask = TestScheduledTask # This will call the function available in the current scope (module or mocked)
    WriteLog -Message "Result of TestScheduledTask: $isRunningAsTask" -Level DEBUG

    if (-not $isRunningAsTask) {
        WriteLog -Message "Running interactively. Attempting direct notification." -Level INFO
        try {
             if (-not (Get-Module -ListAvailable -Name BurntToast)) {
                 WriteLog -Message "BurntToast module not found. Attempting to install for current user." -Level WARN
                 Install-Module -Name BurntToast -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction SilentlyContinue
             }
             Import-Module BurntToast -ErrorAction SilentlyContinue
             $appLogoPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
             New-BurntToastNotification -AppLogo $appLogoPath -Text $Title, $Message -ErrorAction Stop
             WriteLog -Message "Direct notification sent successfully." -Level INFO
             return
        } catch {
            WriteLog -Message "Direct notification failed: $($_.Exception.Message). Falling back to scheduled task method." -Level WARN
        }
    }

    WriteLog -Message "Attempting notification via scheduled task method." -Level INFO
    $activeSessions = @()
    try {
        WriteLog -Message "Querying Win32_LogonSession for LogonType = 2..." -Level DEBUG
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType = 2"
        WriteLog -Message "Found $($sessions.Count) sessions with LogonType 2." -Level DEBUG
        
        # Log details of all found sessions before filtering
        if ($sessions) {
            WriteLog -Message "Details of all LogonType=2 sessions found:" -Level DEBUG
            foreach ($s in $sessions) {
                $assocAcc = Get-CimAssociatedInstance -InputObject $s -ResultClassName Win32_Account -ErrorAction SilentlyContinue
                $userName = if ($assocAcc) { "$($assocAcc[0].Domain)\$($assocAcc[0].Name)" } else { "<Account N/A>" }
                WriteLog -Message "- Session ID: $($s.LogonId), StartTime: $($s.StartTime), User: $userName" -Level DEBUG
            }
        } else {
            WriteLog -Message "No LogonType=2 sessions returned by Get-CimInstance." -Level DEBUG
        }

        foreach ($session in $sessions) {
            $assocAccounts = Get-CimAssociatedInstance -InputObject $session -ResultClassName Win32_Account -ErrorAction SilentlyContinue
            if ($assocAccounts) {
                WriteLog -Message "Found associated account: $($assocAccounts[0].Domain)\$($assocAccounts[0].Name) for session $($session.LogonId)." -Level DEBUG
                $quserOutput = quser.exe $session.LogonId 2>$null | Out-String
                WriteLog -Message "quser output for session $($session.LogonId):`n$quserOutput" -Level DEBUG
                # Check if quser output contains the session ID, indicating it's likely an interactive session
                if ($quserOutput -match "\b$($session.LogonId)\b") {
                    WriteLog -Message "Session $($session.LogonId) found in quser output, assuming interactive." -Level DEBUG
                    $userPrincipal = New-Object System.Security.Principal.NTAccount($assocAccounts[0].Domain, $assocAccounts[0].Name)
                    $activeSessions += [PSCustomObject]@{
                        SessionId = $session.LogonId
                        UserName = $assocAccounts[0].Name
                        Domain = $assocAccounts[0].Domain
                        UserSID = $userPrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        Principal = "$($assocAccounts[0].Domain)\$($assocAccounts[0].Name)"
                    }
                    WriteLog -Message "Added active interactive session: $($assocAccounts[0].Domain)\$($assocAccounts[0].Name) (Session ID: $($session.LogonId))" -Level DEBUG
                } else {
                    WriteLog -Message "Session $($session.LogonId) NOT found in quser output or output is empty." -Level DEBUG
                }
            } else {
                 WriteLog -Message "Could not find associated account for session ID: $($session.LogonId)." -Level DEBUG
            }
        }
    } catch {
        WriteLog -Message "Error querying user sessions: $($_.Exception.Message)" -Level WARN
        WriteLog -Message "Stack trace for session query error: $($_.ScriptStackTrace)" -Level DEBUG # Changed level to DEBUG as per convention
    }

    WriteLog -Message "Total active sessions identified for notification: $($activeSessions.Count)" -Level DEBUG
    if ($activeSessions.Count -gt 0) {
        if (-not (Get-Module -ListAvailable -Name BurntToast)) {
             WriteLog -Message "BurntToast module not found. Notifications may fail if not installed for target users." -Level WARN
        }

        $appLogoPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

        foreach ($userSession in $activeSessions) {
            $taskName = "TempLoxoneToastNotification_$($userSession.UserName)_$(Get-Date -Format 'yyyyMMddHHmmssfff')"
            $principal = $userSession.Principal
            WriteLog -Message "Attempting to send notification to user '$principal' via temporary scheduled task '$taskName'." -Level INFO

            $escapedTitle = $Title -replace "'", "''"
            $escapedMessage = $Message -replace "'", "''"
            $actionCommand = "Import-Module BurntToast -ErrorAction SilentlyContinue; New-BurntToastNotification -AppLogo '$appLogoPath' -Text '$escapedTitle', '$escapedMessage' -ErrorAction SilentlyContinue"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -Command `"$actionCommand`""
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
            # Use older, more compatible parameters for settings (Reverted based on test failures)
            $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
                                                     -DisallowStartIfOnBatteries $false `
                                                     -StopIfGoingOnBatteries $false `
                                                     -AllowHardTerminate $true `
                                                     -StartWhenAvailable $true `
                                                     -RunOnlyIfNetworkAvailable $false `
                                                     -Enabled $true `
                                                     -Hidden $true `
                                                     -ExecutionTimeLimit ([System.TimeSpan]::Zero) 
try {
    WriteLog -Message "Attempting to register scheduled task '$taskName' for user '$principal'..." -Level DEBUG # Added Log
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -RunLevel Limited -Force -ErrorAction Stop
    WriteLog -Message "Successfully registered task '$taskName'." -Level DEBUG # Changed Level
    WriteLog -Message "Attempting to start scheduled task '$taskName'..." -Level DEBUG # Added Log
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    WriteLog -Message "Successfully started task '$taskName'." -Level DEBUG # Changed Level
} catch {
    WriteLog -Message "Error during scheduled task registration/start for user '$principal': $($_.Exception.Message)" -Level ERROR # Changed Level
    WriteLog -Message "Stack trace for task registration/start error: $($_.ScriptStackTrace)" -Level ERROR # Changed Level
} finally {
            } finally {
                Start-Sleep -Seconds 1
                try {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                    WriteLog -Message "Unregistered temporary task '$taskName'." -Level DEBUG
                } catch {
                    WriteLog -Message "Failed to unregister temporary task '$taskName': $($_.Exception.Message)" -Level WARN
                }
            }
        }
    }
    else {
         WriteLog -Message "No active interactive user sessions found to display the notification." -Level WARN
    }
    }
    finally {
        ExitFunction # Already correct
    }
}
#endregion Notification Helper

#region Error Handling
function InvokeScriptErrorHandling {
    param(
        # The PowerShell ErrorRecord object to handle.
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    if (-not $ErrorRecord) { $ErrorRecord = $Error[0] }
    try {
    $invInfo = $ErrorRecord.InvocationInfo
    $command = if ($invInfo -and $invInfo.MyCommand) { $invInfo.MyCommand.ToString() } else { "N/A" }
    $scriptName = if ($invInfo -and $invInfo.ScriptName) { $invInfo.ScriptName } else { "N/A" }
    $lineNumber = if ($invInfo -and $invInfo.ScriptLineNumber) { $invInfo.ScriptLineNumber } else { "N/A" }
    $line = if ($invInfo -and $invInfo.Line) { $invInfo.Line } else { "N/A" }
    $position = if ($invInfo -and $invInfo.PositionMessage) { $invInfo.PositionMessage } else { "N/A" }
    $fullCommandLine = if ($line) { $line.Trim() } else { "N/A" }
    $localVars = Get-Variable -Scope 1 | ForEach-Object { "$($_.Name) = $($_.Value)" } | Out-String

    WriteLog -Message "ERROR in command: ${command}" -Level ERROR # Already correct
    WriteLog -Message "Script: ${scriptName}" -Level ERROR # Already correct
    WriteLog -Message "Line number: ${lineNumber}" -Level ERROR # Already correct
    WriteLog -Message "Offending line: ${line}" -Level ERROR # Already correct
    WriteLog -Message "Position details: ${position}" -Level ERROR # Already correct
    WriteLog -Message "Full command line: ${fullCommandLine}" -Level ERROR # Already correct
    WriteLog -Message "Local variables in scope:`n${localVars}" -Level ERROR # Already correct

    ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate Failed!" -Message "Error: ${($ErrorRecord.Exception.Message)}`nCommand: ${command}`nLine: ${lineNumber}`nCommandLine: ${fullCommandLine}`nLocal Variables:`n${localVars}" -Timeout 0

    # Log comprehensive error details
    WriteLog -Message "-------------------- SCRIPT ERROR DETAILS --------------------" -Level ERROR # Already correct
    WriteLog -Message "Full Error Record: $($ErrorRecord.ToString())" -Level ERROR # Already correct
    WriteLog -Message "Exception Message: ${($ErrorRecord.Exception.Message)}" -Level ERROR # Already correct
    
    if ($invInfo) {
        WriteLog -Message "Occurred in Command: ${command}" -Level ERROR # Already correct
        WriteLog -Message "Script: ${scriptName}" -Level ERROR # Already correct
        WriteLog -Message "Line Number: ${lineNumber}" -Level ERROR # Already correct
        WriteLog -Message "Offending Line Content: ${line}" -Level ERROR # Already correct
        WriteLog -Message "Position Details: ${position}" -Level ERROR # Already correct
        WriteLog -Message "Full Command Line Parsed: ${fullCommandLine}" -Level ERROR # Already correct
    } else {
        WriteLog -Message "InvocationInfo not available." -Level ERROR # Already correct
    }
    
    WriteLog -Message "Local Variables in Caller Scope:`n${localVars}" -Level ERROR # Already correct
    
    # Log PowerShell Script Stack Trace
    if ($ErrorRecord.ScriptStackTrace) {
        WriteLog -Message "PowerShell Script Stack Trace:`n${($ErrorRecord.ScriptStackTrace)}" -Level ERROR # Already correct
    } else {
        WriteLog -Message "No PowerShell Script Stack Trace available." -Level ERROR # Already correct
    }

    # Log .NET Exception Stack Trace (if available)
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.StackTrace) {
        WriteLog -Message ".NET Exception Stack Trace:`n${($ErrorRecord.Exception.StackTrace)}" -Level ERROR # Already correct
    } else {
        WriteLog -Message "No .NET Exception Stack Trace available." -Level ERROR # Already correct
    }
    WriteLog -Message "------------------ END SCRIPT ERROR DETAILS ------------------" -Level ERROR # Already correct
    
	$global:ErrorOccurred = $true
    $global:LastErrorLine = $lineNumber
    
    WriteLog -Message "Script error occurred on line $global:LastErrorLine. Error flag set." -Level ERROR # Already correct
    # Removed exit 1 - Let the caller handle termination/pausing
    }
    finally {
        ExitFunction # Already correct
    }
}
#endregion Error Handling

#region Process and Task Helpers
function GetProcessStatus {
    param(
        # The name of the process to check (without .exe).
        [Parameter(Mandatory = $true)] [string]$ProcessName,
        # If specified, attempt to stop the process if found.
        [switch]$StopProcess
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try { # Outer try
        try { # Inner try (Original logic)
            $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
            if ($processes) {
                WriteLog -Message "Process '${ProcessName}' is running." -Level INFO
                if ($StopProcess) {
                    foreach ($proc in $processes) {
                        try { # Innermost try (Original logic)
                            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                            WriteLog -Message "Process '${ProcessName}' (PID: $($proc.Id)) stopped." -Level INFO
                        }
                        catch { # Innermost catch (Original logic)
                            WriteLog -Message "Failed to stop process '${ProcessName}' (PID: $($proc.Id)): ${($_.Exception.Message)}" -Level ERROR
                            throw $_
                        }
                    }
                }
                return $true
            }
            else {
                WriteLog -Message "Process '${ProcessName}' is not running." -Level INFO
                return $false
            }
        } # End of Inner try
        catch { # Catch for Inner try (Original logic)
            WriteLog -Message "Error checking process '${ProcessName}': ${($_.Exception.Message)}" -Level ERROR
            throw $_
        } # End of Inner catch
    } # End of Outer try
    finally { # Finally for Outer try
        ExitFunction # Already correct
    } # End of Outer finally
}

function TestScheduledTask {
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    WriteLog -Message "Executing TestScheduledTask function from module." -Level DEBUG # Adjusted log message
    # Removed outer try/catch, inner try/catch removed to allow errors to propagate
    try {
        $parentProcessId = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId
        $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId"
        $parentProcessName = $parentProcess.Name
        WriteLog -Message "Parent process for PID $PID is ${parentProcessName} (PID: ${parentProcessId})" -Level DEBUG
        if ($parentProcessName.Trim() -ieq "taskeng.exe" -or $parentProcessName.Trim() -ieq "svchost.exe") { return $true } else { return $false } # Added .Trim() for robustness
    }
    finally {
        ExitFunction # Already correct
    }
}

function Get-ExecutableSignature { # Renamed from TestExecutableSignature
    [CmdletBinding()]
    param(
        # The path to the executable file to validate.
        [string]$ExePath
    )

    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    WriteLog -Message "Validating signature for '$ExePath'..." -Level INFO # Removed expected signature from log
    try {

    if (-not (Test-Path -Path $ExePath -PathType Leaf)) {
        WriteLog -Message "Executable file not found at '$ExePath'. Cannot validate signature." -Level WARN
        return $false
    }

    try {
        $signatureInfo = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction Stop
        if ($signatureInfo.Status -eq 'Valid') {
            WriteLog -Message "Signature VALID: Authenticode status for '$ExePath' is 'Valid'." -Level INFO
            return $true
        } else {
            WriteLog -Message "Signature INVALID: Authenticode status for '$ExePath' is '$($signatureInfo.Status)'." -Level WARN
            return $false
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        WriteLog -Message "Signature check failed: File not found at '$ExePath'." -Level WARN
        return $false
    } catch {
        $errorMessage = $_.Exception.Message
        WriteLog -Message "Signature check failed for '$ExePath': $errorMessage" -Level WARN
        if ($errorMessage -like '*file is not digitally signed*') {
             WriteLog -Message "(File '$ExePath' is not digitally signed.)" -Level INFO
        }
        return $false
    }
    }
    finally {
        ExitFunction # Already correct
    }
}

function StartProcessInteractive {
    param(
        # The path to the executable to start.
        [Parameter(Mandatory = $true)][string]$FilePath,
        # Optional arguments to pass to the executable.
        [string]$Arguments = ""
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
    try {
        $shell = New-Object -ComObject "Shell.Application"
        $process = $shell.ShellExecute($FilePath, $Arguments, "", "open", 1)
        Wait-Process -Id $process.Id
    }
    catch {
        throw "Failed to launch process interactively: ${($_.Exception.Message)}"
    }
    }
    finally {
        ExitFunction # Already correct
    }
}
#endregion Process and Task Helpers

#region Network Helpers
function WaitForPingTimeout {
    param(
        # The IP address, hostname, or URL containing the host to ping.
        [string]$InputAddress,
        # Maximum time in seconds to wait for the host to become unreachable.
        [int]$TimeoutSeconds = 300,
        # Interval in seconds between ping attempts.
        [int]$IntervalSeconds = 5
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    $timeout = New-TimeSpan -Seconds $TimeoutSeconds
    try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    # Extract IP/Hostname from potential URL
    $TargetHost = $InputAddress
    if ($InputAddress -match '(?<=:\/\/)[^\/:]+') {
        $TargetHost = $matches[0]
        WriteLog -Message "Wait-For-PingTimeout: Extracted host '$TargetHost' from '$InputAddress'" -Level DEBUG
    }

    while ($stopwatch.Elapsed -lt $timeout) {
        if (-not (Test-NetConnection -ComputerName $TargetHost -Port 80 -InformationLevel Quiet)) { # Use extracted host
            WriteLog -Message "Ping timeout: $TargetHost became unreachable." -Level DEBUG
            $stopwatch.Stop()
            return $true
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    $stopwatch.Stop()
    WriteLog -Message "Ping timeout: $TargetHost remained reachable for $($TimeoutSeconds) seconds." -Level DEBUG
    return $false
    }
    finally {
        ExitFunction # Already correct
    }
}

function WaitForPingSuccess {
    param(
        # The IP address, hostname, or URL containing the host to ping.
        [string]$InputAddress,
        # Maximum time in seconds to wait for the host to become reachable.
        [int]$TimeoutSeconds = 300,
        # Interval in seconds between ping attempts.
        [int]$IntervalSeconds = 5
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    $timeout = New-TimeSpan -Seconds $TimeoutSeconds
    try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Extract IP/Hostname from potential URL
    $TargetHost = $InputAddress
    if ($InputAddress -match '(?<=:\/\/)[^\/:]+') {
        $TargetHost = $matches[0]
        WriteLog -Message "Wait-For-Ping-Success: Extracted host '$TargetHost' from '$InputAddress'" -Level DEBUG
    }

    while ($stopwatch.Elapsed -lt $timeout) {
        if (Test-NetConnection -ComputerName $TargetHost -Port 80 -InformationLevel Quiet) { # Use extracted host
            WriteLog -Message "Ping success: $TargetHost is reachable." -Level DEBUG
            $stopwatch.Stop()
            return $true
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    $stopwatch.Stop()
    WriteLog -Message "Ping success: $TargetHost did not become reachable within $($TimeoutSeconds) seconds." -Level DEBUG
    return $false
    }
    finally {
        ExitFunction # Already correct
    }
}
#endregion Network Helpers

#region Installation Helpers (Continued)
function GetInstalledApplicationPath {
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    try {
        $registryPaths = @(
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $appName = "Loxone Config"

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                $displayName = $key.GetValue("DisplayName") -as [string]
                if ($displayName -eq $appName) {
                    $installLocation = $key.GetValue("InstallLocation") -as [string]
                    if ($installLocation -and (Test-Path $installLocation)) {
                        WriteLog -Message "Found Loxone Config installation at: ${installLocation}" -Level DEBUG # Corrected function call
                        return $installLocation
                    }
                }
            }
        }
    }
    WriteLog -Message "Loxone Config installation path not found in registry." -Level INFO # Corrected function call
    return $null
    } # Closing brace for the try block
    finally {
        ExitFunction # Corrected function call
    } # Closing brace for the finally block
}

function GetLoxoneConfigExePath {
    [CmdletBinding()]
    param() # No parameters needed

    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    try {
        $installDir = GetInstalledApplicationPath # Corrected function call (removed hyphen)
        if ($installDir) {
            $exePath = Join-Path -Path $installDir -ChildPath "LoxoneConfig.exe"
            WriteLog -Message "Determined LoxoneConfig.exe path: '$exePath'" -Level DEBUG # Corrected function call
            return $exePath
        } else {
            WriteLog -Message "Loxone Config installation directory not found. Cannot determine .exe path." -Level INFO # Corrected function call
            return $null
        }
    }
    finally {
        ExitFunction # Corrected function call
    }
}
#endregion Installation Helpers (Continued)

#region Register-ScheduledTaskForScript Function
function Register-ScheduledTaskForScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$ScriptPath,
        [Parameter(Mandatory = $true)] [string]$TaskName,
        [Parameter()] [int]$ScheduledTaskIntervalMinutes = 10,
        [Parameter()] [string]$Channel = "Test",
        [Parameter()] [bool]$DebugMode = $false,
        [Parameter()] [bool]$EnableCRC = $true,
        [Parameter()] [string]$InstallMode = "verysilent",
        [Parameter()] [bool]$CloseApplications = $false,
        [Parameter()] [string]$ScriptSaveFolder = "$env:USERPROFILE\Scripts",
        [Parameter()] [int]$MaxLogFileSizeMB = 1,
        [Parameter()] [bool]$SkipUpdateIfAnyProcessIsRunning = $false
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    WriteLog -Message "Register-ScheduledTaskForScript called. Received -DebugMode parameter value: $DebugMode" -Level DEBUG

    # Check if task exists
    $taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    # Always attempt to register/update. If it exists, unregister first to ensure arguments are clean.
    if ($taskExists) {
        WriteLog -Message "Scheduled task '${TaskName}' already exists. Unregistering before re-registering to ensure arguments are updated." -Level INFO
        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
        catch { WriteLog -Message "Failed to unregister existing task '$TaskName': $($_.Exception.Message). Re-registration might fail or use old settings." -Level WARN }
    }
    
    WriteLog -Message "Attempting to register task '${TaskName}'." -Level INFO
    # Build action arguments, conditionally adding -DebugMode
    $actionArgs = [System.Collections.Generic.List[string]]::new()
    $actionArgs.Add("-NoProfile")
    $actionArgs.Add("-ExecutionPolicy Bypass")
    $actionArgs.Add("-File `"$ScriptPath`"")
    $actionArgs.Add("-Channel `"$Channel`"")
    if ($DebugMode) {
        $actionArgs.Add("-DebugMode")
        WriteLog -Message "Adding -DebugMode to scheduled task arguments." -Level DEBUG
    }
    $actionArgs.Add("-EnableCRC `$($EnableCRC)")
    $actionArgs.Add("-InstallMode `"$InstallMode`"")
    $actionArgs.Add("-CloseApplications `$($CloseApplications)")
    $actionArgs.Add("-ScriptSaveFolder `"$ScriptSaveFolder`"")
    $actionArgs.Add("-MaxLogFileSizeMB $MaxLogFileSizeMB")
    $actionArgs.Add("-ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes")
    $actionArgs.Add("-SkipUpdateIfAnyProcessIsRunning `$($SkipUpdateIfAnyProcessIsRunning)")
    
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument ($actionArgs -join " ")
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $ScheduledTaskIntervalMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest # Run as SYSTEM
    
    # Simplified settings for compatibility
    $settingsParams = @{
        MultipleInstances = 'IgnoreNew'
        StartWhenAvailable = $true
        Hidden = $true
        ExecutionTimeLimit = ([System.TimeSpan]::Zero) # No time limit
        # Add other basic, known compatible parameters if needed
    }
    WriteLog -Message "Attempting to create task settings with parameters: $($settingsParams | Out-String)" -Level DEBUG
    $settings = New-ScheduledTaskSettingsSet @settingsParams -ErrorAction SilentlyContinue

    if (-not $settings) {
         WriteLog -Message "Failed to create ScheduledTaskSettingsSet object. Task registration cannot proceed." -Level ERROR
         throw "Failed to create ScheduledTaskSettingsSet."
    }
    WriteLog -Message "Successfully created basic ScheduledTaskSettingsSet object." -Level DEBUG

    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Automatic Loxone Config Update" -ErrorAction Stop # Removed -Force as we unregister first
        WriteLog -Message "Scheduled task '${TaskName}' created successfully." -Level INFO
        
        # Attempt to set other settings separately (might fail on older systems)
        try {
            $task = Get-ScheduledTask -TaskName $TaskName
            $task.Settings.DisallowStartIfOnBatteries = $false
            $task.Settings.StopIfGoingOnBatteries = $false
            $task.Settings.AllowHardTerminate = $true
            $task.Settings.RunOnlyIfNetworkAvailable = $false
            $task.Settings.Enabled = $true
            Set-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
            WriteLog -Message "Attempted to apply additional settings to task '$TaskName'." -Level DEBUG
        } catch {
            WriteLog -Message "Could not apply additional settings to task '$TaskName' using Set-ScheduledTask: $($_.Exception.Message)" -Level WARN
        }

    }
    catch {
        WriteLog -Message "Error creating the scheduled task: ${($_.Exception.Message)}" -Level ERROR
        # If running non-elevated, this is expected. If elevated, it's a real error.
        if (-not $script:IsAdminRun) {
             Write-Host "  INFO: Task registration correctly failed with error (not Admin): $($_.Exception.Message)" -ForegroundColor Gray
        } else {
             throw $_ # Re-throw if running as admin, as it shouldn't fail
        }
    }
    finally {
        ExitFunction # Already correct
    }
}
#endregion Register-ScheduledTaskForScript Function

# Helper function to format seconds into HH:mm:ss
#region Utility Helpers (Continued)
function Format-TimeSpanFromSeconds {
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    param(
        # The total number of seconds to format.
        [double]$TotalSeconds
    )
    try {
    # More robust check: Handle double Infinity, NaN, negative, AND the string "Infinity"
    if (($TotalSeconds -is [double] -and ([double]::IsInfinity($TotalSeconds) -or [double]::IsNaN($TotalSeconds) -or $TotalSeconds -lt 0)) `
        -or ($TotalSeconds -is [string] -and $TotalSeconds -eq 'Infinity')) {
        WriteLog -Message "Format-TimeSpanFromSeconds received invalid input: $TotalSeconds. Returning '--:--:--'." -Level DEBUG # Corrected function call
        return "--:--:--"
    }
    $ts = [System.TimeSpan]::FromSeconds($TotalSeconds)
    return "{0:00}:{1:00}:{2:00}" -f $ts.Hours, $ts.Minutes, $ts.Seconds
    }
    finally {
        ExitFunction # Corrected function call
    }
}

#endregion Utility Helpers (Continued)

#region Version Helpers
function ConvertVersionString {
    param(
        # The version string to normalize (e.g., "14.0.3.28").
        [string]$VersionString
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    try {
    if ($VersionString -and $VersionString -match "\.") {
        $parts = $VersionString -split "\."
        $normalizedParts = foreach ($part in $parts) { [int]$part }
        return ($normalizedParts -join ".")
    }
    return $VersionString # Return original if no dots found or empty
    }
    finally {
        ExitFunction # Corrected function call
    }
} # Closing brace for ConvertVersionString
#endregion Version Helpers

#region Miniserver Update Logic
    function UpdateMS {
        [CmdletBinding()]
        param(
            # The target Loxone Config version string (normalized).
            [Parameter(Mandatory = $true)] [string]$DesiredVersion,
            # Path to the text file containing Miniserver connection strings.
            [Parameter(Mandatory = $true)] [string]$MSListPath,
            # Path to the main log file.
            [Parameter(Mandatory = $true)] [string]$LogFile,
            # Maximum log file size in MB (passed for potential future use).
            [Parameter(Mandatory = $true)] [int]$MaxLogFileSizeMB,
            # Switch to enable debug logging.
            [Parameter()][switch]$DebugMode,
            # Path to the *directory* containing the installed LoxoneConfig.exe.
            [Parameter(Mandatory = $true)] [string]$InstalledExePath,
            # Path to the script's save folder (used for context).
            [Parameter(Mandatory = $true)] [string]$ScriptSaveFolder
        )
        
        EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    
        $anyMSUpdated = $false # Initialize flag
    
        try { # Main try block
            # --- Start of Logic ---
            $global:LogFile = $LogFile
            $script:DebugMode = $DebugMode.IsPresent
            WriteLog -Message "Starting Miniserver update check process..." -Level "INFO"
    
            if (-not (Test-Path $MSListPath)) {
                WriteLog -Message "Miniserver list file not found at '${MSListPath}'. Skipping Miniserver updates." -Level "WARN"
                return $false
            }
    
            $miniservers = Get-Content $MSListPath | Where-Object { $_ -match '\S' }
            WriteLog -Message "Loaded Miniserver list with $($miniservers.Count) entries." -Level "INFO"
    
            if ($miniservers.Count -eq 0) {
                WriteLog -Message "Miniserver list is empty. Skipping Miniserver updates." -Level "INFO"
                return $false
            }
    
            $loxoneConfigExe = Join-Path -Path $InstalledExePath -ChildPath "LoxoneConfig.exe"
            if (-not (Test-Path $loxoneConfigExe)) {
                WriteLog -Message "LoxoneConfig.exe not found (checked based on directory path '${InstalledExePath}'). Cannot perform Miniserver updates." -Level "ERROR"
                return $false
            }
    
            foreach ($msEntry in $miniservers) {
                $redactedEntryForLog = GetRedactedPassword $msEntry # Corrected call
                WriteLog -Message "Processing Miniserver entry: ${redactedEntryForLog}" -Level INFO
    
                $msIP = $null
                $versionUri = $null
                $updateArg = $null
                $credential = $null
    
                try { # Inner try for parsing entry
                    $entryToParse = $msEntry
                    if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
                    $uriBuilder = [System.UriBuilder]$entryToParse
                    $msIP = $uriBuilder.Host
    
                    if (-not ([string]::IsNullOrWhiteSpace($uriBuilder.UserName))) {
                        $securePassword = $uriBuilder.Password | ConvertTo-SecureString -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential($uriBuilder.UserName, $securePassword)
                        $updateArg = $uriBuilder.UserName + ":" + $uriBuilder.Password + "@" + $uriBuilder.Host
                        WriteLog -Message "Parsed credentials for $msIP. User: $($uriBuilder.UserName)" -Level DEBUG
                    } else {
                        $updateArg = $msIP
                        WriteLog -Message "No credentials found for $msIP." -Level DEBUG
                    }
    
                    $uriBuilder.Path = "/dev/cfg/version"
                    $uriBuilder.Port = 80
                    $uriBuilder.Password = $null
                    $uriBuilder.UserName = $null
                    $versionUri = $uriBuilder.Uri.AbsoluteUri
    
                } catch { # Inner catch for parsing entry
                    WriteLog -Message "Failed to parse Miniserver entry '$redactedEntryForLog' as URI: $($_.Exception.Message). Assuming it's just an IP/hostname." -Level "WARN"
                    $credential = $null
                    $msIP = $msEntry.Split('@')[-1].Split('/')[0]
                    $updateArg = $msIP
                    if ($msIP) {
                        $versionUri = "http://${msIP}/dev/cfg/version"
                    } else {
                        WriteLog -Message "Could not determine IP/Host from entry '$redactedEntryForLog'. Skipping." -Level "ERROR"
                        continue # Skip to next entry in foreach
                    } # End of else block
                } # End inner catch for parsing entry <-- CORRECTED BRACE PLACEMENT
    
                $redactedVersionUri = GetRedactedPassword $versionUri # Corrected call
                WriteLog -Message "Checking current Miniserver version for '$msIP' via URI: ${redactedVersionUri}" -Level "INFO"
    
                $responseObject = $null
                $msVersionCheckSuccess = $false
                $originalScheme = $null
                $iwrParamsBase = @{ TimeoutSec = 15; ErrorAction = 'Stop'; Method = 'Get' } # Base params without URI/Credential

                try { # Outer try for the whole version check + update process for this MS
                    $originalScheme = ([uri]$versionUri).Scheme # Get scheme reliably

                    # Add credential if present (applies to both HTTPS and HTTP attempts)
                    if ($credential) {
                        $iwrParamsBase.Credential = $credential
                        WriteLog -Message "Using credentials for Invoke-WebRequest to $msIP" -Level DEBUG
                    }

                    if ($originalScheme -eq 'http') {
                        # Attempt HTTPS first
                        $httpsUriBuilder = [System.UriBuilder]$versionUri
                        $httpsUriBuilder.Scheme = 'https'
                        $httpsUriBuilder.Port = 443 # Standard HTTPS port
                        $httpsUri = $httpsUriBuilder.Uri.AbsoluteUri
                        $redactedHttpsUri = GetRedactedPassword $httpsUri # Redact for logging
                        WriteLog -Message "Original URI is HTTP. Attempting secure connection first: $redactedHttpsUri" -Level INFO
                        $httpsParams = $iwrParamsBase.Clone() # Clone base params
                        $httpsParams.Uri = $httpsUri

                        try {
                            WriteLog -Message "Attempting Invoke-WebRequest with HTTPS..." -Level DEBUG
                            $responseObject = Invoke-WebRequest @httpsParams
                            WriteLog -Message "HTTPS connection successful." -Level INFO
                            $msVersionCheckSuccess = $true
                        } catch [System.Net.WebException] {
                            WriteLog -Message "HTTPS failed: $($_.Exception.Message). Falling back to HTTP." -Level WARN
                        } catch {
                            WriteLog -Message "Unexpected error during HTTPS connection attempt: $($_.Exception.Message). Falling back to HTTP." -Level WARN
                        }
                    }

                    # Proceed with original protocol if HTTPS wasn't attempted or failed
                    if (-not $msVersionCheckSuccess) {
                        $originalParams = $iwrParamsBase.Clone() # Clone base params
                        $originalParams.Uri = $versionUri # Set original URI

                        try {
                             $responseObject = Invoke-WebRequest @originalParams
                             WriteLog -Message "Connection successful using $($originalScheme.ToUpper()) URI: $versionUri" -Level INFO
                             $msVersionCheckSuccess = $true
                        } catch [System.Net.WebException] {
                             WriteLog -Message "Failed to connect using $($originalScheme.ToUpper()) URI: $($_.Exception.Message)" -Level WARN
                        } catch {
                             WriteLog -Message "Unexpected error during $($originalScheme.ToUpper()) connection attempt: $($_.Exception.Message)" -Level ERROR
                        }
                    }

                    # --- Process response ONLY if a connection succeeded ---
                    if ($msVersionCheckSuccess -and $responseObject) {
                        if ($DebugMode) {
                            $rawResponseContent = $responseObject.RawContent
                            $debugMsg = "DEBUG: Raw response content from $msIP`: $rawResponseContent"
                            WriteLog -Message $debugMsg -Level DEBUG
                        }

                        $xmlResponse = [xml]$responseObject.Content
                        $currentVersion = $xmlResponse.LL.value
                        if ($null -eq $xmlResponse -or $null -eq $xmlResponse.LL -or $null -eq $xmlResponse.LL.value) { throw "Could not find version value in parsed Miniserver response XML (Expected structure: LL.value)." }

                        WriteLog -Message "Miniserver '$msIP' current version: ${currentVersion}" -Level "INFO"
                        $normalizedCurrentVersion = ConvertVersionString $currentVersion

                        WriteLog -Message "Comparing current version (${normalizedCurrentVersion}) with desired version (${DesiredVersion})." -Level DEBUG
                        if ($normalizedCurrentVersion -ne $DesiredVersion) {
                            WriteLog -Message "Update required for Miniserver at '$msIP' (Current: ${normalizedCurrentVersion}, Desired: ${DesiredVersion}). Triggering update..." -Level "INFO"
                            ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate" -Message "Starting update for Miniserver ${msIP}..."

                            $invokeParams = @{
                                LoxoneConfigPath = $loxoneConfigExe
                                MiniserverArg = $updateArg
                                NormalizedDesiredVersion = $DesiredVersion
                                VerificationUri = $versionUri
                                VerificationCredential = $credential
                            }
                            $updateSuccess = InvokeMiniserverUpdate @invokeParams
                            if ($updateSuccess) {
                                $anyMSUpdated = $true
                                WriteLog -Message "Update successful for Miniserver '$msIP'." -Level INFO
                            } else {
                                WriteLog -Message "Update attempt failed or verification failed for Miniserver '$msIP'." -Level WARN
                            }
                        } else {
                            WriteLog -Message "Miniserver at '$msIP' is already up-to-date (Version: ${normalizedCurrentVersion}). Skipping update." -Level "INFO"
                        }

                    } elseif (-not $msVersionCheckSuccess) {
                        WriteLog -Message "Failed to check Miniserver version for '$msIP' (URI: ${redactedVersionUri}) after attempting relevant protocols. Skipping." -Level "ERROR"
                    } # End of if/elseif for successful connection check
                } catch { # Outer catch for the whole MS processing
                    WriteLog -Message "Caught exception during processing for Miniserver '$msIP'. Error: $($_.Exception.Message)" -Level ERROR # Existing log, Removed -ForceLog
                    WriteLog -Message "Continuing script execution after error processing Miniserver '$msIP'." -Level INFO # Added Log, Removed -ForceLog
                } # End outer try/catch for this MS
            } # End foreach loop
            WriteLog -Message "Finished processing all Miniservers." -Level "INFO"
            # --- End of Logic ---
        } # End main try block
        catch { # Main catch block
            WriteLog -Message "Unexpected error caught in main UpdateMS try block: $($_.Exception.Message)" -Level ERROR
        }
        finally { # Main finally block
            ExitFunction # Corrected call
        }
        
        # Return the final status after try/catch/finally
        return $anyMSUpdated
    }

    function InvokeMiniserverUpdate {
        param(
            # Full path to LoxoneConfig.exe.
            [Parameter(Mandatory=$true)][string]$LoxoneConfigPath,
            # The argument for LoxoneConfig /update (e.g., "user:pass@host" or "host").
            [Parameter(Mandatory=$true)][string]$MiniserverArg,
            # The target version string (normalized) for verification after update.
            [Parameter(Mandatory=$true)][string]$NormalizedDesiredVersion,
            # The full URI to query the Miniserver version post-update (e.g., "http://host/dev/cfg/version").
            [Parameter(Mandatory=$true)][string]$VerificationUri,
            # Optional PSCredential object for authenticating the post-update version check.
            [Parameter()][System.Management.Automation.PSCredential]$VerificationCredential = $null
        )
        EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    
        try {
        # Derive values needed for logging and pinging from MiniserverArg
        $redactedArg = GetRedactedPassword $MiniserverArg
        $hostForPing = $MiniserverArg.Split('@')[-1] # Extract host part after potential user:pass@
    
        WriteLog -Message "Attempting to update Miniserver: ${redactedArg}" -Level INFO
    
        # Use the original $MiniserverArg (potentially with password) for the actual command
        $arguments = "/update:${MiniserverArg}" # CORRECTED/VERIFIED Argument format
        WriteLog -Message "Executing: '$LoxoneConfigPath' $arguments" -Level DEBUG
    
        try {
            # Execute LoxoneConfig.exe with the /update argument
            $process = Start-Process -FilePath $LoxoneConfigPath -ArgumentList $arguments -PassThru -Wait -ErrorAction Stop
            WriteLog -Message "LoxoneConfig.exe update command executed for '${redactedArg}'. Exit Code: $($process.ExitCode)" -Level INFO
    
            # Check Exit Code (Optional but recommended)
            if ($process.ExitCode -ne 0) {
                 WriteLog -Message "LoxoneConfig.exe returned non-zero exit code ($($process.ExitCode)) for update on '${redactedArg}'. Update may have failed to initiate." -Level WARN
            }
    
            # --- Wait for Miniserver Reboot and Verify Update ---
            WriteLog -Message "Waiting for Miniserver ${hostForPing} to start rebooting (ping timeout)..." -Level INFO
            if (WaitForPingTimeout -InputAddress $hostForPing -TimeoutSeconds 180) {
                WriteLog -Message "Miniserver ${hostForPing} started rebooting." -Level INFO
                WriteLog -Message "Waiting for Miniserver ${hostForPing} to come back online (ping success)..." -Level INFO
                if (WaitForPingSuccess -InputAddress $hostForPing -TimeoutSeconds 600) {
                    WriteLog -Message "Miniserver ${hostForPing} is back online." -Level INFO
                    Start-Sleep -Seconds 15 # Allow services to fully start
                    WriteLog -Message "Re-checking Miniserver version after update..." -Level INFO
                    try {
                        $verifyParams = @{
                            Uri = $VerificationUri
                            UseBasicParsing = $true
                            TimeoutSec = 15
                            ErrorAction = 'Stop'
                        }
                        if ($VerificationCredential) {
                            $verifyParams.Credential = $VerificationCredential
                        }
    
                        $responseAfterUpdate = Invoke-WebRequest @verifyParams
                        $xmlAfterUpdate = [xml]$responseAfterUpdate.Content
                        $versionAfterUpdate = $xmlAfterUpdate.LL.value
                        if ([string]::IsNullOrEmpty($versionAfterUpdate)) {
                            throw "Could not find version value in Miniserver XML response after update."
                        }
    
                        $normalizedVersionAfterUpdate = ConvertVersionString $versionAfterUpdate
    
                        if ($normalizedVersionAfterUpdate) {
                            WriteLog -Message "Version after update: ${normalizedVersionAfterUpdate}" -Level INFO
                            if ($normalizedVersionAfterUpdate -eq $NormalizedDesiredVersion) {
                                WriteLog -Message "SUCCESS: Miniserver ${redactedArg} successfully updated and verified to version ${NormalizedDesiredVersion}." -Level INFO
                                ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate" -Message "SUCCESS: Miniserver ${redactedArg} updated to ${NormalizedDesiredVersion}."
                                return $true # Indicate success
                            } else {
                                WriteLog -Message "FAILURE: Miniserver ${redactedArg} update verification failed. Version after update (${normalizedVersionAfterUpdate}) does not match desired (${NormalizedDesiredVersion})." -Level ERROR
                                ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate FAILED" -Message "FAILURE: Miniserver ${redactedArg} update verification failed. Found ${normalizedVersionAfterUpdate}, expected ${NormalizedDesiredVersion}."
                                return $false # Indicate failure
                            }
                        } else {
                             WriteLog -Message "FAILURE: Could not determine a valid version for Miniserver ${redactedArg} after update attempt. Found raw value: '$versionAfterUpdate'." -Level ERROR
                             ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate FAILED" -Message "FAILURE: Could not verify Miniserver ${redactedArg} version after update."
                             return $false # Indicate failure
                        }
                    } catch {
                        WriteLog -Message "FAILURE: Could not verify Miniserver ${redactedArg} version after update. Error during verification request: $($_.Exception.Message)" -Level ERROR
                        ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate FAILED" -Message "FAILURE: Could not verify Miniserver ${redactedArg} version after update (Error: $($_.Exception.Message))."
                        return $false # Indicate failure
                    }
                } else {
                    WriteLog -Message "FAILURE: Miniserver ${hostForPing} did not come back online within the timeout period after update attempt." -Level ERROR
                    ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate FAILED" -Message "FAILURE: Miniserver ${redactedArg} did not come back online after update attempt."
                    return $false # Indicate failure
                }
            } else {
                WriteLog -Message "WARN: Miniserver ${hostForPing} did not seem to reboot within the timeout period after update command. Verification skipped." -Level WARN
                ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate WARN" -Message "WARN: Miniserver ${redactedArg} did not seem to reboot after update command. Please check manually."
                return $false # Indicate failure (as verification couldn't happen)
            }
            # --- End Wait and Verify ---
    
        } catch {
            WriteLog -Message "Error executing LoxoneConfig.exe for update on '${redactedArg}': $($_.Exception.Message)" -Level ERROR
            ShowNotificationToLoggedInUsers -Title "Loxone AutoUpdate FAILED" -Message "FAILURE: Error executing update command for Miniserver ${redactedArg}: $($_.Exception.Message)."
            return $false # Indicate failure
        }
        }
        finally {
            ExitFunction
        }
    } # Closing brace for InvokeMiniserverUpdate
#endregion Miniserver Update Logic

#region Utility Helpers (Continued)
    function GetRedactedPassword {
        param(
            # The input string potentially containing "user:password@host".
            [Parameter(Mandatory=$true)][string]$InputString
        )
        EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
        try {
            # Updated Regex: Handles optional user:pass@ part, ensures '@' is not in password
            $pattern = "^(?<scheme>http[s]?://)?(?:(?<user>[^:']+)(?::(?<pass>[^@/]*))?@)?(?<rest>.*)$" # Corrected Line: Removed invalid trailing text
            
            if ($InputString -match $pattern) {
                $userPart = $matches['user']
                $passPart = $matches['pass']
                $schemePart = $matches['scheme']
                $restPart = $matches['rest']
                
                if (-not ([string]::IsNullOrEmpty($passPart))) {
                    $redactedPassword = "****" # Fixed redaction as per test requirement
                    $redactedUrl = "${schemePart}${userPart}:${redactedPassword}@${restPart}"
                    WriteLog -Message "GetRedactedPassword - Redacted URL: $redactedUrl" -Level DEBUG # Corrected function name in log
                    return $redactedUrl
                } else {
                    WriteLog -Message "Get-RedactedPassword - No password part found or password empty, returning original URL: $InputString" -Level DEBUG
                    return $InputString
                }
            } else {
                WriteLog -Message "Get-RedactedPassword - Regex did not match, returning original URL: $InputString" -Level DEBUG
                return $InputString
            }
        }
        finally {
            ExitFunction
        }
    } # Closing brace for GetRedactedPassword
#endregion Utility Helpers (Continued)

#region Download and Verification
function Invoke-ZipDownloadAndVerification {
    [CmdletBinding()]
    param(
        # The URL of the ZIP file to download.
        [Parameter(Mandatory = $true)][string]$ZipUrl,
        # The local file path where the ZIP file should be saved.
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        # Optional: The expected CRC32 checksum (hex string) for verification.
        [Parameter()][string]$ExpectedCRC32 = $null,
        # Optional: The expected file size in bytes for verification.
        [Parameter()][int64]$ExpectedFilesize = 0,
        # The number of times to retry the download if it fails verification (0 means 1 attempt total).
        [Parameter()][int]$MaxRetries = 1
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call

    try {
    WriteLog -Message "Starting ZIP download and verification for '$DestinationPath'." -Level INFO
    $DestinationDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path -Path $DestinationDir -PathType Container)) {
        WriteLog -Message "Destination directory '$DestinationDir' not found. Creating..." -Level INFO
        try {
            New-Item -Path $DestinationDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            WriteLog -Message "Successfully created directory '$DestinationDir'." -Level INFO
        } catch {
            WriteLog -Message "Failed to create destination directory '$DestinationDir': $($_.Exception.Message)" -Level ERROR
            throw "Failed to create destination directory '$DestinationDir'. Cannot proceed."
        }
    }

    # 1. Pre-Download Check (Size & Checksum if provided)
    $null = (Test-Path $DestinationPath -ErrorAction SilentlyContinue) # Check existence and suppress output
    $fileExists = $? # Check if the Test-Path command succeeded (meaning path exists)
    $needsDownload = $true # Assume download is needed unless proven otherwise

    if ($fileExists) {
        WriteLog -Message "Local file '$DestinationPath' exists. Verifying..." -Level INFO
        try {
            $localFileItem = Get-Item $DestinationPath -ErrorAction Stop
            $localFileSize = $localFileItem.Length
            $sizeMatch = $true # Assume size matches unless check is enabled and fails
            $crcMatch = $true # Assume CRC matches unless check is enabled and fails

            # Check Size if ExpectedFilesize > 0
            if ($ExpectedFilesize -gt 0) {
                if ($localFileSize -ne $ExpectedFilesize) {
                    WriteLog -Message "Local file size ($localFileSize bytes) does not match expected size ($ExpectedFilesize bytes). Will re-download." -Level WARN
                    $sizeMatch = $false
                } else {
                    WriteLog -Message "Local file size matches." -Level DEBUG
                }
            } else {
                WriteLog -Message "Expected file size is 0 or not provided. Skipping size check." -Level DEBUG
            }

            # Check CRC *only if* size matches AND ExpectedCRC32 is provided
            if ($sizeMatch -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                WriteLog -Message "Size matches. Checking CRC32..." -Level DEBUG
                try {
                    $localCRC32 = Get-CRC32 -InputFile $DestinationPath # Corrected function call
                    if ($localCRC32 -ne $ExpectedCRC32) {
                        WriteLog -Message "Local file checksum ($localCRC32) does not match expected checksum ($ExpectedCRC32). Will re-download." -Level WARN
                        $crcMatch = $false
                    } else {
                        WriteLog -Message "Local file checksum matches." -Level DEBUG
                    }
                } catch {
                    # If Get-CRC32 fails (e.g., type not found), treat it as a mismatch
                    WriteLog -Message "Error calculating CRC32 for existing file: $($_.Exception.Message). Assuming mismatch." -Level WARN
                    $crcMatch = $false
                }
            } elseif ($sizeMatch) {
                # Size matched, but no CRC provided for check
                WriteLog -Message "Size matches, but Expected CRC32 not provided. Skipping CRC check." -Level DEBUG
            } else {
                # Size did not match, no need to check CRC
                WriteLog -Message "Size mismatch. Not checking CRC." -Level DEBUG
            }

            # Determine if download is needed based on checks
            if ($sizeMatch -and $crcMatch) {
                # Specific logging for why skip occurred
                if ($ExpectedFilesize -gt 0 -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                    WriteLog -Message "Local file is valid (Size and Checksum match). Download skipped." -Level INFO
                } elseif ($ExpectedFilesize -gt 0) {
                    WriteLog -Message "Local file is valid (Size match, Checksum not checked). Download skipped." -Level INFO
                } elseif (-not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                    WriteLog -Message "Local file is valid (Checksum match, Size not checked). Download skipped." -Level INFO
                } else {
                     WriteLog -Message "Local file exists (Size/Checksum not checked). Download skipped." -Level INFO # Fallback if neither check was requested
                }
                $needsDownload = $false
                return $true # Indicate success immediately
            } else {
                WriteLog -Message "Local file '$DestinationPath' failed validation (Size Match: $sizeMatch, CRC Match: $crcMatch). Re-downloading." -Level WARN
                Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue # Remove the invalid file
            }

        } catch { # Catch errors from Get-Item or Get-CRC32
            WriteLog -Message "Error verifying existing local file '$DestinationPath': $($_.Exception.Message). Will re-download." -Level WARN
            if (Test-Path $DestinationPath) {
                 Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        WriteLog -Message "Local file '$DestinationPath' does not exist. Proceeding to download." -Level INFO
        $needsDownload = $true
    }

    # 2. Conditional Download & 3. Post-Download Check (with Retries)
    if ($needsDownload) {
        $totalAttempts = $MaxRetries + 1
        for ($attempt = 1; $attempt -le $totalAttempts; $attempt++) {
            WriteLog -Message "Attempting download ($attempt/$totalAttempts) from '$ZipUrl' to '$DestinationPath'..." -Level INFO
            Write-Host "Downloading from: $ZipUrl" # Display URL to console

            # --- Remove old file if it exists ---
            if (Test-Path $DestinationPath) {
                 WriteLog -Message "Removing existing file '$DestinationPath' before download attempt $attempt." -Level DEBUG
                 Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
            }

            # --- Start Download Job ---
            $downloadJob = Start-Job -ScriptBlock {
                param($Url, $Path)
                try {
                    # Use System.Net.WebClient for better control and potential progress reporting within the job (though we poll externally)
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($Url, $Path)
                    exit 0 
                } catch {
                    Write-Error -Message "Download failed: $($_.Exception.Message)" -ErrorAction Stop
                    exit 1 
                }
            } -ArgumentList $ZipUrl, $DestinationPath

            WriteLog -Message "Download job started with ID: $($downloadJob.Id)" -Level DEBUG

            # --- Polling Loop for Progress ---
            $startTime = Get-Date
            $lastBytes = 0
            $lastTime = $startTime

            while ($downloadJob.State -eq 'Running' -or $downloadJob.State -eq 'NotStarted') {
                Start-Sleep -Milliseconds 500 # Polling interval

                if (Test-Path $DestinationPath) {
                    $currentFileItem = Get-Item $DestinationPath -ErrorAction SilentlyContinue
                    if ($currentFileItem) {
                        $currentBytes = $currentFileItem.Length
                        $currentTime = Get-Date
                        $intervalSeconds = ($currentTime - $lastTime).TotalSeconds
                        $bytesDownloadedThisInterval = $currentBytes - $lastBytes
                        $speedFormatted = "0.0 MB/s"
                        $remainingTimeFormatted = "--:--:--"

                        if ($intervalSeconds -gt 0 -and $bytesDownloadedThisInterval -gt 0) {
                            $downloadSpeedBytesPerSec = $bytesDownloadedThisInterval / $intervalSeconds
                            $speedFormatted = "{0:N1} MB/s" -f ($downloadSpeedBytesPerSec / 1MB) # Format speed in MB/s

                            if ($ExpectedFilesize -gt 0 -and $downloadSpeedBytesPerSec -gt 0) {
                                $remainingBytes = $ExpectedFilesize - $currentBytes
                                if ($remainingBytes -gt 0) {
                                    $remainingSeconds = 0 # Initialize to 0
                                    if ($downloadSpeedBytesPerSec -gt 0) {
                                        $remainingSeconds = [double]($remainingBytes / $downloadSpeedBytesPerSec)
                                    } else {
                                        $remainingSeconds = [double]::PositiveInfinity
                                    }
                                    
                                    if ($remainingSeconds -is [double] -and -not ([double]::IsInfinity($remainingSeconds)) -and -not ([double]::IsNaN($remainingSeconds)) -and $remainingSeconds -ge 0) {
                                        $remainingTimeFormatted = Format-TimeSpanFromSeconds $remainingSeconds
                                    } else {
                                        $remainingTimeFormatted = "--:--:--"
                                    }
                                } else {
                                    $remainingTimeFormatted = "00:00:00"
                                }
                            }
                        }
                        
                        $percent = 0
                        if ($ExpectedFilesize -gt 0) {
                            $percent = [math]::Round(($currentBytes / $ExpectedFilesize) * 100)
                        }

                        $progressParams = @{
                            Activity        = "Downloading Loxone Update from '$ZipUrl'"
                            Status          = "{0:N0} MB / {1:N0} MB ({2}%) at {3} - Rem: {4}" -f ($currentBytes / 1MB), ($ExpectedFilesize / 1MB), $percent, $speedFormatted, $remainingTimeFormatted
                            PercentComplete = $percent
                            CurrentOperation= "Saving to '$DestinationPath'"
                        }
                        Write-Progress @progressParams

                        $lastBytes = $currentBytes
                        $lastTime = $currentTime
                    }
                }
                if ($downloadJob.State -ne 'Running' -and $downloadJob.State -ne 'NotStarted') {
                    break
                }
            } # End while polling

            # --- Check Job Result ---
            WriteLog -Message "Download job finished with state: $($downloadJob.State)" -Level DEBUG
            $downloadSuccess = $false
            if ($downloadJob.State -eq 'Completed') {
                $jobError = $null
                try {
                    $downloadJob | Wait-Job | Out-Null
                    $downloadJob | Receive-Job -ErrorAction SilentlyContinue
                    $jobError = $downloadJob.ChildJobs[0].Error

                    if ($jobError -and $jobError.Count -gt 0) {
                        $errorMessage = "Download attempt $attempt failed (Job state: Completed, but error received)."
                        $errorMessage += " Error details: $($jobError | Out-String)"
                        WriteLog -Message $errorMessage -Level ERROR
                    } else {
                        WriteLog -Message "Download attempt $attempt completed successfully." -Level INFO
                        $downloadSuccess = $true
                    }
                } catch {
                    $errorMessage = "Error waiting for or receiving download job result (Attempt $attempt): $($_.Exception.Message)"
                    WriteLog -Message $errorMessage -Level ERROR
                } finally {
                    Remove-Job -Job $downloadJob -Force -ErrorAction SilentlyContinue
                }
            } else {
                $errorMessage = "Download attempt $attempt failed (Job State: $($downloadJob.State))."
                if ($downloadJob.JobStateInfo.Reason) {
                    $errorMessage += " Reason: $($downloadJob.JobStateInfo.Reason.Message)"
                }
                Remove-Job -Job $downloadJob -Force -ErrorAction SilentlyContinue
                WriteLog -Message $errorMessage -Level ERROR
            }

            # --- Post-Download Verification (Size & Checksum) ---
            if ($downloadSuccess) {
                WriteLog -Message "Verifying downloaded file size and checksum (Attempt $attempt)..." -Level INFO
                try {
                    if (-not (Test-Path $DestinationPath)) {
                         WriteLog -Message "Downloaded file '$DestinationPath' not found after successful download (Attempt $attempt)." -Level ERROR
                         throw "Downloaded file missing."
                    }
                    $downloadedFileItem = Get-Item $DestinationPath -ErrorAction Stop
                    $downloadedFileSize = $downloadedFileItem.Length
                    $sizeVerified = $true
                    $crcVerified = $true

                    if ($ExpectedFilesize -gt 0) {
                        if ($downloadedFileSize -ne $ExpectedFilesize) {
                            WriteLog -Message "Downloaded file size ($downloadedFileSize bytes) does not match expected size ($ExpectedFilesize bytes) (Attempt $attempt)." -Level ERROR
                            $sizeVerified = $false
                        } else {
                            WriteLog -Message "Downloaded file size matches (Attempt $attempt)." -Level DEBUG
                        }
                    } else {
                         WriteLog -Message "Expected file size is 0 or not provided. Skipping size check." -Level DEBUG
                    }

                    if ($sizeVerified -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                        WriteLog -Message "Checking CRC32..." -Level DEBUG
                        $localCRC32 = Get-CRC32 -InputFile $DestinationPath
                        if ($localCRC32 -ne $ExpectedCRC32) {
                            WriteLog -Message "Local file checksum ($localCRC32) does not match expected checksum ($ExpectedCRC32) (Attempt $attempt)." -Level ERROR
                            $crcVerified = $false
                        } else {
                            WriteLog -Message "Local file checksum matches (Attempt $attempt)." -Level DEBUG
                        }
                    } elseif (-not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                         WriteLog -Message "Size mismatch or CRC check skipped. Not verifying CRC." -Level DEBUG
                    } else {
                         WriteLog -Message "Expected CRC32 not provided. Skipping CRC verification." -Level DEBUG
                    }

                    if ($sizeVerified -and $crcVerified) {
                        WriteLog -Message "Verification successful (Attempt $attempt)." -Level INFO
                        Write-Progress -Activity "Downloading Loxone Update" -Completed
                        return $true
                    } else {
                        if (-not $sizeVerified) { throw "Incorrect file size." }
                        if (-not $crcVerified) { throw "Incorrect checksum." }
                    }

                } catch { # Catch verification errors
                    $errorMessage = "Verification failed for download attempt {0}: {1}" -f $attempt, $_.Exception.Message
                    WriteLog -Message $errorMessage -Level ERROR
                    if (Test-Path $DestinationPath) {
                        Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
                    }
                    if ($attempt -eq $totalAttempts) {
                        WriteLog -Message "Maximum download attempts reached. Verification failed." -Level ERROR
                        Write-Progress -Activity "Downloading Loxone Update" -Completed
                        throw $errorMessage
                    }
                    WriteLog -Message "Waiting 5 seconds before retry..." -Level INFO
                    Start-Sleep -Seconds 5
                } # End Verification Catch
            } else { # If download failed
                 if ($attempt -eq $totalAttempts) {
                     WriteLog -Message "Maximum download attempts reached. Download failed." -Level ERROR
                     Write-Progress -Activity "Downloading Loxone Update" -Completed
                     throw "Download failed after $totalAttempts attempts."
                 }
                 WriteLog -Message "Waiting 5 seconds before retry..." -Level INFO
                 Start-Sleep -Seconds 5
            }
        } # End For loop (attempts)
    } # End if ($needsDownload)

    WriteLog -Message "Download and verification ultimately failed after $totalAttempts attempts." -Level ERROR
    Write-Progress -Activity "Downloading Loxone Update" -Completed
    }
    finally {
        ExitFunction # Corrected function call
    }
}
#endregion Download and Verification

#region CRC32 Logic
# --- Add CRC32 Class ---
$Source = @"
using System;
using System.IO;

public static class CRC32
{
    private static readonly uint[] table = GenerateTable();
    private const uint Poly = 0xEDB88320; // Standard CRC32 polynomial (reversed)

    private static uint[] GenerateTable()
    {
        uint[] createTable = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) == 1)
                    c = (c >> 1) ^ Poly;
                else
                    c = c >> 1;
            }
            createTable[i] = c;
        }
        return createTable;
    }

    public static uint Compute(byte[] bytes)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in bytes)
        {
            crc = (crc >> 8) ^ table[(crc & 0xFF) ^ b];
        }
        return ~crc; // Final XOR
    }
}
"@

try {
    if (-not ([System.Management.Automation.PSTypeName]'CRC32').Type) {
        Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
        WriteLog -Message "Successfully added CRC32 type definition." -Level DEBUG
    } else {
        WriteLog -Message "CRC32 type already exists." -Level DEBUG
    }
} catch {
    WriteLog -Message "Error adding CRC32 type: $($_.Exception.Message)" -Level ERROR
    # throw "Failed to add necessary CRC32 type."
}

function GetCRC32 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($InputFile)
        WriteLog -Message "Read $($fileBytes.Length) bytes from file '$InputFile'." -Level DEBUG
        $crc = [CRC32]::Compute($fileBytes)
        $crcString = $crc.ToString("X8")
        WriteLog -Message "Calculated CRC32 for '$InputFile': ${crcString}" -Level DEBUG
        return $crcString
    }
    catch {
        WriteLog -Message "Error calculating CRC32 for ${InputFile}: $($_.Exception.Message)" -Level ERROR
        throw $_ 
    }
    finally {
        ExitFunction
    }
}
#endregion CRC32 Logic

#region Zip Extraction
function Invoke-ZipFileExtraction {
    [CmdletBinding()]
    param(
        # Full path to the ZIP archive.
        [Parameter(Mandatory=$true)][string]$ZipPath,
        # Full path to the destination directory where files should be extracted.
        [Parameter(Mandatory=$true)][string]$DestinationPath
    )
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    WriteLog -Message "Extracting '$ZipPath' to '$DestinationPath'..." -Level INFO
    try {
        if (-not (Test-Path $ZipPath -PathType Leaf)) {
            throw "Source ZIP file not found: '$ZipPath'"
        }
        if (-not (Test-Path $DestinationPath -PathType Container)) {
            WriteLog -Message "Destination directory '$DestinationPath' does not exist. Creating..." -Level INFO
            New-Item -Path $DestinationPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force -ErrorAction Stop
        WriteLog -Message "Successfully extracted '$ZipPath' to '$DestinationPath'." -Level INFO
    } catch {
        WriteLog -Message "Error during ZIP extraction from '$ZipPath' to '$DestinationPath': $($_.Exception.Message)" -Level ERROR
        throw $_ # Re-throw the error
    } finally {
        ExitFunction
    }
}
#endregion Zip Extraction

#region Send Toast Notification
function Send-ToastNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Text, # Changed type to string array to match BurntToast

        # Optional common parameters (add more as needed)
        [Parameter()]
        [string]$AppLogo,
        [Parameter()]
        [string]$Sound,
        [string]$AppId = 'Autoupdate Loxone Config' # Custom AppId
    )

    # --- START NEW DIAGNOSTIC LOGGING ---
    try {
        Write-Host "DEBUG (Send-ToastNotification): Entering function. PSScriptRoot = '$($PSScriptRoot)'" -ForegroundColor Magenta
        $debugRunAsUserManifestPath = Join-Path -Path $PSScriptRoot -ChildPath 'RunAsUser.psm1'
        Write-Host "DEBUG (Send-ToastNotification): Calculated RunAsUser Path = '$($debugRunAsUserManifestPath)'" -ForegroundColor Magenta
        Write-Host "DEBUG (Send-ToastNotification): Test-Path for RunAsUser Path = $(Test-Path $debugRunAsUserManifestPath)" -ForegroundColor Magenta
    } catch {
        Write-Host "DEBUG (Send-ToastNotification): Error during initial diagnostic logging: $($_.Exception.Message)" -ForegroundColor Red
    }
    # --- END NEW DIAGNOSTIC LOGGING ---

    Write-Host "DEBUG (Send-ToastNotification): BEFORE EnterFunction" -ForegroundColor Cyan # ADDED
    EnterFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Host "DEBUG (Send-ToastNotification): AFTER EnterFunction, BEFORE Manual Param Copy" -ForegroundColor Cyan # UPDATED Log
    $safeParams = @{} # Create new hashtable
    foreach ($key in $PSBoundParameters.Keys) { $safeParams[$key] = $PSBoundParameters[$key] } # Manual copy
    Write-Host "DEBUG (Send-ToastNotification): AFTER Manual Param Copy, BEFORE WriteLog" -ForegroundColor Cyan # UPDATED Log
    WriteLog -Message "Attempting to send toast notification." -Level INFO -Parameters $safeParams # This is the log we weren't seeing

    try {
        $isSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
        WriteLog -Message "Running as SYSTEM: $isSystem" -Level DEBUG

        if ($isSystem) {
            WriteLog -Message "Running as SYSTEM. Attempting notification via Invoke-AsCurrentUser." -Level INFO
            try {
                # Construct path to RunAsUser module using PSScriptRoot for reliability
                $runAsUserModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'RunAsUser.psd1'
                WriteLog -Message "Attempting to import RunAsUser module from '$runAsUserModulePath'." -Level DEBUG

                if (Test-Path $runAsUserModulePath) {
                    Import-Module $runAsUserModulePath -Force
                    WriteLog -Message "RunAsUser module imported successfully." -Level DEBUG
                } else {
                    WriteLog -Message "RunAsUser module not found at '$runAsUserModulePath'. Cannot send notification via Invoke-AsCurrentUser." -Level ERROR
                    # Exit this block as the required module is missing
                    return
                }

                # Define the script block content as a multi-line string with placeholders
                $scriptBlockString = @'
Import-Module BurntToast -ErrorAction Stop

# --- Find Loxone Config AppID ---
# --- Loxone Config AppID (Hardcoded) ---
$loxoneAppId = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'

# Define parameters for the toast notification using placeholders
$Params = @{
    Title = '$Title' # Placeholder for Title
    Text = @('$TextLines') # Placeholder for Text lines (will be joined)
    # AppLogo = '$AppLogoPath' # Placeholder for AppLogo (Icon Path) - REMOVED as AppID should provide icon
    AppId = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe' # Hardcoded AppId
    # Add other parameters as needed, e.g., AppId, Buttons
}

# Add AppId if provided and not the default
if ('$AppIdValue' -ne 'Autoupdate Loxone Config' -and '$AppIdValue') {
    $Params.AppId = '$AppIdValue'
}

# Add Buttons if provided (assuming $Buttons contains the necessary structure)
# Note: Complex objects like Buttons might require careful serialization/reconstruction
# if ('$Buttons') {
#    # This part needs refinement based on how $Buttons is structured/passed
#    # For simple buttons, you might pass pre-formatted strings
#    # $Params.Button = Get-Variable -Name 'Buttons' -ValueOnly
# }

# Add boolean switches if present in original $safeParams
# Example: if ($safeParams.ContainsKey('Force')) { $Params.Force = $true } # Needs actual check

Write-Host "DEBUG (Invoke-AsCurrentUser ScriptBlock): Preparing to send toast with Params:"
$Params | Out-String | Write-Host

try {
    New-BurntToastNotification @Params -ErrorAction Stop
    Write-Host "SUCCESS (Invoke-AsCurrentUser ScriptBlock): Toast notification sent successfully."
} catch {
    Write-Host "ERROR (Invoke-AsCurrentUser ScriptBlock): Failed to send toast. Error: $($_.Exception.Message)"
}
'@

                # Prepare replacement values (handle potential nulls/missing keys and escaping)
                $titleValue = $safeParams['Title'] -replace "'", "''"
                # Join array elements for Text, escaping single quotes within each element
                $textLinesValue = ($safeParams['Text'] | ForEach-Object { $_ -replace "'", "''" }) -join "','"
                $appLogoValue = $safeParams['AppLogo'] -replace "'", "''" # Crucial: The icon path
                $appIdValue = $safeParams['AppId'] -replace "'", "''"
                # $buttonsValue = ... # How to handle buttons needs clarification based on usage

                # Perform replacements
                $finalScriptContent = $scriptBlockString -replace '\$Title', $titleValue `
                                                      -replace '\$TextLines', $textLinesValue `
                                                      # -replace '\$AppLogoPath', $appLogoValue # REMOVED as AppID should provide icon
                                                      -replace '\$AppIdValue', $appIdValue `
                                                      # Removed AppId placeholder replacement
                                                      # -replace '\$Buttons', $buttonsValue # Add if buttons are handled

                WriteLog -Message "Final script content for Invoke-AsCurrentUser:`n$finalScriptContent" -Level DEBUG

                # Create the final script block
                $finalScriptBlock = [ScriptBlock]::Create($finalScriptContent)

                # Execute the script block using Invoke-AsCurrentUser
                # Added -CaptureOutput as requested, though its effect might depend on Invoke-AsCurrentUser implementation
                WriteLog -Message "Executing Invoke-AsCurrentUser with placeholder-replaced script block..." -Level DEBUG
                Invoke-AsCurrentUser -ScriptBlock $finalScriptBlock -CaptureOutput # Use the final script block

                WriteLog -Message "Invoke-AsCurrentUser call completed." -Level INFO

            } catch {
                WriteLog -Message "Error attempting notification via Invoke-AsCurrentUser: $($_.Exception.Message)" -Level ERROR
                # Consider if fallback to msg.exe is desired here, or just log the error.
                # For now, just logging the error.
            }

        } else { # This is the 'else' for 'if ($isSystem)' - Running as interactive user
            # Running as a normal user
            WriteLog -Message "Running as interactive user. Attempting direct notification." -Level INFO
            try {
                 Import-Module BurntToast -ErrorAction SilentlyContinue

                 if (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue) {
                     WriteLog -Message "DEBUG: About to send BurntToast notification directly..." -Level DEBUG # Added Log
                     New-BurntToastNotification @PSBoundParameters -ErrorAction Stop
                     WriteLog -Message "DEBUG: Direct BurntToast notification call completed." -Level DEBUG # Added Log
                     WriteLog -Message "Direct notification sent successfully." -Level INFO
                 } else {
                     WriteLog -Message "BurntToast module not loaded or New-BurntToastNotification command not found. Cannot send direct notification." -Level WARN
                 }
            } catch {
                WriteLog -Message "DEBUG: Error occurred during direct BurntToast notification call." -Level ERROR # Added Log
                WriteLog -Message "Error sending direct BurntToast notification: $($_.Exception.Message)" -Level ERROR
            }
        }
    }
    finally {
        ExitFunction
    }
}
#endregion Send Toast Notification

# Export functions to make them available
Export-ModuleMember -Function GetScriptSaveFolder, InvokeLogFileRotation, GetInstalledVersion, StartLoxoneUpdateInstaller, GetCRC32, ShowNotificationToLoggedInUsers, Send-ToastNotification, InvokeScriptErrorHandling, GetProcessStatus, TestScheduledTask, Get-ExecutableSignature, StartProcessInteractive, WaitForPingTimeout, WaitForPingSuccess, Invoke-ZipDownloadAndVerification, GetInstalledApplicationPath, GetLoxoneConfigExePath, Format-TimeSpanFromSeconds, ConvertVersionString, UpdateMS, InvokeMiniserverUpdate, GetRedactedPassword, WriteLog, EnterFunction, ExitFunction, Invoke-ZipFileExtraction # Added Invoke-ZipFileExtraction, Renamed TestExecutableSignature, Added Send-ToastNotification
