# Module: UpdateLoxoneUtils.psm1
# Contains helper functions for the UpdateLoxone.ps1 script

#region Logging Functions
function Write-DebugLog {
    param(
        [string]$Message,
        [switch]$ErrorMessage
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = "DEBUG"
    if ($ErrorMessage) { $prefix = "ERROR" }
    $elevationStatus = if ($global:IsElevatedInstance) { $true } else { $false } # Ensure boolean
    $logEntry = "$timestamp [$prefix] [PID:$PID|Elevated:$elevationStatus] $Message"

    # Console Output controlled by $script:DebugMode
    if ($script:DebugMode) {
        if ($ErrorMessage) {
            Write-Host "ERROR: $Message" -ForegroundColor Red
        }
        else {
            Write-Host "DEBUG: $Message"
        }
    }
    
    # File Output controlled by $global:LogFile existence
    # File Output controlled by $global:LogFile existence AND $script:DebugMode
    if ($global:LogFile) {
        # Only write DEBUG level to file if DebugMode is enabled
        if ($script:DebugMode) {
            try {
                # Ensure log directory exists (important when run as SYSTEM maybe?)
                $logDir = Split-Path -Path $global:LogFile -Parent
                if (-not (Test-Path $logDir)) {
                    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                }
                $logEntry | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
            }
            catch {
                Write-Host "ERROR: Could not write DEBUG entry to log file '${global:LogFile}'. Exception: ${($_.Exception.Message)}" -ForegroundColor Red
            }
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
    $elevationStatus = if ($global:IsElevatedInstance) { $true } else { $false } # Ensure boolean
    $logEntry = "[$timestamp] [$Level] [PID:$PID|Elevated:$elevationStatus] $Message"
    
    # File Output controlled by $global:LogFile existence
    if ($global:LogFile) {
        try {
             # Ensure log directory exists
            $logDir = Split-Path -Path $global:LogFile -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
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
    }

    # Console Output controlled by Level and $script:DebugMode for DEBUG level
    switch ($Level.ToUpper()) {
        "DEBUG" { if ($script:DebugMode) { Write-Verbose $logEntry } } 
        "INFO"  { Write-Host $logEntry -ForegroundColor Green }
        "WARN"  { Write-Warning $logEntry }
        "ERROR" { Write-Warning "ERROR: $Message" } 
    }
}
#endregion

#region Log Rotation
function Invoke-LogFileRotation {
    param(
        [string]$LogPath,
        [int]$MaxArchives = 24
    )
    if (Test-Path $LogPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logDir = Split-Path -Path $LogPath -Parent
        $archiveFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogPath) + "_${timestamp}.log"
        $archivePath = Join-Path -Path $logDir -ChildPath $archiveFileName
        
        Write-DebugLog "Attempting to rotate '$LogPath' to '$archivePath'"
        try {
            # Try renaming first, might release lock faster than copy/delete
            Rename-Item -Path $LogPath -NewName $archivePath -Force -ErrorAction Stop
            Write-DebugLog -Message "Log file renamed to archive '${archivePath}'."
        }
        catch {
            Write-LogMessage -Message "Error rotating log file '$LogPath' to '$archivePath' using Rename-Item: ${($_.Exception.Message)}. Will attempt cleanup anyway." -Level "WARN"
            # Continue to cleanup logic even if rename fails
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
		   Return $null
        }
    }
    else {
        Write-LogMessage "Installed application not found at ${ExePath}." -Level "WARN"
		Return $null
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
# Note: Add-Type should ideally be run once, perhaps in the main script or module loading.
# Keeping it here for now, but be aware it might log "already loaded" messages.
# CRC32 Add-Type logic moved to main UpdateLoxone.ps1 script's initialization block.

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
        [int]$Timeout = 0,
        [string]$AppId = 'WindowsPowerShell'
    )

    Write-DebugLog "Entering Show-NotificationToLoggedInUsers" 
    $isRunningAsTask = Test-ScheduledTask # This will call the function available in the current scope (module or mocked)
    Write-DebugLog "Result of Test-ScheduledTask: $isRunningAsTask" 

    if (-not $isRunningAsTask) {
        Write-LogMessage "Running interactively. Attempting direct notification." -Level "INFO"
        try {
             if (-not (Get-Module -ListAvailable -Name BurntToast)) {
                 Write-LogMessage "BurntToast module not found. Attempting to install for current user." -Level "WARN"
                 Install-Module -Name BurntToast -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction SilentlyContinue
             }
             Import-Module BurntToast -ErrorAction SilentlyContinue
             $appLogoPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
             New-BurntToastNotification -AppLogo $appLogoPath -Text $Title, $Message -ErrorAction Stop
             Write-LogMessage "Direct notification sent successfully." -Level "INFO"
             return
        } catch {
            Write-LogMessage "Direct notification failed: $($_.Exception.Message). Falling back to scheduled task method." -Level "WARN"
        }
    }

    Write-LogMessage "Attempting notification via scheduled task method." -Level "INFO"
    $activeSessions = @()
    try {
        Write-DebugLog "Querying Win32_LogonSession for LogonType = 2..."
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType = 2"
        Write-DebugLog "Found $($sessions.Count) sessions with LogonType 2."
        
        # Log details of all found sessions before filtering
        if ($sessions) {
            Write-DebugLog "Details of all LogonType=2 sessions found:"
            foreach ($s in $sessions) {
                $assocAcc = Get-CimAssociatedInstance -InputObject $s -ResultClassName Win32_Account -ErrorAction SilentlyContinue
                $userName = if ($assocAcc) { "$($assocAcc[0].Domain)\$($assocAcc[0].Name)" } else { "<Account N/A>" }
                Write-DebugLog "- Session ID: $($s.LogonId), StartTime: $($s.StartTime), User: $userName"
            }
        } else {
            Write-DebugLog "No LogonType=2 sessions returned by Get-CimInstance."
        }

        foreach ($session in $sessions) {
            $assocAccounts = Get-CimAssociatedInstance -InputObject $session -ResultClassName Win32_Account -ErrorAction SilentlyContinue
            if ($assocAccounts) {
                Write-DebugLog "Found associated account: $($assocAccounts[0].Domain)\$($assocAccounts[0].Name) for session $($session.LogonId)."
                $quserOutput = quser.exe $session.LogonId 2>$null | Out-String
                Write-DebugLog "quser output for session $($session.LogonId):`n$quserOutput"
                # Check if quser output contains the session ID, indicating it's likely an interactive session
                if ($quserOutput -match "\b$($session.LogonId)\b") {
                    Write-DebugLog "Session $($session.LogonId) found in quser output, assuming interactive."
                    $userPrincipal = New-Object System.Security.Principal.NTAccount($assocAccounts[0].Domain, $assocAccounts[0].Name)
                    $activeSessions += [PSCustomObject]@{
                        SessionId = $session.LogonId
                        UserName = $assocAccounts[0].Name
                        Domain = $assocAccounts[0].Domain
                        UserSID = $userPrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        Principal = "$($assocAccounts[0].Domain)\$($assocAccounts[0].Name)"
                    }
                    Write-DebugLog "Added active interactive session: $($assocAccounts[0].Domain)\$($assocAccounts[0].Name) (Session ID: $($session.LogonId))"
                } else {
                    Write-DebugLog "Session $($session.LogonId) NOT found in quser output or output is empty."
                }
            } else {
                 Write-DebugLog "Could not find associated account for session ID: $($session.LogonId)."
            }
        }
    } catch {
        Write-LogMessage "Error querying user sessions: $($_.Exception.Message)" -Level "WARN"
        Write-DebugLog "Stack trace for session query error: $($_.ScriptStackTrace)" -ErrorMessage
    }

    Write-DebugLog "Total active sessions identified for notification: $($activeSessions.Count)"
    if ($activeSessions.Count -gt 0) {
        if (-not (Get-Module -ListAvailable -Name BurntToast)) {
             Write-LogMessage "BurntToast module not found. Notifications may fail if not installed for target users." -Level "WARN"
        }

        $appLogoPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

        foreach ($userSession in $activeSessions) {
            $taskName = "TempLoxoneToastNotification_$($userSession.UserName)_$(Get-Date -Format 'yyyyMMddHHmmssfff')"
            $principal = $userSession.Principal
            Write-LogMessage "Attempting to send notification to user '$principal' via temporary scheduled task '$taskName'." -Level "INFO"

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
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -RunLevel Limited -Force -ErrorAction Stop
                Write-DebugLog "Registered temporary task '$taskName' for user '$principal'."
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                Write-LogMessage "Triggered temporary notification task '$taskName' for user '$principal'." -Level "INFO"
            } catch {
                Write-LogMessage "Failed to register or start temporary notification task '$taskName' for user '$principal': $($_.Exception.Message)" -Level "ERROR"
                Write-DebugLog "Stack trace for temporary task registration/start error: $($_.ScriptStackTrace)" -ErrorMessage
            } finally {
                Start-Sleep -Seconds 1
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

#region Invoke-ScriptErrorHandling Function
function Invoke-ScriptErrorHandling {
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
    
	$global:ErrorOccurred = $true
    $global:LastErrorLine = $lineNumber
    
    Write-LogMessage "Script execution terminated = $global:ErrorOccurred due to the above error on line $global:LastErrorLine." -Level "ERROR"
    exit 1
}
#endregion

#region Get-ProcessStatus, Test-ScheduledTask, Start-ProcessInteractive
function Get-ProcessStatus {
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

function Test-ScheduledTask {
    Write-DebugLog "Executing ORIGINAL Test-ScheduledTask function from module." # Added log
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
function Invoke-ZipFileExtraction {
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

function Get-ExecutableSignature {
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

#region UPDATED Convert-VersionString Function
function Convert-VersionString {
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
            return $true
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    $stopwatch.Stop()
    Write-LogMessage "Ping timeout: $IPAddress remained reachable for $($TimeoutSeconds) seconds." -Level "DEBUG"
    return $false
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
            return $true
        }
        Start-Sleep -Seconds $IntervalSeconds
    }

    $stopwatch.Stop()
    Write-LogMessage "Ping success: $IPAddress did not become reachable within $($TimeoutSeconds) seconds." -Level "DEBUG"
    return $false
}
#endregion

#region Get-FileRecursive Function
function Get-FileRecursive {
    param(
        [string]$BasePath,
        [string]$FileName
    )
    try {
        $found = Get-ChildItem -Path $BasePath -Filter $FileName -Recurse -ErrorAction Stop | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
        else {
            return $null
        }
    }
    catch {
        Write-LogMessage "Error searching for file '${FileName}' under '${BasePath}': ${($_.Exception.Message)}" -Level "WARN"
        return $null
    }
}
#endregion

#region Format-DoubleCharacter Function
function Format-DoubleCharacter {
    param([int]$Number)
    return "{0:D2}" -f $Number
}
#endregion

#region Get-RedactedPassword Function (Reverted to original simpler regex)
function Get-RedactedPassword {
    param([string]$Url)
    # Write-DebugLog "Get-RedactedPassword - Input URL: $Url" # Removed to avoid logging potentially sensitive input
    # Reverted Regex: Lookbehind for ://, capture user, :, capture password, lookahead for @
    if ($Url -match "(?<=://)([^:]+):([^@]+)(?=@)") {
        Write-DebugLog "Get-RedactedPassword - Regex matched. User: $($Matches[1]), Password Length: $($Matches[2].Length)" 
        $redactedPassword = "*" * $Matches[2].Length
        $redactedUrl = $Url -replace "(?<=://)([^:]+):([^@]+)(?=@)", ('$1:{0}' -f $redactedPassword)
        Write-DebugLog "Get-RedactedPassword - Redacted URL: $redactedUrl"
        return $redactedUrl
    }
    Write-DebugLog "Get-RedactedPassword - Regex did not match." 
    return $Url # Return original URL if no match
}
#endregion

#region Set-ConstantVariable Function
function Set-ConstantVariable {
    param(
        [string]$Name,
        [object]$Value
    )
    Set-Variable -Name $Name -Value $Value -Option Constant -Scope Global
}
#endregion

#region Get-InstalledApplicationPath Function
function Get-InstalledApplicationPath {
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
                        Write-LogMessage "Found Loxone Config installation at: ${installLocation}" -Level "INFO"
                        return $installLocation
                    }
                }
            }
        }
    }
    Write-LogMessage "Loxone Config installation path not found in registry." -Level "INFO"
    return $null
}
#endregion

#region Update-MS Function (Corrected URI Logic + Redaction before logging)
function Update-MS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$DesiredVersion,
        [Parameter(Mandatory = $true)] [string]$MSListPath,
        [Parameter(Mandatory = $true)] [string]$LogFile,
        [Parameter(Mandatory = $true)] [int]$MaxLogFileSizeMB,
        [Parameter(Mandatory = $true)] [bool]$DebugMode,
        [Parameter(Mandatory = $true)] [string]$InstalledExePath,
        [Parameter(Mandatory = $true)] [string]$ScriptSaveFolder
    )

    Write-LogMessage "Starting Update-MS function..." -Level "INFO"

    if (-not (Test-Path $MSListPath)) {
        Write-LogMessage "Miniserver list file not found at '${MSListPath}'. Skipping Miniserver updates." -Level "WARN"
        return
    }

    $miniservers = Get-Content $MSListPath | Where-Object { $_ -match '\S' } # Read non-empty lines
    Write-LogMessage "Loaded Miniserver list with $($miniservers.Count) entries." -Level "INFO"

    if ($miniservers.Count -eq 0) {
        Write-LogMessage "Miniserver list is empty. Skipping Miniserver updates." -Level "INFO"
        return
    }

    # Find LoxoneConfig.exe path (needed for update command)
    $loxoneConfigExe = Join-Path -Path $InstalledExePath -ChildPath "LoxoneConfig.exe"
    if (-not (Test-Path $loxoneConfigExe)) {
        Write-LogMessage "LoxoneConfig.exe not found at '${loxoneConfigExe}'. Cannot perform Miniserver updates." -Level "ERROR"
        return # Cannot proceed without the executable
    }

    $normalizedDesiredVersion = Convert-VersionString $DesiredVersion

    foreach ($msEntry in $miniservers) {
        $redactedEntry = Get-RedactedPassword $msEntry # Redact the entry first for logging
        Write-DebugLog -Message "Processing Miniserver entry: ${redactedEntry}"
        
        $msIP = $null
        $versionUri = $null
        $updateArg = $null # Argument for LoxoneConfig.exe /update:
        $baseUriBuilder = $null

        $credential = $null # Store credentials if present
        try {
            # Attempt to parse the entry as a URI to extract components
            $entryToParse = $msEntry
            if ($entryToParse -notmatch '^[a-zA-Z]+://') {
        $redactedMsIP = "[Could not determine IP]" # Default for logging if IP extraction fails
                $entryToParse = "http://" + $entryToParse # Assume http if no scheme
            }
            $baseUriBuilder = [System.UriBuilder]$entryToParse
            $msIP = $baseUriBuilder.Host # Get Host/IP
            
            $redactedMsIP = $msIP # Start with host, redact later if needed

            # Extract credentials if present
            if (-not [string]::IsNullOrEmpty($baseUriBuilder.UserName)) {
                $credential = New-Object System.Management.Automation.PSCredential($baseUriBuilder.UserName, ($baseUriBuilder.Password | ConvertTo-SecureString -AsPlainText -Force))
            }
            # Construct the version check URI correctly
            $versionUriBuilder = [System.UriBuilder]$baseUriBuilder # Copy base info
            $versionUriBuilder.Path = "/dev/cfg/version" # Set the correct path
            $versionUri = $versionUriBuilder.Uri.AbsoluteUri # Use AbsoluteUri to get final string

            # Construct the argument for the update command
            $updateArg = if (-not [string]::IsNullOrEmpty($baseUriBuilder.UserName)) {
                             $baseUriBuilder.UserName + ":" + $baseUriBuilder.Password + "@" + $baseUriBuilder.Host
                         } else {
                             $msIP # Just host/IP if no credentials
                         }

        } catch {
            Write-LogMessage "Failed to parse Miniserver entry '$redactedEntry' as URI: $($_.Exception.Message). Assuming it's just an IP/hostname." -Level "WARN"
            $credential = $null # No credentials if parsing failed
            # Assume the entry is just the IP/hostname if parsing fails
            $msIP = $msEntry.Split('@')[-1].Split('/')[0] # Basic attempt to extract host/IP
            $redactedMsIP = $msIP # No credentials to redact if parsing failed
            $versionUri = "http://${msIP}/dev/cfg/version" # Construct basic URI
            $updateArg = $msIP # Use just host/IP for update arg
        }

        if (-not $msIP) {
             Write-LogMessage "Could not determine IP/Host from entry '$redactedEntry'. Skipping." -Level "ERROR"
             continue # Skip to next entry
        }

        # Log the URI *after* redaction
        $redactedVersionUri = Get-RedactedPassword $versionUri
        Write-LogMessage "Checking current Miniserver version via URI: ${redactedVersionUri}" -Level "INFO"
        
        try {
            # Use the *unredacted* URI for the web request
            # Use the *unredacted* URI for the web request
            $webRequestParams = @{
                Uri = $versionUri
                UseBasicParsing = $true
                TimeoutSec = 10
                ErrorAction = 'Stop'
            }
            if ($credential) { $webRequestParams.Credential = $credential }
            $response = Invoke-WebRequest @webRequestParams
            # Parse XML response to extract version from <LL value="...">
            $xmlResponse = [xml]$response.Content
            $currentVersion = $xmlResponse.LL.value
            if ([string]::IsNullOrEmpty($currentVersion)) {
                throw "Could not find version value in Miniserver XML response: $($response.Content)"
            }
            
            Write-LogMessage "Current Miniserver Version: ${currentVersion}" -Level "INFO"
            $normalizedCurrentVersion = Convert-VersionString $currentVersion

            # Compare versions
            Write-DebugLog -Message "Comparing current version (${normalizedCurrentVersion}) with desired version (${normalizedDesiredVersion})."
            if ($normalizedCurrentVersion -ne $normalizedDesiredVersion) {
                Write-LogMessage "Miniserver at ${redactedMsIP} requires update (Current: ${normalizedCurrentVersion}, Desired: ${normalizedDesiredVersion})." -Level "INFO"
                # Use the potentially credentialed base URI for the update command argument
                Invoke-MiniserverUpdate -LoxoneConfigPath $loxoneConfigExe -MiniserverIP $updateArg 
            }
            else {
                Write-LogMessage "Mininiserver at ${redactedMsIP} is already up-to-date (Version: ${normalizedCurrentVersion}). Skipping update." -Level "INFO"
            }
        }
        catch {
            # Log the error using the redacted VERSION URI
            Write-LogMessage "Failed to check or update Miniserver (URI: ${redactedVersionUri}). ErrorRecord: $_" -Level "ERROR"
            # Continue to the next Miniserver
        }
    } # End foreach Miniserver

    Write-LogMessage "Update-MS function completed. All Miniservers have been processed." -Level "INFO"
}
#endregion

#region Invoke-MiniserverUpdate Function
function Invoke-MiniserverUpdate {
    param(
        [string]$LoxoneConfigPath,
        [string]$MiniserverIP # This might now contain user:pass@host
    )
    $redactedIP = Get-RedactedPassword $MiniserverIP
    Write-LogMessage "Attempting to update Miniserver ${redactedIP} using ${LoxoneConfigPath}..." -Level "INFO"
    # LoxoneConfig.exe likely expects the argument format /update:user:pass@host or /update:host
    $arguments = "/update:${MiniserverIP}" # Pass the potentially credentialed string directly
    try {
        $process = Start-Process -FilePath $LoxoneConfigPath -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
        Write-LogMessage "LoxoneConfig update process for ${redactedIP} finished with Exit Code: $($process.ExitCode)." -Level "INFO"
        if ($process.ExitCode -ne 0) {
            Write-LogMessage "LoxoneConfig update process for ${redactedIP} reported a non-zero exit code: $($process.ExitCode)." -Level "WARN"
            # Consider this a warning, not necessarily a fatal error for the whole script
        }
    }
    catch {
        Write-LogMessage "Error starting LoxoneConfig update process for ${redactedIP}: ${($_.Exception.Message)}" -Level "ERROR"
        # Continue to next Miniserver if possible
    }
}
#endregion

# Save-ScriptToUserLocation function removed as it's no longer suitable with the module dependency.

#region Invoke-AdminAndCorrectPathCheck Function
function Invoke-AdminAndCorrectPathCheck {
    # Placeholder - Actual logic might involve checking admin status and script path
    Write-DebugLog -Message "Invoke-AdminAndCorrectPathCheck called (currently a placeholder)."
}
#endregion

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
    Write-DebugLog "Register-ScheduledTaskForScript called. Received -DebugMode parameter value: $DebugMode"

    Write-LogMessage "Checking if the scheduled task '${TaskName}' exists." -Level "INFO"
    $taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    # Always attempt to register/update. If it exists, unregister first to ensure arguments are clean.
    if ($taskExists) {
        Write-LogMessage "Scheduled task '${TaskName}' already exists. Unregistering before re-registering to ensure arguments are updated." -Level "INFO"
        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
        catch { Write-LogMessage "Failed to unregister existing task '$TaskName': $($_.Exception.Message). Re-registration might fail or use old settings." -Level "WARN" }
    }
    # If task didn't exist or was successfully unregistered, proceed to register.
    # Note: If unregister failed, Register-ScheduledTask below might also fail or update incorrectly.
    
    Write-LogMessage "Attempting to register task '${TaskName}'." -Level "INFO"
    $actionArgs = @(
        "-NoProfile",
        "-ExecutionPolicy Bypass",
        "-File `"$ScriptPath`"",
        "-Channel `"$Channel`"",
        # "-DebugMode `$($DebugMode)", # Removed unconditional inclusion
        "-EnableCRC `$($EnableCRC)",
        "-InstallMode `"$InstallMode`"",
        "-CloseApplications `$($CloseApplications)",
        "-ScriptSaveFolder `"$ScriptSaveFolder`"",
        "-MaxLogFileSizeMB $MaxLogFileSizeMB",
        "-ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes",
        "-SkipUpdateIfAnyProcessIsRunning `$($SkipUpdateIfAnyProcessIsRunning)"
    )
     # Conditionally add DebugMode switch only if it was true during registration
     if ($DebugMode) {
         $actionArgs += "-DebugMode" # Add the switch without a value
        Write-DebugLog "Final actionArgs array before join: $($actionArgs | Out-String)"
     }
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument ($actionArgs -join " ")
    # Corrected Trigger: Removed RepetitionDuration for indefinite interval
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
    Write-DebugLog "Attempting to create task settings with parameters: $($settingsParams | Out-String)" # Added Log
    $settings = New-ScheduledTaskSettingsSet @settingsParams -ErrorAction SilentlyContinue

    if (-not $settings) {
         Write-LogMessage "Failed to create ScheduledTaskSettingsSet object. Task registration cannot proceed." -Level "ERROR"
         throw "Failed to create ScheduledTaskSettingsSet."
    }
    Write-DebugLog "Successfully created basic ScheduledTaskSettingsSet object." # Added Log

    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Automatic Loxone Config Update" -ErrorAction Stop # Removed -Force as we unregister first
            Write-LogMessage "Scheduled task '${TaskName}' created successfully." -Level "INFO"
            
            # Attempt to set other settings separately (might fail on older systems)
            try {
                $task = Get-ScheduledTask -TaskName $TaskName
                $task.Settings.DisallowStartIfOnBatteries = $false
                $task.Settings.StopIfGoingOnBatteries = $false
                $task.Settings.AllowHardTerminate = $true
                $task.Settings.RunOnlyIfNetworkAvailable = $false
                $task.Settings.Enabled = $true
                Set-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
                Write-DebugLog "Attempted to apply additional settings to task '$TaskName'."
            } catch {
                Write-DebugLog "Could not apply additional settings to task '$TaskName' using Set-ScheduledTask: $($_.Exception.Message)"
            }

        }
        catch {
            Write-LogMessage "Error creating the scheduled task: ${($_.Exception.Message)}" -Level "ERROR"
            # If running non-elevated, this is expected. If elevated, it's a real error.
            if (-not $script:IsAdminRun) {
                 Write-Host "  INFO: Task registration correctly failed with error (not Admin): $($_.Exception.Message)" -ForegroundColor Gray
            } else {
                 throw $_ # Re-throw if running as admin, as it shouldn't fail
            }
        }
}
#endregion

#region Find-File Function (Placeholder/Example)
function Find-File {
    param(
        [string]$BasePath,
        [string]$FileName = "loxonemonitor.exe" # Default to monitor
    )
    # Simple placeholder implementation
    $potentialPath = Join-Path -Path $BasePath -ChildPath $FileName
    if (Test-Path $potentialPath) {
        return $potentialPath
    }
    # Add more sophisticated search logic if needed (e.g., recursive)
    return $null
}
#endregion

#region Start/Stop Loxone Monitor (Placeholders)
function Start-LoxoneMonitor {
    param([string]$MonitorExePath)
    Write-DebugLog "Start-LoxoneMonitor called with path: $MonitorExePath (currently placeholder)"
    # Add logic to start the monitor process if needed
}

function Stop-LoxoneMonitor {
    Write-DebugLog "Stop-LoxoneMonitor called (currently placeholder)"
    # Add logic to stop the monitor process if needed
    Stop-Process -Name loxonemonitor -Force -ErrorAction SilentlyContinue
}
#endregion

#region Watch-And-Move-MonitorLogs (Placeholder)
function Watch-And-Move-MonitorLogs {
    param(
        [string]$SourceLogDir,
        [string]$DestinationLogDir,
        [int]$TimeoutMinutes,
        [switch]$CreateTestFile
    )
    Write-DebugLog "Watch-And-Move-MonitorLogs called (currently placeholder)"
    Write-LogMessage "Source: $SourceLogDir, Dest: $DestinationLogDir, Timeout: $TimeoutMinutes" -Level "DEBUG"
    if ($CreateTestFile) { Write-LogMessage "CreateTestFile switch was present." -Level "DEBUG" }
    # Placeholder return value
    return $true
}
#endregion

#region Invoke-ZipDownloadAndVerification Function (Placeholder)
function Invoke-ZipDownloadAndVerification {
    param(
        [string]$ZipUrl,
        [string]$DestinationPath,
        [string]$ExpectedCRC32,
        [int64]$ExpectedFilesize,
        [int]$MaxRetries
    )
     Write-DebugLog "Invoke-ZipDownloadAndVerification called (currently placeholder)"
     Write-LogMessage "URL: $ZipUrl, Dest: $DestinationPath" -Level "DEBUG"
     # Placeholder - Assume success for testing flow
     # In reality, download, check size, check CRC
     if (-not (Test-Path $DestinationPath)) {
         Set-Content -Path $DestinationPath -Value "Dummy ZIP content" # Create dummy file if needed
     }
}
#endregion
