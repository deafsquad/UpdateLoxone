[CmdletBinding()]
param(
    [Parameter()][ValidateSet("Release", "Beta", "Test", IgnoreCase = $true)] [string]$Channel = "Test",
    [Parameter()] [object]$DebugMode = $false,
    [Parameter()] [object]$EnableCRC = $true,
    [Parameter()][ValidateSet("silent", "verysilent", IgnoreCase = $true)] [string]$InstallMode = "verysilent",
    [Parameter()] [object]$CloseApplications = $false,
    # Default will be overridden below by the script's own location.
    [Parameter()] [string]$ScriptSaveFolder = $null, # Default to null, will be set below
    [Parameter()] [int]$MaxLogFileSizeMB = 1,
    [Parameter()] [int]$ScheduledTaskIntervalMinutes = 10,
    [Parameter()] [object]$SkipUpdateIfAnyProcessIsRunning = $false,
    [Parameter()] [switch]$TestNotifications = $false,
    [Parameter()] [int]$MonitorLogWatchTimeoutMinutes = 240,
    [Parameter()] [switch]$TestMonitor = $false,
    [Parameter()] [string]$MonitorSourceLogDirectory = $null, # Optional: Specify custom path for monitor logs
    [Parameter()] [switch]$TestKill = $false, # Pause script for external termination test
    [Parameter()] [switch]$SetupSystemMonitor = $false, # Special mode to start monitor as SYSTEM for testing
    [Parameter(DontShow=$true)][switch]$Elevated = $false # Internal switch for self-elevation
)

# ScriptSaveFolder and LogFile will be determined after module import using Get-ScriptSaveFolder function.

# $ScriptSaveFolder will be determined after module import.
# $global:LogFile will be set after $ScriptSaveFolder is determined.
# Immediately convert parameters to proper Boolean types.
# Immediately convert parameters to proper Boolean types.
$DebugMode = [bool]$DebugMode
$EnableCRC = [bool]$EnableCRC
$CloseApplications = [bool]$CloseApplications
$SkipUpdateIfAnyProcessIsRunning = [bool]$SkipUpdateIfAnyProcessIsRunning
# Make elevation status globally accessible for logging functions
$global:IsElevatedInstance = $Elevated

# Define download directory
$downloadDir = Join-Path -Path $ScriptSaveFolder -ChildPath "Downloads" # Define download dir relative to script save folder
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [DEBUG] Download directory set to: '$downloadDir'"
# Set VerbosePreference based on DebugMode.
# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [DEBUG] Running as Admin: $isAdmin"
if ($DebugMode) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

###############################################################################
#                            INITIALIZATION & IMPORTS                         #
###############################################################################


#region CRC32 Class Definition and Loading
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
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [DEBUG] Successfully loaded CRC32 class (in main script)."
    }
    catch {
        Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to load CRC32 class: $($_.Exception.Message)"
        throw $_ # Fail fast if CRC class can't be loaded
    }
} else {
     Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [DEBUG] CRC32 class already loaded. Skipping Add-Type (in main script)."
}
#endregion


try {
     # Construct module path - prioritize $PSScriptRoot, fallback to CWD for interactive
     $moduleUtilPath = "UpdateLoxoneUtils.psm1"
     $moduleFullPath = ""
    if (-not [string]::IsNullOrEmpty($PSScriptRoot)) {
        $moduleFullPath = Join-Path -Path $PSScriptRoot -ChildPath $moduleUtilPath
     } elseif (Test-Path (Join-Path (Get-Location) $moduleUtilPath)) {
         # Fallback for interactive if module is in CWD
         $moduleFullPath = Join-Path (Get-Location) $moduleUtilPath
         Write-Warning "Could not determine PSScriptRoot, attempting to load module from CWD: $moduleFullPath"
     } else {
         throw "Cannot determine script path or find module '$moduleUtilPath' in CWD."
     }
     
     Import-Module -Name $moduleFullPath -Force -ErrorAction Stop
    # Use Write-Host as Write-DebugLog might not be available yet if import fails partially
    Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")] [DEBUG] Successfully imported UpdateLoxoneUtils module."
    # Now determine the ScriptSaveFolder using the function from the module
    $ScriptSaveFolder = Get-ScriptSaveFolder -InvocationInfo $MyInvocation -BoundParameters $PSBoundParameters
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [DEBUG] ScriptSaveFolder determined by function: '$ScriptSaveFolder'"

    # Initialize the global log file path using the determined ScriptSaveFolder.
    $global:LogFile = Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxone.log"
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [DEBUG] Global LogFile path set to: '$global:LogFile'"
    
    # Initialize remaining global status flags (Write-DebugLog is now available)
    $global:ErrorOccurred = $false
    $global:LastErrorLine = "N/A"
    $global:UacCancelled = $false
    $global:ScriptInterrupted = $false
    Write-DebugLog "Global variables initialized. LogFile: $($global:LogFile)"

} catch {
    Write-Warning "FATAL: Could not import utility module 'UpdateLoxoneUtils.psm1' or determine ScriptSaveFolder. Script cannot continue. Error: $($_.Exception.Message)"
    # Log to temp file if possible - tempLogPath was removed, consider alternative if needed
    # if ($tempLogPath) { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [FATAL] Script initialization failed. Error: $($_.Exception.Message)" | Out-File -FilePath $tempLogPath -Append -Encoding UTF8 }
    exit 1
}
# Cleaned up placeholders after moving functions to module
 
 #region Main Script Execution
 Write-LogMessage "Script starting execution. PID: $PID. IsElevatedInstance: $Elevated" -Level "INFO"
 
 # Only rotate logs if this is the initial (non-elevated) instance.
 if (-not $Elevated) {
     Write-LogMessage "Running as initial instance (PID: $PID). Invoking log rotation." -Level "INFO"
     Invoke-LogFileRotation -LogPath $global:LogFile
 } else {
     Write-LogMessage "Running as elevated instance (PID: $PID). Skipping log rotation." -Level "INFO"
 }

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
        if ($installedExePath) { 
            $loxoneMonitorExePath = Find-File -BasePath $installedExePath
        }
        if (-not $loxoneMonitorExePath) {
            Write-LogMessage "loxonemonitor.exe not found under path: ${installedExePath}. Cannot set up SYSTEM process." -Level "ERROR"
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
        if (-not [string]::IsNullOrEmpty($installedVersion)) {
            Write-LogMessage "Installed version: ${installedVersion}" -Level "INFO"
        } else {
            Write-LogMessage "Could not determine installed version from '$localAppExe'." -Level "WARN"
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

    # --- Scheduled Task Setup ---
    $scheduledTaskName = "LoxoneUpdateTask"
    $isRunningAsTask = Test-ScheduledTask # Assume this function exists and works

    Write-DebugLog "Checking interactivity and admin status. IsRunningAsTask: $isRunningAsTask, IsAdmin: $isAdmin, ElevatedSwitch: $Elevated"

    # Only attempt elevation or registration if NOT running as a task (i.e., interactive)
    if (-not $isRunningAsTask) {
        Write-DebugLog "Script detected as running interactively. Proceeding with elevation/registration checks."
        # If this is the first run (not the elevated instance) AND we are not Admin, attempt elevation.
        if (-not $Elevated -and -not $isAdmin) {
            Write-LogMessage "Scheduled task requires Admin rights for interactive setup. Attempting self-elevation..." -Level "WARN"
            # Prepare arguments for re-launch, passing all original parameters + -Elevated
            $relaunchArgsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", """$($MyInvocation.MyCommand.Path)""")
            $PSBoundParameters.Keys | ForEach-Object {
                $paramName = $_; $paramValue = $PSBoundParameters[$paramName]
                if ($paramValue -is [System.Management.Automation.SwitchParameter]) {
                    if ($paramValue.IsPresent) { $relaunchArgsList += "-$paramName" }
                } else {
                    # Ensure values with spaces are quoted correctly
                    $relaunchArgsList += "-$paramName", """$($paramValue -replace '"','""')""" # Double up internal quotes
                }
            }
            $relaunchArgsList += "-Elevated" # Add the internal switch
            $relaunchArgs = $relaunchArgsList -join " "
            Write-DebugLog "Relaunch Args: $relaunchArgs"
            try {
                Start-Process -FilePath "PowerShell.exe" -ArgumentList $relaunchArgs -Verb RunAs -ErrorAction Stop
                Write-LogMessage "Elevated process launched. Exiting current non-elevated instance." -Level "INFO"
                exit 0 # Exit the non-elevated instance
            } catch { Write-LogMessage "Failed to self-elevate: $($_.Exception.Message). Task registration will likely fail." -Level "ERROR" }
        }
        # If we are Admin (either initially or after elevation), register/update the task.
        # The function uses -Force, so it handles creation or update.
        elseif ($isAdmin) {
            Write-LogMessage "Running interactively as Admin. Ensuring scheduled task '$scheduledTaskName' is registered/updated." -Level "INFO"
            Write-DebugLog "About to call Register-ScheduledTaskForScript. Value of `$DebugMode in this scope: $DebugMode"
            $scriptDestination = $MyInvocation.MyCommand.Path # Use current script path
            Register-ScheduledTaskForScript -ScriptPath $scriptDestination -TaskName $scheduledTaskName
        }
        # If not Admin and elevation failed or was skipped, log it (interactive context)
        elseif (-not $isAdmin) {
             Write-LogMessage "Running interactively without Admin rights and elevation failed or was skipped. Scheduled task cannot be registered/updated." -Level "WARN"
        }
    }
    else {
        Write-DebugLog "Script detected as running via Scheduled Task. Skipping elevation and task registration/update."
    }
    # We rely on the -Elevated switch to prevent the elevated instance from trying again if elevation was attempted.

    # --- Installation Check Block Moved Up ---


    if ($SkipUpdateIfAnyProcessIsRunning -and $installedExePath) {
        $isRunning = Get-ProcessStatus -ProcessName "loxoneconfig" # Changed from Check-ProcessRunning
        if ($isRunning) {
            Write-LogMessage "LoxoneConfig.exe is running. Skipping update." -Level "INFO"
            exit 0  # Exit if Loxone Config is running and skip is enabled
        }
        # No need for else log here, Get-ProcessStatus logs if not running
        else {
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

    # --- Process Update XML ---
    if ($DebugMode) {
        Write-LogMessage "XML Root: $($xml.DocumentElement.Name)" -Level "DEBUG"
        Write-LogMessage "Available update channels:" -Level "DEBUG"
        foreach ($node in $xml.DocumentElement.ChildNodes) {
            Write-LogMessage "- $($node.name)" -Level "DEBUG"
        }
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
        Get-ExecutableSignature -ExePath $extractedExe.FullName -ReferenceExePath $localAppExe # Pass installed exe path for thumbprint comparison

        Write-LogMessage "Starting Loxone Config installer..." -Level "INFO"
        Start-LoxoneUpdateInstaller -InstallerPath $extractedExe.FullName -InstallMode $InstallMode
		 # --- Miniserver Update (Always runs after LoxoneConfig install/update) ---
		Write-LogMessage "Proceeding with Miniserver update." -Level "INFO"
		  Update-MS -DesiredVersion $updateVersion `
        Write-DebugLog "Update-MS Call 1: ScriptSaveFolder='$ScriptSaveFolder', MSListPath='$(Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt")'"
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
     Write-DebugLog "Update-MS Call 2: ScriptSaveFolder='$ScriptSaveFolder', MSListPath='$(Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt")'"
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
     # Note: $LASTEXITCODE might not be accurate if script exited via 'exit' in catch block

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
        Write-LogMessage "Script execution finished with an ERROR detected on line $global:LastErrorLine. $exitCodeMsg" -Level "ERROR"
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
