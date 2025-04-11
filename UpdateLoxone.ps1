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
  - Verifies the installer's digital signature.
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
    [bool]$EnableCRC = $true,
    [ValidateSet('silent', 'verysilent')]
    [string]$InstallMode = "verysilent",
    [switch]$CloseApplications,
    [string]$ScriptSaveFolder = $null, # Default determined later
    [int]$MaxLogFileSizeMB = 1,
    [int]$ScheduledTaskIntervalMinutes = 10,
    [switch]$RegisterTask, # New switch to trigger task registration
    [switch]$SkipUpdateIfAnyProcessIsRunning # New switch
)
$script:ScriptDebugMode = $PSBoundParameters.ContainsKey('DebugMode') -and $DebugMode




# --- Script Initialization ---
$script:ErrorOccurred = $false # Use script scope for trap accessibility
$script:LastErrorLine = 0
$script:IsAdminRun = $false # Assume not admin initially
$script:DebugMode = $DebugMode.IsPresent # Set script-level debug mode flag
$global:IsElevatedInstance = $false # Global flag accessible by module
$global:LogFile = $null # Global log file path accessible by module
$script:configUpdated = $false # Flag to track if Config update occurred

# --- Determine if Running as Admin ---
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $script:IsAdminRun = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $global:IsElevatedInstance = $script:IsAdminRun # Set global flag
} catch {
    Write-WARN "Could not determine administrator status. Assuming non-admin. Error: $($_.Exception.Message)"
    $script:IsAdminRun = $false
    $global:IsElevatedInstance = $false
}

# --- Determine Script Save Folder ---
Write-Debug "Determining ScriptSaveFolder..."
if ([string]::IsNullOrWhiteSpace($ScriptSaveFolder)) {
    # Try PSScriptRoot first
    if ($PSScriptRoot) {
        $ScriptSaveFolder = $PSScriptRoot
        Write-Debug "Using PSScriptRoot: '$ScriptSaveFolder'"
    } else {
        # Fallback to UserProfile if PSScriptRoot is not available (e.g., running selection in ISE/VSCode)
        $ScriptSaveFolder = Join-Path -Path $env:USERPROFILE -ChildPath "UpdateLoxone"
        Write-Debug "PSScriptRoot not available. Falling back to UserProfile path: '$ScriptSaveFolder'"
    }
} else {
    Write-Debug "Using provided ScriptSaveFolder parameter: '$ScriptSaveFolder'"
}
Write-Host "INFO: Final ScriptSaveFolder set to: '$ScriptSaveFolder'" -ForegroundColor Cyan

# --- Set Download Directory ---
$DownloadDir = Join-Path -Path $ScriptSaveFolder -ChildPath "Downloads"
Write-Debug "Download directory set to: '$DownloadDir'"

# --- Set Global Log File Path ---
# Get current user and sanitize for filename
$userNameForFile = (([Security.Principal.WindowsIdentity]::GetCurrent()).Name -split '\\')[-1] -replace '[\\:]', '_'
# Construct user-specific log file path
$global:LogFile = Join-Path -Path $ScriptSaveFolder -ChildPath "UpdateLoxone_$userNameForFile.log"
Write-Debug "Global LogFile path set to: '$($global:LogFile)'"

# --- Define Constants ---
$UpdateXmlUrl = "https://update.loxone.com/updatecheck.xml"
$MSListFileName = "UpdateLoxoneMSList.txt"
$MSListPath = Join-Path -Path $ScriptSaveFolder -ChildPath $MSListFileName
$ZipFileName = "LoxoneConfigSetup.zip"
$ZipFilePath = Join-Path -Path $DownloadDir -ChildPath $ZipFileName
$InstallerFileName = "loxoneconfigsetup.exe" # Corrected filename based on user feedback
$InstallerPath = Join-Path -Path $DownloadDir -ChildPath $InstallerFileName
$TaskName = "LoxoneUpdateTask" # Name for the scheduled task

# --- Log Initial Admin Status ---
Write-Debug "Running as Admin: $script:IsAdminRun"

# --- Load Helper Module ---
$UtilsModulePath = Join-Path -Path $PSScriptRoot -ChildPath "UpdateLoxoneUtils.psm1"

if (-not (Test-Path $UtilsModulePath)) {
    Write-Error "Helper module 'UpdateLoxoneUtils.psm1' not found at '$UtilsModulePath'. Script cannot continue."
    exit 1 # Critical dependency missing
}
try {
    # CRC32 Add-Type logic moved to UpdateLoxoneUtils.psm1 inside Get-CRC32 function
    # Remove the module if it's already loaded to ensure the latest version is imported
    Remove-Module UpdateLoxoneUtils -Force -ErrorAction SilentlyContinue
    Import-Module $UtilsModulePath -Force -ErrorAction Stop
    # REMOVED: Explicit global import - rely on standard module import
    # REMOVED: Explicit global import workaround for specific functions.

    # Explicit import removed - relying on the main import above
    Write-Debug "Successfully imported UpdateLoxoneUtils module."
} catch {
    Write-Error "Failed to load helper module '$UtilsModulePath' or define CRC32 type. Error: $($_.Exception.Message). Script cannot continue."
    exit 1 # Critical dependency failed
} # Added missing closing brace and exit call
# --- Define Trap for Error Handling (Moved After Module Import) ---
trap [Exception] {
    # Use the module's error handler
    # Check if the function exists before calling, to prevent errors if module load failed
    if (Get-Command -Name InvokeScriptErrorHandling -ErrorAction SilentlyContinue) {
        InvokeScriptErrorHandling -ErrorRecord $_
    } else {
        Write-Error "CRITICAL: Module function Invoke-ScriptErrorHandling not found. Cannot handle error gracefully. Error was: $($_.Exception.Message)"
    }
    # The handler might call exit 1, but 'break' ensures the script stops after the trap.
    # Explicitly exit here to prevent the finally block from running in case of an error
    exit 1
}

# --- Log PID and Elevation Status ---
# --- Log Rotation ---
if ($global:IsElevatedInstance) { # This line seems correct, no change needed based on function list.
    # Elevated instance, log rotation skipped implicitly or handled elsewhere if needed.
} else {
    # Non-elevated instance, perform log rotation check.
    # Rotate log file on every non-elevated run if it exists
    if (Test-Path $global:LogFile) {
        InvokeLogFileRotation -LogPath $global:LogFile -MaxArchives 24 -DebugMode:$DebugMode # Keep 24 archives, pass DebugMode
    }
} # Closing brace for the 'else' block starting at line 363

# --- Enter Script Scope & Log Start ---
EnterFunction -FunctionName (Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf) -FilePath $PSCommandPath -LineNumber $MyInvocation.ScriptLineNumber
WriteLog -Message "Script starting execution. PID: $PID. IsElevated: $global:IsElevatedInstance" -Level DEBUG

# --- Get Latest Version Info ---
WriteLog -Message "Loading update XML from $UpdateXmlUrl" -Level DEBUG
$webClient = New-Object System.Net.WebClient
try {
    $updateXmlString = $webClient.DownloadString($UpdateXmlUrl)
} catch {
    WriteLog -Message "Failed to download update XML from '$UpdateXmlUrl'. Error: $($_.Exception.Message). Cannot perform version check." -Level ERROR
    throw "Failed to download update XML. Cannot continue." # Throw to trigger trap
}
$updateXml = [xml]$updateXmlString
if ($script:DebugMode) {
    try {
        # Clone the original XML for modification to avoid affecting main logic
        $debugXml = $updateXml.Clone()
        $root = $debugXml.DocumentElement # Get root of the clone

        # 1. Redact Root Certificate Attribute
        if ($root -and $root.HasAttribute('certificate')) {
            $root.SetAttribute('certificate', '[REDACTED]')
            WriteLog -Message "Redacted 'certificate' attribute on root in debug XML." -Level DEBUG
        }

        # 2. Recursively Remove Nodes Starting with 'update' (Case-Insensitive)
        # XPath: //*[starts-with(translate(local-name(), 'UPDATE', 'update'), 'update')]
        # Selects any element (*) anywhere (//) whose lowercase local name starts with 'update'
        $updateNodesToRemove = $debugXml.SelectNodes("//*[starts-with(translate(local-name(), 'UPDATE', 'update'), 'update')]")
        if ($updateNodesToRemove -and $updateNodesToRemove.Count -gt 0) {
            WriteLog -Message "Found $($updateNodesToRemove.Count) nodes starting with 'update' for recursive removal in debug XML." -Level DEBUG
            # Iterate backwards or clone list to avoid modification issues during iteration
            foreach ($node in @($updateNodesToRemove)) { # Clone the collection before iterating
                if ($node.ParentNode) {
                    WriteLog -Message "Removing node '$($node.Name)' from parent '$($node.ParentNode.Name)' in debug XML." -Level DEBUG
                    [void]$node.ParentNode.RemoveChild($node)
                } else {
                    WriteLog -Message "Skipping removal of node '$($node.Name)' as it has no parent (likely root)." -Level DEBUG -Level WARN
                }
            }
            WriteLog -Message "Finished removing 'update*' nodes from debug XML." -Level DEBUG
        } else {
             WriteLog -Message "No nodes starting with 'update' found for removal in debug XML." -Level DEBUG
        }


        # 3. Recursively Redact 'signature' Attributes
        # XPath: //*[@signature]
        # Selects any element (*) anywhere (//) that has a 'signature' attribute
        $signatureNodes = $debugXml.SelectNodes("//*[@signature]")
        if ($signatureNodes -and $signatureNodes.Count -gt 0) {
            WriteLog -Message "Found $($signatureNodes.Count) nodes with 'signature' attribute for redaction in debug XML." -Level DEBUG
            foreach ($node in $signatureNodes) {
                $originalSignature = $node.GetAttribute('signature')
                WriteLog -Message "Redacted 'signature' attribute on node '$($originalSignature)' in debug XML." -Level DEBUG
            }
             WriteLog -Message "Finished redacting 'signature' attributes in debug XML." -Level DEBUG
        } else {
             WriteLog -Message "No 'signature' attributes found for redaction in debug XML." -Level DEBUG
        }

        # 4. Format the MODIFIED XML for Output
        $stringWriter = New-Object System.IO.StringWriter
        $xmlWriter = New-Object System.Xml.XmlTextWriter($stringWriter)
        $xmlWriter.Formatting = [System.Xml.Formatting]::Indented
        $debugXml.WriteTo($xmlWriter) # Write the modified clone
        $formattedXml = $stringWriter.ToString()

        # Log the modified and formatted XML
        Write-Host "DEBUG: Processed (Redacted/Filtered) XML Content:`n$formattedXml" -ForegroundColor Gray

    } catch {
        # Fallback in case of XML processing errors
        Write-Host "DEBUG: Error processing XML for debug output: $($_.Exception.Message). Falling back to raw XML." -ForegroundColor Yellow
        Write-Host "DEBUG: Raw Downloaded XML Content:`n$($updateXml.OuterXml)" -ForegroundColor Gray # Log original XML on error
    }
}

# Select the correct update node based on the channel
# Map 'Public' channel to 'Release' XML node name
$xmlNodeName = if ($Channel -eq 'Public') { 'Release' } else { $Channel }
$updateNode = $updateXml.Miniserversoftware.$xmlNodeName


if (-not $updateNode) {
    throw "Could not find update information for channel '$Channel' in the XML."
}

$LatestVersion = $updateNode.Version
$ZipUrl = $updateNode.Path # Corrected attribute name for the download URL
$ExpectedZipSize = $null
if ($EnableCRC) {
    $ExpectedCRC = $updateNode.crc32 # Correct attribute name
    if ([string]::IsNullOrWhiteSpace($ExpectedCRC)) {
    if ($script:DebugMode) {
        # Filter and truncate XML for debug logging
        try {
            $root = $updateXml.Miniserversoftware # Use $updateXml based on surrounding code
            $truncatedCert = "..." # Default in case attribute is missing
            if ($root.HasAttribute('certificate')) {
                $certValue = $root.GetAttribute('certificate')
                $truncatedCert = $certValue.Substring(0, [System.Math]::Min($certValue.Length, 30)) + "..."
            }

            # Build attribute string excluding certificate
            $attributesString = ($root.Attributes | Where-Object {$_.Name -ne 'certificate'} | ForEach-Object { "$($_.Name)='$($_.Value)'" }) -join " "

            # Start building the filtered XML string
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("<?xml version=`"1.0`" encoding=`"UTF-8`"?>") # Add declaration
            [void]$sb.Append("<$($root.Name) $($attributesString) certificate='$truncatedCert'>")

            # Append allowed child nodes
            $root.ChildNodes | Where-Object {$_.NodeType -eq 'Element' -and $_.Name -notlike 'update*'} | ForEach-Object {
                [void]$sb.Append("`n  ") # Add indentation
                [void]$sb.Append($_.OuterXml)
            }

            [void]$sb.Append("`n</$($root.Name)>")
            $filteredXmlString = $sb.ToString()
            WriteLog -Message "Downloaded XML Content:`n$filteredXmlString" -Level DEBUG
        } catch {
            # Fallback if filtering fails
            WriteLog -Message "Downloaded XML Content (filtering failed):`n$($updateXml.OuterXml)" -Level DEBUG # Log original if filter fails
        }
}
        WriteLog -Message "CRC check enabled, but no CRC found in XML for channel '$Channel'. Disabling CRC check." -Level WARN
        $EnableCRC = $false
    }
}
# Try parsing ExpectedZipSize, default to 0 if missing or invalid
if (-not ([long]::TryParse($updateNode.FileSize, [ref]$ExpectedZipSize))) {
    WriteLog -Message "Could not parse FileSize ('$($updateNode.FileSize)') from XML for channel '$Channel'. File size check might be inaccurate." -Level WARN
    $ExpectedZipSize = 0 # Default to 0 if parsing fails
}
$ExpectedXmlSignature = $updateNode.signature # Extract signature from XML
if ([string]::IsNullOrWhiteSpace($ExpectedXmlSignature)) {
    WriteLog -Message "Signature value missing in XML for channel '$Channel'. Signature validation cannot be performed." -Level WARN
    # Decide if this is critical. For now, we'll allow proceeding without signature check if missing.
    # Consider adding a parameter to enforce signature presence?
    $ExpectedXmlSignature = $null # Ensure it's null if missing/empty
} else {
    if ($DebugMode) {
         WriteLog -Message "Expected XML Signature: $ExpectedXmlSignature" -Level INFO
    }
}

# Construct the core message
$updateInfoMsg = "(Channel: $Channel):$LatestVersion, ${ExpectedZipSize}B, $ZipUrl"
# Append CRC if enabled
if ($EnableCRC) {
    $updateInfoMsg += ", Expected CRC $ExpectedCRC"
}
# Log the combined message
WriteLog -Message $updateInfoMsg -Level INFO

# --- Fetch Installed Version & Compare ---
$LatestVersion = ConvertVersionString $LatestVersion # Convert the raw version immediately

# --- Find Installed Loxone Config ---
$InstalledExePath = GetLoxoneConfigExePath # Uses registry via helper function
$InstalledVersion = if ($InstalledExePath -and (Test-Path $InstalledExePath)) { GetInstalledVersion -ExePath $InstalledExePath } else { "" }
# Look for LoxoneConfig.ico in the installation directory
$LoxoneIconPath = $null
if ($InstalledExePath -and (Test-Path $InstalledExePath)) {
    $InstallDir = Split-Path -Parent $InstalledExePath
    $PotentialIconPath = Join-Path -Path $InstallDir -ChildPath "LoxoneConfig.ico"
    if (Test-Path $PotentialIconPath) {
        $LoxoneIconPath = $PotentialIconPath
        Write-Debug "Found Loxone icon at: $LoxoneIconPath"
    } else {
        Write-Debug "LoxoneConfig.ico not found in $InstallDir. No icon will be used."
    }
}

# --- Convert Installed Version (AFTER fetching) ---
$normalizedInstalled = ConvertVersionString $InstalledVersion
Write-Debug "Normalized - Latest: '$LatestVersion', Installed: '$normalizedInstalled'" # Use converted versions

# Note: The actual *action* based on comparison happens later (around line 440)
# This section just logs the comparison result if needed.
if ($LatestVersion -eq $normalizedInstalled) { # Use the converted $LatestVersion
    WriteLog -Message "Loxone Config is already up-to-date (Version: $InstalledVersion). Config update will be skipped." -Level INFO
    # Optionally notify users even if no update was needed
    # Send-ToastNotification -Text "Loxone AutoUpdate", "Loxone Config is already up-to-date (Version: $InstalledVersion)."
} else {
    WriteLog -Message "Loxone Config update required (Installed: '$InstalledVersion', Available: '$LatestVersion'). Update process will proceed." -Level INFO
}
# --- END VERSION INFO FETCHING AND COMPARISON LOGGING ---

# --- Check/Install BurntToast ---
# Moved inside Send-ToastNotification for interactive vs. task context

# --- Find Installed Loxone Config ---

# --- Monitor Test (Optional, requires installation) ---
if ($InstalledExePath) {
    # Example: Test if Monitor is running and optionally stop it
    # Get-ProcessStatus -ProcessName "loxonemonitor" -StopProcess:$CloseApplications
} else {
    WriteLog -Message "No existing Loxone Config installation found. Cannot run Monitor test without installation." -Level WARN
}

# --- Register Scheduled Task Logic ---
if ($RegisterTask) {
    if (-not $script:IsAdminRun) {
        Write-WARN "Registering the scheduled task requires Administrator privileges. Please re-run as Admin."
        # Don't exit here, allow script to continue if other actions were intended, but log the failure.
        WriteLog -Message "Task registration requested but script is not running as Admin. Task registration skipped." -Level WARN
    } else {
        WriteLog -Message "RegisterTask switch detected. Registering/Updating the scheduled task '$TaskName'." -Level INFO
        # Pass all relevant parameters to the task registration function
        Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition `
                                        -TaskName $TaskName `
                                        -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes `
                                        -Channel $Channel `
                                        -DebugMode:$DebugMode `
                                        -EnableCRC:$EnableCRC `
                                        -InstallMode $InstallMode `
                                        -CloseApplications:$CloseApplications `
                                        -ScriptSaveFolder $ScriptSaveFolder `
                                        -MaxLogFileSizeMB $MaxLogFileSizeMB `
                                        -SkipUpdateIfAnyProcessIsRunning:$SkipUpdateIfAnyProcessIsRunning
        WriteLog -Message "Task registration process finished. Exiting script as -RegisterTask was specified." -Level INFO
        exit 0 # Exit after registering the task
    }
} elseif ($script:IsInteractive -and $script:IsAdminRun -and ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -ne 'NT AUTHORITY\SYSTEM' -and -not (TestScheduledTask)) {
    # If running interactively as Admin, ensure the task is registered for future runs
    WriteLog -Message "Running interactively as Admin. Ensuring scheduled task '$TaskName' is registered/updated." -Level INFO
    Register-ScheduledTaskForScript -ScriptPath $MyInvocation.MyCommand.Definition `
                                    -TaskName $TaskName `
                                    -ScheduledTaskIntervalMinutes $ScheduledTaskIntervalMinutes `
                                    -Channel $Channel `
                                    -DebugMode:$DebugMode `
                                    -EnableCRC:$EnableCRC `
                                    -InstallMode $InstallMode `
                                    -CloseApplications:$CloseApplications `
                                    -ScriptSaveFolder $ScriptSaveFolder `


                                    -MaxLogFileSizeMB $MaxLogFileSizeMB `

                                    -SkipUpdateIfAnyProcessIsRunning:$SkipUpdateIfAnyProcessIsRunning
}

# --- Main Update Logic ---
try {
    # XML fetching and version comparison moved earlier (around line 186)

    # --- Determine Loxone Config Path for Miniserver Update ---
    # This needs to be determined regardless of whether Config update happens,
    # as it's needed for the Miniserver update section later.
    # If Config is up-to-date, use the existing path. If it needs update,
    # the path will be updated *after* successful installation.
    WriteLog -Message "Determining Loxone Config path for potential Miniserver update..." -Level INFO
    $LoxoneConfigExePathForMSUpdate = $InstalledExePath # Default to current path if found, otherwise null

    # --- Loxone Config Update Section (Only if needed) ---
    # The check ($normalizedLatest -ne $normalizedInstalled) was performed earlier.
    # We re-use the result here.
    if ($LatestVersion -ne $normalizedInstalled) { # Use converted $LatestVersion
        # This block now only contains the download/install logic,
        # as the "is update needed?" check and logging happened earlier.
        WriteLog -Message "Update required (Installed: '$InstalledVersion', Available: '$LatestVersion')." -Level INFO
        $toastParams = @{ Text = "Loxone AutoUpdate", "New version $LatestVersion available. Starting download..." }
        if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
        Send-ToastNotification @toastParams

        # --- Check Running Processes ---
        $processesToCheck = @("LoxoneConfig", "loxonemonitor", "LoxoneLiveView") # Add other relevant processes if needed
        $anyProcessRunning = $false
        foreach ($procName in $processesToCheck) {
            if (GetProcessStatus -ProcessName $procName -StopProcess:$false) { # Just check, don't stop yet
                $anyProcessRunning = $true
                WriteLog -Message "Detected running process: $procName" -Level INFO
            }
        }

        if ($anyProcessRunning -and $SkipUpdateIfAnyProcessIsRunning) {
            WriteLog -Message "Skipping update because one or more Loxone processes are running and -SkipUpdateIfAnyProcessIsRunning was specified." -Level WARN
            $toastParams = @{ Text = "Loxone AutoUpdate Skipped", "Update skipped because Loxone application(s) are running." }
            if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
            Send-ToastNotification @toastParams
            # Exit gracefully without error
            exit 0
        }

        # --- Check for Existing Installer and Validate ---
        $skipDownload = $false
        if (Test-Path -Path $InstallerPath -PathType Leaf) {
            WriteLog -Message "Existing installer found at '$InstallerPath'. Validating version and signature..." -Level INFO
            $existingVersion = GetInstalledVersion -ExePath $InstallerPath # Use helper to get file version
            $normalizedExisting = ConvertVersionString $existingVersion
            $signatureValid = $false
            $versionMatch = $false

            if ($normalizedExisting) {
                WriteLog -Message "Existing installer version: $normalizedExisting. Target version: $LatestVersion." -Level DEBUG # Use converted $LatestVersion
                if ($normalizedExisting -eq $LatestVersion) { # Use converted $LatestVersion
                    $versionMatch = $true
                    WriteLog -Message "Existing installer version matches target version." -Level INFO
                } else {
                    WriteLog -Message "Existing installer version ($normalizedExisting) does NOT match target version ($normalizedLatest)." -Level WARN
                }
            } else {
                WriteLog -Message "Could not determine version for existing installer '$InstallerPath'." -Level WARN
            }

            if ($ExpectedXmlSignature) {
                WriteLog -Message "Validating signature of existing installer..." -Level DEBUG
                if (TestExecutableSignature -ExePath $InstallerPath) {
                    $signatureValid = $true
                    WriteLog -Message "Existing installer signature is VALID." -Level INFO
                } else {
                    WriteLog -Message "Existing installer signature is INVALID." -Level WARN
                }
            } else {
                 WriteLog -Message "XML Signature was missing. Cannot validate existing installer signature." -Level WARN
                 # Signature cannot be considered valid if it's missing from XML
                 $signatureValid = $false
            }

            # Skip download ONLY if BOTH version matches AND signature is valid (or signature check was skipped but version matched)
            # If signature was required ($ExpectedXmlSignature was present) it MUST be valid.
            # If signature was NOT required ($ExpectedXmlSignature was null), only version needs to match.
            if ($versionMatch -and (!$ExpectedXmlSignature -or $signatureValid)) {
                 WriteLog -Message "Existing installer '$InstallerPath' matches target version and has a valid signature (or signature check not required). Skipping download." -Level INFO
                 $skipDownload = $true
            } else {
                 WriteLog -Message "Existing installer '$InstallerPath' failed validation (Version Match: $versionMatch, Signature Valid: $signatureValid). Removing and proceeding with download." -Level WARN
                 Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
            }
        } else {
             WriteLog -Message "No existing installer found at '$InstallerPath'. Proceeding with download." -Level INFO
        }

        # --- Download and Verify ---
        if (-not $skipDownload) {
            WriteLog -Message "Starting download and verification..." -Level INFO

        # --- Download and Verify ---
        # Ensure Download Directory Exists
        if (-not (Test-Path -Path $DownloadDir -PathType Container)) {
            WriteLog -Message "Download directory '$DownloadDir' not found. Creating..." -Level INFO
            New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null
        }

        # Call the download and verification function from the module
        # Determine the CRC value to pass based on the EnableCRC flag
        $CrcValueToPass = if ($EnableCRC) { $ExpectedCRC } else { $null }

        # Call the download and verification function from the module
        # Call the download and verification function from the module.
        # It throws an error on failure, which is caught by the script's trap handler.
        # Capture the function's return value ($true on success) to prevent it from echoing to the host.
        $null = Invoke-ZipDownloadAndVerification -ZipUrl $ZipUrl `
                                          -DestinationPath $ZipFilePath `
                                          -ExpectedCRC32 $CrcValueToPass `
                                          -ExpectedFilesize $ExpectedZipSize `
                                          -MaxRetries 1 # Allow 1 retry (2 total attempts)

        # Error handling for download/verification is now inside the function, which throws on failure.
        # If the function returns $true, we proceed. If it throws, the script trap handles it.
        WriteLog -Message "Download and verification completed successfully." -Level INFO

        # --- Extract Installer ---
        WriteLog -Message "Extracting installer from $ZipFilePath..." -Level INFO
        # Remove existing installer if it exists to ensure clean extraction
        if (Test-Path $InstallerPath) {
            Write-Debug "Removing existing installer file: $InstallerPath"
            Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
        }
        Expand-Archive -Path $ZipFilePath -DestinationPath $DownloadDir -Force -ErrorAction Stop
        if (-not (Test-Path $InstallerPath)) {
            throw "Installer file '$InstallerPath' not found after extraction."
        }
        WriteLog -Message "Installer extracted successfully to $InstallerPath." -Level INFO
        } # End of the 'if (-not $skipDownload)' block for download/extraction/verification

        # --- Verify Final Installer Signature (only if downloaded) ---
        if (-not $skipDownload) {
            WriteLog -Message "Verifying downloaded installer signature using XML data..." -Level INFO
            if ($ExpectedXmlSignature) {
                if (-not (TestExecutableSignature -ExePath $InstallerPath)) {
                    # If the downloaded installer fails validation, it's a critical error.
                    throw "CRITICAL: Downloaded installer '$InstallerPath' failed signature validation against the expected XML signature '$ExpectedXmlSignature'."
                }
                WriteLog -Message "Downloaded installer signature verified successfully against XML signature." -Level INFO
            } else {
                WriteLog -Message "XML Signature was missing. Skipping downloaded installer signature validation." -Level WARN
                # Optionally, perform the standard Authenticode check as a fallback?
                # Write-Log -Message "Performing standard Authenticode check as fallback..." -Level INFO
                # Get-ExecutableSignature -ExePath $InstallerPath # Keep old check as fallback? Or remove completely? Removing for now.
                # Write-Log -Message "Standard Authenticode check completed (result logged by function)." -Level INFO
            }
        } else {
            WriteLog -Message "Skipping final installer signature verification as download was skipped (existing installer was valid)." -Level INFO
        }

        # --- Close Applications (if requested and not skipping) ---
        if ($CloseApplications -and -not $SkipUpdateIfAnyProcessIsRunning) {
            WriteLog -Message "Attempting to close Loxone applications..." -Level INFO
            $toastParams = @{ Text = "Loxone AutoUpdate", "Closing Loxone applications for update..." }
            if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
            Send-ToastNotification @toastParams
            foreach ($procName in $processesToCheck) {
                GetProcessStatus -ProcessName $procName -StopProcess:$true # Now actually stop them
            }
            Start-Sleep -Seconds 2 # Give processes time to close
        } elseif ($anyProcessRunning -and -not $SkipUpdateIfAnyProcessIsRunning) {
            # If processes are running but CloseApplications was not specified
            WriteLog -Message "Loxone application(s) are running, but -CloseApplications was not specified. Update might fail." -Level WARN
            $toastParams = @{ Text = "Loxone AutoUpdate WARN", "Loxone application(s) are running. Update might fail. Please close them manually if issues occur." }
            if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
            Send-ToastNotification @toastParams
        }

        # --- Run Installer ---
        WriteLog -Message "Running installer..." -Level INFO
        $toastParams = @{ Text = "Loxone AutoUpdate", "Installing version $LatestVersion..." }
        if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
        Send-ToastNotification @toastParams
        StartLoxoneUpdateInstaller -InstallerPath $InstallerPath -InstallMode $InstallMode -ScriptSaveFolder $ScriptSaveFolder
        WriteLog -Message "Installation completed." -Level INFO

        # --- Verify New Installation ---
        $NewInstalledExePath = GetLoxoneConfigExePath # Re-check path after install using helper
        $NewInstalledVersion = if ($NewInstalledExePath -and (Test-Path $NewInstalledExePath)) { GetInstalledVersion -ExePath $NewInstalledExePath } else { "" }
        $normalizedNewInstalled = ConvertVersionString $NewInstalledVersion

        if ($normalizedNewInstalled -eq $LatestVersion) { # Use converted $LatestVersion
            WriteLog -Message "Successfully updated Loxone Config to version $NewInstalledVersion." -Level INFO
            $toastParams = @{ Text = "Loxone AutoUpdate Complete", "Successfully updated Loxone Config to version $NewInstalledVersion." }
            if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
            Send-ToastNotification @toastParams
            $script:configUpdated = $true # Set flag indicating Config update happened
            # Update the path variable for the MS update section later
            $LoxoneConfigExePathForMSUpdate = $NewInstalledExePath
            WriteLog -Message "Loxone Config path for MS update set to: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
        } else {
            # This block executes if the installed version after update doesn't match the expected latest version
            $errorMessage = "Update verification failed! Expected version '$($LatestVersion)' but found '$($normalizedNewInstalled)' after installation." # Use converted $LatestVersion
            WriteLog -Message $errorMessage -Level ERROR
            $toastParams = @{ Text = "Loxone AutoUpdate Failed", $errorMessage }
            if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
            Send-ToastNotification @toastParams
            # Consider this a script error and throw it to be caught by the trap
            throw $errorMessage
        }

    } else {
        # This block executes if the installed version MATCHES the latest version
        WriteLog -Message "Loxone Config is already up-to-date (Version: $InstalledVersion). No update needed." -Level INFO
        # Ensure the path for MS update is still set correctly using the current installation
        WriteLog -Message "Using current installation path for potential Miniserver update: $LoxoneConfigExePathForMSUpdate" -Level DEBUG
    }
    # End of Config update logic


# --- End of Main Try Block ---
} catch {
    # This is the main catch block for errors *outside* the download/verification function
    # The download/verification function's errors are caught by the script trap via 'throw'
    $script:ErrorOccurred = $true
    # Safely try to get the line number
    $script:LastErrorLine = try { $_.InvocationInfo.ScriptLineNumber } catch { 0 } 
    # Safely format the error message


    $exceptionMessage = try { $_.Exception.Message -as [string] } catch { "Could not retrieve exception message." }
    $commandName = try { $_.InvocationInfo.MyCommand.ToString() -as [string] } catch { "N/A" }
    $scriptName = try { $_.InvocationInfo.ScriptName -as [string] } catch { "N/A" }
    $lineContent = try { $_.InvocationInfo.Line -as [string] } catch { "N/A" }

    $errorMessage = "An unexpected error occurred during the update process: $exceptionMessage"
    $errorDetails = @"
Error: $exceptionMessage
Script: $scriptName
Line: $script:LastErrorLine
Command: $commandName
Line Content: $lineContent
"@
    WriteLog -Message $errorMessage -Level ERROR
    WriteLog -Message "--- Error Details ---`n$errorDetails`n--- End Error Details ---" -Level ERROR
    if ($_.ScriptStackTrace) {
        $exceptionStackTrace = try { $_.ScriptStackTrace -as [string] } catch { "Could not retrieve stack trace." }
        WriteLog -Message "--- StackTrace ---`n$exceptionStackTrace`n--- End StackTrace ---" -Level ERROR
    }
    $toastParams = @{ Text = "Loxone AutoUpdate FAILED", $errorMessage }
    if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
    Send-ToastNotification @toastParams

    # Pause for user input only if running interactively - Logic moved to Finally block
    # if (-not (Test-ScheduledTask)) {
    #     # Pause logic moved to finally block
    # }
    exit 1 # Ensure script exits with an error code
} finally {
    # Final cleanup actions, always run
    Write-Debug "Executing Finally block."

    # Pause for user input if an error occurred AND running interactively
    if ($script:ErrorOccurred -and -not (TestScheduledTask)) {
        # Check if the error occurred *before* the main catch block's pause was reached
        # (e.g., error handled by the trap which calls exit)
        # This pause might be redundant if the trap already paused, but ensures a pause happens
        # if the error was caught differently or if the trap's exit was bypassed somehow.
        Write-Host "`n--- SCRIPT PAUSED DUE TO ERROR (Finally Block) ---" -ForegroundColor Yellow
        Write-Host "An error occurred during script execution (Last known error line: $script:LastErrorLine)." -ForegroundColor Yellow
        Write-Host "Check the log file '$($global:LogFile)' for details." -ForegroundColor Yellow
        # Avoid double pausing if the main catch already did it.
        Read-Host "Press Enter to exit..."
    }

    ExitFunction # Exit Script Scope
}

# --- Functions used by the script (Moved to UpdateLoxoneUtils.psm1) ---
# The function definitions previously here (lines 510-613) have been moved to the module.
# Keeping the section headers for reference, but the code is gone.

# --- Get-InstalledApplicationPath Function ---

# --- Get-InstalledVersion Function ---

# --- Convert-VersionString Function ---

# --- Invoke-ZipDownloadAndVerification Function ---

# --- Get-CRC32 Function ---

# --- Invoke-ZipFileExtraction Function ---

# --- Get-ExecutableSignature Function ---

# --- Update Miniservers (Always Run After Config Check) ---
if (-not ([string]::IsNullOrWhiteSpace($LoxoneConfigExePathForMSUpdate)) -and (Test-Path $LoxoneConfigExePathForMSUpdate)) {

    # NOTE: The actual calls to Wait-For-Ping-Timeout/Success happen inside the Update-MS function (in UpdateLoxoneUtils.psm1).
    # Fixing the empty InputAddress parameter requires modifying UpdateLoxoneUtils.psm1.
    # The following demonstrates the required extraction logic, but cannot be directly passed to the wait functions from here.
    # Example extraction (assuming $miniserverEntry contained the URI like 'http://user:pass@192.168.1.77/path'):
    # $miniserverHost = ($miniserverEntry -as [uri]).Host # This should be done inside Invoke-MiniserverUpdate in the module.

    # Pass the determined LoxoneConfig.exe path
    # Pass the determined LoxoneConfig.exe path and capture the result
    $miniserversUpdated = UpdateMS -DesiredVersion $LatestVersion `
                                    -MSListPath $MSListPath `
                                    -LogFile $global:LogFile `
                                    -MaxLogFileSizeMB $MaxLogFileSizeMB `
                                    -DebugMode:$DebugMode `
                                    -ScriptSaveFolder $ScriptSaveFolder `
                                    -InstalledExePath (Split-Path -Parent $LoxoneConfigExePathForMSUpdate) # Pass only the directory path

    # --- Check Log File for Errors from UpdateMS ---
    # Note: This is a basic check. A more robust solution might involve UpdateMS returning a status object.
    if (Test-Path $global:LogFile) {
        # Get the content logged *since* the script started (approximate)
        # We can refine this if needed, e.g., by passing start time to UpdateMS
        $recentLogContent = Get-Content $global:LogFile -Raw -ErrorAction SilentlyContinue # Read the whole file
        # Check if any ERROR lines related to UpdateMS or Miniserver processing exist
        if ($recentLogContent -match '\[ERROR\].*(UpdateMS|Miniserver)') {
            WriteLog -Message "Detected ERROR in log related to Miniserver update process. Setting error flag." -Level WARN
            $script:ErrorOccurred = $true # Set the global error flag
        }
    }

    # Determine if any update action was performed (for notification purposes)
    $anyUpdatePerformed = $script:configUpdated -or $miniserversUpdated
    WriteLog -Message "Update Status - Config Updated: $($script:configUpdated), Miniservers Updated: $($miniserversUpdated), Any Update Performed: $anyUpdatePerformed" -Level INFO

    # Only show final notification if an update action was performed
    # if ($anyUpdatePerformed) { # Temporarily commented out to force notification for testing
    #    WriteLog -Message "DEBUG: Calling Send-ToastNotification for final status..." -Level DEBUG # Added Log
        $toastParams = @{ Text = "Loxone AutoUpdate Complete", "Loxone update process finished. Check logs for details." }
        if ($LoxoneIconPath) { $toastParams.AppLogo = $LoxoneIconPath }
        Send-ToastNotification @toastParams
    # } else {
    #    WriteLog -Message "No Loxone Config or Miniserver updates were performed. Skipping final notification." -Level INFO # Reverted Level Change
    # }
} # End of the 'if' block starting on line 705
else { # This 'else' corresponds to the 'if' on line 705
    WriteLog -Message "Skipping Miniserver update because a valid Loxone Config path could not be determined (Path: '$LoxoneConfigExePathForMSUpdate')." -Level WARN
} # End of the 'else' block starting on line 735

# --- Final Exit Code Handling ---
if ($script:ErrorOccurred) {
    WriteLog -Message "Exiting with error code 1 due to detected errors." -Level ERROR
    Exit 1
} else {
    WriteLog -Message "Exiting with code 0 (Success)." -Level INFO
    Exit 0
}
