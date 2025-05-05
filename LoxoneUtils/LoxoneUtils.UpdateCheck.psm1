# LoxoneUtils.UpdateCheck.psm1
# Module containing functions to check update status for various Loxone components.

##Requires -Modules LoxoneUtils.Logging, LoxoneUtils.Utility # Specify dependencies (Commented out for standalone import testing)

#region Private Helper Functions

# Helper to create the standard component status object
function New-LoxoneComponentStatusObject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Config', 'App', 'MS')]
        [string]$ComponentType,

        [Parameter(Mandatory = $true)]
        [string]$Identifier,

        [Parameter(Mandatory = $false)]
        $InitialVersion, # Can be [version] or [string] or $null

        [Parameter(Mandatory = $false)]
        $LatestVersion, # Can be [version] or [string] or $null

        [Parameter(Mandatory = $true)]
        [bool]$UpdateNeeded,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = $null,

        [Parameter(Mandatory = $false)]
        [string]$RawEntry = $null, # Specific to MS

        # Component-specific data objects
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$ConfigData = $null, # Specific to Config

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$AppData = $null # Specific to App (currently unused for extra fields)
    )

    LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (Before Create): Received ComponentType = '$ComponentType'"
    $statusObject = [PSCustomObject]@{
        ComponentType   = $ComponentType
        Identifier      = $Identifier
        InitialVersion  = $InitialVersion
        LatestVersion   = $LatestVersion # Store the raw string/version object passed
        UpdateNeeded    = $UpdateNeeded
        ShouldRun       = $false # Initialize ShouldRun to false
        Status          = $Status
        UpdateAttempted = $false # Initialize status tracking fields
        UpdateSuccess   = $false
        FinalVersion    = $null
        ErrorMessage    = $ErrorMessage
        RawEntry        = $RawEntry
        # Add component-specific fields conditionally
        ZipUrl          = if ($ComponentType -eq 'Config') { $ConfigData?.Path } else { $null }
        ExpectedCRC     = if ($ComponentType -eq 'Config') { $ConfigData?.CRC32 } else { $null }
        ExpectedSize    = if ($ComponentType -eq 'Config') { $ConfigData?.FileSize } else { $null }
        # Add App specific fields here if needed in the future from $AppData
    }
    LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] Created object properties: $(($statusObject | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -join ', ')"
    # Add Debugging AFTER object creation
    LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (After Assignment): statusObject.ZipUrl = '$($statusObject?.ZipUrl)'"
    LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (After Assignment): statusObject.ExpectedCRC = '$($statusObject?.ExpectedCRC)'"
    LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (After Assignment): statusObject.ExpectedSize = '$($statusObject?.ExpectedSize)'"
            # --- Start Moved Block (Adapted) ---
            # Explicitly set ShouldRun based on Status/UpdateNeeded
            if ($statusObject.Status -eq 'NotFound') {
                LoxoneUtils.Logging\Write-Log -Level INFO -Message "[New-LoxoneComponentStatusObject] Component not installed (Status='NotFound'). Setting ShouldRun=True."
                $statusObject.ShouldRun = $true
            } elseif ($statusObject.UpdateNeeded) {
                 LoxoneUtils.Logging\Write-Log -Level INFO -Message "[New-LoxoneComponentStatusObject] Update required based on version (UpdateNeeded=True). Setting ShouldRun=True."
                 $statusObject.ShouldRun = $true # Ensure it's true if UpdateNeeded is true but status wasn't 'NotFound'
            } else {
                 # ShouldRun is already initialized to $false, but we can be explicit
                 $statusObject.ShouldRun = $false
            }
            # --- End Moved Block ---

}

# Helper to map Compare-LoxoneVersion result to Status and UpdateNeeded
function Get-UpdateStatusFromComparison {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComparisonResult,

        [Parameter(Mandatory = $true)]
        [string]$ComponentLogPrefix, # e.g., "[Config Check]", "[App Check]", "[MS Check '$msIdentifier']"

        # Pass versions for richer logging
        [Parameter(Mandatory = $false)]
        $InstalledVersionString,

        [Parameter(Mandatory = $false)]
        $TargetVersionString
    )

    $updateNeeded = $false
    $status = "Unknown" # Default

    switch ($ComparisonResult) {
        "NotFound" {
            $status = "NotFound"
            $updateNeeded = $true # Assume update needed if not found
            # Removed duplicated lines 109-110
            LoxoneUtils.Logging\Write-Log -Message "$ComponentLogPrefix Installation not found." -Level INFO
        }
        "CheckSkipped (No Target)" {
            $status = "CheckSkipped (No Target)"
            $updateNeeded = $false
            LoxoneUtils.Logging\Write-Log -Message "$ComponentLogPrefix Initial version found ($InstalledVersionString), but target version ('$TargetVersionString') is missing or invalid. Skipping check." -Level WARN
        }
        "Up-to-date" {
            $status = "Up-to-date" # Explicitly set status
            $updateNeeded = $false
            LoxoneUtils.Logging\Write-Log -Message "Is up-to-date ($InstalledVersionString)." -Level INFO
        }
        "Outdated" {
            $status = "Outdated"
            $updateNeeded = $true # Explicitly set update needed
            LoxoneUtils.Logging\Write-Log -Message "$ComponentLogPrefix Update required (Installed: $InstalledVersionString, Latest: $TargetVersionString)." -Level INFO
        }
        "ComparisonError" {
            $status = "VersionCheckFailed" # Map comparison error to a check failure
            $updateNeeded = $false # Don't attempt update if comparison failed
            LoxoneUtils.Logging\Write-Log -Message "$ComponentLogPrefix Failed to compare versions ($InstalledVersionString vs $TargetVersionString)." -Level WARN
        }
        default {
            $status = "ErrorDeterminingStatus" # Unexpected status from Compare-LoxoneVersion
            $updateNeeded = $false
            LoxoneUtils.Logging\Write-Log -Message "$ComponentLogPrefix Unexpected status '$ComparisonResult' received from Compare-LoxoneVersion." -Level ERROR
        } # Added missing closing brace for switch
    } # End switch

    return [PSCustomObject]@{
        Status       = $status
        UpdateNeeded = $updateNeeded
    }
} # End function Get-UpdateStatusFromComparison

# Helper to perform the check logic for a single MS
function Invoke-MSCheckLogic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MSEntry,

        [Parameter(Mandatory = $false)] # Target might be null/empty
        [string]$TargetVersionString,

        [Parameter(Mandatory = $false)] # Normalized target might be null
        [string]$NormalizedLatestMSVersionString,

        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )

    # Assuming Get-RedactedPassword is available (from LoxoneUtils.Utility)
    $redactedEntry = LoxoneUtils.Utility\Get-RedactedPassword $MSEntry
    $msVersion = $null
    $msIdentifier = "UnknownHost" # Default identifier
    $statusResult = $null
    $errorMessage = $null

    # --- Extract Identifier ---
    try {
        # Regex to capture host from various formats (http://user:pass@host:port, user:pass@host, host:port, host)
        if ($MSEntry -match '^(?:https?://)?(?:[^:]+:[^@]+@)?(?<host>[^/:]+)(?::\d+)?') {
            $msIdentifier = $matches.host
        } else {
             LoxoneUtils.Logging\Write-Log -Level WARN -Message "[MS Check Internal] Regex failed to extract host from '$redactedEntry'. Using URI fallback."
             try { $msIdentifier = ([uri]$MSEntry).Host } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($msIdentifier)) { $msIdentifier = "UnknownHost" } # Final fallback
        LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[MS Check Internal] Extracted Identifier '$msIdentifier' for entry '$redactedEntry'."
    } catch {
        LoxoneUtils.Logging\Write-Log -Level WARN -Message "[MS Check Internal] Could not parse entry '$redactedEntry' for identifier. Using fallback. Error: $($_.Exception.Message)"
        try { $msIdentifier = $MSEntry.Split('@')[-1].Split('/')[0].Split(':')[0] } catch {} # Original fallback
        if ([string]::IsNullOrWhiteSpace($msIdentifier)) { $msIdentifier = "UnknownHost" } # Final fallback
    }
    # --- End Extract Identifier ---

    $logPrefix = "[MS Check '$msIdentifier']"

    try {
        # Call Get-MSVersion
        $getMSVersionParams = @{
            MSEntry = $MSEntry
            LogFile         = $LogFile
            ErrorAction     = 'Stop'
        }
        if ($DebugMode.IsPresent) { $getMSVersionParams.DebugMode = $true }

        LoxoneUtils.Logging\Write-Log -Message "$logPrefix Calling Get-MSVersion..." -Level DEBUG
        # IMPORTANT: Call Get-MSVersion directly as it's exported from the module
        $msVersion = Get-MSVersion @getMSVersionParams
LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "$logPrefix Miniserver version check returned: '$msVersion'"

        if ($msVersion) {
            LoxoneUtils.Logging\Write-Log -Message "$logPrefix Version retrieved: $msVersion" -Level INFO
            $normalizedCurrentMSVersionString = $null
            try {
                $normalizedCurrentMSVersionString = LoxoneUtils.Utility\Convert-VersionString $msVersion # Normalize for logging comparison
            } catch {
                 LoxoneUtils.Logging\Write-Log -Message "$logPrefix Failed to normalize current version '$msVersion': $($_.Exception.Message)" -Level WARN
            }


            # Compare versions using Compare-LoxoneVersion (from LoxoneUtils.Utility)
            # IMPORTANT: Call Compare-LoxoneVersion directly as it's exported from the module
            $comparisonStatus = LoxoneUtils.Utility\Compare-LoxoneVersion -InstalledVersionString $msVersion -TargetVersionString $TargetVersionString
            LoxoneUtils.Logging\Write-Log -Message "$logPrefix Compare-LoxoneVersion returned: '$comparisonStatus'" -Level DEBUG

            # Map comparison status using the other helper
            # IMPORTANT: Call Get-UpdateStatusFromComparison directly as it's now in the same module scope
            $getStatusParams = @{
                ComparisonResult        = $comparisonStatus
                ComponentLogPrefix      = $logPrefix
                InstalledVersionString  = $normalizedCurrentMSVersionString
                TargetVersionString     = $NormalizedLatestMSVersionString
            }
            $statusResult = Get-UpdateStatusFromComparison @getStatusParams

        } else { # This is the correct 'else' corresponding to 'if ($msVersion)'
            $errorMessage = "Could not retrieve version (Get-MSVersion returned null/empty)."
            LoxoneUtils.Logging\Write-Log -Message "$logPrefix $errorMessage" -Level WARN
            $statusResult = [PSCustomObject]@{ Status = "VersionCheckFailed"; UpdateNeeded = $false }
        } # Closing brace for the inner 'if ($msVersion)' / 'else' block
        } catch {
            # Catch errors specifically from Get-MSVersion or other issues in the outer try block
            $errorMessage = "Error retrieving/processing version: $($_.Exception.Message)."
            LoxoneUtils.Logging\Write-Log -Message "$logPrefix $errorMessage" -Level WARN
            $msVersion = $null # Ensure version is null on error
            $statusResult = [PSCustomObject]@{ Status = "VersionCheckFailed"; UpdateNeeded = $false }
        } # Closing brace for the catch block

    # Return results needed for the status object
    return [PSCustomObject]@{
        Identifier     = $msIdentifier
        InitialVersion = $msVersion # Raw version string or null
        Status         = $statusResult.Status
        UpdateNeeded   = $statusResult.UpdateNeeded
        ErrorMessage   = $errorMessage # Will be null if no error occurred
    }
} # End function Invoke-MSCheckLogic

# Helper functions moved back to UpdateLoxone.ps1
#endregion Private Helper Functions


# Function to perform the overall update check
# Refactored Test-UpdateNeeded function content
function Test-UpdateNeeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Test', 'Public')]
        [string]$Channel,

        # Parameters needed for component checks (passed from main script)
        [Parameter(Mandatory = $false)]
        [string]$InstalledVersion, # For Config check (Changed to string to allow empty/null)

        [Parameter(Mandatory = $false)]
        [version]$InstalledAppVersion, # For App check

        [Parameter(Mandatory = $false)]
        [string]$InstalledExePath, # For App check (future use?)

        [Parameter(Mandatory = $true)]
        [bool]$CheckLoxoneApp, # For App check

        [Parameter(Mandatory = $true)]
        [string]$ScriptRoot, # To find MS list and download dir

        [Parameter(Mandatory = $true)]
        [string]$LogFile, # For MS check logging

        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )

    Write-Log -Level DEBUG -Message "Entering function $($MyInvocation.MyCommand.Name)" # Replaced Start-FunctionLog
    # --- Logic moved to UpdateLoxone.ps1 ---
    LoxoneUtils.Logging\Write-Log -Message "[Update Check] Function Test-UpdateNeeded entered but logic is now integrated into UpdateLoxone.ps1. Returning empty list." -Level DEBUG
    Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name)" # Replaced Stop-FunctionLog
    return [System.Collections.Generic.List[PSCustomObject]]::new() # Return empty list
}

# Function to check Loxone Config update status
function Test-LoxoneConfigComponent {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)] # Restore Mandatory
            [PSCustomObject]$ConfigData,    # Restore PSCustomObject type
    
            # Keep other existing parameters
            [Parameter(Mandatory = $false)]
            [string]$InstalledVersion, # Changed type from [version] to [string] to allow null/empty
    
            [Parameter(Mandatory = $false)]
            [string]$DownloadDir,
    
            [Parameter(Mandatory = $false)]
            [switch]$DebugMode
        )

    Write-Log -Level DEBUG -Message "Entering function $($MyInvocation.MyCommand.Name)" # Replaced Start-FunctionLog


        # Extract latest version from ConfigData
        $latestVersion = $null
        if ($null -ne $ConfigData) {
            $latestVersion = $ConfigData.Version
        } else {
            LoxoneUtils.Logging\Write-Log -Message "[Config Check] ConfigData parameter was null. Cannot determine latest version." -Level WARN
            # Fall through, logic below handles null target version
        }
    
        # Use Compare-LoxoneVersion to determine status
        # Ensure Compare-LoxoneVersion is available (should be via NestedModules in PSD1 later)
        # Assign properties to local variables FIRST
        # Use Compare-LoxoneVersion to determine status
        # Ensure Compare-LoxoneVersion is available (should be via NestedModules in PSD1 later)
        $comparisonStatus = LoxoneUtils.Utility\Compare-LoxoneVersion -InstalledVersionString $InstalledVersion -TargetVersionString $latestVersion
    LoxoneUtils.Logging\Write-Log -Message "[Config Check] Compare-LoxoneVersion returned: '$comparisonStatus'" -Level DEBUG
    # NOTE: The problematic 'if ($comparisonStatus -eq 'NotFound')' block is confirmed absent here.

    # Duplicate 'NotFound' block removed.

    # Determine status based on comparison result
    # Call Get-UpdateStatusFromComparison directly (now in same module scope)
    $statusResult = Get-UpdateStatusFromComparison -ComparisonResult $comparisonStatus `
                                                  -ComponentLogPrefix "[Config Check]" `
                                                  -InstalledVersionString $InstalledVersion `
                                                  -TargetVersionString $latestVersion

    # Create Config Status Object using helper
    # Create Config Status Object using helper

    # --- Local variable definitions and related debug logs removed ---

    # Call New-LoxoneComponentStatusObject directly (now in same module scope)
    $configStatusObject = New-LoxoneComponentStatusObject -ComponentType 'Config' `
                                                          -Identifier 'Config' `
                                                          -InitialVersion $InstalledVersion `
                                                          -LatestVersion $latestVersion `
                                                          -UpdateNeeded $statusResult.UpdateNeeded `
                                                          -Status $statusResult.Status `
                                                          -ConfigData $ConfigData # Pass object

   # Explicitly set ShouldRun if component not found, overriding initial value if necessary
   # [ShouldRun logic moved to New-LoxoneComponentStatusObject]

   LoxoneUtils.Logging\Write-Log -Message "[Config Check] Status object created: $($configStatusObject | ConvertTo-Json -Depth 1 -Compress)" -Level DEBUG
   Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name)" # Replaced Stop-FunctionLog
   Write-Output $configStatusObject
}

# Export the function(s) from this module file
# Function to check Loxone App update status
function Test-LoxoneAppComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] # AppData might be null if XML parsing failed for App node
        [PSCustomObject]$AppData,

        [Parameter(Mandatory = $true)]
        [bool]$CheckEnabled, # Corresponds to $UpdateLoxoneApp parameter

        [Parameter(Mandatory = $false)] # Passed from main script
        [version]$InstalledAppVersion,

        [Parameter(Mandatory = $false)] # Passed from main script
        [string]$LoxoneExePath, # Currently unused, but passed for potential future use

        [Parameter(Mandatory = $false)] # Passed from main script
        [string]$DownloadDir, # Currently unused, but passed for potential future use

        [Parameter(Mandatory = $false)] # Passed from main script
        [switch]$DebugMode
    )

    Write-Log -Level DEBUG -Message "Entering function $($MyInvocation.MyCommand.Name)" # Replaced Start-FunctionLog

    $latestAppVersion = $null
    if ($null -ne $AppData) {
        $latestAppVersion = $AppData.Version
    } else {
        LoxoneUtils.Logging\Write-Log -Message "[App Check] AppData parameter was null. Cannot determine latest version." -Level WARN
        # Fall through, logic below handles null target version
    }

    $appStatusObject = $null # Initialize

    if ($CheckEnabled) {
        LoxoneUtils.Logging\Write-Log -Message "[App Check] Check enabled. Proceeding..." -Level DEBUG

        LoxoneUtils.Logging\Write-Log -Message "[App Check] Check enabled. Using passed InstalledAppVersion: '$InstalledAppVersion'" -Level DEBUG

        # Use the passed $InstalledAppVersion parameter directly
        # Removed call to Get-AppVersionFromRegistry

        # Use Compare-LoxoneVersion to determine status
        $comparisonStatus = LoxoneUtils.Utility\Compare-LoxoneVersion -InstalledVersionString $InstalledAppVersion -TargetVersionString $latestAppVersion
        # Map comparison status using helper
        # Call Get-UpdateStatusFromComparison directly (now in same module scope)
        $statusResult = Get-UpdateStatusFromComparison -ComparisonResult $comparisonStatus `
                                                      -ComponentLogPrefix "[App Check]" `
                                                      -InstalledVersionString $InstalledAppVersion `
                                                      -TargetVersionString $latestAppVersion

        # Create App Status Object using helper (when check is enabled)
        # Call New-LoxoneComponentStatusObject directly (now in same module scope)
        $appStatusObject = New-LoxoneComponentStatusObject -ComponentType 'App' `
                                                          -Identifier 'App' `
                                                          -InitialVersion $InstalledAppVersion `
                                                          -LatestVersion $latestAppVersion `
                                                          -UpdateNeeded $statusResult.UpdateNeeded `
                                                          -Status $statusResult.Status `
                                                          -AppData $AppData # Pass AppData for potential future use

       # [ShouldRun logic moved to New-LoxoneComponentStatusObject]

   } else {
       LoxoneUtils.Logging\Write-Log -Message "[App Check] Loxone App update check skipped by parameter." -Level INFO

       # Create Skipped App Status Object using helper
       # Call New-LoxoneComponentStatusObject directly (now in same module scope)
       $appStatusObject = New-LoxoneComponentStatusObject -ComponentType 'App' `
                                                         -Identifier 'App' `
                                                         -InitialVersion $null `
                                                         -LatestVersion $latestAppVersion `
                                                         -UpdateNeeded $false ` # ShouldRun will be initialized to false here
                                                         -Status 'Skipped' `
                                                         -AppData $AppData
       # [ShouldRun logic moved to New-LoxoneComponentStatusObject]
   }

   LoxoneUtils.Logging\Write-Log -Message "[App Check] Status object created: $($appStatusObject | ConvertTo-Json -Depth 1 -Compress)" -Level DEBUG

   Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name)" # Replaced Stop-FunctionLog
   LoxoneUtils.Logging\Write-Log -Level DEBUG -Message "[Test-LoxoneAppComponent] Object before Write-Output: $($appStatusObject | ConvertTo-Json -Depth 2 -Compress)" -SkipStackFrame
   Write-Output $appStatusObject # Then output the object
} # Added missing closing brace for Test-LoxoneAppComponent


# Function to check update status for multiple MSs
function Test-LoxoneMSComponents {
    # Temporarily commented out for debugging return value issue
    [CmdletBinding()] # Restore CmdletBinding
    param(
        [Parameter(Mandatory = $true)] # Restore Mandatory attribute
        [string[]]$MSEntries, # Array of entries (e.g., user:pass@host)

        [Parameter(Mandatory = $false)] # MSData might be null if XML parsing failed
        [PSCustomObject]$MSData, # Corrected type constraint

        [Parameter(Mandatory = $true)]
        [string]$LogFile, # Pass log file path explicitly

        [Parameter(Mandatory = $false)]
        [switch]$DebugMode # Changed to switch
        # Removed [ref]$ComponentStatusList parameter
    )

    Write-Log -Level DEBUG -Message "Entering function $($MyInvocation.MyCommand.Name)" # Replaced Start-FunctionLog

    # --- Logic moved to Test-UpdateNeeded ---
    # Keep the function signature but return an empty list immediately.
    # This avoids breaking the module export but bypasses the problematic code.
    LoxoneUtils.Logging\Write-Log -Message "[MS Check] Function Test-LoxoneMSComponents entered but logic is now integrated into Test-UpdateNeeded. Returning empty list." -Level DEBUG

    # Initialize empty list
    $msStatusObjects = [System.Collections.Generic.List[PSCustomObject]]::new()

    # No try/catch needed here anymore as the core logic is gone.
    # Minimal finally block just for logging.
    finally {
        # This block ALWAYS executes to ensure logging stops correctly
        LoxoneUtils.Logging\Write-Log -Message "[MS Check] Entering finally block for gutted function." -Level DEBUG
        Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name)" # Replaced Stop-FunctionLog
    }
    # Log count and return the empty list *after* the finally block
    LoxoneUtils.Logging\Write-Log -Message "[MS Check] Function finished. Returning $($msStatusObjects.Count) MS status objects (should be 0)." -Level DEBUG
    return $msStatusObjects
}

# Removed duplicate function definition

# Function to fetch and parse Loxone update XML data
function Get-LoxoneUpdateData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$UpdateXmlUrl,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Test', 'Public')]
        [string]$ConfigChannel,

        [Parameter(Mandatory=$true)]
        [bool]$CheckAppUpdate,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Test', 'Beta', 'Release', 'Internal', 'InternalV2', 'Latest')]
        [string]$AppChannelPreference,

        [Parameter(Mandatory=$false)]
        [bool]$EnableCRC = $true,

        [Parameter(Mandatory=$false)]
        [switch]$DebugMode
    )

    Write-Log -Level DEBUG -Message "Entering function $($MyInvocation.MyCommand.Name)" # Replaced Start-FunctionLog

    $result = [PSCustomObject]@{
        ConfigLatestVersion     = $null
        ConfigZipUrl            = $null
        ConfigExpectedZipSize   = 0L
        ConfigExpectedCRC       = $null
        AppLatestVersionRaw     = $null
        AppLatestVersion        = $null
        AppInstallerUrl         = $null
        AppExpectedCRC          = $null
        AppExpectedSize         = 0L
        SelectedAppChannelName  = $null
        Error                   = $null
    }

    try {
        # --- Fetch XML ---
        # --- Fetch XML ---
        LoxoneUtils.Logging\Write-Log -Message "Loading update XML from $UpdateXmlUrl" -Level INFO
        $webClient = New-Object System.Net.WebClient
        try {
            $updateXmlString = $webClient.DownloadString($UpdateXmlUrl)
        } catch {
            $result.Error = "Failed to download update XML from '$UpdateXmlUrl'. Error: $($_.Exception.Message)."
            LoxoneUtils.Logging\Write-Log -Message $result.Error -Level ERROR
            Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name) due to error" # Replaced Stop-FunctionLog
            return $result # Return early with error
        }
        $updateXml = [xml]$updateXmlString

        # --- Config Update Info ---
        $xmlNodeName = if ($ConfigChannel -eq 'Public') { 'Release' } else { $ConfigChannel }
        $updateNode = $updateXml.Miniserversoftware.$xmlNodeName
        if (-not $updateNode) {
            $result.Error = "Could not find update information for Config channel '$ConfigChannel' in the XML."
            LoxoneUtils.Logging\Write-Log -Message $result.Error -Level ERROR
            Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name) due to error" # Replaced Stop-FunctionLog
            return $result # Return early with error
        }

        $rawConfigVersion = $updateNode.Version
        $result.ConfigZipUrl = $updateNode.Path
        $expectedConfigSize = 0L
        if (-not ([long]::TryParse($updateNode.FileSize, [ref]$expectedConfigSize))) {
            LoxoneUtils.Logging\Write-Log -Message "[Config] Could not parse FileSize ('$($updateNode.FileSize)') from XML for channel '$ConfigChannel'. Size check might be inaccurate." -Level WARN
            $expectedConfigSize = 0L
        }
        $result.ConfigExpectedZipSize = $expectedConfigSize

        if ($EnableCRC) {
            $result.ConfigExpectedCRC = $updateNode.crc32
            if ([string]::IsNullOrWhiteSpace($result.ConfigExpectedCRC)) {
                LoxoneUtils.Logging\Write-Log -Message "[Config] CRC check enabled, but no CRC found in XML for channel '$ConfigChannel'. CRC check will be skipped for Config." -Level WARN
                $result.ConfigExpectedCRC = $null # Ensure it's null if not found
            }
        }

        try {
            $result.ConfigLatestVersion = LoxoneUtils.Utility\Convert-VersionString $rawConfigVersion
            LoxoneUtils.Logging\Write-Log -Message "[Config] Latest Version (Channel: $ConfigChannel): $($result.ConfigLatestVersion) (Raw: $rawConfigVersion), Size: $($result.ConfigExpectedZipSize)B, URL: $($result.ConfigZipUrl)" -Level INFO
            if ($result.ConfigExpectedCRC) { LoxoneUtils.Logging\Write-Log -Message "[Config] Expected CRC: $($result.ConfigExpectedCRC)" -Level INFO }
        } catch {
            $result.Error = "Failed to convert Config version string '$rawConfigVersion': $($_.Exception.Message)"
            LoxoneUtils.Logging\Write-Log -Message $result.Error -Level ERROR
            # Continue to App check if possible, but mark error
        }

        # --- Loxone for Windows (App) Update Info ---
        $result.SelectedAppChannelName = $AppChannelPreference # Store preference initially
        if ($CheckAppUpdate) {
            LoxoneUtils.Logging\Write-Log -Message "[App] Fetching update details for 'Loxone for Windows' (Channel Preference: $AppChannelPreference) from XML..." -Level INFO
            try {
                $loxWindowsBaseNode = $updateXml.SelectSingleNode("/Miniserversoftware/update[@Name='Loxone for Windows']")
                if (-not $loxWindowsBaseNode) { throw "Could not find base node for 'Loxone for Windows' in XML." }

                $loxWindowsUpdateNode = $null

                if ($AppChannelPreference -eq 'Latest') {
                    LoxoneUtils.Logging\Write-Log -Message "[App] Finding latest version across all channels..." -Level DEBUG
                    $allChannelNodes = $loxWindowsBaseNode.SelectNodes("*") # Select Test, Beta, Release, Internal, InternalV2 etc.
                    $latestNode = $null
                    $latestParsedVersion = [Version]"0.0.0.0"

                    foreach ($channelNode in $allChannelNodes) {
                        $channelName = $channelNode.LocalName # Test, Beta, Release...
                        $rawVersion = $channelNode.Version
                        $parsedVersion = $null
                        $versionToConvert = $null
                        if ($rawVersion -match '\(([\d.]+)\)') { $versionToConvert = $matches[1] }

                        if ($versionToConvert) {
                            try {
                                $parsedVersion = LoxoneUtils.Utility\Convert-VersionString $versionToConvert
                                LoxoneUtils.Logging\Write-Log -Message "[App] Parsed version '$parsedVersion' from channel '$channelName' (Raw: '$rawVersion')." -Level DEBUG
                                if ([Version]$parsedVersion -gt $latestParsedVersion) {
                                    $latestParsedVersion = [Version]$parsedVersion
                                    $latestNode = $channelNode
                                    $result.SelectedAppChannelName = $channelName # Update selected channel name to the actual latest
                                    LoxoneUtils.Logging\Write-Log -Message "[App] Found newer latest version: '$parsedVersion' in channel '$channelName'." -Level DEBUG
                                }
                            } catch {
                                LoxoneUtils.Logging\Write-Log -Message "[App] Error converting version '$versionToConvert' from channel '$channelName': $($_.Exception.Message). Skipping channel." -Level WARN
                            }
                        } else {
                            LoxoneUtils.Logging\Write-Log -Message "[App] Could not extract numerical version pattern from raw string '$rawVersion' for channel '$channelName'. Skipping channel." -Level WARN
                        }
                    }
                    $loxWindowsUpdateNode = $latestNode
                    if ($loxWindowsUpdateNode) {
                         LoxoneUtils.Logging\Write-Log -Message "[App] Selected latest version from channel '$($result.SelectedAppChannelName)'." -Level INFO
                    } else {
                         LoxoneUtils.Logging\Write-Log -Message "[App] Could not determine the latest version across channels." -Level WARN
                    }

                } else {
                    # Specific channel selected
                    $xpath = "/Miniserversoftware/update[@Name='Loxone for Windows']/$AppChannelPreference"
                    LoxoneUtils.Logging\Write-Log -Message "[App] Selecting specific channel node using XPath: $xpath" -Level DEBUG
                    $loxWindowsUpdateNode = $updateXml.SelectSingleNode($xpath)
                }

                # --- Process the selected App node ---
                if ($loxWindowsUpdateNode) {
                    $result.AppLatestVersionRaw = $loxWindowsUpdateNode.Version
                    $result.AppInstallerUrl = $loxWindowsUpdateNode.Path
                    $expectedAppSize = 0L
                    if (-not ([long]::TryParse($loxWindowsUpdateNode.FileSize, [ref]$expectedAppSize))) { LoxoneUtils.Logging\Write-Log -Message "[App] Could not parse FileSize ('$($loxWindowsUpdateNode.FileSize)') for Loxone for Windows (Channel: $($result.SelectedAppChannelName)). Size check might be inaccurate." -Level WARN; $expectedAppSize = 0L }
                    $result.AppExpectedSize = $expectedAppSize

                    if ($EnableCRC) {
                        $result.AppExpectedCRC = $loxWindowsUpdateNode.crc32
                        if ([string]::IsNullOrWhiteSpace($result.AppExpectedCRC)) { LoxoneUtils.Logging\Write-Log -Message "[App] CRC check enabled, but CRC missing for Loxone for Windows (Channel: $($result.SelectedAppChannelName)) in XML." -Level WARN; $result.AppExpectedCRC = $null }
                    }

                    if ([string]::IsNullOrWhiteSpace($result.AppLatestVersionRaw) -or [string]::IsNullOrWhiteSpace($result.AppInstallerUrl)) {
                        LoxoneUtils.Logging\Write-Log -Message "[App] Required attributes (Version, Path) missing for 'Loxone for Windows' (Channel: $($result.SelectedAppChannelName)) in XML. Cannot proceed with App update check." -Level WARN
                        # Reset App fields
                        $result.AppLatestVersionRaw = $null; $result.AppInstallerUrl = $null; $result.AppExpectedCRC = $null; $result.AppExpectedSize = 0L; $result.AppLatestVersion = $null
                    } else {
                        $versionToConvert = $null
                        LoxoneUtils.Logging\Write-Log -Message "[App] Raw version string from XML (Channel: $($result.SelectedAppChannelName)): '$($result.AppLatestVersionRaw)'" -Level DEBUG
                        if ($result.AppLatestVersionRaw -match '\(([\d.]+)\)') {
                            $versionToConvert = $matches[1]
                            LoxoneUtils.Logging\Write-Log -Message "[App] Extracted date-based version from XML (Channel: $($result.SelectedAppChannelName)): '$versionToConvert'" -Level DEBUG
                        } else {
                            LoxoneUtils.Logging\Write-Log -Message "[App] Could not extract numerical version pattern from raw string '$($result.AppLatestVersionRaw)' (Channel: $($result.SelectedAppChannelName)). Cannot determine latest app version." -Level WARN
                            $result.AppLatestVersionRaw = $null; $result.AppLatestVersion = $null; $result.AppInstallerUrl = $null; $result.AppExpectedCRC = $null; $result.AppExpectedSize = 0L
                        }

                        if ($versionToConvert) {
                            try {
                                $result.AppLatestVersion = LoxoneUtils.Utility\Convert-VersionString $versionToConvert
                                LoxoneUtils.Logging\Write-Log -Message "[App] Converted numerical version (Channel: $($result.SelectedAppChannelName)): '$($result.AppLatestVersion)'" -Level DEBUG
                            } catch {
                                 LoxoneUtils.Logging\Write-Log -Message "[App] Error converting extracted version '$versionToConvert' (Channel: $($result.SelectedAppChannelName)): $($_.Exception.Message). Cannot determine latest app version." -Level WARN
                                 $result.AppLatestVersionRaw = $null; $result.AppLatestVersion = $null; $result.AppInstallerUrl = $null; $result.AppExpectedCRC = $null; $result.AppExpectedSize = 0L
                            }
                        }

                        # Only log info if we successfully got a version
                        if ($result.AppLatestVersion) {
                            $appUpdateInfoMsg = "[App] Latest Loxone for Windows (Channel: $($result.SelectedAppChannelName)): Version=$($result.AppLatestVersionRaw) ($($result.AppLatestVersion)), Size=$($result.AppExpectedSize)B, URL=$($result.AppInstallerUrl)"
                            if ($result.AppExpectedCRC) { $appUpdateInfoMsg += ", Expected CRC=$($result.AppExpectedCRC)" }
                            LoxoneUtils.Logging\Write-Log -Message $appUpdateInfoMsg -Level INFO
                        }
                    }
                } else {
                    LoxoneUtils.Logging\Write-Log -Message "[App] Could not find 'Loxone for Windows' update information for channel '$($result.SelectedAppChannelName)' in the XML. Cannot perform App update check." -Level WARN
                }
            } catch {
                LoxoneUtils.Logging\Write-Log -Message "[App] Error parsing XML for Loxone for Windows details (Channel: $($result.SelectedAppChannelName)): $($_.Exception.Message). Cannot perform App update check." -Level ERROR
                # Reset App fields on error
                $result.AppLatestVersionRaw = $null; $result.AppInstallerUrl = $null; $result.AppExpectedCRC = $null; $result.AppExpectedSize = 0L; $result.AppLatestVersion = $null
                if (-not $result.Error) { $result.Error = "Error parsing App XML details." } # Set general error if not already set
            }
        } else {
            LoxoneUtils.Logging\Write-Log -Message "[App] Skipping Loxone for Windows update check as CheckAppUpdate parameter was false." -Level INFO
        }

    } catch {
        # Catch any unexpected errors during the whole process
        $result.Error = "Unexpected error in Get-LoxoneUpdateData: $($_.Exception.Message)"
        LoxoneUtils.Logging\Write-Log -Message $result.Error -Level ERROR
    } finally {
        Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name)" # Replaced Stop-FunctionLog
    }
    # Moved return outside finally block
    return $result
}
# Consolidate exports at the end
Export-ModuleMember -Function Test-UpdateNeeded, Test-LoxoneConfigComponent, Test-LoxoneAppComponent, Test-LoxoneMSComponents, New-LoxoneComponentStatusObject, Get-UpdateStatusFromComparison, Invoke-MSCheckLogic, Get-LoxoneUpdateData
# Removed duplicate Export-ModuleMember call
# Removed extra closing brace