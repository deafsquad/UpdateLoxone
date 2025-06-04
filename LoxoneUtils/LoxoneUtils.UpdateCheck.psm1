# LoxoneUtils.UpdateCheck.psm1
# Module containing functions to check update status for various Loxone components.
# NOTE: Most functions in this module have been refactored and their logic moved to UpdateLoxone.ps1 and WorkflowSteps module

#region Active Functions - Still Used

# Function to fetch and parse Loxone update XML data
# This function is still actively used by the workflow
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

    Write-Log -Level DEBUG -Message "Entering function $($MyInvocation.MyCommand.Name)"

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
        Write-Log -Message "Loading update XML from $UpdateXmlUrl" -Level INFO
        $webClient = New-Object System.Net.WebClient
        try {
            $updateXmlString = $webClient.DownloadString($UpdateXmlUrl)
        } catch {
            $result.Error = "Failed to download update XML from '$UpdateXmlUrl'. Error: $($_.Exception.Message)."
            Write-Log -Message $result.Error -Level ERROR
            Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name) due to error"
            return $result # Return early with error
        }
        $updateXml = [xml]$updateXmlString

        # --- Config Update Info ---
        $xmlNodeName = if ($ConfigChannel -eq 'Public') { 'Release' } else { $ConfigChannel }
        $updateNode = $updateXml.Miniserversoftware.$xmlNodeName
        if (-not $updateNode) {
            $result.Error = "Could not find update information for Config channel '$ConfigChannel' in the XML."
            Write-Log -Message $result.Error -Level ERROR
            Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name) due to error"
            return $result # Return early with error
        }

        $rawConfigVersion = $updateNode.Version
        $result.ConfigZipUrl = $updateNode.Path
        $expectedConfigSize = 0L
        if (-not ([long]::TryParse($updateNode.FileSize, [ref]$expectedConfigSize))) {
            Write-Log -Message "[Config] Could not parse FileSize ('$($updateNode.FileSize)') from XML for channel '$ConfigChannel'. Size check might be inaccurate." -Level WARN
            $expectedConfigSize = 0L
        }
        $result.ConfigExpectedZipSize = $expectedConfigSize

        if ($EnableCRC) {
            $result.ConfigExpectedCRC = $updateNode.crc32
            if ([string]::IsNullOrWhiteSpace($result.ConfigExpectedCRC)) {
                Write-Log -Message "[Config] CRC check enabled, but no CRC found in XML for channel '$ConfigChannel'. CRC check will be skipped for Config." -Level WARN
                $result.ConfigExpectedCRC = $null # Ensure it's null if not found
            }
        }

        try {
            $result.ConfigLatestVersion = Convert-VersionString $rawConfigVersion
            Write-Log -Message "[Config] Latest Version (Channel: $ConfigChannel): $($result.ConfigLatestVersion) (Raw: $rawConfigVersion), Size: $($result.ConfigExpectedZipSize)B, URL: $($result.ConfigZipUrl)" -Level INFO
            if ($result.ConfigExpectedCRC) { Write-Log -Message "[Config] Expected CRC: $($result.ConfigExpectedCRC)" -Level INFO }
        } catch {
            $result.Error = "Failed to convert Config version string '$rawConfigVersion': $($_.Exception.Message)"
            Write-Log -Message $result.Error -Level ERROR
            # Continue to App check if possible, but mark error
        }

        # --- Loxone for Windows (App) Update Info ---
        $result.SelectedAppChannelName = $AppChannelPreference # Store preference initially
        if ($CheckAppUpdate) {
            Write-Log -Message "[App] Fetching update details for 'Loxone for Windows' (Channel Preference: $AppChannelPreference) from XML..." -Level INFO
            try {
                $loxWindowsBaseNode = $updateXml.SelectSingleNode("/Miniserversoftware/update[@Name='Loxone for Windows']")
                if (-not $loxWindowsBaseNode) { throw "Could not find base node for 'Loxone for Windows' in XML." }

                $loxWindowsUpdateNode = $null

                if ($AppChannelPreference -eq 'Latest') {
                    Write-Log -Message "[App] Finding latest version across all channels..." -Level DEBUG
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
                                $parsedVersion = Convert-VersionString $versionToConvert
                                Write-Log -Message "[App] Parsed version '$parsedVersion' from channel '$channelName' (Raw: '$rawVersion')." -Level DEBUG
                                if ([Version]$parsedVersion -gt $latestParsedVersion) {
                                    $latestParsedVersion = [Version]$parsedVersion
                                    $latestNode = $channelNode
                                    $result.SelectedAppChannelName = $channelName # Update selected channel name to the actual latest
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
                         Write-Log -Message "[App] Selected latest version from channel '$($result.SelectedAppChannelName)'." -Level INFO
                    } else {
                         Write-Log -Message "[App] Could not determine the latest version across channels." -Level WARN
                    }

                } else {
                    # Specific channel selected
                    $xpath = "/Miniserversoftware/update[@Name='Loxone for Windows']/$AppChannelPreference"
                    Write-Log -Message "[App] Selecting specific channel node using XPath: $xpath" -Level DEBUG
                    $loxWindowsUpdateNode = $updateXml.SelectSingleNode($xpath)
                }

                # --- Process the selected App node ---
                if ($loxWindowsUpdateNode) {
                    $result.AppLatestVersionRaw = $loxWindowsUpdateNode.Version
                    $result.AppInstallerUrl = $loxWindowsUpdateNode.Path
                    $expectedAppSize = 0L
                    if (-not ([long]::TryParse($loxWindowsUpdateNode.FileSize, [ref]$expectedAppSize))) { 
                        Write-Log -Message "[App] Could not parse FileSize ('$($loxWindowsUpdateNode.FileSize)') for Loxone for Windows (Channel: $($result.SelectedAppChannelName)). Size check might be inaccurate." -Level WARN
                        $expectedAppSize = 0L 
                    }
                    $result.AppExpectedSize = $expectedAppSize

                    if ($EnableCRC) {
                        $result.AppExpectedCRC = $loxWindowsUpdateNode.crc32
                        if ([string]::IsNullOrWhiteSpace($result.AppExpectedCRC)) { 
                            Write-Log -Message "[App] CRC check enabled, but CRC missing for Loxone for Windows (Channel: $($result.SelectedAppChannelName)) in XML." -Level WARN
                            $result.AppExpectedCRC = $null 
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($result.AppLatestVersionRaw) -or [string]::IsNullOrWhiteSpace($result.AppInstallerUrl)) {
                        Write-Log -Message "[App] Required attributes (Version, Path) missing for 'Loxone for Windows' (Channel: $($result.SelectedAppChannelName)) in XML. Cannot proceed with App update check." -Level WARN
                        # Reset App fields
                        $result.AppLatestVersionRaw = $null
                        $result.AppInstallerUrl = $null
                        $result.AppExpectedCRC = $null
                        $result.AppExpectedSize = 0L
                        $result.AppLatestVersion = $null
                    } else {
                        $versionToConvert = $null
                        Write-Log -Message "[App] Raw version string from XML (Channel: $($result.SelectedAppChannelName)): '$($result.AppLatestVersionRaw)'" -Level DEBUG
                        if ($result.AppLatestVersionRaw -match '\(([\d.]+)\)') {
                            $versionToConvert = $matches[1]
                            Write-Log -Message "[App] Extracted date-based version from XML (Channel: $($result.SelectedAppChannelName)): '$versionToConvert'" -Level DEBUG
                        } else {
                            Write-Log -Message "[App] Could not extract numerical version pattern from raw string '$($result.AppLatestVersionRaw)' (Channel: $($result.SelectedAppChannelName)). Cannot determine latest app version." -Level WARN
                            $result.AppLatestVersionRaw = $null
                            $result.AppLatestVersion = $null
                            $result.AppInstallerUrl = $null
                            $result.AppExpectedCRC = $null
                            $result.AppExpectedSize = 0L
                        }

                        if ($versionToConvert) {
                            try {
                                $result.AppLatestVersion = Convert-VersionString $versionToConvert
                                Write-Log -Message "[App] Converted numerical version (Channel: $($result.SelectedAppChannelName)): '$($result.AppLatestVersion)'" -Level DEBUG
                            } catch {
                                 Write-Log -Message "[App] Error converting extracted version '$versionToConvert' (Channel: $($result.SelectedAppChannelName)): $($_.Exception.Message). Cannot determine latest app version." -Level WARN
                                 $result.AppLatestVersionRaw = $null
                                 $result.AppLatestVersion = $null
                                 $result.AppInstallerUrl = $null
                                 $result.AppExpectedCRC = $null
                                 $result.AppExpectedSize = 0L
                            }
                        }

                        # Only log info if we successfully got a version
                        if ($result.AppLatestVersion) {
                            $appUpdateInfoMsg = "[App] Latest Loxone for Windows (Channel: $($result.SelectedAppChannelName)): Version=$($result.AppLatestVersionRaw) ($($result.AppLatestVersion)), Size=$($result.AppExpectedSize)B, URL=$($result.AppInstallerUrl)"
                            if ($result.AppExpectedCRC) { $appUpdateInfoMsg += ", Expected CRC=$($result.AppExpectedCRC)" }
                            Write-Log -Message $appUpdateInfoMsg -Level INFO
                        }
                    }
                } else {
                    Write-Log -Message "[App] Could not find 'Loxone for Windows' update information for channel '$($result.SelectedAppChannelName)' in the XML. Cannot perform App update check." -Level WARN
                }
            } catch {
                Write-Log -Message "[App] Error parsing XML for Loxone for Windows details (Channel: $($result.SelectedAppChannelName)): $($_.Exception.Message). Cannot perform App update check." -Level ERROR
                # Reset App fields on error
                $result.AppLatestVersionRaw = $null
                $result.AppInstallerUrl = $null
                $result.AppExpectedCRC = $null
                $result.AppExpectedSize = 0L
                $result.AppLatestVersion = $null
                if (-not $result.Error) { $result.Error = "Error parsing App XML details." } # Set general error if not already set
            }
        } else {
            Write-Log -Message "[App] Skipping Loxone for Windows update check as CheckAppUpdate parameter was false." -Level INFO
        }

    } catch {
        # Catch any unexpected errors during the whole process
        $result.Error = "Unexpected error in Get-LoxoneUpdateData: $($_.Exception.Message)"
        Write-Log -Message $result.Error -Level ERROR
    } finally {
        Write-Log -Level DEBUG -Message "Exiting function $($MyInvocation.MyCommand.Name)"
    }
    
    return $result
}

#endregion Active Functions

#region Deprecated Functions - Logic Moved to UpdateLoxone.ps1/WorkflowSteps

# NOTE: The following functions are kept for backward compatibility but their logic has been moved.
# They return empty results and should not be used in new code.

function Test-UpdateNeeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Test', 'Public')]
        [string]$Channel,
        [Parameter(Mandatory = $false)]
        [string]$InstalledVersion,
        [Parameter(Mandatory = $false)]
        [version]$InstalledAppVersion,
        [Parameter(Mandatory = $false)]
        [string]$InstalledExePath,
        [Parameter(Mandatory = $true)]
        [bool]$CheckLoxoneApp,
        [Parameter(Mandatory = $true)]
        [string]$ScriptRoot,
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )
    Write-Log -Message "[DEPRECATED] Test-UpdateNeeded - Logic moved to UpdateLoxone.ps1. Returning empty list." -Level WARN
    return [System.Collections.Generic.List[PSCustomObject]]::new()
}

function Test-LoxoneConfigComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ConfigData,
        [Parameter(Mandatory = $false)]
        [string]$InstalledVersion,
        [Parameter(Mandatory = $false)]
        [string]$DownloadDir,
        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )
    Write-Log -Message "[DEPRECATED] Test-LoxoneConfigComponent - Logic moved to Initialize-UpdatePipelineData. Returning null." -Level WARN
    return $null
}

function Test-LoxoneAppComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$AppData,
        [Parameter(Mandatory = $true)]
        [bool]$CheckEnabled,
        [Parameter(Mandatory = $false)]
        [version]$InstalledAppVersion,
        [Parameter(Mandatory = $false)]
        [string]$LoxoneExePath,
        [Parameter(Mandatory = $false)]
        [string]$DownloadDir,
        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )
    Write-Log -Message "[DEPRECATED] Test-LoxoneAppComponent - Logic moved to Initialize-UpdatePipelineData. Returning null." -Level WARN
    return $null
}

function Test-LoxoneMSComponents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$MSEntries,
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$MSData,
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )
    Write-Log -Message "[DEPRECATED] Test-LoxoneMSComponents - Logic moved to Initialize-UpdatePipelineData. Returning empty list." -Level WARN
    return [System.Collections.Generic.List[PSCustomObject]]::new()
}

function New-LoxoneComponentStatusObject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Config', 'App', 'MS')]
        [string]$ComponentType,
        [Parameter(Mandatory = $true)]
        [string]$Identifier,
        [Parameter(Mandatory = $false)]
        $InitialVersion,
        [Parameter(Mandatory = $false)]
        $LatestVersion,
        [Parameter(Mandatory = $true)]
        [bool]$UpdateNeeded,
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = $null,
        [Parameter(Mandatory = $false)]
        [string]$RawEntry = $null,
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$ConfigData = $null,
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$AppData = $null
    )
    Write-Log -Message "[DEPRECATED] New-LoxoneComponentStatusObject - Logic moved to Initialize-UpdatePipelineData. This function now returns objects for compatibility." -Level WARN
    # Original function creates object but was missing return statement
    # Fixed to return the object for backward compatibility
    $statusObject = [PSCustomObject]@{
        ComponentType   = $ComponentType
        Identifier      = $Identifier
        InitialVersion  = $InitialVersion
        LatestVersion   = $LatestVersion
        UpdateNeeded    = $UpdateNeeded
        ShouldRun       = ($Status -eq 'NotFound' -or $UpdateNeeded)
        Status          = $Status
        UpdateAttempted = $false
        UpdateSuccess   = $false
        FinalVersion    = $null
        ErrorMessage    = $ErrorMessage
        RawEntry        = $RawEntry
        ZipUrl          = if ($ComponentType -eq 'Config') { $ConfigData?.Path } else { $null }
        ExpectedCRC     = if ($ComponentType -eq 'Config') { $ConfigData?.CRC32 } else { $null }
        ExpectedSize    = if ($ComponentType -eq 'Config') { $ConfigData?.FileSize } else { $null }
    }
    # FIXED: Added missing return statement
    return $statusObject
}

# These helper functions are also deprecated but kept for compatibility
function Get-UpdateStatusFromComparison {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComparisonResult,
        [Parameter(Mandatory = $true)]
        [string]$ComponentLogPrefix,
        [Parameter(Mandatory = $false)]
        $InstalledVersionString,
        [Parameter(Mandatory = $false)]
        $TargetVersionString
    )
    Write-Log -Message "[DEPRECATED] Get-UpdateStatusFromComparison - Helper function no longer used." -Level DEBUG
    return [PSCustomObject]@{
        Status       = "Unknown"
        UpdateNeeded = $false
    }
}

function Invoke-MSCheckLogic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MSEntry,
        [Parameter(Mandatory = $false)]
        [string]$TargetVersionString,
        [Parameter(Mandatory = $false)]
        [string]$NormalizedLatestMSVersionString,
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )
    Write-Log -Message "[DEPRECATED] Invoke-MSCheckLogic - Helper function no longer used." -Level DEBUG
    return [PSCustomObject]@{
        Identifier     = "UnknownHost"
        InitialVersion = $null
        Status         = "Unknown"
        UpdateNeeded   = $false
        ErrorMessage   = "Function deprecated"
    }
}

#endregion Deprecated Functions

# Export only the active function and deprecated ones for backward compatibility
Export-ModuleMember -Function Get-LoxoneUpdateData, Test-UpdateNeeded, Test-LoxoneConfigComponent, Test-LoxoneAppComponent, Test-LoxoneMSComponents, New-LoxoneComponentStatusObject, Get-UpdateStatusFromComparison, Invoke-MSCheckLogic