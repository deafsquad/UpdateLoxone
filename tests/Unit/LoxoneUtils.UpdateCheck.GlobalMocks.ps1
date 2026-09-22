# Global mocks for UpdateCheck functions to prevent real network calls during tests

# Check if running in test mode
if (-not $env:PESTER_TEST_RUN) {
    $env:PESTER_TEST_RUN = "1"
}

# Mock Get-LoxoneUpdateData to prevent real network calls to update servers
function global:Get-LoxoneUpdateData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UpdateXmlUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$ConfigChannel,
        
        [Parameter()]
        [string]$AppChannelPreference = "Release",
        
        [Parameter()]
        [bool]$CheckAppUpdate = $true,
        
        [Parameter()]
        [switch]$DebugMode
    )
    
    Write-Verbose "[GLOBAL-MOCK] Get-LoxoneUpdateData called with URL: $UpdateXmlUrl"
    
    # Return mock update data
    return [PSCustomObject]@{
        ConfigLatestVersion     = "14.0.0.0"
        ConfigZipUrl            = "https://update.loxone.com/config/14.0.0.0/LoxoneConfig.zip"
        ConfigExpectedZipSize   = 100000000
        ConfigExpectedCRC       = "ABCD1234"
        AppLatestVersionRaw     = "14.0.0.0"
        AppLatestVersion        = [version]"14.0.0.0"
        AppInstallerUrl         = "https://update.loxone.com/app/14.0.0.0/LoxoneApp.msi"
        AppExpectedCRC          = "EFGH5678"
        AppExpectedSize         = 50000000
        SelectedAppChannelName  = $AppChannelPreference
        Error                   = $null
    }
}

# Mock Get-LoxoneUpdatePrerequisites to prevent network calls
function global:Get-LoxoneUpdatePrerequisites {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]$WorkflowContext
    )
    
    Write-Verbose "[GLOBAL-MOCK] Get-LoxoneUpdatePrerequisites called"
    
    # Return mock prerequisites
    return [PSCustomObject]@{
        Succeeded = $true
        Component = "Prerequisites"
        Error = $null
        LatestConfigVersionNormalized = "14.0.0.0"
        ConfigUpdateNeeded = $false
        ConfigZipUrl = "https://update.loxone.com/config/14.0.0.0/LoxoneConfig.zip"
        ConfigExpectedZipSize = 100000000
        ConfigExpectedCRC = "ABCD1234"
        ConfigZipFileName = "LoxoneConfig_14.0.0.0.zip"
        ConfigInstallerFileName = "LoxoneConfig.msi"
        AppUpdateNeeded = $false
        LatestAppVersion = "14.0.0.0"
        AppInstallerUrl = "https://update.loxone.com/app/14.0.0.0/LoxoneApp.msi"
        AppExpectedSize = 50000000
        AppExpectedCRC = "EFGH5678"
        AppInstallerFileName = "LoxoneApp_14.0.0.0.msi"
        SelectedAppChannelName = "Release"
    }
}

Write-Host "Global UpdateCheck mocks loaded - no real update server calls will be made" -ForegroundColor Green
$Global:UpdateCheckMocksLoaded = $true