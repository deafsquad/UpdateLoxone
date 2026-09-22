# Mock suite for LoxoneUtils.Installation module
# This file contains all mocks needed to prevent real installation operations during tests
# Note: Module must be imported BEFORE sourcing this file

# Create reusable mock implementations
$mockGetInstalledVersion = {
    param($ExePath)
    return "14.0.0.0"
}

$mockStartLoxoneUpdateInstaller = {
    param($InstallerPath, $InstallMode, $ScriptSaveFolder)
    return @{
        ExitCode = 0
        Success = $true
        Mock = $true
        Succeeded = $true  # Add alternative property name
    }
}

$mockStartLoxoneForWindowsInstaller = {
    param($InstallerPath, $InstallMode, $ScriptSaveFolder)
    return @{
        ExitCode = 0
        Success = $true
        Mock = $true
        TimedOut = $false
        Succeeded = $true  # Add alternative property name
    }
}

$mockGetInstalledApplicationPath = {
    param($AppName = "Loxone Config")
    if ($AppName -eq "Loxone Config") {
        return "C:\Program Files (x86)\Loxone\LoxoneConfig"
    } elseif ($AppName -eq "Loxone") {
        return "C:\Program Files (x86)\Loxone"
    }
    return $null
}

$mockGetLoxoneExePath = {
    param($AppName = "Loxone Config", $ExeName = "LoxoneConfig.exe")
    if ($AppName -eq "Loxone Config") {
        return "C:\Program Files (x86)\Loxone\LoxoneConfig\LoxoneConfig.exe"
    }
    return $null
}

$mockTestExistingInstaller = {
    param($InstallerPath, $TargetVersion, $ComponentName = "Installer")
    return @{
        IsValid        = $false
        Reason         = "Mock - no existing installer"
        SkipDownload   = $false
        SkipExtraction = $false
    }
}

$mockInvokeZipFileExtraction = {
    param($ZipPath, $DestinationPath)
    # Validate that zip file exists if specified
    if ($ZipPath -and -not (Test-Path $ZipPath)) {
        throw "Source ZIP file not found: '$ZipPath'"
    }
    # Create destination directory in test mode
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }
    return @{
        Succeeded = $true
        ExtractedPath = $DestinationPath
    }
}

$mockGetExecutableSignature = {
    param($ExePath)
    return @{
        Status = 'Valid'
        SignerCertificate = @{
            Subject = 'CN=Loxone Electronics GmbH'
        }
    }
}

$mockStopProcess = {
    param($Name, $Force)
    # Do nothing - don't kill real processes
}

$mockGetProcess = {
    param($Name, $ErrorAction)
    # Return nothing - no processes running
    return $null
}

# Apply mocks both module-scoped and globally
Mock -ModuleName LoxoneUtils.Installation Get-InstalledVersion $mockGetInstalledVersion
Mock Get-InstalledVersion $mockGetInstalledVersion

Mock -ModuleName LoxoneUtils.Installation Start-LoxoneUpdateInstaller $mockStartLoxoneUpdateInstaller
Mock Start-LoxoneUpdateInstaller $mockStartLoxoneUpdateInstaller

Mock -ModuleName LoxoneUtils.Installation Start-LoxoneForWindowsInstaller $mockStartLoxoneForWindowsInstaller
Mock Start-LoxoneForWindowsInstaller $mockStartLoxoneForWindowsInstaller

Mock -ModuleName LoxoneUtils.Installation Get-InstalledApplicationPath $mockGetInstalledApplicationPath
Mock Get-InstalledApplicationPath $mockGetInstalledApplicationPath

Mock -ModuleName LoxoneUtils.Installation Get-LoxoneExePath $mockGetLoxoneExePath
Mock Get-LoxoneExePath $mockGetLoxoneExePath

Mock -ModuleName LoxoneUtils.Installation Test-ExistingInstaller $mockTestExistingInstaller
Mock Test-ExistingInstaller $mockTestExistingInstaller

Mock -ModuleName LoxoneUtils.Installation Invoke-ZipFileExtraction $mockInvokeZipFileExtraction
Mock Invoke-ZipFileExtraction $mockInvokeZipFileExtraction

Mock -ModuleName LoxoneUtils.Installation Get-ExecutableSignature $mockGetExecutableSignature
Mock Get-ExecutableSignature $mockGetExecutableSignature

Mock -ModuleName LoxoneUtils.Installation Stop-Process $mockStopProcess
Mock Stop-Process $mockStopProcess

Mock -ModuleName LoxoneUtils.Installation Get-Process $mockGetProcess
Mock Get-Process $mockGetProcess

# Export a flag indicating mocks are loaded
$Global:InstallationMocksLoaded = $true

# Suppress mock loading messages in parallel/CI mode to reduce noise
if (-not $env:CI -and -not $env:LOXONE_PARALLEL_MODE) {
    Write-Host "Installation module mocks loaded - no real installations will occur" -ForegroundColor Green
}
