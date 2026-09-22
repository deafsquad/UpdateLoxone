# Mock suite for LoxoneUtils.Network module
# This file contains all mocks needed to prevent real network operations during tests
# Note: Module must be imported BEFORE sourcing this file

# Create the mock implementation as a script block to reuse
$mockInvokeLoxoneDownload = {
    param(
        $Url, $DestinationPath, $ActivityName, $ExpectedCRC32, $ExpectedFilesize, 
        $MaxRetries, $IsInteractive, $ErrorOccurred, $AnyUpdatePerformed,
        $StepNumber, $TotalSteps, $StepName, $DownloadNumber, $TotalDownloads, $ItemName
    )
    
    # Check if we should use a test ZIP file
    if ($env:LOXONE_TEST_ZIP_PATH -and (Test-Path $env:LOXONE_TEST_ZIP_PATH)) {
        Copy-Item -Path $env:LOXONE_TEST_ZIP_PATH -Destination $DestinationPath -Force
        $fileInfo = Get-Item $DestinationPath
        $fileSize = $fileInfo.Length
    } else {
        # Create a mock file
        "Mock download content for test" | Out-File $DestinationPath -Encoding UTF8
        $fileSize = 100
    }
    
    return @{
        Succeeded = $true
        Success = $true
        Filesize = $fileSize
        CalculatedCRC32 = if ($ExpectedCRC32) { $ExpectedCRC32 } else { "MOCKCRC32" }
        ActualFilesize = $fileSize
        LocalPath = $DestinationPath
        FilePath = $DestinationPath
    }
}

# Apply mock both module-scoped and globally
Mock -ModuleName LoxoneUtils.Network Invoke-LoxoneDownload $mockInvokeLoxoneDownload
Mock Invoke-LoxoneDownload $mockInvokeLoxoneDownload

# Create reusable mock for Wait-ForPingSuccess
$mockWaitForPingSuccess = {
    param($InputAddress, $TimeoutSeconds)
    return $true  # Always succeed
}

# Apply mock both module-scoped and globally
Mock -ModuleName LoxoneUtils.Network Wait-ForPingSuccess $mockWaitForPingSuccess
Mock Wait-ForPingSuccess $mockWaitForPingSuccess

# Create reusable mock for Wait-ForPingTimeout
$mockWaitForPingTimeout = {
    param($InputAddress, $TimeoutSeconds)
    return $false  # Simulate device went offline
}

# Apply mock both module-scoped and globally
Mock -ModuleName LoxoneUtils.Network Wait-ForPingTimeout $mockWaitForPingTimeout
Mock Wait-ForPingTimeout $mockWaitForPingTimeout

# Mock Test-Connection for network checks
$mockTestConnection = {
    param($ComputerName, $Count, $Quiet)
    return $true  # Always reachable
}

# Apply mock both module-scoped and globally
Mock -ModuleName LoxoneUtils.Network Test-Connection $mockTestConnection
Mock Test-Connection $mockTestConnection

# Mock web request operations that might be used internally
Mock -ModuleName LoxoneUtils.Network Invoke-WebRequest {
    param($Uri, $OutFile, $UseBasicParsing, $Headers, $Method, $TimeoutSec)
    
    if ($OutFile) {
        # Create a mock file at the output location
        "Mock web content" | Out-File $OutFile -Encoding UTF8
    }
    
    return @{
        StatusCode = 200
        StatusDescription = "OK"
        Content = "Mock web content"
        Headers = @{}
    }
}

# Mock .NET WebClient if used
Mock -ModuleName LoxoneUtils.Network New-Object {
    param($TypeName, $ArgumentList)
    
    if ($TypeName -eq "System.Net.WebClient") {
        $mockWebClient = New-Object PSObject
        Add-Member -InputObject $mockWebClient -MemberType ScriptMethod -Name "DownloadFile" -Value {
            param($url, $destination)
            "Mock download" | Out-File $destination -Encoding UTF8
        }
        Add-Member -InputObject $mockWebClient -MemberType ScriptMethod -Name "Dispose" -Value {}
        return $mockWebClient
    }
    
    # For other types, call the real New-Object
    return Microsoft.PowerShell.Utility\New-Object $TypeName $ArgumentList
}

# Mock progress reporting
Mock -ModuleName LoxoneUtils.Network Write-Progress {
    param($Activity, $Status, $PercentComplete, $Id, $ParentId)
    # Do nothing - no progress bars in tests
}


# Export a flag indicating mocks are loaded
$Global:NetworkMocksLoaded = $true

# Suppress mock loading messages in parallel/CI mode to reduce noise
if (-not $env:CI -and -not $env:LOXONE_PARALLEL_MODE) {
    Write-Host "Network module mocks loaded - no real downloads will occur" -ForegroundColor Green
}