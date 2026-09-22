# Mock suite for LoxoneUtils.Miniserver module
# This file contains all mocks needed to prevent real Miniserver operations during tests
# Note: Module must be imported BEFORE sourcing this file

# Create reusable mock implementations
$mockInvokeMiniserverWebRequest = {
    param($Parameters)
    
    # Check what type of request this is based on the URI
    if ($Parameters.Uri -match '/dev/cfg/version|/dev/cfg/api|/dev/cfg/updatelevel') {
        # Version/API request - return XML format expected by version check
        return @{
            StatusCode = 200
            Content = '<LL control="test" value="14.0.0.0" Code="200"/>'
            Headers = @{}
        }
    } elseif ($Parameters.Uri -match '/dev/sys/autoupdate') {
        # Update trigger request
        return @{
            StatusCode = 200
            Content = '<LL control="test" value="1" Code="200"/>'
            Headers = @{}
        }
    } else {
        # Other requests - return generic response
        return @{
            StatusCode = 200
            Content = '{"status":"ok"}'
            Headers = @{}
        }
    }
}

$mockGetMiniserverVersion = {
    param($MSEntry, [switch]$SkipCertificateCheck, $TimeoutSec)
    return [version]"14.0.0.0"
}

$mockInvokeMSUpdate = {
    param($MSUri, $NormalizedDesiredVersion, $Credential)
    return @{
        Succeeded = $true
        Message = "MOCK: Update triggered for $MSUri"
    }
}

$mockUpdateMS = {
    param($MiniserverEntry, $UpdateNeeded, $ErrorOccurred, $AnyUpdatePerformed)
    return @{
        UpdateSucceeded = $true
        CurrentVersion = [version]"14.0.0.0"
        UpdateTriggered = $UpdateNeeded
        Message = "MOCK: Miniserver update completed"
    }
}

$mockTestLoxoneMiniserverUpdateLevel = {
    param($URL, $Credential, $UpdateLevel)  # Changed ExpectedLevel to UpdateLevel and MSEntry to URL
    return $true  # Always at expected level
}

$mockInvokeWebRequest = {
    param($Uri, $Method, $Headers, $Credential, $TimeoutSec, $UseBasicParsing)
    
    # Return mock response based on URI
    if ($Uri -match '/dev/cfg/version') {
        return @{
            StatusCode = 200
            Content = '<LL control="test" value="14.0.0.0" Code="200"/>'
        }
    }
    
    return @{
        StatusCode = 200
        Content = '<LL control="test" value="1" Code="200"/>'
    }
}

$mockTestConnection = {
    param($ComputerName, $Count, $Quiet)
    return $true  # Always reachable
}

# Apply mocks both module-scoped and globally
Mock -ModuleName LoxoneUtils.Miniserver Invoke-MiniserverWebRequest $mockInvokeMiniserverWebRequest
Mock Invoke-MiniserverWebRequest $mockInvokeMiniserverWebRequest

Mock -ModuleName LoxoneUtils.Miniserver Get-MiniserverVersion $mockGetMiniserverVersion
Mock Get-MiniserverVersion $mockGetMiniserverVersion

Mock -ModuleName LoxoneUtils.Miniserver Invoke-MSUpdate $mockInvokeMSUpdate
Mock Invoke-MSUpdate $mockInvokeMSUpdate

Mock -ModuleName LoxoneUtils.Miniserver Update-MS $mockUpdateMS
Mock Update-MS $mockUpdateMS

Mock -ModuleName LoxoneUtils.Miniserver Test-LoxoneMiniserverUpdateLevel $mockTestLoxoneMiniserverUpdateLevel
Mock Test-LoxoneMiniserverUpdateLevel $mockTestLoxoneMiniserverUpdateLevel

Mock -ModuleName LoxoneUtils.Miniserver Invoke-WebRequest $mockInvokeWebRequest
Mock Invoke-WebRequest $mockInvokeWebRequest

Mock -ModuleName LoxoneUtils.Miniserver Test-Connection $mockTestConnection
Mock Test-Connection $mockTestConnection

# Note: Get-Credential is a cmdlet from Microsoft.PowerShell.Security module
# We can't mock it directly in LoxoneUtils.Miniserver module
# Instead, tests should create credentials directly or mock at a higher level

# Export a flag indicating mocks are loaded
$Global:MiniserverMocksLoaded = $true

# Suppress mock loading messages in parallel/CI mode to reduce noise
if (-not $env:CI -and -not $env:LOXONE_PARALLEL_MODE) {
    Write-Host "Miniserver module mocks loaded - no real Miniserver operations will occur" -ForegroundColor Green
}
