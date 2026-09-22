# Mock suite for LoxoneUtils.Logging module
# This file contains mocks for logging operations during tests
# Note: Module must be imported BEFORE sourcing this file

# Set up test log file location
$testLogDir = Join-Path $env:TEMP "LoxoneTestLogs"
if (-not (Test-Path $testLogDir)) {
    New-Item -ItemType Directory -Path $testLogDir -Force | Out-Null
}
$Global:LogFile = Join-Path $testLogDir "test-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Create the log file if it doesn't exist
if (-not (Test-Path $Global:LogFile)) {
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

# Create reusable mock implementations
$mockInvokeLogFileRotation = {
    param($LogFilePath)
    # Return the same log file path (no rotation)
    # This matches the expected behavior where the function returns the rotated file path
    # or $false if no rotation occurred
    return $false
}

$mockWriteLog = {
    param($Message, $Level = "INFO")
    # Optionally write to test log for debugging
    if ($Global:LogFile -and (Test-Path $Global:LogFile)) {
        Add-Content -Path $Global:LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    }
}

$mockEnterFunction = {
    param($FunctionName)
    # Do minimal logging in tests
}

$mockExitFunction = {
    param($FunctionName)
    # Do minimal logging in tests
}

# Apply mocks both module-scoped and globally
Mock -ModuleName LoxoneUtils.Logging Invoke-LogFileRotation $mockInvokeLogFileRotation
Mock Invoke-LogFileRotation $mockInvokeLogFileRotation

# Don't mock Write-Log by default as it's useful for test debugging
# But provide option to override if needed
if ($env:MOCK_WRITE_LOG -eq "1") {
    Mock -ModuleName LoxoneUtils.Logging Write-Log $mockWriteLog
    Mock Write-Log $mockWriteLog
}

Mock -ModuleName LoxoneUtils.Logging Enter-Function $mockEnterFunction
Mock Enter-Function $mockEnterFunction

Mock -ModuleName LoxoneUtils.Logging Exit-Function $mockExitFunction
Mock Exit-Function $mockExitFunction

# Optionally suppress console output during tests
if ($env:SUPPRESS_TEST_LOGS -eq "1") {
    $mockWriteHost = {
        param($Object, $ForegroundColor, $BackgroundColor, $NoNewline)
        # Suppress all console output
    }
    
    $mockWriteWarning = {
        param($Message)
        # Suppress warnings
    }
    
    $mockWriteError = {
        param($Message, $ErrorAction)
        # Suppress errors (but tests can still check for them)
    }
    
    Mock -ModuleName LoxoneUtils.Logging Write-Host $mockWriteHost
    Mock Write-Host $mockWriteHost
    
    Mock -ModuleName LoxoneUtils.Logging Write-Warning $mockWriteWarning
    Mock Write-Warning $mockWriteWarning
    
    Mock -ModuleName LoxoneUtils.Logging Write-Error $mockWriteError
    Mock Write-Error $mockWriteError
}

# Export a flag indicating mocks are loaded
$Global:LoggingMocksLoaded = $true

# Suppress mock loading messages in parallel/CI mode to reduce noise
if (-not $env:CI -and -not $env:LOXONE_PARALLEL_MODE) {
    Write-Host "Logging module mocks loaded - test logging configured at: $Global:LogFile" -ForegroundColor Green
}
