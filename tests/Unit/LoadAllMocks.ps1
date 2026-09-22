# Master mock loader script
# This file loads all mock suites for comprehensive test safety
# NOTE: This must be called from within a Pester test context (BeforeAll, Describe, etc.)

param(
    [switch]$Quiet
)

# Check if we're in a Pester context
if (-not $PSCmdlet.SessionState.PSVariable.GetValue('____Pester')) {
    Write-Warning "LoadAllMocks.ps1 should be called from within a Pester test context"
    # Don't load mocks outside of Pester
    return
}

$mockFiles = @(
    "LoxoneUtils.Installation.TestMocks.ps1",
    "LoxoneUtils.Network.TestMocks.ps1",
    "LoxoneUtils.Miniserver.TestMocks.ps1",
    "LoxoneUtils.Logging.TestMocks.ps1",
    "LoxoneUtils.ParallelWorkflow.TestMocks.ps1"  # This already exists
)

$testDir = Split-Path $PSCommandPath -Parent
$loadedCount = 0

foreach ($mockFile in $mockFiles) {
    $mockPath = Join-Path $testDir $mockFile
    if (Test-Path $mockPath) {
        if (-not $Quiet) {
            Write-Host "Loading mock suite: $mockFile" -ForegroundColor Cyan
        }
        . $mockPath
        $loadedCount++
    } else {
        if (-not $Quiet) {
            Write-Host "Mock file not found: $mockFile" -ForegroundColor Yellow
        }
    }
}

# Set global test flags
$env:PESTER_TEST_RUN = "1"
$env:LOXONE_TEST_MODE = "1"
$Global:IsTestRun = $true

if (-not $Quiet) {
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Loaded $loadedCount mock suites" -ForegroundColor Green
    Write-Host "Test environment configured" -ForegroundColor Green
    Write-Host "All dangerous operations are now mocked" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
}