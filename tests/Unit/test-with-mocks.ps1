# Quick test runner with mocks loaded
Write-Host "Loading all mock suites..." -ForegroundColor Cyan

# Load all mocks
. "$PSScriptRoot\LoadAllMocks.ps1" -Quiet

# Set test environment
$env:PESTER_TEST_RUN = "1"
$env:LOXONE_TEST_MODE = "1"
$Global:IsTestRun = $true

Write-Host "Running tests with mocks..." -ForegroundColor Yellow

# Run a specific test file to verify mocks work
$testFile = "$PSScriptRoot\LoxoneUtils.Network.Working.Tests.ps1"

if (Test-Path $testFile) {
    $result = Invoke-Pester -Path $testFile -PassThru -Output Detailed
    
    Write-Host "`nTest Results:" -ForegroundColor Cyan
    Write-Host "  Passed: $($result.PassedCount)" -ForegroundColor Green
    Write-Host "  Failed: $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -eq 0) { 'Green' } else { 'Red' })
    Write-Host "  Skipped: $($result.SkippedCount)" -ForegroundColor Gray
} else {
    Write-Host "Test file not found: $testFile" -ForegroundColor Red
}

Write-Host "`nMock verification complete" -ForegroundColor Green