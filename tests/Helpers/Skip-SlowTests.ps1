# Helper to skip slow or problematic tests in CI/automated environments
param(
    [switch]$SkipRealTests,
    [switch]$SkipNetworkTests
)

# Set environment variable to skip real implementation tests
if ($SkipRealTests) {
    $env:SKIP_REAL_TESTS = "1"
    Write-Host "Skipping real implementation tests (SKIP_REAL_TESTS=1)" -ForegroundColor Yellow
}

# Set environment variable to skip network tests
if ($SkipNetworkTests) {
    $env:SKIP_NETWORK_TESTS = "1"
    Write-Host "Skipping network tests (SKIP_NETWORK_TESTS=1)" -ForegroundColor Yellow
}

# Also set a shorter default timeout for tests
$env:TEST_TIMEOUT_SEC = "1"
Write-Host "Set test timeout to 1 second (TEST_TIMEOUT_SEC=1)" -ForegroundColor Yellow