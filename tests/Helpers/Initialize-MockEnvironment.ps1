# Initialize-MockEnvironment.ps1
# Central mock loader for test infrastructure
# This replaces the BeforeAll pattern with direct mock loading

param(
    [Parameter()]
    [ValidateSet('All', 'Network', 'Installation', 'Miniserver', 'Logging', 'Toast')]
    [string[]]$Modules = @('All'),
    
    [Parameter()]
    [switch]$SuppressOutput
)

# Set test environment flags
$env:PESTER_TEST_RUN = '1'
$env:LOXONE_TEST_MODE = '1'
$Global:IsTestRun = $true

# Base paths
$testRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $testRoot
$moduleRoot = Join-Path $projectRoot "LoxoneUtils"

# Import the main module first
$modulePath = Join-Path $moduleRoot "LoxoneUtils.psd1"
if (-not (Get-Module LoxoneUtils)) {
    Import-Module $modulePath -Force -DisableNameChecking
    if (-not $SuppressOutput) {
        Write-Host "Imported LoxoneUtils module from: $modulePath" -ForegroundColor Cyan
    }
}

# Define available mock files
$mockFiles = @{
    'Network'      = Join-Path $testRoot "Unit\LoxoneUtils.Network.TestMocks.ps1"
    'Installation' = Join-Path $testRoot "Unit\LoxoneUtils.Installation.TestMocks.ps1"
    'Miniserver'   = Join-Path $testRoot "Unit\LoxoneUtils.Miniserver.TestMocks.ps1"
    'Logging'      = Join-Path $testRoot "Unit\LoxoneUtils.Logging.TestMocks.ps1"
    'Toast'        = Join-Path $testRoot "Unit\LoxoneUtils.Toast.TestMocks.ps1"
    'System'       = Join-Path $testRoot "Unit\LoxoneUtils.System.TestMocks.ps1"
}

# Add System to All modules list
if ($Modules -contains 'All') {
    # Ensure System is included when loading All
    $Modules = @('Network', 'Installation', 'Miniserver', 'Logging', 'Toast', 'System')
}

# Determine which mocks to load
$modulesToLoad = if ($Modules -contains 'All') {
    $mockFiles.Keys
} else {
    $Modules
}

# Load requested mock files
$loadedMocks = @()
foreach ($module in $modulesToLoad) {
    if ($mockFiles.ContainsKey($module)) {
        $mockFile = $mockFiles[$module]
        if (Test-Path $mockFile) {
            # Source the mock file directly (no BeforeAll)
            . $mockFile
            $loadedMocks += $module
            if (-not $SuppressOutput) {
                Write-Host "  Loaded $module mocks from: $mockFile" -ForegroundColor Green
            }
        } elseif (-not $SuppressOutput) {
            Write-Warning "Mock file not found for $module`: $mockFile"
        }
    }
}

# Set global flag indicating mock environment is initialized
$Global:MockEnvironmentInitialized = $true
$Global:LoadedMocks = $loadedMocks

if (-not $SuppressOutput) {
    Write-Host "`nMock environment initialized with modules: $($loadedMocks -join ', ')" -ForegroundColor Cyan
    Write-Host "Test flags set: PESTER_TEST_RUN=1, LOXONE_TEST_MODE=1, IsTestRun=true" -ForegroundColor DarkGray
}

# Return loaded mock information
return @{
    LoadedMocks = $loadedMocks
    ModulePath = $modulePath
    MockFiles = $mockFiles
    TestRoot = $testRoot
    ProjectRoot = $projectRoot
}