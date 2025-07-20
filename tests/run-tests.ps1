<#
.SYNOPSIS
    Comprehensive test runner for UpdateLoxone project - THE ONLY TEST RUNNER YOU NEED
    
.DESCRIPTION
    This script provides a single entry point for running all tests with various options:
    - Unit tests (fast, no external dependencies)
    - Integration tests (network/external dependencies) 
    - SYSTEM tests (requires admin privileges)
    - Debug mode with detailed output
    - CI mode for automated pipelines
    - Comprehensive logging with rotation
    - Parallel execution support
    - JSON/XML result export
    - Test file cleanup utilities
    
.PARAMETER TestType
    Type of tests to run (default: Unit):
    • Unit: Fast tests, no external dependencies, mocked network calls (~2-3 min)
    • Integration: Tests requiring network/external resources (~5-10 min) 
    • System: Tests requiring admin privileges for SYSTEM context (~1 min)
    • All: Run Unit + Integration + System tests (~8-15 min)
    
.PARAMETER SkipSystemTests
    Skip SYSTEM tests even when running as admin (overrides TestType=All)
    
.PARAMETER IncludeIntegration  
    Include integration tests when TestType=Unit (backward compatibility)
    
.PARAMETER Detailed
    Enable detailed output showing:
    • Individual test progress and timing
    • Test discovery information
    • Comprehensive failure details
    • File-by-file execution status
    
.PARAMETER DebugMode
    Enable debug mode with maximum verbosity (implies Detailed)
    
.PARAMETER CI
    Run in CI mode with minimal output and no prompts
    
.PARAMETER LiveProgress
    Show live test progress with Windows toast notifications. When enabled:
    • Creates real-time toast notifications showing test progress
    • Updates a single toast with pass/fail counts and progress bar
    • Logs all output to TestResults\TestRun_TIMESTAMP\live-progress-full.log
    • Best for interactive monitoring of long test runs
    
.PARAMETER LogToFile
    Enable detailed logging to file (default: true). Always creates a full transcript
    of all test output in TestResults\TestRun_TIMESTAMP\test-run-full.log
    
.PARAMETER MaxLogFiles
    Maximum number of log files to keep (default: 10)
    
.PARAMETER Timeout
    Timeout in seconds for each test file (default: 120)
    
.PARAMETER Filter
    Filter tests by name pattern (e.g., "Logging" or "*.Network.*")
    
.PARAMETER OutputFormat
    Output format for results: Console, JSON, XML, All (default: Console)
    
.PARAMETER Tag
    Filter tests by Pester tags (e.g., "Unit", "Integration")
    
.PARAMETER ExcludeTag
    Exclude tests with specific Pester tags
    
.PARAMETER Coverage
    Generate comprehensive test coverage reports after test execution
    
.PARAMETER CleanupTestFiles
    Clean up old test result files and logs
    
.PARAMETER CleanupOnly
    Only perform cleanup, don't run tests
    
.PARAMETER WhatIf
    Show what would be cleaned up without actually deleting
    
.EXAMPLE
    .\run-tests.ps1
    Run unit tests only (default, fast)
    
.EXAMPLE
    .\run-tests.ps1 -TestType All
    Run all tests (unit, integration, system if admin)
    
.EXAMPLE
    .\run-tests.ps1 -TestType Integration -Detailed
    Run only integration tests with detailed output
    
.EXAMPLE
    .\run-tests.ps1 -IncludeIntegration
    Run unit + integration tests (backward compatibility)
    
.EXAMPLE
    .\run-tests.ps1 -DebugMode -Filter "Miniserver"
    Debug Miniserver tests only
    
.EXAMPLE
    .\run-tests.ps1 -CI -OutputFormat All
    CI mode with all output formats
    
.EXAMPLE
    .\run-tests.ps1 -CleanupTestFiles
    Run tests and clean up old result files
    
.EXAMPLE
    .\run-tests.ps1 -CleanupOnly -WhatIf
    Show what test files would be cleaned up
    
.EXAMPLE
    .\run-tests.ps1 -Coverage
    Run unit tests and generate coverage reports
    
.EXAMPLE
    .\run-tests.ps1 -LiveProgress
    Run unit tests with live progress toast notifications
    
.EXAMPLE
    .\run-tests.ps1 -TestType All -Coverage -LiveProgress
    Run all tests with coverage analysis and live progress notifications
#>
[CmdletBinding(DefaultParameterSetName = "RunTests")]
param(
    # Test execution parameters
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [ValidateSet('All', 'Unit', 'Integration', 'System')]
    [string]$TestType = 'Unit',
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$SkipSystemTests,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$IncludeIntegration,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$Detailed,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$DebugMode,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$CI,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$LiveProgress,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$LogToFile = $true,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [int]$MaxLogFiles = 10,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [int]$Timeout = 120,
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [string]$Filter = "",
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [ValidateSet('Console', 'JSON', 'XML', 'All')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [string[]]$Tag = @(),
    
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [string[]]$ExcludeTag = @(),
    
    # Coverage parameters
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$Coverage,
    
    # Error output suppression
    [Parameter(ParameterSetName = "RunTests")]
    [Parameter(ParameterSetName = "RunAndCleanup")]
    [switch]$SuppressErrorOutput,
    
    # Cleanup parameters
    [Parameter(ParameterSetName = "RunAndCleanup", Mandatory)]
    [switch]$CleanupTestFiles,
    
    [Parameter(ParameterSetName = "CleanupOnly", Mandatory)]
    [switch]$CleanupOnly,
    
    [Parameter(ParameterSetName = "CleanupOnly")]
    [switch]$WhatIf,
    
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$UnrecognizedArgs
)

$ErrorActionPreference = 'Stop'

# Ensure array parameters are properly initialized to avoid Count property errors
if ($null -eq $Tag) { $Tag = @() }
if ($null -eq $ExcludeTag) { $ExcludeTag = @() }

# Validate parameter combinations
if ($PSCmdlet.ParameterSetName -eq "CleanupOnly" -and (-not $CleanupOnly)) {
    throw "When using -WhatIf, you must also specify -CleanupOnly"
}

if ($DebugMode -and $CI) {
    throw "Cannot use -DebugMode and -CI together (conflicting verbosity levels)"
}

# Logging function - defined early for cleanup usage
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = 'White'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output (unless CI mode and not error/coverage/summary)
    if (-not $CI -or $Level -eq "ERROR" -or $Level -eq "COVERAGE" -or $Level -eq "SUMMARY") {
        Write-Host $Message -ForegroundColor $Color
    }
    
    # File output
    if ($LogToFile -and $script:LogFile) {
        $logMessage | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }
}

# Handle backward compatibility and parameter combinations
if ($IncludeIntegration -and $TestType -eq 'Unit') {
    # User wants Unit + Integration
    $TestType = 'All'
    $SkipSystemTests = $true
}

if ($DebugMode) {
    $Detailed = $true
    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'
}

# Check for unrecognized parameters
if ($UnrecognizedArgs) {
    Write-Host "ERROR: Unrecognized parameters: $($UnrecognizedArgs -join ', ')" -ForegroundColor Red
    
    # Check for common mistakes
    if ($UnrecognizedArgs -contains "-IncludeSystemTests") {
        Write-Host ""
        Write-Host "NOTE: -IncludeSystemTests has been replaced with -SkipSystemTests" -ForegroundColor Yellow
        Write-Host "      SYSTEM tests now run by DEFAULT when admin privileges are available" -ForegroundColor Yellow
        Write-Host "      Use -SkipSystemTests to exclude them" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Valid parameters:" -ForegroundColor Cyan
    Write-Host "  -TestType <type>    : All, Unit, Integration, System (default: Unit)"
    Write-Host "  -SkipSystemTests    : Skip SYSTEM tests even with TestType=All"
    Write-Host "  -IncludeIntegration : Include integration tests with unit tests"
    Write-Host "  -Detailed           : Enable detailed output"
    Write-Host "  -DebugMode          : Maximum verbosity for troubleshooting"
    Write-Host "  -CI                 : CI mode (minimal output, no prompts)"
    Write-Host "  -Filter <string>    : Filter by test name pattern"
    Write-Host "  -Tag <string[]>     : Filter by Pester tags"
    Write-Host "  -ExcludeTag <array> : Exclude specific tags"
    Write-Host "  -OutputFormat       : Console, JSON, XML, All"
    Write-Host "  -LogToFile          : Enable file logging (default: true)"
    Write-Host "  -MaxLogFiles <int>  : Max log files to keep (default: 10)"
    Write-Host "  -Timeout <int>      : Timeout per test in seconds (default: 120)"
    Write-Host "  -CleanupTestFiles   : Clean up old test results after run"
    Write-Host "  -CleanupOnly        : Only cleanup, don't run tests"
    Write-Host "  -WhatIf             : Show what would be cleaned up"
    Write-Host ""
    Write-Host "Common usage:" -ForegroundColor Gray  
    Write-Host "  .\run-tests.ps1                           # Quick unit tests only"
    Write-Host "  .\run-tests.ps1 -TestType All             # Everything"
    Write-Host "  .\run-tests.ps1 -IncludeIntegration       # Unit + Integration"
    Write-Host "  .\run-tests.ps1 -DebugMode -Filter 'Network'  # Debug specific tests"
    Write-Host "  .\run-tests.ps1 -CI -OutputFormat All     # CI pipeline"
    exit 1
}

# Script configuration
$script:TestsPath = $PSScriptRoot
$script:StartTime = Get-Date
$script:TestRunId = $script:StartTime.ToString('yyyyMMdd-HHmmss')
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Initialize logging variables early to prevent errors
if ($LogToFile) {
    # Ensure log directory exists
    $script:LogPath = Join-Path ([System.IO.Path]::GetTempPath()) "UpdateLoxoneTests" 
    if (-not (Test-Path $script:LogPath)) {
        New-Item -ItemType Directory -Path $script:LogPath -Force | Out-Null
    }
    
    # Initialize log file path early
    $script:LogFile = Join-Path $script:LogPath "test-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    
    # Also set Global:LogFile for modules that expect it (like LoxoneUtils.Toast)
    $Global:LogFile = $script:LogFile
}

# Pre-load ScheduledTasks mocks if running in PowerShell 7 to avoid timeout issues
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $mockPath = Join-Path $script:TestsPath "Helpers" | Join-Path -ChildPath "Mock-ScheduledTasks.ps1"
    if (Test-Path $mockPath) {
        Write-Host "Pre-loading ScheduledTasks mocks for PowerShell 7 compatibility..." -ForegroundColor DarkGray
        . $mockPath
    }
}

# Consolidate all results into a single results directory with timestamp
$script:ResultsBasePath = Join-Path $script:TestsPath "TestResults"
$script:CurrentRunPath = Join-Path $script:ResultsBasePath "TestRun_$($script:TestRunId)"

# Create timestamped directory for this run
if (-not (Test-Path $script:CurrentRunPath)) {
    New-Item -ItemType Directory -Path $script:CurrentRunPath -Force | Out-Null
}

# LastRun functionality removed - coverage reports now have self-descriptive filenames

# Log file configuration
$script:LogPath = $script:CurrentRunPath
$script:ResultsPath = $script:CurrentRunPath

# Create timestamped temp directory for this test run
$script:TempPath = Join-Path $script:TestsPath "temp\TestRun_$($script:TestRunId)"
if (-not (Test-Path $script:TempPath)) {
    New-Item -ItemType Directory -Path $script:TempPath -Force | Out-Null
}

# Set environment variable for tests to use
$env:UPDATELOXONE_TEST_TEMP = $script:TempPath

# Determine which test categories to run
$script:RunUnit = $TestType -in @('All', 'Unit')
$script:RunIntegration = $TestType -in @('All', 'Integration') -or $IncludeIntegration
$script:RunSystem = $TestType -in @('All', 'System') -and $script:IsAdmin -and -not $SkipSystemTests

# Track why System tests might not run
$script:SystemTestSkipReason = ""
if ($TestType -in @('All', 'System')) {
    if (-not $script:IsAdmin) {
        $script:SystemTestSkipReason = "Not running as admin"
    } elseif ($SkipSystemTests) {
        $script:SystemTestSkipReason = "SkipSystemTests parameter specified"
    } elseif (-not $script:RunSystem) {
        $script:SystemTestSkipReason = "Unknown reason (RunSystem=$($script:RunSystem))"
    }
}

# Initialize logging early if needed (check both script and global)
if ($LogToFile -and -not $script:LogFile -and -not $Global:LogFile) {
    # Ensure log directory exists
    if (-not (Test-Path $script:LogPath)) {
        New-Item -ItemType Directory -Path $script:LogPath -Force | Out-Null
    }
    
    # Initialize log file path early
    $script:LogFile = Join-Path $script:LogPath "test-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    $Global:LogFile = $script:LogFile
}

# Log admin status and test determination
Write-TestLog "Admin check: IsAdmin=$($script:IsAdmin), Current User=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Color Cyan
Write-TestLog "Test type determination: TestType=$TestType, SkipSystemTests=$SkipSystemTests" -Color Cyan
Write-TestLog "Tests to run: Unit=$($script:RunUnit), Integration=$($script:RunIntegration), System=$($script:RunSystem)" -Color Cyan

# Debug output for System test determination
if ($TestType -in @('All', 'System')) {
    if (-not $script:IsAdmin) {
        Write-TestLog "System tests requested but admin privileges not available" -Level "WARN" -Color Yellow
    } elseif ($SkipSystemTests) {
        Write-TestLog "System tests requested but SkipSystemTests flag is set" -Level "WARN" -Color Yellow
    }
}

# Set script-level variables for function access
$script:LiveProgress = $LiveProgress
$script:CI = $CI
$script:Detailed = $Detailed
$script:DebugMode = $DebugMode

# Set environment variables for coverage report context
$env:UPDATELOXONE_TEST_TYPE = $TestType
$env:UPDATELOXONE_IS_ADMIN = $script:IsAdmin.ToString()
$env:UPDATELOXONE_SKIP_SYSTEM = $SkipSystemTests.ToString()
$env:UPDATELOXONE_CI_MODE = if ($CI) { "true" } else { "false" }
$env:UPDATELOXONE_RUN_CATEGORIES = @(
    if ($script:RunUnit) { "Unit" }
    if ($script:RunIntegration) { "Integration" }
    if ($script:RunSystem) { "System" }
) -join ","

# Ensure paths exist
if ($LogToFile -and -not (Test-Path $script:LogPath)) {
    New-Item -ItemType Directory -Path $script:LogPath -Force | Out-Null
}

# Function to implement log rotation for TestResults
function Invoke-TestResultRotation {
    param(
        [int]$DaysToKeep = 7,
        [int]$MaxTestRuns = 20,
        [switch]$WhatIf,
        [switch]$Quiet
    )
    
    $rotationStartTime = Get-Date
    $resultsPath = Join-Path $PSScriptRoot "TestResults"
    
    if (-not $Quiet) {
        Write-TestLog "Starting test result rotation..." -Color Cyan
        Write-TestLog "  Retention: $DaysToKeep days or $MaxTestRuns most recent runs" -Color Gray
    }
    
    # Get all TestRun directories
    $testRuns = @(Get-ChildItem -Path $resultsPath -Filter "TestRun_*" -Directory -ErrorAction SilentlyContinue | 
                Sort-Object CreationTime -Descending)
    
    $totalRuns = if ($testRuns) { $testRuns.Count } else { 0 }
    $runsToDelete = @()
    $bytesToFree = 0
    
    # Keep the most recent N runs regardless of age
    if ($totalRuns -gt $MaxTestRuns) {
        $runsToDelete += $testRuns | Select-Object -Skip $MaxTestRuns
    }
    
    # Also delete runs older than retention period
    $cutoffDate = (Get-Date).AddDays(-$DaysToKeep)
    $oldRuns = $testRuns | Where-Object { $_.CreationTime -lt $cutoffDate }
    
    # Combine and deduplicate safely
    if ($oldRuns) {
        $combinedList = [System.Collections.ArrayList]::new()
        $runsToDelete | ForEach-Object { [void]$combinedList.Add($_) }
        @($oldRuns) | ForEach-Object { [void]$combinedList.Add($_) }
        $runsToDelete = $combinedList.ToArray() | Select-Object -Unique
    }
    
    if ($runsToDelete -and $runsToDelete.Count -gt 0) {
        foreach ($run in $runsToDelete) {
            $size = (Get-ChildItem -Path $run.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum).Sum
            $bytesToFree += $size
            
            if (-not $Quiet) {
                $ageInDays = [math]::Round(((Get-Date) - $run.CreationTime).TotalDays, 1)
                Write-TestLog "  $(if ($WhatIf) {'Would delete'} else {'Deleting'}): $($run.Name) (Age: $ageInDays days, Size: $([math]::Round($size/1MB, 2)) MB)" -Color DarkGray
            }
            
            if (-not $WhatIf) {
                Remove-Item -Path $run.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Clean up old coverage reports (keep only last 10)
    $coverageDir = Join-Path $resultsPath "coverage"
    if (Test-Path $coverageDir) {
        $coverageFiles = @(Get-ChildItem -Path $coverageDir -Filter "coverage_*.md" -File -ErrorAction SilentlyContinue |
                        Sort-Object CreationTime -Descending)
        
        if ($coverageFiles -and $coverageFiles.Count -gt 10) {
            $coverageToDelete = $coverageFiles | Select-Object -Skip 10
            foreach ($file in $coverageToDelete) {
                $bytesToFree += $file.Length
                if (-not $Quiet) {
                    Write-TestLog "  $(if ($WhatIf) {'Would delete'} else {'Deleting'}) coverage: $($file.Name)" -Color DarkGray
                }
                if (-not $WhatIf) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    
    # Clean up old TestRun folders in temp directory
    $tempPath = Join-Path $PSScriptRoot "temp"
    if (Test-Path $tempPath) {
        $tempTestRuns = @(Get-ChildItem -Path $tempPath -Filter "TestRun_*" -Directory -ErrorAction SilentlyContinue | 
                        Sort-Object CreationTime -Descending)
        
        $tempRunsToDelete = @()
        
        # Apply same retention rules to temp folders
        if ($tempTestRuns -and $tempTestRuns.Count -gt $MaxTestRuns) {
            $tempRunsToDelete += $tempTestRuns | Select-Object -Skip $MaxTestRuns
        }
        
        $tempOldRuns = $tempTestRuns | Where-Object { $_.CreationTime -lt $cutoffDate }
        if ($tempOldRuns) {
            # Combine arrays safely using ArrayList
            $combinedList = [System.Collections.ArrayList]::new()
            $tempRunsToDelete | ForEach-Object { [void]$combinedList.Add($_) }
            @($tempOldRuns) | ForEach-Object { [void]$combinedList.Add($_) }
            $tempRunsToDelete = $combinedList.ToArray() | Select-Object -Unique
        }
        
        if ($tempRunsToDelete -and $tempRunsToDelete.Count -gt 0) {
            if (-not $Quiet) {
                Write-TestLog "`n  Cleaning temp TestRun folders..." -Color Cyan
            }
            
            foreach ($run in $tempRunsToDelete) {
                $size = (Get-ChildItem -Path $run.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum).Sum
                $bytesToFree += $size
                
                if (-not $Quiet) {
                    $ageInDays = [math]::Round(((Get-Date) - $run.CreationTime).TotalDays, 1)
                    Write-TestLog "  $(if ($WhatIf) {'Would delete'} else {'Deleting'}) temp: $($run.Name) (Age: $ageInDays days, Size: $([math]::Round($size/1MB, 2)) MB)" -Color DarkGray
                }
                
                if (-not $WhatIf) {
                    Remove-Item -Path $run.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            
            $runsToDelete += $tempRunsToDelete
        }
        
    }
    
    $duration = (Get-Date) - $rotationStartTime
    
    return @{
        RunsDeleted = if ($runsToDelete) { $runsToDelete.Count } else { 0 }
        TotalRuns = $totalRuns
        BytesFreed = $bytesToFree
        Duration = $duration
    }
}

# Function to clean up test files
function Invoke-TestFileCleanup {
    param(
        [switch]$WhatIf,
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-TestLog "`n=== Test File Cleanup ===" -Color Cyan
    }
    
    $cleanupItems = @{
        "Legacy XML Results (root)" = @{
            Path = $script:TestsPath
            Pattern = @("*-results.xml", "test-results-*.xml")
            KeepDays = 0  # Delete immediately - these are now in TestResults
        }
        "Legacy JSON Results (root)" = @{
            Path = $script:TestsPath
            Pattern = @("test-results-*.json", "*-TestResults.json")
            KeepDays = 0  # Delete immediately - these are now in TestResults
        }
        "Old Test Run Folders" = @{
            Path = $script:ResultsBasePath
            Pattern = "TestRun_*"
            KeepDays = 7  # Keep test results for a week
        }
        "Legacy Archive Folder" = @{
            Path = Join-Path $script:ResultsBasePath "Archive"
            Pattern = "*"
            KeepDays = 0  # Delete all - no longer used
        }
        "Legacy test-logs Directory" = @{
            Path = Join-Path $script:TestsPath "test-logs"
            Pattern = "*"
            KeepDays = 0  # Delete all - deprecated directory
        }
        "Legacy test-execution-logs Directory" = @{
            Path = Join-Path $script:TestsPath "test-execution-logs"
            Pattern = "*"
            KeepDays = 0  # Delete all - deprecated directory
        }
        "Legacy logs Directory" = @{
            Path = Join-Path $script:TestsPath "logs"
            Pattern = "*"
            KeepDays = 0  # Delete all - deprecated directory
        }
        "Old Diagnostic Files" = @{
            Path = $script:TestsPath
            Pattern = @("diagnose-*.ps1", "test-*-direct.ps1", "smoke-test.ps1")
            KeepDays = 0  # Delete immediately
        }
    }
    
    $totalDeleted = 0
    $totalSize = 0
    
    foreach ($category in $cleanupItems.Keys) {
        $item = $cleanupItems[$category]
        
        if (-not (Test-Path $item.Path)) {
            continue
        }
        
        $cutoffDate = (Get-Date).AddDays(-$item.KeepDays)
        
        foreach ($pattern in @($item.Pattern)) {
            $files = Get-ChildItem -Path $item.Path -Filter $pattern -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.LastWriteTime -lt $cutoffDate }
            
            if ($files -and $files.Count -gt 0) {
                if (-not $Quiet) {
                    Write-TestLog "`n$category ($pattern):" -Color Yellow
                }
                
                foreach ($file in $files) {
                    $size = $file.Length
                    
                    if ($WhatIf) {
                        Write-TestLog "  Would delete: $($file.Name) ($([math]::Round($size/1KB, 2)) KB)" -Color Gray
                    } else {
                        try {
                            Remove-Item $file.FullName -Force
                            if (-not $Quiet) {
                                Write-TestLog "  Deleted: $($file.Name) ($([math]::Round($size/1KB, 2)) KB)" -Color DarkGray
                            }
                            $totalDeleted++
                            $totalSize += $size
                        } catch {
                            Write-TestLog "  Failed to delete: $($file.Name) - $_" -Level "WARN" -Color Red
                        }
                    }
                }
            }
        }
    }
    
    # Clean empty directories in temp
    if (-not $WhatIf) {
        $tempPath = Join-Path $script:TestsPath "temp"
        if (Test-Path $tempPath) {
            Get-ChildItem -Path $tempPath -Directory -Recurse |
                Sort-Object -Property FullName -Descending |
                Where-Object { (Get-ChildItem $_.FullName -Force).Count -eq 0 } |
                ForEach-Object {
                    try {
                        Remove-Item $_.FullName -Force
                        if (-not $Quiet) {
                            Write-TestLog "  Removed empty directory: $($_.Name)" -Color DarkGray
                        }
                    } catch {
                        # Ignore errors
                    }
                }
        }
        
        # Remove deprecated log directories if empty
        $deprecatedDirs = @("test-logs", "test-execution-logs", "logs")
        foreach ($dir in $deprecatedDirs) {
            $dirPath = Join-Path $script:TestsPath $dir
            if (Test-Path $dirPath) {
                $items = Get-ChildItem $dirPath -Force
                if ($items.Count -eq 0) {
                    try {
                        Remove-Item $dirPath -Force
                        if (-not $Quiet) {
                            Write-TestLog "  Removed empty legacy directory: $dir" -Color DarkGray
                        }
                    } catch {
                        # Ignore errors
                    }
                }
            }
        }
    }
    
    if (-not $Quiet) {
        Write-TestLog "`nCleanup Summary:" -Color Cyan
        if ($WhatIf) {
            Write-TestLog "  WhatIf mode - no files were deleted" -Color Yellow
        } else {
            Write-TestLog "  Files deleted: $totalDeleted" -Color Green
            Write-TestLog "  Space freed: $([math]::Round($totalSize/1MB, 2)) MB" -Color Green
        }
    }
    
    return @{
        FilesDeleted = $totalDeleted
        SpaceFreed = $totalSize
    }
}

# If CleanupOnly is specified, just do cleanup and exit
if ($CleanupOnly) {
    # Initialize logging for cleanup
    if ($LogToFile) {
        $script:LogFile = Join-Path $script:LogPath "cleanup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    }
    
    Write-TestLog "Running test file cleanup..." -Color Cyan
    $cleanupResult = Invoke-TestFileCleanup -WhatIf:$WhatIf
    
    Write-TestLog "`nCleanup completed." -Color Green
    
    # Stop transcript if it was started
    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
        } catch {
            # Ignore errors when stopping transcript
        }
    }
    
    exit 0
}

# Log rotation function
function Invoke-LogRotation {
    param([string]$LogDirectory, [int]$MaxFiles)
    
    if (-not (Test-Path $LogDirectory)) { return }
    
    $logFiles = Get-ChildItem -Path $LogDirectory -Filter "test-run-*.log" | 
                Sort-Object -Property LastWriteTime -Descending
    
    if ($logFiles.Count -gt $MaxFiles) {
        $filesToDelete = $logFiles | Select-Object -Skip $MaxFiles
        foreach ($file in $filesToDelete) {
            Remove-Item $file.FullName -Force
            if (-not $CI) {
                Write-Host "Removed old log file: $($file.Name)" -ForegroundColor Gray
            }
        }
    }
}

# Write-TestLog function moved earlier for cleanup usage

# Function to shorten error messages for display
function Get-ShortErrorReason {
    param([string]$ErrorMessage)
    
    if ([string]::IsNullOrWhiteSpace($ErrorMessage)) {
        return ""
    }
    
    # Common error patterns and their short forms
    $patterns = @(
        @{ Pattern = 'The term ''([^'']+)'' is not recognized'; Short = 'Command not found: $1' }
        @{ Pattern = 'Could not find Command ([^\s]+)'; Short = 'Missing: $1' }
        @{ Pattern = 'CommandNotFoundException: (.+)'; Short = 'Not found: $1' }
        @{ Pattern = 'Expected (.+), but got (.+)'; Short = 'Expected $1, got $2' }
        @{ Pattern = 'Cannot find path ''([^'']+)'''; Short = 'Path not found' }
        @{ Pattern = 'The operation has timed out'; Short = 'Timeout' }
        @{ Pattern = 'Access to the path .+ is denied'; Short = 'Access denied' }
        @{ Pattern = 'Could not load file or assembly'; Short = 'Assembly load error' }
        @{ Pattern = 'Unable to find type \[([^\]]+)\]'; Short = 'Type not found: $1' }
        @{ Pattern = 'Cannot bind argument to parameter ''([^'']+)'''; Short = 'Invalid param: $1' }
        @{ Pattern = 'Cannot process command because of one or more missing mandatory parameters: (.+)'; Short = 'Missing param: $1' }
        @{ Pattern = 'Object reference not set to an instance'; Short = 'Null reference' }
        @{ Pattern = 'Index was outside the bounds'; Short = 'Index out of bounds' }
    )
    
    # Try each pattern
    foreach ($p in $patterns) {
        if ($ErrorMessage -match $p.Pattern) {
            $short = $p.Short
            # Replace capture groups
            for ($i = 1; $i -le $matches.Count - 1; $i++) {
                $short = $short -replace "\`$$i", $matches[$i]
            }
            return " → $short"
        }
    }
    
    # Generic shortening if no pattern matched
    $firstLine = ($ErrorMessage -split "`n")[0].Trim()
    if ($firstLine.Length -gt 40) {
        return " → " + $firstLine.Substring(0, 37) + "..."
    }
    return " → $firstLine"
}

# Function to parse XML test results and extract failed test details
function Get-FailedTestsFromXml {
    param([string]$XmlPath)
    
    if (-not (Test-Path $XmlPath)) {
        return @()
    }
    
    try {
        [xml]$xml = Get-Content $XmlPath -Raw
        $failedTests = @()
        
        # Find all failed test cases
        $xml.SelectNodes("//test-case[@result='Failure']") | ForEach-Object {
            $testCase = $_
            $testName = $testCase.GetAttribute('name')
            $description = $testCase.GetAttribute('description')
            $failureNode = $testCase.SelectSingleNode('failure/message')
            $message = if ($failureNode) { $failureNode.InnerText } else { 'Unknown error' }
            
            # Extract function name from test name (e.g., "Get-StepWeight Function.Returns correct weight")
            $functionName = if ($testName -match '^([^.]+)\s+Function\.(.+)$') {
                $matches[1]
            } else {
                $testName.Split('.')[0]
            }
            
            # Get file name from parent test-suite
            $filePath = $testCase.ParentNode
            while ($filePath -and -not ($filePath.GetAttribute('name') -and $filePath.GetAttribute('name').EndsWith('.ps1'))) {
                $filePath = $filePath.ParentNode
            }
            $fileName = if ($filePath) {
                Split-Path $filePath.GetAttribute('name') -Leaf
            } else {
                'Unknown'
            }
            
            $failedTests += @{
                Test = "$functionName - $description"
                Error = $message
                File = $fileName
                FullName = $testName
            }
        }
        
        return $failedTests
    }
    catch {
        Write-TestLog "Error parsing XML: $_" -Level "WARN" -Color Yellow
        return @()
    }
}

# Set UTF-8 encoding for proper Unicode support
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Initialize logging
if ($LogToFile) {
    Invoke-LogRotation -LogDirectory $script:LogPath -MaxFiles $MaxLogFiles
    
    # Only set if not already initialized
    if (-not $script:LogFile) {
        $script:LogFile = Join-Path $script:LogPath "test-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    }
    
    # Write header
    @"
========================================
UpdateLoxone Test Run
Started: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
Parameters: $(($PSBoundParameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')
========================================
"@ | Out-File -FilePath $script:LogFile -Encoding UTF8
}

# Initialize full output logging (capture everything including Pester output)
$script:FullLogFile = Join-Path $script:CurrentRunPath "test-run-full.log"
$script:TranscriptStarted = $false

# Start transcript to capture ALL output
try {
    Start-Transcript -Path $script:FullLogFile -Force -ErrorAction Stop
    $script:TranscriptStarted = $true
    Write-TestLog "Full output logging started to: $($script:FullLogFile)" -Color Gray
} catch {
    Write-TestLog "Warning: Could not start transcript logging: $_" -Level "WARN" -Color Yellow
}

Write-TestLog "=== UpdateLoxone Unified Test Runner ===" -Color Cyan

# Check for admin if system tests requested
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $SkipSystemTests -and -not $isAdmin -and -not $CI) {
    Write-TestLog "Administrator privileges required for SYSTEM tests" -Level "WARN" -Color Yellow
    $response = Read-Host "Restart as Administrator? (Y/N)"
    
    if ($response -eq 'Y') {
        $arguments = @($MyInvocation.MyCommand.Path)
        foreach ($param in $PSBoundParameters.GetEnumerator()) {
            if ($param.Value -is [switch] -and $param.Value) {
                $arguments += "-$($param.Key)"
            } elseif ($param.Value -isnot [switch]) {
                $arguments += "-$($param.Key)"
                $arguments += $param.Value
            }
        }
        
        Start-Process powershell.exe -ArgumentList ($arguments -join ' ') -Verb RunAs
        Write-TestLog "Restarting as Administrator..." -Color Cyan
        exit 0
    } else {
        Write-TestLog "Skipping SYSTEM tests (no admin privileges)" -Color Gray
        $SkipSystemTests = $true
    }
}

# Import required modules
try {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
    Write-TestLog "Pester v$(Get-Module Pester | Select-Object -ExpandProperty Version) loaded"
    
    # Set up test environment flags before loading modules
    # This ensures Toast functionality doesn't interfere with tests
    $Global:SuppressLoxoneToastInit = $true
    $Global:PersistentToastInitialized = $true
    
    # Mock all Toast functions to prevent any usage during tests
    # UNLESS LiveProgress is enabled
    if (-not $LiveProgress) {
        function Global:Show-UpdateLoxoneToast { Write-Verbose "MOCK: Toast function called" }
        function Global:Update-PersistentToast { Write-Verbose "MOCK: Toast function called" }
        function Global:Initialize-Toast { Write-Verbose "MOCK: Toast function called" }
        function Global:Update-Toast { Write-Verbose "MOCK: Toast function called" }
        function Global:Show-FinalStatusToast { Write-Verbose "MOCK: Toast function called" }
        function Global:Initialize-LoxoneToastAppId { Write-Verbose "MOCK: Toast function called" }
    } else {
        # When LiveProgress is enabled, we need real toast functions that use DataBinding
        Import-Module BurntToast -Force
        
        # Import the full LoxoneUtils module first to get all dependencies
        $loxoneUtilsPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        if (Test-Path $loxoneUtilsPath) {
            Import-Module $loxoneUtilsPath -Force -Global
        }
        
        # Initialize and get Loxone AppId
        $loxoneAppId = $null
        if (Get-Command Initialize-LoxoneToastAppId -ErrorAction SilentlyContinue) {
            Initialize-LoxoneToastAppId
        }
        if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
            $loxoneAppId = Get-LoxoneToastAppId
        }
        if (-not $loxoneAppId) {
            # Fallback to default PowerShell AppId
            $loxoneAppId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        }
        
        # Initialize global data binding for smooth updates
        $Global:LiveProgressTestCount = 0
        $Global:LiveProgressPassedCount = 0
        $Global:LiveProgressFailedCount = 0
        $Global:LiveProgressSkippedCount = 0
        $Global:LiveProgressTotalTests = 0
        $Global:LiveProgressModuleCount = 0
        $Global:LiveProgressTotalModules = if ($testFiles) { $testFiles.Count } else { 0 }
        $Global:LiveProgressStartTime = Get-Date
        
        # Determine which test types are being run
        $testTypesRunning = @()
        if ($script:RunUnit) { $testTypesRunning += "Unit" }
        if ($script:RunIntegration) { $testTypesRunning += "Integration" }
        if ($script:RunSystem) { $testTypesRunning += "System" }
        $Global:LiveProgressTestTypeDisplay = if ($testTypesRunning.Count -eq 3) { "All Tests" } else { $testTypesRunning -join " + " }
        
        $Global:LiveProgressToastData = @{
            StatusText = "$Global:LiveProgressTestTypeDisplay | 0:00"
            ModuleProgressTitle = "Initializing..."  # Title above upper bar
            ProgressBarStatus = "0 / 0 modules"  # Status below upper bar
            ProgressBarValue = 0
            TestProgressTitle = "Discovering tests..."  # Title above lower bar
            OverallProgressStatus = "0 / 0 tests"  # Status below lower bar
            OverallProgressValue = 0
            DetailsText = "✅ Passed: 0`n❌ Failed: 0`n⏭️ Skipped: 0"
        }
        $Global:LiveProgressToastId = "UpdateLoxoneTests"
        $Global:LiveProgressToastInitialized = $false
        
        function Global:Initialize-Toast {
            try {
                # Create components with data binding - double progress bar like live implementation
                $text1 = New-BTText -Content "StatusText"
                $progressBar1 = New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "ModuleProgressTitle"
                $progressBar2 = New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "TestProgressTitle"
                $text2 = New-BTText -Content "DetailsText"
                
                # Add Loxone icon if available
                $appLogo = Join-Path (Split-Path $PSScriptRoot -Parent) 'ms.png'
                if (Test-Path $appLogo) {
                    $image = New-BTImage -Source $appLogo -AppLogoOverride
                    $binding = New-BTBinding -Children $text1, $progressBar1, $progressBar2, $text2 -AppLogoOverride $image
                } else {
                    $binding = New-BTBinding -Children $text1, $progressBar1, $progressBar2, $text2
                }
                
                $visual = New-BTVisual -BindingGeneric $binding
                $audio = New-BTAudio -Silent
                
                # Create content with reminder scenario for persistence
                $content = New-BTContent -Visual $visual -Audio $audio -Scenario Reminder -Duration Long -ActivationType Protocol
                
                # Submit with data binding and Loxone AppId
                $submitParams = @{
                    Content = $content
                    UniqueIdentifier = $Global:LiveProgressToastId
                    DataBinding = $Global:LiveProgressToastData
                }
                # Always use the Loxone AppId
                $submitParams.AppId = $loxoneAppId
                
                Submit-BTNotification @submitParams
                $Global:LiveProgressToastInitialized = $true
                Write-Verbose "LiveProgress toast initialized with Loxone branding"
            } catch {
                Write-Verbose "Failed to initialize LiveProgress toast: $_"
            }
        }
        
        function Global:Update-Toast {
            param($Message, [bool]$TestPassed = $true, [bool]$TestSkipped = $false)
            try {
                $Global:LiveProgressTestCount++
                if ($TestSkipped) {
                    $Global:LiveProgressSkippedCount++
                } elseif ($TestPassed) {
                    $Global:LiveProgressPassedCount++
                } else {
                    $Global:LiveProgressFailedCount++
                }
                
                if ($Global:LiveProgressTotalTests -gt 0) {
                    # Update data binding values
                    $testPercent = [math]::Round(($Global:LiveProgressTestCount / $Global:LiveProgressTotalTests) * 100, 0) / 100
                    
                    # Calculate runtime in M:SS format
                    $runtime = (Get-Date) - $Global:LiveProgressStartTime
                    $minutes = [math]::Floor($runtime.TotalMinutes)
                    $seconds = [math]::Floor($runtime.TotalSeconds % 60)
                    $runtimeDisplay = $minutes.ToString() + ":" + $seconds.ToString('00')
                    
                    $Global:LiveProgressToastData.StatusText = "$Global:LiveProgressTestTypeDisplay | $runtimeDisplay"
                    $Global:LiveProgressToastData.OverallProgressStatus = "$Global:LiveProgressTestCount / $Global:LiveProgressTotalTests tests"
                    $Global:LiveProgressToastData.OverallProgressValue = $testPercent
                    $Global:LiveProgressToastData.DetailsText = "✅ Passed: $Global:LiveProgressPassedCount`n❌ Failed: $Global:LiveProgressFailedCount`n⏭️ Skipped: $Global:LiveProgressSkippedCount"
                    
                    # Initialize toast if needed
                    if (-not $Global:LiveProgressToastInitialized) {
                        Initialize-Toast
                    } else {
                        # Update existing toast with data binding
                        $updateParams = @{
                            UniqueIdentifier = $Global:LiveProgressToastId
                            DataBinding = $Global:LiveProgressToastData
                        }
                        # Always use the Loxone AppId
                        $updateParams.AppId = $loxoneAppId
                        Update-BTNotification @updateParams
                    }
                }
            } catch {
                # Silently ignore
            }
        }
        
        # Re-export the Toast module functions to global scope if needed
        if (-not (Get-Command Initialize-LoxoneToastAppId -ErrorAction SilentlyContinue)) {
            function Global:Initialize-LoxoneToastAppId { 
                # This is a fallback - the real function should come from the Toast module
                Write-Verbose "Using fallback AppId initialization" 
            }
        }
        
        # Keep track of test execution by monitoring Pester output
        $Global:LastTestFile = ""
        $Global:TestUpdateCounter = 0
        
        # Set up periodic updates using a background job instead of timer
        $Global:LiveProgressJob = $null
        
        # Function to check test progress (will be called manually)
        function Global:Check-TestProgress {
            if ($Global:LiveProgressTestCount -gt 0 -and $Global:LiveProgressTotalTests -gt 0) {
                $progress = $Global:LiveProgressTestCount / $Global:LiveProgressTotalTests
                $Global:LiveProgressToastData.ProgressBarValue = $progress
                $Global:LiveProgressToastData.StatusText = "Running tests..."
                $Global:LiveProgressToastData.ProgressBarStatus = "$Global:LiveProgressTestCount / $Global:LiveProgressTotalTests tests"
                $Global:LiveProgressToastData.DetailsText = "✅ Passed: $Global:LiveProgressPassedCount | ❌ Failed: $Global:LiveProgressFailedCount"
                
                Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId
            }
        }
        
        # Map other functions to Update-Toast
        function Global:Update-PersistentToast { 
            param($Message) 
            # Always update progress when this is called during tests
            Update-Toast -Message $Message 
        }
        function Global:Show-UpdateLoxoneToast { 
            param($Message) 
            Update-Toast -Message $Message 
        }
        function Global:Show-FinalStatusToast { Write-Verbose "Final toast handled separately" }
    }
    
} catch {
    Write-TestLog "Failed to load Pester: $_" -Level "ERROR" -Color Red
    exit 1
}

# Import LoxoneUtils module to get TestTracking
try {
    $script:loxoneUtilsPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    if (Test-Path $script:loxoneUtilsPath) {
        # Remove module first to ensure clean import
        Remove-Module LoxoneUtils -Force -ErrorAction SilentlyContinue
        Import-Module $script:loxoneUtilsPath -Force
        
        # Enable assertion tracking if TestTracking module is available
        if (Get-Command Enable-AssertionTracking -ErrorAction SilentlyContinue) {
            Enable-AssertionTracking
            Write-TestLog "Assertion tracking enabled for individual test goals"
        }
    }
} catch {
    Write-TestLog "Failed to load LoxoneUtils module: $_" -Level "ERROR" -Color Red
}

# Fix ConvertTo-SecureString if missing (PowerShell environment issue)
if (-not (Get-Command ConvertTo-SecureString -ErrorAction SilentlyContinue)) {
    function global:ConvertTo-SecureString {
        param(
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$String,
            [switch]$AsPlainText,
            [switch]$Force
        )
        $secure = New-Object System.Security.SecureString
        foreach ($char in $String.ToCharArray()) {
            $secure.AppendChar($char)
        }
        $secure.MakeReadOnly()
        return $secure
    }
    Write-TestLog "ConvertTo-SecureString cmdlet missing - using workaround" -Level "WARN"
}

# Function to parse Pester XML output and extract test details
function Get-PesterXmlTestDetails {
    param(
        [string]$XmlPath
    )
    
    $failedTests = @()
    
    if (-not (Test-Path $XmlPath)) {
        Write-TestLog "XML file not found: $XmlPath" -Level "DEBUG" -Color Gray
        return $failedTests
    }
    
    try {
        [xml]$xmlContent = Get-Content $XmlPath -Raw
        
        # Find all failed test cases
        $failedTestCases = $xmlContent.SelectNodes("//test-case[@result='Failure']")
        
        foreach ($testCase in $failedTestCases) {
            # Extract test name components
            $fullName = $testCase.GetAttribute("name")
            $description = $testCase.GetAttribute("description")
            
            # Parse the file name from parent test-suite
            $parentSuite = $testCase.ParentNode
            while ($parentSuite -and $parentSuite.GetAttribute("type") -ne "TestFixture") {
                $parentSuite = $parentSuite.ParentNode
            }
            
            $fileName = "Unknown"
            if ($parentSuite) {
                $suiteName = $parentSuite.GetAttribute("name")
                if ($suiteName -match '\\([^\\]+\.Tests\.ps1)$') {
                    $fileName = $matches[1]
                }
            }
            
            # Extract error message and stack trace
            $failureNode = $testCase.SelectSingleNode("failure")
            $messageNode = $failureNode.SelectSingleNode("message")
            $stackNode = $failureNode.SelectSingleNode("stack-trace")
            
            $errorMessage = if ($messageNode) { $messageNode.InnerText } else { "No error message" }
            $stackTrace = if ($stackNode) { $stackNode.InnerText } else { "" }
            
            # Extract line number from stack trace if available
            $lineNumber = ""
            if ($stackTrace -match ':([0-9]+)$') {
                $lineNumber = " (Line $($matches[1]))"
            }
            
            $failedTests += @{
                Test = $fullName
                Description = $description
                Error = $errorMessage
                File = $fileName
                LineNumber = $lineNumber
                StackTrace = $stackTrace
            }
        }
    } catch {
        Write-TestLog "Error parsing XML: $_" -Level "ERROR" -Color Red
    }
    
    return $failedTests
}

# Initialize result tracking
$script:Results = @{
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    SkippedTests = 0
    UnitTests = @{
        Total = 0
        Passed = 0
        Failed = 0
        Duration = $null
        Status = "Not Run"
    }
    IntegrationTests = @{
        Total = 0
        Passed = 0
        Failed = 0
        Duration = $null
        Status = "Not Run"
    }
    SystemTests = @{
        Total = 0
        Passed = 0
        Failed = 0
        Skipped = 0
        Duration = $null
        Status = "Not Run"
    }
    FailedTestDetails = @()
    SkippedTestDetails = @()
}

# Function to run tests with live progress notifications
function Invoke-TestsWithLiveProgress {
    param(
        [string[]]$TestPaths,
        [string]$TestFilter = "*.Tests.ps1",
        [string[]]$ExcludeTags = @(),
        [string[]]$IncludeTags = @(),
        [switch]$NoTagFiltering
    )
    
    # Check if BurntToast is available
    $script:LiveProgressNoToast = $false
    try {
        if (-not (Get-Module BurntToast)) {
            Import-Module BurntToast -ErrorAction Stop
        }
        # Test if BurntToast commands are available
        if (-not (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue)) {
            throw "BurntToast commands not available"
        }
    } catch {
        Write-TestLog "BurntToast module not available or not working: $_" -Level "WARN" -Color Yellow
        $script:LiveProgressNoToast = $true
    }
    
    # Initialize live progress state
    $script:LiveProgressState = @{
        TotalTests = 0
        ExecutedTests = 0
        PassedTests = 0
        FailedTests = 0
        SkippedTests = 0
        CurrentTest = ""
        StartTime = Get-Date
        LastToastUpdate = Get-Date
        ToastUpdateInterval = 500  # milliseconds
    }
    
    # Get all test files
    $testFiles = @()
    foreach ($path in $TestPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Filter $TestFilter -File -Recurse
            $testFiles += $files
        }
    }
    
    if (-not $testFiles -or $testFiles.Count -eq 0) {
        Write-TestLog "No test files found matching filter: $TestFilter" -Level "WARN" -Color Yellow
        return @{
            TotalTests = 0
            PassedTests = 0
            FailedTests = 0
            SkippedTests = 0
            Duration = 0
        }
    }
    
    # Configure Pester
    $config = New-PesterConfiguration
    $config.Run.Path = $testFiles.FullName
    $config.Run.PassThru = $true
    
    # Apply tag filtering unless disabled
    if (-not $NoTagFiltering) {
        if ($ExcludeTags.Count -gt 0) {
            $config.Filter.ExcludeTag = $ExcludeTags
        }
        if ($IncludeTags.Count -gt 0) {
            $config.Filter.Tag = $IncludeTags
        }
    }
    
    # Set verbosity based on mode
    if ($script:CI) {
        $config.Output.Verbosity = 'Minimal'
    } elseif ($script:Detailed) {
        # Use Detailed output when requested
        $config.Output.Verbosity = 'Detailed'
        $config.Output.CIFormat = 'None'  # Ensure we get standard output format
    } elseif ($script:DebugMode) {
        $config.Output.Verbosity = 'Diagnostic'
    } else {
        $config.Output.Verbosity = 'Normal'
    }
    
    # Enable test result export
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $script:ResultsPath "LiveProgress-TestResults.xml"
    $config.TestResult.OutputFormat = "NUnit2.5"
    
    # Count total tests for progress tracking
    Write-TestLog "Discovering tests in $(if ($testFiles) { $testFiles.Count } else { 0 }) files..." -Color Gray
    $discoveryConfig = New-PesterConfiguration
    $discoveryConfig.Run.Path = $testFiles.FullName
    $discoveryConfig.Run.PassThru = $true
    $discoveryConfig.Run.SkipRun = $true  # Only discover, don't run
    
    if (-not $NoTagFiltering) {
        if ($ExcludeTags.Count -gt 0) {
            $discoveryConfig.Filter.ExcludeTag = $ExcludeTags
        }
        if ($IncludeTags.Count -gt 0) {
            $discoveryConfig.Filter.Tag = $IncludeTags
        }
    }
    
    $discovery = Invoke-Pester -Configuration $discoveryConfig
    $totalTests = $discovery.TotalCount
    
    # Add RunAsUser SYSTEM tests to the count if they will run
    $runAsUserSystemTests = 0
    if ($script:IsAdmin -and $TestType -in @('All', 'System') -and -not $SkipSystemTests) {
        $systemTestScript = Join-Path $script:TestsPath "Helpers" | Join-Path -ChildPath "invoke-system-tests.ps1"
        if (Test-Path $systemTestScript) {
            $runAsUserSystemTests = 4  # These 4 tests run via PsExec as SYSTEM user
            $totalTests += $runAsUserSystemTests
        }
    }
    
    Write-TestLog "Discovered $totalTests tests" -Color Gray
    if ($runAsUserSystemTests -gt 0) {
        Write-TestLog "  (includes $runAsUserSystemTests RunAsUser SYSTEM tests)" -Color Gray
    }
    
    # Set global total for progress updates
    $Global:LiveProgressTotalTests = $totalTests
    $Global:LiveProgressTestCount = 0
    
    # Initial toast notification - just call Initialize-Toast
    if (-not $script:LiveProgressNoToast) {
        try {
            # Initialize the toast with data binding
            if (Get-Command Initialize-Toast -ErrorAction SilentlyContinue) {
                Initialize-Toast
                Write-TestLog "Initial progress toast notification sent with Loxone AppId and persistence" -Level "DEBUG"
            }
            
            # Store the start time for progress updates
            $script:LiveProgressState.StartTime = Get-Date
            $script:LiveProgressState.LastUpdateTime = Get-Date
            $script:LiveProgressState.TotalTests = $totalTests
        } catch {
            Write-TestLog "Toast notification failed: $_" -Level "DEBUG"
            $script:LiveProgressNoToast = $true
        }
    }
    
    Write-TestLog "Running tests with live progress tracking..." -Color Cyan
    
    # Initialize toast before running tests
    if (-not $script:LiveProgressNoToast -and (Get-Command Initialize-Toast -ErrorAction SilentlyContinue)) {
        Initialize-Toast
    }
    
    # Run tests with output monitoring for LiveProgress
    $startTime = Get-Date
    
    # For LiveProgress, we'll capture output from Pester and update toast notifications
    if ($Global:LiveProgressTotalTests -gt 0) {
        Write-TestLog "Setting up test-level progress tracking..." -Level "DEBUG"
        
        # Create synchronized hashtable for progress tracking
        $Global:LiveProgressData = [hashtable]::Synchronized(@{
            TestsRun = 0
            TestsPassed = 0
            TestsFailed = 0 
            TestsSkipped = 0
            CurrentTest = ""
            CurrentDescribe = ""
            LastUpdate = Get-Date
            TotalTests = $totalTests
        })
    }
    
    # Run Pester with live progress monitoring
    if ($Global:LiveProgressTotalTests -gt 0) {
        Write-TestLog "Using wrapper runner for individual test progress tracking..." -Level "DEBUG"
        
        # SOLUTION: Run tests one by one using a wrapper runner approach!
        # First, discover all tests without running them
        $discoveryConfig = New-PesterConfiguration
        $discoveryConfig.Run.Path = $testFiles.FullName
        $discoveryConfig.Run.PassThru = $true
        $discoveryConfig.Run.SkipRun = $true  # Discovery only
        
        if (-not $NoTagFiltering) {
            if ($ExcludeTags.Count -gt 0) {
                $discoveryConfig.Filter.ExcludeTag = $ExcludeTags
            }
            if ($IncludeTags.Count -gt 0) {
                $discoveryConfig.Filter.Tag = $IncludeTags
            }
        }
        
        # Helper function to extract tests from nested blocks
        function Get-TestsFromBlock {
            param($Block)
            $tests = @()
            
            # Add tests from this block
            foreach ($test in $Block.Tests) {
                # Log test discovery for debugging
                Write-Verbose "Discovered test: $($test.ExpandedPath) in file: $($test.ScriptBlock.File)"
                $tests += @{
                    Name = $test.ExpandedPath
                    File = $test.ScriptBlock.File
                }
            }
            
            # Recurse into child blocks
            foreach ($childBlock in $Block.Blocks) {
                $tests += Get-TestsFromBlock -Block $childBlock
            }
            
            return $tests
        }
        
        Write-TestLog "Discovering individual tests..." -Level "DEBUG"
        $discovered = Invoke-Pester -Configuration $discoveryConfig
        
        # Extract all test names from discovery
        $allTests = @()
        foreach ($container in $discovered.Containers) {
            foreach ($block in $container.Blocks) {
                $testsFromBlock = Get-TestsFromBlock -Block $block
                foreach ($test in $testsFromBlock) {
                    # Ensure we have the file property
                    if (-not $test.File -and $container.Item) {
                        $test.File = $container.Item.FullName
                    }
                    $allTests += $test
                }
            }
        }
        
        # Add RunAsUser SYSTEM tests to the count if they will run
        $totalTestsIncludingSystem = $allTests.Count
        if ($script:IsAdmin -and $TestType -in @('All', 'System') -and -not $SkipSystemTests) {
            $systemTestScript = Join-Path $script:TestsPath "Helpers" | Join-Path -ChildPath "invoke-system-tests.ps1"
            if (Test-Path $systemTestScript) {
                $totalTestsIncludingSystem += 4  # Add the 4 RunAsUser SYSTEM tests
            }
        }
        
        Write-TestLog "Found $($allTests.Count) individual tests to run" -Level "DEBUG"
        if ($totalTestsIncludingSystem -gt $allTests.Count) {
            Write-TestLog "  (plus $($totalTestsIncludingSystem - $allTests.Count) RunAsUser SYSTEM tests)" -Level "DEBUG"
        }
        
        # Update global total to include SYSTEM tests
        $Global:LiveProgressTotalTests = $totalTestsIncludingSystem
        
        # Count unique modules
        $uniqueModules = @()
        foreach ($test in $allTests) {
            if ($test.File -and $uniqueModules -notcontains $test.File) {
                $uniqueModules += $test.File
            }
        }
        $Global:LiveProgressTotalModules = $uniqueModules.Count
        Write-TestLog "Found $($uniqueModules.Count) unique test modules" -Level "DEBUG"
        
        # Initialize module progress in toast data
        $Global:LiveProgressToastData.ModuleProgressTitle = "Starting modules..."
        $Global:LiveProgressToastData.ProgressBarStatus = "0 / $($uniqueModules.Count) modules"
        $Global:LiveProgressToastData.ProgressBarValue = 0
        $Global:LiveProgressToastData.TestProgressTitle = "Starting tests..."
        $Global:LiveProgressToastData.OverallProgressStatus = "0 / $totalTestsIncludingSystem tests"
        
        # Now run tests one by one with progress updates
        $testResults = @{
            PassedCount = 0
            FailedCount = 0
            SkippedCount = 0
            TotalCount = 0
            Passed = @()
            Failed = @()
            Skipped = @()
        }
        
        $startTime = Get-Date
        $testIndex = 0
        $script:LastModuleName = ""
        $Global:LiveProgressModuleCount = 0
        
        foreach ($test in $allTests) {
            $testIndex++
            
            # Debug output
            Write-Verbose "Running test $testIndex/$($allTests.Count): $($test.Name)"
            
            # Run single test
            $singleTestConfig = New-PesterConfiguration
            $singleTestConfig.Run.Path = $test.File
            $singleTestConfig.Run.PassThru = $true
            $singleTestConfig.Filter.FullName = $test.Name
            $singleTestConfig.Output.Verbosity = 'None'  # Quiet for individual runs
            
            Write-Verbose "Invoking Pester for: $($test.Name) in $($test.File)"
            $singleResult = Invoke-Pester -Configuration $singleTestConfig
            
            # Update counts
            $testResults.TotalCount++
            $testPassed = $false
            $testSkipped = $false
            
            if ($singleResult.PassedCount -gt 0) {
                $testResults.PassedCount++
                $testPassed = $true
                # Store the test object for categorization
                if ($singleResult.Passed) {
                    $testResults.Passed += $singleResult.Passed[0]
                }
            } elseif ($singleResult.FailedCount -gt 0) {
                $testResults.FailedCount++
                $testPassed = $false
                # Store the test object for categorization
                if ($singleResult.Failed) {
                    $testResults.Failed += $singleResult.Failed[0]
                }
            } else {
                $testResults.SkippedCount++
                $testSkipped = $true
                # Store the test object for categorization
                if ($singleResult.Skipped) {
                    $testResults.Skipped += $singleResult.Skipped[0]
                }
            }
            
            # Update toast notification after EVERY test!
            if (Get-Command Update-Toast -ErrorAction SilentlyContinue) {
                # This calls the existing Update-Toast function which increments counters
                Update-Toast -Message $test.Name -TestPassed $testPassed -TestSkipped $testSkipped
            }
            
            # Also update progress directly for more accurate tracking
            $progress = $testIndex / $allTests.Count
            $elapsed = (Get-Date) - $startTime
            
            # Track which module we're in
            $currentModuleName = Split-Path $test.File -Leaf
            if ($script:LastModuleName -ne $currentModuleName) {
                $script:LastModuleName = $currentModuleName
                $Global:LiveProgressModuleCount++
                $moduleProgress = if ($Global:LiveProgressTotalModules -gt 0) { 
                    $Global:LiveProgressModuleCount / $Global:LiveProgressTotalModules 
                } else { 0 }
                # Update module name as title, keep numbers as status
                $moduleDisplayName = $currentModuleName -replace '\.Tests\.ps1$', ''
                
                # Determine test category from file path
                $testCategory = "Unit"
                if ($test.File -match "\\Integration\\") {
                    $testCategory = "Integration"
                } elseif ($test.File -match "\\System\\") {
                    $testCategory = "System"
                }
                
                $Global:LiveProgressToastData.ModuleProgressTitle = "[$testCategory] $moduleDisplayName"
                $Global:LiveProgressToastData.ProgressBarStatus = "$Global:LiveProgressModuleCount / $Global:LiveProgressTotalModules modules"
                $Global:LiveProgressToastData.ProgressBarValue = $moduleProgress
            }
            
            # Calculate runtime in M:SS format
            $runtime = (Get-Date) - $Global:LiveProgressStartTime
            $minutes = [math]::Floor($runtime.TotalMinutes)
            $seconds = [math]::Floor($runtime.TotalSeconds % 60)
            $runtimeDisplay = $minutes.ToString() + ":" + $seconds.ToString('00')
            
            # Update status with test type and runtime
            $Global:LiveProgressToastData.StatusText = "$Global:LiveProgressTestTypeDisplay | $runtimeDisplay"
            
            # Get just the test name from the full path
            $testDisplayName = $test.Name
            if ($testDisplayName -match '\\([^\\]+)$') {
                $testDisplayName = $matches[1]
            }
            $Global:LiveProgressToastData.TestProgressTitle = $testDisplayName
            $Global:LiveProgressToastData.OverallProgressStatus = "$testIndex / $totalTestsIncludingSystem tests"
            $Global:LiveProgressToastData.OverallProgressValue = $progress
            $Global:LiveProgressToastData.DetailsText = "✅ Passed: $($testResults.PassedCount)`n❌ Failed: $($testResults.FailedCount)`n⏭️ Skipped: $($testResults.SkippedCount)"
            
            Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId -ErrorAction SilentlyContinue
        }
        
        # Create a mock PesterResult object for compatibility
        $pesterResult = [PSCustomObject]@{
            PassedCount = $testResults.PassedCount
            FailedCount = $testResults.FailedCount
            SkippedCount = $testResults.SkippedCount
            TotalCount = $testResults.TotalCount
            Duration = (Get-Date) - $startTime
            Result = if ($testResults.FailedCount -eq 0) { 'Passed' } else { 'Failed' }
            Passed = $testResults.Passed
            Failed = $testResults.Failed
            Skipped = $testResults.Skipped
        }
    } else {
        # Normal execution without LiveProgress
        $pesterResult = Invoke-Pester -Configuration $config
    }
    
    $duration = (Get-Date) - $startTime
    
    # Clean up LiveProgress
    if ($Global:LiveProgressTotalTests -gt 0) {
        # Clean up global variables
        Remove-Variable -Name LiveProgressData -Scope Global -ErrorAction SilentlyContinue
    }
    
    # No final toast needed - the last test update already shows the final state
    
    # Return results
    return @{
        TotalTests = $pesterResult.TotalCount
        PassedTests = $pesterResult.PassedCount
        FailedTests = $pesterResult.FailedCount
        SkippedTests = $pesterResult.SkippedCount
        Duration = $duration.TotalSeconds
        PesterResult = $pesterResult
    }
}

# Function to run a category of tests
function Invoke-TestCategory {
    param(
        [string]$CategoryName,
        [string[]]$TestPaths,
        [string[]]$IncludeTags = @(),
        [string[]]$ExcludeTags = @(),
        [string]$ResultsKey = "StandardTests"
    )
    
    Write-TestLog "`nRunning $CategoryName tests..." -Color Cyan
    
    # Show additional details in Detailed mode
    if ($script:Detailed -and $TestPaths.Count -gt 0) {
        Write-TestLog "Test paths: $($TestPaths -join ', ')" -Level "INFO" -Color Gray
        if ($IncludeTags.Count -gt 0) {
            Write-TestLog "Include tags: $($IncludeTags -join ', ')" -Level "INFO" -Color Gray
        }
        if ($ExcludeTags.Count -gt 0) {
            Write-TestLog "Exclude tags: $($ExcludeTags -join ', ')" -Level "INFO" -Color Gray
        }
    }
    
    # LiveProgress is handled internally now
    if ($LiveProgress -and $script:LiveProgressState -eq $null) {
        Write-TestLog "Using live progress with toast notifications..." -Color Yellow
        
        # Build filter based on category
        $testFilter = switch ($CategoryName) {
            "Unit" { "*.Tests.ps1" }
            "Integration" { "*Integration*.Tests.ps1" }
            "System" { "*System*.Tests.ps1" }
            default { "*.Tests.ps1" }
        }
        
        # Call the internal live progress function
        # For Unit tests, don't use tag filtering to avoid Pester's aggressive exclusion
        $liveExcludeTags = if ($CategoryName -eq "Unit") { @() } else { $ExcludeTags }
        $liveResults = Invoke-TestsWithLiveProgress -TestPaths $TestPaths -TestFilter $testFilter -ExcludeTags $liveExcludeTags
        
        if ($liveResults.PesterResult) {
            # Update our tracking with the results
            $script:Results.$ResultsKey = @{
                Status = if ($liveResults.FailedTests -eq 0) { "Passed" } else { "Failed" }
                Total = $liveResults.TotalTests
                Passed = $liveResults.PassedTests
                Failed = $liveResults.FailedTests
                Skipped = $liveResults.SkippedTests
                Duration = [TimeSpan]::FromSeconds($liveResults.Duration)
            }
            
            # Update global totals
            $script:Results.TotalTests = $liveResults.TotalTests
            $script:Results.PassedTests = $liveResults.PassedTests
            $script:Results.FailedTests = $liveResults.FailedTests
            $script:Results.SkippedTests = $liveResults.SkippedTests
            
            # Collect failed test details from Pester result
            if ($liveResults.PesterResult.FailedCount -gt 0) {
                foreach ($failure in $liveResults.PesterResult.Failed) {
                    $script:Results.FailedTestDetails += @{
                        Category = $CategoryName
                        Test = $failure.ExpandedPath
                        Error = $failure.ErrorRecord.Exception.Message
                        File = Split-Path $failure.ScriptBlock.File -Leaf
                    }
                }
            }
            
            # Collect skipped test details
            if ($liveResults.PesterResult.SkippedCount -gt 0) {
                foreach ($skipped in $liveResults.PesterResult.Skipped) {
                    $script:Results.SkippedTestDetails += @{
                        Category = $CategoryName
                        Test = $skipped.ExpandedPath
                        Reason = if ($skipped.ErrorRecord) { $skipped.ErrorRecord.Exception.Message } else { "Test marked with -Skip" }
                        File = Split-Path $skipped.ScriptBlock.File -Leaf
                    }
                }
            }
        }
        
        return
    }
    
    # Get test files from all specified paths
    $testFiles = @()
    foreach ($path in $TestPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Filter "*.Tests.ps1" -File -Recurse
            $testFiles += $files
        }
    }
    
    # Show file list in Detailed mode
    if ($script:Detailed -and $testFiles.Count -gt 0) {
        Write-TestLog "Found $($testFiles.Count) test files to run:" -Level "INFO" -Color Gray
        $testFiles | ForEach-Object {
            Write-TestLog "  - $($_.Name)" -Level "INFO" -Color DarkGray
        }
    }
    
    # Apply name filter if specified
    if ($Filter) {
        $testFiles = $testFiles | Where-Object { $_.Name -like "*$Filter*" }
        Write-TestLog "Filtered to $($testFiles.Count) test files matching '$Filter'"
    }
    
    if (-not $testFiles -or $testFiles.Count -eq 0) {
        Write-TestLog "No $CategoryName test files found" -Level "WARN" -Color Yellow
        return
    }
    
    # Configure Pester for this category
    $categoryConfig = New-PesterConfiguration
    $categoryConfig.Run.Path = $testFiles.FullName
    $categoryConfig.Run.PassThru = $true
    
    # Apply tags
    # Ensure arrays are properly initialized
    if ($null -eq $Tag) { $Tag = @() }
    if ($null -eq $ExcludeTag) { $ExcludeTag = @() }
    if ($null -eq $IncludeTags) { $IncludeTags = @() }
    if ($null -eq $ExcludeTags) { $ExcludeTags = @() }
    
    if ($IncludeTags.Count -gt 0 -or $Tag.Count -gt 0) {
        $allIncludeTags = $IncludeTags + $Tag | Select-Object -Unique
        $categoryConfig.Filter.Tag = $allIncludeTags
    }
    
    if ($ExcludeTags.Count -gt 0 -or $ExcludeTag.Count -gt 0) {
        $allExcludeTags = $ExcludeTags + $ExcludeTag | Select-Object -Unique
        $categoryConfig.Filter.ExcludeTag = $allExcludeTags
    }
    
    # Set output verbosity
    if ($script:DebugMode) {
        $categoryConfig.Output.Verbosity = 'Diagnostic'
        $categoryConfig.Debug.WriteDebugMessages = $true
        $categoryConfig.Debug.ShowFullErrors = $true
    } elseif ($script:Detailed) {
        $categoryConfig.Output.Verbosity = 'Detailed'
    } elseif ($script:CI) {
        $categoryConfig.Output.Verbosity = 'Minimal'
    } else {
        $categoryConfig.Output.Verbosity = 'Normal'
    }
    
    # Enable test result export
    $categoryConfig.TestResult.Enabled = $true
    $outputFileName = "$CategoryName-TestResults.xml".Replace(' ', '-')
    $categoryConfig.TestResult.OutputPath = Join-Path $script:ResultsPath $outputFileName
    $categoryConfig.TestResult.OutputFormat = "NUnit2.5"
    
    # JSON export if requested
    if ($OutputFormat -in @('JSON', 'All')) {
        # Will export manually after test run
    }
    
    # Run tests
    $categoryStartTime = Get-Date
    
    try {
        # Run tests sequentially
        $pesterResult = Invoke-Pester -Configuration $categoryConfig
        
        # Export assertion results if tracking is enabled
        if (Get-Command Export-TestAssertionResults -ErrorAction SilentlyContinue) {
            $assertionPath = Join-Path $script:ResultsPath "$CategoryName-AssertionResults.json".Replace(' ', '-')
            try {
                Export-TestAssertionResults -Path $assertionPath -Format JSON
                Write-TestLog "Assertion tracking results exported to $assertionPath" -Level "DEBUG"
            } catch {
                Write-TestLog "Failed to export assertion results: $_" -Level "DEBUG"
            }
        }
        
        # Update results
        if (-not $script:Results.ContainsKey($ResultsKey)) {
            $script:Results[$ResultsKey] = @{
                Total = 0
                Passed = 0  
                Failed = 0
                Duration = [TimeSpan]::Zero
                Status = "NotRun"
            }
        }
        
        # Use actual test counts that ran, not discovery count
        $actualTestsRun = $pesterResult.PassedCount + $pesterResult.FailedCount + $pesterResult.SkippedCount
        $script:Results[$ResultsKey].Total = $actualTestsRun
        $script:Results[$ResultsKey].Passed = $pesterResult.PassedCount
        $script:Results[$ResultsKey].Failed = $pesterResult.FailedCount
        $script:Results[$ResultsKey].Duration = (Get-Date) - $categoryStartTime
        $script:Results[$ResultsKey].Status = if ($pesterResult.FailedCount -eq 0) { "Passed" } else { "Failed" }
        
        # Update totals
        $script:Results.TotalTests += $actualTestsRun
        $script:Results.PassedTests += $pesterResult.PassedCount
        $script:Results.FailedTests += $pesterResult.FailedCount
        $script:Results.SkippedTests += $pesterResult.SkippedCount
        
        # Collect failed test details
        if ($pesterResult.FailedCount -gt 0) {
            foreach ($failure in $pesterResult.Failed) {
                $script:Results.FailedTestDetails += @{
                    Category = $CategoryName
                    Test = $failure.ExpandedPath
                    Error = $failure.ErrorRecord.Exception.Message
                    File = Split-Path $failure.ScriptBlock.File -Leaf
                }
            }
        }
        
        # Collect skipped test details
        if ($pesterResult.SkippedCount -gt 0) {
            Write-TestLog "Found $($pesterResult.SkippedCount) skipped tests in $CategoryName" -Level "DEBUG"
            
            # Debug: Check what properties are available
            if ($script:Detailed -or $script:DebugMode) {
                Write-TestLog "PesterResult type: $($pesterResult.GetType().FullName)" -Level "DEBUG"
                Write-TestLog "PesterResult properties: $(($pesterResult | Get-Member -MemberType Property | Select-Object -ExpandProperty Name) -join ', ')" -Level "DEBUG"
            }
            
            # Try different approaches to get skipped tests
            $skippedTests = $null
            
            # Approach 1: Direct Skipped property
            if ($pesterResult.Skipped) {
                $skippedTests = $pesterResult.Skipped
                Write-TestLog "Found skipped tests in .Skipped property (Count: $($skippedTests.Count))" -Level "DEBUG"
            }
            # Approach 2: Tests property with Skipped = true
            elseif ($pesterResult.Tests) {
                $skippedTests = $pesterResult.Tests | Where-Object { $_.Skipped -eq $true }
                Write-TestLog "Found skipped tests in .Tests property (Count: $($skippedTests.Count))" -Level "DEBUG"
            }
            # Approach 3: Containers/Blocks/Tests hierarchy
            elseif ($pesterResult.Containers) {
                $skippedTests = @()
                foreach ($container in $pesterResult.Containers) {
                    foreach ($block in $container.Blocks) {
                        $blockSkipped = $block.Tests | Where-Object { $_.Skipped -eq $true }
                        $skippedTests += $blockSkipped
                    }
                }
                Write-TestLog "Found skipped tests in container hierarchy (Count: $($skippedTests.Count))" -Level "DEBUG"
            }
            
            if ($skippedTests -and $skippedTests.Count -gt 0) {
                foreach ($skipped in $skippedTests) {
                    # Handle different test result formats
                    $testName = $skipped.ExpandedPath -or $skipped.Name -or "Unknown test"
                    $fileName = if ($skipped.ScriptBlock -and $skipped.ScriptBlock.File) {
                        Split-Path $skipped.ScriptBlock.File -Leaf
                    } elseif ($skipped.File) {
                        Split-Path $skipped.File -Leaf
                    } else {
                        "Unknown file"
                    }
                    
                    $reason = "Test skipped"
                    if ($skipped.ErrorRecord) {
                        $reason = $skipped.ErrorRecord.Exception.Message
                    } elseif ($skipped.SkippedBecause) {
                        $reason = $skipped.SkippedBecause
                    } elseif ($skipped.Tag) {
                        $reason = "Filtered by tag"
                    }
                    
                    $script:Results.SkippedTestDetails += @{
                        Category = $CategoryName
                        Test = $testName
                        Reason = $reason
                        File = $fileName
                    }
                }
                Write-TestLog "Added $($skippedTests.Count) skipped test details" -Level "DEBUG"
            } else {
                Write-TestLog "Unable to retrieve skipped test details from Pester result" -Level "DEBUG"
                
                # As a fallback, at least record that tests were skipped
                $script:Results.SkippedTestDetails += @{
                    Category = $CategoryName
                    Test = "$($pesterResult.SkippedCount) tests"
                    Reason = "Details not available - tests were filtered or skipped"
                    File = "Multiple files"
                }
            }
        }
        
        Write-TestLog "$CategoryName tests: $($pesterResult.PassedCount)/$($pesterResult.TotalCount) passed in $([math]::Round($script:Results[$ResultsKey].Duration.TotalSeconds, 2))s" -Color $(if ($pesterResult.FailedCount -eq 0) { 'Green' } else { 'Red' })
        
        # Show additional statistics in Detailed mode
        if ($script:Detailed) {
            $avgTimePerTest = if ($pesterResult.TotalCount -gt 0) { 
                [math]::Round($script:Results[$ResultsKey].Duration.TotalMilliseconds / $pesterResult.TotalCount, 1) 
            } else { 0 }
            
            Write-TestLog "  Test statistics:" -Color Gray
            Write-TestLog "    Files processed: $($testFiles.Count)" -Color DarkGray
            Write-TestLog "    Tests per file: $([math]::Round($pesterResult.TotalCount / [Math]::Max($testFiles.Count, 1), 1))" -Color DarkGray
            Write-TestLog "    Average time per test: ${avgTimePerTest}ms" -Color DarkGray
            
            if ($pesterResult.FailedCount -gt 0) {
                Write-TestLog "    Failed: $($pesterResult.FailedCount) ($([math]::Round($pesterResult.FailedCount / $pesterResult.TotalCount * 100, 1))%)" -Color Red
            }
            if ($pesterResult.SkippedCount -gt 0) {
                Write-TestLog "    Skipped: $($pesterResult.SkippedCount) ($([math]::Round($pesterResult.SkippedCount / $pesterResult.TotalCount * 100, 1))%)" -Color Yellow
            }
            
            # Show FULL detailed test list grouped by file
            Write-TestLog "`n  === DETAILED TEST RESULTS ===" -Color Cyan
            
            # Collect all tests with their status
            $allTestsWithStatus = @()
            
            # Add passed tests
            if ($pesterResult.Passed) {
                foreach ($test in $pesterResult.Passed) {
                    $allTestsWithStatus += [PSCustomObject]@{
                        File = Split-Path $test.ScriptBlock.File -Leaf
                        Name = $test.Name
                        Status = "Passed"
                        Duration = $test.Duration
                    }
                }
            }
            
            # Add failed tests
            if ($pesterResult.Failed) {
                foreach ($test in $pesterResult.Failed) {
                    $allTestsWithStatus += [PSCustomObject]@{
                        File = Split-Path $test.ScriptBlock.File -Leaf
                        Name = $test.Name
                        Status = "Failed"
                        Error = $test.ErrorRecord.Exception.Message
                    }
                }
            }
            
            # Add skipped tests
            if ($pesterResult.Skipped) {
                foreach ($test in $pesterResult.Skipped) {
                    $allTestsWithStatus += [PSCustomObject]@{
                        File = Split-Path $test.ScriptBlock.File -Leaf
                        Name = $test.Name
                        Status = "Skipped"
                        Reason = if ($test.ErrorRecord) { $test.ErrorRecord.Exception.Message } else { "Test marked with -Skip" }
                    }
                }
            }
            
            # Group by file and display
            $testsByFile = $allTestsWithStatus | Group-Object -Property File | Sort-Object Name
            
            foreach ($fileGroup in $testsByFile) {
                Write-TestLog "  $($fileGroup.Name):" -Color Yellow
                
                $passed = @($fileGroup.Group | Where-Object { $_.Status -eq "Passed" })
                $failed = @($fileGroup.Group | Where-Object { $_.Status -eq "Failed" })
                $skipped = @($fileGroup.Group | Where-Object { $_.Status -eq "Skipped" })
                
                $fileSummary = "($($passed.Count) passed"
                if ($failed.Count -gt 0) { $fileSummary += ", $($failed.Count) failed" }
                if ($skipped.Count -gt 0) { $fileSummary += ", $($skipped.Count) skipped" }
                $fileSummary += ")"
                Write-TestLog "    $fileSummary" -Color Gray
                
                foreach ($test in $fileGroup.Group | Sort-Object Name) {
                    $statusColor = switch ($test.Status) {
                        "Passed" { "Green" }
                        "Failed" { "Red" }
                        "Skipped" { "Yellow" }
                        default { "Gray" }
                    }
                    
                    $statusSymbol = switch ($test.Status) {
                        "Passed" { "✅" }
                        "Failed" { "❌" }
                        "Skipped" { "⏭️" }
                        default { "❓" }
                    }
                    
                    $testLine = "    $statusSymbol $($test.Name)"
                    if ($test.Status -eq "Failed" -and $test.Error) {
                        $errorMsg = $test.Error.Split([Environment]::NewLine)[0]
                        if ($errorMsg.Length -gt 80) { $errorMsg = $errorMsg.Substring(0, 77) + "..." }
                        $testLine += " - $errorMsg"
                    } elseif ($test.Status -eq "Skipped" -and $test.Reason -and $test.Reason -ne "Test marked with -Skip") {
                        $reasonMsg = $test.Reason
                        if ($reasonMsg.Length -gt 80) { $reasonMsg = $reasonMsg.Substring(0, 77) + "..." }
                        $testLine += " - $reasonMsg"
                    }
                    
                    Write-TestLog $testLine -Color $statusColor
                }
            }
        }
        
        # Export JSON if requested
        if ($OutputFormat -in @('JSON', 'All')) {
            $jsonPath = Join-Path $script:ResultsPath "$CategoryName-TestResults.json".Replace(' ', '-')
            $jsonData = @{
                Category = $CategoryName
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Results = $script:Results[$ResultsKey]
                Failed = $script:Results.FailedTestDetails | Where-Object { $_.Category -eq $CategoryName }
            }
            $jsonData | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
        }
        
    } catch {
        Write-TestLog "Error running $CategoryName tests: $_" -Level "ERROR" -Color Red
        $script:Results[$ResultsKey].Status = "Error"
    }
}

# Initialize additional result categories
$script:Results.IntegrationTests = @{ Status = "NotRun"; Total = 0; Passed = 0; Failed = 0; Skipped = 0; Duration = [TimeSpan]::Zero }
$script:Results.UnitTests = @{ Status = "NotRun"; Total = 0; Passed = 0; Failed = 0; Skipped = 0; Duration = [TimeSpan]::Zero }

# Check if we should use unified progress for multiple categories
# ONLY use unified progress when LiveProgress is explicitly requested
$useUnifiedProgress = $LiveProgress -and (
    ($script:RunUnit -and $script:RunIntegration) -or
    ($script:RunUnit -and $script:RunSystem) -or
    ($script:RunIntegration -and $script:RunSystem) -or
    ($TestType -eq 'All')
)

if ($useUnifiedProgress) {
    Write-TestLog "Using unified progress tracking across all test categories..." -Color Cyan
    
    # For unified progress, we need to run all tests in one Pester invocation
    # This way the progress bar tracks ALL tests from 0 to 100% continuously
    
    # Use the internal live progress function with all test paths
    # Include all subdirectories explicitly
    $allTestPaths = @("Unit", "Integration", "System") | ForEach-Object {
        Join-Path $script:TestsPath $_
    } | Where-Object { Test-Path $_ }
    
    Write-TestLog "Unified progress test paths:" -Level "DEBUG"
    foreach ($path in $allTestPaths) {
        Write-TestLog "  - $path (exists: $(Test-Path $path))" -Level "DEBUG"
        if (Test-Path $path) {
            $testFiles = Get-ChildItem -Path $path -Filter "*.Tests.ps1" -File
            Write-TestLog "    Found $($testFiles.Count) test files" -Level "DEBUG"
        }
    }
    
    $liveResults = Invoke-TestsWithLiveProgress -TestPaths $allTestPaths -TestFilter "*.Tests.ps1" -NoTagFiltering
    
    if ($liveResults.PesterResult) {
        # Update our result tracking
        $script:Results.TotalTests = $liveResults.TotalTests
        $script:Results.PassedTests = $liveResults.PassedTests
        $script:Results.FailedTests = $liveResults.FailedTests
        $script:Results.SkippedTests = $liveResults.SkippedTests
        
        # For unified run, we need to properly categorize results
        # Store the full results for post-processing later
        $script:LiveProgressFullResults = $liveResults
        
        # Initialize category results - will be properly populated after categorization
        $script:Results.UnitTests = @{
            Status = "Completed"
            Total = 0  # Will be set after categorization
            Passed = 0
            Failed = 0
            Skipped = 0
            Duration = [TimeSpan]::FromSeconds($liveResults.Duration)
        }
        
        $script:Results.IntegrationTests = @{
            Status = "Completed"
            Total = 0  # Will be set after categorization
            Passed = 0
            Failed = 0
            Skipped = 0
            Duration = [TimeSpan]::Zero
        }
        
        $script:Results.SystemTests = @{
            Status = "Completed"
            Total = 0  # Will be set after categorization
            Passed = 0
            Failed = 0
            Skipped = 0
            Duration = [TimeSpan]::Zero
        }
        
        # Collect all failed test details
        if ($liveResults.PesterResult.FailedCount -gt 0) {
            foreach ($failure in $liveResults.PesterResult.Failed) {
                # Try to determine category from file path
                $category = "Unit"  # Default
                if ($failure.ScriptBlock.File -match "\\Integration\\") {
                    $category = "Integration"
                } elseif ($failure.ScriptBlock.File -match "\\System\\") {
                    $category = "System"
                }
                
                $script:Results.FailedTestDetails += @{
                    Category = $category
                    Test = $failure.ExpandedPath
                    Error = $failure.ErrorRecord.Exception.Message
                    File = Split-Path $failure.ScriptBlock.File -Leaf
                    Description = $failure.Name
                }
            }
        }
        
        # Collect all skipped test details
        if ($liveResults.PesterResult.SkippedCount -gt 0) {
            foreach ($skipped in $liveResults.PesterResult.Skipped) {
                # Try to determine category from file path
                $category = "Unit"  # Default
                if ($skipped.ScriptBlock.File -match "\\Integration\\") {
                    $category = "Integration"
                } elseif ($skipped.ScriptBlock.File -match "\\System\\") {
                    $category = "System"
                }
                
                $script:Results.SkippedTestDetails += @{
                    Category = $category
                    Test = $skipped.ExpandedPath
                    Reason = if ($skipped.ErrorRecord) { $skipped.ErrorRecord.Exception.Message } else { "Test marked with -Skip" }
                    File = Split-Path $skipped.ScriptBlock.File -Leaf
                }
            }
        }
        
        # Skip normal test execution
        $script:RunUnit = $false
        $script:RunIntegration = $false
        $script:RunSystem = $false
    }
}

# Set up error suppression if requested
if ($SuppressErrorOutput) {
    Write-TestLog "Enabling error output suppression..." -Color Yellow
    
    # Store original error action preference
    $script:OriginalErrorActionPreference = $ErrorActionPreference
    
    # Set error action to continue (show errors but don't stop)
    $ErrorActionPreference = 'Continue'
    
    # Override Write-Error to filter out specific test-related errors
    # Store original but don't override globally to avoid breaking other functionality
    $script:SuppressSpecificErrors = $true
    
    # Hook into error stream instead of overriding Write-Error
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Set up error variable to capture errors silently
    $script:SuppressedErrors = @()
    
    # Function to restore original behavior
    function Global:Restore-ErrorOutput {
        $ErrorActionPreference = $script:OriginalErrorActionPreference
        $script:SuppressSpecificErrors = $false
    }
    
    Write-TestLog "Error suppression enabled for tests" -Color Green
}

# Discover all tests first to enable dynamic categorization
Write-TestLog "Discovering all tests for dynamic categorization..." -Color Cyan

# Get all test paths
$allTestPaths = @()
$testFolders = @("Unit", "Integration", "System") | ForEach-Object {
    Join-Path $script:TestsPath $_
} | Where-Object { Test-Path $_ }

# Run discovery to categorize tests dynamically
$discoveryConfig = New-PesterConfiguration
$discoveryConfig.Run.Path = $testFolders
$discoveryConfig.Run.PassThru = $true
$discoveryConfig.Run.SkipRun = $true  # Discovery only

Write-TestLog "Running test discovery..." -Level "DEBUG"

# Suppress Pester discovery output
$originalOut = [Console]::Out
$originalError = [Console]::Error
try {
    [Console]::SetOut([System.IO.TextWriter]::Null)
    [Console]::SetError([System.IO.TextWriter]::Null)
    $discoveryResult = Invoke-Pester -Configuration $discoveryConfig 6>&1 5>&1 4>&1 3>&1 2>&1 | Where-Object { $_ -is [Pester.Run] }
}
finally {
    [Console]::SetOut($originalOut)
    [Console]::SetError($originalError)
}

# Categorize tests based on tags and file patterns
$testCategories = @{
    Unit = @()
    Integration = @()
    System = @()
}

foreach ($test in $discoveryResult.Tests) {
    $testTags = $test.Tag
    $testFile = $test.ScriptBlock.File
    
    # Categorize based on tags first, then folder path, then file pattern
    if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
        $testCategories.System += $test
    }
    elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
        $testCategories.Integration += $test
    }
    elseif ($testFile -match "\\Integration\\") {
        $testCategories.Integration += $test
    }
    elseif ($testFile -match "\\System\\") {
        $testCategories.System += $test
    }
    elseif ($testFile -like "*Integration*.Tests.ps1") {
        $testCategories.Integration += $test
    }
    elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
        # Only categorize as System if it has System in name AND is not in Unit folder
        $testCategories.System += $test
    }
    else {
        $testCategories.Unit += $test
    }
}

# Ensure all categories are arrays even if empty
if ($null -eq $testCategories.Unit) { $testCategories.Unit = @() }
if ($null -eq $testCategories.Integration) { $testCategories.Integration = @() }
if ($null -eq $testCategories.System) { $testCategories.System = @() }

# Account for RunAsUser SYSTEM tests (4 tests that run via invoke-system-tests.ps1)
$runAsUserSystemTests = 0
if ($script:IsAdmin -and $TestType -in @('All', 'System') -and -not $SkipSystemTests) {
    $systemTestScript = Join-Path $script:TestsPath "Helpers" | Join-Path -ChildPath "invoke-system-tests.ps1"
    if (Test-Path $systemTestScript) {
        $runAsUserSystemTests = 4  # These 4 tests run via PsExec as SYSTEM user
    }
}
$systemTestCount = if ($testCategories.System) { $testCategories.System.Count } else { 0 }
$totalSystemTests = $systemTestCount + $runAsUserSystemTests

Write-TestLog "Test discovery complete: Unit=$(if ($testCategories.Unit) { $testCategories.Unit.Count } else { 0 }), Integration=$(if ($testCategories.Integration) { $testCategories.Integration.Count } else { 0 }), System=$totalSystemTests" -Level "SUMMARY" -Color Green

# If we already ran tests with unified progress, process the results now that we have categorization
if ($script:LiveProgressFullResults) {
    Write-TestLog "Processing unified progress results with discovered test categories..." -Color Cyan
    
    # Update category totals with discovered counts
    $script:Results.UnitTests.Total = if ($testCategories.Unit) { $testCategories.Unit.Count } else { 0 }
    $script:Results.IntegrationTests.Total = if ($testCategories.Integration) { $testCategories.Integration.Count } else { 0 }
    $script:Results.SystemTests.Total = if ($testCategories.System) { $testCategories.System.Count } else { 0 }
    
    # Process results to categorize passed/failed/skipped by test
    $unitPassed = 0; $unitFailed = 0; $unitSkipped = 0
    $integrationPassed = 0; $integrationFailed = 0; $integrationSkipped = 0
    $systemPassed = 0; $systemFailed = 0; $systemSkipped = 0
    
    # Process passed tests
    if ($script:LiveProgressFullResults.PesterResult.Passed) {
        foreach ($test in $script:LiveProgressFullResults.PesterResult.Passed) {
            $testFile = $test.ScriptBlock.File
            $testTags = $test.Tag
            
            if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
                $systemPassed++
            } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
                $integrationPassed++
            } elseif ($testFile -like "*Integration*.Tests.ps1") {
                $integrationPassed++
            } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
                $systemPassed++
            } else {
                $unitPassed++
            }
        }
    }
    
    # Process failed tests
    if ($script:LiveProgressFullResults.PesterResult.Failed) {
        foreach ($test in $script:LiveProgressFullResults.PesterResult.Failed) {
            $testFile = $test.ScriptBlock.File
            $testTags = $test.Tag
            
            if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
                $systemFailed++
            } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
                $integrationFailed++
            } elseif ($testFile -like "*Integration*.Tests.ps1") {
                $integrationFailed++
            } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
                $systemFailed++
            } else {
                $unitFailed++
            }
        }
    }
    
    # Process skipped tests
    if ($script:LiveProgressFullResults.PesterResult.Skipped) {
        foreach ($test in $script:LiveProgressFullResults.PesterResult.Skipped) {
            $testFile = $test.ScriptBlock.File
            $testTags = $test.Tag
            
            if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
                $systemSkipped++
            } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
                $integrationSkipped++
            } elseif ($testFile -like "*Integration*.Tests.ps1") {
                $integrationSkipped++
            } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
                $systemSkipped++
            } else {
                $unitSkipped++
            }
        }
    }
    
    # Update category results
    $script:Results.UnitTests.Passed = $unitPassed
    $script:Results.UnitTests.Failed = $unitFailed
    $script:Results.UnitTests.Skipped = $unitSkipped
    
    $script:Results.IntegrationTests.Passed = $integrationPassed
    $script:Results.IntegrationTests.Failed = $integrationFailed
    $script:Results.IntegrationTests.Skipped = $integrationSkipped
    
    $script:Results.SystemTests.Passed = $systemPassed
    $script:Results.SystemTests.Failed = $systemFailed
    $script:Results.SystemTests.Skipped = $systemSkipped
    
    # Calculate proportional durations based on test counts
    $totalDuration = $script:LiveProgressFullResults.PesterResult.Duration
    $totalExecutedTests = $unitPassed + $unitFailed + $integrationPassed + $integrationFailed + $systemPassed + $systemFailed
    
    if ($totalExecutedTests -gt 0 -and $totalDuration) {
        # Calculate duration per test
        $durationPerTest = $totalDuration.TotalMilliseconds / $totalExecutedTests
        
        # Assign proportional durations
        $unitExecuted = $unitPassed + $unitFailed
        $integrationExecuted = $integrationPassed + $integrationFailed
        $systemExecuted = $systemPassed + $systemFailed
        
        Write-TestLog "Duration calculation: Unit=$unitExecuted, Integration=$integrationExecuted, System=$systemExecuted tests executed" -Level "DEBUG"
        
        # Calculate durations
        $unitDuration = if ($unitExecuted -gt 0) { [TimeSpan]::FromMilliseconds($unitExecuted * $durationPerTest) } else { [TimeSpan]::Zero }
        $integrationDuration = if ($integrationExecuted -gt 0) { [TimeSpan]::FromMilliseconds($integrationExecuted * $durationPerTest) } else { [TimeSpan]::Zero }
        $systemDuration = if ($systemExecuted -gt 0) { [TimeSpan]::FromMilliseconds($systemExecuted * $durationPerTest) } else { [TimeSpan]::Zero }
        
        # Ensure minimum duration for categories that ran tests
        if ($unitExecuted -gt 0 -and $unitDuration.TotalMilliseconds -lt 1) { $unitDuration = [TimeSpan]::FromMilliseconds(1) }
        if ($integrationExecuted -gt 0 -and $integrationDuration.TotalMilliseconds -lt 1) { $integrationDuration = [TimeSpan]::FromMilliseconds(1) }
        if ($systemExecuted -gt 0 -and $systemDuration.TotalMilliseconds -lt 1) { $systemDuration = [TimeSpan]::FromMilliseconds(1) }
        
        $script:Results.UnitTests.Duration = $unitDuration
        $script:Results.IntegrationTests.Duration = $integrationDuration
        $script:Results.SystemTests.Duration = $systemDuration
    }
    
    # Skip normal test execution since we already have results
    $script:RunUnit = $false
    $script:RunIntegration = $false
    $script:RunSystem = $false
    
    # But we still need to run the special SYSTEM user tests via PsExec
    if ($script:IsAdmin -and $TestType -in @('All', 'System')) {
        try {
            $systemTestScript = Join-Path $script:TestsPath "Helpers" | Join-Path -ChildPath "invoke-system-tests.ps1"
            if (Test-Path $systemTestScript) {
                Write-TestLog "Running special RunAsUser SYSTEM tests..." -Color Cyan
                $systemResult = & $systemTestScript -Quiet:$CI
                
                if ($systemResult.Success) {
                    # Store the current duration before updating counts
                    $existingDuration = $script:Results.SystemTests.Duration
                    
                    # Add these test results to our System totals
                    $script:Results.SystemTests.Total += $systemResult.Results.TotalTests
                    $script:Results.SystemTests.Passed += $systemResult.Results.PassedTests
                    $script:Results.SystemTests.Failed += ($systemResult.Results.TotalTests - $systemResult.Results.PassedTests)
                    
                    # Add the duration from SYSTEM tests to existing duration
                    if ($systemResult.Results.Duration) {
                        $systemTestDuration = [TimeSpan]::FromSeconds($systemResult.Results.Duration)
                        $script:Results.SystemTests.Duration = $existingDuration.Add($systemTestDuration)
                    } elseif ($existingDuration.TotalMilliseconds -eq 0 -and $systemResult.Results.TotalTests -gt 0) {
                        # If no duration was set but tests ran, estimate based on average test time
                        $avgTestTime = 100  # milliseconds per test (reasonable estimate)
                        $estimatedDuration = [TimeSpan]::FromMilliseconds($systemResult.Results.TotalTests * $avgTestTime)
                        $script:Results.SystemTests.Duration = $estimatedDuration
                    }
                    
                    # Update global totals
                    $script:Results.TotalTests += $systemResult.Results.TotalTests
                    $script:Results.PassedTests += $systemResult.Results.PassedTests
                    $script:Results.FailedTests += ($systemResult.Results.TotalTests - $systemResult.Results.PassedTests)
                    
                    # Update live progress notification with RunAsUser SYSTEM test results
                    if ($LiveProgress -and -not $script:LiveProgressNoToast) {
                        # Update global counters for notification
                        # DO NOT update $Global:LiveProgressTotalTests - we already included these tests in the initial count
                        $Global:LiveProgressTestCount += $systemResult.Results.TotalTests
                        $Global:LiveProgressPassedCount += $systemResult.Results.PassedTests
                        $Global:LiveProgressFailedCount += ($systemResult.Results.TotalTests - $systemResult.Results.PassedTests)
                        
                        # Force a toast update with new totals
                        # Note: Don't use Update-Toast here as it increments the count
                        if (Get-Command Update-BTNotification -ErrorAction SilentlyContinue) {
                            try {
                                # Update the toast data directly
                                $Global:LiveProgressToastData.TestProgressTitle = "RunAsUser SYSTEM tests completed"
                                $Global:LiveProgressToastData.OverallProgressStatus = "$Global:LiveProgressTestCount / $Global:LiveProgressTotalTests tests"
                                $progressPercent = if ($Global:LiveProgressTotalTests -gt 0) { $Global:LiveProgressTestCount / $Global:LiveProgressTotalTests } else { 0 }
                                $Global:LiveProgressToastData.OverallProgressValue = $progressPercent
                                $Global:LiveProgressToastData.DetailsText = "✅ Passed: $Global:LiveProgressPassedCount`n❌ Failed: $Global:LiveProgressFailedCount`n⏭️ Skipped: $Global:LiveProgressSkippedCount"
                                
                                # Update notification
                                $loxoneAppId = if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
                                    Get-LoxoneToastAppId
                                } else {
                                    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
                                }
                                Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId -ErrorAction SilentlyContinue
                            } catch {
                                Write-Verbose "Failed to update toast: $_"
                            }
                        }
                    }
                    
                    # Clear skip reason since RunAsUser SYSTEM tests actually ran
                    if ($systemResult.Results.PassedTests -gt 0) {
                        $script:SystemTestSkipReason = ""  # Clear skip reason since RunAsUser tests ran
                    }
                    
                    Write-TestLog "RunAsUser SYSTEM tests: $($systemResult.Results.PassedTests)/$($systemResult.Results.TotalTests) passed" -Color $(if ($systemResult.Results.PassedTests -eq $systemResult.Results.TotalTests) { 'Green' } else { 'Yellow' })
                    
                    # Force one more toast update to ensure it shows the correct final count
                    if ($LiveProgress -and -not $script:LiveProgressNoToast -and (Get-Command Update-BTNotification -ErrorAction SilentlyContinue)) {
                        Write-TestLog "Forcing final toast update after SYSTEM tests: TestCount=$Global:LiveProgressTestCount, TotalTests=$Global:LiveProgressTotalTests" -Level "DEBUG"
                        $Global:LiveProgressToastData.TestProgressTitle = "All tests completed (including SYSTEM)"
                        $Global:LiveProgressToastData.OverallProgressStatus = "$Global:LiveProgressTestCount / $Global:LiveProgressTotalTests tests"
                        $progressPercent = if ($Global:LiveProgressTotalTests -gt 0) { [Math]::Min(1.0, $Global:LiveProgressTestCount / $Global:LiveProgressTotalTests) } else { 1.0 }
                        $Global:LiveProgressToastData.OverallProgressValue = $progressPercent
                        $Global:LiveProgressToastData.DetailsText = "✅ Passed: $Global:LiveProgressPassedCount`n❌ Failed: $Global:LiveProgressFailedCount`n⏭️ Skipped: $Global:LiveProgressSkippedCount"
                        
                        $loxoneAppId = if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
                            Get-LoxoneToastAppId
                        } else {
                            '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
                        }
                        Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId -ErrorAction SilentlyContinue
                    }
                }
            }
        } catch {
            Write-TestLog "Error running RunAsUser SYSTEM tests: $_" -Level "ERROR" -Color Red
        }
    }
}

# When running ALL tests without LiveProgress, run everything at once and categorize
# This needs to happen RIGHT AFTER discovery, before detailed output
if ($TestType -eq 'All' -and -not $LiveProgress -and -not $useUnifiedProgress) {
    Write-TestLog "`nRunning all tests and categorizing results..." -Color Cyan
    
    # Run all tests at once
    $allPaths = @("Unit", "Integration", "System") | ForEach-Object {
        Join-Path $script:TestsPath $_
    } | Where-Object { Test-Path $_ }
    
    # Run without tag filtering to get all tests
    $config = New-PesterConfiguration
    $config.Run.Path = $allPaths
    $config.Run.PassThru = $true
    
    # Set verbosity
    if ($script:DebugMode) {
        $config.Output.Verbosity = 'Diagnostic'
    } elseif ($script:Detailed) {
        $config.Output.Verbosity = 'Detailed'
    } else {
        $config.Output.Verbosity = 'Normal'
    }
    
    # Run tests
    Write-TestLog "Executing all $($discoveryResult.Tests.Count) tests..." -Color Cyan
    $allResults = Invoke-Pester -Configuration $config
    
    # Process results by category
    $unitPassed = 0; $unitFailed = 0; $unitSkipped = 0
    $integrationPassed = 0; $integrationFailed = 0; $integrationSkipped = 0
    $systemPassed = 0; $systemFailed = 0; $systemSkipped = 0
    
    # Categorize passed tests
    foreach ($test in $allResults.Passed) {
        $testFile = $test.ScriptBlock.File
        $testTags = $test.Tag
        
        if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
            $systemPassed++
        } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
            $integrationPassed++
        } elseif ($testFile -match "\\Integration\\") {
            $integrationPassed++
        } elseif ($testFile -match "\\System\\") {
            $systemPassed++
        } elseif ($testFile -like "*Integration*.Tests.ps1") {
            $integrationPassed++
        } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
            $systemPassed++
        } else {
            $unitPassed++
        }
    }
    
    # Categorize failed tests
    foreach ($test in $allResults.Failed) {
        $testFile = $test.ScriptBlock.File
        $testTags = $test.Tag
        
        if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
            $systemFailed++
        } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
            $integrationFailed++
        } elseif ($testFile -match "\\Integration\\") {
            $integrationFailed++
        } elseif ($testFile -match "\\System\\") {
            $systemFailed++
        } elseif ($testFile -like "*Integration*.Tests.ps1") {
            $integrationFailed++
        } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
            $systemFailed++
        } else {
            $unitFailed++
        }
        
        # Collect failure details
        $script:Results.FailedTestDetails += @{
            Category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                      elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                      elseif ($testFile -match "\\Integration\\") { "Integration" }
                      elseif ($testFile -match "\\System\\") { "System" }
                      elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                      elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                      else { "Unit" }
            Test = $test.ExpandedPath
            Error = $test.ErrorRecord.Exception.Message
            File = Split-Path $test.ScriptBlock.File -Leaf
            Description = $test.Name
        }
    }
    
    # Categorize skipped tests
    foreach ($test in $allResults.Skipped) {
        $testFile = $test.ScriptBlock.File
        $testTags = $test.Tag
        
        if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
            $systemSkipped++
        } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
            $integrationSkipped++
        } elseif ($testFile -match "\\Integration\\") {
            $integrationSkipped++
        } elseif ($testFile -match "\\System\\") {
            $systemSkipped++
        } elseif ($testFile -like "*Integration*.Tests.ps1") {
            $integrationSkipped++
        } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
            $systemSkipped++
        } else {
            $unitSkipped++
        }
        
        # Collect skip details
        $script:Results.SkippedTestDetails += @{
            Category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                      elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                      elseif ($testFile -match "\\Integration\\") { "Integration" }
                      elseif ($testFile -match "\\System\\") { "System" }
                      elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                      elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                      else { "Unit" }
            Test = $test.ExpandedPath
            Reason = if ($test.ErrorRecord) { $test.ErrorRecord.Exception.Message } else { "Test marked with -Skip" }
            File = Split-Path $test.ScriptBlock.File -Leaf
        }
    }
    
    # Set results for each category
    # When running unified, share the duration proportionally based on test counts
    $totalTestsRun = $allResults.TotalCount
    $unitProportion = if ($totalTestsRun -gt 0) { ($unitPassed + $unitFailed + $unitSkipped) / $totalTestsRun } else { 0 }
    $integrationProportion = if ($totalTestsRun -gt 0) { ($integrationPassed + $integrationFailed + $integrationSkipped) / $totalTestsRun } else { 0 }
    $systemProportion = if ($totalTestsRun -gt 0) { ($systemPassed + $systemFailed + $systemSkipped) / $totalTestsRun } else { 0 }
    
    $script:Results.UnitTests = @{
        Status = if ($unitFailed -eq 0) { "Passed" } else { "Failed" }
        Total = $testCategories.Unit.Count
        Passed = $unitPassed
        Failed = $unitFailed
        Skipped = $unitSkipped
        Duration = [TimeSpan]::FromMilliseconds($allResults.Duration.TotalMilliseconds * $unitProportion)
    }
    
    $script:Results.IntegrationTests = @{
        Status = if ($integrationFailed -eq 0) { "Passed" } else { "Failed" }
        Total = $testCategories.Integration.Count
        Passed = $integrationPassed
        Failed = $integrationFailed
        Skipped = $integrationSkipped
        Duration = [TimeSpan]::FromMilliseconds($allResults.Duration.TotalMilliseconds * $integrationProportion)
    }
    
    $script:Results.SystemTests = @{
        Status = if ($systemFailed -eq 0) { "Passed" } else { "Failed" }
        Total = $testCategories.System.Count
        Passed = $systemPassed
        Failed = $systemFailed
        Skipped = $systemSkipped
        Duration = [TimeSpan]::FromMilliseconds($allResults.Duration.TotalMilliseconds * $systemProportion)
    }
    
    # Update global totals
    $script:Results.TotalTests = $testCategories.Unit.Count + $testCategories.Integration.Count + $testCategories.System.Count
    $script:Results.PassedTests = $unitPassed + $integrationPassed + $systemPassed
    $script:Results.FailedTests = $unitFailed + $integrationFailed + $systemFailed
    $script:Results.SkippedTests = $unitSkipped + $integrationSkipped + $systemSkipped
    
    # Check if all System tests were skipped and set skip reason
    if ($testCategories.System.Count -gt 0 -and $systemSkipped -eq $testCategories.System.Count) {
        $script:SystemTestSkipReason = "Tests marked with -Skip flag in test file (complex dependencies)"
    }
    
    # Show detailed statistics if requested
    if ($script:Detailed) {
        Write-TestLog "`nTest execution statistics:" -Color Gray
        Write-TestLog "  Total tests run: $($allResults.TotalCount)" -Color DarkGray
        Write-TestLog "  Unit: $unitPassed passed, $unitFailed failed, $unitSkipped skipped" -Color DarkGray
        Write-TestLog "  Integration: $integrationPassed passed, $integrationFailed failed, $integrationSkipped skipped" -Color DarkGray
        Write-TestLog "  System: $systemPassed passed, $systemFailed failed, $systemSkipped skipped" -Color DarkGray
        Write-TestLog "  Total duration: $($allResults.Duration)" -Color DarkGray
        
        # Show FULL detailed test list grouped by type and file
        Write-TestLog "`n=== DETAILED TEST RESULTS BY CATEGORY ===" -Color Cyan
        
        # Collect all tests with their status and category
        $allTestsWithStatus = @()
        
        # Add passed tests
        foreach ($test in $allResults.Passed) {
            $testFile = $test.ScriptBlock.File
            $testTags = $test.Tag
            
            $category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                       elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                       elseif ($testFile -match "\\Integration\\") { "Integration" }
                       elseif ($testFile -match "\\System\\") { "System" }
                       elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                       elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                       else { "Unit" }
            
            $allTestsWithStatus += [PSCustomObject]@{
                Category = $category
                File = Split-Path $testFile -Leaf
                Name = $test.Name
                Status = "Passed"
                Duration = $test.Duration
            }
        }
        
        # Add failed tests
        foreach ($test in $allResults.Failed) {
            $testFile = $test.ScriptBlock.File
            $testTags = $test.Tag
            
            $category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                       elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                       elseif ($testFile -match "\\Integration\\") { "Integration" }
                       elseif ($testFile -match "\\System\\") { "System" }
                       elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                       elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                       else { "Unit" }
            
            $allTestsWithStatus += [PSCustomObject]@{
                Category = $category
                File = Split-Path $testFile -Leaf
                Name = $test.Name
                Status = "Failed"
                Error = $test.ErrorRecord.Exception.Message
            }
        }
        
        # Add skipped tests
        foreach ($test in $allResults.Skipped) {
            $testFile = $test.ScriptBlock.File
            $testTags = $test.Tag
            
            $category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                       elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                       elseif ($testFile -match "\\Integration\\") { "Integration" }
                       elseif ($testFile -match "\\System\\") { "System" }
                       elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                       elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                       else { "Unit" }
            
            $allTestsWithStatus += [PSCustomObject]@{
                Category = $category
                File = Split-Path $testFile -Leaf
                Name = $test.Name
                Status = "Skipped"
                Reason = if ($test.ErrorRecord) { $test.ErrorRecord.Exception.Message } else { "Test marked with -Skip" }
            }
        }
        
        # Group by category and file
        $testsByCategory = $allTestsWithStatus | Group-Object -Property Category | Sort-Object Name
        
        foreach ($categoryGroup in $testsByCategory) {
            Write-TestLog "`n--- $($categoryGroup.Name) Tests ---" -Color Yellow
            
            $testsByFile = $categoryGroup.Group | Group-Object -Property File | Sort-Object Name
            
            foreach ($fileGroup in $testsByFile) {
                Write-TestLog "  $($fileGroup.Name):" -Color Cyan
                
                foreach ($test in $fileGroup.Group | Sort-Object Name) {
                    $statusColor = switch ($test.Status) {
                        "Passed" { "Green" }
                        "Failed" { "Red" }
                        "Skipped" { "Yellow" }
                        default { "Gray" }
                    }
                    
                    $statusSymbol = switch ($test.Status) {
                        "Passed" { "✅" }
                        "Failed" { "❌" }
                        "Skipped" { "⏭️" }
                        default { "❓" }
                    }
                    
                    $testLine = "    $statusSymbol $($test.Name)"
                    if ($test.Status -eq "Failed" -and $test.Error) {
                        $testLine += " - $($test.Error.Split([Environment]::NewLine)[0])"
                    } elseif ($test.Status -eq "Skipped" -and $test.Reason) {
                        $testLine += " - $($test.Reason)"
                    }
                    
                    Write-TestLog $testLine -Color $statusColor
                }
            }
        }
    }
    
    # Skip individual category runs by marking them as done
    $script:RunUnit = $false
    $script:RunIntegration = $false
    $script:RunSystem = $false
}

# Show detailed discovery breakdown in Detailed mode
if ($script:Detailed) {
    Write-TestLog "`nDetailed test categorization:" -Color Cyan
    
    # Show sample tests from each category
    if ($testCategories.Unit.Count -gt 0) {
        Write-TestLog "  Unit test examples:" -Color Gray
        $testCategories.Unit | Select-Object -First 3 | ForEach-Object {
            Write-TestLog "    - $($_.Name) in $(Split-Path $_.ScriptBlock.File -Leaf)" -Color DarkGray
        }
        if ($testCategories.Unit.Count -gt 3) {
            Write-TestLog "    ... and $($testCategories.Unit.Count - 3) more" -Color DarkGray
        }
    }
    
    if ($testCategories.Integration.Count -gt 0) {
        Write-TestLog "  Integration test examples:" -Color Gray
        $testCategories.Integration | Select-Object -First 3 | ForEach-Object {
            Write-TestLog "    - $($_.Name) in $(Split-Path $_.ScriptBlock.File -Leaf)" -Color DarkGray
        }
        if ($testCategories.Integration.Count -gt 3) {
            Write-TestLog "    ... and $($testCategories.Integration.Count - 3) more" -Color DarkGray
        }
    }
    
    if ($testCategories.System.Count -gt 0) {
        Write-TestLog "  System test examples:" -Color Gray
        $testCategories.System | Select-Object -First 3 | ForEach-Object {
            Write-TestLog "    - $($_.Name) in $(Split-Path $_.ScriptBlock.File -Leaf)" -Color DarkGray
        }
        if ($testCategories.System.Count -gt 3) {
            Write-TestLog "    ... and $($testCategories.System.Count - 3) more" -Color DarkGray
        }
    }
}

# This duplicate block has been moved earlier in the execution flow

# Phase 1: Run Unit Tests (only when not running All tests)
if ($script:RunUnit -and $testCategories.Unit -and $testCategories.Unit.Count -gt 0) {
    Write-TestLog "`nRunning $($testCategories.Unit.Count) Unit tests..." -Color Cyan
    
    # When using LiveProgress, we need to handle this specially
    if ($LiveProgress) {
        # For LiveProgress, we'll run all tests and filter results afterward
        # This is a limitation of the current LiveProgress implementation
        Write-TestLog "Note: LiveProgress mode runs all tests together, categorizing results afterward" -Level "DEBUG"
        
        # Run only Unit tests with LiveProgress
        if ($script:RunUnit -or $script:RunIntegration -or $script:RunSystem) {
            # Only use Unit path for Unit tests
            $unitPaths = @(Join-Path $script:TestsPath "Unit")
            
            # Use proper tag filtering
            $excludeTags = @('System', 'RequiresAdmin')
            if ($TestType -eq 'Unit') {
                # When specifically running Unit tests, also exclude Integration
                $excludeTags += @('Integration', 'RequiresNetwork')
            }
            
            $liveResults = Invoke-TestsWithLiveProgress -TestPaths $unitPaths -TestFilter "*.Tests.ps1" -ExcludeTags $excludeTags
            
            if ($liveResults.PesterResult) {
                # Use discovered counts for accurate reporting
                $script:Results.UnitTests = @{
                    Status = "Completed"
                    Total = $testCategories.Unit.Count
                    Passed = [Math]::Min($liveResults.PassedTests, $testCategories.Unit.Count)
                    Failed = 0  # Will be updated from detailed results
                    Skipped = 0  # Will be updated from detailed results
                    Duration = $liveResults.Duration
                }
                
                # Store the full results for later processing
                $script:LiveProgressFullResults = $liveResults
            }
        }
    } else {
        # Use standard invocation with proper tag filtering
        $unitPaths = @(Join-Path $script:TestsPath "Unit")
        
        # For TestType=All, exclude Integration and System tests
        if ($TestType -eq 'All') {
            $excludeTags = @('Integration', 'System', 'RequiresAdmin', 'RequiresNetwork')
        } else {
            # For TestType=Unit, only exclude System tests
            $excludeTags = @('System', 'RequiresAdmin')
        }
        
        Invoke-TestCategory -CategoryName "Unit" -TestPaths $unitPaths -ExcludeTags $excludeTags -ResultsKey "UnitTests"
        
        # The above run included ALL tests because Pester doesn't properly filter by tags
        # We need to fix the counts based on what we discovered
        if ($TestType -eq 'All' -and $script:Results.UnitTests.Total -gt $testCategories.Unit.Count) {
            Write-TestLog "Correcting counts - Pester ran all tests, adjusting to match discovery" -Level "DEBUG"
            # We ran all 253 tests, but need to distribute them properly
            # This is a temporary fix until we implement proper test filtering
            $script:Results.UnitTests.Total = $testCategories.Unit.Count
            $script:Results.UnitTests.Passed = [Math]::Min($script:Results.UnitTests.Passed, $testCategories.Unit.Count)
            $script:Results.UnitTests.Failed = 0  # Will be set from actual failed test details
            $script:Results.UnitTests.Skipped = 0  # Will be set from actual skipped test details
        }
    }
}

# Phase 2: Run Integration Tests  
if ($script:RunIntegration -and $testCategories.Integration -and $testCategories.Integration.Count -gt 0) {
    Write-TestLog "`nNOTE: Integration tests may take longer and require network connectivity" -Level "WARN" -Color Yellow
    Write-TestLog "Running $($testCategories.Integration.Count) Integration tests..." -Color Cyan
    
    if ($LiveProgress) {
        # Check if we already ran tests (from Unit phase)
        if ($script:LiveProgressFullResults) {
            # LiveProgress already ran all tests, just set the results based on discovered counts
            $script:Results.IntegrationTests = @{
                Status = "Completed"
                Total = $testCategories.Integration.Count
                Passed = 0  # Will be calculated from actual results
                Failed = 0  # Will be calculated from actual results
                Skipped = 0  # Will be calculated from actual results
                Duration = [TimeSpan]::Zero  # Share the total duration
            }
        } else {
            # Need to run LiveProgress for Integration tests
            Write-TestLog "Running Integration tests with LiveProgress..." -Level "DEBUG"
            
            # Get specific files containing Integration tests
            $integrationFiles = @()
            foreach ($test in $testCategories.Integration) {
                $testFile = $test.ScriptBlock.File
                if ($testFile -and $integrationFiles -notcontains $testFile) {
                    $integrationFiles += $testFile
                }
            }
            
            Write-TestLog "Found $($integrationFiles.Count) Integration test files" -Level "DEBUG"
            
            # Debug: Log the files being passed
            foreach ($file in $integrationFiles) {
                Write-TestLog "Integration test file: $file" -Level "DEBUG"
            }
            
            # Pass specific files to LiveProgress
            if ($integrationFiles.Count -gt 0) {
                $liveResults = Invoke-TestsWithLiveProgress -TestPaths $integrationFiles -TestFilter "*.Tests.ps1" -IncludeTags @('Integration', 'RequiresNetwork') -ExcludeTags @('System', 'RequiresAdmin')
            } else {
                Write-TestLog "No Integration test files found!" -Level "WARN"
                $liveResults = @{
                    TotalTests = 0
                    PassedTests = 0
                    FailedTests = 0
                    SkippedTests = 0
                    Duration = 0
                    PesterResult = $null
                }
            }
            
            if ($liveResults.PesterResult) {
                # Store the full results for later processing
                $script:LiveProgressFullResults = $liveResults
                
                $script:Results.IntegrationTests = @{
                    Status = "Completed"
                    Total = $testCategories.Integration.Count
                    Passed = 0  # Will be updated from detailed results
                    Failed = 0  # Will be updated from detailed results
                    Skipped = 0  # Will be updated from detailed results
                    Duration = [TimeSpan]::FromSeconds($liveResults.Duration)
                }
            }
        }
    } else {
        # Run Integration tests from both Integration folder and Unit folder with Integration tags
        $integrationPaths = @()
        
        # Add Integration folder if it exists
        $integrationPath = Join-Path $script:TestsPath "Integration"
        if (Test-Path $integrationPath) {
            $integrationPaths += $integrationPath
        }
        
        # Also add Unit folder to catch Integration-tagged tests there
        $unitPath = Join-Path $script:TestsPath "Unit"
        if (Test-Path $unitPath) {
            $integrationPaths += $unitPath
        }
        
        if ($integrationPaths.Count -gt 0) {
            Invoke-TestCategory -CategoryName "Integration" -TestPaths $integrationPaths -IncludeTags @('Integration', 'RequiresNetwork') -ResultsKey "IntegrationTests"
            
            # Ensure we have results even if no tests matched
            if (-not $script:Results.IntegrationTests -or $script:Results.IntegrationTests.Total -eq 0) {
                $script:Results.IntegrationTests = @{
                    Status = "Completed"
                    Total = $testCategories.Integration.Count
                    Passed = 0
                    Failed = 0
                    Skipped = 0
                    Duration = [TimeSpan]::Zero
                }
                Write-TestLog "No Integration tests were actually run (tag filtering issue)" -Level "WARN"
            }
        }
    }
}

# Phase 3: Run SYSTEM tests
if ($script:RunSystem -and $testCategories.System -and $testCategories.System.Count -gt 0) {
    Write-TestLog "`nRunning SYSTEM tests (requires admin)..." -Color Cyan
    Write-TestLog "Found $($testCategories.System.Count) System tests to run" -Color Cyan
    
    if ($LiveProgress) {
        # Check if we already ran tests (from Unit or Integration phase)
        if ($script:LiveProgressFullResults) {
            # LiveProgress already ran all tests, just set the results based on discovered counts
            $script:Results.SystemTests = @{
                Status = "Completed"
                Total = $testCategories.System.Count
                Passed = 0  # Will be calculated from actual results
                Failed = 0  # Will be calculated from actual results
                Skipped = 0  # Will be calculated from actual results
                Duration = [TimeSpan]::Zero  # Share the total duration
            }
        } else {
            # Need to run LiveProgress for System tests
            Write-TestLog "Running System tests with LiveProgress..." -Level "DEBUG"
            
            $allTestPaths = @("Unit", "Integration", "System") | ForEach-Object {
                Join-Path $script:TestsPath $_
            } | Where-Object { Test-Path $_ }
            
            $liveResults = Invoke-TestsWithLiveProgress -TestPaths $allTestPaths -TestFilter "*.Tests.ps1"
            
            if ($liveResults.PesterResult) {
                # Store the full results for later processing
                $script:LiveProgressFullResults = $liveResults
                
                $script:Results.SystemTests = @{
                    Status = "Completed"
                    Total = $testCategories.System.Count
                    Passed = 0  # Will be updated from detailed results
                    Failed = 0  # Will be updated from detailed results
                    Skipped = 0  # Will be updated from detailed results
                    Duration = [TimeSpan]::FromSeconds($liveResults.Duration)
                }
            }
        }
    } else {
        # Run System tests from System folder and any System-tagged tests
        $systemPaths = @()
        
        # Add System folder if it exists
        $systemPath = Join-Path $script:TestsPath "System"
        if (Test-Path $systemPath) {
            $systemPaths += $systemPath
        }
        
        # Also check Unit folder for System-tagged tests
        $unitPath = Join-Path $script:TestsPath "Unit"
        if (Test-Path $unitPath) {
            $systemPaths += $unitPath
        }
        
        if ($systemPaths.Count -gt 0) {
            Invoke-TestCategory -CategoryName "System" -TestPaths $systemPaths -IncludeTags @('System', 'RequiresAdmin') -ResultsKey "SystemTests"
        }
    }
    
    # Then run special RunAsUser SYSTEM tests
    try {
        $systemTestScript = Join-Path $script:TestsPath "Helpers" | Join-Path -ChildPath "invoke-system-tests.ps1"
        if (Test-Path $systemTestScript) {
            $systemResult = & $systemTestScript -Quiet:$CI
            
            if ($systemResult.Success) {
                # If we already ran some System tests, add to existing totals
                if ($script:Results.SystemTests.Status -in @("Passed", "Failed", "Completed") -and $script:Results.SystemTests.Total -gt 0) {
                    $script:Results.SystemTests.Total += $systemResult.Results.TotalTests
                    $script:Results.SystemTests.Passed += $systemResult.Results.PassedTests
                    $script:Results.SystemTests.Failed += $systemResult.Results.TotalTests - $systemResult.Results.PassedTests
                } else {
                    # First System tests
                    $script:Results.SystemTests.Total = $systemResult.Results.TotalTests
                    $script:Results.SystemTests.Passed = $systemResult.Results.PassedTests
                    $script:Results.SystemTests.Failed = $systemResult.Results.TotalTests - $systemResult.Results.PassedTests
                }
                # Update status based on results
                $script:Results.SystemTests.Status = if ($script:Results.SystemTests.Failed -eq 0) { "Passed" } else { "Failed" }
                
                $script:Results.TotalTests += $systemResult.Results.TotalTests
                $script:Results.PassedTests += $systemResult.Results.PassedTests
                $script:Results.FailedTests += ($systemResult.Results.TotalTests - $systemResult.Results.PassedTests)
                
                # Update live progress notification with RunAsUser SYSTEM test results
                if ($LiveProgress -and -not $script:LiveProgressNoToast) {
                    # Update global counters for notification
                    # DO NOT update $Global:LiveProgressTotalTests - we already included these tests in the initial count
                    $Global:LiveProgressTestCount += $systemResult.Results.TotalTests
                    $Global:LiveProgressPassedCount += $systemResult.Results.PassedTests
                    $Global:LiveProgressFailedCount += ($systemResult.Results.TotalTests - $systemResult.Results.PassedTests)
                    
                    # Force a toast update with new totals
                    # Note: Don't use Update-Toast here as it increments the count
                    if (Get-Command Update-BTNotification -ErrorAction SilentlyContinue) {
                        try {
                            # Update the toast data directly
                            $Global:LiveProgressToastData.TestProgressTitle = "RunAsUser SYSTEM tests completed"
                            $Global:LiveProgressToastData.OverallProgressStatus = "$Global:LiveProgressTestCount / $Global:LiveProgressTotalTests tests"
                            $Global:LiveProgressToastData.DetailsText = "✅ Passed: $Global:LiveProgressPassedCount`n❌ Failed: $Global:LiveProgressFailedCount`n⏭️ Skipped: $Global:LiveProgressSkippedCount"
                            
                            # Update notification
                            $loxoneAppId = Get-LoxoneConfigToastAppId
                            Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId -ErrorAction SilentlyContinue
                        } catch {
                            Write-Verbose "Failed to update toast: $_"
                        }
                    }
                }
                
                Write-TestLog "RunAsUser SYSTEM tests: $($systemResult.Results.PassedTests)/$($systemResult.Results.TotalTests) passed" -Color $(if ($systemResult.Results.PassedTests -eq $systemResult.Results.TotalTests) { 'Green' } else { 'Yellow' })
                
                # Force one more toast update to ensure it shows the correct final count
                if ($LiveProgress -and -not $script:LiveProgressNoToast -and (Get-Command Update-BTNotification -ErrorAction SilentlyContinue)) {
                    Write-TestLog "Forcing final toast update after SYSTEM tests (phase 3): TestCount=$Global:LiveProgressTestCount, TotalTests=$Global:LiveProgressTotalTests" -Level "DEBUG"
                    $Global:LiveProgressToastData.TestProgressTitle = "All tests completed (including SYSTEM)"
                    $Global:LiveProgressToastData.OverallProgressStatus = "$Global:LiveProgressTestCount / $Global:LiveProgressTotalTests tests"
                    $progressPercent = if ($Global:LiveProgressTotalTests -gt 0) { [Math]::Min(1.0, $Global:LiveProgressTestCount / $Global:LiveProgressTotalTests) } else { 1.0 }
                    $Global:LiveProgressToastData.OverallProgressValue = $progressPercent
                    $Global:LiveProgressToastData.DetailsText = "✅ Passed: $Global:LiveProgressPassedCount`n❌ Failed: $Global:LiveProgressFailedCount`n⏭️ Skipped: $Global:LiveProgressSkippedCount"
                    
                    $loxoneAppId = if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
                        Get-LoxoneToastAppId
                    } else {
                        '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
                    }
                    Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId -ErrorAction SilentlyContinue
                }
                
                # Show error details for failed tests if any
                if ($systemResult.Results.PassedTests -lt $systemResult.Results.TotalTests) {
                    Write-TestLog "SYSTEM test error details:" -Color Yellow
                    if ($systemResult.Results.Test1_Error) { 
                        Write-TestLog "  Test 1 (Simple Execution): $($systemResult.Results.Test1_Error)" -Color Red 
                        if ($systemResult.Results.Test1_Result) { Write-TestLog "    Actual result: '$($systemResult.Results.Test1_Result)'" -Color Gray }
                    }
                    if ($systemResult.Results.Test2_Error) { 
                        Write-TestLog "  Test 2 (Context Switch): $($systemResult.Results.Test2_Error)" -Color Red 
                        if ($systemResult.Results.Test2_Result) { Write-TestLog "    Actual result: '$($systemResult.Results.Test2_Result)'" -Color Gray }
                    }
                    if ($systemResult.Results.Test3_Error) { Write-TestLog "  Test 3 (NoWait): $($systemResult.Results.Test3_Error)" -Color Red }
                    if ($systemResult.Results.Test4_Error) { Write-TestLog "  Test 4 (File Execution): $($systemResult.Results.Test4_Error)" -Color Red }
                }
            } else {
                $script:Results.SystemTests.Status = "Failed: $($systemResult.Error)"
                Write-TestLog "SYSTEM tests failed: $($systemResult.Error)" -Level "WARN" -Color Yellow
            }
        } else {
            # Try running system tests with tags - look in both Unit and System folders
            $systemPaths = @(
                Join-Path $script:TestsPath "Unit",
                Join-Path $script:TestsPath "System"
            )
            Invoke-TestCategory -CategoryName "System" -TestPaths $systemPaths -IncludeTags @('System', 'RequiresAdmin') -ResultsKey "SystemTests"
        }
    } catch {
        $script:Results.SystemTests.Status = "Error: $_"
        Write-TestLog "Error running SYSTEM tests: $_" -Level "ERROR" -Color Red
    }
} else {
    # System tests were requested but couldn't run (no admin privileges)
    if ($TestType -in @('All', 'System') -and -not $script:IsAdmin) {
        # Mark system tests status but don't count as skipped in global totals
        $systemTestCount = 4  # Based on invoke-system-tests.ps1
        # Only add to skipped if explicitly requested (System or All)
        if ($TestType -eq 'System') {
            # System tests were explicitly requested but can't run - count as skipped
            $script:Results.SkippedTests += $systemTestCount
            $script:Results.TotalTests += $systemTestCount
        }
        $script:Results.SystemTests.Total = $systemTestCount
        $script:Results.SystemTests.Skipped = $systemTestCount
        $script:Results.SystemTests.Status = "Requires admin"
        
        Write-TestLog "SYSTEM tests: $systemTestCount tests require admin privileges" -Color Yellow
    }
}

# Post-process LiveProgress results to properly categorize by discovered tests
if ($LiveProgress -and $script:LiveProgressFullResults) {
    Write-TestLog "`nPost-processing LiveProgress results to match discovered categorization..." -Level "DEBUG"
    
    # Get the actual Pester result for detailed analysis
    $pesterResult = $script:LiveProgressFullResults.PesterResult
    
    # Process failed tests to categorize them
    $unitFailed = 0
    $integrationFailed = 0
    $systemFailed = 0
    
    if ($pesterResult -and $pesterResult.Failed) {
        foreach ($failure in $pesterResult.Failed) {
            $testFile = $failure.ScriptBlock.File
            $testTags = $failure.Tag
            
            # Categorize the failure
            if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
                $systemFailed++
            } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
                $integrationFailed++
            } elseif ($testFile -match "\\Integration\\") {
                $integrationFailed++
            } elseif ($testFile -match "\\System\\") {
                $systemFailed++
            } elseif ($testFile -like "*Integration*.Tests.ps1") {
                $integrationFailed++
            } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
                $systemFailed++
            } else {
                $unitFailed++
            }
            
            # Collect failure details
            $script:Results.FailedTestDetails += @{
                Category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                          elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                          elseif ($testFile -match "\\Integration\\") { "Integration" }
                          elseif ($testFile -match "\\System\\") { "System" }
                          elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                          elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                          else { "Unit" }
                Test = $failure.ExpandedPath
                Error = $failure.ErrorRecord.Exception.Message
                File = Split-Path $failure.ScriptBlock.File -Leaf
                Description = $failure.Name
            }
        }
    }
    
    # Process skipped tests
    $unitSkipped = 0
    $integrationSkipped = 0
    $systemSkipped = 0
    
    # Check if we already have skipped test details (from earlier LiveProgress processing)
    $alreadyHaveSkippedDetails = $script:Results.SkippedTestDetails.Count -gt 0
    
    if ($pesterResult -and $pesterResult.Skipped) {
        foreach ($skipped in $pesterResult.Skipped) {
            $testFile = $skipped.ScriptBlock.File
            $testTags = $skipped.Tag
            
            # Categorize the skip
            if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') {
                $systemSkipped++
            } elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') {
                $integrationSkipped++
            } elseif ($testFile -match "\\Integration\\") {
                $integrationSkipped++
            } elseif ($testFile -match "\\System\\") {
                $systemSkipped++
            } elseif ($testFile -like "*Integration*.Tests.ps1") {
                $integrationSkipped++
            } elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") {
                $systemSkipped++
            } else {
                $unitSkipped++
            }
            
            # Only collect skip details if we don't already have them
            if (-not $alreadyHaveSkippedDetails) {
                $script:Results.SkippedTestDetails += @{
                    Category = if ($testTags -contains 'System' -or $testTags -contains 'RequiresAdmin') { "System" }
                              elseif ($testTags -contains 'Integration' -or $testTags -contains 'RequiresNetwork') { "Integration" }
                              elseif ($testFile -match "\\Integration\\") { "Integration" }
                              elseif ($testFile -match "\\System\\") { "System" }
                              elseif ($testFile -like "*Integration*.Tests.ps1") { "Integration" }
                              elseif ($testFile -like "*System*.Tests.ps1" -and $testFile -notmatch "\\Unit\\") { "System" }
                              else { "Unit" }
                    Test = $skipped.ExpandedPath
                    Reason = if ($skipped.ErrorRecord) { $skipped.ErrorRecord.Exception.Message } else { "Test marked with -Skip" }
                    File = Split-Path $skipped.ScriptBlock.File -Leaf
                }
            }
        }
    }
    
    # Update category results with accurate counts
    if ($script:RunUnit) {
        $script:Results.UnitTests.Failed = $unitFailed
        $script:Results.UnitTests.Skipped = $unitSkipped
        $script:Results.UnitTests.Passed = $testCategories.Unit.Count - $unitFailed - $unitSkipped
        $script:Results.UnitTests.Status = if ($unitFailed -eq 0) { "Passed" } else { "Failed" }
    }
    
    if ($script:RunIntegration) {
        $script:Results.IntegrationTests.Failed = $integrationFailed
        $script:Results.IntegrationTests.Skipped = $integrationSkipped
        $script:Results.IntegrationTests.Passed = $testCategories.Integration.Count - $integrationFailed - $integrationSkipped
        $script:Results.IntegrationTests.Status = if ($integrationFailed -eq 0) { "Passed" } else { "Failed" }
    }
    
    if ($script:RunSystem) {
        # Only update if we haven't already added RunAsUser SYSTEM test results
        # RunAsUser tests add 4 to the total, so check if Total > discovered count
        $hasRunAsUserResults = $script:Results.SystemTests.Total -gt $testCategories.System.Count
        
        if ($hasRunAsUserResults) {
            # RunAsUser tests have been added, only update the regular test counts
            # Keep the Total as is (includes RunAsUser), but update passed/failed/skipped for regular tests
            $regularSystemPassed = $testCategories.System.Count - $systemFailed - $systemSkipped
            # The Passed count should include both regular passed + RunAsUser passed
            # RunAsUser passed count = current Passed - previous regular passed estimate
            $runAsUserPassed = $script:Results.SystemTests.Passed - ($script:Results.SystemTests.Total - 4)
            $script:Results.SystemTests.Passed = $regularSystemPassed + $runAsUserPassed
            $script:Results.SystemTests.Failed = $systemFailed + $script:Results.SystemTests.Failed
            $script:Results.SystemTests.Skipped = $systemSkipped
        } else {
            # No RunAsUser results yet, update normally
            $script:Results.SystemTests.Failed = $systemFailed
            $script:Results.SystemTests.Skipped = $systemSkipped
            $script:Results.SystemTests.Passed = $testCategories.System.Count - $systemFailed - $systemSkipped
        }
        $script:Results.SystemTests.Status = if ($script:Results.SystemTests.Failed -eq 0) { "Passed" } else { "Failed" }
    }
    
    # Share the duration proportionally based on actual tests run
    if ($pesterResult -and $pesterResult.Duration) {
        $totalDuration = $pesterResult.Duration
        $totalTestsRun = $unitPassed + $unitFailed + $unitSkipped + $integrationPassed + $integrationFailed + $integrationSkipped + $systemPassed + $systemFailed + $systemSkipped
        
        if ($totalTestsRun -gt 0) {
            $unitCount = $unitPassed + $unitFailed + $unitSkipped
            $integrationCount = $integrationPassed + $integrationFailed + $integrationSkipped
            $systemCount = $systemPassed + $systemFailed + $systemSkipped
            
            if ($script:RunUnit -and $unitCount -gt 0) {
                $script:Results.UnitTests.Duration = [TimeSpan]::FromMilliseconds($totalDuration.TotalMilliseconds * ($unitCount / $totalTestsRun))
            }
            if ($script:RunIntegration -and $integrationCount -gt 0) {
                $script:Results.IntegrationTests.Duration = [TimeSpan]::FromMilliseconds($totalDuration.TotalMilliseconds * ($integrationCount / $totalTestsRun))
            }
            if ($script:RunSystem -and $systemCount -gt 0) {
                $script:Results.SystemTests.Duration = [TimeSpan]::FromMilliseconds($totalDuration.TotalMilliseconds * ($systemCount / $totalTestsRun))
            }
        }
    }
    
    # Update global totals to match discovered counts
    $script:Results.TotalTests = 0
    $script:Results.PassedTests = 0
    $script:Results.FailedTests = 0
    $script:Results.SkippedTests = 0
    
    foreach ($category in @('UnitTests', 'IntegrationTests', 'SystemTests')) {
        if ($script:Results[$category].Total -gt 0) {
            $script:Results.TotalTests += $script:Results[$category].Total
            $script:Results.PassedTests += $script:Results[$category].Passed
            $script:Results.FailedTests += $script:Results[$category].Failed
            $script:Results.SkippedTests += $script:Results[$category].Skipped
        }
    }
    
    Write-TestLog "LiveProgress post-processing complete. Totals: Unit=$($script:Results.UnitTests.Total), Integration=$($script:Results.IntegrationTests.Total), System=$($script:Results.SystemTests.Total)" -Level "DEBUG"
    
    # Debug System test results and set skip reason
    if ($testCategories.System.Count -gt 0) {
        Write-TestLog "System test details: Discovered=$($testCategories.System.Count), Passed=$systemPassed, Failed=$systemFailed, Skipped=$systemSkipped" -Level "DEBUG"
        if ($systemSkipped -eq $testCategories.System.Count -and $systemSkipped -gt 0) {
            Write-TestLog "All System tests were skipped - check test prerequisites or dependencies" -Level "WARN"
            $script:SystemTestSkipReason = "Tests marked with -Skip flag in test file (complex dependencies)"
        }
    }
}

# Compatibility: Update StandardTests from UnitTests for backward compatibility
$script:Results.StandardTests = $script:Results.UnitTests

# Parse XML results if needed (handled by Invoke-TestCategory now)

# Count tests that were not requested as skipped for coverage reporting
# This provides a complete picture of test coverage across all available tests
if ($TestType -ne 'All') {
    # Estimate test counts for categories that weren't run
    $estimatedIntegrationTests = 13  # Based on typical test suite
    $estimatedSystemTests = 4        # Based on invoke-system-tests.ps1
    
    # Mark integration tests status if not run (but don't add to skipped count)
    if (-not $script:RunIntegration) {
        $script:Results.IntegrationTests.Total = $estimatedIntegrationTests
        $script:Results.IntegrationTests.Skipped = $estimatedIntegrationTests
        $script:Results.IntegrationTests.Status = "Not requested"
        # Don't add to global skipped/total counts - these weren't requested
        # $script:Results.SkippedTests += $estimatedIntegrationTests
        # $script:Results.TotalTests += $estimatedIntegrationTests
    }
    
    # Mark system tests status if not run (but don't add to skipped count)
    if (-not $script:RunSystem) {
        # Don't double-count if already handled above for no admin
        if ($script:Results.SystemTests.Status -ne "Skipped (no admin)") {
            $script:Results.SystemTests.Total = $estimatedSystemTests
            $script:Results.SystemTests.Skipped = $estimatedSystemTests
            $script:Results.SystemTests.Status = if (-not $script:IsAdmin) { "Requires admin" } else { "Not requested" }
            # Don't add to global skipped/total counts - these weren't requested
            # $script:Results.SkippedTests += $estimatedSystemTests
            # $script:Results.TotalTests += $estimatedSystemTests
        }
    }
}

# Calculate pass rate
$passRate = if ($script:Results.TotalTests -gt 0) {
    [math]::Round(($script:Results.PassedTests / $script:Results.TotalTests) * 100, 2)
} else { 0 }

# Update final toast notification with complete results (including SYSTEM tests)
if ($LiveProgress -and -not $script:LiveProgressNoToast -and (Get-Command Update-BTNotification -ErrorAction SilentlyContinue)) {
    try {
        # Debug log current state
        Write-TestLog "Final toast update - Current LiveProgress counts: Test=$Global:LiveProgressTestCount, Total=$Global:LiveProgressTotalTests" -Level "DEBUG"
        Write-TestLog "Final toast update - Script results: Total=$($script:Results.TotalTests), Passed=$($script:Results.PassedTests), Failed=$($script:Results.FailedTests), Skipped=$($script:Results.SkippedTests)" -Level "DEBUG"
        
        # Ensure global counters reflect ALL tests including SYSTEM tests
        if ($Global:LiveProgressTestCount -ne $script:Results.TotalTests -or $Global:LiveProgressTotalTests -ne $script:Results.TotalTests) {
            Write-TestLog "Updating LiveProgress final counts: TestCount=$($script:Results.TotalTests), TotalTests=$($script:Results.TotalTests), Passed=$($script:Results.PassedTests), Failed=$($script:Results.FailedTests), Skipped=$($script:Results.SkippedTests)" -Level "DEBUG"
            $Global:LiveProgressTestCount = $script:Results.TotalTests
            $Global:LiveProgressTotalTests = $script:Results.TotalTests  # Also update the total to ensure consistency
            $Global:LiveProgressPassedCount = $script:Results.PassedTests
            $Global:LiveProgressFailedCount = $script:Results.FailedTests
            $Global:LiveProgressSkippedCount = $script:Results.SkippedTests
        }
        
        # Update the toast data for final display
        $Global:LiveProgressToastData.TestProgressTitle = "All tests completed"
        $Global:LiveProgressToastData.OverallProgressStatus = "$($script:Results.TotalTests) / $($script:Results.TotalTests) tests"
        $Global:LiveProgressToastData.OverallProgressValue = 1.0  # 100% complete
        $Global:LiveProgressToastData.DetailsText = "✅ Passed: $($script:Results.PassedTests)`n❌ Failed: $($script:Results.FailedTests)`n⏭️ Skipped: $($script:Results.SkippedTests)"
        
        # Calculate runtime
        if ($Global:LiveProgressStartTime) {
            $runtime = (Get-Date) - $Global:LiveProgressStartTime
            $minutes = [math]::Floor($runtime.TotalMinutes)
            $seconds = [math]::Floor($runtime.TotalSeconds % 60)
            $runtimeDisplay = $minutes.ToString() + ":" + $seconds.ToString('00')
            $Global:LiveProgressToastData.StatusText = "Completed | $runtimeDisplay | $passRate% pass rate"
        }
        
        # Update notification
        $loxoneAppId = if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
            Get-LoxoneToastAppId
        } else {
            '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        }
        Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressToastData -AppId $loxoneAppId -ErrorAction SilentlyContinue
        Write-TestLog "Final toast notification updated with complete test results" -Level "DEBUG"
    } catch {
        Write-Verbose "Failed to update final toast: $_"
    }
}

# Export results
$summaryData = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Overall = @{
        Total = $script:Results.TotalTests
        Passed = $script:Results.PassedTests
        Failed = $script:Results.FailedTests
        Skipped = $script:Results.SkippedTests
        PassRate = $passRate
    }
    UnitTests = @{
        Status = $script:Results.UnitTests.Status
        Total = $script:Results.UnitTests.Total
        Passed = $script:Results.UnitTests.Passed
        Failed = $script:Results.UnitTests.Failed
        Duration = if ($script:Results.UnitTests.Duration) { $script:Results.UnitTests.Duration.ToString() } else { "00:00:00" }
    }
    IntegrationTests = @{
        Status = $script:Results.IntegrationTests.Status
        Total = $script:Results.IntegrationTests.Total
        Passed = $script:Results.IntegrationTests.Passed
        Failed = $script:Results.IntegrationTests.Failed
        Skipped = if ($script:Results.IntegrationTests.ContainsKey('Skipped')) { $script:Results.IntegrationTests.Skipped } else { 0 }
        Duration = if ($script:Results.IntegrationTests.Duration) { $script:Results.IntegrationTests.Duration.ToString() } else { "00:00:00" }
    }
    SystemTests = @{
        Status = $script:Results.SystemTests.Status
        Total = $script:Results.SystemTests.Total
        Passed = $script:Results.SystemTests.Passed
        Failed = $script:Results.SystemTests.Failed
        Skipped = if ($script:Results.SystemTests.ContainsKey('Skipped')) { $script:Results.SystemTests.Skipped } else { 0 }
    }
}

$summaryPath = Join-Path $script:ResultsPath "test-results-summary.json"
$summaryData | ConvertTo-Json -Depth 3 | Out-File -FilePath $summaryPath -Encoding UTF8

# Export detailed results if failed tests exist
if ($script:Results.FailedTestDetails.Count -gt 0) {
    $detailedPath = Join-Path $script:ResultsPath "test-results-failed-details.json"
    $script:Results.FailedTestDetails | ConvertTo-Json -Depth 3 | Out-File -FilePath $detailedPath -Encoding UTF8
}

# Show detailed test listing when requested and using LiveProgress
if ($script:Detailed -and $script:LiveProgressFullResults -and $script:LiveProgressFullResults.PesterResult) {
    Write-TestLog "`n=== DETAILED TEST LISTING ===" -Color Cyan
    
    # Collect all tests from LiveProgress results
    $allTestsDetailed = @()
    
    # Add passed tests
    if ($script:LiveProgressFullResults.PesterResult.Passed) {
        foreach ($test in $script:LiveProgressFullResults.PesterResult.Passed) {
            $allTestsDetailed += @{
                Status = "Passed"
                Test = $test
            }
        }
    }
    
    # Add failed tests
    if ($script:LiveProgressFullResults.PesterResult.Failed) {
        foreach ($test in $script:LiveProgressFullResults.PesterResult.Failed) {
            $allTestsDetailed += @{
                Status = "Failed"
                Test = $test
            }
        }
    }
    
    # Add skipped tests
    if ($script:LiveProgressFullResults.PesterResult.Skipped) {
        foreach ($test in $script:LiveProgressFullResults.PesterResult.Skipped) {
            $allTestsDetailed += @{
                Status = "Skipped"
                Test = $test
            }
        }
    }
    
    # Group by file and display
    $testsByFile = $allTestsDetailed | Group-Object -Property { $_.Test.ScriptBlock.File } | Sort-Object Name
    
    foreach ($fileGroup in $testsByFile) {
        $fileName = Split-Path $fileGroup.Name -Leaf
        $shortName = $fileName -replace '\.Tests\.ps1$', ''
        
        # Determine category from file path
        $category = "Unit"
        if ($fileGroup.Name -match "\\Integration\\") {
            $category = "Integration"
        } elseif ($fileGroup.Name -match "\\System\\") {
            $category = "System"
        }
        
        Write-TestLog "`n$shortName [$category] ($($fileGroup.Count) tests):" -Color Yellow
        
        # Group by describe block
        $testsByDescribe = $fileGroup.Group | Group-Object -Property { 
            if ($_.Test.ExpandedPath -match '^([^.]+)\..+$') { $matches[1] } else { "Tests" }
        } | Sort-Object Name
        
        foreach ($describeGroup in $testsByDescribe) {
            Write-TestLog "  $($describeGroup.Name):" -Color Cyan
            
            foreach ($item in $describeGroup.Group | Sort-Object { $_.Test.Name }) {
                $test = $item.Test
                $testName = $test.Name
                
                # Status symbol
                $statusSymbol = switch ($item.Status) {
                    "Passed" { "✅" }
                    "Failed" { "❌" }
                    "Skipped" { "⏭️" }
                    default { "❓" }
                }
                
                # Status color
                $statusColor = switch ($item.Status) {
                    "Passed" { "Green" }
                    "Failed" { "Red" }
                    "Skipped" { "Cyan" }
                    default { "Gray" }
                }
                
                Write-TestLog "    $statusSymbol $testName" -Color $statusColor
                
                # Show error for failed tests
                if ($item.Status -eq "Failed" -and $test.ErrorRecord) {
                    $errorMsg = $test.ErrorRecord.Exception.Message
                    if ($errorMsg.Length -gt 100) {
                        $errorMsg = $errorMsg.Substring(0, 97) + "..."
                    }
                    Write-TestLog "      Error: $errorMsg" -Color DarkRed
                }
            }
        }
    }
    
    # Show summary counts
    $passedCount = ($allTestsDetailed | Where-Object { $_.Status -eq "Passed" }).Count
    $failedCount = ($allTestsDetailed | Where-Object { $_.Status -eq "Failed" }).Count
    $skippedCount = ($allTestsDetailed | Where-Object { $_.Status -eq "Skipped" }).Count
    
    Write-TestLog "`nDetailed Summary: $passedCount passed, $failedCount failed, $skippedCount skipped" -Color Cyan
}

# Generate coverage report (before test summary)
if ($Coverage) {
    Write-TestLog "`n========================================" -Level "COVERAGE" -Color Cyan
    Write-TestLog "CODE COVERAGE ANALYSIS" -Level "COVERAGE" -Color Cyan
    Write-TestLog "========================================" -Level "COVERAGE" -Color Cyan
    
    try {
        # Find coverage module
        $rootPath = Split-Path $PSScriptRoot -Parent
        $coverageModule = Get-ChildItem -Path $rootPath -Recurse -Filter "LoxoneUtils.TestCoverage.psm1" | Select-Object -First 1
        if (-not $coverageModule) {
            Write-TestLog "Coverage module not found" -Level "ERROR" -Color Red
        } else {
            # Import module if function not already available
            if (-not (Get-Command -Name New-TestCoverageReport -ErrorAction SilentlyContinue)) {
                Import-Module $coverageModule -Force
            }
            
            # Use central coverage folder instead of individual TestRun folder
            $centralCoverageDir = Join-Path $script:TestsPath "TestResults"
            
            # Run coverage analysis
            $coverageParams = @{
                ShowConsole = $true
                CheckUsage = $true  # Enable usage analysis to detect dead code
                OutputDirectory = $centralCoverageDir
                TestResultsPath = $script:CurrentRunPath  # Point to current test run for test results
                IncludeTestResults = $true  # Include test results by default
                TestRunId = $script:TestRunId  # Pass the test run ID for synchronized timestamps
                CI = $CI  # Pass CI flag to suppress verbose output
                # InvocationInfo is handled internally by New-TestCoverageReport
            }
            
            # Validate OutputDirectory before calling coverage
            if ([string]::IsNullOrWhiteSpace($centralCoverageDir)) {
                Write-TestLog "ERROR: Central coverage directory path is null or empty" -Level "ERROR" -Color Red
                $coverageParams.OutputDirectory = $script:TestsPath
            } elseif (-not (Test-Path $centralCoverageDir)) {
                Write-TestLog "Creating central coverage directory: $centralCoverageDir" -Level "INFO" -Color Yellow
                New-Item -ItemType Directory -Path $centralCoverageDir -Force | Out-Null
            }
            
            if ($CI) {
                # In CI mode, suppress verbose console output but capture the result
                $coverageParams.ShowConsole = $false  # Disable console output
                Write-TestLog "Generating coverage report in CI mode..." -Color Gray
                
                # Temporarily redirect console output to suppress Pester discovery messages
                $originalOut = [Console]::Out
                $originalError = [Console]::Error
                try {
                    [Console]::SetOut([System.IO.TextWriter]::Null)
                    [Console]::SetError([System.IO.TextWriter]::Null)
                    $coverageResult = New-TestCoverageReport @coverageParams
                }
                finally {
                    [Console]::SetOut($originalOut)
                    [Console]::SetError($originalError)
                }
            } else {
                Write-TestLog "Generating coverage report..." -Color Gray
                $coverageResult = New-TestCoverageReport @coverageParams
            }
            
            
            if ($CI -and $coverageResult) {
                # In CI mode, show only essential coverage info
                Write-TestLog "KPIs: TestCount/TestExecution%/TestSuccess%/Coverage%/DeadCode%/DeadTests%" -Level "COVERAGE" -Color Gray
                Write-TestLog "Coverage: $($coverageResult.CoverageResult.TotalCoverage)% | KPIs: $($coverageResult.KPIs)" -Level "COVERAGE" -Color $(
                    if ($coverageResult.CoverageResult.TotalCoverage -ge 80) { 'Green' }
                    elseif ($coverageResult.CoverageResult.TotalCoverage -ge 60) { 'Yellow' }
                    else { 'Red' }
                )
            } elseif ($coverageResult) {
                Write-TestLog "`nCoverage report generated:" -Color Green
                Write-TestLog "  Location: $($coverageResult.ReportPath)" -Color Gray
                Write-TestLog "  Runtime: $($coverageResult.Runtime)" -Color Gray
                Write-TestLog "  KPIs Format: TestCount/TestExecution%/TestSuccess%/Coverage%/DeadCode%/DeadTests%" -Color Gray
                Write-TestLog "  KPIs: $($coverageResult.KPIs)" -Color Gray
                Write-TestLog "  Overall Coverage: $($coverageResult.CoverageResult.TotalCoverage)%" -Color $(
                    if ($coverageResult.CoverageResult.TotalCoverage -ge 80) { 'Green' }
                    elseif ($coverageResult.CoverageResult.TotalCoverage -ge 60) { 'Yellow' }
                    else { 'Red' }
                )
            }
        }
    }
    catch {
        Write-TestLog "Failed to generate coverage report: $_" -Level "ERROR" -Color Red
        Write-TestLog "Exception Type: $($_.Exception.GetType().FullName)" -Level "ERROR" -Color Red
        Write-TestLog "Stack Trace: $($_.Exception.StackTrace)" -Level "ERROR" -Color Red
    }
}

# Display summary
Write-TestLog "`n========================================" -Level "SUMMARY" -Color Cyan
Write-TestLog "TEST RUN SUMMARY" -Level "SUMMARY" -Color Cyan
Write-TestLog "========================================" -Level "SUMMARY" -Color Cyan

# Show invocation parameters
$invocationParams = @()
if ($TestType -ne 'Unit') { $invocationParams += "TestType=$TestType" }
if ($SkipSystemTests) { $invocationParams += "SkipSystemTests" }
if ($IncludeIntegration) { $invocationParams += "IncludeIntegration" }
if ($Detailed) { $invocationParams += "Detailed" }
if ($DebugMode) { $invocationParams += "DebugMode" }
if ($CI) { $invocationParams += "CI" }
if ($LiveProgress) { $invocationParams += "LiveProgress" }
if ($Coverage) { $invocationParams += "Coverage" }
if ($CleanupTestFiles) { $invocationParams += "CleanupTestFiles" }
if ($WhatIf) { $invocationParams += "WhatIf" }
if ($Filter) { $invocationParams += "Filter='$Filter'" }
if ($Tag.Count -gt 0) { $invocationParams += "Tag=$($Tag -join ',')" }
if ($ExcludeTag.Count -gt 0) { $invocationParams += "ExcludeTag=$($ExcludeTag -join ',')" }
if ($OutputFormat -ne 'Console') { $invocationParams += "OutputFormat=$OutputFormat" }
if ($Timeout -ne 120) { $invocationParams += "Timeout=$Timeout" }
if (-not $LogToFile) { $invocationParams += "NoLogFile" }
if ($SuppressErrorOutput) { $invocationParams += "SuppressErrorOutput" }

$invocationString = if ($invocationParams.Count -gt 0) { " ($($invocationParams -join ', '))" } else { "" }
Write-TestLog "Invocation: .\run-tests.ps1$invocationString" -Level "SUMMARY" -Color Gray
Write-TestLog "Running as Admin: $($script:IsAdmin) | User: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Level "SUMMARY" -Color Gray
Write-TestLog "" -Level "SUMMARY"

Write-TestLog "Total Tests: $($script:Results.TotalTests)" -Level "SUMMARY"
Write-TestLog "Passed: $($script:Results.PassedTests)" -Level "SUMMARY" -Color Green
Write-TestLog "Failed: $($script:Results.FailedTests)" -Level "SUMMARY" -Color $(if ($script:Results.FailedTests -eq 0) { 'Green' } else { 'Red' })
if ($script:Results.SkippedTests -gt 0) {
    Write-TestLog "Skipped: $($script:Results.SkippedTests)" -Level "SUMMARY" -Color Cyan
}
Write-TestLog "Pass Rate: $passRate%`n" -Level "SUMMARY" -Color $(if ($passRate -ge 80) { 'Green' } elseif ($passRate -ge 60) { 'Yellow' } else { 'Red' })

# Show results by category - dynamically discover from results
$categoryMapping = @{
    "UnitTests" = "Unit Tests"
    "IntegrationTests" = "Integration Tests"
    "SystemTests" = "System Tests"
}

# Get all test result keys that match our known categories
$testResultKeys = $script:Results.Keys | Where-Object { 
    $_ -in @("UnitTests", "IntegrationTests", "SystemTests") 
} | Sort-Object

foreach ($resultKey in $testResultKeys) {
    $result = $script:Results[$resultKey]
    
    # Skip if no result object
    if (-not $result) {
        continue
    }
    
    # Skip categories that weren't run and have no data
    if ($result.Status -eq "Not Run" -and $result.Total -eq 0) {
        continue
    }
    
    # Get display name
    $displayName = if ($categoryMapping.ContainsKey($resultKey)) {
        $categoryMapping[$resultKey]
    } else {
        # Fallback: convert key to readable format
        $resultKey -replace 'Tests$', ' Tests'
    }
    
    # Build display line
    $displayText = "${displayName}: "
    
    # Extract counts with null safety
    $passedCount = if ($null -ne $result.Passed) { $result.Passed } else { 0 }
    $totalCount = if ($null -ne $result.Total) { $result.Total } else { 0 }
    $failedCount = if ($null -ne $result.Failed) { $result.Failed } else { 0 }
    $skippedCount = if ($null -ne $result.Skipped) { $result.Skipped } else { 0 }
    
    if ($result.Status -in @("Not requested", "Requires admin", "Not Run")) {
        # Special status messages
        Write-TestLog "$displayText$($result.Status)" -Level "SUMMARY" -Color Gray
    } elseif ($totalCount -eq 0 -and $result.Status -in @("Completed", "Passed", "Failed")) {
        # Category was run but had no tests
        Write-TestLog "${displayText}0 tests found" -Level "SUMMARY" -Color Yellow
    } else {
        # Build consistent status line
        $statusLine = "$passedCount/$totalCount passed ($failedCount failed) [$skippedCount skipped"
        
        # Add skip reason for System tests if there are skipped tests and we have a reason
        # But only show it if it makes sense (not when RunAsUser tests passed)
        if ($resultKey -eq "SystemTests" -and $script:SystemTestSkipReason -and $skippedCount -gt 0) {
            # Show skip reason inline only if it's meaningful in context
            if ($passedCount -eq 0) {
                # All tests were skipped
                $statusLine += ": $script:SystemTestSkipReason"
            } elseif ($skippedCount -gt 4) {
                # Many tests skipped, but some passed (likely RunAsUser tests)
                $statusLine += " - regular tests skipped"
            }
        }
        $statusLine += "]"
        
        # Add duration if available - ensure it's set for all categories
        if ($result.Duration -and $result.Duration -is [TimeSpan]) {
            $statusLine += " - $($result.Duration.ToString('mm\:ss\.fff'))"
        } elseif ($totalCount -gt 0 -and ($passedCount + $failedCount) -gt 0) {
            # If duration is missing but tests ran, show placeholder
            $statusLine += " - --:---.---"
        }
        
        # Determine color based on results
        $color = if ($failedCount -eq 0 -and $totalCount -gt 0) { 'Green' } 
                elseif ($failedCount -gt 0) { 'Red' }
                elseif ($totalCount -eq 0) { 'Yellow' }
                else { 'Gray' }
        
        Write-TestLog "$displayText$statusLine" -Level "SUMMARY" -Color $color
    }
}

# Show total duration
$totalDuration = [TimeSpan]::Zero
foreach ($category in @('UnitTests', 'IntegrationTests', 'SystemTests')) {
    if ($script:Results[$category].Duration) {
        $totalDuration = $totalDuration.Add($script:Results[$category].Duration)
    }
}
if ($totalDuration.TotalSeconds -gt 0) {
    # Always show total duration, even in CI mode
    Write-Host "`nTotal Duration: $($totalDuration.ToString('mm\:ss\.fff'))" -ForegroundColor Gray
}

# Show failed test summary
if ($script:Results.FailedTests -gt 0) {
    Write-TestLog "`n=== FAILED TESTS SUMMARY ===" -Color Red
    
    # Debug: Show what we have
    if ($script:Detailed -or $script:DebugMode) {
        Write-TestLog "Failed test details count: $($script:Results.FailedTestDetails.Count)" -Level "DEBUG"
    }
    
    # Group failures by file and show in a compact format
    $failuresByFile = $script:Results.FailedTestDetails | Where-Object { $_.File } | Group-Object -Property File | Sort-Object Count -Descending
    
    # Check if we have any files
    if ($failuresByFile.Count -eq 0) {
        # No file information available, check if we have any details at all
        if ($script:Results.FailedTestDetails.Count -gt 0) {
            Write-TestLog "Total: $($script:Results.FailedTests) failed test(s)" -Color Red
            
            # Show whatever details we have without file grouping
            Write-TestLog "`nFailed tests:" -Color Yellow
            foreach ($failure in $script:Results.FailedTestDetails) {
                $testName = if ($failure.Test) { $failure.Test } else { "Unknown test" }
                $category = if ($failure.Category) { " [$($failure.Category)]" } else { "" }
                Write-TestLog "  • $testName$category" -Color Red
                if ($failure.Error) {
                    Write-TestLog "    Error: $($failure.Error)" -Color Gray
                }
            }
        } else {
            Write-TestLog "Total: $($script:Results.FailedTests) failed test(s) - details not available" -Color Red
        }
    } else {
        # Create compact summary - show multiple entries per line
        $entries = @()
        foreach ($group in $failuresByFile) {
            $fileName = $group.Name -replace 'LoxoneUtils\.', '' -replace '\.ps1$', ''  # Shorten names
            $entries += "$fileName($($group.Count))"
        }
        
        # Display in columns (3 per line)
        $columnsPerLine = 3
        for ($i = 0; $i -lt $entries.Count; $i += $columnsPerLine) {
            $line = $entries[$i..([Math]::Min($i + $columnsPerLine - 1, $entries.Count - 1))] -join "  "
            Write-TestLog $line -Color Yellow
        }
        
        Write-TestLog "`nTotal: $($script:Results.FailedTests) failed tests in $($failuresByFile.Count) files" -Color Red
    }
    
    # Show detailed enumerated list when there are failures
    if ($script:Results.FailedTestDetails.Count -gt 0) {
        Write-TestLog "`n=== DETAILED FAILURE LIST ===" -Color Red
        
        $testNumber = 1
        foreach ($group in $failuresByFile) {
            $shortName = $group.Name -replace 'LoxoneUtils\.', '' -replace '\.ps1$', ''
            Write-TestLog "`n$shortName ($($group.Count) failures):" -Color Yellow
            
            # Show each failure on a single line with test number
            foreach ($failure in $group.Group) {
                # Format the test description
                if ($failure.Description) {
                    # Extract the parent describe block and test name
                    if ($failure.Test -match '([^.]+)\.[^.]+$') {
                        $parentBlock = $matches[1] -replace ' Function$', ''
                        $testDesc = "$parentBlock - $($failure.Description)"
                    } else {
                        $testDesc = $failure.Description
                    }
                } else {
                    $testDesc = $failure.Test
                }
                # Add shortened error reason
                $errorReason = Get-ShortErrorReason $failure.Error
                Write-TestLog ("  {0,3}. {1}{2}" -f $testNumber, $testDesc, $errorReason) -Color Gray
                $testNumber++
            }
        }
        
        Write-TestLog "`nAll $($script:Results.FailedTests) failures enumerated above" -Color Cyan
    }
}

# Show skipped test summary
if ($script:Results.SkippedTests -gt 0) {
    Write-TestLog "`n=== SKIPPED TESTS SUMMARY ===" -Color Cyan
    
    # Group skips by file
    $skipsByFile = $script:Results.SkippedTestDetails | Where-Object { $_.File -and $_.File -ne "Multiple files" } | Group-Object -Property File | Sort-Object Count -Descending
    
    if ($skipsByFile.Count -eq 0 -and $script:Results.SkippedTestDetails.Count -eq 0) {
        Write-TestLog "Note: $($script:Results.SkippedTests) tests were skipped but details not available" -Color Yellow
        Write-TestLog "Skipped tests are usually:" -Color Gray
        Write-TestLog "  • Tests marked with -Skip parameter" -Color Gray
        Write-TestLog "  • Tests with unmet requirements (tags filtered out)" -Color Gray
        Write-TestLog "  • Tests in containers that failed discovery" -Color Gray
    } else {
        # Show whatever details we have
        if ($skipsByFile.Count -gt 0) {
            # Show compact summary
            $entries = @()
            foreach ($group in $skipsByFile) {
                $fileName = $group.Name -replace 'LoxoneUtils\.', '' -replace '\.ps1$', ''
                $entries += "$fileName($($group.Count))"
            }
            
            # Display in columns
            $columnsPerLine = 3
        for ($i = 0; $i -lt $entries.Count; $i += $columnsPerLine) {
            $line = $entries[$i..([Math]::Min($i + $columnsPerLine - 1, $entries.Count - 1))] -join "  "
            Write-TestLog $line -Color Cyan
        }
        
        Write-TestLog "`nTotal: $($script:Results.SkippedTests) skipped tests in $($skipsByFile.Count) files" -Color Cyan
        
        # Always show skipped test details
        if ($script:Results.SkippedTestDetails.Count -gt 0) {
            Write-TestLog "`n=== SKIPPED TEST DETAILS ===" -Color Cyan
            
            foreach ($group in $skipsByFile) {
                $shortName = $group.Name -replace 'LoxoneUtils\.', '' -replace '\.ps1$', ''
                Write-TestLog "`n$shortName ($($group.Count) skipped):" -Color Cyan
                
                foreach ($skip in $group.Group) {
                    # Extract test name from path
                    $testName = if ($skip.Test -match '\.([^.]+)$') { $matches[1] } else { $skip.Test }
                    Write-TestLog "  • $testName" -Color Gray
                    if ($skip.Reason -and $skip.Reason -ne "Test marked with -Skip") {
                        Write-TestLog "    Reason: $($skip.Reason)" -Color DarkGray
                    }
                }
            }
        }
        } else {
            # Show general summary if no file grouping available
            Write-TestLog "Total: $($script:Results.SkippedTests) tests skipped" -Color Cyan
            if ($script:Results.SkippedTestDetails.Count -gt 0) {
                Write-TestLog "Categories affected:" -Color Gray
                $categoryCounts = $script:Results.SkippedTestDetails | Group-Object -Property Category
                foreach ($cat in $categoryCounts) {
                    Write-TestLog "  • $($cat.Name): $($cat.Count) tests" -Color Gray
                }
            }
        }
    }
}

# Show result files location
if ($LogToFile -and -not $CI) {
    Write-TestLog "`n=== Result Files ===" -Color Cyan
    $resultFiles = Get-ChildItem $script:CurrentRunPath -File | Sort-Object Name
    foreach ($file in $resultFiles) {
        $fileDesc = switch -Regex ($file.Name) {
            'test-run-full\.log' { " (Complete terminal output)" }
            'test-run-\d+\.log' { " (Summary log)" }
            '\.xml$' { " (Test results)" }
            '\.json$' { " (JSON results)" }
            default { "" }
        }
        Write-TestLog "  $($file.Name) ($([math]::Round($file.Length/1KB, 2)) KB)$fileDesc" -Color Gray
    }
}

# Debug final LiveProgress state
if ($LiveProgress) {
    Write-TestLog "`n=== Final LiveProgress State ===" -Level "DEBUG" -Color Magenta
    Write-TestLog "LiveProgressTestCount: $Global:LiveProgressTestCount" -Level "DEBUG"
    Write-TestLog "LiveProgressTotalTests: $Global:LiveProgressTotalTests" -Level "DEBUG"
    Write-TestLog "LiveProgressPassedCount: $Global:LiveProgressPassedCount" -Level "DEBUG"
    Write-TestLog "LiveProgressFailedCount: $Global:LiveProgressFailedCount" -Level "DEBUG"
    Write-TestLog "LiveProgressSkippedCount: $Global:LiveProgressSkippedCount" -Level "DEBUG"
    Write-TestLog "Script Results TotalTests: $($script:Results.TotalTests)" -Level "DEBUG"
}

# Display final result location
Write-TestLog "`n=== Test Results Location ===" -Color Cyan
Write-TestLog "Test results saved to: TestResults\TestRun_$($script:TestRunId)\" -Color Green
if ($CleanupTestFiles) {
    Write-TestLog "`n=== Post-Test Cleanup ===" -Color Cyan
    $cleanupResult = Invoke-TestFileCleanup -WhatIf:$WhatIf -Quiet:$CI
    if (-not $CI) {
        Write-TestLog "Cleanup complete: $($cleanupResult.FilesDeleted) files deleted, $([math]::Round($cleanupResult.SpaceFreed/1MB, 2)) MB freed" -Color Green
    }
}

# Always run test result rotation to prevent unlimited growth
Write-TestLog "`n=== Test Result Rotation ===" -Color Cyan
$rotationResult = Invoke-TestResultRotation -Quiet:$CI
if ($rotationResult.RunsDeleted -gt 0 -or -not $CI) {
    Write-TestLog "Rotation complete: $($rotationResult.RunsDeleted)/$($rotationResult.TotalRuns) test runs deleted, $([math]::Round($rotationResult.BytesFreed/1MB, 2)) MB freed" -Color Green
}

# Stop transcript if it was started
if ($script:TranscriptStarted) {
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
        Write-TestLog "Full output log saved to: $($script:FullLogFile)" -Color Green
    } catch {
        # Ignore errors when stopping transcript
    }
}

# Restore error output if it was suppressed
if ($SuppressErrorOutput -and (Get-Command Restore-ErrorOutput -ErrorAction SilentlyContinue)) {
    Restore-ErrorOutput
}

# Calculate total runtime
$totalRuntime = (Get-Date) - $script:StartTime
$runtimeFormatted = "{0:mm\:ss\.fff}" -f $totalRuntime

# Determine exit code
$exitCode = if ($script:Results.FailedTests -eq 0) { 0 } else { 1 }

# Display final summary line (always show, even in CI mode)
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Total Runtime: $runtimeFormatted | Exit Code: $exitCode" -ForegroundColor $(if ($exitCode -eq 0) { 'Green' } else { 'Red' })
Write-Host "========================================" -ForegroundColor Cyan

# Exit with appropriate code
exit $exitCode