function New-TestCoverageReport {
    <#
    .SYNOPSIS
        Generates a comprehensive test coverage report
    
    .DESCRIPTION
        Generates a single coverage report that includes both executive summary
        and detailed analysis in one file
    
    .PARAMETER CheckUsage
        Include function usage analysis in the report
    
    .PARAMETER ShowConsole
        Display summary information in the console
    
    .PARAMETER OutputDirectory
        Directory where report will be saved
        
    .PARAMETER TestResultsPath
        Path to directory containing test results (XML files and JSON summary)
        
    .PARAMETER IncludeTestResults
        Include test run results (pass/fail/skip) in the report
        
    .PARAMETER TestRunId
        Test run ID timestamp to use for coverage report filename (format: yyyyMMdd-HHmmss)
    
    .EXAMPLE
        New-TestCoverageReport -ShowConsole -IncludeTestResults
    #>
    [CmdletBinding()]
    param(
        [switch]$CheckUsage,
        [switch]$ShowConsole,
        [string]$OutputDirectory,
        [string]$TestResultsPath,
        [switch]$IncludeTestResults,
        [string]$TestRunId
    )
    
    # Track start time for runtime calculation
    $startTime = Get-Date
    
    # Get invocation information early while call stack is available
    $invocationInfo = ""
    $callingScript = ""
    
    try {
        $callStack = Get-PSCallStack
        if ($callStack.Count -gt 1) {
            # Look for the script that called us (skip the current function)
            for ($i = 1; $i -lt $callStack.Count; $i++) {
                $caller = $callStack[$i]
                if ($caller.ScriptName -and $caller.ScriptName -ne $MyInvocation.ScriptName) {
                    $callingScript = Split-Path $caller.ScriptName -Leaf
                    $invocationInfo = "Invoked by: **$callingScript**"
                    if ($caller.FunctionName -and $caller.FunctionName -ne '<ScriptBlock>') {
                        $invocationInfo += " â†’ $($caller.FunctionName)"
                    }
                    break
                }
            }
        }
        
        # If no calling script found, check command line
        if (-not $callingScript) {
            $commandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue).CommandLine
            if ($commandLine -match '\\([^\\]+\.ps1)(.*)') {
                $callingScript = $matches[1]
                $params = $matches[2].Trim()
                if ($params) {
                    $invocationInfo = "Invoked by: **$callingScript** with parameters: $params"
                } else {
                    $invocationInfo = "Invoked by: **$callingScript**"
                }
            } else {
                $invocationInfo = "Invoked directly or interactively"
            }
        }
        
        # Add test execution context from environment variables
        $testContext = ""
        if ($env:UPDATELOXONE_TEST_TYPE) {
            $testContext = " | Test Type: **$($env:UPDATELOXONE_TEST_TYPE)**"
        }
        if ($env:UPDATELOXONE_RUN_CATEGORIES) {
            $testContext += " | Categories: **$($env:UPDATELOXONE_RUN_CATEGORIES)**"
        }
        if ($env:UPDATELOXONE_IS_ADMIN -eq 'True') {
            $testContext += " | **Running as Administrator**"
        } else {
            $testContext += " | Running as User"
        }
        if ($env:UPDATELOXONE_SKIP_SYSTEM -eq 'True') {
            $testContext += " | Skip System: True"
        }
        $invocationInfo += $testContext
    } catch {
        $invocationInfo = "Invocation info unavailable"
    }
    
    # Set up output directory
    if (-not $OutputDirectory) {
        # Try multiple fallback options for output directory
        if ($script:TestPath -and (Test-Path $script:TestPath)) {
            $OutputDirectory = Join-Path $script:TestPath "TestResults"
        } elseif (Test-Path "$PSScriptRoot\..\tests") {
            $OutputDirectory = Join-Path "$PSScriptRoot\..\tests" "TestResults"
        } else {
            # Ultimate fallback - use temp directory
            $OutputDirectory = Join-Path $env:TEMP "UpdateLoxone_TestResults"
            Write-Warning "Using temporary directory for coverage output: $OutputDirectory"
        }
    }
    
    # Set up test results path if not provided
    if (-not $TestResultsPath -and $IncludeTestResults) {
        # Try to find the most recent test results
        $resultsBase = $OutputDirectory
        if (Test-Path $resultsBase) {
            # Get most recent TestRun folder
            $mostRecent = Get-ChildItem $resultsBase -Filter "TestRun_*" -Directory | 
                          Sort-Object LastWriteTime -Descending | 
                          Select-Object -First 1
            if ($mostRecent) {
                $TestResultsPath = $mostRecent.FullName
            }
        }
    }
    
    # Validate output directory path
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        throw "OutputDirectory is null or empty. Cannot generate coverage report."
    }
    
    # Create coverage subdirectory
    $coverageDir = Join-Path $OutputDirectory "coverage"
    if (-not (Test-Path $coverageDir)) {
        New-Item -ItemType Directory -Path $coverageDir -Force | Out-Null
    }
    
    # Use provided TestRunId or generate new timestamp
    $timestamp = if ($TestRunId) { $TestRunId } else { Get-Date -Format 'yyyyMMdd-HHmmss' }
    
    Write-Host "Generating Test Coverage Report..." -ForegroundColor Cyan
    Write-Host ""
    
    # First run analysis to get KPIs for filename
    $tempReportPath = Join-Path $OutputDirectory "temp_coverage.md"
    
    # Execute coverage analysis in a script block to capture invocation context
    $coverageParams = @{
        GenerateReport = $false  # We'll generate it ourselves with proper context
        CheckUsage = $CheckUsage
        ShowIndex = $true
        ShowDetails = $true
        IncludeTestResults = $IncludeTestResults
        TestResultsPath = if ($TestResultsPath) { $TestResultsPath } else { $OutputDirectory }
    }
    
    $coverageResult = Get-TestCoverage @coverageParams
    
    # Calculate runtime
    $runtime = (Get-Date) - $startTime
    $runtimeMinutes = [math]::Floor($runtime.TotalMinutes)
    $runtimeSeconds = [math]::Floor($runtime.TotalSeconds) % 60
    $runtimeFormatted = "{0}m{1}s" -f $runtimeMinutes, $runtimeSeconds
    
    # Calculate KPIs for filename
    $totalFunctions = $coverageResult.TotalFunctions
    $deadFunctions = $coverageResult.UnusedExported + $coverageResult.UnusedInternal
    $activeFunctions = $totalFunctions - $deadFunctions
    
    # Calculate active tested (tested functions that are not dead code)
    $testedExported = $coverageResult.TestedExported
    $testedInternal = $coverageResult.TestedInternal
    $totalTested = $testedExported + $testedInternal
    
    # For active coverage, we use total coverage if no usage analysis, otherwise active coverage
    if ($CheckUsage -and $activeFunctions -gt 0) {
        # Need to calculate how many tested functions are actually used
        # This is approximate since we don't have the detailed data here
        $activeCoverage = [math]::Round(($totalTested / $totalFunctions) * 100, 0)
    } else {
        $activeCoverage = if ($totalFunctions -gt 0) { 
            [math]::Round(($totalTested / $totalFunctions) * 100, 0) 
        } else { 0 }
    }
    
    # Calculate dead code ratio (unused functions)
    $deadCodeRatio = if ($totalFunctions -gt 0) {
        [math]::Round(($deadFunctions / $totalFunctions) * 100, 0)
    } else { 0 }
    
    $deadTestRatio = if (($coverageResult.TotalTestReferences + $coverageResult.DeprecatedTests) -gt 0) {
        [math]::Round(($coverageResult.DeprecatedTests / ($coverageResult.TotalTestReferences + $coverageResult.DeprecatedTests)) * 100, 0)
    } else { 0 }
    
    # Calculate test execution coverage and success rate if we have test results
    $testExecutionCoverage = 0
    $testSuccessRate = 0
    $totalTestCount = 0
    $totalSkipped = 0
    if ($IncludeTestResults -and $TestResultsPath) {
        # Try to get test results from JSON summary
        $jsonSummaryPath = Join-Path $TestResultsPath "test-results-summary.json"
        if (Test-Path $jsonSummaryPath) {
            try {
                $jsonSummary = Get-Content $jsonSummaryPath -Raw | ConvertFrom-Json
                $totalTestCount = $jsonSummary.Overall.Total
                $passedTests = $jsonSummary.Overall.Passed
                $failedTests = $jsonSummary.Overall.Failed
                $totalSkipped = if ($jsonSummary.Overall.PSObject.Properties['Skipped']) { $jsonSummary.Overall.Skipped } else { 0 }
                if ($totalTestCount -gt 0) {
                    # Test execution coverage = (Passed + Failed) / Total * 100
                    # We count failed tests as "executed" since they ran, just didn't pass
                    $executedTests = $passedTests + $failedTests
                    $testExecutionCoverage = [math]::Round(($executedTests / $totalTestCount) * 100, 0)
                    
                    # Test success rate = Passed / (Passed + Failed) * 100
                    if ($executedTests -gt 0) {
                        $testSuccessRate = [math]::Round(($passedTests / $executedTests) * 100, 0)
                    }
                }
            } catch {
                # Fall back to zeros if JSON parsing fails
            }
        }
    }
    
    # Format KPIs with leading zeros
    # New format: TTTT-EEE-SSS-FFF-DDD-TTT where:
    # TTTT = Total test count (4 digits)
    # EEE = Test execution coverage % (3 digits)
    # SSS = Test success rate % (3 digits)
    # FFF = Function coverage % (3 digits)
    # DDD = Dead code ratio % (3 digits)
    # TTT = Dead test ratio % (3 digits)
    $kpiString = "{0:D4}-{1:D3}-{2:D3}-{3:D3}-{4:D3}-{5:D3}" -f $totalTestCount, [int]$testExecutionCoverage, [int]$testSuccessRate, [int]$activeCoverage, [int]$deadCodeRatio, [int]$deadTestRatio
    
    # Create final filename with timestamp and KPIs
    $finalReportName = "coverage_${timestamp}_${kpiString}.md"
    $reportPath = Join-Path $coverageDir $finalReportName
    
    # Now generate the report with all proper context
    Write-Host "Generating detailed coverage report..." -ForegroundColor Gray
    
    # Re-run with report generation to get all the detailed data
    $null = Get-TestCoverage `
        -GenerateReport `
        -CheckUsage:$CheckUsage `
        -OutputPath $tempReportPath `
        -ShowIndex `
        -ShowDetails `
        -IncludeTestResults:$IncludeTestResults `
        -TestResultsPath $(if ($TestResultsPath) { $TestResultsPath } else { $OutputDirectory })
    
    # Update report with runtime and invocation information
    $reportContent = Get-Content $tempReportPath -Raw
    
    # Load test execution data to add to header
    $testExecutionInfo = ""
    if ($IncludeTestResults) {
        # Use TestResultsPath if provided, otherwise fall back to OutputDirectory
        $testDataPath = if ($TestResultsPath) { $TestResultsPath } else { $OutputDirectory }
        
        # First try to read from JSON summary for most accurate results
        $jsonSummaryPath = Join-Path $testDataPath "test-results-summary.json"
        if (Test-Path $jsonSummaryPath) {
            try {
                $jsonSummary = Get-Content $jsonSummaryPath -Raw | ConvertFrom-Json
                $totalPassed = $jsonSummary.Overall.Passed
                $totalFailed = $jsonSummary.Overall.Failed
                $totalSkipped = if ($jsonSummary.Overall.PSObject.Properties['Skipped']) { $jsonSummary.Overall.Skipped } else { 0 }
                $totalTests = $jsonSummary.Overall.Total
                
                # Calculate total time from all test categories
                $totalTime = 0
                if ($jsonSummary.UnitTests.Duration) {
                    $unitDuration = [TimeSpan]::Parse($jsonSummary.UnitTests.Duration)
                    $totalTime += $unitDuration.TotalSeconds
                }
                if ($jsonSummary.IntegrationTests.Duration) {
                    $integrationDuration = [TimeSpan]::Parse($jsonSummary.IntegrationTests.Duration)
                    $totalTime += $integrationDuration.TotalSeconds
                }
                if ($jsonSummary.SystemTests.Duration) {
                    $systemDuration = [TimeSpan]::Parse($jsonSummary.SystemTests.Duration)
                    $totalTime += $systemDuration.TotalSeconds
                }
                
                $testExecutionInfo = "`n**Test Execution Results:** $totalTests tests total ($totalPassed passed, $totalFailed failed, $totalSkipped skipped) in $([math]::Round($totalTime, 2))s"
            } catch {
                # Fall back to XML parsing if JSON fails
                $testExecutionInfo = $null
            }
        }
        
        # If no JSON or it failed, fall back to XML parsing
        if ($null -eq $testExecutionInfo -or [string]::IsNullOrWhiteSpace($testExecutionInfo)) {
            # Look for test result XML files
            $xmlFiles = @()
            if (Test-Path $testDataPath) {
                $xmlFiles = Get-ChildItem $testDataPath -Filter "*-TestResults.xml" -File -ErrorAction SilentlyContinue
            }
            
            if ($xmlFiles.Count -gt 0) {
                $totalTests = 0
                $totalPassed = 0
                $totalFailed = 0
                $totalSkipped = 0
                $totalTime = 0
                
                foreach ($xmlFile in $xmlFiles) {
                    try {
                        [xml]$xml = Get-Content $xmlFile.FullName -Raw
                        $testSuite = $xml.SelectSingleNode("//test-suite[@type='Assembly']")
                        if ($testSuite) {
                            $total = [int]$testSuite.GetAttribute("total")
                            $passed = [int]$testSuite.GetAttribute("passed")
                            $failed = [int]$testSuite.GetAttribute("failed")
                            $skipped = [int]$testSuite.GetAttribute("skipped")
                            $time = [double]$testSuite.GetAttribute("time")
                            
                            $totalTests += $total
                            $totalPassed += $passed
                            $totalFailed += $failed
                            $totalSkipped += $skipped
                            $totalTime += $time
                        }
                    } catch {
                        # Ignore errors reading individual files
                    }
                }
                
                if ($totalTests -gt 0) {
                    $testExecutionInfo = "`n**Test Execution Results:** $totalTests tests total ($totalPassed passed, $totalFailed failed, $totalSkipped skipped) in $([math]::Round($totalTime, 2))s"
                }
            }
        }
    }
    
    # Create filename breakdown explanation
    $filenameBreakdown = @"

**Report Filename:** ``$finalReportName``
- **$($totalTestCount.ToString().PadLeft(4, '0'))** total tests
- **$([int]$testExecutionCoverage)%** test execution coverage ($($totalTestCount - $totalSkipped) of $totalTestCount tests ran)
- **$([int]$testSuccessRate)%** test success rate ($totalPassed/$($totalTestCount - $totalSkipped))
- **$([int]$activeCoverage)%** function coverage
- **$([int]$deadCodeRatio)%** dead code ratio
- **$([int]$deadTestRatio)%** dead test ratio
"@
    
    # Add TestRun information if available
    $testRunInfo = ""
    if ($TestResultsPath -and (Test-Path $TestResultsPath)) {
        # Extract TestRun ID from path
        if ($TestResultsPath -match 'TestRun_(\d{8}-\d{6})') {
            $testRunId = $matches[1]
            $testRunInfo = "`n**TestRun:** TestRun_$testRunId"
        }
    }
    
    # Fix the header to include invocation info, runtime, and test execution
    $newHeader = @"
# UpdateLoxone Test Coverage Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (Runtime: $runtimeFormatted) | $invocationInfo$testExecutionInfo$testRunInfo
$filenameBreakdown
"@
    
    # Replace the header
    $reportContent = $reportContent -replace '# UpdateLoxone Test Coverage Report\s*\n\s*Generated: [^\n]+', $newHeader
    
    # Write with UTF8 encoding without BOM
    [System.IO.File]::WriteAllText($reportPath, $reportContent, [System.Text.Encoding]::UTF8)
    
    # Remove temp file
    Remove-Item $tempReportPath -Force -ErrorAction SilentlyContinue
    
    # Also clean up old coverage.md files in root directory
    $oldCoverageFile = Join-Path $OutputDirectory "coverage.md"
    if (Test-Path $oldCoverageFile) {
        Remove-Item $oldCoverageFile -Force -ErrorAction SilentlyContinue
    }
    
    if ($ShowConsole) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "COVERAGE SUMMARY" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        $coverageColor = if ($coverageResult.TotalCoverage -ge 80) { 'Green' } 
                        elseif ($coverageResult.TotalCoverage -ge 60) { 'Yellow' } 
                        else { 'Red' }
        Write-Host "Overall Coverage: $($coverageResult.TotalCoverage)%" -ForegroundColor $coverageColor
        
        $untestedColor = if ($coverageResult.UntestedExported -eq 0) { 'Green' }
                        elseif ($coverageResult.UntestedExported -le 5) { 'Yellow' }
                        else { 'Red' }
        Write-Host "Untested Exported Functions: $($coverageResult.UntestedExported)" -ForegroundColor $untestedColor
        
        $deprecatedColor = if ($coverageResult.DeprecatedTests -eq 0) { 'Green' } else { 'Yellow' }
        Write-Host "Deprecated Test References: $($coverageResult.DeprecatedTests)" -ForegroundColor $deprecatedColor
    }
    
    # Console output is handled by calling script to avoid duplication
    $kpiDisplay = $kpiString -replace '-', '/'
    
    # Return paths for integration with other scripts
    return @{
        ReportPath = $reportPath
        Timestamp = $timestamp
        CoverageResult = $coverageResult
        Runtime = $runtimeFormatted
        KPIs = $kpiDisplay
    }
}
