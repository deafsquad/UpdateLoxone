function Format-TestCoverageReport {
    <#
    .SYNOPSIS
        Formats coverage data into a comprehensive markdown report
    
    .DESCRIPTION
        Takes coverage analysis data and generates a detailed markdown report
        with executive summary at the top followed by detailed analysis.
        Now includes enforcement status and compliance metrics.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$CoverageData,
        [string]$Runtime = "N/A",
        [hashtable]$DeadTestCalculation = @{},
        [hashtable]$EnforcementData = @{}
    )
    
    $allFunctions = $CoverageData.AllFunctions
    $functionsByModule = $CoverageData.FunctionsByModule
    $deprecatedTestReferences = $CoverageData.DeprecatedTestReferences
    $stats = $CoverageData.Statistics
    $untestedExported = $CoverageData.UntestedExported
    $unusedExported = $CoverageData.UnusedExported
    $unusedInternal = $CoverageData.UnusedInternal
    $checkUsage = $CoverageData.CheckUsage
    $includeTestResults = $CoverageData.IncludeTestResults
    $testResults = $CoverageData.TestResults
    $invocationInfo = if ($CoverageData.InvocationInfo) { $CoverageData.InvocationInfo } else { "Invocation info unavailable" }
    $testExecutionTotals = $CoverageData.TestExecutionTotals
    
    # Calculate KPIs excluding test infrastructure
    $totalDefined = $stats.TotalFunctions
    $testInfraCount = if ($stats.TestInfrastructureFunctions) { $stats.TestInfrastructureFunctions } else { 0 }
    $activeFunctionsTotal = if ($stats.ActiveFunctions) { $stats.ActiveFunctions } else { $totalDefined - $testInfraCount }
    $deadFunctions = if ($checkUsage) { $stats.UnusedExported + $stats.UnusedInternal } else { 0 }
    $deadFunctionPercent = if ($activeFunctionsTotal -gt 0) { [math]::Round(($deadFunctions / $activeFunctionsTotal) * 100, 1) } else { 0 }
    
    $activeFunctions = $activeFunctionsTotal - $deadFunctions
    $activeTested = if ($checkUsage) {
        # Ensure variables are treated as collections
        $unusedExportedCollection = @($unusedExported)
        $unusedInternalCollection = @($unusedInternal)
        ($stats.TestedExported + $stats.TestedInternal) - 
        (($unusedExportedCollection | Where-Object { $_.Value.Tested }).Count + 
         ($unusedInternalCollection | Where-Object { $_.Value.Tested }).Count)
    } else {
        $stats.TestedExported + $stats.TestedInternal
    }
    $activeCoverage = if ($activeFunctions -gt 0) { [math]::Round(($activeTested / $activeFunctions) * 100, 1) } else { 0 }
    
    # Use provided calculation or calculate it
    if (-not $DeadTestCalculation -or $DeadTestCalculation.Count -eq 0) {
        # Calculate dead test ratio - ratio of deprecated references to total references
        # This measures how much of our test code references non-existent functions
        $validTestReferences = $stats.TotalTestReferences  # References to functions that exist
        $deprecatedTestReferences = $stats.DeprecatedTests # References to functions that don't exist
        $totalReferences = $validTestReferences + $deprecatedTestReferences
        
        $deadTestPercent = if ($totalReferences -gt 0) { 
            [math]::Round(($deprecatedTestReferences / $totalReferences) * 100, 1) 
        } else { 0 }
        
        # Store calculation details for the report
        $deadTestCalculation = @{
            ValidReferences = $validTestReferences
            DeprecatedReferences = $deprecatedTestReferences
            TotalReferences = $totalReferences
            Percentage = $deadTestPercent
        }
    } else {
        $deadTestPercent = $DeadTestCalculation.Percentage
        $deadTestCalculation = $DeadTestCalculation
    }
    
    
    # Use provided test execution totals if available, otherwise calculate from details
    if ($testExecutionTotals -and $testExecutionTotals.TotalTests -gt 0) {
        # Use the accurate totals from XML/JSON
        $totalTests = $testExecutionTotals.TotalTests
        $totalPassed = $testExecutionTotals.TotalPassed
        $totalFailed = $testExecutionTotals.TotalFailed
        $totalSkipped = $testExecutionTotals.TotalSkipped
    } else {
        # Fall back to calculating from test details (may be incomplete)
        $totalPassed = 0
        $totalFailed = 0
        $totalSkipped = 0
        $totalTests = 0
        
        if ($includeTestResults -and $testResults) {
            foreach ($funcResults in $testResults.Values) {
                if ($funcResults.Details) {
                    foreach ($detail in $funcResults.Details) {
                        $totalTests++
                        switch ($detail.Result) {
                            "Success" { $totalPassed++ }
                            "Failure" { $totalFailed++ }
                            "Ignored" { $totalSkipped++ }
                            "Skipped" { $totalSkipped++ }
                        }
                    }
                }
            }
        }
    }
    
    # Test execution summary is now handled by New-TestCoverageReport function
    $testExecutionSummary = ""
    
    # Get enforcement data if not provided
    if (-not $EnforcementData -or $EnforcementData.Count -eq 0) {
        # Load exception data
        $exceptionPath = Join-Path (Split-Path $script:ModulePath -Parent) "TestCoverageExceptions.json"
        if (Test-Path $exceptionPath) {
            try {
                $exceptions = ConvertFrom-JsonToHashtable -Json (Get-Content $exceptionPath -Raw)
                $EnforcementData = @{
                    Exceptions = $exceptions
                    GrandfatheredCount = $exceptions.grandfathered.Count
                    PermanentCount = $exceptions.permanent.Count
                    NextReviewDate = $exceptions.metadata.next_review
                }
            } catch {
                $EnforcementData = @{}
            }
        }
    }
    
    # Calculate documentation completeness metrics
    $docStats = @{
        Documented = 0
        FullyDocumented = 0
        PartiallyDocumented = 0
        Undocumented = 0
        TotalScore = 0
        TotalFunctions = 0
    }
    
    foreach ($func in $allFunctions.Values) {
        # Only count exported functions for documentation metrics
        if ($func.Exported) {
            $docStats.TotalFunctions++
            
            if ($func.Documentation -and $func.Documentation.HasDocumentation) {
                $docStats.Documented++
                $docStats.TotalScore += $func.Documentation.CompletionScore
                
                if ($func.Documentation.CompletionScore -ge 75) {
                    $docStats.FullyDocumented++
                } else {
                    $docStats.PartiallyDocumented++
                }
            } else {
                $docStats.Undocumented++
            }
        }
    }
    
    $docCompleteness = if ($docStats.TotalFunctions -gt 0) {
        [math]::Round(($docStats.Documented / $docStats.TotalFunctions) * 100, 1)
    } else { 0 }
    
    $avgDocScore = if ($docStats.Documented -gt 0) {
        [math]::Round($docStats.TotalScore / $docStats.Documented, 1)
    } else { 0 }
    
    # Calculate enforcement compliance metrics
    $enforcementMetrics = @{
        NewCodeCompliance = "100%"  # Default for new code
        GrandfatheredViolations = if ($EnforcementData.GrandfatheredCount) { $EnforcementData.GrandfatheredCount } else { 0 }
        PermanentExceptions = if ($EnforcementData.PermanentCount) { $EnforcementData.PermanentCount } else { 0 }
        EnforcementLevel = "Phase 2: New-Code-Only"
        ComplianceRate = $stats.ExportedCoverage
    }
    
    # Start building the report with executive summary at the top
    $report = @"
# UpdateLoxone Test Coverage Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (Runtime: $Runtime) | $invocationInfo$testExecutionSummary
**Enforcement Level:** $($enforcementMetrics.EnforcementLevel) | **Compliance Status:** $($enforcementMetrics.ComplianceRate)% compliant

## Key Performance Indicators (KPIs)

| Metric | Value | Status |
|--------|-------|--------|
| **Test Success Rate** | $(if ($totalPassed + $totalFailed -gt 0) { [math]::Round(($totalPassed / ($totalPassed + $totalFailed)) * 100, 1) } else { 0 })% ($totalPassed/$(if ($totalPassed + $totalFailed -gt 0) { $totalPassed + $totalFailed } else { 1 })) | $(if ($totalPassed + $totalFailed -eq 0) { "N/A" } elseif ($totalPassed + $totalFailed -gt 0 -and ($totalPassed / ($totalPassed + $totalFailed)) -ge 0.8) { "Good" } elseif ($totalPassed + $totalFailed -gt 0 -and ($totalPassed / ($totalPassed + $totalFailed)) -ge 0.6) { "Fair" } else { "Poor" }) |
| **Active Function Coverage** | $activeCoverage% ($activeTested/$activeFunctions) | $(if ($activeCoverage -ge 80) { "Good" } elseif ($activeCoverage -ge 60) { "Fair" } else { "Poor" }) |
| **Dead Code Ratio** | $deadFunctionPercent% ($deadFunctions/$totalDefined functions) | $(if ($deadFunctionPercent -le 10) { "Good" } elseif ($deadFunctionPercent -le 30) { "Fair" } else { "Poor" }) |
| **Dead Test Ratio** | $deadTestPercent% ($($deadTestCalculation.DeprecatedReferences)/$($deadTestCalculation.TotalReferences) refs) | $(if ($deadTestPercent -le 10) { "Good" } elseif ($deadTestPercent -le 20) { "Fair" } else { "Poor" }) |
| **Documentation Coverage** | $docCompleteness% ($($docStats.Documented)/$($docStats.TotalFunctions) exported) | $(if ($docCompleteness -ge 80) { "Excellent" } elseif ($docCompleteness -ge 60) { "Good" } elseif ($docCompleteness -ge 40) { "Fair" } else { "Poor" }) |
| **Enforcement Compliance** | $($enforcementMetrics.ComplianceRate)% ($($enforcementMetrics.GrandfatheredViolations) exempted) | $(if ($enforcementMetrics.ComplianceRate -ge 90) { "Excellent" } elseif ($enforcementMetrics.ComplianceRate -ge 80) { "Good" } elseif ($enforcementMetrics.ComplianceRate -ge 60) { "Fair" } else { "Needs Work" }) |

### KPI Calculation Formulas

- **Test Success Rate** = (Passed Tests) / (Passed Tests + Failed Tests) * 100
  - Measures the percentage of tests that pass out of all tests that ran
  - Does not include skipped tests in the calculation
  
- **Active Function Coverage** = (Tested Functions in Active Code) / (Total Active Functions) * 100
  - Active functions are those actually used in the codebase (not dead code)
  - Excludes test infrastructure functions from both numerator and denominator
  
- **Dead Code Ratio** = (Unused Functions) / (Total Active Functions) * 100  
  - Functions defined but never called anywhere in the codebase
  - Excludes test infrastructure functions from calculation
  
- **Dead Test Ratio** = (Deprecated Function References) / (Total Function References) * 100
  - Measures what percentage of function references in tests point to non-existent functions
  - Formula: Deprecated function refs / (Valid function refs + Deprecated function refs)
  - Calculation: $($deadTestCalculation.DeprecatedReferences) / ($($deadTestCalculation.ValidReferences) + $($deadTestCalculation.DeprecatedReferences)) = $deadTestPercent%
  
- **Documentation Coverage** = (Documented Exported Functions) / (Total Exported Functions) * 100
  - Measures what percentage of exported functions have comment-based help documentation
  - Average documentation completeness: $avgDocScore%
  - Fully documented (75%+): $($docStats.FullyDocumented), Partially: $($docStats.PartiallyDocumented), Missing: $($docStats.Undocumented)
  
Note: This compares function references (102 valid + 95 deprecated = 197 total), not test cases (313 executed).

### Test Execution Context

- **Test Cases Executed**: $($totalPassed + $totalFailed) (from XML results)
- **Test Cases Skipped**: $totalSkipped (includes system tests when not running as admin)
- **Total Test Cases**: $totalTests

## Executive Summary

**Overall Coverage: $($stats.TotalCoverage)%** | Exported: $($stats.ExportedCoverage)% | Internal: $($stats.InternalCoverage)%

### Quick Stats
- **Total Functions**: $($stats.TotalFunctions) (Exported: $($stats.ExportedFunctions), Internal: $($stats.InternalFunctions))$(if ($testInfraCount -gt 0) { "`n- **Test Infrastructure**: $testInfraCount functions (excluded from coverage metrics)" })
- **Active Functions**: $activeFunctionsTotal (functions requiring test coverage)
- **Test Coverage**: $($stats.TestedExported + $stats.TestedInternal)/$activeFunctionsTotal functions tested
- **Test Files**: $($stats.TestFilesAnalyzed) files analyzed
- **Test References**: $($stats.TotalTestReferences) function references found
- **Documentation**: $($docStats.Documented)/$($stats.ExportedFunctions) exported functions documented (avg $avgDocScore% complete)$(if ($includeTestResults -and $testResults.Count -gt 0) {
    # Note: These totals were already calculated above for the header
    "`n- **Test Execution**: $totalTests tests ($totalPassed passed, $totalFailed failed, $totalSkipped skipped)"
} else {
    "`n- **Test Execution**: Not available (coverage analysis only)"
})

### Critical Issues
1. **Untested Exported Functions**: $($stats.UntestedExported) functions need tests
2. **Untested Internal Functions**: $($stats.UntestedInternal) functions need tests  
3. **Deprecated Test References**: $($stats.DeprecatedTests) references to non-existent functions
$(if ($checkUsage) { "4. **Unused Functions**: $($stats.UnusedExported) exported, $($stats.UnusedInternal) internal functions unused" })

### Enforcement Status

| Category | Count | Details |
|----------|-------|---------|
| **Grandfathered Violations** | $($enforcementMetrics.GrandfatheredViolations) | Functions exempted until expiration dates |
| **Permanent Exceptions** | $($enforcementMetrics.PermanentExceptions) | Functions permanently exempted (meta-functions) |
| **Active Violations** | $(($stats.UntestedExported) - $enforcementMetrics.GrandfatheredViolations - $enforcementMetrics.PermanentExceptions) | Functions requiring immediate tests |
| **Next Review Date** | $(if ($EnforcementData.NextReviewDate) { $EnforcementData.NextReviewDate } else { "Not set" }) | Next exception expiration review |

### Action Items
- **Immediate**: Write tests for the $($stats.UntestedExported) untested exported functions
- **Consider**: Write tests for the $($stats.UntestedInternal) untested internal functions (lower priority)
- **Short-term**: Clean up $($stats.DeprecatedTests) deprecated test references
- **Goal**: Achieve 90%+ coverage for exported functions (currently $($stats.ExportedCoverage)%)
- **Enforcement**: $(if ($enforcementMetrics.GrandfatheredViolations -gt 0) { "Review $($enforcementMetrics.GrandfatheredViolations) grandfathered exceptions by their expiration dates" } else { "All violations actively enforced" })

---

## Detailed Analysis

### Coverage by Function Type

| Category | Tested | Total | Coverage |
|----------|--------|-------|----------|
| Exported Functions | $($stats.TestedExported) | $($stats.ExportedFunctions) | $($stats.ExportedCoverage)% |
| Internal Functions | $($stats.TestedInternal) | $($stats.InternalFunctions) | $($stats.InternalCoverage)% |
| **Total** | **$(($stats.TestedExported + $stats.TestedInternal))** | **$($stats.TotalFunctions)** | **$($stats.TotalCoverage)%** |
"@

    # Add Test Infrastructure section if there are any
    if ($testInfraCount -gt 0 -and $CoverageData.TestInfrastructureCategories) {
        $report += @"

### Test Infrastructure Functions ($testInfraCount)

These functions are part of the test framework itself and are excluded from coverage requirements:
"@
        
        foreach ($category in $CoverageData.TestInfrastructureCategories.PSObject.Properties) {
            $categoryName = $category.Name
            $categoryData = $category.Value
            $report += @"

**$($categoryData.description):**
"@
            foreach ($funcName in $categoryData.functions) {
                if ($allFunctions.ContainsKey($funcName)) {
                    $func = $allFunctions[$funcName]
                    $usageStatus = if ($func.UsedInCodebase) { "✓ Used" } else { "○ Infrastructure" }
                    $report += "`n- ``$funcName`` ($($func.Module)) - $usageStatus"
                }
            }
        }
    }

    $report += @"

### Untested Exported Functions ($($stats.UntestedExported))

These functions are part of the public API but lack test coverage:

| Function | Module | Enforcement Status | Expiration |
|----------|--------|-------------------|------------|
"@

    foreach ($func in @($untestedExported) | Sort-Object { $_.Value.Module }, { $_.Key }) {
        $funcName = $func.Key
        $enforcementStatus = "âŒ Required"
        $expiration = "Now"
        
        # Check if function has exception
        if ($EnforcementData.Exceptions) {
            if ($EnforcementData.Exceptions.grandfathered.ContainsKey($funcName)) {
                $exception = $EnforcementData.Exceptions.grandfathered[$funcName]
                $enforcementStatus = "âš ï¸ Grandfathered"
                $expiration = $exception.expires
            } elseif ($EnforcementData.Exceptions.permanent.ContainsKey($funcName)) {
                $enforcementStatus = "âœ… Permanent Exception"
                $expiration = "Never"
            }
        }
        
        $report += "`n| ``$($funcName)`` | $($func.Value.Module) | $enforcementStatus | $expiration |"
    }
    
    # Add untested internal functions section
    $untestedInternal = $CoverageData.AllFunctions.GetEnumerator() | Where-Object { -not $_.Value.Exported -and -not $_.Value.Tested }
    if ($untestedInternal.Count -gt 0) {
        $report += @"

### Untested Internal Functions ($($untestedInternal.Count))

These internal functions lack test coverage:

| Function | Module | Usage Status |
|----------|--------|--------------|
"@
        foreach ($func in @($untestedInternal) | Sort-Object { $_.Value.Module }, { $_.Key }) {
            $usageStatus = if ($checkUsage) {
                if ($func.Value.UsedInCodebase) {
                    "Used in: $($func.Value.UsageLocations -join ', ')"
                } else {
                    "**UNUSED - candidate for removal**"
                }
            } else { "Not analyzed" }
            $report += "`n| ``$($func.Key)`` | $($func.Value.Module) | $usageStatus |"
        }
    }
    
    # Add module breakdown
    $report += @"

### Module Breakdown

| Module | Total | Tested | Coverage | Exported | Internal |
|--------|-------|--------|----------|----------|----------|
"@

    foreach ($module in $functionsByModule.GetEnumerator() | Sort-Object Key) {
        $moduleName = $module.Key
        $moduleFuncs = $module.Value
        $moduleTotal = $moduleFuncs.Count
        $moduleTested = ($moduleFuncs | Where-Object { $allFunctions[$_].Tested }).Count
        $moduleExported = ($moduleFuncs | Where-Object { $allFunctions[$_].Exported }).Count
        $moduleInternal = $moduleTotal - $moduleExported
        $moduleCoverage = if ($moduleTotal -gt 0) { 
            [math]::Round(($moduleTested / $moduleTotal) * 100, 1) 
        } else { 0 }
        
        $report += "`n| $moduleName | $moduleTotal | $moduleTested | $moduleCoverage% | $moduleExported | $moduleInternal |"
    }
    
    # Add detailed function coverage section
    $report += @"

### Tested Functions Detail

"@

    # Initialize detailed status counters to verify against header totals
    $detailPassCount = 0
    $detailFailCount = 0
    $detailSkipCount = 0
    $detailNotRunCount = 0
    $detailTotalCount = 0

    foreach ($module in $functionsByModule.GetEnumerator() | Sort-Object Key) {
        $moduleName = $module.Key
        $testedFuncs = $module.Value | Where-Object { $allFunctions[$_].Tested } | Sort-Object
        
        if ($testedFuncs.Count -gt 0) {
            $report += @"

#### $moduleName

"@
            foreach ($funcName in $testedFuncs) {
                $func = $allFunctions[$funcName]
                $exportedTag = if ($func.Exported) { "**[Exported]**" } else { "*[Internal]*" }
                $report += "`n**``$funcName``** $exportedTag"
                
                # Add function documentation if available
                if ($func.Documentation -and $func.Documentation.HasDocumentation) {
                    $doc = $func.Documentation
                    $docCompleteness = "$($doc.CompletionScore)%"
                    $report += " - Documentation: $docCompleteness complete"
                    
                    if ($doc.Synopsis) {
                        $report += "`n   - **Synopsis:** $($doc.Synopsis)"
                    }
                    if ($doc.Description -and $doc.Description -ne $doc.Synopsis) {
                        # Truncate long descriptions
                        $desc = if ($doc.Description.Length -gt 200) {
                            $doc.Description.Substring(0, 197) + "..."
                        } else {
                            $doc.Description
                        }
                        $report += "`n   - **Description:** $desc"
                    }
                } else {
                    $report += " - **Documentation:** âš ï¸ Missing"
                }
                
                
                # Add test result summary if available
                if ($includeTestResults -and $func.TestResults) {
                    # Use the integrated real test results
                    $passCount = 0
                    $failCount = 0
                    $skipCount = 0
                    $totalTime = 0
                    
                    foreach ($result in $func.TestResults) {
                        switch ($result.Status) {
                            "Passed" { $passCount++ }
                            "Failed" { $failCount++ }
                            "Skipped" { $skipCount++ }
                        }
                        if ($result.Duration) {
                            $totalTime += [double]$result.Duration
                        }
                    }
                    
                    $totalTests = $passCount + $failCount + $skipCount
                    $resultText = " - Test Results: "
                    if ($failCount -gt 0) {
                        $resultText += '**FAILED** ('
                    } else {
                        $resultText += '**PASSED** ('
                    }
                    $resultText += "$passCount passed"
                    if ($failCount -gt 0) {
                        $resultText += ", $failCount failed"
                    }
                    if ($skipCount -gt 0) {
                        $resultText += ", $skipCount skipped"
                    }
                    $resultText += ")"
                    if ($totalTime -gt 0) {
                        $resultText += " in $([math]::Round($totalTime, 2))s"
                    }
                    $report += $resultText
                } elseif ($includeTestResults -and $testResults.ContainsKey($funcName)) {
                    $result = $testResults[$funcName]
                    $totalTests = $result.Passed + $result.Failed + $result.Skipped
                    $resultText = " - Test Results: "
                    if ($result.Failed -gt 0) {
                        $resultText += '<span style="color: red;">**FAILED**</span> ('
                    } else {
                        $resultText += '<span style="color: green;">**PASSED**</span> ('
                    }
                    $resultText += '<span style="color: green;">' + $result.Passed + ' passed</span>'
                    if ($result.Failed -gt 0) {
                        $resultText += ', <span style="color: red;">' + $result.Failed + ' failed</span>'
                    }
                    if ($result.Skipped -gt 0) {
                        $resultText += ', <span style="color: orange;">' + $result.Skipped + ' skipped</span>'
                    }
                    $resultText += ")"
                    if ($result.TotalTime -gt 0) {
                        $resultText += " in $([math]::Round($result.TotalTime, 2))s"
                    }
                    $report += $resultText
                }
                $report += "`n"
                
                if ($func.TestDetails.Count -gt 0) {
                    $report += "`n**Test Coverage Details:**`n"
                    
                    # Process each test with its full context
                    $testNumber = 1
                    foreach ($testKey in $func.TestDetails.Keys | Sort-Object) {
                        $detail = $func.TestDetails[$testKey]
                        $testFiles = $detail.TestFiles -join ', '
                        
                        # Get test result if available
                        $testStatus = "[NOT RUN]"  # Default status
                        $testTime = ""
                        $errorMessage = ""
                        
                        if ($includeTestResults -and $func.TestResults) {
                            # Try to match by test description from integrated test results
                            $matchingResult = $func.TestResults | Where-Object { 
                                # Match exact It block description
                                $_.It -eq $detail.It -or
                                # Match by combined Describe.It pattern
                                $_.Name -eq "$($detail.Describe).$($detail.It)" -or
                                # Match if test name contains the It description
                                $_.It -like "*$($detail.It)*" -or
                                $_.Name -like "*$($detail.It)*"
                            } | Select-Object -First 1
                            
                            if ($matchingResult) {
                                $testStatus = switch ($matchingResult.Status) {
                                    "Passed" { "[PASS]" }
                                    "Failed" { "[FAIL]" }
                                    "Skipped" { "[SKIP]" }
                                    default { "[UNKNOWN]" }
                                }
                                if ($matchingResult.Duration) {
                                    $testTime = " ($($matchingResult.Duration)s)"
                                }
                                if ($matchingResult.ErrorMessage) {
                                    $errorMessage = $matchingResult.ErrorMessage
                                }
                            }
                        } elseif ($includeTestResults -and $testResults.ContainsKey($funcName)) {
                            # Fallback to old test results format if no integrated results
                            $matchingResult = $testResults[$funcName].Details | Where-Object { 
                                # Match exact It block description
                                $_.TestName -eq $detail.It -or
                                # Match partial It block description (in case of truncation)
                                $_.TestName -like "*$($detail.It)*" -or 
                                # Match using the full name from XML if available
                                ($_.FullName -and (
                                    # Match the combined Describe.It format from XML
                                    $_.FullName -eq "$($detail.Describe).$($detail.It)" -or
                                    # Match if full name contains both Describe and It parts
                                    ($_.FullName -like "*$($detail.Describe)*" -and $_.FullName -like "*$($detail.It)*")
                                ))
                            } | Select-Object -First 1
                            
                            if ($matchingResult) {
                                $testStatus = switch ($matchingResult.Result) {
                                    "Success" { "[PASS]" }
                                    "Failure" { "[FAIL]" }
                                    "Ignored" { "[SKIP]" }
                                    "Skipped" { "[SKIP]" }
                                    default { "[UNKNOWN]" }
                                }
                                if ($matchingResult.Time) {
                                    $testTime = " (${matchingResult.Time}s)"
                                }
                            }
                        }
                        
                        # Count test status for verification
                        $detailTotalCount++
                        switch ($testStatus) {
                            "[PASS]" { $detailPassCount++ }
                            "[FAIL]" { $detailFailCount++ }
                            "[SKIP]" { $detailSkipCount++ }
                            "[NOT RUN]" { $detailNotRunCount++ }
                        }
                        
                        # Color the test name based on its status
                        $testNameFormatted = if ($testStatus) {
                            switch ($testStatus) {
                                "[PASS]" { "`n$testNumber. **Test:** $($detail.It) **[PASSED]**`n" }
                                "[FAIL]" { "`n$testNumber. **Test:** $($detail.It) **[FAILED]**`n" }
                                "[SKIP]" { "`n$testNumber. **Test:** $($detail.It) **[SKIPPED]**`n" }
                                "[NOT RUN]" { "`n$testNumber. **Test:** $($detail.It) **[NOT RUN]**`n" }
                                default { "`n$testNumber. **Test:** $($detail.It)`n" }
                            }
                        } else {
                            "`n$testNumber. **Test:** $($detail.It)`n"
                        }
                        $report += $testNameFormatted
                        $report += "   - **File:** $testFiles`n"
                        $report += "   - **Context:** $($detail.Describe)`n"
                        
                        # Always add status
                        $statusDisplay = switch ($testStatus) {
                            "[PASS]" { '**PASS**' }
                            "[FAIL]" { '**FAIL**' }
                            "[SKIP]" { '**SKIP**' }
                            "[NOT RUN]" { '**NOT RUN**' }
                            default { '**UNKNOWN**' }
                        }
                        $report += "   - **Status:** $statusDisplay$testTime`n"
                        
                        # Add error message if test failed
                        if ($errorMessage -and $testStatus -eq "[FAIL]") {
                            # Truncate long error messages
                            $shortError = if ($errorMessage.Length -gt 150) {
                                $errorMessage.Substring(0, 147) + "..."
                            } else {
                                $errorMessage
                            }
                            $report += "   - **Error:** $shortError`n"
                        }
                        
                        # Check for individual assertion results from TestTracking
                        $assertionResults = @{}
                        $hasAssertionTracking = $false
                        
                        # Try to get assertion tracking results if available
                        # First check if results are available in memory
                        if (Get-Command Get-TestAssertionResults -ErrorAction SilentlyContinue) {
                            $testKey = "$funcName.$($detail.It)"
                            $assertionData = Get-TestAssertionResults -TestName $detail.It -FunctionName $funcName
                            if ($assertionData -and $assertionData.Assertions) {
                                $hasAssertionTracking = $true
                                # Index assertions by their description/expectation
                                foreach ($assertion in $assertionData.Assertions) {
                                    $assertionResults[$assertion.Description] = $assertion.Passed
                                }
                            }
                        }
                        
                        # If no in-memory results, try to load from file
                        if (-not $hasAssertionTracking -and $includeTestResults -and $TestResultsPath) {
                            # Look for assertion results JSON files
                            $assertionFiles = @()
                            if (Test-Path $TestResultsPath) {
                                $assertionFiles = Get-ChildItem -Path $TestResultsPath -Filter "*-AssertionResults.json" -File -ErrorAction SilentlyContinue
                            }
                            
                            foreach ($file in $assertionFiles) {
                                try {
                                    $assertionDataFromFile = Get-Content $file.FullName -Raw | ConvertFrom-Json
                                    # Look for our specific test
                                    foreach ($testEntry in $assertionDataFromFile.PSObject.Properties) {
                                        if ($testEntry.Value.TestName -eq $detail.It -and $testEntry.Value.FunctionName -eq $funcName) {
                                            $hasAssertionTracking = $true
                                            foreach ($assertion in $testEntry.Value.Assertions) {
                                                $assertionResults[$assertion.Description] = $assertion.Passed
                                            }
                                            break
                                        }
                                    }
                                    if ($hasAssertionTracking) { break }
                                } catch {
                                    # Ignore file read errors
                                }
                            }
                        }
                        
                        # Add expectations/goals if available
                        if ($detail.Expectations -and $detail.Expectations.Count -gt 0) {
                            $report += "   - **Test Goals:**`n"
                            foreach ($expectation in $detail.Expectations) {
                                # Check if we have individual assertion results
                                $goalIndicator = '-'
                                $hasIndividualResult = $false
                                
                                if ($hasAssertionTracking) {
                                    # Use advanced pattern matching from TestTracking module
                                    if (Get-Command Find-AssertionMatch -ErrorAction SilentlyContinue) {
                                        $match = Find-AssertionMatch -Goal $expectation -AssertionResults $assertionResults -ReturnBestMatch
                                        if ($match -and $match.Score -ge 40) {  # Minimum confidence threshold
                                            $hasIndividualResult = $true
                                            $goalIndicator = if ($assertionResults[$match.AssertionDescription]) {
                                                '**[PASS]**'
                                            } else {
                                                '**[FAIL]**'
                                            }
                                        }
                                    } else {
                                        # Fallback to simple matching if advanced matching not available
                                        foreach ($desc in $assertionResults.Keys) {
                                            if ($desc -like "*$expectation*" -or $expectation -like "*$desc*") {
                                                $hasIndividualResult = $true
                                                $goalIndicator = if ($assertionResults[$desc]) {
                                                    '**[PASS]**'
                                                } else {
                                                    '**[FAIL]**'
                                                }
                                                break
                                            }
                                        }
                                    }
                                }
                                
                                if (-not $hasIndividualResult) {
                                    # Fall back to overall test status only if test was actually run
                                    $goalIndicator = if ($testStatus -and $testStatus -ne "[NOT RUN]") {
                                        switch ($testStatus) {
                                            "[PASS]" { '**[PASS]**' }
                                            "[FAIL]" { '**[FAIL]**' }
                                            "[SKIP]" { '**[SKIP]**' }
                                            default { '-' }
                                        }
                                    } else {
                                        '-'
                                    }
                                }
                                
                                $report += "     - $goalIndicator $expectation`n"
                            }
                        } else {
                            # Try to extract goals from the test description
                            if ($detail.It -match '\[(.+)\]') {
                                $report += "   - **Test Goals:**`n"
                                $goals = $matches[1] -split ';'
                                foreach ($goal in $goals) {
                                    # Check if we have individual assertion results
                                    $goalIndicator = '-'
                                    $hasIndividualResult = $false
                                    
                                    if ($hasAssertionTracking) {
                                        # Try to match goal with assertion results
                                        foreach ($desc in $assertionResults.Keys) {
                                            if ($desc -like "*$($goal.Trim())*" -or $goal.Trim() -like "*$desc*") {
                                                $hasIndividualResult = $true
                                                $goalIndicator = if ($assertionResults[$desc]) {
                                                    '**[PASS]**'
                                                } else {
                                                    '**[FAIL]**'
                                                }
                                                break
                                            }
                                        }
                                    }
                                    
                                    if (-not $hasIndividualResult) {
                                        # Fall back to overall test status only if test was actually run
                                        $goalIndicator = if ($testStatus -and $testStatus -ne "[NOT RUN]") {
                                            switch ($testStatus) {
                                                "[PASS]" { '**[PASS]**' }
                                                "[FAIL]" { '**[FAIL]**' }
                                                "[SKIP]" { '**[SKIP]**' }
                                                default { '-' }
                                            }
                                        } else {
                                            '-'
                                        }
                                    }
                                    
                                    $report += "     - $goalIndicator $($goal.Trim())`n"
                                }
                            }
                        }
                        
                        $testNumber++
                    }
                } else {
                    $report += "- Referenced in tests but no specific test cases found`n"
                }
                $report += "`n"
            }
        }
    }
    
    # Add test status summary from detailed section
    if ($detailTotalCount -gt 0) {
        $report += @"

### Test Status Summary (from Details)

| Status | Count | Percentage |
|--------|-------|------------|
| **PASSED** | $detailPassCount | $([math]::Round(($detailPassCount / $detailTotalCount) * 100, 1))% |
| **FAILED** | $detailFailCount | $([math]::Round(($detailFailCount / $detailTotalCount) * 100, 1))% |
| **SKIPPED** | $detailSkipCount | $([math]::Round(($detailSkipCount / $detailTotalCount) * 100, 1))% |
| **NOT RUN** | $detailNotRunCount | $([math]::Round(($detailNotRunCount / $detailTotalCount) * 100, 1))% |
| **Total** | **$detailTotalCount** | **100%** |

"@
    }
    
    # Add comprehensive cleanup section
    # Ensure variables are collections before accessing .Count
    $unusedExportedList = @($unusedExported)
    $unusedInternalList = @($unusedInternal)
    $totalCleanupItems = $unusedExportedList.Count + $unusedInternalList.Count + $deprecatedTestReferences.Count
    
    if ($totalCleanupItems -gt 0) {
        $report += @"

### Code Cleanup Recommendations

Total items to clean up: **$totalCleanupItems**

#### Functions to Remove ($($unusedExportedList.Count + $unusedInternalList.Count) total)

These functions are not used anywhere in the UpdateLoxone codebase:

| Function | Module | Type | Tested | Action |
|----------|--------|------|--------|--------|
"@
        # First add unused exported functions
        foreach ($func in $unusedExportedList | Sort-Object { $_.Value.Module }, { $_.Key }) {
            $tested = if ($func.Value.Tested) { "Yes" } else { "No" }
            $action = if ($func.Value.Tested) {
                "Remove function + tests"
            } else {
                "**Remove immediately**"
            }
            $report += "`n| ``$($func.Key)`` | $($func.Value.Module) | Exported | $tested | $action |"
        }
        
        # Then add unused internal functions
        foreach ($func in $unusedInternalList | Sort-Object { $_.Value.Module }, { $_.Key }) {
            $tested = if ($func.Value.Tested) { "Yes" } else { "No" }
            $action = if ($func.Value.Tested) {
                "Remove function + tests"
            } else {
                "**Remove immediately**"
            }
            $report += "`n| ``$($func.Key)`` | $($func.Value.Module) | Internal | $tested | $action |"
        }
        
        # Add deprecated test references
        if ($deprecatedTestReferences.Count -gt 0) {
            # Count total occurrences
            $totalOccurrences = 0
            foreach ($ref in $deprecatedTestReferences.Values) {
                $totalOccurrences += $ref.Count
            }
            
            $report += @"

#### Test References to Remove ($($deprecatedTestReferences.Count) unique functions, $totalOccurrences total occurrences)

These function calls in test files reference non-existent functions:

| Referenced Function | Test Files | Occurrences | Action |
|---------------------|------------|-------------|--------|
"@
            foreach ($ref in $deprecatedTestReferences.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending) {
                $testFilesList = $ref.Value -join ', '
                if ($testFilesList.Length -gt 60) {
                    $testFilesList = $testFilesList.Substring(0, 57) + "..."
                }
                $report += "`n| ``$($ref.Key)`` | $testFilesList | $($ref.Value.Count) | Clean up test files |"
            }
            
            $report += @"

##### Deprecated Test Analysis
- **Unique deprecated functions**: $($deprecatedTestReferences.Count)
- **Total occurrences across test files**: $totalOccurrences
- **Average occurrences per function**: $([math]::Round($totalOccurrences / $deprecatedTestReferences.Count, 1))
"@
        }
    }
    
    # Add cleanup summary
    if ($totalCleanupItems -gt 0) {
        $testedButUnused = ($unusedExportedList | Where-Object { $_.Value.Tested }).Count + 
                          ($unusedInternalList | Where-Object { $_.Value.Tested }).Count
        $untestedAndUnused = ($unusedExportedList | Where-Object { -not $_.Value.Tested }).Count + 
                            ($unusedInternalList | Where-Object { -not $_.Value.Tested }).Count
        
        $report += @"

### Cleanup Summary

**Total cleanup required: $totalCleanupItems items**
- **$($unusedExportedList.Count + $unusedInternalList.Count) unused functions** to remove
  - $untestedAndUnused functions with no tests (remove immediately)
  - $testedButUnused functions with tests (remove function + tests)
- **$($deprecatedTestReferences.Count) test references** to non-existent functions to clean up

Since this module is only used internally within UpdateLoxone, all unused functions can be safely removed.

"@
    }
    
    # Add enforcement summary at the end
    $report += @"

---

## Enforcement System Status

### Current Implementation Phase
**$($enforcementMetrics.EnforcementLevel)**

### Features Available
- âœ… **Exception Management**: Grandfathering system for existing violations
- âœ… **New-Code Validation**: Prevents new untested code via pre-commit hooks
- âœ… **CI/CD Integration**: Automated compliance checking in pipelines
- âœ… **Helper Tools**: Test stub generation and compliance checking
- âœ… **Compliance Reporting**: Enhanced reports with enforcement details

### Enforcement Tools
- ``Test-CoverageCompliance``: Full compliance validation
- ``Test-NewCodeCompliance``: New code only validation  
- ``New-TestStub``: Generate test templates
- ``Test-FunctionCoverage``: Check specific functions
- ``Get-ComplianceViolations``: Module-level analysis

### Exception Timeline
$(if ($EnforcementData.Exceptions -and $EnforcementData.Exceptions.grandfathered) {
    $expirations = @()
    $grouped = $EnforcementData.Exceptions.grandfathered.GetEnumerator() | Group-Object { $_.Value.expires }
    foreach ($group in $grouped | Sort-Object Name) {
        $expirations += "- **$($group.Name)**: $($group.Count) exceptions expire"
    }
    $expirations -join "`n"
} else {
    "- No grandfathered exceptions found"
})

### Next Steps
$(if ($enforcementMetrics.GrandfatheredViolations -gt 0) {
    "1. Start writing tests for functions expiring soon`n2. Use ``New-TestStub`` to generate test templates`n3. Monitor compliance with ``Test-CoverageCompliance -ShowViolations``"
} else {
    "1. Maintain 100% compliance for new code`n2. Consider enabling stricter enforcement`n3. Target internal functions for improved coverage"
})
"@
    
    return $report
}
