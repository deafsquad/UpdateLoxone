#Requires -Version 5.0
<#
.SYNOPSIS
    Test coverage analysis module for UpdateLoxone

.DESCRIPTION
    Provides comprehensive test coverage analysis functionality including:
    - Function discovery across all modules
    - Test coverage calculation
    - Report generation with summary and details
    - Deprecated test reference tracking
    - Function usage analysis
#>

# Module variables
$script:ModulePath = if ($PSScriptRoot) { 
    Split-Path $PSScriptRoot -Parent 
} else { 
    # Fallback when PSScriptRoot is not available (e.g., in certain admin contexts)
    $moduleFile = (Get-Module LoxoneUtils).Path
    if ($moduleFile) {
        Split-Path (Split-Path $moduleFile -Parent) -Parent
    } else {
        # Ultimate fallback - use current location
        Get-Location
    }
}
$script:TestPath = Join-Path $script:ModulePath 'tests'

function Get-TestCoverage {
    <#
    .SYNOPSIS
        Analyzes test coverage for the UpdateLoxone project
    
    .DESCRIPTION
        Performs comprehensive analysis of test coverage including function discovery,
        test mapping, and coverage calculation for both exported and internal functions
    
    .PARAMETER ShowDetails
        Shows detailed coverage information in console output
    
    .PARAMETER GenerateReport
        Generates a detailed coverage report file
    
    .PARAMETER OutputPath
        Path where the coverage report will be saved. If not specified, uses TestResults/coverage.md
    
    .PARAMETER CheckUsage
        Performs additional analysis to check if functions are used in the codebase
    
    .PARAMETER ShowIndex
        Shows an index/table of contents in the console output
    
    .PARAMETER IncludeTestResults
        Include test execution results (pass/fail/skip) from the most recent test run
    
    .PARAMETER TestResultsPath
        Path to test results directory. If not specified, uses most recent TestRun
    
    .EXAMPLE
        Get-TestCoverage -GenerateReport -ShowDetails
        
    .EXAMPLE
        Get-TestCoverage -CheckUsage -OutputPath "C:\Reports\coverage.md"
    #>
    [CmdletBinding()]
    param(
        [switch]$ShowDetails,
        [switch]$GenerateReport,
        [string]$OutputPath,
        [switch]$CheckUsage,
        [switch]$ShowIndex,
        [switch]$IncludeTestResults,
        [string]$TestResultsPath
    )
    
    # Set default output path
    if (-not $OutputPath -and $GenerateReport) {
        $OutputPath = Join-Path $script:TestPath "TestResults/coverage.md"
    }
    
    # Initialize collections
    $allFunctions = @{}
    $functionsByModule = @{}
    $deprecatedTestReferences = @{}
    $testFilesAnalyzed = 0
    $totalTestReferences = 0
    
    Write-Host "Enhanced Test Coverage Analysis for UpdateLoxone" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Analysis started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # Phase 1: Extract all functions from source
    Write-Host "Phase 1: Scanning module files..." -ForegroundColor Yellow
    $modulePath = Join-Path $script:ModulePath 'LoxoneUtils'
    $moduleFiles = Get-ChildItem -Path $modulePath -Filter "*.psm1" -File
    
    foreach ($moduleFile in $moduleFiles) {
        Write-Host "  • $($moduleFile.Name)" -ForegroundColor Gray
        $content = Get-Content $moduleFile.FullName -Raw
        
        # Find all function definitions
        $functionMatches = [regex]::Matches($content, 'function\s+(?<name>[\w-]+)\s*{')
        
        $moduleFunctions = @()
        foreach ($match in $functionMatches) {
            $funcName = $match.Groups['name'].Value
            $moduleFunctions += $funcName
            $allFunctions[$funcName] = @{
                Module = $moduleFile.BaseName
                File = $moduleFile.Name
                Exported = $false
                Tested = $false
                TestCount = 0
                TestDetails = @{}
                UsedInCodebase = $false
                UsageLocations = @()
                IsInternal = $false
            }
        }
        
        $functionsByModule[$moduleFile.BaseName] = $moduleFunctions
    }
    
    # Phase 2: Check which functions are exported
    Write-Host ""
    Write-Host "Phase 2: Analyzing module manifest..." -ForegroundColor Yellow
    $psdPath = Join-Path $modulePath 'LoxoneUtils.psd1'
    if (Test-Path $psdPath) {
        $psdContent = Get-Content $psdPath -Raw
        
        # Extract FunctionsToExport
        if ($psdContent -match "FunctionsToExport\s*=\s*@\(([^)]+)\)") {
            $exportedFuncs = $matches[1] -split "[\s,']+" | Where-Object { 
                $_ -and $_ -ne '@(' -and $_ -ne ')' -and $_ -notmatch '^\s*#' 
            }
            
            $validExports = 0
            $invalidExports = 0
            
            foreach ($func in $exportedFuncs) {
                if ($allFunctions.ContainsKey($func)) {
                    $allFunctions[$func].Exported = $true
                    $validExports++
                } else {
                    $invalidExports++
                }
            }
            
            Write-Host "  • Valid exports: $validExports" -ForegroundColor Green
            if ($invalidExports -gt 0) {
                Write-Host "  • Invalid exports: $invalidExports" -ForegroundColor Red
            }
        }
    }
    
    # Determine internal functions
    foreach ($func in $allFunctions.Keys) {
        if (-not $allFunctions[$func].Exported) {
            $allFunctions[$func].IsInternal = $true
        }
    }
    
    # Phase 3: Check function usage in codebase
    if ($CheckUsage) {
        Write-Host ""
        Write-Host "Phase 3: Checking function usage in codebase..." -ForegroundColor Yellow
        
        # Get all PowerShell files
        $allPSFiles = @()
        $allPSFiles += Get-ChildItem -Path $script:ModulePath -Filter "*.ps1" -File
        $allPSFiles += Get-ChildItem -Path $modulePath -Filter "*.psm1" -File
        
        $filesScanned = 0
        foreach ($funcName in $allFunctions.Keys) {
            foreach ($psFile in $allPSFiles) {
                $fileContent = Get-Content $psFile.FullName -Raw
                
                # Skip the file where the function is defined
                if ($psFile.BaseName -eq $allFunctions[$funcName].Module) {
                    continue
                }
                
                # Look for function calls
                if ($fileContent -match "\b$funcName\b\s*(-|$|\s)") {
                    $allFunctions[$funcName].UsedInCodebase = $true
                    $allFunctions[$funcName].UsageLocations += $psFile.Name
                }
                $filesScanned++
            }
        }
        Write-Host "  • Files scanned: $($allPSFiles.Count)" -ForegroundColor Gray
        Write-Host "  • Functions checked: $($allFunctions.Count)" -ForegroundColor Gray
    }
    
    # Phase 4: Scan test files
    Write-Host ""
    Write-Host "Phase 4: Scanning test files..." -ForegroundColor Yellow
    $testFiles = Get-ChildItem -Path $script:TestPath -Filter "*.Tests.ps1" -Recurse
    
    foreach ($testFile in $testFiles) {
        Write-Host "  • $($testFile.Name)" -ForegroundColor Gray
        $testContent = Get-Content $testFile.FullName -Raw
        $testFilesAnalyzed++
        
        # Check each function for test coverage
        foreach ($funcName in $allFunctions.Keys) {
            if ($testContent -match "\b$funcName\b") {
                $allFunctions[$funcName].Tested = $true
                $allFunctions[$funcName].TestCount++
                $totalTestReferences++
                
                # Get detailed test context
                $testContexts = Get-TestContext -TestContent $testContent -FunctionName $funcName -TestFileName $testFile.Name
                
                foreach ($context in $testContexts) {
                    $key = "$($context.Describe) - $($context.It)"
                    if (-not $allFunctions[$funcName].TestDetails.ContainsKey($key)) {
                        $allFunctions[$funcName].TestDetails[$key] = @{
                            Describe = $context.Describe
                            It = $context.It
                            TestFiles = @()
                            Expectations = $context.Expectations
                        }
                    }
                    $allFunctions[$funcName].TestDetails[$key].TestFiles += $context.TestFile
                }
            }
        }
        
        # Find deprecated test references (functions that don't exist)
        # Only look for specific patterns that indicate actual function calls
        $deprecatedFound = @{}
        
        # Pattern 1: Mock statements for functions that don't exist
        # This is the most reliable indicator of deprecated functions
        $mockPattern = 'Mock\s+(?:-CommandName\s+)?[''"]?([A-Z][\w-]+)[''"]?\s*(?:-|{|\s|$)'
        $mockMatches = [regex]::Matches($testContent, $mockPattern)
        foreach ($match in $mockMatches) {
            $funcName = $match.Groups[1].Value
            # Skip if it's a known function
            if (-not $allFunctions.ContainsKey($funcName)) {
                # Only skip very specific PowerShell core cmdlets
                # The original pattern was too broad and caught legitimate deprecated functions
                $isBuiltIn = $funcName -match '^(Write|Read|Get|Set|Test)-(Host|Output|Error|Warning|Verbose|Debug|Content|Item|ChildItem|Location|Path|Variable)$' -or
                            $funcName -match '^(Import|Export|Select|Where|Sort|Group|Format)-(Module|Object|String|List|Table|Wide|Custom)$' -or
                            $funcName -match '^(Start|Stop|Wait|Invoke)-(Process|Service|Job|Sleep|Command|Expression|WebRequest|RestMethod)$'
                
                if (-not $isBuiltIn) {
                    $deprecatedFound[$funcName] = $true
                }
            }
        }
        
        # Pattern 2: Function calls in test assertions (Should -Contain, etc.)
        $assertionPattern = 'Should\s+-Contain\s+[''"]([A-Z][\w-]+)[''"]'
        $assertionMatches = [regex]::Matches($testContent, $assertionPattern)
        foreach ($match in $assertionMatches) {
            $funcName = $match.Groups[1].Value
            if (-not $allFunctions.ContainsKey($funcName)) {
                $deprecatedFound[$funcName] = $true
            }
        }
        
        # Pattern 3: Get-Command checks for our functions  
        $getCommandPattern = 'Get-Command\s+[''"]?([A-Z][\w-]+)[''"]?\s*-ErrorAction'
        $getCommandMatches = [regex]::Matches($testContent, $getCommandPattern)
        foreach ($match in $getCommandMatches) {
            $funcName = $match.Groups[1].Value
            if (-not $allFunctions.ContainsKey($funcName)) {
                $deprecatedFound[$funcName] = $true
            }
        }
        
        # Add found deprecated references
        foreach ($funcName in $deprecatedFound.Keys) {
            # Skip ONLY Pester built-in commands and PowerShell language keywords
            # Do NOT skip functions that are mocked in tests but don't exist in our codebase
            if ($funcName -in @(
                # Pester commands
                'Should', 'Describe', 'Context', 'It', 'BeforeAll', 'BeforeEach', 'AfterAll', 'AfterEach',
                'Mock', 'Assert', 'InModuleScope',
                # PowerShell language keywords (not functions)
                'If', 'Else', 'ElseIf', 'For', 'ForEach', 'While', 'Do', 'Switch', 'Return', 'Break', 'Continue',
                'Try', 'Catch', 'Finally', 'Function', 'Filter', 'Class', 'Enum', 'Using', 'Param',
                'Begin', 'Process', 'End', 'DynamicParam', 'Hidden', 'Static', 'Public', 'Private',
                # Common parameter names that are definitely not functions
                'Path', 'LiteralPath', 'Name', 'Value', 'Force', 'Recurse', 'WhatIf', 'Confirm',
                'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'ErrorVariable',
                'PassThru', 'Scope', 'Module', 'Property', 'Filter', 'Include', 'Exclude',
                # PowerShell automatic variables
                'True', 'False', 'Null', 'PSScriptRoot', 'PSCommandPath', 'MyInvocation', 'PSBoundParameters')) {
                continue
            }
            
            if (-not $deprecatedTestReferences.ContainsKey($funcName)) {
                $deprecatedTestReferences[$funcName] = @()
            }
            if ($testFile.Name -notin $deprecatedTestReferences[$funcName]) {
                $deprecatedTestReferences[$funcName] += $testFile.Name
            }
        }
    }
    
    # Generate statistics
    $exportedFunctions = $allFunctions.GetEnumerator() | Where-Object { $_.Value.Exported }
    $internalFunctions = $allFunctions.GetEnumerator() | Where-Object { -not $_.Value.Exported }
    $testedExported = $exportedFunctions | Where-Object { $_.Value.Tested }
    $untestedExported = $exportedFunctions | Where-Object { -not $_.Value.Tested }
    $testedInternal = $internalFunctions | Where-Object { $_.Value.Tested }
    $untestedInternal = $internalFunctions | Where-Object { -not $_.Value.Tested }
    
    if ($CheckUsage) {
        $unusedExported = $exportedFunctions | Where-Object { -not $_.Value.UsedInCodebase }
        $unusedInternal = $internalFunctions | Where-Object { -not $_.Value.UsedInCodebase }
    } else {
        $unusedExported = @()
        $unusedInternal = @()
    }
    
    # Calculate coverage percentages
    $exportedCoverage = if ($exportedFunctions.Count -gt 0) { 
        [math]::Round(($testedExported.Count / $exportedFunctions.Count) * 100, 1) 
    } else { 0 }
    $internalCoverage = if ($internalFunctions.Count -gt 0) { 
        [math]::Round(($testedInternal.Count / $internalFunctions.Count) * 100, 1) 
    } else { 0 }
    $totalCoverage = [math]::Round((($testedExported.Count + $testedInternal.Count) / $allFunctions.Count) * 100, 1)
    
    # Display summary
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Yellow
    Write-Host "COVERAGE ANALYSIS SUMMARY" -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Yellow
    Write-Host ""
    
    if ($ShowIndex) {
        Write-Host "INDEX:" -ForegroundColor Cyan
        Write-Host "  1. Function Statistics" -ForegroundColor Gray
        Write-Host "  2. Coverage Metrics" -ForegroundColor Gray
        Write-Host "  3. Untested Functions" -ForegroundColor Gray
        Write-Host "  4. Deprecated Test References" -ForegroundColor Gray
        Write-Host "  5. Module Breakdown" -ForegroundColor Gray
        if ($CheckUsage) {
            Write-Host "  6. Unused Functions" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    Write-Host "1. FUNCTION STATISTICS:" -ForegroundColor Cyan
    Write-Host "   Total Functions: $($allFunctions.Count)" -ForegroundColor White
    Write-Host "   - Exported: $($exportedFunctions.Count)" -ForegroundColor Green
    Write-Host "   - Internal: $($internalFunctions.Count)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Test Files Analyzed: $testFilesAnalyzed" -ForegroundColor White
    Write-Host "   Total Test References: $totalTestReferences" -ForegroundColor White
    Write-Host ""
    
    Write-Host "2. COVERAGE METRICS:" -ForegroundColor Cyan
    $coverageColor = if ($totalCoverage -ge 80) { 'Green' } elseif ($totalCoverage -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host "   Overall Coverage: $($totalCoverage)%" -ForegroundColor $coverageColor
    Write-Host "   - Exported: $($testedExported.Count)/$($exportedFunctions.Count) (${exportedCoverage}%)" -ForegroundColor Green
    Write-Host "   - Internal: $($testedInternal.Count)/$($internalFunctions.Count) (${internalCoverage}%)" -ForegroundColor Gray
    Write-Host ""
    
    # Show untested functions if ShowDetails
    if ($ShowDetails -and $untestedExported.Count -gt 0) {
        Write-Host "3. UNTESTED EXPORTED FUNCTIONS ($($untestedExported.Count)):" -ForegroundColor Red
        foreach ($func in @($untestedExported) | Sort-Object { $_.Value.Module }, { $_.Key }) {
            $usageInfo = if ($CheckUsage) {
                if ($func.Value.UsedInCodebase) {
                    " [USED]"
                } else {
                    " [UNUSED]"
                }
            } else { "" }
            Write-Host "   • $($func.Key) [$($func.Value.Module)]$usageInfo" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    # Get test results if requested
    $testResults = @{}
    if ($IncludeTestResults) {
        Write-Host ""
        Write-Host "Phase 5: Loading test execution results..." -ForegroundColor Yellow
        $testResults = Get-TestResults -TestResultsPath $TestResultsPath
        Write-Host "  • Test results loaded: $($testResults.Count) functions with results" -ForegroundColor Gray
    }
    
    # Generate report if requested
    if ($GenerateReport) {
        Write-Host "Generating coverage report..." -ForegroundColor Gray
        
        # Calculate dead test ratio for report
        $deadTestCalculation = @{
            ValidReferences = $totalTestReferences
            DeprecatedReferences = $deprecatedTestReferences.Count
            TotalReferences = $totalTestReferences + $deprecatedTestReferences.Count
            Percentage = if (($totalTestReferences + $deprecatedTestReferences.Count) -gt 0) {
                [math]::Round(($deprecatedTestReferences.Count / ($totalTestReferences + $deprecatedTestReferences.Count)) * 100, 1)
            } else { 0 }
        }
        
        $reportContent = Format-TestCoverageReport -CoverageData @{
            AllFunctions = $allFunctions
            FunctionsByModule = $functionsByModule
            DeprecatedTestReferences = $deprecatedTestReferences
            Statistics = @{
                TotalFunctions = $allFunctions.Count
                ExportedFunctions = $exportedFunctions.Count
                InternalFunctions = $internalFunctions.Count
                TestedExported = $testedExported.Count
                TestedInternal = $testedInternal.Count
                UntestedExported = $untestedExported.Count
                UntestedInternal = $untestedInternal.Count
                UnusedExported = $unusedExported.Count
                UnusedInternal = $unusedInternal.Count
                TotalCoverage = $totalCoverage
                ExportedCoverage = $exportedCoverage
                InternalCoverage = $internalCoverage
                DeprecatedTests = $deprecatedTestReferences.Count
                TestFilesAnalyzed = $testFilesAnalyzed
                TotalTestReferences = $totalTestReferences
            }
            UntestedExported = $untestedExported
            UnusedExported = $unusedExported
            UnusedInternal = $unusedInternal
            CheckUsage = $CheckUsage
            IncludeTestResults = $IncludeTestResults
            TestResults = $testResults
            InvocationInfo = ""  # Placeholder for now
            Runtime = "0m0s"     # Placeholder for now
        } -DeadTestCalculation $deadTestCalculation
        
        $reportContent | Out-File $OutputPath -Encoding UTF8
        Write-Host ""
        Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
    }
    
    # Return summary object
    return @{
        TotalFunctions = $allFunctions.Count
        ExportedFunctions = $exportedFunctions.Count
        InternalFunctions = $internalFunctions.Count
        TestedExported = $testedExported.Count
        TestedInternal = $testedInternal.Count
        UntestedExported = $untestedExported.Count
        UntestedInternal = $untestedInternal.Count
        UnusedExported = $unusedExported.Count
        UnusedInternal = $unusedInternal.Count
        TotalCoverage = $totalCoverage
        ExportedCoverage = $exportedCoverage
        InternalCoverage = $internalCoverage
        DeprecatedTests = $deprecatedTestReferences.Count
        TestFilesAnalyzed = $testFilesAnalyzed
        TotalTestReferences = $totalTestReferences
    }
}

function Get-TestContext {
    <#
    .SYNOPSIS
        Extracts test context information from test content
    
    .DESCRIPTION
        Parses test file content to extract Describe/Context/It blocks
        that reference a specific function, including test expectations
    #>
    [CmdletBinding()]
    param(
        [string]$TestContent,
        [string]$FunctionName,
        [string]$TestFileName
    )
    
    $contexts = @()
    
    # Use a much simpler approach - find Context and It blocks independently
    # Find the Describe block title
    $describePattern = 'Describe\s+["'']([^"'']+)["'']'
    $describeMatch = [regex]::Match($TestContent, $describePattern)
    $describeTitle = if ($describeMatch.Success) { $describeMatch.Groups[1].Value } else { "Unknown" }
    
    # Only process if the test content mentions our function
    if ($TestContent -match "\b$FunctionName\b") {
        
        # Find all Context blocks
        $contextPattern = 'Context\s+["'']([^"'']+)["'']'
        $contextMatches = [regex]::Matches($TestContent, $contextPattern)
        
        # Find all It blocks
        $itPattern = 'It\s+["'']([^"'']+)["'']'
        $itMatches = [regex]::Matches($TestContent, $itPattern)
        
        # If we have Context blocks, pair them with It blocks
        if ($contextMatches.Count -gt 0) {
            foreach ($contextMatch in $contextMatches) {
                $contextTitle = $contextMatch.Groups[1].Value
                $contextStart = $contextMatch.Index
                
                # Find the next Context block or end of file to determine this Context's range
                $nextContextIndex = $TestContent.Length
                foreach ($nextContext in $contextMatches) {
                    if ($nextContext.Index -gt $contextStart -and $nextContext.Index -lt $nextContextIndex) {
                        $nextContextIndex = $nextContext.Index
                    }
                }
                
                # Find It blocks within this Context range
                $contextItBlocks = @()
                foreach ($itMatch in $itMatches) {
                    if ($itMatch.Index -gt $contextStart -and $itMatch.Index -lt $nextContextIndex) {
                        $contextItBlocks += $itMatch
                    }
                }
                
                # Create entries for each It block in this Context
                if ($contextItBlocks.Count -gt 0) {
                    foreach ($it in $contextItBlocks) {
                        $itTitle = $it.Groups[1].Value
                        
                        # Extract expectations (comprehensive)
                        $expectations = @()
                        $itContent = ""
                        
                        # Try to get the content after the It statement (larger window)
                        $itEnd = $it.Index + $it.Length
                        if ($itEnd -lt $TestContent.Length) {
                            $itContent = $TestContent.Substring($itEnd, [Math]::Min(1500, $TestContent.Length - $itEnd))
                            
                            # Comprehensive Should assertion parsing
                            $shouldMatches = [regex]::Matches($itContent, 'Should\s+(-\w+)(?:\s+([^;\n}]+))?')
                            foreach ($shouldMatch in $shouldMatches) {
                                $assertion = $shouldMatch.Groups[1].Value
                                $value = if ($shouldMatch.Groups[2].Success) { $shouldMatch.Groups[2].Value.Trim() } else { "" }
                                
                                switch ($assertion) {
                                    "-Be" { 
                                        if ($value -match '^\$?(true|false)$') {
                                            $expectations += "expects boolean result: $value"
                                        } elseif ($value -match '^\d+$') {
                                            $expectations += "expects numeric value: $value"
                                        } else {
                                            $expectations += "expects exact value: $value"
                                        }
                                    }
                                    "-BeExactly" { $expectations += "expects exact match: $value" }
                                    "-BeLike" { $expectations += "expects pattern match: $value" }
                                    "-BeOfType" { $expectations += "expects specific type: $value" }
                                    "-BeGreaterThan" { $expectations += "expects value greater than: $value" }
                                    "-BeLessThan" { $expectations += "expects value less than: $value" }
                                    "-BeNullOrEmpty" { $expectations += "expects null or empty result" }
                                    "-Contain" { $expectations += "expects output to contain: $value" }
                                    "-Match" { $expectations += "expects regex match: $value" }
                                    "-Exist" { $expectations += "expects file/path to exist" }
                                    "-Throw" { 
                                        if ($value) {
                                            $expectations += "expects exception: $value"
                                        } else {
                                            $expectations += "expects to throw any exception"
                                        }
                                    }
                                    "-Not" { 
                                        # Handle -Not assertions
                                        if ($itContent -match 'Should\s+-Not\s+-(\w+)(?:\s+([^;\n}]+))?') {
                                            $notAssertion = $matches[1]
                                            $notValue = if ($matches[2]) { $matches[2].Trim() } else { "" }
                                            $expectations += "expects NOT ${notAssertion}: ${notValue}"
                                        }
                                    }
                                    default { $expectations += "expects assertion: $assertion $value" }
                                }
                            }
                            
                            # Look for Mock assertions
                            $mockMatches = [regex]::Matches($itContent, 'Assert-MockCalled\s+(?:-CommandName\s+)?([A-Z][\w-]+)(?:\s+-Times\s+(\d+))?')
                            foreach ($mockMatch in $mockMatches) {
                                $mockCmd = $mockMatch.Groups[1].Value
                                $times = if ($mockMatch.Groups[2].Success) { $mockMatch.Groups[2].Value } else { "any number of"
                                }
                                $expectations += "expects $mockCmd to be called $times times"
                            }
                            
                            # Look for parameter validation tests
                            if ($itContent -match 'ParameterArgumentValidationError') {
                                $expectations += "expects parameter validation error"
                            }
                            
                            # Look for specific error patterns
                            if ($itContent -match '-ErrorId\s+"([^"]+)"') {
                                $expectations += "expects specific error ID: $($matches[1])"
                            }
                            
                            # Look for file operations
                            if ($itContent -match 'Out-File|Set-Content|Add-Content') {
                                $expectations += "expects file write operation"
                            }
                            if ($itContent -match 'Get-Content|Test-Path') {
                                $expectations += "expects file read/check operation"
                            }
                        }
                        
                        $contexts += @{
                            Describe = $describeTitle
                            It = $itTitle
                            TestFile = $TestFileName
                            Expectations = $expectations
                        }
                    }
                } else {
                    # No It blocks found in this Context, use fallback
                    $contexts += @{
                        Describe = $describeTitle
                        It = "Tests within context ($contextTitle)"
                        TestFile = $TestFileName
                        Expectations = @()
                    }
                }
            }
        } else {
            # No Context blocks, look for standalone It blocks
            foreach ($itMatch in $itMatches) {
                $itTitle = $itMatch.Groups[1].Value
                
                # Extract expectations (comprehensive)
                $expectations = @()
                $itContent = ""
                
                # Try to get the content after the It statement (larger window)
                $itEnd = $itMatch.Index + $itMatch.Length
                if ($itEnd -lt $TestContent.Length) {
                    $itContent = $TestContent.Substring($itEnd, [Math]::Min(1500, $TestContent.Length - $itEnd))
                    
                    # Comprehensive Should assertion parsing
                    $shouldMatches = [regex]::Matches($itContent, 'Should\s+(-\w+)(?:\s+([^;\n}]+))?')
                    foreach ($shouldMatch in $shouldMatches) {
                        $assertion = $shouldMatch.Groups[1].Value
                        $value = if ($shouldMatch.Groups[2].Success) { $shouldMatch.Groups[2].Value.Trim() } else { "" }
                        
                        switch ($assertion) {
                            "-Be" { 
                                if ($value -match '^\$?(true|false)$') {
                                    $expectations += "expects boolean result: $value"
                                } elseif ($value -match '^\d+$') {
                                    $expectations += "expects numeric value: $value"
                                } else {
                                    $expectations += "expects exact value: $value"
                                }
                            }
                            "-BeExactly" { $expectations += "expects exact match: $value" }
                            "-BeLike" { $expectations += "expects pattern match: $value" }
                            "-BeOfType" { $expectations += "expects specific type: $value" }
                            "-BeGreaterThan" { $expectations += "expects value greater than: $value" }
                            "-BeLessThan" { $expectations += "expects value less than: $value" }
                            "-BeNullOrEmpty" { $expectations += "expects null or empty result" }
                            "-Contain" { $expectations += "expects output to contain: $value" }
                            "-Match" { $expectations += "expects regex match: $value" }
                            "-Exist" { $expectations += "expects file/path to exist" }
                            "-Throw" { 
                                if ($value) {
                                    $expectations += "expects exception: $value"
                                } else {
                                    $expectations += "expects to throw any exception"
                                }
                            }
                            "-Not" { 
                                # Handle -Not assertions
                                if ($itContent -match 'Should\s+-Not\s+-(\w+)(?:\s+([^;\n}]+))?') {
                                    $notAssertion = $matches[1]
                                    $notValue = if ($matches[2]) { $matches[2].Trim() } else { "" }
                                    $expectations += "expects NOT ${notAssertion}: ${notValue}"
                                }
                            }
                            default { $expectations += "expects assertion: $assertion $value" }
                        }
                    }
                    
                    # Look for Mock assertions
                    $mockMatches = [regex]::Matches($itContent, 'Assert-MockCalled\s+(?:-CommandName\s+)?([A-Z][\w-]+)(?:\s+-Times\s+(\d+))?')
                    foreach ($mockMatch in $mockMatches) {
                        $mockCmd = $mockMatch.Groups[1].Value
                        $times = if ($mockMatch.Groups[2].Success) { $mockMatch.Groups[2].Value } else { "any number of" }
                        $expectations += "expects $mockCmd to be called $times times"
                    }
                    
                    # Look for parameter validation tests
                    if ($itContent -match 'ParameterArgumentValidationError') {
                        $expectations += "expects parameter validation error"
                    }
                    
                    # Look for specific error patterns
                    if ($itContent -match '-ErrorId\s+"([^"]+)"') {
                        $expectations += "expects specific error ID: $($matches[1])"
                    }
                    
                    # Look for file operations
                    if ($itContent -match 'Out-File|Set-Content|Add-Content') {
                        $expectations += "expects file write operation"
                    }
                    if ($itContent -match 'Get-Content|Test-Path') {
                        $expectations += "expects file read/check operation"
                    }
                }
                
                $contexts += @{
                    Describe = $describeTitle
                    It = $itTitle
                    TestFile = $TestFileName
                    Expectations = $expectations
                }
            }
        }
    }
    
    # If still no contexts found but function is mentioned, create a fallback
    if ($contexts.Count -eq 0 -and $TestContent -match "\b$FunctionName\b") {
        $contexts += @{
            Describe = $describeTitle
            It = "Referenced in test file"
            TestFile = $TestFileName
            Expectations = @()
        }
    }
    
    return $contexts
}

function Format-TestCoverageReport {
    <#
    .SYNOPSIS
        Formats coverage data into a comprehensive markdown report
    
    .DESCRIPTION
        Takes coverage analysis data and generates a detailed markdown report
        with executive summary at the top followed by detailed analysis
    #>
    [CmdletBinding()]
    param(
        [hashtable]$CoverageData,
        [string]$Runtime = "N/A",
        [hashtable]$DeadTestCalculation = @{}
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
    
    # Calculate KPIs
    $totalDefined = $stats.TotalFunctions
    $deadFunctions = if ($checkUsage) { $stats.UnusedExported + $stats.UnusedInternal } else { 0 }
    $deadFunctionPercent = if ($totalDefined -gt 0) { [math]::Round(($deadFunctions / $totalDefined) * 100, 1) } else { 0 }
    
    $activeFunctions = $totalDefined - $deadFunctions
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
    
    
    # Test execution summary is now handled by New-TestCoverageReport function
    $testExecutionSummary = ""
    
    # Start building the report with executive summary at the top
    $report = @"
# UpdateLoxone Test Coverage Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (Runtime: $Runtime) | $invocationInfo$testExecutionSummary

## Key Performance Indicators (KPIs)

| Metric | Value | Status |
|--------|-------|--------|
| **Active Function Coverage** | $activeCoverage% ($activeTested/$activeFunctions) | $(if ($activeCoverage -ge 80) { "Good" } elseif ($activeCoverage -ge 60) { "Fair" } else { "Poor" }) |
| **Dead Code Ratio** | $deadFunctionPercent% ($deadFunctions/$totalDefined functions) | $(if ($deadFunctionPercent -le 10) { "Good" } elseif ($deadFunctionPercent -le 30) { "Fair" } else { "Poor" }) |
| **Dead Test Ratio** | $deadTestPercent% ($($deadTestCalculation.DeprecatedReferences)/$($deadTestCalculation.TotalReferences) refs) | $(if ($deadTestPercent -le 10) { "Good" } elseif ($deadTestPercent -le 20) { "Fair" } else { "Poor" }) |

### KPI Calculation Formulas

- **Active Function Coverage** = (Tested Functions in Active Code) / (Total Active Functions) * 100
  - Active functions are those actually used in the codebase (not dead code)
  
- **Dead Code Ratio** = (Unused Functions) / (Total Functions) * 100  
  - Functions defined but never called anywhere in the codebase
  
- **Dead Test Ratio** = (Deprecated Function References) / (Total Function References) * 100
  - Measures what percentage of function references in tests point to non-existent functions
  - Formula: Deprecated function refs / (Valid function refs + Deprecated function refs)
  - Calculation: $($deadTestCalculation.DeprecatedReferences) / ($($deadTestCalculation.ValidReferences) + $($deadTestCalculation.DeprecatedReferences)) = $deadTestPercent%
  
Note: This compares function references (102 valid + 95 deprecated = 197 total), not test cases (313 executed).

### Test Execution Context

- **Test Cases Executed**: $($totalPassed + $totalFailed) (from XML results)
- **Test Cases Skipped**: $totalSkipped (includes system tests when not running as admin)
- **Total Test Cases**: $totalTests

## Executive Summary

**Overall Coverage: $($stats.TotalCoverage)%** | Exported: $($stats.ExportedCoverage)% | Internal: $($stats.InternalCoverage)%

### Quick Stats
- **Total Functions**: $($stats.TotalFunctions) (Exported: $($stats.ExportedFunctions), Internal: $($stats.InternalFunctions))
- **Test Coverage**: $($stats.TestedExported + $stats.TestedInternal)/$($stats.TotalFunctions) functions tested
- **Test Files**: $($stats.TestFilesAnalyzed) files analyzed
- **Test References**: $($stats.TotalTestReferences) function references found$(if ($includeTestResults -and $testResults.Count -gt 0) {
    # Note: These totals were already calculated above for the header
    "`n- **Test Execution**: $totalTests tests ($totalPassed passed, $totalFailed failed, $totalSkipped skipped) in $([math]::Round($totalTime, 2))s"
} else {
    "`n- **Test Execution**: Not available (coverage analysis only)"
})

### Critical Issues
1. **Untested Exported Functions**: $($stats.UntestedExported) functions need tests
2. **Untested Internal Functions**: $($stats.UntestedInternal) functions need tests  
3. **Deprecated Test References**: $($stats.DeprecatedTests) references to non-existent functions
$(if ($checkUsage) { "4. **Unused Functions**: $($stats.UnusedExported) exported, $($stats.UnusedInternal) internal functions unused" })

### Action Items
- **Immediate**: Write tests for the $($stats.UntestedExported) untested exported functions
- **Consider**: Write tests for the $($stats.UntestedInternal) untested internal functions (lower priority)
- **Short-term**: Clean up $($stats.DeprecatedTests) deprecated test references
- **Goal**: Achieve 90%+ coverage for exported functions (currently $($stats.ExportedCoverage)%)

---

## Detailed Analysis

### Coverage by Function Type

| Category | Tested | Total | Coverage |
|----------|--------|-------|----------|
| Exported Functions | $($stats.TestedExported) | $($stats.ExportedFunctions) | $($stats.ExportedCoverage)% |
| Internal Functions | $($stats.TestedInternal) | $($stats.InternalFunctions) | $($stats.InternalCoverage)% |
| **Total** | **$(($stats.TestedExported + $stats.TestedInternal))** | **$($stats.TotalFunctions)** | **$($stats.TotalCoverage)%** |

### Untested Exported Functions ($($stats.UntestedExported))

These functions are part of the public API but lack test coverage:

| Function | Module | Usage Status |
|----------|--------|--------------|
"@

    foreach ($func in @($untestedExported) | Sort-Object { $_.Value.Module }, { $_.Key }) {
        $usageStatus = if ($checkUsage) {
            if ($func.Value.UsedInCodebase) {
                "Used in: $($func.Value.UsageLocations -join ', ')"
            } else {
                "**UNUSED - candidate for removal**"
            }
        } else { "Not analyzed" }
        $report += "`n| ``$($func.Key)`` | $($func.Value.Module) | $usageStatus |"
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
                
                # Add test result summary if available
                if ($includeTestResults -and $testResults.ContainsKey($funcName)) {
                    $result = $testResults[$funcName]
                    $totalTests = $result.Passed + $result.Failed + $result.Skipped
                    $resultText = " - Test Results: "
                    if ($result.Failed -gt 0) {
                        $resultText += "**FAILED** ("
                    } else {
                        $resultText += "Passed ("
                    }
                    $resultText += "$($result.Passed) passed"
                    if ($result.Failed -gt 0) {
                        $resultText += ", $($result.Failed) failed"
                    }
                    if ($result.Skipped -gt 0) {
                        $resultText += ", $($result.Skipped) skipped"
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
                        $testStatus = ""
                        $testTime = ""
                        if ($includeTestResults -and $testResults.ContainsKey($funcName)) {
                            # Try to match by test description
                            $matchingResult = $testResults[$funcName].Details | Where-Object { 
                                $_.TestName -like "*$($detail.It)*" -or 
                                $_.TestName -like "*$($detail.Describe)*"
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
                            } else {
                                $testStatus = "[NOT RUN]"
                            }
                        }
                        
                        $report += "`n$testNumber. **Test:** $($detail.It)`n"
                        $report += "   - **File:** $testFiles`n"
                        $report += "   - **Context:** $($detail.Describe)`n"
                        if ($testStatus) {
                            # Add status with markdown formatting for emphasis
                            $statusDisplay = switch ($testStatus) {
                                "[PASS]" { "**[PASS]**" }
                                "[FAIL]" { "**[FAIL]**" }
                                "[SKIP]" { "**[SKIP]**" }
                                "[NOT RUN]" { "**[NOT RUN]**" }
                                default { "**[UNKNOWN]**" }
                            }
                            $report += "   - **Status:** $statusDisplay$testTime`n"
                        }
                        
                        # Add expectations/goals if available
                        if ($detail.Expectations -and $detail.Expectations.Count -gt 0) {
                            $report += "   - **Test Goals:**`n"
                            foreach ($expectation in $detail.Expectations) {
                                $report += "     - $expectation`n"
                            }
                        } else {
                            # Try to extract goals from the test description
                            if ($detail.It -match '\[(.+)\]') {
                                $report += "   - **Test Goals:**`n"
                                $goals = $matches[1] -split ';'
                                foreach ($goal in $goals) {
                                    $report += "     - $($goal.Trim())`n"
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
    
    return $report
}

function Get-TestResults {
    <#
    .SYNOPSIS
        Loads test results from the most recent test run
    
    .DESCRIPTION
        Reads test result files to get pass/fail/skip status for each test
    #>
    [CmdletBinding()]
    param(
        [string]$TestResultsPath
    )
    
    $testResults = @{}
    
    # Try to find the most recent test results
    if (-not $TestResultsPath) {
        # Try multiple possible locations for test results
        $possiblePaths = @(
            (Join-Path (Split-Path $script:TestPath -Parent) "tests\TestResults"),
            (Join-Path $script:TestPath "TestResults"),
            (Join-Path (Get-Location) "tests\TestResults")
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                # Get most recent TestRun folder
                $mostRecent = Get-ChildItem $path -Filter "TestRun_*" -Directory -ErrorAction SilentlyContinue | 
                              Sort-Object LastWriteTime -Descending | 
                              Select-Object -First 1
                if ($mostRecent) {
                    $TestResultsPath = $mostRecent.FullName
                    break
                }
            }
        }
    }
    
    if ($TestResultsPath -and (Test-Path $TestResultsPath)) {
        # Load test results from XML files
        $xmlFiles = Get-ChildItem $TestResultsPath -Filter "*-TestResults.xml" -File
        
        foreach ($xmlFile in $xmlFiles) {
            try {
                [xml]$xml = Get-Content $xmlFile.FullName -Raw
                
                # Parse test results - Pester NUnit format
                $testCases = $xml.SelectNodes("//test-case")
                foreach ($testCase in $testCases) {
                    $testName = $testCase.GetAttribute("name")
                    $description = $testCase.GetAttribute("description")
                    $result = $testCase.GetAttribute("result")
                    $success = $testCase.GetAttribute("success")
                    $time = $testCase.GetAttribute("time")
                    
                    # Extract function name from test name or description
                    # Test names are usually in format "Module.Function.Test Description"
                    $functionName = $null
                    if ($testName -match '\.([A-Z][\w-]+)\s+(Function|Command|Cmdlet)?\.') {
                        $functionName = $matches[1]
                    } elseif ($description -match '([A-Z][\w-]+)') {
                        # Fallback to first PascalCase word in description
                        $functionName = $matches[1]
                    }
                    
                    if ($functionName) {
                        if (-not $testResults.ContainsKey($functionName)) {
                            $testResults[$functionName] = @{
                                Passed = 0
                                Failed = 0
                                Skipped = 0
                                TotalTime = 0
                                Details = @()
                            }
                        }
                        
                        # Map NUnit result status to our format
                        if ($success -eq "True") {
                            $testResults[$functionName].Passed++
                        } elseif ($result -eq "Failure") {
                            $testResults[$functionName].Failed++
                        } elseif ($result -eq "Ignored" -or $result -eq "Skipped") {
                            $testResults[$functionName].Skipped++
                        }
                        
                        if ($time) {
                            $testResults[$functionName].TotalTime += [double]$time
                        }
                        
                        $testResults[$functionName].Details += @{
                            TestName = $description
                            Result = $result
                            Time = $time
                            Success = $success
                        }
                    }
                }
            } catch {
                Write-Verbose "Failed to parse $($xmlFile.Name): $_"
            }
        }
    }
    
    return $testResults
}

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
        [switch]$IncludeTestResults = $true,
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
                        $invocationInfo += " → $($caller.FunctionName)"
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
    
    # Calculate test execution coverage if we have test results
    $testExecutionCoverage = 0
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
                $totalSkipped = if ($jsonSummary.Overall.PSObject.Properties['Skipped']) { $jsonSummary.Overall.Skipped } else { 0 }
                if ($totalTestCount -gt 0) {
                    # Test execution coverage = (Passed + Failed) / Total * 100
                    # We count failed tests as "executed" since they ran, just didn't pass
                    $executedTests = $passedTests + $jsonSummary.Overall.Failed
                    $testExecutionCoverage = [math]::Round(($executedTests / $totalTestCount) * 100, 0)
                }
            } catch {
                # Fall back to zeros if JSON parsing fails
            }
        }
    }
    
    # Format KPIs with leading zeros
    # New format: TTTT-EEE-FFF-DDD-TTT where:
    # TTTT = Total test count (4 digits)
    # EEE = Test execution coverage % (3 digits)
    # FFF = Function coverage % (3 digits)
    # DDD = Dead code ratio % (3 digits)
    # TTT = Dead test ratio % (3 digits)
    $kpiString = "{0:D4}-{1:D3}-{2:D3}-{3:D3}-{4:D3}" -f $totalTestCount, [int]$testExecutionCoverage, [int]$activeCoverage, [int]$deadCodeRatio, [int]$deadTestRatio
    
    # Create final filename with timestamp and KPIs
    $finalReportName = "coverage_${timestamp}_${kpiString}.md"
    $reportPath = Join-Path $coverageDir $finalReportName
    
    # Now generate the report with all proper context
    # Get all the data we need for the report
    $allFunctions = @{}
    $functionsByModule = @{}
    $deprecatedTestReferences = @{}
    $testResults = @{}
    
    # We need to re-run just to get the detailed data since Get-TestCoverage returns summary only
    # This is a temporary workaround - ideally Get-TestCoverage should return all data
    Write-Host "Generating detailed coverage report..." -ForegroundColor Gray
    
    # Skip the direct Format-TestCoverageReport call since it doesn't have the proper data
    # The re-run below will generate the correct report with all the detailed data
    
    # For now, let's use the old approach until we can refactor properly
    # Re-run with report generation
    $tempCoverageResult = Get-TestCoverage `
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
        if ($testExecutionInfo -eq $null -or [string]::IsNullOrWhiteSpace($testExecutionInfo)) {
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
- **$([int]$activeCoverage)%** function coverage
- **$([int]$deadCodeRatio)%** dead code ratio
- **$([int]$deadTestRatio)%** dead test ratio
"@
    
    # Fix the header to include invocation info, runtime, and test execution
    $newHeader = @"
# UpdateLoxone Test Coverage Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (Runtime: $runtimeFormatted) | $invocationInfo$testExecutionInfo
$filenameBreakdown
"@
    
    # Replace the header
    $reportContent = $reportContent -replace '# UpdateLoxone Test Coverage Report\s*\n\s*Generated: [^\n]+', $newHeader
    
    $reportContent | Out-File $reportPath -Encoding UTF8
    
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

# Export module functions
Export-ModuleMember -Function @(
    'Get-TestCoverage',
    'New-TestCoverageReport',
    'Get-TestResults'
)