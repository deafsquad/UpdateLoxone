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
                    $functionName = $null
                    
                    # First try to extract from the test name
                    if ($testName -match '^([A-Z][\w-]+)(?:\s+(?:Function|Command|Cmdlet))?\.' ) {
                        $functionName = $matches[1]
                    }
                    # Also try nested describe blocks
                    elseif ($testName -match '^([A-Z][\w-]+)\s+(?:Function|Command|Cmdlet)\.') {
                        $functionName = $matches[1]
                    }
                    # Try to extract from a pattern like "FunctionName Core Functionality.Description"
                    elseif ($testName -match '^([A-Z][\w-]+)\s+Core\s+Functionality\.') {
                        $functionName = $matches[1]
                    }
                    # If that fails, try a more general pattern
                    elseif ($testName -match '([A-Z][\w-]+)') {
                        # Get the first PascalCase/hyphenated word that looks like a PowerShell function
                        $functionName = $matches[1]
                    }
                    
                    # Store test result details
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
                        
                        # Extract test context (Describe/It blocks)
                        $testParts = $testName -split '\.'
                        if ($testParts.Count -gt 1) {
                            # For nested contexts like "Get-InstalledVersion Function.Version Detection.Handles nested contexts"
                            # Take all parts except the last one as the describe block
                            $describe = ($testParts[0..($testParts.Count-2)]) -join '.'
                            $it = $testParts[-1]  # Last part is the It block
                        } else {
                            $describe = $functionName
                            $it = $description
                        }
                        
                        $testResults[$functionName].Details += @{
                            TestName = $description
                            FullName = $testName
                            Result = $result
                            Time = $time
                            Success = $success
                            DescribeBlock = $describe
                            ItBlock = $it
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
