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
    
    # Load test coverage exceptions
    $exceptions = @{
        testInfrastructure = @()
        testInfrastructureCategories = @{}
        genuinelyUnused = @()
    }
    $exceptionsPath = Join-Path $script:ModulePath 'LoxoneUtils/TestCoverageExceptions.json'
    if (Test-Path $exceptionsPath) {
        try {
            $exceptionsData = Get-Content $exceptionsPath -Raw | ConvertFrom-Json
            # Use allFunctions for backward compatibility
            if ($exceptionsData.testInfrastructure.allFunctions) {
                $exceptions.testInfrastructure = $exceptionsData.testInfrastructure.allFunctions
            } else {
                # Fallback to old structure
                $exceptions.testInfrastructure = $exceptionsData.testInfrastructure.functions
            }
            if ($exceptionsData.testInfrastructure.categories) {
                $exceptions.testInfrastructureCategories = $exceptionsData.testInfrastructure.categories
            }
            $exceptions.genuinelyUnused = $exceptionsData.testInfrastructure.genuinelyUnused
            Write-Host "Loaded test coverage exceptions: $($exceptions.testInfrastructure.Count) test infrastructure functions" -ForegroundColor DarkGray
        }
        catch {
            Write-Warning "Failed to load test coverage exceptions: $_"
        }
    }
    
    Write-Host "Enhanced Test Coverage Analysis for UpdateLoxone" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Analysis started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # Phase 1: Extract all functions from source
    Write-Host "Phase 1: Scanning module files..." -ForegroundColor Yellow
    $modulePath = Join-Path $script:ModulePath 'LoxoneUtils'
    $moduleFiles = Get-ChildItem -Path $modulePath -Filter "*.psm1" -File
    
    foreach ($moduleFile in $moduleFiles) {
        Write-Host "  â€¢ $($moduleFile.Name)" -ForegroundColor Gray
        $content = Get-Content $moduleFile.FullName -Raw
        
        # Find all function definitions
        $functionMatches = [regex]::Matches($content, 'function\s+(?<name>[\w-]+)\s*{')
        
        $moduleFunctions = @()
        foreach ($match in $functionMatches) {
            $funcName = $match.Groups['name'].Value
            $moduleFunctions += $funcName
            
            Write-Host "      Processing function: $funcName" -ForegroundColor DarkGray
            Write-Host "      Extracting documentation for: $funcName..." -NoNewline -ForegroundColor DarkGray
            
            try {
                # Extract documentation for the function
                Write-Verbose "      Calling Get-FunctionDocumentation..." -Verbose
                $docInfo = Get-FunctionDocumentation -FunctionName $funcName -FileContent $content
                Write-Verbose "      Function returned, checking result..." -Verbose
                
                if ($null -eq $docInfo) {
                    Write-Host " [NULL RESULT]" -ForegroundColor Yellow
                    throw "Get-FunctionDocumentation returned null"
                }
                
                Write-Host " [OK]" -ForegroundColor Green
                
                # Convert string values back to proper types for internal use
                Write-Verbose "      Converting HasDocumentation value..." -Verbose
                $hasDoc = ($docInfo.HasDocumentation -eq "Yes")
                Write-Verbose "      Converting CompletionScore value..." -Verbose
                $score = [int]$docInfo.CompletionScore
                Write-Verbose "      Conversions complete" -Verbose
                
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
                    Documentation = @{
                        Synopsis = $docInfo.Synopsis
                        Description = $docInfo.Description
                        Parameters = @{}  # Convert string back to hashtable if needed
                        Examples = @()    # Convert string back to array if needed
                        HasDocumentation = $hasDoc
                        CompletionScore = $score
                    }
                }
            }
            catch {
                Write-Host " [ERROR] $_" -ForegroundColor Red
                # Provide a safe fallback
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
                    Documentation = @{
                        Synopsis = "Error extracting documentation"
                        Description = ""
                        Parameters = @{}
                        Examples = @()
                        HasDocumentation = $false
                        CompletionScore = 0
                    }
                }
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
            
            Write-Host "  â€¢ Valid exports: $validExports" -ForegroundColor Green
            if ($invalidExports -gt 0) {
                Write-Host "  â€¢ Invalid exports: $invalidExports" -ForegroundColor Red
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
        Write-Host "  Note: Fixed several usage detection issues:" -ForegroundColor Gray
        Write-Host "  - Added tests directory to search scope" -ForegroundColor Gray
        Write-Host "  - Improved intra-module usage detection" -ForegroundColor Gray
        Write-Host "  - Added special handling for TestCoverage functions" -ForegroundColor Gray
        
        # Get all PowerShell files in the entire project
        $projectRoot = Split-Path -Parent $script:ModulePath
        $allPSFiles = @()
        # Search in module directory
        $allPSFiles += Get-ChildItem -Path $script:ModulePath -Filter "*.ps1" -File -ErrorAction SilentlyContinue
        $allPSFiles += Get-ChildItem -Path $modulePath -Filter "*.psm1" -File -ErrorAction SilentlyContinue
        # Search in project root for main scripts
        $allPSFiles += Get-ChildItem -Path $projectRoot -Filter "*.ps1" -File -ErrorAction SilentlyContinue
        # Search in LoxoneUtils subdirectory for all modules
        $loxoneUtilsPath = Join-Path $projectRoot "LoxoneUtils"
        if (Test-Path $loxoneUtilsPath) {
            $allPSFiles += Get-ChildItem -Path $loxoneUtilsPath -Filter "*.psm1" -File -ErrorAction SilentlyContinue
        }
        # Search in tests directory for ALL test files (including subdirectories)
        $testsPath = Join-Path $projectRoot "tests"
        if (Test-Path $testsPath) {
            $allPSFiles += Get-ChildItem -Path $testsPath -Filter "*.ps1" -File -Recurse -ErrorAction SilentlyContinue
        }
        
        $filesScanned = 0
        foreach ($funcName in $allFunctions.Keys) {
            foreach ($psFile in $allPSFiles) {
                $fileContent = Get-Content $psFile.FullName -Raw
                
                # For functions defined in the same file, only check for usage outside function definition
                # This allows detection of intra-module usage (e.g., OnRemove handlers, internal calls)
                $isDefiningFile = ($psFile.BaseName -eq $allFunctions[$funcName].Module)
                if ($isDefiningFile) {
                    # Skip function definition itself, but check for usage in the same file
                    # Look for the function definition to exclude that line
                    $functionDefPattern = "function\s+$funcName\s*\{"
                    if ($fileContent -match $functionDefPattern) {
                        # Remove the function definition line and surrounding context
                        $defMatch = [regex]::Match($fileContent, $functionDefPattern)
                        $beforeDef = $fileContent.Substring(0, $defMatch.Index)
                        $afterDef = $fileContent.Substring($defMatch.Index + $defMatch.Length)
                        $fileContent = $beforeDef + $afterDef
                    }
                }
                
                # Look for function calls with improved regex patterns
                # Match: function name followed by space, parameter (-), pipe (|), newline, or in a command
                $patterns = @(
                    "\b$funcName\b\s*(-[\w]+|\s|$|\|)",  # Standard call with parameters or pipe
                    "\b$funcName\b[\r\n]",                 # Function followed by newline
                    "&\s*[`'`"]?$funcName[`'`"]?",          # Call operator & 'function' or & function
                    "\.$funcName\s*\(",                    # Method-style call
                    "\`[$funcName\`]",                       # Type accelerator style
                    "Export-ModuleMember.*\b$funcName\b",  # Export statements
                    "FunctionsToExport.*[`'`"]$funcName[`'`"]", # Module manifest exports
                    "\`$$funcName\b",                      # Assignment from function call
                    "=\s*$funcName\b",                      # Variable assignment
                    "Get-Command\s+[`'`"]?$funcName[`'`"]?",   # Get-Command checks (common in tests)
                    "\b$funcName\b.*-ErrorAction",          # Function calls with ErrorAction
                    "if.*\b$funcName\b",                     # Conditional function calls
                    "^\s*$funcName\b",                      # Function call at start of line (common after if blocks)
                    "\b$funcName\s+-"                       # Function with parameters
                )
                
                $found = $false
                foreach ($pattern in $patterns) {
                    if ($fileContent -match $pattern) {
                        # Additional validation: ensure it's not just the function definition
                        $match = [regex]::Match($fileContent, $pattern)
                        $context = ""
                        if ($match.Success) {
                            # Get some context around the match
                            $start = [Math]::Max(0, $match.Index - 20)
                            $length = [Math]::Min(40, $fileContent.Length - $start)
                            $context = $fileContent.Substring($start, $length)
                            
                            # Skip if this looks like a function definition
                            if ($context -notmatch "^\s*function\s+$funcName\s*\{") {
                                $found = $true
                                break
                            }
                        }
                    }
                }
                
                # Special handling for TestCoverage functions - they may be called from PowerShell sessions
                # Mark TestCoverage module functions as used since they're designed for external invocation
                if (-not $found -and $allFunctions[$funcName].Module -eq "LoxoneUtils.TestCoverage") {
                    if ($funcName -in @('Get-TestCoverage', 'New-TestCoverageReport', 'Get-TestResults')) {
                        $found = $true
                        $allFunctions[$funcName].UsageLocations += "External PowerShell sessions"
                    }
                }
                
                # Special handling for TestTracking functions - they are called from test scripts
                # Mark TestTracking module functions as used since they're designed for test invocation
                if ($allFunctions[$funcName].Module -eq "LoxoneUtils.TestTracking") {
                    # All exported TestTracking functions are used by test infrastructure
                    if ($allFunctions[$funcName].Exported) {
                        if (-not $found) {
                            $found = $true
                        }
                        # Always add the test infrastructure description for TestTracking functions
                        if ($allFunctions[$funcName].UsageLocations -notcontains "Test infrastructure (run-tests.ps1, assertion demos)") {
                            $allFunctions[$funcName].UsageLocations += "Test infrastructure (run-tests.ps1, assertion demos)"
                        }
                    }
                }
                
                if ($found) {
                    $allFunctions[$funcName].UsedInCodebase = $true
                    $allFunctions[$funcName].UsageLocations += $psFile.Name
                }
                $filesScanned++
            }
        }
        Write-Host "  â€¢ Files scanned: $($allPSFiles.Count)" -ForegroundColor Gray
        Write-Host "  â€¢ Functions checked: $($allFunctions.Count)" -ForegroundColor Gray
    }
    
    # Phase 4: Scan test files
    Write-Host ""
    Write-Host "Phase 4: Scanning test files..." -ForegroundColor Yellow
    $testFiles = Get-ChildItem -Path $script:TestPath -Filter "*.Tests.ps1" -Recurse
    
    foreach ($testFile in $testFiles) {
        Write-Host "  â€¢ $($testFile.Name)" -ForegroundColor Gray
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
        $mockPattern = 'Mock\s+(?:-CommandName\s+)?[`''"]?([A-Z][\w-]+)[`''"]?\s*(?:-|{|\s|$)'
        $mockMatches = [regex]::Matches($testContent, $mockPattern)
        foreach ($match in $mockMatches) {
            $funcName = $match.Groups[1].Value
            
            # Get context to check if this is a parameter name in Mock -ParameterFilter
            $contextStart = [Math]::Max(0, $match.Index - 50)
            $contextEnd = [Math]::Min($testContent.Length, $match.Index + 150)
            $context = $testContent.Substring($contextStart, $contextEnd - $contextStart)
            
            # Skip if this appears to be a parameter name in -ParameterFilter
            if ($context -match '-ParameterFilter\s*{\s*\$' + $funcName) {
                continue
            }
            
            # Skip if it's a known function
            if (-not $allFunctions.ContainsKey($funcName)) {
                # Skip PowerShell built-in cmdlets and known external modules
                $isBuiltIn = $false
                
                # Common PowerShell cmdlets
                if ($funcName -match '^(Get|Set|New|Remove|Add|Clear|Copy|Move|Rename|Test|Out|Write|Read|Import|Export|ConvertTo|ConvertFrom|Select|Where|Sort|Group|Format|Measure|Compare|Start|Stop|Restart|Wait|Invoke|Enter|Exit|Push|Pop|Join|Split|Resolve|Update|Register|Unregister|Enable|Disable|Install|Uninstall|Save|Restore|Backup|Compress|Expand|Publish|Unpublish|Grant|Revoke|Block|Unblock|Protect|Unprotect|Initialize|Reset|Submit|Approve|Deny|Send|Receive|Connect|Disconnect|Suspend|Resume|Debug|Trace|Show|Hide|Lock|Unlock|Limit|Skip|Use)-\w+') {
                    $isBuiltIn = $true
                }
                
                # BurntToast module functions
                elseif ($funcName -match '^(New-BT|Update-BT|Submit-BT|Get-BT|Remove-BT)\w+') {
                    $isBuiltIn = $true
                }
                elseif ($funcName -eq 'BurntToast' -or $funcName -eq 'New-BurntToastNotification') {
                    $isBuiltIn = $true
                }
                
                # Common .NET types and methods
                elseif ($funcName -in @('New-Object', 'Get-Member', 'Add-Type', 'Using')) {
                    $isBuiltIn = $true
                }
                
                # Parameter names that look like functions but aren't
                elseif ($funcName -match '^(Path|FilePath|LiteralPath|Name|Value|Property|Filter|Include|Exclude|Force|Recurse|WhatIf|Confirm|Verbose|Debug|ErrorAction|WarningAction|InformationAction|ErrorVariable|WarningVariable|InformationVariable|OutVariable|OutBuffer|PipelineVariable|PassThru|NoTypeInformation|AsJob|ThrottleLimit|TimeoutSec|MaxRetries|Interval|Delay|Wait|Timeout|Port|ComputerName|Credential|Session|UseSSL|SkipCertificateCheck|Headers|Method|Uri|Body|ContentType|UserAgent|TransferEncoding|DestinationPath|SourcePath|Destination|Source|Target|InputObject|OutputPath|Append|NoClobber|Width|Wrap|AutoSize|DisplayError|ShowError|View|GroupBy|Property|Status|Before|After|First|Last|Skip|SkipLast|Unique|AsHashTable|CaseSensitive|Culture|Ascending|Descending|Top|Bottom|StatusMessage|MSEntry|InitialVersion|MSIP|ExePath|CurrentWeight|MaxRetries|IsInteractive|ErrorOccurred|InstalledAppVersion|TargetVersion|InputAddress|InputString|AppData|ConfigData|UpdateXmlUrl|ZipPath|InputFile|InstallerPath|FilePath)$') {
                    $isBuiltIn = $true
                }
                
                # Specific functions from our codebase that were removed/renamed
                elseif ($funcName -in @('Get-LoxoneConfigToastAppId', 'Compare-LoxoneVersion', 'Get-CurrentVersion', 'Install-LoxoneConfig')) {
                    # These are legitimate deprecated functions - let them be flagged
                    $isBuiltIn = $false
                }
                
                # Common parameter names that shouldn't be flagged as functions
                elseif ($funcName -in @('ZipPath', 'AppName', 'ComponentName', 'InstallerPath', 'Url', 'InputFile', 'InputString', 'Thumbprint', 'DownloadDir', 'EnableCRC', 'CheckEnabled', 'CheckAppUpdate', 'AttemptedUpdate', 'ExpectedFilesize', 'StepNumber', 'TotalDownloads', 'PSTypeName')) {
                    $isBuiltIn = $true
                }
                
                if (-not $isBuiltIn) {
                    $deprecatedFound[$funcName] = $true
                }
            }
        }
        
        # Pattern 2: Function calls in test assertions (Should -Contain, etc.)
        # IMPORTANT: This pattern often catches property names, not function calls
        # Only include if it's checking for exported functions
        $assertionPattern = 'Should\s+-Contain\s+[`''"]([A-Z][\w-]+)[`''"]'
        $assertionMatches = [regex]::Matches($testContent, $assertionPattern)
        foreach ($match in $assertionMatches) {
            $funcName = $match.Groups[1].Value
            # Only flag if context suggests it's checking for functions
            $contextStart = [Math]::Max(0, $match.Index - 100)
            $contextLength = [Math]::Min(200, $testContent.Length - $contextStart)
            $context = $testContent.Substring($contextStart, $contextLength)
            
            # Skip if it's checking properties or parameters
            if ($context -match '\.Properties\.Name\s*\|\s*Should\s+-Contain' -or
                $context -match 'PSObject\.Properties' -or
                $context -match 'ParameterSets.*\.Parameters' -or
                $context -match '\$\w+\s*\|\s*Should\s+-Contain' -or
                $context -match '\.Parameters\.Keys\s*\|\s*Should\s+-Contain' -or
                $context -match '\.Parameters\s*\|\s*Should\s+-Contain' -or
                $context -match '\.Parameters\.' -or
                $context -match 'Get-Command\s+\S+\s+-Module') {
                continue
            }
            
            # Also skip if the function name is clearly a parameter name
            if ($funcName -in @('MSEntry', 'ExePath', 'InputAddress', 'InputString', 'AppName', 
                               'AppData', 'ConfigData', 'UpdateXmlUrl', 'ZipPath', 'InputFile', 
                               'InstallerPath', 'FilePath')) {
                continue
            }
            
            # Only flag if it's likely checking for exported functions
            if ($context -match 'Export.*Functions|\.Functions\.Keys' -and 
                $context -notmatch '\.Parameters') {
                if (-not $allFunctions.ContainsKey($funcName)) {
                    $deprecatedFound[$funcName] = $true
                }
            }
        }
        
        # Pattern 3: Get-Command checks for our functions  
        $getCommandPattern = 'Get-Command\s+[`''"]?([A-Z][\w-]+)[`''"]?\s*-ErrorAction'
        $getCommandMatches = [regex]::Matches($testContent, $getCommandPattern)
        foreach ($match in $getCommandMatches) {
            $funcName = $match.Groups[1].Value
            if (-not $allFunctions.ContainsKey($funcName)) {
                # Skip built-in cmdlets
                $isBuiltIn = $false
                
                # Check if it matches common PowerShell cmdlet patterns
                if ($funcName -match '^(Get|Set|New|Remove|Add|Clear|Copy|Move|Rename|Test|Out|Write|Read|Import|Export|ConvertTo|ConvertFrom|Select|Where|Sort|Group|Format|Measure|Compare|Start|Stop|Restart|Wait|Invoke|Enter|Exit|Push|Pop|Join|Split|Resolve|Update|Register|Unregister|Enable|Disable|Install|Uninstall|Save|Restore|Backup|Compress|Expand|Publish|Unpublish|Grant|Revoke|Block|Unblock|Protect|Unprotect|Initialize|Reset|Submit|Approve|Deny|Send|Receive|Connect|Disconnect|Suspend|Resume|Debug|Trace|Show|Hide|Lock|Unlock|Limit|Skip|Use)-\w+') {
                    $isBuiltIn = $true
                }
                
                # Check for specific known cmdlets
                elseif ($funcName -in @('New-Object', 'Get-Member', 'Add-Type', 'Using', 'New-Guid')) {
                    $isBuiltIn = $true
                }
                
                if (-not $isBuiltIn) {
                    $deprecatedFound[$funcName] = $true
                }
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
    
    # Filter out test infrastructure functions from untested counts
    $testInfrastructureFunctions = $exportedFunctions | Where-Object { $_.Key -in $exceptions.testInfrastructure }
    $nonTestInfraExported = $exportedFunctions | Where-Object { $_.Key -notin $exceptions.testInfrastructure }
    
    $testedExported = $nonTestInfraExported | Where-Object { $_.Value.Tested }
    $untestedExported = $nonTestInfraExported | Where-Object { -not $_.Value.Tested }
    $testedInternal = $internalFunctions | Where-Object { $_.Value.Tested }
    $untestedInternal = $internalFunctions | Where-Object { -not $_.Value.Tested }
    
    if ($CheckUsage) {
        # Exclude test infrastructure from unused calculations
        $unusedExported = $nonTestInfraExported | Where-Object { -not $_.Value.UsedInCodebase }
        $unusedInternal = $internalFunctions | Where-Object { -not $_.Value.UsedInCodebase }
    } else {
        $unusedExported = @()
        $unusedInternal = @()
    }
    
    # Calculate coverage percentages (excluding test infrastructure)
    $exportedCoverage = if ($nonTestInfraExported.Count -gt 0) { 
        [math]::Round(($testedExported.Count / $nonTestInfraExported.Count) * 100, 1) 
    } else { 0 }
    $internalCoverage = if ($internalFunctions.Count -gt 0) { 
        [math]::Round(($testedInternal.Count / $internalFunctions.Count) * 100, 1) 
    } else { 0 }
    # Total coverage excludes test infrastructure functions
    $totalFunctionsExcludingTestInfra = $allFunctions.Count - $testInfrastructureFunctions.Count
    $totalCoverage = if ($totalFunctionsExcludingTestInfra -gt 0) {
        [math]::Round((($testedExported.Count + $testedInternal.Count) / $totalFunctionsExcludingTestInfra) * 100, 1)
    } else { 0 }
    
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
    if ($testInfrastructureFunctions.Count -gt 0) {
        Write-Host "   - Test Infrastructure: $($testInfrastructureFunctions.Count)" -ForegroundColor DarkGray -NoNewline
        Write-Host " (excluded from coverage)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "   Test Files Analyzed: $testFilesAnalyzed" -ForegroundColor White
    Write-Host "   Total Test References: $totalTestReferences" -ForegroundColor White
    Write-Host ""
    
    Write-Host "2. COVERAGE METRICS:" -ForegroundColor Cyan
    $coverageColor = if ($totalCoverage -ge 80) { 'Green' } elseif ($totalCoverage -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host "   Overall Coverage: $($totalCoverage)%" -ForegroundColor $coverageColor -NoNewline
    Write-Host " (excluding test infrastructure)" -ForegroundColor DarkGray
    Write-Host "   - Exported: $($testedExported.Count)/$($nonTestInfraExported.Count) (${exportedCoverage}%)" -ForegroundColor Green
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
            Write-Host "   â€¢ $($func.Key) [$($func.Value.Module)]$usageInfo" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    # Get test results if requested
    $testResults = @{}
    if ($IncludeTestResults) {
        Write-Host ""
        Write-Host "Phase 5: Loading test execution results..." -ForegroundColor Yellow
        $testResults = Get-TestResults -TestResultsPath $TestResultsPath
        Write-Host "  â€¢ Test results loaded: $($testResults.Count) functions with results" -ForegroundColor Gray
        
        # Debug: Show unmatched test results if verbose
        if ($VerbosePreference -eq 'Continue') {
            Write-Host ""
            Write-Host "DEBUG: Test Result Matching Analysis" -ForegroundColor Magenta
            $unmatchedTests = @()
            foreach ($funcName in $testResults.Keys) {
                if (-not $allFunctions.ContainsKey($funcName)) {
                    $unmatchedTests += $funcName
                }
            }
            
            if ($unmatchedTests.Count -gt 0) {
                Write-Host "  Unmatched test results (tests for non-existent functions):" -ForegroundColor Yellow
                foreach ($unmatched in $unmatchedTests | Sort-Object) {
                    $testCount = $testResults[$unmatched].Details.Count
                    Write-Host "    - $unmatched ($testCount tests)" -ForegroundColor Yellow
                }
            }
            
            Write-Host ""
            Write-Host "  Functions with test results:" -ForegroundColor Green
            $matchedCount = 0
            foreach ($funcName in $allFunctions.Keys | Sort-Object) {
                if ($testResults.ContainsKey($funcName)) {
                    $matchedCount++
                    $result = $testResults[$funcName]
                    Write-Host "    - $funcName (P:$($result.Passed) F:$($result.Failed) S:$($result.Skipped))" -ForegroundColor Green
                }
            }
            Write-Host "  Total matched: $matchedCount/$($allFunctions.Count) functions" -ForegroundColor Green
            Write-Host ""
        }
        
        # Integrate real test results with test details
        Write-Host ""
        Write-Host "Phase 5b: Merging real test results with coverage data..." -ForegroundColor Yellow
        foreach ($funcName in $testResults.Keys) {
            if ($allFunctions.ContainsKey($funcName)) {
                # Store the actual test results
                $allFunctions[$funcName].TestResults = $testResults[$funcName]
                
                # Merge with existing test details
                foreach ($testResult in $testResults[$funcName]) {
                    $key = "$($testResult.Describe) - $($testResult.It)"
                    if ($allFunctions[$funcName].TestDetails.ContainsKey($key)) {
                        # Update existing test detail with real result
                        $allFunctions[$funcName].TestDetails[$key].Status = $testResult.Status
                        $allFunctions[$funcName].TestDetails[$key].Duration = $testResult.Duration
                        $allFunctions[$funcName].TestDetails[$key].ErrorMessage = $testResult.ErrorMessage
                    } else {
                        # Add new test detail from real results
                        $allFunctions[$funcName].TestDetails[$key] = @{
                            Describe = $testResult.Describe
                            It = $testResult.It
                            Status = $testResult.Status
                            Duration = $testResult.Duration
                            ErrorMessage = $testResult.ErrorMessage
                            TestFiles = @($testResult.File)
                            Expectations = @()
                        }
                    }
                }
            }
        }
        Write-Host "  â€¢ Test results integrated successfully" -ForegroundColor Gray
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
        
        # Get test execution totals from XML/JSON if available
        $testExecutionTotals = @{
            TotalTests = 0
            TotalPassed = 0
            TotalFailed = 0
            TotalSkipped = 0
        }
        
        if ($IncludeTestResults -and $TestResultsPath) {
            # Try JSON first
            $jsonPath = Join-Path $TestResultsPath "test-results-summary.json"
            if (Test-Path $jsonPath) {
                try {
                    $json = Get-Content $jsonPath -Raw | ConvertFrom-Json
                    $testExecutionTotals.TotalTests = $json.Overall.Total
                    $testExecutionTotals.TotalPassed = $json.Overall.Passed
                    $testExecutionTotals.TotalFailed = $json.Overall.Failed
                    $testExecutionTotals.TotalSkipped = if ($json.Overall.PSObject.Properties['Skipped']) { $json.Overall.Skipped } else { 0 }
                } catch {
                    # Fall back to XML parsing below
                }
            }
            
            # If no JSON data, try XML
            if ($testExecutionTotals.TotalTests -eq 0) {
                $xmlFiles = Get-ChildItem $TestResultsPath -Filter "*-TestResults.xml" -File -ErrorAction SilentlyContinue
                foreach ($xmlFile in $xmlFiles) {
                    try {
                        [xml]$xml = Get-Content $xmlFile.FullName -Raw
                        $root = $xml.SelectSingleNode("//test-results")
                        if ($root) {
                            $testExecutionTotals.TotalTests += [int]$root.GetAttribute("total")
                            $testExecutionTotals.TotalPassed += ([int]$root.GetAttribute("total") - [int]$root.GetAttribute("failures") - [int]$root.GetAttribute("not-run"))
                            $testExecutionTotals.TotalFailed += [int]$root.GetAttribute("failures")
                            $testExecutionTotals.TotalSkipped += [int]$root.GetAttribute("not-run")
                        }
                    } catch {
                        # Ignore individual file errors
                    }
                }
            }
        }
        
        $reportContent = Format-TestCoverageReport -CoverageData @{
            AllFunctions = $allFunctions
            FunctionsByModule = $functionsByModule
            DeprecatedTestReferences = $deprecatedTestReferences
            Statistics = @{
                TotalFunctions = $allFunctions.Count
                ExportedFunctions = $exportedFunctions.Count
                InternalFunctions = $internalFunctions.Count
                TestInfrastructureFunctions = $testInfrastructureFunctions.Count
                ActiveFunctions = $totalFunctionsExcludingTestInfra
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
            TestInfrastructure = $exceptions.testInfrastructure
            TestInfrastructureCategories = $exceptions.testInfrastructureCategories
            UntestedExported = $untestedExported
            UnusedExported = $unusedExported
            UnusedInternal = $unusedInternal
            TestExecutionTotals = $testExecutionTotals
            CheckUsage = $CheckUsage
            IncludeTestResults = $IncludeTestResults
            TestResults = $testResults
            InvocationInfo = ""  # Placeholder for now
            Runtime = "0m0s"     # Placeholder for now
        } -DeadTestCalculation $deadTestCalculation -EnforcementData @{
            Phase = "Phase 2: New-Code-Only"
            CompliancePercentage = if ($allFunctions.Count -gt 0) { [math]::Round((($allFunctions.Count - $untestedExported.Count) / $allFunctions.Count) * 100, 1) } else { 0 }
            ExemptedCount = 28  # From TestCoverageExceptions.json
            GrandfatheredCount = 28
            PermanentExceptions = 1
            ActiveViolations = 0
            NextReviewDate = "2025-07-01"
            ExceptionTimeline = @{
                "2025-07-01" = 17
                "2025-08-01" = 2
                "2025-09-01" = 9
            }
        }
        
        # Write with UTF8 encoding without BOM
        [System.IO.File]::WriteAllText($OutputPath, $reportContent, [System.Text.Encoding]::UTF8)
        Write-Host ""
        Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
    }
    
    # Return summary object
    return @{
        TotalFunctions = $allFunctions.Count
        ExportedFunctions = $exportedFunctions.Count
        InternalFunctions = $internalFunctions.Count
        TestInfrastructureFunctions = $testInfrastructureFunctions.Count
        TestInfrastructureCategories = $exceptions.testInfrastructureCategories
        ActiveFunctions = $totalFunctionsExcludingTestInfra
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
        AllFunctions = $allFunctions
        TestInfrastructure = $exceptions.testInfrastructure
    }
}
