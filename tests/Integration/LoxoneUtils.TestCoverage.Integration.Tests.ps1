# Integration tests for TestCoverage functions that require real module analysis

Describe "Get-TestCoverage Integration Tests" -Tag 'Integration', 'TestCoverage' {
    
    BeforeAll {
        # Import the module
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
        
        # Set up paths
        $script:ModulePath = Split-Path -Parent $modulePath
        $script:TestPath = Split-Path -Parent $PSScriptRoot
        
        # Create test results directory
        $script:TestResultsPath = Join-Path $TestDrive "TestResults"
        New-Item -ItemType Directory -Path $script:TestResultsPath -Force | Out-Null
    }
    
    It "Analyzes functions and calculates coverage for real module" {
        # Run actual test coverage analysis on a subset of modules
        $coverage = Get-TestCoverage -TestResultsPath $script:TestResultsPath
        
        # Verify we got a coverage result
        $coverage | Should -Not -BeNullOrEmpty
        $coverage | Should -BeOfType [hashtable]
        
        # Check for expected properties
        $coverage.TotalFunctions | Should -BeGreaterThan 0
        $coverage.ExportedFunctions | Should -BeGreaterThan 0
        $coverage.TestedExported | Should -BeGreaterOrEqual 0
        $coverage.TotalCoverage | Should -BeGreaterOrEqual 0
        $coverage.TotalCoverage | Should -BeLessOrEqual 100
        
        # Verify module analysis worked - AllFunctions is the correct property name
        $coverage.AllFunctions | Should -Not -BeNullOrEmpty
        $coverage.AllFunctions.Count | Should -BeGreaterThan 0
    }
    
    It "Provides verbose output when enabled" {
        # Capture verbose output
        $verboseOutput = @()
        $allOutput = Get-TestCoverage -Verbose -TestResultsPath $script:TestResultsPath -ErrorAction SilentlyContinue 4>&1
        
        # Separate verbose output from regular output
        $coverage = $null
        foreach ($output in $allOutput) {
            if ($output -is [System.Management.Automation.VerboseRecord]) {
                $verboseOutput += $output.Message
            } elseif ($output -is [hashtable]) {
                $coverage = $output
            }
        }
        
        # Check that verbose messages were produced
        $verboseOutput.Count | Should -BeGreaterThan 0
        
        # Verify some expected verbose messages
        $verboseOutput -join "`n" | Should -Match "Analyzing module"
    }
    
    It "Generates coverage report when requested" {
        # Set up output directory - must include the filename since OutputPath expects a full path
        $outputDir = Join-Path $TestDrive "CoverageReports"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        $outputPath = Join-Path $outputDir "coverage.md"
        
        # Generate coverage with report
        $coverage = Get-TestCoverage -GenerateReport -OutputPath $outputPath -TestResultsPath $script:TestResultsPath
        
        # Check that report file was created
        Test-Path $outputPath | Should -Be $true
        
        # Verify report content
        $reportContent = Get-Content -Path $outputPath -Raw
        $reportContent | Should -Match "Test Coverage Report"
        $reportContent | Should -Match "Total Functions"
        $reportContent | Should -Match "Coverage"
    }
}

Describe "Get-TestResults Integration Tests" -Tag 'Integration', 'TestCoverage' {
    
    BeforeAll {
        # Import the module
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
        
        # Create a real test results directory
        $script:RealTestResultsPath = Join-Path $TestDrive "RealTestResults"
        New-Item -ItemType Directory -Path $script:RealTestResultsPath -Force | Out-Null
    }
    
    It "Parses real Pester test results with verbose output" {
        # First run a simple test to generate real results
        $testScript = @'
Describe "Sample Test" {
    It "Should pass" {
        $true | Should -Be $true
    }
    It "Should fail" {
        $false | Should -Be $true
    }
}
'@
        $testFile = Join-Path $TestDrive "Sample.Tests.ps1"
        Set-Content -Path $testFile -Value $testScript
        
        # Run Pester to generate real results
        $config = New-PesterConfiguration
        $config.Run.Path = $testFile
        $config.Run.PassThru = $true
        $config.TestResult.Enabled = $true
        $config.TestResult.OutputPath = Join-Path $script:RealTestResultsPath "Unit-TestResults.xml"
        $config.TestResult.OutputFormat = "NUnit2.5"
        $config.Output.Verbosity = 'None'
        
        $pesterResult = Invoke-Pester -Configuration $config
        
        # Verify the test results file was created
        $xmlPath = Join-Path $script:RealTestResultsPath "Unit-TestResults.xml"
        Test-Path $xmlPath | Should -Be $true
        
        # Now test Get-TestResults with verbose output
        $verboseOutput = @()
        $allOutput = Get-TestResults -TestResultsPath $script:RealTestResultsPath -Verbose 4>&1
        
        # Separate verbose output from the actual result
        $actualResults = $null
        foreach ($output in $allOutput) {
            if ($output -is [System.Management.Automation.VerboseRecord]) {
                $verboseOutput += $output.Message
            } elseif ($output -is [hashtable]) {
                $actualResults = $output
            }
        }
        
        # Verify results
        $actualResults | Should -Not -BeNullOrEmpty
        $actualResults | Should -BeOfType [hashtable]
        $verboseOutput.Count | Should -BeGreaterThan 0
        
        # Check verbose messages contain expected information
        $verboseMessages = $verboseOutput -join "`n"
        $verboseMessages | Should -Match "Processing.*TestResults.xml"
        $verboseMessages | Should -Match "Found test case"
    }
}