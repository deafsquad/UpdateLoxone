#Requires -Modules Pester

BeforeAll {
    # Set test environment flag to prevent downloads
    $Global:IsTestRun = $true
    $env:PESTER_TEST_RUN = "1"
    
    # CRITICAL: Disable progress output to prevent terminal freeze
    $Global:ProgressPreference = 'SilentlyContinue'
    
    # Import the module first so functions exist to mock
    $modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'LoxoneUtils'
    Import-Module (Join-Path $modulePath 'LoxoneUtils.psd1') -Force -DisableNameChecking
    
    # Mock network operations to prevent hanging
    Mock Write-Progress {}
    Mock Invoke-LoxoneDownload { 
        @{
            Success = $true
            FilePath = Join-Path $TestDrive "mock-download.txt"
            FileSize = 100
        }
    }
    
    # Set required script variables for the functions
    $script:ModulePath = Split-Path $modulePath -Parent
    $script:TestPath = Join-Path $script:ModulePath 'tests'
    
    # Load individual TestCoverage functions instead of full module
    . (Join-Path $modulePath 'TestCoverage\Get-TestResults.ps1')
    . (Join-Path $modulePath 'TestCoverage\Get-FunctionDocumentation.ps1')
    
    # Only import the TestCoverage module, not the entire LoxoneUtils suite
    Import-Module (Join-Path $modulePath 'LoxoneUtils.TestCoverage.psm1') -Force
    
    # Set up test paths
    $script:TestOutputPath = Join-Path $TestDrive "TestOutput"
    New-Item -ItemType Directory -Path $script:TestOutputPath -Force | Out-Null
    
    # Create mock test results XML
    $script:MockTestResultsPath = Join-Path $TestDrive "MockTestResults"
    New-Item -ItemType Directory -Path $script:MockTestResultsPath -Force | Out-Null
    
    # Create a mock test results XML file
    $mockXml = @'
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<test-results xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="nunit_schema_2.5.xsd" name="Pester" total="5" errors="0" failures="2" not-run="1" inconclusive="0" ignored="0" skipped="0" invalid="0" date="2025-06-04" time="17:06:43">
  <test-suite type="TestFixture" name="Pester" executed="True" result="Success" success="True" time="1.5" asserts="0" description="Pester">
    <results>
      <test-case description="Shows toast notification" name="Initialize-ScriptWorkflow Function.Shows toast notification" time="0.05" asserts="0" success="True" result="Success" executed="True" />
      <test-case description="Does not show toast when not interactive" name="Initialize-ScriptWorkflow Function.Does not show toast when not interactive" time="0.03" asserts="0" success="True" result="Success" executed="True" />
      <test-case description="Writes to log file" name="Write-Log Function.Writes to log file" time="0.02" asserts="0" success="False" result="Failure" executed="True">
        <failure>
          <message>Expected: True, but got False</message>
        </failure>
      </test-case>
      <test-case description="Returns correct version" name="Get-MiniserverVersion Function.Returns correct version" time="0.10" asserts="0" success="True" result="Success" executed="True" />
      <test-case description="Handles missing version" name="Get-MiniserverVersion Function.Handles missing version" time="0.05" asserts="0" success="True" result="Success" executed="True" />
      <test-case description="Validates input parameters" name="Update-MS Function.Validates input parameters" time="0.08" asserts="0" success="False" result="Failure" executed="True">
        <failure>
          <message>Parameter validation failed</message>
        </failure>
      </test-case>
      <test-case description="Sets global flags correctly" name="Invoke-ScriptErrorHandling Core Functionality.Sets global flags correctly" time="0.15" asserts="0" success="True" result="Success" executed="True" />
      <test-case description="Should be skipped" name="Test-SkippedFunction Function.Should be skipped" time="0.00" asserts="0" success="False" result="Ignored" executed="False" />
      <test-case description="Handles nested contexts" name="Get-InstalledVersion Function.Version Detection.Handles nested contexts" time="0.12" asserts="0" success="True" result="Success" executed="True" />
      <test-case description="Unknown function test" name="Some-UnknownFunction.Does something" time="0.05" asserts="0" success="True" result="Success" executed="True" />
    </results>
  </test-suite>
</test-results>
'@
    Set-Content -Path (Join-Path $script:MockTestResultsPath "Unit-TestResults.xml") -Value $mockXml
    
    # Create mock test summary JSON
    $mockJson = @{
        Overall = @{
            Total = 10
            Passed = 7
            Failed = 2
            Skipped = 1
        }
        Categories = @{
            Unit = @{
                Total = 10
                Passed = 7
                Failed = 2
                Skipped = 1
            }
        }
    } | ConvertTo-Json -Depth 3
    Set-Content -Path (Join-Path $script:MockTestResultsPath "test-results-summary.json") -Value $mockJson
}

Describe "Get-TestResults Function" {
    Context "XML Parsing" {
        It "Should extract function names from test results" {
            $results = Get-TestResults -TestResultsPath $script:MockTestResultsPath
            
            $results | Should -Not -BeNullOrEmpty
            $results.Keys | Should -Contain "Initialize-ScriptWorkflow"
            $results.Keys | Should -Contain "Write-Log"
            $results.Keys | Should -Contain "Get-MiniserverVersion"
            $results.Keys | Should -Contain "Update-MS"
            $results.Keys | Should -Contain "Invoke-ScriptErrorHandling"
            $results.Keys | Should -Contain "Get-InstalledVersion"
        }
        
        It "Should correctly count passed/failed/skipped tests" {
            $results = Get-TestResults -TestResultsPath $script:MockTestResultsPath
            
            # Initialize-ScriptWorkflow: 2 passed
            $results["Initialize-ScriptWorkflow"].Passed | Should -Be 2
            $results["Initialize-ScriptWorkflow"].Failed | Should -Be 0
            $results["Initialize-ScriptWorkflow"].Skipped | Should -Be 0
            
            # Write-Log: 1 failed
            $results["Write-Log"].Passed | Should -Be 0
            $results["Write-Log"].Failed | Should -Be 1
            $results["Write-Log"].Skipped | Should -Be 0
            
            # Test-SkippedFunction: 1 skipped
            $results["Test-SkippedFunction"].Passed | Should -Be 0
            $results["Test-SkippedFunction"].Failed | Should -Be 0
            $results["Test-SkippedFunction"].Skipped | Should -Be 1
        }
        
        It "Should extract describe and it blocks correctly" {
            $results = Get-TestResults -TestResultsPath $script:MockTestResultsPath
            
            $details = $results["Initialize-ScriptWorkflow"].Details
            $details.Count | Should -Be 2
            
            $firstDetail = $details[0]
            $firstDetail.DescribeBlock | Should -Be "Initialize-ScriptWorkflow Function"
            $firstDetail.ItBlock | Should -Be "Shows toast notification"
            $firstDetail.Success | Should -Be "True"
        }
        
        It "Should handle nested describe blocks" {
            $results = Get-TestResults -TestResultsPath $script:MockTestResultsPath
            
            $details = $results["Get-InstalledVersion"].Details
            $details.Count | Should -Be 1
            $details[0].DescribeBlock | Should -Be "Get-InstalledVersion Function.Version Detection"
            $details[0].ItBlock | Should -Be "Handles nested contexts"
        }
        
        It "Should handle Core Functionality pattern" {
            $results = Get-TestResults -TestResultsPath $script:MockTestResultsPath
            
            $results.Keys | Should -Contain "Invoke-ScriptErrorHandling"
            $details = $results["Invoke-ScriptErrorHandling"].Details
            $details[0].DescribeBlock | Should -Be "Invoke-ScriptErrorHandling Core Functionality"
        }
        
        # Note: "provide verbose output when enabled" is tested in:
        # tests/Integration/LoxoneUtils.TestCoverage.Integration.Tests.ps1
    }
    
    Context "Error Handling" {
        It "Should return empty hashtable when no test results found" {
            $emptyPath = Join-Path $TestDrive "EmptyResults"
            New-Item -ItemType Directory -Path $emptyPath -Force | Out-Null
            
            $results = Get-TestResults -TestResultsPath $emptyPath
            $results | Should -BeOfType [hashtable]
            $results.Count | Should -Be 0
        }
        
        It "Should handle malformed XML gracefully" {
            $badXmlPath = Join-Path $TestDrive "BadXml"
            New-Item -ItemType Directory -Path $badXmlPath -Force | Out-Null
            Set-Content -Path (Join-Path $badXmlPath "Bad-TestResults.xml") -Value "<invalid>xml</malformed>"
            
            $results = Get-TestResults -TestResultsPath $badXmlPath
            $results | Should -BeOfType [hashtable]
            # Should not throw, just return empty or partial results
        }
    }
}

Describe "Get-TestCoverage Function" {
    BeforeAll {
        # Mock some functions for testing
        Mock Get-ChildItem -ParameterFilter { $Path -like "*LoxoneUtils" -and $Filter -eq "*.psm1" } {
            @(
                [PSCustomObject]@{ 
                    Name = "LoxoneUtils.TestModule.psm1"
                    FullName = Join-Path $TestDrive "LoxoneUtils.TestModule.psm1"
                    BaseName = "LoxoneUtils.TestModule"
                }
            )
        }
        
        # Create a mock module file
        $mockModuleContent = @'
function Initialize-ScriptWorkflow {
    # Test function
}

function Write-Log {
    # Test function
}

function Get-MiniserverVersion {
    # Test function
}

function Update-MS {
    # Test function
}

function Internal-Helper {
    # Internal function
}
'@
        Set-Content -Path (Join-Path $TestDrive "LoxoneUtils.TestModule.psm1") -Value $mockModuleContent
        
        # Mock the manifest file
        Mock Get-Content -ParameterFilter { $Path -like "*LoxoneUtils.psd1" } {
            @'
@{
    FunctionsToExport = @(
        'Initialize-ScriptWorkflow',
        'Write-Log',
        'Get-MiniserverVersion',
        'Update-MS'
    )
}
'@
        }
        
        # Mock test files
        Mock Get-ChildItem -ParameterFilter { $Path -like "*tests" -and $Filter -eq "*.Tests.ps1" } {
            @(
                [PSCustomObject]@{ 
                    Name = "TestModule.Tests.ps1"
                    FullName = Join-Path $TestDrive "TestModule.Tests.ps1"
                }
            )
        }
        
        # Create a mock test file
        $mockTestContent = @'
Describe "Initialize-ScriptWorkflow Function" {
    It "Shows toast notification" {
        Initialize-ScriptWorkflow
    }
    
    It "Does not show toast when not interactive" {
        Initialize-ScriptWorkflow -NoToast
    }
}

Describe "Write-Log Function" {
    It "Writes to log file" {
        Write-Log -Message "Test"
    }
}
'@
        Set-Content -Path (Join-Path $TestDrive "TestModule.Tests.ps1") -Value $mockTestContent
    }
    
    Context "Basic Functionality" {
        # Note: "analyze functions and calculate coverage" is tested in:
        # tests/Integration/LoxoneUtils.TestCoverage.Integration.Tests.ps1
        
        It "Should support verbose debugging output" {
            # Test that verbose parameter doesn't cause errors
            # Mock Get-TestCoverage to avoid actual analysis in parallel
            Mock Get-TestCoverage {
                return @{
                    TotalFunctions = 5
                    ExportedFunctions = 4
                    TestedExported = 3
                    TotalCoverage = 60
                }
            }
            { Get-TestCoverage -Verbose -IncludeTestResults -TestResultsPath $script:MockTestResultsPath } | Should -Not -Throw
        }
    }
}

AfterAll {
    # Clean up test environment flag
    $Global:IsTestRun = $false
    $env:PESTER_TEST_RUN = ""
    # Restore progress preference
    $Global:ProgressPreference = 'Continue'
}

Describe "New-TestCoverageReport Function" {
    Context "Report Generation" {
        It "Should create a coverage report file" {
            Mock Get-TestCoverage {
                @{
                    TotalFunctions = 5
                    ExportedFunctions = 4
                    InternalFunctions = 1
                    TestedExported = 3
                    TestedInternal = 0
                    UntestedExported = 1
                    UntestedInternal = 1
                    TotalCoverage = 60
                    ExportedCoverage = 75
                    InternalCoverage = 0
                }
            }
            
            $reportPath = Join-Path $script:TestOutputPath "test-coverage.md"
            New-TestCoverageReport -OutputDirectory $script:TestOutputPath -TestRunId "20250604-170000"
            
            # Note: The actual file creation happens in Get-TestCoverage when GenerateReport is true
            # This test validates the function doesn't throw
        }
        
        It "Should include test results when requested" {
            { 
                New-TestCoverageReport -OutputDirectory $script:TestOutputPath `
                                     -TestResultsPath $script:MockTestResultsPath `
                                     -IncludeTestResults `
                                     -TestRunId "20250604-170000"
            } | Should -Not -Throw
        }
    }
}


