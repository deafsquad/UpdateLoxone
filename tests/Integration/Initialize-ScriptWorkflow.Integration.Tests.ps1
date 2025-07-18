# Integration test for Initialize-ScriptWorkflow that runs in a real script environment

Describe "Initialize-ScriptWorkflow Integration Tests" -Tag 'Integration', 'WorkflowSteps' {
    
    BeforeAll {
        # Import the module
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
        
        # Create a temporary test script that calls Initialize-ScriptWorkflow
        $script:TestScriptPath = Join-Path $TestDrive "TestInitialize.ps1"
        
        # Get absolute path to the module
        $moduleAbsolutePath = (Resolve-Path $modulePath).Path
        
        $scriptContent = @"
param(
    [string]`$ScriptSaveFolder,
    [bool]`$DebugMode = `$false
)

# Temporarily disable test mode to allow logging initialization
`$env:PESTER_TEST_RUN = "0"
`$env:LOXONE_TEST_MODE = "0"
`$Global:IsTestRun = `$false

# Import the module using absolute path
Import-Module '$moduleAbsolutePath' -Force

# Call Initialize-ScriptWorkflow with real invocation context
`$result = Initialize-ScriptWorkflow -BoundParameters `$PSBoundParameters -PSScriptRoot `$PSScriptRoot -MyInvocation `$MyInvocation

# Output the result as JSON for easy parsing
`$result | ConvertTo-Json -Depth 10
"@
        Set-Content -Path $script:TestScriptPath -Value $scriptContent
    }
    
    It "Successfully initializes workflow context in real script environment" {
        # Execute the test script with parameters
        $testFolder = Join-Path $TestDrive "TestWorkflow"
        $output = & $script:TestScriptPath -ScriptSaveFolder $testFolder -DebugMode $false
        
        # Parse the JSON output
        $result = $output | ConvertFrom-Json
        
        # Verify the result
        $result | Should -Not -BeNullOrEmpty
        $result.Succeeded | Should -Be $true
        $result.Component | Should -Be "Initialization"
        $result.ScriptSaveFolder | Should -Be $testFolder
        $result.Params | Should -Not -BeNullOrEmpty
        $result.Params.ScriptSaveFolder | Should -Be $testFolder
        $result.Params.DebugMode | Should -Be $false
    }
    
    It "Handles quoted paths correctly in real environment" {
        # Test with single quotes
        $testFolder = "'$TestDrive\QuotedPath'"
        $output = & $script:TestScriptPath -ScriptSaveFolder $testFolder
        $result = $output | ConvertFrom-Json
        
        $result.ScriptSaveFolder | Should -Be "$TestDrive\QuotedPath"
        
        # Test with double quotes
        $testFolder = "`"$TestDrive\DoubleQuoted`""
        $output = & $script:TestScriptPath -ScriptSaveFolder $testFolder
        $result = $output | ConvertFrom-Json
        
        $result.ScriptSaveFolder | Should -Be "$TestDrive\DoubleQuoted"
    }
    
    It "Sets DebugPreference correctly when DebugMode is true" {
        # Create a script that also outputs DebugPreference
        $debugScriptPath = Join-Path $TestDrive "TestDebug.ps1"
        $debugScript = @"
param([bool]`$DebugMode = `$false)

# Temporarily disable test mode to allow logging initialization
`$env:PESTER_TEST_RUN = "0"
`$env:LOXONE_TEST_MODE = "0"
`$Global:IsTestRun = `$false

Import-Module '$moduleAbsolutePath' -Force

`$Global:DebugPreference = 'SilentlyContinue'
`$result = Initialize-ScriptWorkflow -BoundParameters `$PSBoundParameters -PSScriptRoot `$PSScriptRoot -MyInvocation `$MyInvocation

@{
    Result = `$result
    DebugPreference = `$Global:DebugPreference
} | ConvertTo-Json -Depth 10
"@
        Set-Content -Path $debugScriptPath -Value $debugScript
        
        $output = & $debugScriptPath -DebugMode $true
        $data = $output | ConvertFrom-Json
        
        # DebugPreference can be either string 'Continue' or numeric value 2
        $data.DebugPreference | Should -BeIn @('Continue', 2, '2')
    }
    
    It "Creates directory if it doesn't exist" {
        $nonExistentPath = Join-Path $TestDrive "NonExistentFolder"
        
        # Ensure it doesn't exist
        if (Test-Path $nonExistentPath) {
            Remove-Item $nonExistentPath -Recurse -Force
        }
        
        $output = & $script:TestScriptPath -ScriptSaveFolder $nonExistentPath
        $result = $output | ConvertFrom-Json
        
        # Verify directory was created
        Test-Path $nonExistentPath | Should -Be $true
        $result.ScriptSaveFolder | Should -Be $nonExistentPath
    }
    
    It "Correctly identifies script context (admin/system/interactive)" {
        # Create a script that returns context information
        $contextScriptPath = Join-Path $TestDrive "TestContext.ps1"
        $contextScript = @"
param()

# Temporarily disable test mode to allow logging initialization
`$env:PESTER_TEST_RUN = "0"
`$env:LOXONE_TEST_MODE = "0"
`$Global:IsTestRun = `$false

Import-Module '$moduleAbsolutePath' -Force

`$result = Initialize-ScriptWorkflow -BoundParameters @{} -PSScriptRoot `$PSScriptRoot -MyInvocation `$MyInvocation

@{
    IsAdminRun = `$result.IsAdminRun
    IsRunningAsSystem = `$result.IsRunningAsSystem
    IsInteractive = `$result.IsInteractive
} | ConvertTo-Json
"@
        Set-Content -Path $contextScriptPath -Value $contextScript
        
        $output = & $contextScriptPath
        $context = $output | ConvertFrom-Json
        
        # These values will reflect the actual running context
        # We're running in a test environment, so we expect:
        # - Not running as SYSTEM (unless tests are run as SYSTEM)
        # - Admin status depends on how tests are run
        # - Should be interactive when run from console
        
        # Just verify the properties exist and are boolean
        $context.IsAdminRun | Should -BeOfType [bool]
        $context.IsRunningAsSystem | Should -BeOfType [bool]
        $context.IsInteractive | Should -BeOfType [bool]
        
        # In normal test runs, we're not SYSTEM
        if ($env:USERNAME -ne 'SYSTEM') {
            $context.IsRunningAsSystem | Should -Be $false
        }
        
        # When run from console/VS Code, should be interactive
        if ($Host.Name -in @('ConsoleHost', 'Visual Studio Code Host')) {
            $context.IsInteractive | Should -Be $true
        }
    }
    
    It "Logs initialization details to log file" {
        # Create a script that passes log file parameter
        $logScriptPath = Join-Path $TestDrive "TestLogging.ps1"
        $logPath = Join-Path $TestDrive "workflow.log"
        
        $logScript = @"
param(
    [string]`$ScriptSaveFolder,
    [string]`$PassedLogFile
)

# Temporarily disable test mode to allow logging initialization
`$env:PESTER_TEST_RUN = "0"
`$env:LOXONE_TEST_MODE = "0"
`$Global:IsTestRun = `$false

Import-Module '$moduleAbsolutePath' -Force

# Call Initialize-ScriptWorkflow with log file parameter
`$result = Initialize-ScriptWorkflow -BoundParameters @{ScriptSaveFolder=`$ScriptSaveFolder; PassedLogFile=`$PassedLogFile} -PSScriptRoot `$PSScriptRoot -MyInvocation `$MyInvocation

`$result | ConvertTo-Json -Depth 10
"@
        Set-Content -Path $logScriptPath -Value $logScript
        
        $testFolder = Join-Path $TestDrive "LogTest"
        $output = & $logScriptPath -ScriptSaveFolder $testFolder -PassedLogFile $logPath
        
        # Wait a moment for log to be written
        Start-Sleep -Milliseconds 500
        
        # Check log file exists and has content
        $logExists = Test-Path $logPath
        if (-not $logExists) {
            Write-Host "DEBUG: Log file not found at: $logPath"
            Write-Host "DEBUG: TestDrive contents:"
            Get-ChildItem $TestDrive -Recurse | ForEach-Object { Write-Host "  $_" }
            Write-Host "DEBUG: Global LogFile: $($Global:LogFile)"
        }
        $logExists | Should -Be $true
        
        $logContent = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrEmpty($logContent)) {
            Write-Host "DEBUG: Log file exists but is empty or unreadable"
            Write-Host "DEBUG: File size: $((Get-Item $logPath -ErrorAction SilentlyContinue).Length) bytes"
        }
        $logContent | Should -Not -BeNullOrEmpty
        $logContent | Should -Match "Initial log setup complete"
        $logContent | Should -Match "Write-Log is available"
    }
}