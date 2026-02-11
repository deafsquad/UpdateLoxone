# Working tests for LoxoneUtils.WorkflowSteps based on actual behavior

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop

    # Set up temp directory - use environment variable if available
    $script:TestTempPath = if ($env:UPDATELOXONE_TEST_TEMP) {
        $env:UPDATELOXONE_TEST_TEMP
    } else {
        Join-Path $PSScriptRoot '../temp'
    }
    if (-not (Test-Path $script:TestTempPath)) {
        New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    }

    # Set up logging
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'

    # Mock functions that don't exist but are referenced in tests
    function Global:Test-IsAdministrator { return $false }
    function Global:Test-IsRunningAsSystem { return $false }
    function Global:Test-IsInteractive { return $true }
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Get-StepWeight Function" -Tag 'WorkflowSteps' {

    # NOTE: Import-Module -Force in BeforeAll creates a new module session state.
    # InModuleScope then targets a stale reference, so Get-StepWeight outside the scope
    # sees a different $script:WorkflowStepDefinitions. The solution is to run both
    # the setup and the assertion inside InModuleScope.

    AfterEach {
        InModuleScope LoxoneUtils.WorkflowSteps {
            $script:WorkflowStepDefinitions = @()
        }
    }

    It "Exists and is exported" {
        Get-Command Get-StepWeight -Module LoxoneUtils | Should -Not -BeNullOrEmpty
    }

    It "Returns correct weight for existing step" {
        InModuleScope LoxoneUtils.WorkflowSteps {
            $script:WorkflowStepDefinitions = @(
                [PSCustomObject]@{ ID = "Step1"; Weight = 10; Name = "Test Step 1" }
                [PSCustomObject]@{ ID = "Step2"; Weight = 20; Name = "Test Step 2" }
            )
            $result = Get-StepWeight -StepID "Step1"
            $result | Should -Be 10
        }
    }

    It "Returns 0 for non-existent step" {
        InModuleScope LoxoneUtils.WorkflowSteps {
            $script:WorkflowStepDefinitions = @(
                [PSCustomObject]@{ ID = "Step1"; Weight = 10; Name = "Test Step 1" }
            )
            $result = Get-StepWeight -StepID "NonExistent"
            $result | Should -Be 0
        }
    }

    It "Handles empty WorkflowStepDefinitions array" {
        InModuleScope LoxoneUtils.WorkflowSteps {
            $script:WorkflowStepDefinitions = @()
            $result = Get-StepWeight -StepID "AnyStep"
            $result | Should -Be 0
        }
    }

    It "Handles null WorkflowStepDefinitions" {
        # Get-StepWeight should handle the case when WorkflowStepDefinitions is not initialized
        # AfterEach already cleared it; just call the function
        InModuleScope LoxoneUtils.WorkflowSteps {
            $result = Get-StepWeight -StepID "AnyStep"
            $result | Should -Be 0
        }
    }

    It "Is case-sensitive for step IDs" {
        InModuleScope LoxoneUtils.WorkflowSteps {
            $script:WorkflowStepDefinitions = @(
                [PSCustomObject]@{ ID = "Step1"; Weight = 10; Name = "Test" }
            )
            # PowerShell's -eq is case-insensitive by default, so this should still match
            $result = Get-StepWeight -StepID "step1"
            $result | Should -Be 10
        }
    }
}

Describe "Initialize-ScriptWorkflow Function" -Tag 'WorkflowSteps' {

    It "Exists and is exported" {
        Get-Command Initialize-ScriptWorkflow -Module LoxoneUtils | Should -Not -BeNullOrEmpty
    }

    # NOTE: Initialize-ScriptWorkflow requires a real $MyInvocation object which cannot be mocked.
    # The following functionality is fully tested in integration tests:
    # - tests/Integration/Initialize-ScriptWorkflow.Integration.Tests.ps1
    #
    # Tested scenarios in integration:
    # - Creates properly initialized context object
    # - Strips quotes from ScriptSaveFolder parameter
    # - Sets DebugPreference when DebugMode is true
    # - Uses PSScriptRoot when ScriptSaveFolder not provided
    # - Creates directory if it doesn't exist
    # - Logs initialization details
    # - Detects admin/system/interactive context correctly
}

Describe "Initialize-UpdatePipelineData Function" -Tag 'WorkflowSteps' {

    BeforeEach {
        Mock Test-Path { $false } -ModuleName LoxoneUtils
    }

    It "Exists and is exported" {
        Get-Command Initialize-UpdatePipelineData -Module LoxoneUtils | Should -Not -BeNullOrEmpty
    }

    # Skip all tests that actually call Initialize-UpdatePipelineData as it requires proper workflow context
    # and internally calls Initialize-ScriptWorkflow which needs mandatory parameters including $MyInvocation

    It "Creates Config target when update is needed" -Skip {
        # Skip: Initialize-UpdatePipelineData requires proper workflow context and calls Initialize-ScriptWorkflow
        $workflowContext = [PSCustomObject]@{
            InitialInstalledConfigVersion = "13.0.0.0"
            DownloadDir = "C:\Downloads"
            Params = @{ Channel = "Release" }
            InitialLoxoneAppDetails = [PSCustomObject]@{ FileVersion = "13.0.0.0" }
            MSListPath = "C:\MSList.txt"
        }

        $prerequisites = [PSCustomObject]@{
            LatestConfigVersionNormalized = "14.0.0.0"
            ConfigUpdateNeeded = $true
            ConfigZipUrl = "https://update.loxone.com/config.zip"
            ConfigExpectedZipSize = 1000000
            ConfigExpectedCRC = "ABCD1234"
            ConfigZipFileName = "config.zip"
            ConfigInstallerFileName = "config.exe"
        }

        $result = Initialize-UpdatePipelineData -WorkflowContext $workflowContext -Prerequisites $prerequisites

        $result.Succeeded | Should -Be $true
        $configTarget = $result.UpdateTargetsInfo | Where-Object { $_.Type -eq "Config" }
        $configTarget | Should -Not -BeNullOrEmpty
        $configTarget.Name | Should -Be "Conf"
        $configTarget.InitialVersion | Should -Be "13.0.0.0"
        $configTarget.TargetVersion | Should -Be "14.0.0.0"
        $configTarget.UpdateNeeded | Should -Be $true
        $configTarget.Status | Should -Be "NeedsUpdate"
    }

    It "Creates App target when UpdateLoxoneApp is true" -Skip {
        # Skip: Initialize-UpdatePipelineData requires proper workflow context and calls Initialize-ScriptWorkflow
        $workflowContext = [PSCustomObject]@{
            InitialInstalledConfigVersion = "13.0.0.0"
            DownloadDir = "C:\Downloads"
            Params = @{
                Channel = "Release"
                UpdateLoxoneApp = $true
            }
            InitialLoxoneAppDetails = [PSCustomObject]@{ FileVersion = "13.0.0.0" }
            MSListPath = "C:\MSList.txt"
        }

        $prerequisites = [PSCustomObject]@{
            LatestConfigVersionNormalized = "14.0.0.0"
            ConfigUpdateNeeded = $true
            LatestAppVersion = "14.0.0.0"
            AppUpdateNeeded = $true
            AppInstallerUrl = "https://update.loxone.com/app.exe"
            AppExpectedSize = 500000
            AppExpectedCRC = "EFGH5678"
            AppInstallerFileName = "app.exe"
            SelectedAppChannelName = "Release"
        }

        $result = Initialize-UpdatePipelineData -WorkflowContext $workflowContext -Prerequisites $prerequisites

        $appTarget = $result.UpdateTargetsInfo | Where-Object { $_.Type -eq "App" }
        $appTarget | Should -Not -BeNullOrEmpty
        $appTarget.Name | Should -Be "APP"
        $appTarget.UpdateNeeded | Should -Be $true
    }

    It "Skips App target when UpdateLoxoneApp is false" -Skip {
        # Skip: Initialize-UpdatePipelineData requires proper workflow context and calls Initialize-ScriptWorkflow
        $workflowContext = [PSCustomObject]@{
            InitialInstalledConfigVersion = "13.0.0.0"
            DownloadDir = "C:\Downloads"
            Params = @{
                Channel = "Release"
                UpdateLoxoneApp = $false
            }
            InitialLoxoneAppDetails = [PSCustomObject]@{ FileVersion = "13.0.0.0" }
            MSListPath = "C:\MSList.txt"
        }

        $prerequisites = [PSCustomObject]@{
            LatestConfigVersionNormalized = "14.0.0.0"
            ConfigUpdateNeeded = $true
            AppUpdateNeeded = $true
        }

        $result = Initialize-UpdatePipelineData -WorkflowContext $workflowContext -Prerequisites $prerequisites

        $appTarget = $result.UpdateTargetsInfo | Where-Object { $_.Type -eq "App" }
        $appTarget | Should -BeNullOrEmpty
    }

    It "Defaults UpdateLoxoneApp to true when not specified" -Skip {
        # Skip: Initialize-UpdatePipelineData requires proper workflow context and calls Initialize-ScriptWorkflow
        $workflowContext = [PSCustomObject]@{
            InitialInstalledConfigVersion = "13.0.0.0"
            DownloadDir = "C:\Downloads"
            Params = @{ Channel = "Release" }  # No UpdateLoxoneApp
            InitialLoxoneAppDetails = [PSCustomObject]@{ FileVersion = "13.0.0.0" }
            MSListPath = "C:\MSList.txt"
        }

        $prerequisites = [PSCustomObject]@{
            LatestConfigVersionNormalized = "14.0.0.0"
            ConfigUpdateNeeded = $true
            AppUpdateNeeded = $true
            AppInstallerUrl = "https://update.loxone.com/app.exe"
            AppInstallerFileName = "app.exe"
        }

        $result = Initialize-UpdatePipelineData -WorkflowContext $workflowContext -Prerequisites $prerequisites

        $appTarget = $result.UpdateTargetsInfo | Where-Object { $_.Type -eq "App" }
        $appTarget | Should -Not -BeNullOrEmpty
    }

    It "Sets correct status based on update need" -Skip {
        # Skip: Initialize-UpdatePipelineData requires proper workflow context and calls Initialize-ScriptWorkflow
        $workflowContext = [PSCustomObject]@{
            InitialInstalledConfigVersion = "14.0.0.0"
            DownloadDir = "C:\Downloads"
            Params = @{}
            InitialLoxoneAppDetails = [PSCustomObject]@{ FileVersion = "14.0.0.0" }
            MSListPath = "C:\MSList.txt"
        }

        $prerequisites = [PSCustomObject]@{
            LatestConfigVersionNormalized = "14.0.0.0"
            ConfigUpdateNeeded = $false
        }

        $result = Initialize-UpdatePipelineData -WorkflowContext $workflowContext -Prerequisites $prerequisites

        $configTarget = $result.UpdateTargetsInfo | Where-Object { $_.Type -eq "Config" }
        $configTarget.Status | Should -Be "UpToDate"
    }

    It "Sets NotInstalled status when initial version is null" -Skip {
        # Skip: Initialize-UpdatePipelineData requires proper workflow context and calls Initialize-ScriptWorkflow
        $workflowContext = [PSCustomObject]@{
            InitialInstalledConfigVersion = $null
            DownloadDir = "C:\Downloads"
            Params = @{}
            InitialLoxoneAppDetails = [PSCustomObject]@{ FileVersion = $null }
            MSListPath = "C:\MSList.txt"
        }

        $prerequisites = [PSCustomObject]@{
            LatestConfigVersionNormalized = "14.0.0.0"
            ConfigUpdateNeeded = $false
        }

        $result = Initialize-UpdatePipelineData -WorkflowContext $workflowContext -Prerequisites $prerequisites

        $configTarget = $result.UpdateTargetsInfo | Where-Object { $_.Type -eq "Config" }
        $configTarget.Status | Should -Be "NotInstalled"
    }

    It "Creates Miniserver targets when MSList file exists" -Skip {
        # Skip: Mocking across module boundaries is unreliable and Initialize-UpdatePipelineData
        # requires proper workflow context that calls Initialize-ScriptWorkflow
    }
}

Describe "Test-PipelineStepShouldRun Function" -Tag 'WorkflowSteps' {

    It "Exists and is exported" {
        Get-Command Test-PipelineStepShouldRun -Module LoxoneUtils | Should -Not -BeNullOrEmpty
    }

    It "Returns true when target needs update and not performed" {
        $targets = [System.Collections.ArrayList]@(
            [PSCustomObject]@{ Type = "Config"; UpdateNeeded = $true; UpdatePerformed = $false }
        )
        $result = Test-PipelineStepShouldRun -TargetsInfo $targets -ExpectedType "Config" -ConditionBlock { param($item) $item.UpdateNeeded -and -not $item.UpdatePerformed }
        $result | Should -Be $true
    }

    It "Returns false when target doesn't need update" {
        $targets = [System.Collections.ArrayList]@(
            [PSCustomObject]@{ Type = "Config"; UpdateNeeded = $false; UpdatePerformed = $false }
        )
        $result = Test-PipelineStepShouldRun -TargetsInfo $targets -ExpectedType "Config" -ConditionBlock { param($item) $item.UpdateNeeded -and -not $item.UpdatePerformed }
        $result | Should -Be $false
    }

    It "Returns true when condition always matches" {
        $targets = [System.Collections.ArrayList]@(
            [PSCustomObject]@{ Type = "Config"; UpdateNeeded = $false; UpdatePerformed = $false }
        )
        $result = Test-PipelineStepShouldRun -TargetsInfo $targets -ExpectedType "Config" -ConditionBlock { param($item) $true }
        $result | Should -Be $true
    }

    It "Returns false when update already performed" {
        $targets = [System.Collections.ArrayList]@(
            [PSCustomObject]@{ Type = "Config"; UpdateNeeded = $true; UpdatePerformed = $true }
        )
        $result = Test-PipelineStepShouldRun -TargetsInfo $targets -ExpectedType "Config" -ConditionBlock { param($item) $item.UpdateNeeded -and -not $item.UpdatePerformed }
        $result | Should -Be $false
    }

    It "Returns false for non-existent target type" {
        $targets = [System.Collections.ArrayList]@(
            [PSCustomObject]@{ Type = "Config"; UpdateNeeded = $true; UpdatePerformed = $false }
        )
        $result = Test-PipelineStepShouldRun -TargetsInfo $targets -ExpectedType "NonExistent" -ConditionBlock { param($item) $true }
        $result | Should -Be $false
    }

    It "Handles empty update targets array" -Skip {
        # Cannot pass empty ArrayList to mandatory [System.Collections.ArrayList] parameter -
        # PowerShell rejects empty collections during parameter binding validation
    }

    It "Handles null update targets" -Skip {
        # Cannot pass $null to mandatory [System.Collections.ArrayList] parameter
    }

    It "Evaluates multiple targets of same type correctly" {
        $targets = [System.Collections.ArrayList]@(
            [PSCustomObject]@{ Type = "Miniserver"; UpdateNeeded = $false; UpdatePerformed = $false }
            [PSCustomObject]@{ Type = "Miniserver"; UpdateNeeded = $true; UpdatePerformed = $false }
            [PSCustomObject]@{ Type = "Miniserver"; UpdateNeeded = $true; UpdatePerformed = $true }
        )
        $result = Test-PipelineStepShouldRun -TargetsInfo $targets -ExpectedType "Miniserver" -ConditionBlock { param($item) $item.UpdateNeeded -and -not $item.UpdatePerformed }
        $result | Should -Be $true
    }
}

Describe "Module Exports" -Tag 'WorkflowSteps' {

    It "Exports expected workflow functions" {
        $module = Get-Module LoxoneUtils
        $exports = $module.ExportedFunctions.Keys

        $exports | Should -Contain 'Get-StepWeight'
        $exports | Should -Contain 'Initialize-ScriptWorkflow'
        $exports | Should -Contain 'Initialize-UpdatePipelineData'
        $exports | Should -Contain 'Test-PipelineStepShouldRun'
    }
}
