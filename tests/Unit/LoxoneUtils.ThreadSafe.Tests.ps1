# Tests for LoxoneUtils.ThreadSafe - Mutex-protected workflow state management

BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    $Global:SuppressLoxoneToastInit = $true

    $script:TestTempPath = Join-Path $TestDrive "Tests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    # Ensure mutex is cleaned up after all tests
    Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Initialize-WorkflowStateMutex" -Tag 'Unit' {

    BeforeEach {
        # Clean up any existing mutex before each test
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    AfterEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    It "Returns true on successful initialization" {
        $result = Initialize-WorkflowStateMutex
        $result | Should -Be $true
    }

    It "Can be called multiple times without error" {
        Initialize-WorkflowStateMutex | Should -Be $true
        # Calling again after cleanup should also work
        Remove-WorkflowStateMutex
        Initialize-WorkflowStateMutex | Should -Be $true
    }
}

Describe "Update-WorkflowState - Bulk Updates" -Tag 'Unit' {

    BeforeEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
        Initialize-WorkflowStateMutex
        $script:testState = @{}
    }

    AfterEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    It "Applies bulk updates to state hashtable" {
        Update-WorkflowState -State $script:testState -Updates @{
            Status   = 'Running'
            Progress = 50
        }

        $script:testState['Status'] | Should -Be 'Running'
        $script:testState['Progress'] | Should -Be 50
    }

    It "Overwrites existing values with bulk updates" {
        $script:testState['Status'] = 'Pending'
        $script:testState['Progress'] = 0

        Update-WorkflowState -State $script:testState -Updates @{
            Status   = 'Completed'
            Progress = 100
        }

        $script:testState['Status'] | Should -Be 'Completed'
        $script:testState['Progress'] | Should -Be 100
    }

    It "Handles multiple keys in a single bulk update" {
        Update-WorkflowState -State $script:testState -Updates @{
            Key1 = 'Value1'
            Key2 = 'Value2'
            Key3 = 'Value3'
        }

        $script:testState['Key1'] | Should -Be 'Value1'
        $script:testState['Key2'] | Should -Be 'Value2'
        $script:testState['Key3'] | Should -Be 'Value3'
    }
}

Describe "Update-WorkflowState - Targeted Updates" -Tag 'Unit' {

    BeforeEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
        Initialize-WorkflowStateMutex
        $script:testState = @{}
    }

    AfterEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    It "Sets a direct property when no Component is specified" {
        Update-WorkflowState -State $script:testState -Property 'Status' -Value 'Running'

        $script:testState['Status'] | Should -Be 'Running'
    }

    It "Creates component sub-hashtable and sets property" {
        Update-WorkflowState -State $script:testState -Component 'Config' -Property 'Status' -Value 'Downloading'

        $script:testState['Config'] | Should -Not -BeNullOrEmpty
        $script:testState['Config']['Status'] | Should -Be 'Downloading'
    }

    It "Updates existing component property without losing other properties" {
        # Set up initial component state
        Update-WorkflowState -State $script:testState -Component 'Config' -Property 'Status' -Value 'Downloading'
        Update-WorkflowState -State $script:testState -Component 'Config' -Property 'Progress' -Value 25

        # Update one property
        Update-WorkflowState -State $script:testState -Component 'Config' -Property 'Status' -Value 'Installing'

        # Both properties should exist
        $script:testState['Config']['Status'] | Should -Be 'Installing'
        $script:testState['Config']['Progress'] | Should -Be 25
    }

    It "Handles multiple components independently" {
        Update-WorkflowState -State $script:testState -Component 'Config' -Property 'Status' -Value 'Done'
        Update-WorkflowState -State $script:testState -Component 'App' -Property 'Status' -Value 'Pending'

        $script:testState['Config']['Status'] | Should -Be 'Done'
        $script:testState['App']['Status'] | Should -Be 'Pending'
    }
}

Describe "Get-WorkflowState" -Tag 'Unit' {

    BeforeEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
        Initialize-WorkflowStateMutex
        $script:testState = @{
            Status   = 'Running'
            Progress = 75
            Config   = @{
                Status   = 'Completed'
                Progress = 100
            }
            App      = @{
                Status   = 'Downloading'
                Progress = 40
            }
        }
    }

    AfterEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    It "Returns a clone of the entire state when no parameters given" {
        $result = Get-WorkflowState -State $script:testState

        $result | Should -Not -BeNullOrEmpty
        $result['Status'] | Should -Be 'Running'
        $result['Progress'] | Should -Be 75
    }

    It "Returns a clone, not a reference to the original state" {
        $result = Get-WorkflowState -State $script:testState

        # Modify the clone - should not affect the original
        $result['Status'] = 'Modified'
        $script:testState['Status'] | Should -Be 'Running'
    }

    It "Returns a direct property value when Property is specified" {
        $result = Get-WorkflowState -State $script:testState -Property 'Status'
        $result | Should -Be 'Running'
    }

    It "Returns a component sub-hashtable when Component is specified" {
        $result = Get-WorkflowState -State $script:testState -Component 'Config'

        $result | Should -Not -BeNullOrEmpty
        $result['Status'] | Should -Be 'Completed'
        $result['Progress'] | Should -Be 100
    }

    It "Returns a specific component property when both Component and Property are specified" {
        $result = Get-WorkflowState -State $script:testState -Component 'App' -Property 'Progress'
        $result | Should -Be 40
    }

    It "Returns null for non-existent component" {
        $result = Get-WorkflowState -State $script:testState -Component 'NonExistent'
        $result | Should -BeNullOrEmpty
    }

    It "Returns null for non-existent property" {
        $result = Get-WorkflowState -State $script:testState -Property 'NonExistent'
        $result | Should -BeNullOrEmpty
    }
}

Describe "Remove-WorkflowStateMutex" -Tag 'Unit' {

    It "Cleans up mutex without error after initialization" {
        Initialize-WorkflowStateMutex
        { Remove-WorkflowStateMutex } | Should -Not -Throw
    }

    It "Does not throw when called without prior initialization" {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
        # Call again when nothing to dispose
        { Remove-WorkflowStateMutex } | Should -Not -Throw
    }

    It "Allows re-initialization after removal" {
        Initialize-WorkflowStateMutex
        Remove-WorkflowStateMutex

        $result = Initialize-WorkflowStateMutex
        $result | Should -Be $true

        # Cleanup
        Remove-WorkflowStateMutex
    }
}

Describe "Full workflow lifecycle" -Tag 'Unit' {

    BeforeEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    AfterEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    It "Supports init -> update -> read -> cleanup cycle" {
        # Initialize
        $initResult = Initialize-WorkflowStateMutex
        $initResult | Should -Be $true

        # Create state and update it
        $state = @{}
        Update-WorkflowState -State $state -Updates @{ Phase = 'Download'; Progress = 0 }

        # Read back
        $readPhase = Get-WorkflowState -State $state -Property 'Phase'
        $readPhase | Should -Be 'Download'

        # Update with targeted approach
        Update-WorkflowState -State $state -Property 'Progress' -Value 50

        $readProgress = Get-WorkflowState -State $state -Property 'Progress'
        $readProgress | Should -Be 50

        # Update component
        Update-WorkflowState -State $state -Component 'Miniserver' -Property 'Count' -Value 3

        $msCount = Get-WorkflowState -State $state -Component 'Miniserver' -Property 'Count'
        $msCount | Should -Be 3

        # Final state check
        $fullState = Get-WorkflowState -State $state
        $fullState['Phase'] | Should -Be 'Download'
        $fullState['Progress'] | Should -Be 50
        $fullState['Miniserver']['Count'] | Should -Be 3

        # Cleanup
        Remove-WorkflowStateMutex
    }

    It "State persists across multiple update and read cycles" {
        Initialize-WorkflowStateMutex
        $state = @{}

        # Simulate a multi-step workflow
        $steps = @(
            @{ Property = 'Step'; Value = 'CheckUpdate' }
            @{ Property = 'Step'; Value = 'Download' }
            @{ Property = 'Step'; Value = 'Install' }
            @{ Property = 'Step'; Value = 'Verify' }
            @{ Property = 'Step'; Value = 'Complete' }
        )

        foreach ($step in $steps) {
            Update-WorkflowState -State $state -Property $step.Property -Value $step.Value
        }

        # Final step should be the last one written
        $finalStep = Get-WorkflowState -State $state -Property 'Step'
        $finalStep | Should -Be 'Complete'

        Remove-WorkflowStateMutex
    }
}

Describe "Update-WorkflowState without prior initialization" -Tag 'Unit' {

    BeforeEach {
        # Ensure no mutex exists so auto-init path is exercised
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    AfterEach {
        Remove-WorkflowStateMutex -ErrorAction SilentlyContinue
    }

    It "Auto-initializes mutex when Update-WorkflowState is called without prior init" {
        $state = @{}

        # Should not throw - mutex gets auto-initialized inside Update-WorkflowState
        { Update-WorkflowState -State $state -Updates @{ AutoInit = 'yes' } } | Should -Not -Throw

        $state['AutoInit'] | Should -Be 'yes'
    }

    It "Auto-initializes mutex when Get-WorkflowState is called without prior init" {
        $state = @{ TestKey = 'TestValue' }

        # Should not throw - mutex gets auto-initialized inside Get-WorkflowState
        $result = Get-WorkflowState -State $state -Property 'TestKey'
        $result | Should -Be 'TestValue'
    }
}
