# Coverage tests for LoxoneUtils.NetworkCore - Initialize-NetworkCore and Clear-NetworkCore

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop

    # Set up temp directory
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

    # Save original environment variables so we can restore them
    $script:OrigFastNetwork = $env:LOXONE_USE_FAST_NETWORK
    $script:OrigPesterTestRun = $env:PESTER_TEST_RUN
    $script:OrigTestMode = $env:LOXONE_TEST_MODE
}

AfterAll {
    # Restore original environment variables
    $env:LOXONE_USE_FAST_NETWORK = $script:OrigFastNetwork
    $env:PESTER_TEST_RUN = $script:OrigPesterTestRun
    $env:LOXONE_TEST_MODE = $script:OrigTestMode

    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Initialize-NetworkCore Function" -Tag 'Unit', 'NetworkCore' {

    Context "Function existence and parameters" {

        It "Exists and is exported from LoxoneUtils" {
            Get-Command Initialize-NetworkCore -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has CmdletBinding attribute" {
            $cmd = Get-Command Initialize-NetworkCore -Module LoxoneUtils
            $cmd.CmdletBinding | Should -Be $true
        }

        It "Accepts no mandatory parameters" {
            $params = (Get-Command Initialize-NetworkCore -Module LoxoneUtils).Parameters
            $mandatoryParams = $params.Values | Where-Object {
                $_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }
            }
            $mandatoryParams | Should -BeNullOrEmpty
        }
    }

    Context "Basic invocation" {

        It "Can be called without error" {
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Can be called multiple times without error" {
            { Initialize-NetworkCore } | Should -Not -Throw
            { Initialize-NetworkCore } | Should -Not -Throw
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Returns no output" {
            $result = Initialize-NetworkCore
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Test mode detection via environment variables" {

        BeforeEach {
            # Clear all test-mode env vars before each test
            $env:LOXONE_USE_FAST_NETWORK = $null
            $env:PESTER_TEST_RUN = $null
            $env:LOXONE_TEST_MODE = $null
        }

        It "Does not throw when LOXONE_USE_FAST_NETWORK is set to 1" {
            $env:LOXONE_USE_FAST_NETWORK = "1"
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Does not throw when PESTER_TEST_RUN is set to 1" {
            $env:PESTER_TEST_RUN = "1"
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Does not throw when LOXONE_TEST_MODE is set to 1" {
            $env:LOXONE_TEST_MODE = "1"
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Does not throw when no test environment variables are set" {
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Does not throw when all test environment variables are set" {
            $env:LOXONE_USE_FAST_NETWORK = "1"
            $env:PESTER_TEST_RUN = "1"
            $env:LOXONE_TEST_MODE = "1"
            { Initialize-NetworkCore } | Should -Not -Throw
        }
    }

    Context "Related functions remain available after initialization" {

        BeforeAll {
            Initialize-NetworkCore
        }

        It "Invoke-NetworkRequest is still exported after Initialize-NetworkCore" {
            Get-Command Invoke-NetworkRequest -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Test-NetworkEndpoint is still exported after Initialize-NetworkCore" {
            Get-Command Test-NetworkEndpoint -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Clear-NetworkCore is still exported after Initialize-NetworkCore" {
            Get-Command Clear-NetworkCore -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Clear-NetworkCore Function" -Tag 'Unit', 'NetworkCore' {

    Context "Function existence and parameters" {

        It "Exists and is exported from LoxoneUtils" {
            Get-Command Clear-NetworkCore -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has CmdletBinding attribute" {
            $cmd = Get-Command Clear-NetworkCore -Module LoxoneUtils
            $cmd.CmdletBinding | Should -Be $true
        }

        It "Accepts no mandatory parameters" {
            $params = (Get-Command Clear-NetworkCore -Module LoxoneUtils).Parameters
            $mandatoryParams = $params.Values | Where-Object {
                $_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }
            }
            $mandatoryParams | Should -BeNullOrEmpty
        }
    }

    Context "Basic invocation" {

        It "Can be called without error" {
            { Clear-NetworkCore } | Should -Not -Throw
        }

        It "Can be called multiple times without error (idempotent)" {
            { Clear-NetworkCore } | Should -Not -Throw
            { Clear-NetworkCore } | Should -Not -Throw
            { Clear-NetworkCore } | Should -Not -Throw
        }

        It "Returns no output" {
            $result = Clear-NetworkCore
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Cleanup and re-initialization cycle" {

        It "Can re-initialize after clearing" {
            { Clear-NetworkCore } | Should -Not -Throw
            { Initialize-NetworkCore } | Should -Not -Throw
        }

        It "Clear then initialize then clear cycle works" {
            { Clear-NetworkCore } | Should -Not -Throw
            { Initialize-NetworkCore } | Should -Not -Throw
            { Clear-NetworkCore } | Should -Not -Throw
        }

        It "Network functions remain exported after clear" {
            Clear-NetworkCore
            Get-Command Initialize-NetworkCore -Module LoxoneUtils | Should -Not -BeNullOrEmpty
            Get-Command Clear-NetworkCore -Module LoxoneUtils | Should -Not -BeNullOrEmpty
            Get-Command Invoke-NetworkRequest -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "NetworkCore Module Exports" -Tag 'Unit', 'NetworkCore' {

    It "Exports Initialize-NetworkCore" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Initialize-NetworkCore'
    }

    It "Exports Clear-NetworkCore" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Clear-NetworkCore'
    }

    It "Exports Invoke-NetworkRequest" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Invoke-NetworkRequest'
    }

    It "Exports Test-NetworkEndpoint" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Test-NetworkEndpoint'
    }

    It "Exports Test-FastNetworkEndpoint" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Test-FastNetworkEndpoint'
    }

    It "Exports Test-StandardNetworkEndpoint" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Test-StandardNetworkEndpoint'
    }
}
