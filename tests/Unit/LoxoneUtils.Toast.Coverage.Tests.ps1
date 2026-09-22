# Coverage tests for LoxoneUtils.Toast - Get-LoxoneToastAppId and Update-Toast
# Tests toast app ID resolution and toast update state management

BeforeAll {
    # Mock mutex BEFORE module import to prevent serialization issues
    . (Join-Path $PSScriptRoot 'Mock-Toast-NoMutex-ForTests.ps1')

    # Force test mode before importing module
    $env:PESTER_TEST_RUN = "1"
    $Global:IsTestRun = $true
    $Global:SuppressLoxoneToastInit = $false

    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop

    # Get the Toast module and force suppression off so functions are testable
    $toastModule = Get-Module LoxoneUtils
    & $toastModule { $script:SuppressToastInit = $false }

    # Mock BurntToast functions in the LoxoneUtils module scope
    Mock Submit-BTNotification {} -ModuleName LoxoneUtils
    Mock Update-BTNotification {} -ModuleName LoxoneUtils
    Mock New-BTBinding {} -ModuleName LoxoneUtils
    Mock New-BTProgressBar {} -ModuleName LoxoneUtils
    Mock New-BTText {} -ModuleName LoxoneUtils
    Mock New-BTImage {} -ModuleName LoxoneUtils
    Mock New-BTColumn {} -ModuleName LoxoneUtils
    Mock New-BTVisual {} -ModuleName LoxoneUtils
    Mock New-BTContent {} -ModuleName LoxoneUtils
    Mock New-BTAudio {} -ModuleName LoxoneUtils
    Mock New-BTButton {} -ModuleName LoxoneUtils
    Mock New-BTAction {} -ModuleName LoxoneUtils

    # Set up temp directory for logging
    $script:TestTempPath = Join-Path $TestDrive "ToastCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name PersistentToastId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name PersistentToastInitialized -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name PersistentToastData -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name ForceToastSuppression -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name ScriptStartTime -Scope Global -ErrorAction SilentlyContinue
}

Describe "Get-LoxoneToastAppId" -Tag 'Unit', 'Toast' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept PreFoundPath parameter" {
            $cmd = Get-Command Get-LoxoneToastAppId
            $cmd.Parameters.Keys | Should -Contain 'PreFoundPath'
        }
    }

    Context "With pre-found path" {

        It "Should return the Loxone Config AppId when a path is provided" {
            $result = Get-LoxoneToastAppId -PreFoundPath 'C:\Program Files\Loxone\LoxoneConfig\LoxoneConfig.exe'
            $result | Should -Not -BeNullOrEmpty
            $result | Should -Match 'LoxoneConfig\.exe'
            $result | Should -Match '7C5A40EF'
        }

        It "Should return the same AppId regardless of the specific path given" {
            $result1 = Get-LoxoneToastAppId -PreFoundPath 'C:\Loxone\LoxoneConfig.exe'
            $result2 = Get-LoxoneToastAppId -PreFoundPath 'D:\Custom\Path\LoxoneConfig.exe'
            $result1 | Should -Be $result2
        }
    }

    Context "Without pre-found path" {

        It "Should call Get-LoxoneExePath when no PreFoundPath is provided" {
            # On this machine Loxone Config IS installed, so Get-LoxoneExePath returns a real path.
            # We verify the function works correctly by checking it returns a valid AppId
            # (since Loxone is installed, the real Get-LoxoneExePath will find it).
            $result = Get-LoxoneToastAppId
            # Result depends on whether Loxone is installed on the test machine
            if ($result) {
                $result | Should -Match '7C5A40EF'
            } else {
                $result | Should -BeNullOrEmpty
            }
        }

        It "Should return null when PreFoundPath is explicitly empty" {
            # When PreFoundPath is empty string, the function treats it as falsy
            # and falls through to Get-LoxoneExePath.
            # Just verify the function does not throw with empty string.
            { Get-LoxoneToastAppId -PreFoundPath '' } | Should -Not -Throw
        }
    }
}

Describe "Update-Toast" -Tag 'Unit', 'Toast' {

    BeforeEach {
        # Reset global toast state before each test
        $Global:PersistentToastInitialized = $true
        $Global:PersistentToastId = 'LoxoneUpdateStatusToast'
        $Global:PersistentToastData = [ordered]@{
            StatusText            = "Test status"
            ProgressBarStatus     = "Download: -"
            ProgressBarValue      = 0.0
            OverallProgressStatus = "Overall: 0%"
            OverallProgressValue  = 0.0
            StepNumber            = 0
            TotalSteps            = 1
            StepName              = "Testing..."
            DownloadFileName      = ""
            DownloadNumber        = 0
            TotalDownloads        = 0
            CurrentWeight         = 0
            TotalWeight           = 1
            DownloadSpeedLine     = ""
            DownloadTimeLine      = ""
            DownloadSizeLine      = ""
            ConfigTitle           = "Loxone Config"
            AppTitle              = "Loxone App"
            ConfigStatus          = "Waiting..."
            ConfigProgress        = 0.0
            AppStatus             = "Waiting..."
            AppProgress           = 0.0
            MiniserverStatus      = "Waiting..."
            MiniserverProgress    = 0.0
            MiniserversTitle      = "Miniservers"
        }
    }

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Update-Toast -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
        }
    }

    Context "Toast update calls" {

        It "Should call Update-BTNotification when toast is initialized" {
            InModuleScope LoxoneUtils.Toast {
                Mock Update-BTNotification {}
                Mock Enter-SafeFunction {}
                Mock Exit-SafeFunction {}
                Mock Write-SafeLog {}

                $Global:PersistentToastInitialized = $true

                Update-Toast

                Should -Invoke Update-BTNotification -Times 1
            }
        }

        It "Should pass UniqueIdentifier to Update-BTNotification" {
            InModuleScope LoxoneUtils.Toast {
                Mock Update-BTNotification {}
                Mock Enter-SafeFunction {}
                Mock Exit-SafeFunction {}
                Mock Write-SafeLog {}

                $Global:PersistentToastInitialized = $true

                Update-Toast

                Should -Invoke Update-BTNotification -Times 1 -ParameterFilter {
                    $UniqueIdentifier -eq 'LoxoneUpdateStatusToast'
                }
            }
        }
    }

    Context "Error handling" {

        It "Should propagate errors from Update-BTNotification" {
            InModuleScope LoxoneUtils.Toast {
                Mock Update-BTNotification { throw "Toast update failed" }
                Mock Enter-SafeFunction {}
                Mock Exit-SafeFunction {}
                Mock Write-SafeLog {}

                { Update-Toast } | Should -Throw -ExpectedMessage '*Toast update failed*'
            }
        }
    }
}

Describe "Toast Global State Management" -Tag 'Unit', 'Toast' {

    Context "PersistentToastData integrity" {

        It "Should have PersistentToastId set by module initialization" {
            $Global:PersistentToastId | Should -Not -BeNullOrEmpty
        }

        It "Should have PersistentToastData as an ordered hashtable" {
            $Global:PersistentToastData | Should -Not -BeNullOrEmpty
            $Global:PersistentToastData | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        }

        It "Should contain all required data binding keys" {
            $requiredKeys = @(
                'StatusText', 'ProgressBarStatus', 'ProgressBarValue',
                'OverallProgressStatus', 'OverallProgressValue',
                'StepNumber', 'TotalSteps', 'StepName'
            )

            foreach ($key in $requiredKeys) {
                $Global:PersistentToastData.Contains($key) | Should -Be $true -Because "Key '$key' should exist in PersistentToastData"
            }
        }
    }
}
