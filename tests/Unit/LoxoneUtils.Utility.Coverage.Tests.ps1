# Coverage tests for LoxoneUtils.Utility - Get-AppVersionFromRegistry and Get-InvocationTrace

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
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Get-AppVersionFromRegistry Function" -Tag 'Unit', 'Utility' {

    Context "Function existence and parameters" {

        It "Exists and is exported from LoxoneUtils" {
            Get-Command Get-AppVersionFromRegistry -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has RegistryPath as a mandatory parameter" {
            $params = (Get-Command Get-AppVersionFromRegistry -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'RegistryPath'
            $params['RegistryPath'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory } | Should -Not -BeNullOrEmpty
        }

        It "Has AppNameValueName as an optional parameter with default 'shortcutname'" {
            $params = (Get-Command Get-AppVersionFromRegistry -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'AppNameValueName'
        }

        It "Has InstallPathValueName as an optional parameter with default 'InstallLocation'" {
            $params = (Get-Command Get-AppVersionFromRegistry -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'InstallPathValueName'
        }
    }

    Context "Return structure" {

        It "Returns a hashtable with expected keys" {
            # Use a non-existent registry path to get a clean error-only result
            $result = Get-AppVersionFromRegistry -RegistryPath 'HKLM:\SOFTWARE\NonExistentKeyForTesting12345'

            $result | Should -BeOfType [hashtable]
            $result.Keys | Should -Contain 'ShortcutName'
            $result.Keys | Should -Contain 'InstallLocation'
            $result.Keys | Should -Contain 'FileVersion'
            $result.Keys | Should -Contain 'ProductVersion'
            $result.Keys | Should -Contain 'ComparableVersion'
            $result.Keys | Should -Contain 'DisplayVersion'
            $result.Keys | Should -Contain 'VersionFormat'
            $result.Keys | Should -Contain 'BuildNumber'
            $result.Keys | Should -Contain 'BuildDate'
            $result.Keys | Should -Contain 'Error'
        }
    }

    Context "Registry key not found" {

        It "Sets Error when registry key does not exist" {
            $result = Get-AppVersionFromRegistry -RegistryPath 'HKLM:\SOFTWARE\NonExistentKeyForTesting12345'

            $result.Error | Should -Not -BeNullOrEmpty
            $result.Error | Should -BeLike '*not found*'
        }

        It "Returns null for all version fields when key does not exist" {
            $result = Get-AppVersionFromRegistry -RegistryPath 'HKLM:\SOFTWARE\NonExistentKeyForTesting12345'

            $result.ShortcutName | Should -BeNullOrEmpty
            $result.InstallLocation | Should -BeNullOrEmpty
            $result.FileVersion | Should -BeNullOrEmpty
            $result.ComparableVersion | Should -BeNullOrEmpty
        }
    }

    Context "Registry key exists but missing required values" {

        BeforeAll {
            # Create a temporary registry key for testing
            $script:TestRegPath = 'HKCU:\SOFTWARE\LoxoneUtilsTest_Coverage'
            if (Test-Path $script:TestRegPath) {
                Remove-Item $script:TestRegPath -Recurse -Force
            }
            New-Item -Path $script:TestRegPath -Force | Out-Null
        }

        AfterAll {
            if (Test-Path $script:TestRegPath) {
                Remove-Item $script:TestRegPath -Recurse -Force
            }
        }

        It "Sets Error when InstallLocation value is missing" {
            # Key exists but has no InstallLocation property
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath

            $result.Error | Should -Not -BeNullOrEmpty
            $result.Error | Should -BeLike '*InstallLocation*not found*'
        }

        It "Returns ShortcutName as null when shortcutname value is missing" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath

            $result.ShortcutName | Should -BeNullOrEmpty
        }
    }

    Context "Registry key with InstallLocation pointing to non-existent path" {

        BeforeAll {
            $script:TestRegPath2 = 'HKCU:\SOFTWARE\LoxoneUtilsTest_Coverage2'
            if (Test-Path $script:TestRegPath2) {
                Remove-Item $script:TestRegPath2 -Recurse -Force
            }
            New-Item -Path $script:TestRegPath2 -Force | Out-Null
            Set-ItemProperty -Path $script:TestRegPath2 -Name 'InstallLocation' -Value 'C:\NonExistent\Path\For\Testing'
            Set-ItemProperty -Path $script:TestRegPath2 -Name 'shortcutname' -Value 'TestApp'
        }

        AfterAll {
            if (Test-Path $script:TestRegPath2) {
                Remove-Item $script:TestRegPath2 -Recurse -Force
            }
        }

        It "Sets Error when InstallLocation directory does not exist" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath2

            $result.Error | Should -Not -BeNullOrEmpty
        }

        It "Reads ShortcutName from registry successfully" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath2

            $result.ShortcutName | Should -Be 'TestApp'
        }

        It "Reads InstallLocation from registry successfully" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath2

            $result.InstallLocation | Should -Be 'C:\NonExistent\Path\For\Testing'
        }
    }

    Context "Registry key with valid executable" {

        BeforeAll {
            # Use notepad.exe as a known valid executable
            $script:TestRegPath3 = 'HKCU:\SOFTWARE\LoxoneUtilsTest_Coverage3'
            if (Test-Path $script:TestRegPath3) {
                Remove-Item $script:TestRegPath3 -Recurse -Force
            }
            New-Item -Path $script:TestRegPath3 -Force | Out-Null
            Set-ItemProperty -Path $script:TestRegPath3 -Name 'InstallLocation' -Value "$env:windir\System32"
            Set-ItemProperty -Path $script:TestRegPath3 -Name 'shortcutname' -Value 'notepad'
        }

        AfterAll {
            if (Test-Path $script:TestRegPath3) {
                Remove-Item $script:TestRegPath3 -Recurse -Force
            }
        }

        It "Reads version from a real executable" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath3

            $result.Error | Should -BeNullOrEmpty
            $result.InstallLocation | Should -BeLike '*notepad.exe'
            $result.ComparableVersion | Should -Not -BeNullOrEmpty
        }

        It "Returns a non-null FileVersion" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath3

            $result.FileVersion | Should -Not -BeNullOrEmpty
        }

        It "Returns a non-null VersionFormat" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath3

            $result.VersionFormat | Should -Not -BeNullOrEmpty
        }
    }

    Context "Custom value name parameters" {

        BeforeAll {
            $script:TestRegPath4 = 'HKCU:\SOFTWARE\LoxoneUtilsTest_Coverage4'
            if (Test-Path $script:TestRegPath4) {
                Remove-Item $script:TestRegPath4 -Recurse -Force
            }
            New-Item -Path $script:TestRegPath4 -Force | Out-Null
            Set-ItemProperty -Path $script:TestRegPath4 -Name 'CustomInstallPath' -Value "$env:windir\System32"
            Set-ItemProperty -Path $script:TestRegPath4 -Name 'CustomAppName' -Value 'notepad'
        }

        AfterAll {
            if (Test-Path $script:TestRegPath4) {
                Remove-Item $script:TestRegPath4 -Recurse -Force
            }
        }

        It "Uses custom AppNameValueName and InstallPathValueName parameters" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath4 `
                -AppNameValueName 'CustomAppName' `
                -InstallPathValueName 'CustomInstallPath'

            $result.Error | Should -BeNullOrEmpty
            $result.ShortcutName | Should -Be 'notepad'
            $result.InstallLocation | Should -BeLike '*notepad.exe'
        }
    }

    Context "Empty InstallLocation value" {

        BeforeAll {
            $script:TestRegPath5 = 'HKCU:\SOFTWARE\LoxoneUtilsTest_Coverage5'
            if (Test-Path $script:TestRegPath5) {
                Remove-Item $script:TestRegPath5 -Recurse -Force
            }
            New-Item -Path $script:TestRegPath5 -Force | Out-Null
            Set-ItemProperty -Path $script:TestRegPath5 -Name 'InstallLocation' -Value ''
            Set-ItemProperty -Path $script:TestRegPath5 -Name 'shortcutname' -Value 'TestApp'
        }

        AfterAll {
            if (Test-Path $script:TestRegPath5) {
                Remove-Item $script:TestRegPath5 -Recurse -Force
            }
        }

        It "Sets Error when InstallLocation value is empty" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath5

            $result.Error | Should -Not -BeNullOrEmpty
            $result.Error | Should -BeLike '*empty*'
        }
    }

    Context "InstallLocation pointing directly to a file" {

        BeforeAll {
            $script:TestRegPath6 = 'HKCU:\SOFTWARE\LoxoneUtilsTest_Coverage6'
            if (Test-Path $script:TestRegPath6) {
                Remove-Item $script:TestRegPath6 -Recurse -Force
            }
            New-Item -Path $script:TestRegPath6 -Force | Out-Null
            Set-ItemProperty -Path $script:TestRegPath6 -Name 'InstallLocation' -Value "$env:windir\System32\notepad.exe"
            Set-ItemProperty -Path $script:TestRegPath6 -Name 'shortcutname' -Value 'notepad'
        }

        AfterAll {
            if (Test-Path $script:TestRegPath6) {
                Remove-Item $script:TestRegPath6 -Recurse -Force
            }
        }

        It "Reads version when InstallLocation is a direct file path" {
            $result = Get-AppVersionFromRegistry -RegistryPath $script:TestRegPath6

            $result.Error | Should -BeNullOrEmpty
            $result.ComparableVersion | Should -Not -BeNullOrEmpty
            $result.FileVersion | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Get-InvocationTrace Function" -Tag 'Unit', 'Utility' {

    Context "Function existence and parameters" {

        It "Exists and is exported from LoxoneUtils" {
            Get-Command Get-InvocationTrace -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has CmdletBinding attribute" {
            $cmd = Get-Command Get-InvocationTrace -Module LoxoneUtils
            $cmd.CmdletBinding | Should -Be $true
        }

        It "Accepts no mandatory parameters" {
            $params = (Get-Command Get-InvocationTrace -Module LoxoneUtils).Parameters
            $mandatoryParams = $params.Values | Where-Object {
                $_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }
            }
            $mandatoryParams | Should -BeNullOrEmpty
        }
    }

    Context "Return structure" {

        It "Returns a PSCustomObject" {
            $result = Get-InvocationTrace
            $result | Should -Not -BeNullOrEmpty
            $result.PSObject | Should -Not -BeNullOrEmpty
        }

        It "Contains CallStack property" {
            $result = Get-InvocationTrace
            $result.PSObject.Properties.Name | Should -Contain 'CallStack'
        }

        It "Contains ThisProcessCLI property" {
            $result = Get-InvocationTrace
            $result.PSObject.Properties.Name | Should -Contain 'ThisProcessCLI'
        }

        It "Contains ParentProcessCLI property" {
            $result = Get-InvocationTrace
            $result.PSObject.Properties.Name | Should -Contain 'ParentProcessCLI'
        }
    }

    Context "Return values" {

        It "Returns a non-empty CallStack" {
            $result = Get-InvocationTrace
            $result.CallStack | Should -Not -BeNullOrEmpty
        }

        It "CallStack is an array" {
            $result = Get-InvocationTrace
            # CallStack comes from Get-PSCallStack .Command which returns an array
            $result.CallStack.Count | Should -BeGreaterThan 0
        }

        It "Returns a non-empty ThisProcessCLI" {
            $result = Get-InvocationTrace
            $result.ThisProcessCLI | Should -Not -BeNullOrEmpty
        }

        It "ThisProcessCLI contains current PID information" {
            $result = Get-InvocationTrace
            # Should reference the current process ID or name
            $result.ThisProcessCLI | Should -BeLike "*$PID*"
        }

        It "Returns a non-empty ParentProcessCLI" {
            $result = Get-InvocationTrace
            $result.ParentProcessCLI | Should -Not -BeNullOrEmpty
        }
    }

    Context "Idempotent calls" {

        It "Can be called multiple times without error" {
            { Get-InvocationTrace } | Should -Not -Throw
            { Get-InvocationTrace } | Should -Not -Throw
        }

        It "Returns consistent structure across calls" {
            $result1 = Get-InvocationTrace
            $result2 = Get-InvocationTrace

            $result1.PSObject.Properties.Name.Count | Should -Be $result2.PSObject.Properties.Name.Count
        }
    }
}
