# Coverage tests for LoxoneUtils.Installation - Test-ExistingInstaller and Start-LoxoneForWindowsInstaller
# Tests installer validation and silent installation execution

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

    $script:TestTempPath = Join-Path $TestDrive "InstallationCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Test-ExistingInstaller" -Tag 'Unit', 'Installation' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Test-ExistingInstaller -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept InstallerPath, TargetVersion, and ComponentName parameters" {
            $cmd = Get-Command Test-ExistingInstaller
            $cmd.Parameters.Keys | Should -Contain 'InstallerPath'
            $cmd.Parameters.Keys | Should -Contain 'TargetVersion'
            $cmd.Parameters.Keys | Should -Contain 'ComponentName'
        }
    }

    Context "Installer not found" {

        It "Should return IsValid=false when installer file does not exist" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $false }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Missing\installer.exe' -TargetVersion '16.3.2.10'
                $result.IsValid | Should -Be $false
                $result.Reason | Should -Be 'Not found'
                $result.SkipDownload | Should -Be $false
            }
        }
    }

    Context "Version matches with valid signature" {

        It "Should return IsValid=true when version and signature are valid" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $true }
                Mock Get-Item {
                    return [PSCustomObject]@{
                        Length = 50000000
                        LastWriteTime = (Get-Date)
                        VersionInfo = [PSCustomObject]@{
                            FileVersion = '16.3.2.10'
                            ProductVersion = '16.3.2.10'
                        }
                    }
                }
                Mock Convert-VersionString { return '16.3.2.10' }
                Mock Get-ExecutableSignature { return [PSCustomObject]@{ Status = 'Valid' } }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Downloads\LoxoneConfig.exe' -TargetVersion '16.3.2.10' -ComponentName 'Config'
                $result.IsValid | Should -Be $true
                $result.SkipDownload | Should -Be $true
                $result.SkipExtraction | Should -Be $true
            }
        }

        It "Should set SkipExtraction=false for App component" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $true }
                Mock Get-Item {
                    return [PSCustomObject]@{
                        Length = 50000000
                        LastWriteTime = (Get-Date)
                        VersionInfo = [PSCustomObject]@{
                            FileVersion = '15150'
                            ProductVersion = '15150'
                        }
                    }
                }
                Mock Convert-VersionString { return '15150' }
                Mock Get-ExecutableSignature { return [PSCustomObject]@{ Status = 'Valid' } }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Downloads\LoxoneApp.exe' -TargetVersion '15150' -ComponentName 'App'
                $result.IsValid | Should -Be $true
                $result.SkipDownload | Should -Be $true
                $result.SkipExtraction | Should -Be $false
            }
        }
    }

    Context "Version mismatch" {

        It "Should return IsValid=false when version does not match target" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $true }
                Mock Get-Item {
                    return [PSCustomObject]@{
                        Length = 50000000
                        LastWriteTime = (Get-Date)
                        VersionInfo = [PSCustomObject]@{
                            FileVersion = '16.2.0.0'
                            ProductVersion = '16.2.0.0'
                        }
                    }
                }
                Mock Convert-VersionString { return '16.2.0.0' }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Downloads\LoxoneConfig.exe' -TargetVersion '16.3.2.10'
                $result.IsValid | Should -Be $false
                $result.Reason | Should -Match 'Version mismatch'
            }
        }
    }

    Context "Invalid signature" {

        It "Should return IsValid=false when signature is invalid" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $true }
                Mock Get-Item {
                    return [PSCustomObject]@{
                        Length = 50000000
                        LastWriteTime = (Get-Date)
                        VersionInfo = [PSCustomObject]@{
                            FileVersion = '16.3.2.10'
                            ProductVersion = '16.3.2.10'
                        }
                    }
                }
                Mock Convert-VersionString { return '16.3.2.10' }
                Mock Get-ExecutableSignature { return [PSCustomObject]@{ Status = 'NotSigned' } }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Downloads\LoxoneConfig.exe' -TargetVersion '16.3.2.10'
                $result.IsValid | Should -Be $false
                $result.Reason | Should -Match 'Invalid signature'
            }
        }
    }

    Context "No version info - App with large file" {

        It "Should return IsValid=true for App installer with no version but large size" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $true }
                Mock Get-Item {
                    return [PSCustomObject]@{
                        Length = 50000000
                        LastWriteTime = (Get-Date)
                        VersionInfo = [PSCustomObject]@{
                            FileVersion = $null
                            ProductVersion = $null
                        }
                    }
                }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Downloads\Loxone.exe' -TargetVersion '15150' -ComponentName 'App'
                $result.IsValid | Should -Be $true
                $result.SkipDownload | Should -Be $true
            }
        }
    }

    Context "Version check error" {

        It "Should return IsValid=false when Convert-VersionString throws" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-Path { return $true }
                Mock Get-Item {
                    return [PSCustomObject]@{
                        Length = 50000000
                        LastWriteTime = (Get-Date)
                        VersionInfo = [PSCustomObject]@{
                            FileVersion = 'invalid'
                            ProductVersion = 'invalid'
                        }
                    }
                }
                Mock Convert-VersionString { throw "Cannot parse version" }

                $result = Test-ExistingInstaller -InstallerPath 'C:\Downloads\LoxoneConfig.exe' -TargetVersion '16.3.2.10'
                $result.IsValid | Should -Be $false
                $result.Reason | Should -Match 'Version check failed'
            }
        }
    }
}

Describe "Start-LoxoneForWindowsInstaller" -Tag 'Unit', 'Installation' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Start-LoxoneForWindowsInstaller -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept InstallerPath, InstallMode, and ScriptSaveFolder parameters" {
            $cmd = Get-Command Start-LoxoneForWindowsInstaller
            $cmd.Parameters.Keys | Should -Contain 'InstallerPath'
            $cmd.Parameters.Keys | Should -Contain 'InstallMode'
            $cmd.Parameters.Keys | Should -Contain 'ScriptSaveFolder'
        }
    }

    Context "Successful installation" {

        It "Should return Success=true when installer exits with code 0" {
            InModuleScope LoxoneUtils.Installation {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Get-Process { return $null }
                Mock Stop-Process {}
                Mock Start-Sleep {}
                Mock Update-PersistentToast {} -ErrorAction SilentlyContinue
                $mockProc = [PSCustomObject]@{ ExitCode = 0; HasExited = $true }
                $mockProc | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) return $true } -Force
                Mock Start-Process { return $mockProc }

                $result = Start-LoxoneForWindowsInstaller -InstallerPath 'C:\Downloads\Loxone.exe' -InstallMode 'silent'
                $result.Success | Should -Be $true
                $result.ExitCode | Should -Be 0
            }
        }
    }
}
