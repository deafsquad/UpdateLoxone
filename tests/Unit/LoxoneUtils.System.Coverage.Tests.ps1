# Coverage tests for LoxoneUtils.System - Test-ScheduledTask, Start-ProcessInteractive, Register-ScheduledTaskForScript
# Tests scheduled task detection, interactive process launching, and task registration

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

    $script:TestTempPath = Join-Path $TestDrive "SystemCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Test-ScheduledTask" -Tag 'Unit', 'SystemModule' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Test-ScheduledTask -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }
    }

    Context "Running under Task Scheduler" {

        It "Should return true when parent process is svchost" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                # Get-Process is called twice: first with -Id $PID (returns current proc with .Parent),
                # then with -Id $parentProcessId (returns parent proc with .Name)
                Mock Get-Process {
                    $parent = [PSCustomObject]@{ Name = 'svchost'; Id = 100 }
                    $obj = [PSCustomObject]@{ Id = $PID }
                    $obj | Add-Member -MemberType NoteProperty -Name Parent -Value $parent -Force
                    return $obj
                } -ParameterFilter { $Id -eq $PID }
                Mock Get-Process {
                    return [PSCustomObject]@{ Name = 'svchost'; Id = 100 }
                } -ParameterFilter { $Id -ne $PID }

                $result = Test-ScheduledTask
                $result | Should -Be $true
            }
        }

        It "Should return true when parent process is taskeng" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                Mock Get-Process {
                    $parent = [PSCustomObject]@{ Name = 'taskeng'; Id = 200 }
                    $obj = [PSCustomObject]@{ Id = $PID }
                    $obj | Add-Member -MemberType NoteProperty -Name Parent -Value $parent -Force
                    return $obj
                } -ParameterFilter { $Id -eq $PID }
                Mock Get-Process {
                    return [PSCustomObject]@{ Name = 'taskeng'; Id = 200 }
                } -ParameterFilter { $Id -ne $PID }

                $result = Test-ScheduledTask
                $result | Should -Be $true
            }
        }
    }

    Context "Not running under Task Scheduler" {

        It "Should return false when parent process is not svchost or taskeng" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                Mock Get-Process {
                    $parent = [PSCustomObject]@{ Name = 'explorer'; Id = 300 }
                    $obj = [PSCustomObject]@{ Id = $PID }
                    $obj | Add-Member -MemberType NoteProperty -Name Parent -Value $parent -Force
                    return $obj
                } -ParameterFilter { $Id -eq $PID }
                Mock Get-Process {
                    return [PSCustomObject]@{ Name = 'explorer'; Id = 300 }
                } -ParameterFilter { $Id -ne $PID }

                $result = Test-ScheduledTask
                $result | Should -Be $false
            }
        }
    }

    Context "Error handling - CIM fallback" {

        It "Should not throw when Get-Process fails and CIM is used" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                Mock Get-Process { throw "Process not found" }
                # CIM is called twice: first for current PID (needs .ParentProcessId),
                # then for parent (needs .Name). Return object with both properties.
                Mock Get-CimInstance { return [PSCustomObject]@{ ParentProcessId = 999; Name = 'explorer.exe' } }

                { Test-ScheduledTask } | Should -Not -Throw
            }
        }
    }
}

Describe "Start-ProcessInteractive" -Tag 'Unit', 'SystemModule' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Start-ProcessInteractive -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept FilePath and Arguments parameters" {
            $cmd = Get-Command Start-ProcessInteractive
            $cmd.Parameters.Keys | Should -Contain 'FilePath'
            $cmd.Parameters.Keys | Should -Contain 'Arguments'
        }
    }

    Context "Process launch" {

        It "Should create Shell.Application COM object and call ShellExecute" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                $mockShell = New-Object PSObject
                $mockShell | Add-Member -MemberType ScriptMethod -Name ShellExecute -Value { param($a,$b,$c,$d,$e) } -Force
                Mock New-Object { return $mockShell } -ParameterFilter { $ComObject -eq 'Shell.Application' }

                { Start-ProcessInteractive -FilePath 'C:\test.exe' -Arguments '/silent' } | Should -Not -Throw
            }
        }
    }
}

Describe "Register-ScheduledTaskForScript" -Tag 'Unit', 'SystemModule' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Register-ScheduledTaskForScript -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept ScriptPath and TaskName parameters" {
            $cmd = Get-Command Register-ScheduledTaskForScript
            $cmd.Parameters.Keys | Should -Contain 'ScriptPath'
            $cmd.Parameters.Keys | Should -Contain 'TaskName'
            $cmd.Parameters.Keys | Should -Contain 'ScheduledTaskIntervalMinutes'
        }
    }

    Context "New task registration" {

        It "Should register a new task when no existing task found" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-LoxoneScheduledTaskExists { return $false }
                Mock New-ScheduledTaskAction { return [PSCustomObject]@{ Execute = 'powershell.exe' } }
                Mock New-ScheduledTaskTrigger { return [PSCustomObject]@{ Repetition = [PSCustomObject]@{ Interval = 'PT10M' } } }
                Mock New-ScheduledTaskPrincipal { return [PSCustomObject]@{ UserId = 'SYSTEM' } }
                Mock New-ScheduledTaskSettingsSet { return [PSCustomObject]@{ Hidden = $true } }
                # Override Register-ScheduledTask with untyped wrapper to avoid CimInstance[] parameter binding
                # (the real cmdlet requires CimInstance[] which PSCustomObject can't satisfy)
                function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, $Settings, $Description, $ErrorAction) }
                Mock Register-ScheduledTask { return [PSCustomObject]@{ TaskName = 'TestTask' } }
                Mock Get-ScheduledTask { return [PSCustomObject]@{ Settings = [PSCustomObject]@{ DisallowStartIfOnBatteries = $true; StopIfGoingOnBatteries = $true; AllowHardTerminate = $false; RunOnlyIfNetworkAvailable = $true; Enabled = $true } } }
                Mock Set-ScheduledTask {}

                { Register-ScheduledTaskForScript -ScriptPath 'C:\Scripts\UpdateLoxone.ps1' -TaskName 'TestTask' } | Should -Not -Throw
                Should -Invoke Register-ScheduledTask -Times 1
            }
        }
    }

    Context "Existing task with matching config" {

        It "Should skip registration when existing task has matching configuration" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-LoxoneScheduledTaskExists { return $true }
                Mock Get-ScheduledTask {
                    return [PSCustomObject]@{
                        Actions = @([PSCustomObject]@{
                            Execute = 'powershell.exe'
                            Arguments = '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\UpdateLoxone.ps1" -ScriptSaveFolder "C:\Scripts"'
                        })
                        Triggers = @([PSCustomObject]@{
                            Repetition = [PSCustomObject]@{ Interval = 'PT10M' }
                        })
                    }
                }
                Mock Register-ScheduledTask {}

                { Register-ScheduledTaskForScript -ScriptPath 'C:\Scripts\UpdateLoxone.ps1' -TaskName 'TestTask' -ScheduledTaskIntervalMinutes 10 -ScriptSaveFolder 'C:\Scripts' } | Should -Not -Throw
            }
        }
    }

    Context "Existing task with different config" {

        It "Should unregister and re-register when configuration differs" {
            InModuleScope LoxoneUtils.System {
                Mock Write-Log {}
                Mock Enter-Function {}
                Mock Exit-Function {}
                Mock Test-LoxoneScheduledTaskExists { return $true }
                # Get-ScheduledTask is called multiple times: once for config check, once after re-registration
                # Return existing task with OLD config (different path and interval) to trigger update
                Mock Get-ScheduledTask {
                    return [PSCustomObject]@{
                        Actions = @([PSCustomObject]@{
                            Execute = 'powershell.exe'
                            Arguments = '-NoProfile -ExecutionPolicy Bypass -File "C:\OldPath\UpdateLoxone.ps1"'
                        })
                        Triggers = @([PSCustomObject]@{
                            Repetition = [PSCustomObject]@{ Interval = 'PT5M' }
                        })
                        Settings = [PSCustomObject]@{ DisallowStartIfOnBatteries = $true; StopIfGoingOnBatteries = $true; AllowHardTerminate = $false; RunOnlyIfNetworkAvailable = $true; Enabled = $true }
                    }
                }
                Mock Unregister-ScheduledTask {}
                Mock New-ScheduledTaskAction { return [PSCustomObject]@{ Execute = 'powershell.exe' } }
                Mock New-ScheduledTaskTrigger { return [PSCustomObject]@{ Repetition = [PSCustomObject]@{ Interval = 'PT10M' } } }
                Mock New-ScheduledTaskPrincipal { return [PSCustomObject]@{ UserId = 'SYSTEM' } }
                Mock New-ScheduledTaskSettingsSet { return [PSCustomObject]@{ Hidden = $true } }
                # Override Register-ScheduledTask with untyped wrapper to avoid CimInstance[] parameter binding
                function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, $Settings, $Description, $ErrorAction) }
                Mock Register-ScheduledTask { return [PSCustomObject]@{ TaskName = 'TestTask' } }
                Mock Set-ScheduledTask {}

                { Register-ScheduledTaskForScript -ScriptPath 'C:\Scripts\UpdateLoxone.ps1' -TaskName 'TestTask' -ScheduledTaskIntervalMinutes 10 } | Should -Not -Throw
                Should -Invoke Unregister-ScheduledTask -Times 1
                Should -Invoke Register-ScheduledTask -Times 1
            }
        }
    }
}
