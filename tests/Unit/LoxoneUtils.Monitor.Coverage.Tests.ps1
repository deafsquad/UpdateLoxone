# Coverage tests for LoxoneUtils.Monitor
# Tests all 9 exported functions with mocked external dependencies

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

    $script:TestTempPath = Join-Path $TestDrive "MonitorCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Find-LoxoneMonitorExe" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Find-LoxoneMonitorExe -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept LoxoneConfigInstallPath parameter" {
            $cmd = Get-Command Find-LoxoneMonitorExe
            $cmd.Parameters.Keys | Should -Contain 'LoxoneConfigInstallPath'
        }
    }

    Context "Path not found" {

        It "Should return null when install path does not exist" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $false }

                $result = Find-LoxoneMonitorExe -LoxoneConfigInstallPath 'C:\NonExistent'
                $result | Should -BeNullOrEmpty
            }
        }
    }

    Context "Monitor exe found" {

        It "Should return full path when loxonemonitor.exe is found" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                Mock Get-ChildItem {
                    return [PSCustomObject]@{ FullName = 'C:\Loxone\bin\loxonemonitor.exe' }
                }

                $result = Find-LoxoneMonitorExe -LoxoneConfigInstallPath 'C:\Loxone'
                $result | Should -Be 'C:\Loxone\bin\loxonemonitor.exe'
            }
        }
    }

    Context "Monitor exe not found" {

        It "Should return null when loxonemonitor.exe is not found in install path" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                Mock Get-ChildItem { return $null }

                $result = Find-LoxoneMonitorExe -LoxoneConfigInstallPath 'C:\Loxone'
                $result | Should -BeNullOrEmpty
            }
        }
    }

    Context "Error handling" {

        It "Should return null when Get-ChildItem throws an error" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                Mock Get-ChildItem { throw "Access denied" }

                $result = Find-LoxoneMonitorExe -LoxoneConfigInstallPath 'C:\Loxone'
                $result | Should -BeNullOrEmpty
            }
        }
    }
}

Describe "Stop-LoxoneMonitorProcess" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Stop-LoxoneMonitorProcess -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }
    }

    Context "Process running" {

        It "Should stop the process when it is running" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-Process { return [PSCustomObject]@{ Id = 1234; Name = 'loxonemonitor' } }
                Mock Stop-Process {}

                { Stop-LoxoneMonitorProcess } | Should -Not -Throw
                Should -Invoke Stop-Process -Times 1
            }
        }
    }

    Context "Process not running" {

        It "Should complete without error when no process is running" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-Process { return $null }
                Mock Stop-Process {}

                { Stop-LoxoneMonitorProcess } | Should -Not -Throw
                Should -Invoke Stop-Process -Times 0
            }
        }
    }

    Context "Error handling" {

        It "Should handle Stop-Process failure gracefully" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-Process { return [PSCustomObject]@{ Id = 1234; Name = 'loxonemonitor' } }
                Mock Stop-Process { throw "Access denied" }

                { Stop-LoxoneMonitorProcess } | Should -Not -Throw
            }
        }
    }
}

Describe "Enable-MiniserverLogging" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Enable-MiniserverLogging -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept MiniserverUrl and TargetIP parameters" {
            $cmd = Get-Command Enable-MiniserverLogging
            $cmd.Parameters.Keys | Should -Contain 'MiniserverUrl'
            $cmd.Parameters.Keys | Should -Contain 'TargetIP'
        }
    }

    Context "Successful activation" {

        It "Should return true when web request succeeds with HTTP 200" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Invoke-WebRequest { return [PSCustomObject]@{ StatusCode = 200 } }

                $result = Enable-MiniserverLogging -MiniserverUrl 'http://admin:pass@192.168.1.77' -TargetIP '192.168.1.100'
                $result | Should -Be $true
            }
        }

        It "Should call Invoke-WebRequest with correct URL path" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Invoke-WebRequest { return [PSCustomObject]@{ StatusCode = 200 } }

                Enable-MiniserverLogging -MiniserverUrl 'http://admin:pass@192.168.1.77' -TargetIP '192.168.1.100'

                Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
                    $Uri -match '/dev/sps/log/192\.168\.1\.100'
                }
            }
        }
    }

    Context "Failed activation" {

        It "Should return false when web request throws an error" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Invoke-WebRequest { throw "Connection refused" }

                $result = Enable-MiniserverLogging -MiniserverUrl 'http://admin:pass@192.168.1.77' -TargetIP '192.168.1.100'
                $result | Should -Be $false
            }
        }
    }
}

Describe "Disable-MiniserverLogging" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Disable-MiniserverLogging -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept MiniserverUrl parameter" {
            $cmd = Get-Command Disable-MiniserverLogging
            $cmd.Parameters.Keys | Should -Contain 'MiniserverUrl'
        }
    }

    Context "Successful deactivation" {

        It "Should return true when web request succeeds with HTTP 200" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Invoke-WebRequest { return [PSCustomObject]@{ StatusCode = 200 } }

                $result = Disable-MiniserverLogging -MiniserverUrl 'http://admin:pass@192.168.1.77'
                $result | Should -Be $true
            }
        }

        It "Should call Invoke-WebRequest with /dev/sps/log path (no IP)" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Invoke-WebRequest { return [PSCustomObject]@{ StatusCode = 200 } }

                Disable-MiniserverLogging -MiniserverUrl 'http://admin:pass@192.168.1.77'

                Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
                    $Uri -match '/dev/sps/log$' -or $Uri -match '/dev/sps/log/$'
                }
            }
        }
    }

    Context "Failed deactivation" {

        It "Should return false when web request throws an error" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Invoke-WebRequest { throw "Timeout" }

                $result = Disable-MiniserverLogging -MiniserverUrl 'http://admin:pass@192.168.1.77'
                $result | Should -Be $false
            }
        }
    }
}

Describe "Get-LocalIPAddress" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Get-LocalIPAddress -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }
    }

    Context "Manual IP found" {

        It "Should return static IP when manual adapter is found" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-NetIPAddress {
                    return @(
                        [PSCustomObject]@{ IPAddress = '192.168.1.50'; PrefixOrigin = 'Manual' },
                        [PSCustomObject]@{ IPAddress = '127.0.0.1'; PrefixOrigin = 'WellKnown' }
                    )
                }

                $result = Get-LocalIPAddress
                $result | Should -Be '192.168.1.50'
            }
        }
    }

    Context "DHCP fallback" {

        It "Should return DHCP IP when no manual adapter exists" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-NetIPAddress {
                    return @(
                        [PSCustomObject]@{ IPAddress = '10.0.0.5'; PrefixOrigin = 'Dhcp' },
                        [PSCustomObject]@{ IPAddress = '127.0.0.1'; PrefixOrigin = 'WellKnown' }
                    )
                }

                $result = Get-LocalIPAddress
                $result | Should -Be '10.0.0.5'
            }
        }
    }

    Context "Loopback fallback" {

        It "Should return 127.0.0.1 when Get-NetIPAddress throws" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-NetIPAddress { throw "Network error" }

                $result = Get-LocalIPAddress
                $result | Should -Be '127.0.0.1'
            }
        }
    }
}

Describe "Start-LoxoneMonitorProcess" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Start-LoxoneMonitorProcess -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept MonitorExePath and WorkingDirectory parameters" {
            $cmd = Get-Command Start-LoxoneMonitorProcess
            $cmd.Parameters.Keys | Should -Contain 'MonitorExePath'
            $cmd.Parameters.Keys | Should -Contain 'WorkingDirectory'
        }
    }

    Context "Process already running" {

        It "Should return existing process without starting a new one" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                $existingProc = [PSCustomObject]@{ Id = 5678; Name = 'loxonemonitor' }
                Mock Get-Process { return $existingProc }
                Mock Start-Process {}

                $result = Start-LoxoneMonitorProcess -MonitorExePath 'C:\Loxone\loxonemonitor.exe' -WorkingDirectory 'C:\Work'
                $result.Id | Should -Be 5678
                Should -Invoke Start-Process -Times 0
            }
        }
    }

    Context "Monitor exe not found" {

        It "Should throw when MonitorExePath does not exist" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-Process { return $null }
                Mock Test-Path { return $false }

                { Start-LoxoneMonitorProcess -MonitorExePath 'C:\Missing\loxonemonitor.exe' -WorkingDirectory 'C:\Work' } | Should -Throw
            }
        }
    }

    Context "Successful start" {

        It "Should start process and return it" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-Process { return $null }
                Mock Test-Path { return $true }
                Mock New-Item {}
                Mock Copy-Item {}
                Mock Get-Item { return $null }
                Mock Start-Sleep {}
                $mockProc = [PSCustomObject]@{ Id = 9999 }
                Mock Start-Process { return $mockProc }

                $result = Start-LoxoneMonitorProcess -MonitorExePath 'C:\Loxone\loxonemonitor.exe' -WorkingDirectory 'C:\Work'
                $result.Id | Should -Be 9999
                Should -Invoke Start-Process -Times 1
            }
        }
    }
}

Describe "Find-LxmonFiles" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Find-LxmonFiles -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept MonitorProcessId and DiscoveryMode parameters" {
            $cmd = Get-Command Find-LxmonFiles
            $cmd.Parameters.Keys | Should -Contain 'MonitorProcessId'
            $cmd.Parameters.Keys | Should -Contain 'DiscoveryMode'
        }
    }

    Context "User context with files found" {

        It "Should return path when .lxmon files exist in user context" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-CimInstance { return [PSCustomObject]@{ SessionId = 1 } }
                Mock Test-Path { return $true }
                Mock Get-ChildItem {
                    return @([PSCustomObject]@{ FullName = 'C:\Users\test\Documents\Loxone\test.lxmon'; Name = 'test.lxmon'; DirectoryName = 'C:\Users\test\Documents\Loxone' })
                }

                $result = Find-LxmonFiles -MonitorProcessId 1234
                $result | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context "No files found" {

        It "Should return null when no .lxmon files exist anywhere" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-CimInstance { return [PSCustomObject]@{ SessionId = 1 } }
                Mock Test-Path { return $false }
                Mock Get-ChildItem { return $null }

                $result = Find-LxmonFiles -MonitorProcessId 1234
                $result | Should -BeNullOrEmpty
            }
        }
    }

    Context "CIM error fallback" {

        It "Should fallback to combined search paths when Get-CimInstance fails" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Get-CimInstance { throw "WMI error" }
                Mock Test-Path { return $false }
                Mock Get-ChildItem { return $null }

                $result = Find-LxmonFiles -MonitorProcessId 1234
                $result | Should -BeNullOrEmpty
                Should -Invoke Write-Log -ParameterFilter { $Message -match 'Fehler bei Session-ID' }
            }
        }
    }
}

Describe "Watch-MonitorLogs" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Watch-MonitorLogs -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept required parameters" {
            $cmd = Get-Command Watch-MonitorLogs
            $cmd.Parameters.Keys | Should -Contain 'MonitorProcessId'
            $cmd.Parameters.Keys | Should -Contain 'DestinationLogDir'
            $cmd.Parameters.Keys | Should -Contain 'MiniserverName'
            $cmd.Parameters.Keys | Should -Contain 'MaxWaitMinutes'
            $cmd.Parameters.Keys | Should -Contain 'UpdateCompletedFlag'
            $cmd.Parameters.Keys | Should -Contain 'DiscoveryMode'
        }
    }

    Context "Source directory not found" {

        It "Should return false when Find-LxmonFiles returns null" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                Mock New-Item {}
                Mock Find-LxmonFiles { return $null }

                $flag = $false
                $result = Watch-MonitorLogs -MonitorProcessId 1234 -DestinationLogDir 'C:\Dest' -MiniserverName 'TestMS' -UpdateCompletedFlag ([ref]$flag)
                $result | Should -Be $false
            }
        }
    }
}

Describe "Remove-OldMonitorLogs" -Tag 'Unit', 'Monitor' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Remove-OldMonitorLogs -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept MonitorLogsPath and RetentionDays parameters" {
            $cmd = Get-Command Remove-OldMonitorLogs
            $cmd.Parameters.Keys | Should -Contain 'MonitorLogsPath'
            $cmd.Parameters.Keys | Should -Contain 'RetentionDays'
        }
    }

    Context "Path does not exist" {

        It "Should return without error when path does not exist" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $false }
                Mock Get-ChildItem {}
                Mock Remove-Item {}

                { Remove-OldMonitorLogs -MonitorLogsPath 'C:\NonExistent' } | Should -Not -Throw
                Should -Invoke Get-ChildItem -Times 0
            }
        }
    }

    Context "Old files exist" {

        It "Should delete files older than retention period" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                $oldFile = [PSCustomObject]@{
                    FullName = 'C:\Logs\old.lxmon'
                    Name = 'old.lxmon'
                    LastWriteTime = (Get-Date).AddDays(-60)
                }
                Mock Get-ChildItem { return @($oldFile) }
                Mock Remove-Item {}

                Remove-OldMonitorLogs -MonitorLogsPath 'C:\Logs' -RetentionDays 30

                Should -Invoke Remove-Item -Times 1
            }
        }
    }

    Context "No old files" {

        It "Should not delete any files when all are within retention period" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                Mock Get-ChildItem { return $null }
                Mock Remove-Item {}

                Remove-OldMonitorLogs -MonitorLogsPath 'C:\Logs' -RetentionDays 30

                Should -Invoke Remove-Item -Times 0
            }
        }
    }

    Context "Error handling" {

        It "Should handle Remove-Item failure gracefully" {
            InModuleScope LoxoneUtils.Monitor {
                Mock Write-Log {}
                Mock Test-Path { return $true }
                $oldFile = [PSCustomObject]@{
                    FullName = 'C:\Logs\locked.lxmon'
                    Name = 'locked.lxmon'
                    LastWriteTime = (Get-Date).AddDays(-60)
                }
                Mock Get-ChildItem { return @($oldFile) }
                Mock Remove-Item { throw "File is locked" }

                { Remove-OldMonitorLogs -MonitorLogsPath 'C:\Logs' -RetentionDays 30 } | Should -Not -Throw
            }
        }
    }
}
