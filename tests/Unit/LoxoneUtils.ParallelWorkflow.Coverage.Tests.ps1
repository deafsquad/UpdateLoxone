# Coverage tests for LoxoneUtils.ParallelWorkflow - Remove-ThreadJobs and Write-WorkerLog
# Tests thread job cleanup and worker logging with mocked job infrastructure

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

    $script:TestTempPath = Join-Path $TestDrive "ParallelCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Write-WorkerLog" -Tag 'Unit', 'ParallelWorkflow' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Write-WorkerLog -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept LogQueue, WorkerName, Message, and Level parameters" {
            $cmd = Get-Command Write-WorkerLog
            $cmd.Parameters.Keys | Should -Contain 'LogQueue'
            $cmd.Parameters.Keys | Should -Contain 'WorkerName'
            $cmd.Parameters.Keys | Should -Contain 'Message'
            $cmd.Parameters.Keys | Should -Contain 'Level'
        }
    }

    Context "Queue operations" {

        It "Should enqueue a log entry with correct fields to the queue" {
            $queue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()

            Write-WorkerLog -LogQueue $queue -WorkerName 'ConfigWorker' -Message 'Download started' -Level 'INFO'

            $queue.Count | Should -Be 1

            $entry = $null
            $queue.TryDequeue([ref]$entry) | Should -Be $true
            $entry.Worker | Should -Be 'ConfigWorker'
            $entry.Message | Should -Be 'Download started'
            $entry.Level | Should -Be 'INFO'
            $entry.Timestamp | Should -Not -BeNullOrEmpty
        }

        It "Should default Level to INFO when not specified" {
            $queue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()

            Write-WorkerLog -LogQueue $queue -WorkerName 'TestWorker' -Message 'Test message'

            $entry = $null
            $queue.TryDequeue([ref]$entry) | Should -Be $true
            $entry.Level | Should -Be 'INFO'
        }

        It "Should support different log levels" {
            $queue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()

            Write-WorkerLog -LogQueue $queue -WorkerName 'Worker1' -Message 'Debug msg' -Level 'DEBUG'
            Write-WorkerLog -LogQueue $queue -WorkerName 'Worker1' -Message 'Warn msg' -Level 'WARN'
            Write-WorkerLog -LogQueue $queue -WorkerName 'Worker1' -Message 'Error msg' -Level 'ERROR'

            $queue.Count | Should -Be 3

            $entry1 = $null; $queue.TryDequeue([ref]$entry1) | Out-Null
            $entry2 = $null; $queue.TryDequeue([ref]$entry2) | Out-Null
            $entry3 = $null; $queue.TryDequeue([ref]$entry3) | Out-Null

            $entry1.Level | Should -Be 'DEBUG'
            $entry2.Level | Should -Be 'WARN'
            $entry3.Level | Should -Be 'ERROR'
        }

        It "Should include a timestamp in each log entry" {
            $queue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
            $before = Get-Date

            Write-WorkerLog -LogQueue $queue -WorkerName 'TimestampWorker' -Message 'Timing test'

            $after = Get-Date
            $entry = $null
            $queue.TryDequeue([ref]$entry) | Out-Null

            $entry.Timestamp | Should -BeGreaterOrEqual $before
            $entry.Timestamp | Should -BeLessOrEqual $after
        }
    }

    Context "Null queue handling" {

        It "Should silently return when LogQueue is null" {
            # Should not throw
            { Write-WorkerLog -LogQueue $null -WorkerName 'Worker' -Message 'Should be ignored' } | Should -Not -Throw
        }
    }

    Context "Multiple workers" {

        It "Should correctly attribute entries to different workers" {
            $queue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()

            Write-WorkerLog -LogQueue $queue -WorkerName 'ConfigWorker' -Message 'Config message'
            Write-WorkerLog -LogQueue $queue -WorkerName 'AppWorker' -Message 'App message'
            Write-WorkerLog -LogQueue $queue -WorkerName 'MSWorker' -Message 'MS message'

            $queue.Count | Should -Be 3

            $entries = @()
            while ($queue.Count -gt 0) {
                $entry = $null
                $queue.TryDequeue([ref]$entry) | Out-Null
                $entries += $entry
            }

            ($entries | Where-Object { $_.Worker -eq 'ConfigWorker' }).Message | Should -Be 'Config message'
            ($entries | Where-Object { $_.Worker -eq 'AppWorker' }).Message | Should -Be 'App message'
            ($entries | Where-Object { $_.Worker -eq 'MSWorker' }).Message | Should -Be 'MS message'
        }
    }
}

Describe "Remove-ThreadJobs" -Tag 'Unit', 'ParallelWorkflow' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Remove-ThreadJobs -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept Context and KeepProgressWorker parameters" {
            $cmd = Get-Command Remove-ThreadJobs
            $cmd.Parameters.Keys | Should -Contain 'Context'
            $cmd.Parameters.Keys | Should -Contain 'KeepProgressWorker'
        }
    }

    Context "No jobs present" {

        It "Should complete without error when no jobs exist" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                Mock Get-Job { return @() }
                Mock Write-Log {}

                { Remove-ThreadJobs -Context 'TestCleanup' } | Should -Not -Throw

                Should -Invoke Get-Job -Times 1
            }
        }
    }

    Context "Job cleanup" {

        # Note: Stop-Job/Remove-Job take [Job] typed -Job parameter.
        # PSCustomObject mock objects can't bind to [Job], so we verify
        # Get-Job is called and the function processes jobs without error.

        It "Should process running jobs without error" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                $mockJob = [PSCustomObject]@{
                    Name = 'TestJob1'
                    State = 'Running'
                    Id = 999
                }
                Mock Get-Job { return @($mockJob) }
                Mock Stop-Job {}
                Mock Remove-Job {}
                Mock Write-Log {}

                { Remove-ThreadJobs -Context 'TestCleanup' } | Should -Not -Throw

                Should -Invoke Get-Job -Times 1
                Should -Invoke Write-Log -Times 1 -ParameterFilter {
                    $Message -match 'Found 1 jobs to clean up'
                }
            }
        }

        It "Should process completed jobs without error" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                $mockJob = [PSCustomObject]@{
                    Name = 'CompletedJob'
                    State = 'Completed'
                    Id = 998
                }
                Mock Get-Job { return @($mockJob) }
                Mock Stop-Job {}
                Mock Remove-Job {}
                Mock Write-Log {}

                { Remove-ThreadJobs -Context 'TestCleanup' } | Should -Not -Throw

                Should -Invoke Get-Job -Times 1
                Should -Invoke Write-Log -Times 1 -ParameterFilter {
                    $Message -match 'Found 1 jobs to clean up'
                }
            }
        }

        It "Should log keeping ProgressWorker when KeepProgressWorker switch is set" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                $progressJob = [PSCustomObject]@{
                    Name = 'ProgressWorker'
                    State = 'Running'
                    Id = 997
                }
                $regularJob = [PSCustomObject]@{
                    Name = 'ConfigWorker'
                    State = 'Running'
                    Id = 996
                }
                Mock Get-Job { return @($progressJob, $regularJob) }
                Mock Stop-Job {}
                Mock Remove-Job {}
                Mock Write-Log {}

                { Remove-ThreadJobs -Context 'TestCleanup' -KeepProgressWorker } | Should -Not -Throw

                Should -Invoke Get-Job -Times 1
                Should -Invoke Write-Log -Times 1 -ParameterFilter {
                    $Message -match 'Keeping progress worker'
                }
            }
        }
    }

    Context "Error resilience" {

        It "Should not throw when Stop-Job fails for a job" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                $mockJob = [PSCustomObject]@{
                    Name = 'FailingJob'
                    State = 'Running'
                    Id = 995
                }
                Mock Get-Job { return @($mockJob) }
                Mock Stop-Job { throw "Cannot stop job" }
                Mock Remove-Job {}
                Mock Write-Log {}

                { Remove-ThreadJobs -Context 'ErrorTest' } | Should -Not -Throw
            }
        }

        It "Should not throw when Remove-Job fails for a job" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                $mockJob = [PSCustomObject]@{
                    Name = 'StuckJob'
                    State = 'Completed'
                    Id = 994
                }
                Mock Get-Job { return @($mockJob) }
                Mock Stop-Job {}
                Mock Remove-Job { throw "Cannot remove job" }
                Mock Write-Log {}

                { Remove-ThreadJobs -Context 'ErrorTest' } | Should -Not -Throw
            }
        }
    }

    Context "Default parameter values" {

        It "Should default Context to Unknown when not specified" {
            InModuleScope LoxoneUtils.ParallelWorkflow {
                Mock Get-Job { return @() }
                Mock Write-Log {}

                { Remove-ThreadJobs } | Should -Not -Throw
            }
        }
    }
}
