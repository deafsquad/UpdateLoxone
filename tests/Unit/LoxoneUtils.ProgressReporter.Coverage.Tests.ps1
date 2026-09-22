# Coverage tests for LoxoneUtils.ProgressReporter
# Tests New-ProgressReporter, New-ProgressTracker, and Invoke-WithProgress

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

    $script:TestTempPath = Join-Path $TestDrive "ProgressReporterTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "New-ProgressReporter" -Tag 'Unit', 'ProgressReporter' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command New-ProgressReporter -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should have mandatory Context parameter with ValidateSet" {
            $cmd = Get-Command New-ProgressReporter
            $cmd.Parameters['Context'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }

            $validateSet = $cmd.Parameters['Context'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Sequential'
            $validateSet.ValidValues | Should -Contain 'Parallel'
        }
    }

    Context "Sequential context" {

        It "Should return a scriptblock for Sequential context" {
            Mock Write-Progress {}

            $reporter = New-ProgressReporter -Context 'Sequential'
            $reporter | Should -Not -BeNullOrEmpty
            $reporter | Should -BeOfType [scriptblock]
        }

        It "Should be invokable with standard progress parameters" {
            Mock Write-Progress {}

            $reporter = New-ProgressReporter -Context 'Sequential'

            { & $reporter -Operation 'TestOp' -Status 'Running' -PercentComplete 50 } | Should -Not -Throw
        }
    }

    Context "Parallel context" {

        It "Should return a scriptblock for Parallel context" {
            $pipeline = @{
                LogQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
                ProgressQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
            }

            $reporter = New-ProgressReporter -Context 'Parallel' -Pipeline $pipeline -WorkerName 'TestWorker'
            $reporter | Should -Not -BeNullOrEmpty
            $reporter | Should -BeOfType [scriptblock]
        }

        It "Should enqueue progress updates to the pipeline ProgressQueue" {
            $pipeline = @{
                LogQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
                ProgressQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
            }

            $reporter = New-ProgressReporter -Context 'Parallel' -Pipeline $pipeline -WorkerName 'TestWorker'

            & $reporter -Operation 'Download' -Status 'In Progress' -PercentComplete 75

            $pipeline.ProgressQueue.Count | Should -BeGreaterThan 0

            $entry = $null
            $pipeline.ProgressQueue.TryDequeue([ref]$entry) | Should -Be $true
            $entry.Operation | Should -Be 'Download'
            $entry.Status | Should -Be 'In Progress'
            $entry.Progress | Should -Be 75
            $entry.WorkerName | Should -Be 'TestWorker'
        }

        It "Should enqueue log entries to the pipeline LogQueue" {
            $pipeline = @{
                LogQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
                ProgressQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
            }

            $reporter = New-ProgressReporter -Context 'Parallel' -Pipeline $pipeline -WorkerName 'LogWorker'

            & $reporter -Operation 'Install' -Status 'Starting' -PercentComplete 0

            $pipeline.LogQueue.Count | Should -BeGreaterThan 0
        }
    }

    Context "Invalid context" {

        It "Should reject invalid Context values" {
            { New-ProgressReporter -Context 'InvalidContext' } | Should -Throw
        }
    }
}

Describe "Invoke-WithProgress" -Tag 'Unit', 'ProgressReporter' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Invoke-WithProgress -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should have mandatory Operation, ScriptBlock, and ProgressReporter parameters" {
            $cmd = Get-Command Invoke-WithProgress
            foreach ($paramName in @('Operation', 'ScriptBlock', 'ProgressReporter')) {
                $cmd.Parameters[$paramName].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                    ForEach-Object { $_.Mandatory | Should -Be $true -Because "$paramName should be mandatory" }
            }
        }
    }

    Context "Successful execution" {

        It "Should invoke the script block and call the reporter for start and complete" {
            $reporterCalls = [System.Collections.Generic.List[hashtable]]::new()
            $mockReporter = {
                param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level)
                $reporterCalls.Add(@{
                    Operation = $Operation
                    Status = $Status
                    PercentComplete = $PercentComplete
                })
            }

            $scriptBlock = {
                param($ProgressReporter)
                return "done"
            }

            Invoke-WithProgress -Operation 'TestOp' -ScriptBlock $scriptBlock -ProgressReporter $mockReporter

            $reporterCalls.Count | Should -BeGreaterOrEqual 2
            $reporterCalls[0].Status | Should -Be 'Starting'
            $reporterCalls[0].PercentComplete | Should -Be 0
            $reporterCalls[-1].Status | Should -Be 'Completed'
            $reporterCalls[-1].PercentComplete | Should -Be 100
        }

        It "Should return the result when PassThru is specified" {
            $mockReporter = { param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level) }
            $scriptBlock = {
                param($ProgressReporter)
                return 42
            }

            $result = Invoke-WithProgress -Operation 'ReturnTest' -ScriptBlock $scriptBlock -ProgressReporter $mockReporter -PassThru

            $result | Should -Be 42
        }

        It "Should not return the result when PassThru is not specified" {
            $mockReporter = { param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level) }
            $scriptBlock = {
                param($ProgressReporter)
                return 42
            }

            $result = Invoke-WithProgress -Operation 'NoReturnTest' -ScriptBlock $scriptBlock -ProgressReporter $mockReporter

            $result | Should -BeNullOrEmpty
        }
    }

    Context "Error handling" {

        It "Should report failure and re-throw when the script block throws" {
            $reporterCalls = [System.Collections.Generic.List[hashtable]]::new()
            $mockReporter = {
                param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level)
                $reporterCalls.Add(@{
                    Operation = $Operation
                    Status = $Status
                    Level = $Level
                })
            }

            $failingBlock = {
                param($ProgressReporter)
                throw "Test error"
            }

            { Invoke-WithProgress -Operation 'FailOp' -ScriptBlock $failingBlock -ProgressReporter $mockReporter } | Should -Throw

            # Should have reported the failure with ERROR level
            $failureReport = $reporterCalls | Where-Object { $_.Level -eq 'ERROR' }
            $failureReport | Should -Not -BeNullOrEmpty
            $failureReport.Status | Should -Match 'Failed'
        }
    }
}

Describe "New-ProgressTracker" -Tag 'Unit', 'ProgressReporter' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command New-ProgressTracker -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should have mandatory TotalItems, ProgressReporter, and Operation parameters" {
            $cmd = Get-Command New-ProgressTracker
            foreach ($paramName in @('TotalItems', 'ProgressReporter', 'Operation')) {
                $cmd.Parameters[$paramName].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                    ForEach-Object { $_.Mandatory | Should -Be $true -Because "$paramName should be mandatory" }
            }
        }
    }

    Context "Tracker creation" {

        It "Should return an object with TotalItems, ProcessedItems, StartTime, and Operation" {
            $mockReporter = { param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level) }

            $tracker = New-ProgressTracker -TotalItems 10 -ProgressReporter $mockReporter -Operation 'ProcessItems'

            $tracker.TotalItems | Should -Be 10
            $tracker.ProcessedItems | Should -Be 0
            $tracker.StartTime | Should -Not -BeNullOrEmpty
            $tracker.Operation | Should -Be 'ProcessItems'
        }

        It "Should have an Update method" {
            $mockReporter = { param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level) }

            $tracker = New-ProgressTracker -TotalItems 5 -ProgressReporter $mockReporter -Operation 'TestOp'

            $tracker.PSObject.Methods.Name | Should -Contain 'Update'
        }
    }

    Context "Tracking progress" {

        It "Should increment ProcessedItems on each Update call" {
            $mockReporter = { param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level) }

            $tracker = New-ProgressTracker -TotalItems 3 -ProgressReporter $mockReporter -Operation 'CountTest'

            $tracker.Update("Item 1")
            $tracker.ProcessedItems | Should -Be 1

            $tracker.Update("Item 2")
            $tracker.ProcessedItems | Should -Be 2

            $tracker.Update("Item 3")
            $tracker.ProcessedItems | Should -Be 3
        }

        It "Should call the progress reporter on each Update" {
            $reporterCalls = [System.Collections.Generic.List[hashtable]]::new()
            $mockReporter = {
                param($Operation, $Status, $PercentComplete, $CurrentOperation, $Details, $Level)
                $reporterCalls.Add(@{
                    Operation = $Operation
                    Status = $Status
                    PercentComplete = $PercentComplete
                    CurrentOperation = $CurrentOperation
                })
            }

            $tracker = New-ProgressTracker -TotalItems 2 -ProgressReporter $mockReporter -Operation 'ReporterTest'

            $tracker.Update("Processing item A", "ItemA")
            $tracker.Update("Processing item B", "ItemB")

            $reporterCalls.Count | Should -Be 2
            $reporterCalls[0].PercentComplete | Should -Be 50
            $reporterCalls[1].PercentComplete | Should -Be 100
        }
    }
}
