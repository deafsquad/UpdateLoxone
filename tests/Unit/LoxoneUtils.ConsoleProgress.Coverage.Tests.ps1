# Coverage tests for LoxoneUtils.ConsoleProgress - Show-ConsoleProgress and Start-ConsoleProgressMonitor

BeforeAll {
    # Import the module
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

    # Set up temp directory
    $script:TestTempPath = Join-Path $TestDrive "Tests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Show-ConsoleProgress Function" -Tag 'Unit', 'ConsoleProgress' {

    Context "Function existence and parameters" {

        It "Exists and is exported from LoxoneUtils" {
            Get-Command Show-ConsoleProgress -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has ProgressData parameter" {
            $params = (Get-Command Show-ConsoleProgress -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'ProgressData'
        }

        It "Has ClearScreen switch parameter" {
            $params = (Get-Command Show-ConsoleProgress -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'ClearScreen'
            $params['ClearScreen'].SwitchParameter | Should -Be $true
        }
    }

    Context "Basic invocation with minimal data" {

        It "Does not throw with empty progress data" {
            $progressData = @{}
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with only StatusMessage" {
            $progressData = @{
                StatusMessage = "Test status"
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with only OverallProgress" {
            $progressData = @{
                OverallProgress = 50
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }
    }

    Context "Config update progress data" {

        It "Does not throw when ConfigUpdate is set" {
            $progressData = @{
                ConfigUpdate   = $true
                ConfigProgress = 50
                ConfigStatus   = "Downloading..."
                ConfigElapsed  = "01:30"
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with zero ConfigProgress" {
            $progressData = @{
                ConfigUpdate   = $true
                ConfigProgress = 0
                ConfigStatus   = "Waiting..."
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with 100 ConfigProgress" {
            $progressData = @{
                ConfigUpdate   = $true
                ConfigProgress = 100
                ConfigStatus   = "Complete"
                ConfigElapsed  = "02:15"
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }
    }

    Context "App update progress data" {

        It "Does not throw when AppUpdate is set" {
            $progressData = @{
                AppUpdate   = $true
                AppProgress = 75
                AppStatus   = "Installing..."
                AppElapsed  = "00:45"
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with null AppStatus" {
            $progressData = @{
                AppUpdate   = $true
                AppProgress = 25
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }
    }

    Context "Miniserver progress data" {

        It "Does not throw with Miniserver data" {
            $progressData = @{
                MiniserverCount     = 3
                MiniserverCompleted = 1
                MiniserverProgress  = 33
                MiniserverElapsed   = "00:20"
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with MiniserverDetails" {
            $progressData = @{
                MiniserverCount     = 2
                MiniserverCompleted = 1
                MiniserverProgress  = 50
                MiniserverDetails   = @{
                    '192.168.1.10' = @{ Stage = 'Complete' }
                    '192.168.1.11' = @{ Stage = 'Update' }
                }
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Does not throw with zero MiniserverCount" {
            $progressData = @{
                MiniserverCount = 0
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }

        It "Handles all known Miniserver stage values" {
            $stages = @('Init', 'Update', 'Reboot', 'Wait', 'Complete', 'Failed', 'Unknown')
            foreach ($stage in $stages) {
                $progressData = @{
                    MiniserverCount   = 1
                    MiniserverProgress = 50
                    MiniserverCompleted = 0
                    MiniserverDetails = @{
                        '10.0.0.1' = @{ Stage = $stage }
                    }
                }
                { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
            }
        }
    }

    Context "Combined progress data" {

        It "Does not throw with all components active" {
            $progressData = @{
                ConfigUpdate        = $true
                ConfigProgress      = 100
                ConfigStatus        = "Complete"
                ConfigElapsed       = "01:00"
                AppUpdate           = $true
                AppProgress         = 50
                AppStatus           = "Installing..."
                AppElapsed          = "00:30"
                MiniserverCount     = 2
                MiniserverCompleted = 1
                MiniserverProgress  = 50
                MiniserverElapsed   = "00:15"
                MiniserverDetails   = @{
                    '192.168.1.10' = @{ Stage = 'Complete' }
                    '192.168.1.11' = @{ Stage = 'Update' }
                }
                OverallProgress     = 66
                StatusMessage       = "Processing updates..."
            }
            { Show-ConsoleProgress -ProgressData $progressData } | Should -Not -Throw
        }
    }
}

Describe "Start-ConsoleProgressMonitor Function" -Tag 'Unit', 'ConsoleProgress' {

    Context "Function existence and parameters" {

        It "Exists and is exported from LoxoneUtils" {
            Get-Command Start-ConsoleProgressMonitor -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has ProgressQueue parameter" {
            $params = (Get-Command Start-ConsoleProgressMonitor -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'ProgressQueue'
        }

        It "Has WorkflowDefinition parameter" {
            $params = (Get-Command Start-ConsoleProgressMonitor -Module LoxoneUtils).Parameters
            $params.Keys | Should -Contain 'WorkflowDefinition'
        }
    }

    Context "ConcurrentQueue handling" {

        It "Can create a ConcurrentQueue for use with the function" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $queue.GetType().Name | Should -Be 'ConcurrentQueue`1'
        }

        It "ConcurrentQueue supports enqueue and dequeue" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $queue.Enqueue(@{ Type = 'Complete' })
            $queue.Count | Should -Be 1

            $item = $null
            $dequeued = $queue.TryDequeue([ref]$item)
            $dequeued | Should -Be $true
            $item.Type | Should -Be 'Complete'
        }
    }

    Context "Exits on Complete message" {

        It "Processes a Complete message and returns" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{}

            # Enqueue a Complete message so the monitor loop terminates
            $queue.Enqueue(@{ Type = 'Complete' })

            # The function should process the Complete message and return
            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }
    }

    Context "Processes various message types" {

        It "Processes Component Config messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{ ConfigUpdate = $true }

            $queue.Enqueue(@{
                Type      = 'Component'
                Component = 'Config'
                Progress  = 50
                Step      = 'Download'
                Status    = 'In Progress'
            })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Processes Component App messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{ AppUpdate = $true }

            $queue.Enqueue(@{
                Type      = 'Component'
                Component = 'App'
                Progress  = 75
                Step      = 'Install'
                Status    = 'Running'
            })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Processes MiniserverTotal messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{}

            $queue.Enqueue(@{
                Type  = 'MiniserverTotal'
                Total = 5
            })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Processes MiniserverProgress messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{}

            $queue.Enqueue(@{
                Type      = 'MiniserverProgress'
                Completed = 2
                Progress  = 40
            })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Processes Miniserver detail messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{}

            $queue.Enqueue(@{
                Type  = 'Miniserver'
                IP    = '192.168.1.10'
                Stage = 'Update'
            })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Processes Status messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{}

            $queue.Enqueue(@{
                Type    = 'Status'
                Message = 'All updates complete'
            })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Processes a sequence of mixed messages and exits on Complete" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $workflowDef = @{
                ConfigUpdate      = $true
                AppUpdate         = $true
                MiniserverUpdates = @('ms1', 'ms2')
            }

            $queue.Enqueue(@{ Type = 'Status'; Message = 'Starting...' })
            $queue.Enqueue(@{ Type = 'Component'; Component = 'Config'; Progress = 25; Step = 'Download'; Status = 'Running' })
            $queue.Enqueue(@{ Type = 'Component'; Component = 'App'; Progress = 10; Step = 'Check'; Status = 'Checking' })
            $queue.Enqueue(@{ Type = 'MiniserverTotal'; Total = 2 })
            $queue.Enqueue(@{ Type = 'Miniserver'; IP = '10.0.0.1'; Stage = 'Init' })
            $queue.Enqueue(@{ Type = 'MiniserverProgress'; Completed = 1; Progress = 50 })
            $queue.Enqueue(@{ Type = 'Component'; Component = 'Config'; Progress = 100; Step = 'Install'; Status = 'Done' })
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }
    }

    Context "WorkflowDefinition interpretation" {

        It "Handles empty WorkflowDefinition" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $queue.Enqueue(@{ Type = 'Complete' })

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition @{} } | Should -Not -Throw
        }

        It "Handles WorkflowDefinition with MiniserverUpdates list" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $queue.Enqueue(@{ Type = 'Complete' })

            $workflowDef = @{
                MiniserverUpdates = @('server1', 'server2', 'server3')
            }

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }

        It "Handles WorkflowDefinition with null MiniserverUpdates" {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
            $queue.Enqueue(@{ Type = 'Complete' })

            $workflowDef = @{
                ConfigUpdate      = $true
                MiniserverUpdates = $null
            }

            { Start-ConsoleProgressMonitor -ProgressQueue $queue -WorkflowDefinition $workflowDef } | Should -Not -Throw
        }
    }
}

Describe "ConsoleProgress Module Exports" -Tag 'Unit', 'ConsoleProgress' {

    It "Exports Show-ConsoleProgress" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Show-ConsoleProgress'
    }

    It "Exports Start-ConsoleProgressMonitor" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Start-ConsoleProgressMonitor'
    }

    It "Exports Get-ProgressBar" {
        $module = Get-Module LoxoneUtils
        $module.ExportedFunctions.Keys | Should -Contain 'Get-ProgressBar'
    }
}
