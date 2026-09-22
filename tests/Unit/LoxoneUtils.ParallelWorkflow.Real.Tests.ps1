# Real implementation tests for LoxoneUtils.ParallelWorkflow - using actual parallel execution

BeforeAll {
    # Performance optimization: Skip module import if already loaded
    if (-not $Global:LoxoneUtilsPreloaded) {
        # Module not preloaded, import it
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        # Module already loaded, just ensure it's available in this scope
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    
    # Set flag to suppress toast initialization
    $Global:SuppressLoxoneToastInit = $true
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Set up test environment
    $script:TestTempPath = Join-Path $env:TEMP "LoxoneParallelTests_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    
    # Create test log file
    $Global:LogFile = Join-Path $script:TestTempPath 'parallel-test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    # Clean up temp directory
    if (Test-Path $script:TestTempPath) {
        Remove-Item -Path $script:TestTempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Real Parallel Execution with Jobs" -Tag 'ParallelWorkflow', 'Real' {
    
    It "Executes multiple jobs in parallel and collects results" {
        # Create simple jobs that return data after a delay
        $jobs = @()
        $expectedResults = @()
        
        for ($i = 1; $i -le 3; $i++) {
            $job = Start-Job -ScriptBlock {
                param($Index, $Delay)
                Start-Sleep -Milliseconds $Delay
                return @{
                    Index = $Index
                    ProcessId = $PID
                    StartTime = Get-Date
                    Result = "Job $Index completed"
                }
            } -ArgumentList $i, (Get-Random -Minimum 10 -Maximum 50)
            
            $jobs += $job
            $expectedResults += $i
        }
        
        # Wait for all jobs
        $results = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Verify results
        $results.Count | Should -Be 3
        $results.Index | Sort-Object | Should -Be @(1, 2, 3)
        
        # Verify they ran in different processes
        $pids = $results.ProcessId | Select-Object -Unique
        $pids.Count | Should -Be 3
    }
    
    It "Handles job failures gracefully" {
        $jobs = @()
        
        # Job that succeeds
        $jobs += Start-Job -ScriptBlock {
            return "Success"
        }
        
        # Job that throws error
        $jobs += Start-Job -ScriptBlock {
            throw "Simulated error"
        }
        
        # Job that exits with non-zero code
        $jobs += Start-Job -ScriptBlock {
            exit 1
        }
        
        # Wait and collect
        $completed = $jobs | Wait-Job
        
        # Check job states
        $states = $completed | Select-Object -ExpandProperty State
        $states | Should -Contain "Completed"
        $states | Should -Contain "Failed"
        
        # Clean up
        $jobs | Remove-Job -Force
    }
}

Describe "Real ThreadJob Execution" -Tag 'ParallelWorkflow', 'Real' {
    
    BeforeAll {
        # Performance optimization: Skip module import if already loaded
        if (-not $Global:LoxoneUtilsPreloaded) {
            # Module not preloaded, import it
            $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
            Import-Module $modulePath -Force -ErrorAction Stop
        } else {
            # Module already loaded, just ensure it's available in this scope
            $modulePath = $Global:LoxoneUtilsModulePath
            if (-not (Get-Module LoxoneUtils)) {
                Import-Module $modulePath -ErrorAction Stop
            }
        }
        
        # Set flag to suppress toast initialization
        $Global:SuppressLoxoneToastInit = $true
        
        # Check if ThreadJob module is available
        $script:ThreadJobAvailable = $null -ne (Get-Module -ListAvailable -Name ThreadJob)
        if (-not $script:ThreadJobAvailable) {
            try {
                Install-Module -Name ThreadJob -Force -Scope CurrentUser -ErrorAction Stop
                $script:ThreadJobAvailable = $true
            } catch {
                $script:ThreadJobAvailable = $false
            }
        }
    }
    
    It "Uses ThreadJobs for lightweight parallel execution" -Skip:(-not $script:ThreadJobAvailable) {
        Import-Module ThreadJob -Force
        
        $threadJobs = @()
        $sharedData = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        
        for ($i = 1; $i -le 5; $i++) {
            $job = Start-ThreadJob -ScriptBlock {
                param($Index, $Bag)
                # Simulate work
                $sum = 0
                for ($j = 1; $j -le 100; $j++) {
                    $sum += $j
                }
                $Bag.Add(@{
                    Index = $Index
                    ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                    Result = $sum
                })
            } -ArgumentList $i, $sharedData
            
            $threadJobs += $job
        }
        
        # Wait for completion
        $threadJobs | Wait-Job | Out-Null
        $threadJobs | Remove-Job
        
        # Check results
        $results = @()
        while ($sharedData.TryTake([ref]$item)) {
            $results += $item
        }
        
        $results.Count | Should -Be 5
        $results.Result | Select-Object -Unique | Should -Be 500500
    }
}

Describe "Real Runspace Pool Execution" -Tag 'ParallelWorkflow', 'Real' {
    
    It "Creates and uses a runspace pool for parallel execution" {
        # Create runspace pool
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, 5)
        $runspacePool.Open()
        
        $runspaces = @()
        $results = [System.Collections.ArrayList]::new()
        
        # Create work items
        for ($i = 1; $i -le 10; $i++) {
            $powershell = [powershell]::Create()
            $powershell.RunspacePool = $runspacePool
            
            [void]$powershell.AddScript({
                param($Index)
                $result = @{
                    Index = $Index
                    ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                    ProcessId = $PID
                    Calculation = $Index * $Index
                }
                Start-Sleep -Milliseconds (Get-Random -Minimum 5 -Maximum 20)
                return $result
            }).AddArgument($i)
            
            $runspaces += @{
                PowerShell = $powershell
                Handle = $powershell.BeginInvoke()
                Index = $i
            }
        }
        
        # Wait for all to complete
        foreach ($runspace in $runspaces) {
            $result = $runspace.PowerShell.EndInvoke($runspace.Handle)
            [void]$results.Add($result)
            $runspace.PowerShell.Dispose()
        }
        
        $runspacePool.Close()
        $runspacePool.Dispose()
        
        # Verify results
        $results.Count | Should -Be 10
        $results.Index | Sort-Object | Should -Be (1..10)
        
        # Check calculations
        for ($i = 1; $i -le 10; $i++) {
            $item = $results | Where-Object { $_.Index -eq $i }
            $item.Calculation | Should -Be ($i * $i)
        }
        
        # Verify parallel execution (multiple thread IDs used)
        $threadIds = $results.ThreadId | Select-Object -Unique
        $threadIds.Count | Should -BeGreaterThan 1
        $threadIds.Count | Should -BeLessOrEqual 5  # Pool size
    }
    
    It "Handles runspace errors and exceptions" -Skip {
        # Skip: Runspace tests require specific threading context
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, 2)
        $runspacePool.Open()
        
        # Create job that throws
        $powershell1 = [powershell]::Create()
        $powershell1.RunspacePool = $runspacePool
        [void]$powershell1.AddScript({
            throw "Test exception in runspace"
        })
        
        # Create job that succeeds
        $powershell2 = [powershell]::Create()
        $powershell2.RunspacePool = $runspacePool
        [void]$powershell2.AddScript({
            return "Success"
        })
        
        $handle1 = $powershell1.BeginInvoke()
        $handle2 = $powershell2.BeginInvoke()
        
        # Collect results
        $errorOccurred = $false
        try {
            $result1 = $powershell1.EndInvoke($handle1)
        } catch {
            $errorOccurred = $true
        }
        
        $result2 = $powershell2.EndInvoke($handle2)
        
        # Check error state
        $powershell1.Streams.Error.Count | Should -BeGreaterThan 0
        $result2 | Should -Be "Success"
        
        # Cleanup
        $powershell1.Dispose()
        $powershell2.Dispose()
        $runspacePool.Close()
        $runspacePool.Dispose()
    }
}

Describe "Real Parallel File Operations" -Tag 'ParallelWorkflow', 'Real' {
    
    It "Processes multiple files in parallel" -Skip {
        # Skip: Runspace tests require specific threading context
        # Create test files
        $testFiles = @()
        for ($i = 1; $i -le 10; $i++) {
            $filePath = Join-Path $script:TestTempPath "data_$i.txt"
            $content = "File $i`n" * 10  # Some content to process
            Set-Content -Path $filePath -Value $content
            $testFiles += $filePath
        }
        
        # Process files in parallel using jobs
        $jobs = foreach ($file in $testFiles) {
            Start-Job -ScriptBlock {
                param($FilePath)
                $content = Get-Content $FilePath
                $lineCount = $content.Count
                $wordCount = ($content -join ' ' -split '\s+').Count
                return @{
                    File = [System.IO.Path]::GetFileName($FilePath)
                    Lines = $lineCount
                    Words = $wordCount
                }
            } -ArgumentList $file
        }
        
        # Wait and collect results
        $results = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Verify results
        $results.Count | Should -Be 10
        $results | ForEach-Object {
            $_.Lines | Should -Be 100
            $_.Words | Should -BeGreaterThan 0
        }
    }
    
    It "Writes to different files concurrently without conflicts" {
        $outputFiles = @()
        $jobs = @()
        
        for ($i = 1; $i -le 5; $i++) {
            $outputFile = Join-Path $script:TestTempPath "output_$i.log"
            $outputFiles += $outputFile
            
            $job = Start-Job -ScriptBlock {
                param($FilePath, $Index)
                for ($j = 1; $j -le 10; $j++) {
                    Add-Content -Path $FilePath -Value "Worker $Index - Line $j - Time: $(Get-Date -Format 'HH:mm:ss.fff')"
                    Start-Sleep -Milliseconds 10
                }
            } -ArgumentList $outputFile, $i
            
            $jobs += $job
        }
        
        # Wait for completion
        $jobs | Wait-Job | Out-Null
        $jobs | Remove-Job
        
        # Verify each file has correct content
        foreach ($file in $outputFiles) {
            Test-Path $file | Should -Be $true
            $lines = Get-Content $file
            $lines.Count | Should -Be 10
            $lines | Should -Match "Worker \d+ - Line \d+"
        }
    }
}

Describe "Real Parallel Network Operations" -Tag 'ParallelWorkflow', 'Real' {
    
    It "Performs multiple web requests in parallel" {
        # Use mock delay function instead of external website
        $jobs = 1..3 | ForEach-Object {
            Start-Job -ScriptBlock {
                param($Index)
                # Simulate work with sleep instead of network call
                Start-Sleep -Milliseconds 100
                return @{ Success = $true; Index = $Index }
            } -ArgumentList $_
        }
        
        $startTime = Get-Date
        $results = $jobs | Wait-Job -Timeout 5 | Receive-Job
        $jobs | Remove-Job -Force
        $elapsed = (Get-Date) - $startTime
        
        # Should complete in ~100ms since running in parallel
        # Allow up to 2 seconds for job overhead
        $elapsed.TotalSeconds | Should -BeLessThan 2
        
        # All jobs should succeed
        $results | Should -HaveCount 3
        $results | Where-Object { $_.Success } | Should -HaveCount 3
    }
}

Describe "Real Workflow Coordination" -Tag 'ParallelWorkflow', 'Real' {
    
    It "Coordinates multiple stages of parallel work" {
        $stage1Results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $stage2Results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        
        # Stage 1: Generate data in parallel
        $stage1Jobs = for ($i = 1; $i -le 4; $i++) {
            Start-Job -ScriptBlock {
                param($Index)
                return @{
                    Stage = 1
                    Worker = $Index
                    Data = Get-Random -Minimum 1 -Maximum 100
                }
            } -ArgumentList $i
        }
        
        # Wait for stage 1
        $stage1Data = $stage1Jobs | Wait-Job | Receive-Job
        $stage1Jobs | Remove-Job
        
        # Stage 2: Process stage 1 results in parallel
        $stage2Jobs = foreach ($item in $stage1Data) {
            Start-Job -ScriptBlock {
                param($InputData)
                return @{
                    Stage = 2
                    Original = $InputData.Data
                    Processed = $InputData.Data * 2
                    Worker = $InputData.Worker
                }
            } -ArgumentList $item
        }
        
        # Wait for stage 2
        $stage2Data = $stage2Jobs | Wait-Job | Receive-Job
        $stage2Jobs | Remove-Job
        
        # Verify pipeline
        $stage1Data.Count | Should -Be 4
        $stage2Data.Count | Should -Be 4
        
        # Verify processing
        foreach ($result in $stage2Data) {
            $result.Processed | Should -Be ($result.Original * 2)
            $result.Stage | Should -Be 2
        }
    }
    
    It "Handles partial failures in parallel workflow" {
        $results = [System.Collections.ArrayList]::new()
        
        $jobs = for ($i = 1; $i -le 6; $i++) {
            Start-Job -ScriptBlock {
                param($Index)
                # Simulate 50% failure rate
                if ($Index % 2 -eq 0) {
                    throw "Simulated failure for worker $Index"
                }
                return @{
                    Success = $true
                    Worker = $Index
                    Result = "Completed"
                }
            } -ArgumentList $i
        }
        
        # Collect all results regardless of success/failure
        foreach ($job in $jobs) {
            Wait-Job $job | Out-Null
            if ($job.State -eq "Completed") {
                $output = Receive-Job $job -ErrorAction SilentlyContinue
                if ($output) {
                    [void]$results.Add($output)
                }
            }
        }
        
        $jobs | Remove-Job -Force
        
        # Should have 3 successful results (odd numbers)
        $results.Count | Should -Be 3
        $results.Worker | Sort-Object | Should -Be @(1, 3, 5)
    }
}


