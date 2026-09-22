# ThreadJob mocking for parallel workflow tests
# This prevents real ThreadJobs from being created and executing code in separate runspaces

# Ensure ThreadJob module is loaded
Import-Module ThreadJob -ErrorAction SilentlyContinue

# Clean up any existing jobs
Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

# Create a function wrapper that can be mocked
function global:Start-ThreadJob {
    param(
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [scriptblock]$InitializationScript,
        [string]$Name,
        [int]$ThrottleLimit
    )
    
    Write-Verbose "[MOCK-WRAPPER] Creating fake ThreadJob instead of real job"
    
    # Create a fake job object that looks like a completed ThreadJob
    $fakeJob = [PSCustomObject]@{
        Id = Get-Random
        Name = if ($Name) { $Name } else { "MockJob-$(Get-Random)" }
        State = 'Completed'
        HasMoreData = $false
        PSJobTypeName = 'ThreadJob'
        Command = $ScriptBlock.ToString()
    }
    
    # Add Dispose method
    Add-Member -InputObject $fakeJob -MemberType ScriptMethod -Name "Dispose" -Value {
        Write-Verbose "[MOCK-WRAPPER] Disposing fake job $($this.Name)"
    }
    
    # Add fake output based on script block content
    $scriptText = $ScriptBlock.ToString()
    
    if ($scriptText -match "ProgressWorker|Initialize-Toast") {
        Write-Verbose "[MOCK-WRAPPER] Simulating progress worker completion"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[ProgressWorker] Progress worker started",
            "[ProgressWorker] Initializing toast with 0 miniservers needing updates",
            "[ProgressWorker] Progress worker completed"
        )
    }
    elseif ($scriptText -match "Config|Download") {
        Write-Verbose "[MOCK-WRAPPER] Simulating Config download worker"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[Config Download Worker] CRC32 type initialized",
            "[Config Download Worker] Starting download of Config",
            "[Config Download Worker] Config download completed successfully",
            "[Config Download Worker] Download complete, queuing for installation"
        )
        
        # Simulate adding to install queue if provided
        if ($ArgumentList -and $ArgumentList[0].InstallQueue) {
            $ArgumentList[0].InstallQueue.Enqueue(@{
                Component = 'Config'
                FilePath = "C:\temp\mock_Config.zip"
                TargetVersion = [version]"14.0.0.0"
            })
        }
    }
    elseif ($scriptText -match "Install") {
        Write-Verbose "[MOCK-WRAPPER] Simulating install worker"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[Install Worker] Install worker started",
            "[Install Worker] Expecting 1 downloads to complete",
            "[Install Worker] All downloads processed, exiting",
            "[Install Worker] Install worker completed"
        )
    }
    elseif ($scriptText -match "Miniserver|MS Worker") {
        Write-Verbose "[MOCK-WRAPPER] Simulating miniserver worker"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[MS Worker] Starting miniserver updates for 1 miniservers",
            "[MS Worker] All miniserver updates completed"
        )
    }
    else {
        Write-Verbose "[MOCK-WRAPPER] Generic worker simulation"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[Worker] Job completed successfully"
        )
    }
    
    return $fakeJob
}

# Now mock it in the module scope to override the imported cmdlet
Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ThreadJob {
    param(
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [scriptblock]$InitializationScript,
        [string]$Name,
        [int]$ThrottleLimit
    )
    
    Write-Verbose "[MOCK] Creating fake ThreadJob instead of real job"
    
    # Create a fake job object that looks like a completed ThreadJob
    $fakeJob = [PSCustomObject]@{
        Id = Get-Random
        Name = if ($Name) { $Name } else { "MockJob-$(Get-Random)" }
        State = 'Completed'
        HasMoreData = $false
        PSJobTypeName = 'ThreadJob'
        Command = $ScriptBlock.ToString()
        
        # Add methods that might be called on the job
        PSObject = [PSCustomObject]@{
            Methods = @{
                Dispose = { Write-Verbose "[MOCK] Disposing fake job" }
            }
        }
    }
    
    # Add Dispose method
    Add-Member -InputObject $fakeJob -MemberType ScriptMethod -Name "Dispose" -Value {
        Write-Verbose "[MOCK] Disposing fake job $($this.Name)"
    }
    
    # Add Receive-Job simulation
    Add-Member -InputObject $fakeJob -MemberType ScriptMethod -Name "ReceiveJob" -Value {
        Write-Verbose "[MOCK] Receiving output from fake job $($this.Name)"
        return @()
    }
    
    # Simulate different worker behaviors based on the script block content
    $scriptText = $ScriptBlock.ToString()
    
    if ($scriptText -match "ProgressWorker|Initialize-Toast") {
        Write-Verbose "[MOCK] Simulating progress worker completion"
        # Add some fake output that the monitoring function expects
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[ProgressWorker] Progress worker started",
            "[ProgressWorker] Initializing toast with 0 miniservers needing updates",
            "[ProgressWorker] Progress worker completed"
        )
    }
    elseif ($scriptText -match "Config|Download") {
        Write-Verbose "[MOCK] Simulating Config download worker"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[Config Download Worker] CRC32 type initialized",
            "[Config Download Worker] Starting download of Config",
            "[Config Download Worker] Config download completed successfully",
            "[Config Download Worker] Download complete, queuing for installation"
        )
        
        # Simulate adding to install queue
        if ($ArgumentList -and $ArgumentList[0].InstallQueue) {
            $ArgumentList[0].InstallQueue.Enqueue(@{
                Component = 'Config'
                FilePath = "C:\temp\mock_Config.zip"
                TargetVersion = [version]"14.0.0.0"
            })
        }
    }
    elseif ($scriptText -match "Install") {
        Write-Verbose "[MOCK] Simulating install worker"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[Install Worker] Install worker started",
            "[Install Worker] Expecting 1 downloads to complete",
            "[Install Worker] All downloads processed, exiting",
            "[Install Worker] Install worker completed"
        )
    }
    elseif ($scriptText -match "Miniserver|MS Worker") {
        Write-Verbose "[MOCK] Simulating miniserver worker"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[MS Worker] Starting miniserver updates for 1 miniservers",
            "[MS Worker] All miniserver updates completed"
        )
    }
    else {
        Write-Verbose "[MOCK] Generic worker simulation"
        $fakeJob | Add-Member -MemberType NoteProperty -Name "Output" -Value @(
            "[Worker] Job completed successfully"
        )
    }
    
    return $fakeJob
}

# Mock Receive-Job to return fake output from our fake jobs
Mock -ModuleName LoxoneUtils.ParallelWorkflow Receive-Job {
    param(
        [Parameter(ValueFromPipeline=$true)]
        $Job,
        [switch]$Keep
    )
    
    if ($Job.Output) {
        Write-Verbose "[MOCK] Returning fake job output for $($Job.Name)"
        return $Job.Output
    }
    return @()
}

# Mock Remove-Job to handle cleanup of fake jobs
Mock -ModuleName LoxoneUtils.ParallelWorkflow Remove-Job {
    param(
        [Parameter(ValueFromPipeline=$true)]
        $Job,
        [switch]$Force
    )
    
    Write-Verbose "[MOCK] Removing fake job $($Job.Name)"
    # Do nothing - fake jobs don't need cleanup
}

# Mock Get-Job if needed
Mock -ModuleName LoxoneUtils.ParallelWorkflow Get-Job {
    param(
        [string]$Name,
        [int]$Id,
        [string]$State
    )
    
    Write-Verbose "[MOCK] Get-Job returning empty array"
    return @()
}

# Mock Wait-Job to return immediately
Mock -ModuleName LoxoneUtils.ParallelWorkflow Wait-Job {
    param(
        [Parameter(ValueFromPipeline=$true)]
        $Job,
        [switch]$Any,
        [int]$Timeout
    )
    
    Write-Verbose "[MOCK] Wait-Job returning immediately for $($Job.Name)"
    return $Job
}

Write-Host "ThreadJob mocks loaded (function wrapper) - no real parallel jobs will be created" -ForegroundColor Green
$Global:ThreadJobMocksLoaded = $true