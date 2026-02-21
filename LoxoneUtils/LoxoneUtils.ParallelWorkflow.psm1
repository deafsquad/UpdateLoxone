# LoxoneUtils.ParallelWorkflow.psm1
# Module for parallel execution of Loxone update workflows

# Import ThreadJob module for parallel execution
# Try the new name first (PowerShell 7.6+), then fall back to the old name
if (-not (Get-Module -Name Microsoft.PowerShell.ThreadJob)) {
    Import-Module Microsoft.PowerShell.ThreadJob -ErrorAction SilentlyContinue
}
if (-not (Get-Module -Name Microsoft.PowerShell.ThreadJob) -and -not (Get-Module -Name ThreadJob)) {
    Import-Module ThreadJob -ErrorAction SilentlyContinue
}
if (-not (Get-Module -Name Microsoft.PowerShell.ThreadJob) -and -not (Get-Module -Name ThreadJob)) {
    Write-Warning "ThreadJob module not available. Parallel workflow may not function correctly."
}

# Initialize module-level variables
$script:WorkflowState = @{
    StartTime = $null
    EndTime = $null
    Results = [System.Collections.Concurrent.ConcurrentBag[hashtable]]::new()
    Errors = [System.Collections.Concurrent.ConcurrentBag[hashtable]]::new()
    Progress = [System.Collections.Concurrent.ConcurrentDictionary[string,hashtable]]::new()
}

# Miniserver status symbols for compact display
$script:MSSymbols = @{
    Init     = '🔍'  # Checking for updates
    Update   = '🔄'  # Update in progress  
    Reboot   = '🚀'  # Reboot phase
    Wait     = '⏳'  # Waiting for boot
    Success  = 'âœ“'   # Complete
    Failed   = 'âœ—'   # Failed
}

# Helper function to build miniserver status line with symbols
function Get-MiniserverStatusLine {
    param([hashtable]$MiniserverStates)
    
    # Count miniservers in each state
    $stateCounts = @{}
    foreach ($state in $MiniserverStates.Values) {
        if (-not $stateCounts[$state.Stage]) {
            $stateCounts[$state.Stage] = 0
        }
        $stateCounts[$state.Stage]++
    }
    
    # Build status parts with symbols
    $statusParts = @()
    if ($stateCounts['Init'] -gt 0) {
        $statusParts += "$($stateCounts['Init']) $($script:MSSymbols.Init)"
    }
    if ($stateCounts['Update'] -gt 0) {
        $statusParts += "$($stateCounts['Update']) $($script:MSSymbols.Update)"
    }
    if ($stateCounts['Reboot'] -gt 0) {
        $statusParts += "$($stateCounts['Reboot']) $($script:MSSymbols.Reboot)"
    }
    if ($stateCounts['Wait'] -gt 0) {
        $statusParts += "$($stateCounts['Wait']) $($script:MSSymbols.Wait)"
    }
    if ($stateCounts['Success'] -gt 0) {
        $statusParts += "$($stateCounts['Success']) $($script:MSSymbols.Success)"
    }
    
    # Failed with IPs
    if ($stateCounts['Failed'] -gt 0) {
        $failedMs = $MiniserverStates.Values | Where-Object { $_.Stage -eq 'Failed' }
        $failedIPs = ($failedMs | ForEach-Object { $_.IP }) -join ', '
        $statusParts += "$($stateCounts['Failed']) $($script:MSSymbols.Failed): $failedIPs"
    }
    
    return $statusParts -join ' | '
}

# Calculate overall miniserver progress
function Get-MiniserverProgress {
    param([hashtable]$MiniserverStates)
    
    # Calculate overall progress based on completed miniservers
    $total = $MiniserverStates.Count
    $completed = ($MiniserverStates.Values | Where-Object { $_.Stage -in 'Success', 'Failed', 'Skipped' }).Count
    
    if ($total -eq 0) { return 0 }
    return [math]::Round(($completed / $total) * 100)
}

# Helper function for workers to send log messages back to main thread
function Write-WorkerLog {
    param(
        [System.Collections.Concurrent.ConcurrentQueue[hashtable]]$LogQueue,
        [string]$WorkerName,
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    if (-not $LogQueue) { return }
    
    $logEntry = @{
        Timestamp = Get-Date
        Worker = $WorkerName
        Message = $Message
        Level = $Level
    }
    
    [void]$LogQueue.Enqueue($logEntry)
}

function Remove-ThreadJobs {
    [CmdletBinding()]
    param(
        [string]$Context = "Unknown",
        [switch]$KeepProgressWorker
    )
    
    Write-Log "[$Context] Cleaning up ThreadJobs..." -Level "DEBUG"
    
    # Get all jobs
    $allJobs = @(Get-Job -ErrorAction SilentlyContinue)
    
    if ($allJobs.Count -gt 0) {
        Write-Log "[$Context] Found $($allJobs.Count) jobs to clean up" -Level "INFO"
        
        foreach ($job in $allJobs) {
            # Skip progress worker if requested
            if ($KeepProgressWorker -and $job.Name -match 'ProgressWorker') {
                Write-Log "[$Context] Keeping progress worker job: $($job.Name)" -Level "DEBUG"
                continue
            }
            
            try {
                if ($job.State -eq 'Running') {
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                }
                Remove-Job -Job $job -ErrorAction SilentlyContinue
            } catch {
                # Ignore errors during cleanup
            }
        }
        
        # Force garbage collection to release resources
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        Write-Log "[$Context] ThreadJob cleanup completed" -Level "DEBUG"
    }
}

function Start-ParallelWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$WorkflowDefinition,

        [Parameter()]
        [int]$MaxConcurrency = 10,

        [Parameter()]
        [int]$MaxMSConcurrency = 3,

        [Parameter()]
        [array]$MSPreCheckJobs = $null,

        [Parameter()]
        [bool]$MSPreCheckJobsActive = $false
    )
    
    Write-Log "Starting parallel workflow..." -Level "INFO"
    Write-Host "Starting parallel workflow execution..." -ForegroundColor Cyan
    
    # Track workflow start time for overall timer
    $workflowStartTime = Get-Date
    
    # Initialize workflow pipeline
    # Calculate step mapping for parallel execution - each component has its own step counter
    $stepMapping = @{}
    
    # Config has its own step progression - steps defined as data, count derived dynamically
    if ($WorkflowDefinition.ConfigUpdate) {
        $configStepDefs = @(
            @{ Key = 'ConfigDownload'; StepName = "Downloading" }
            @{ Key = 'ConfigExtract';  StepName = "Extracting" }
            @{ Key = 'ConfigInstall';  StepName = "Installing" }
            @{ Key = 'ConfigVerify';   StepName = "Verifying" }
        )
        $configStep = 1
        foreach ($stepDef in $configStepDefs) {
            $stepMapping[$stepDef.Key] = @{ StepNumber = $configStep++; TotalSteps = $configStepDefs.Count; StepName = $stepDef.StepName }
        }
    }

    # App has its own step progression - steps defined as data, count derived dynamically
    if ($WorkflowDefinition.AppUpdate) {
        $appStepDefs = @(
            @{ Key = 'AppDownload'; StepName = "Downloading" }
            @{ Key = 'AppInstall';  StepName = "Installing" }
            @{ Key = 'AppVerify';   StepName = "Verifying" }
        )
        $appStep = 1
        foreach ($stepDef in $appStepDefs) {
            $stepMapping[$stepDef.Key] = @{ StepNumber = $appStep++; TotalSteps = $appStepDefs.Count; StepName = $stepDef.StepName }
        }
    }
    
    # Miniservers have their own counter (usually just 1/1)
    if ($WorkflowDefinition.MiniserverUpdates -and $WorkflowDefinition.MiniserverUpdates.Count -gt 0) {
        $stepMapping.MiniserverUpdate = @{ StepNumber = 1; TotalSteps = 1; StepName = "Updating Miniservers" }
    }
    
    Write-Log "Step mapping created: TotalSteps=$totalSteps, Mapping=$($stepMapping | ConvertTo-Json -Compress)" -Level "DEBUG"
    
    $pipeline = @{
        InstallQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
        ProgressQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
        Results = [System.Collections.Concurrent.ConcurrentBag[hashtable]]::new()
        LogQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()  # Add log queue for centralized logging
        StepMapping = $stepMapping  # Add step mapping for workers to use
        TotalMiniservers = if ($WorkflowDefinition.MiniserverUpdates) { $WorkflowDefinition.MiniserverUpdates.Count } else { 0 }  # Track total MS count
    }
    
    # Set parallel mode flag
    $env:LOXONE_PARALLEL_MODE = "1"
    
    # Create an array to hold all ThreadJobs
    $allJobs = @()
    
    try {
        # Initialize toast in main thread if there's any work
        $hasWork = $WorkflowDefinition.ConfigUpdate -or $WorkflowDefinition.AppUpdate -or 
                   ($WorkflowDefinition.MiniserverUpdates -and $WorkflowDefinition.MiniserverUpdates.Count -gt 0)
        
        if ($hasWork) {
            Write-Log "Initializing progress toast in main thread..." -Level "INFO"
            
            # Count components for toast
            $totalComponents = 0
            $msCount = if ($WorkflowDefinition.MiniserverUpdates) { $WorkflowDefinition.MiniserverUpdates.Count } else { 0 }
            
            if ($WorkflowDefinition.ConfigUpdate) { $totalComponents++ }
            if ($WorkflowDefinition.AppUpdate) { $totalComponents++ }
            if ($msCount -gt 0) { $totalComponents++ }
            
            # Initialize toast in main thread (avoids COM threading issues)
            try {
                # Check if toast is already initialized to avoid double initialization
                if ($Global:PersistentToastInitialized) {
                    Write-Log "Toast already initialized - skipping re-initialization in parallel workflow" -Level "INFO"
                } elseif (Get-Command Initialize-Toast -ErrorAction SilentlyContinue) {
                    # Set up component information for Initialize-Toast to read
                    $Global:ParallelWorkflowComponents = @{
                        Config = $WorkflowDefinition.ConfigUpdate -ne $null
                        App = $WorkflowDefinition.AppUpdate -ne $null
                        Miniservers = $msCount
                    }
                    
                    # Also set environment variable as backup
                    $env:LOXONE_PARALLEL_COMPONENTS = $Global:ParallelWorkflowComponents | ConvertTo-Json -Compress
                    
                    Write-Log "Setting up parallel components: Config=$($Global:ParallelWorkflowComponents.Config), App=$($Global:ParallelWorkflowComponents.App), Miniservers=$msCount" -Level "INFO"
                    Write-Log "Creating toast with $totalComponents components, $msCount miniservers" -Level "INFO"
                    
                    # Initialize-Toast will read from Global:ParallelWorkflowComponents or env:LOXONE_PARALLEL_COMPONENTS
                    Initialize-Toast
                    $Global:PersistentToastInitialized = $true
                    Write-Log "Toast initialized successfully in main thread" -Level "INFO"
                } else {
                    Write-Log "Initialize-Toast command not available" -Level "WARN"
                }
            } catch {
                Write-Log "Failed to initialize toast: $_" -Level "WARN"
            }
        }
        
        # Send initial progress updates for MS with PreCheck status
        if ($WorkflowDefinition.MiniserverUpdates) {
            foreach ($ms in $WorkflowDefinition.MiniserverUpdates) {
                if ($ms.Status -eq 'PreCheck' -or $ms.InitialVersion -eq 'Checking...') {
                    # Extract IP from OriginalEntry
                    $msIP = ($ms.Name -replace '^MS\s+', '')
                    Write-Log "Sending initial PreCheck progress for MS: $msIP" -Level "DEBUG"

                    $progressUpdate = @{
                        Type = 'Miniserver'
                        Component = 'Miniserver'
                        IP = $msIP
                        State = 'PreCheck'
                        Progress = 0
                        Message = "Checking version..."
                    }
                    $pipeline.ProgressQueue.Enqueue($progressUpdate)
                }
            }
        }

        # Start component workers - each handles its complete workflow
        if ($WorkflowDefinition.ConfigUpdate) {
            Write-Log "Starting Config worker..." -Level "INFO"
            $configJob = Start-ComponentWorker -Pipeline $pipeline -Component 'Config' -UpdateInfo $WorkflowDefinition.ConfigUpdate
            $allJobs += $configJob
        }
        
        if ($WorkflowDefinition.AppUpdate) {
            Write-Log "Starting App worker..." -Level "INFO"
            $appJob = Start-ComponentWorker -Pipeline $pipeline -Component 'App' -UpdateInfo $WorkflowDefinition.AppUpdate
            $allJobs += $appJob
        }
        
        # Start miniserver worker if needed
        if ($WorkflowDefinition.MiniserverUpdates -and $WorkflowDefinition.MiniserverUpdates.Count -gt 0) {
            Write-Log "Starting miniserver worker..." -Level "INFO"
            $msJob = Start-MiniserverWorker -WorkflowDefinition $WorkflowDefinition -Pipeline $pipeline -MaxConcurrency $MaxMSConcurrency -MSPreCheckJobs $MSPreCheckJobs -MSPreCheckJobsActive $MSPreCheckJobsActive
            $allJobs += $msJob
        }
        
        # Process any early logs from workers before entering main monitoring
        if ($pipeline.LogQueue) {
            $earlyLog = $null
            $earlyLogCount = 0
            while ($pipeline.LogQueue.TryDequeue([ref]$earlyLog)) {
                if ($earlyLog) {
                    $formattedMessage = "[$($earlyLog.Worker)] $($earlyLog.Message)"
                    Write-Log $formattedMessage -Level $earlyLog.Level
                    $earlyLogCount++
                }
            }
            if ($earlyLogCount -gt 0) {
                Write-Log "Flushed $earlyLogCount early log entries from workers" -Level "DEBUG"
            }
        }
        
        # Monitor execution
        Write-Log "Monitoring workflow execution..." -Level "INFO"
        $result = Watch-DirectThreadJobs -WorkerJobs $allJobs -WorkflowDefinition $WorkflowDefinition -Pipeline $pipeline
        
        Write-Log "Parallel workflow completed. Success: $($result.Success)" -Level "INFO"
        return $result
        
    } catch {
        Write-Log "Error in parallel workflow: $_" -Level "ERROR"
        throw
    } finally {
        # Cleanup
        Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
        Remove-ThreadJobs -Context "Parallel Workflow Cleanup"
    }
}

# DEPRECATED: Progress worker is no longer needed - toast is managed by main thread
# Keeping function definition for backward compatibility but it's not used
function Start-ProgressWorker {
    param([hashtable]$Pipeline, [hashtable]$WorkflowDefinition)
    
    # Progress worker is deprecated - toast is managed by main thread now
    # This function returns null to maintain compatibility
    return $null
}

<# DEPRECATED CODE - Kept for reference but not executed
    $progressScript = {
        param($Pipeline, $WorkflowDefinition, $ModulePath, $LogFile)
        
        # Define Write-WorkerLog inline for this worker
        function Write-WorkerLog {
            param(
                [System.Collections.Concurrent.ConcurrentQueue[hashtable]]$LogQueue,
                [string]$WorkerName,
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            if (-not $LogQueue) { return }
            
            $logEntry = @{
                Timestamp = Get-Date
                Worker = $WorkerName
                Message = $Message
                Level = $Level
            }
            
            [void]$LogQueue.Enqueue($logEntry)
        }
        
        try {
            # Import modules and set globals in this thread context
            Import-Module (Join-Path $ModulePath "LoxoneUtils.psd1") -Force
            $Global:LogFile = $LogFile
            
            # Apply TLS settings for consistency (though progress worker may not need it)
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls13
            } catch {
                try {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                } catch {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                }
            }
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Progress worker started" -Level "INFO"
            
            # Initialize BurntToast in this context
            if (Get-Command Initialize-LoxoneToastAppId -ErrorAction SilentlyContinue) {
                Initialize-LoxoneToastAppId
            }
            
            # Initialize toast with proper AppId
            $appId = $null
            if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
                $appId = Get-LoxoneToastAppId
            }
            
            # Use a mutex to prevent race condition with toast initialization
            $toastMutex = New-Object System.Threading.Mutex($false, "LoxoneToastInitMutex")
            $toastAcquired = $false
            try {
                $toastAcquired = $toastMutex.WaitOne(5000)  # Wait up to 5 seconds
                if (-not $toastAcquired) {
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Could not acquire toast mutex after 5 seconds" -Level "WARN"
                }
                
                # Check if toast is already initialized to prevent race condition
                $toastAlreadyInitialized = $Global:PersistentToastInitialized -eq $true
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Toast already initialized: $toastAlreadyInitialized" -Level "DEBUG"
            
            # Create initial toast notification with data binding template
            # Simplified: Don't check for New-BTBinding in worker, just send request to main thread
            if (-not $toastAlreadyInitialized) {
                # Count actual components for data binding
                $totalComponents = 0
                $msCount = if ($WorkflowDefinition.MiniserverUpdates) { $WorkflowDefinition.MiniserverUpdates.Count } else { 0 }
                
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Initializing toast with $msCount miniservers needing updates" -Level "INFO"
                
                # Count components for main thread
                if ($WorkflowDefinition.ConfigUpdate) {
                    $totalComponents++
                }
                
                if ($WorkflowDefinition.AppUpdate) {
                    $totalComponents++
                }
                
                if ($msCount -gt 0) {
                    $totalComponents++
                }
                
                # Initialize the global persistent toast data
                # CRITICAL: We must use the SAME global dataframe for all toast operations
                if (-not $Global:PersistentToastData) {
                    # Initialize if not exists (this should normally be done by Toast module)
                    $Global:PersistentToastData = @{
                        statusMessage = 'Starting parallel update process...'
                        configStatus = 'Waiting...'
                        configProgress = 0.0
                        configDuration = ''
                        appStatus = 'Waiting...'
                        appProgress = 0.0
                        appDuration = ''
                        MiniserversTitle = "Miniservers (0/$msCount)"
                        msCompleted = 0
                        msStatus = 'Waiting...'
                        msProgress = 0.0
                    }
                } else {
                    # Update existing global data
                    $Global:PersistentToastData.statusMessage = 'Starting parallel update process...'
                    $Global:PersistentToastData.configStatus = 'Waiting...'
                    $Global:PersistentToastData.configProgress = 0.0
                    if (-not $Global:PersistentToastData.ContainsKey('configDuration')) {
                        $Global:PersistentToastData.configDuration = ''
                    }
                    $Global:PersistentToastData.appStatus = 'Waiting...'
                    $Global:PersistentToastData.appProgress = 0.0
                    if (-not $Global:PersistentToastData.ContainsKey('appDuration')) {
                        $Global:PersistentToastData.appDuration = ''
                    }
                    $Global:PersistentToastData.MiniserversTitle = "Miniservers (0/$msCount)"
                    $Global:PersistentToastData.msCompleted = 0
                    $Global:PersistentToastData.msStatus = 'Waiting...'
                    $Global:PersistentToastData.msProgress = 0.0
                }
                
                # Use the global data for initial binding
                $initialData = $Global:PersistentToastData
                
                # Submit initial toast with AppId and data binding
                # CRITICAL: Use the same toast ID as the main module
                $toastId = if ($Global:PersistentToastId) { $Global:PersistentToastId } else { 'LoxoneUpdateStatusToast' }
                
                try {
                    # Skip actual toast creation in worker threads - just set the data
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Skipping toast creation in worker thread (would cause RPC_E_WRONG_THREAD)" -Level "INFO"
                    
                    # Still mark as initialized so the workflow continues
                    $Global:PersistentToastInitialized = $true
                    
                    # Send a message to main thread to create/update toast instead
                    # Simplified request with just essential data
                    $toastRequest = @{
                        Type = 'CreateToast'
                        TotalComponents = $totalComponents
                        MiniserverCount = $msCount
                    }
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Enqueueing toast request: Type=$($toastRequest.Type), Components=$($toastRequest.TotalComponents), MS=$($toastRequest.MiniserverCount)" -Level "INFO"
                    [void]$Pipeline.ProgressQueue.Enqueue($toastRequest)
                    
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Sent toast creation request to main thread" -Level "INFO"
                } catch {
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Failed to queue toast request: $_" -Level "WARN"
                }
            } elseif ($toastAlreadyInitialized) {
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Skipping toast initialization - already initialized" -Level "INFO"
            }
            } finally {
                if ($toastAcquired -and $toastMutex) {
                    $toastMutex.ReleaseMutex()
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Released toast initialization mutex" -Level "DEBUG"
                }
            }
            
            # Track component states
            $componentStates = @{
                Config = @{ State = 'Pending'; Progress = 0; Message = '' }
                App = @{ State = 'Pending'; Progress = 0; Message = '' }
                Miniservers = @{}
            }
            
            # Initialize miniserver states
            if ($WorkflowDefinition.MiniserverUpdates) {
                foreach ($ms in $WorkflowDefinition.MiniserverUpdates) {
                    $componentStates.Miniservers[$ms.IP] = @{
                        State = 'Pending'
                        Progress = 0
                        Message = ''
                        Name = $ms.Name
                        DNS = $null
                        Error = $null
                    }
                }
            }
            
            # Monitor progress queue
            $lastUpdate = Get-Date
            $complete = $false
            
            while (-not $complete) {
                # Process progress updates
                $update = $null
                while ($Pipeline.ProgressQueue.TryDequeue([ref]$update)) {
                    if ($update) {
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Processing update: $($update | ConvertTo-Json -Compress)" -Level "DEBUG"
                        
                        # Update component state
                        switch ($update.Type) {
                            'Download' {
                                if ($update.Component -eq 'Config') {
                                    $componentStates.Config.State = $update.State
                                    $componentStates.Config.Progress = $update.Progress
                                    $componentStates.Config.Message = $update.Message
                                } elseif ($update.Component -eq 'App') {
                                    $componentStates.App.State = $update.State
                                    $componentStates.App.Progress = $update.Progress
                                    $componentStates.App.Message = $update.Message
                                }
                            }
                            'Install' {
                                # Update component state for installation
                                if ($update.Component -eq 'Config') {
                                    $componentStates.Config.State = $update.State
                                    $componentStates.Config.Progress = $update.Progress
                                    $componentStates.Config.Message = $update.Message
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Config install state: $($update.State), Progress: $($update.Progress)" -Level "DEBUG"
                                } elseif ($update.Component -eq 'App') {
                                    $componentStates.App.State = $update.State
                                    $componentStates.App.Progress = $update.Progress
                                    $componentStates.App.Message = $update.Message
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "App install state: $($update.State), Progress: $($update.Progress)" -Level "DEBUG"
                                }
                            }
                            'Verify' {
                                # Handle verification step - this is typically the last step
                                if ($update.Component -eq 'Config') {
                                    $componentStates.Config.State = 'Verifying'
                                    $componentStates.Config.Progress = $update.Progress
                                    $componentStates.Config.Message = $update.Message
                                } elseif ($update.Component -eq 'App') {
                                    $componentStates.App.State = 'Verifying'
                                    $componentStates.App.Progress = $update.Progress
                                    $componentStates.App.Message = $update.Message
                                }
                            }
                            'Miniserver' {
                                if ($componentStates.Miniservers.ContainsKey($update.IP)) {
                                    $componentStates.Miniservers[$update.IP].State = $update.State
                                    $componentStates.Miniservers[$update.IP].Progress = $update.Progress
                                    $componentStates.Miniservers[$update.IP].Message = $update.Message
                                    
                                    # Capture DNS errors
                                    if ($update.DNSError) {
                                        $componentStates.Miniservers[$update.IP].DNS = $update.DNSError
                                        $componentStates.Miniservers[$update.IP].Error = $update.DNSError
                                    }
                                }
                            }
                            'OperationProgress' {
                                # Handle detailed operation progress from progress reporter
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "$($update.Operation) - $($update.Status)" -Level "INFO"
                                
                                # Update tracking based on operation type
                                if ($update.Operation -match 'Miniserver Update \[(.*?)\]') {
                                    $msIP = $matches[1]
                                    
                                    if ($componentStates.Miniservers.ContainsKey($msIP)) {
                                        # Map progress reporter states to our states
                                        $state = switch ($update.Progress) {
                                            100 { 'Completed' }
                                            0 { if ($update.Status -match 'Failed|Error') { 'Failed' } else { 'Starting' } }
                                            default { 
                                                if ($update.CurrentOperation -match 'Updating|installing') { 'Updating' }
                                                elseif ($update.CurrentOperation -match 'reboot') { 'Polling' }
                                                else { 'InProgress' }
                                            }
                                        }
                                        
                                        $componentStates.Miniservers[$msIP].State = $state
                                        $componentStates.Miniservers[$msIP].Progress = $update.Progress
                                        $componentStates.Miniservers[$msIP].Message = $update.Status
                                        $componentStates.Miniservers[$msIP].CurrentOperation = $update.CurrentOperation
                                        $componentStates.Miniservers[$msIP].LastDetailedUpdate = Get-Date
                                    }
                                }
                            }
                            'Complete' {
                                $complete = $true
                            }
                        }
                    }
                }
                
                # Update toast every 5 seconds to reduce notification spam
                $timeSinceLastUpdate = (Get-Date) - $lastUpdate
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Time since last update: $($timeSinceLastUpdate.TotalSeconds) seconds" -Level "DEBUG"
                
                # Check if toast is already initialized to prevent re-initialization loop
                $toastInitialized = $Global:PersistentToastInitialized -eq $true
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Toast initialized state: $toastInitialized, Global flag: $($Global:PersistentToastInitialized)" -Level "DEBUG"
                
                if ($timeSinceLastUpdate -gt [TimeSpan]::FromSeconds(5)) {
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Triggering toast update (5 second threshold met)" -Level "DEBUG"
                    # Calculate overall progress
                    $totalProgress = 0
                    $activeComponents = 0
                    
                    if ($WorkflowDefinition.ConfigUpdate) {
                        $totalProgress += $componentStates.Config.Progress
                        $activeComponents++
                    }
                    
                    if ($WorkflowDefinition.AppUpdate) {
                        $totalProgress += $componentStates.App.Progress
                        $activeComponents++
                    }
                    
                    # Calculate miniserver progress
                    if ($componentStates.Miniservers.Count -gt 0) {
                        $msProgress = 0
                        $msActive = 0
                        $msUpdating = 0
                        $msFailed = @()
                        
                        foreach ($msState in $componentStates.Miniservers.GetEnumerator()) {
                            $msProgress += $msState.Value.Progress
                            if ($msState.Value.State -ne 'Pending') {
                                $msActive++
                            }
                            if ($msState.Value.State -eq 'Updating' -or $msState.Value.State -eq 'Polling') {
                                $msUpdating++
                            }
                            if ($msState.Value.State -eq 'Failed' -or $msState.Value.Error) {
                                $msFailed += $msState.Key
                            }
                        }
                        
                        if ($componentStates.Miniservers.Count -gt 0) {
                            $totalProgress += ($msProgress / $componentStates.Miniservers.Count)
                            $activeComponents++
                        }
                    }
                    
                    if ($activeComponents -gt 0) {
                        $overallProgress = [Math]::Round($totalProgress / $activeComponents, 0)
                    } else {
                        $overallProgress = 0
                    }
                    
                    # Build status text
                    $statusParts = @()
                    
                    if ($componentStates.Config.State -ne 'Pending') {
                        $statusParts += "Config: $($componentStates.Config.State)"
                    }
                    
                    if ($componentStates.App.State -ne 'Pending') {
                        $statusParts += "App: $($componentStates.App.State)"
                    }
                    
                    if ($msUpdating -gt 0) {
                        $statusParts += "MS: $msUpdating 🔄"
                    }
                    
                    if ($msFailed.Count -gt 0) {
                        # Add failed miniservers to status
                        $failedText = "❌ " + ($msFailed -join ", ")
                        $statusParts += $failedText
                    }
                    
                    $statusText = $statusParts -join " | "
                    
                    # Build detail text with current operations and errors
                    $detailParts = @()
                    
                    # Add Config status if active
                    if ($componentStates.Config.State -ne 'Pending' -and $componentStates.Config.State -ne 'Completed' -and $componentStates.Config.State -ne 'Installed') {
                        $configStatus = switch ($componentStates.Config.State) {
                            'Downloading' { "Config: Downloading... $($componentStates.Config.Progress)%" }
                            'Downloaded' { "Config: Download complete" }
                            'Installing' { "Config: Installing..." }
                            'Failed' { "Config: Failed âœ—" }
                            default { "Config: $($componentStates.Config.State)" }
                        }
                        $detailParts += $configStatus
                    }
                    
                    # Add App status if active
                    if ($componentStates.App.State -ne 'Pending' -and $componentStates.App.State -ne 'Completed' -and $componentStates.App.State -ne 'Installed') {
                        $appStatus = switch ($componentStates.App.State) {
                            'Downloading' { "App: Downloading... $($componentStates.App.Progress)%" }
                            'Downloaded' { "App: Download complete" }
                            'Installing' { "App: Installing..." }
                            'Failed' { "App: Failed âœ—" }
                            default { "App: $($componentStates.App.State)" }
                        }
                        $detailParts += $appStatus
                    }
                    
                    # Add miniserver details
                    foreach ($msState in $componentStates.Miniservers.GetEnumerator()) {
                        if ($msState.Value.CurrentOperation) {
                            # Show current detailed operation
                            $detailParts += "$($msState.Key): $($msState.Value.CurrentOperation)"
                        } elseif ($msState.Value.DNS) {
                            # Show DNS error
                            $detailParts += "$($msState.Key): $($msState.Value.DNS)"
                        } elseif ($msState.Value.State -ne 'Pending' -and $msState.Value.Message) {
                            # Show current message
                            $detailParts += "$($msState.Key): $($msState.Value.Message)"
                        }
                    }
                    
                    $detailText = if ($detailParts.Count -gt 0) {
                        $detailParts -join " | "
                    } else {
                        "Starting update process..."
                    }
                    
                    # Update toast with multiple progress bars
                    if (Get-Command New-BTProgressBar -ErrorAction SilentlyContinue) {
                        # Build updated progress bars
                        $progressBars = @()
                        
                        # Config progress bar
                        if ($WorkflowDefinition.ConfigUpdate) {
                            $configStatus = switch ($componentStates.Config.State) {
                                'Pending' { 'Waiting...' }
                                'Downloading' { "Downloading... $($componentStates.Config.Progress)%" }
                                'Downloaded' { "Download complete" }
                                'Installing' { "Installing..." }
                                'Installed' { 
                                    if ($componentStates.Config.Duration) {
                                        "Completed âœ“ ($($componentStates.Config.Duration))"
                                    } else {
                                        'Completed âœ“'
                                    }
                                }
                                'Completed' { 
                                    if ($componentStates.Config.Duration) {
                                        "Completed âœ“ ($($componentStates.Config.Duration))"
                                    } else {
                                        'Completed âœ“'
                                    }
                                }
                                'Failed' { 'Failed âœ—' }
                                default { $componentStates.Config.Message }
                            }
                            $progressBars += New-BTProgressBar -Title "Loxone Config" -Status $configStatus -Value ($componentStates.Config.Progress / 100)
                        }
                        
                        # App progress bar
                        if ($WorkflowDefinition.AppUpdate) {
                            $appStatus = switch ($componentStates.App.State) {
                                'Pending' { 'Waiting...' }
                                'Downloading' { "Downloading... $($componentStates.App.Progress)%" }
                                'Downloaded' { "Download complete" }
                                'Installing' { "Installing..." }
                                'Installed' { 
                                    if ($componentStates.App.Duration) {
                                        "Completed âœ“ ($($componentStates.App.Duration))"
                                    } else {
                                        'Completed âœ“'
                                    }
                                }
                                'Completed' { 
                                    if ($componentStates.App.Duration) {
                                        "Completed âœ“ ($($componentStates.App.Duration))"
                                    } else {
                                        'Completed âœ“'
                                    }
                                }
                                'Failed' { 'Failed âœ—' }
                                default { $componentStates.App.Message }
                            }
                            $progressBars += New-BTProgressBar -Title "Loxone App" -Status $appStatus -Value ($componentStates.App.Progress / 100)
                        }
                        
                        # Miniserver progress bar
                        if ($componentStates.Miniservers.Count -gt 0) {
                            # Calculate MS progress and status
                            $msCompleted = ($componentStates.Miniservers.Values | Where-Object { $_.State -in 'Completed', 'Failed' }).Count
                            $msTitle = "Miniservers ($msCompleted/$($componentStates.Miniservers.Count))"
                            
                            # Build status line with symbols
                            $statusParts = @()
                            $stateGroups = $componentStates.Miniservers.Values | Group-Object State
                            
                            foreach ($group in $stateGroups) {
                                $symbol = switch ($group.Name) {
                                    'Checking' { '🔍' }
                                    'Updating' { '🔄' }
                                    'Polling' { '🚀' }
                                    'Completed' { 'âœ“' }
                                    'Failed' { 'âœ—' }
                                    default { '⏳' }
                                }
                                $statusParts += "$($group.Count) $symbol"
                            }
                            
                            # Only show symbols with counters, no IPs in progress bar
                            $msStatusText = $statusParts -join ' | '
                            
                            $msOverallProgress = if ($componentStates.Miniservers.Count -gt 0) {
                                ($componentStates.Miniservers.Values.Progress | Measure-Object -Average).Average / 100
                            } else { 0 }
                            
                            $progressBars += New-BTProgressBar -Title $msTitle -Status $msStatusText -Value $msOverallProgress
                        }
                        
                        # Update the toast notification using ONLY data binding
                        # CRITICAL: We must use the SAME dataframe object that was bound during initialization
                        # Creating a new hashtable will break the binding and cause auto-dismissal
                        
                        # Check if we have the global persistent toast data
                        if (-not $Global:PersistentToastData) {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "WARNING: PersistentToastData not found at update time, creating new (this may cause notification loop!)" -Level "WARN"
                            # If not exists, we need to create it (but this shouldn't happen in normal flow)
                            $Global:PersistentToastData = @{
                                statusMessage = $detailText
                                configStatus = 'Waiting...'
                                configProgress = 0.0
                                appStatus = 'Waiting...'
                                appProgress = 0.0
                                MiniserversTitle = "Miniservers ($completedMS/$totalMS)"
                                msCompleted = $completedMS
                                msStatus = 'Waiting...'
                                msProgress = 0.0
                            }
                        }
                        
                        # Update the EXISTING dataframe - DO NOT create a new one!
                        $updateData = $Global:PersistentToastData
                        $updateData.statusMessage = $detailText
                        $updateData.MiniserversTitle = "Miniservers ($completedMS/$totalMS)"
                        $updateData.msCompleted = $completedMS
                        
                        # Update component progress data - modify the existing dataframe
                        if ($componentStates.Config) {
                            $updateData.configStatus = switch ($componentStates.Config.State) {
                                'Downloading' { "Downloading... $($componentStates.Config.Progress)%" }
                                'Downloaded' { "Download complete" }
                                'Installing' { "Installing..." }
                                'Installed' { 'Completed âœ“' }
                                'Completed' { 'Completed âœ“' }
                                'Failed' { 'Failed âœ—' }
                                default { 'Waiting...' }
                            }
                            $updateData.configProgress = $componentStates.Config.Progress / 100.0
                        }
                        
                        if ($componentStates.App) {
                            $updateData.appStatus = switch ($componentStates.App.State) {
                                'Downloading' { "Downloading... $($componentStates.App.Progress)%" }
                                'Downloaded' { "Download complete" }
                                'Installing' { "Installing..." }
                                'Installed' { 'Completed âœ“' }
                                'Completed' { 'Completed âœ“' }
                                'Failed' { 'Failed âœ—' }
                                default { 'Waiting...' }
                            }
                            $updateData.appProgress = $componentStates.App.Progress / 100.0
                        }
                        
                        # Update miniserver progress data
                        if ($componentStates.Miniservers.Count -gt 0) {
                            $msCompleted = ($componentStates.Miniservers.Values | Where-Object { $_.State -in 'Completed', 'Failed' }).Count
                            $updateData.msCompleted = $msCompleted
                            $updateData.MiniserversTitle = "Miniservers ($msCompleted/$($componentStates.Miniservers.Count))"
                            
                            # Build status line with symbols
                            $statusParts = @()
                            $stateGroups = $componentStates.Miniservers.Values | Group-Object State
                            
                            foreach ($group in $stateGroups) {
                                $symbol = switch ($group.Name) {
                                    'Checking' { '🔍' }
                                    'Updating' { '🔄' }
                                    'Polling' { '🚀' }
                                    'Completed' { 'âœ“' }
                                    'Failed' { 'âœ—' }
                                    default { '⏳' }
                                }
                                $statusParts += "$($group.Count) $symbol"
                            }
                            
                            $updateData.msStatus = $statusParts -join ' | '
                            $updateData.msProgress = if ($componentStates.Miniservers.Count -gt 0) {
                                ($componentStates.Miniservers.Values.Progress | Measure-Object -Average).Average / 100.0
                            } else { 0.0 }
                        }
                        
                        # Get AppId for update
                        $appId = $null
                        if (Get-Command Get-LoxoneToastAppId -ErrorAction SilentlyContinue) {
                            $appId = Get-LoxoneToastAppId
                        }
                        
                        # Send toast update request to main thread (avoid COM threading issues)
                        try {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Sending toast update request to main thread - DataBinding keys: $($updateData.Keys -join ', ')" -Level "DEBUG"
                            
                            # Create a shallow copy of the data to avoid threading issues
                            # Don't use Clone() as it's not available on all dictionary types
                            $dataCopy = @{}
                            foreach ($key in $updateData.Keys) {
                                $dataCopy[$key] = $updateData[$key]
                            }
                            
                            # Send update request to main thread via ProgressQueue
                            $toastUpdateRequest = @{
                                Type = 'UpdateToast'
                                Data = $dataCopy
                                AppId = $appId
                            }
                            
                            [void]$Pipeline.ProgressQueue.Enqueue($toastUpdateRequest)
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Toast update request sent to main thread" -Level "DEBUG"
                        } catch {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Failed to send toast update request: $_" -Level "WARN"
                        }
                    }
                    
                    $lastUpdate = Get-Date
                }
                
                Start-Sleep -Milliseconds 500
            }
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Progress worker completed" -Level "INFO"
            
        } catch {
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Error in progress worker: $_" -Level "ERROR"
            throw
        }
    }
    
    $job = Start-ThreadJob -ThrottleLimit 20 -ScriptBlock $progressScript -ArgumentList @(
        $Pipeline,
        $WorkflowDefinition,
        $PSScriptRoot,
        $Global:LogFile
    )
    
    if ($job) {
        Add-Member -InputObject $job -MemberType NoteProperty -Name "Name" -Value "ProgressWorker" -Force
    }
    
    return $job
}
#>

function Start-ComponentWorker {
    param([hashtable]$Pipeline, [string]$Component, [hashtable]$UpdateInfo)
    
    Write-Log "[Start-ComponentWorker] Creating $Component worker to handle all steps" -Level "INFO"
    
    $componentScript = {
        param($Pipeline, $Component, $UpdateInfo, $ModulePath, $LogFile)
        
        # Mark this as a parallel worker thread
        $env:LOXONE_PARALLEL_WORKER = "1"
        
        # Set global reference to progress queue for Update-PersistentToast to use
        $Global:WorkerProgressQueue = $Pipeline.ProgressQueue
        
        # Define Write-WorkerLog inline for this worker
        function Write-WorkerLog {
            param(
                [System.Collections.Concurrent.ConcurrentQueue[hashtable]]$LogQueue,
                [string]$WorkerName,
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            if (-not $LogQueue) { return }
            
            $logEntry = @{
                Timestamp = Get-Date
                Worker = $WorkerName
                Message = $Message
                Level = $Level
            }
            
            [void]$LogQueue.Enqueue($logEntry)
        }
        
        try {
            # Import modules and set globals in this thread context
            Import-Module (Join-Path $ModulePath "LoxoneUtils.psd1") -Force
            $Global:LogFile = $LogFile
            
            # Apply TLS settings for Loxone compatibility
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls13
            } catch {
                # Fallback without TLS 1.3 if not supported
                try {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                } catch {
                    # Last resort - at least TLS 1.2
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                }
            }
            
            # Initialize CRC32 type for this worker thread
            if (Get-Command Initialize-CRC32Type -ErrorAction SilentlyContinue) {
                Initialize-CRC32Type
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "CRC32 type initialized" -Level "INFO"
            }
            
            # Create progress reporter for this worker
            $progressReporter = $null
            if (Get-Command New-ProgressReporter -ErrorAction SilentlyContinue) {
                $progressReporter = New-ProgressReporter -Context 'Parallel' -Pipeline $Pipeline -WorkerName "$Component Download Worker"
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Progress reporter created" -Level "DEBUG"
            }
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Starting $Component update process" -Level "INFO"
            
            # Get step info from pipeline mapping
            $stepInfo = $null
            if ($Pipeline.StepMapping) {
                $stepKey = "${Component}Download"
                $stepInfo = $Pipeline.StepMapping[$stepKey]
                if ($stepInfo) {
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Using step info: $($stepInfo.StepNumber)/$($stepInfo.TotalSteps) - $($stepInfo.StepName)" -Level "DEBUG"
                }
            }
            
            # Send initial progress with step info
            $progressUpdate = @{
                Type = 'Download'
                Component = $Component
                State = 'Downloading'
                Progress = 0
                Message = if ($stepInfo) { "$($stepInfo.StepNumber)/$($stepInfo.TotalSteps) $($stepInfo.StepName)" } else { "Starting $Component download..." }
            }
            if ($stepInfo) {
                $progressUpdate.StepNumber = $stepInfo.StepNumber
                $progressUpdate.TotalSteps = $stepInfo.TotalSteps
                $progressUpdate.StepName = $stepInfo.StepName
            }
            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
            
            # Simulate download with progress updates
            $totalSize = $UpdateInfo.FileSize
            if (-not $totalSize) { $totalSize = 100000000 } # 100MB default
            
            $downloaded = 0
            $chunkSize = [Math]::Min(1024 * 1024, $totalSize / 10) # 1MB chunks or 10% of total
            
            # Use the pre-configured download path from DownloadInfo
            if ($UpdateInfo.OutputPath) {
                # Use the pre-configured path (should be from WorkflowContext.DownloadDir)
                $outputPath = $UpdateInfo.OutputPath
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Using configured path: $outputPath" -Level "DEBUG"
            } else {
                # Fallback: Create output path using the standard Downloads folder
                $scriptRoot = if ($Global:ScriptSaveFolder) { $Global:ScriptSaveFolder } else { $PSScriptRoot }
                
                # Determine if we should use local Downloads folder or temp
                $useLocalDownloads = $false
                if ($scriptRoot -and (Test-Path $scriptRoot)) {
                    # Check if we're running from UpdateLoxone folder (not Program Files)
                    if ($scriptRoot -notmatch 'Program Files') {
                        $downloadsPath = Join-Path $scriptRoot 'Downloads'
                        if (-not (Test-Path $downloadsPath)) {
                            New-Item -ItemType Directory -Path $downloadsPath -Force | Out-Null
                        }
                        $useLocalDownloads = $true
                    }
                }
                
                # Determine file extension from URL or use exe for App
                $fileExtension = if ($UpdateInfo.Url) {
                    $urlFileName = [System.IO.Path]::GetFileName([System.Uri]::new($UpdateInfo.Url).LocalPath)
                    if ($urlFileName -match '\.(\w+)$') { $matches[1] } else { 'exe' }
                } else { 'exe' }
                
                # Build output path
                if ($useLocalDownloads) {
                    # Use Downloads folder with proper filename from URL
                    $fileName = if ($UpdateInfo.Url) {
                        [System.IO.Path]::GetFileName([System.Uri]::new($UpdateInfo.Url).LocalPath)
                    } else {
                        "$Component`_$(Get-Date -Format 'yyyyMMddHHmmss').$fileExtension"
                    }
                    $outputPath = Join-Path $downloadsPath $fileName
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Using local Downloads folder: $outputPath" -Level "DEBUG"
                } else {
                    # Fallback to temp folder (when running from Program Files)
                    $outputPath = Join-Path $env:TEMP "$Component`_$(Get-Date -Format 'yyyyMMddHHmmss').$fileExtension"
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Using Windows temp folder: $outputPath" -Level "DEBUG"
                }
            }
            
            # Perform actual download using Invoke-LoxoneDownload
            if (Get-Command Invoke-LoxoneDownload -ErrorAction SilentlyContinue) {
                # Send initial download starting update
                $progressUpdate = @{
                    Type = 'Download'
                    Component = $Component
                    State = 'Downloading'
                    Progress = 0
                    Message = "Starting $Component download..."
                }
                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                
                # Invoke-LoxoneDownload will call Update-PersistentToast with real progress
                # which will be intercepted and sent through the queue
                $downloadResult = Invoke-LoxoneDownload `
                    -Url $UpdateInfo.Url `
                    -DestinationPath $outputPath `
                    -ActivityName "Downloading $Component" `
                    -ExpectedCRC32 $UpdateInfo.ExpectedCRC32 `
                    -ExpectedFilesize $UpdateInfo.FileSize
                
                if ($downloadResult) {
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "$Component download completed successfully" -Level "INFO"
                    
                    # Send download completion progress
                    $progressUpdate = @{
                        Type = 'Download'
                        Component = $Component
                        State = 'Downloaded'
                        Progress = 100
                        Message = "Download complete"
                    }
                    [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                    
                    # Now continue with installation in the same worker
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Proceeding with $Component installation" -Level "INFO"
                    
                    # Handle Config vs App installation differently
                    if ($Component -eq 'Config') {
                        # Config needs extraction first
                        $extractStepInfo = $Pipeline.StepMapping.ConfigExtract
                        if ($extractStepInfo) {
                            $extractProgress = @{
                                Type = 'Extract'
                                Component = 'Config'
                                State = 'Extracting'
                                Progress = 0
                                Message = "Extracting installer..."
                                StepNumber = $extractStepInfo.StepNumber
                                TotalSteps = $extractStepInfo.TotalSteps
                                StepName = $extractStepInfo.StepName
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($extractProgress)
                        }
                        
                        # Extract ZIP file
                        $extractPath = Join-Path $env:TEMP "LoxoneConfig_Extract_$(Get-Date -Format 'yyyyMMddHHmmss')"
                        Expand-Archive -Path $outputPath -DestinationPath $extractPath
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Extracted Config to $extractPath" -Level "INFO"
                        
                        # Find installer
                        $installer = Get-ChildItem -Path $extractPath -Filter "*.exe" -Recurse | Select-Object -First 1
                        if ($installer) {
                            # Send install progress
                            $installStepInfo = $Pipeline.StepMapping.ConfigInstall
                            if ($installStepInfo) {
                                $installProgress = @{
                                    Type = 'Install'
                                    Component = 'Config'
                                    State = 'Installing'
                                    Progress = 0
                                    Message = "Installing..."
                                    StepNumber = $installStepInfo.StepNumber
                                    TotalSteps = $installStepInfo.TotalSteps
                                    StepName = $installStepInfo.StepName
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($installProgress)
                            }
                            
                            # Install Config
                            $installResult = Start-LoxoneUpdateInstaller -InstallerPath $installer.FullName -InstallMode "VERYSILENT"
                            if ($installResult.Success) {
                                if ($installResult.RestartRequired) {
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Config installation completed successfully but requires system restart (exit code: $($installResult.ExitCode))" -Level "WARN"
                                } else {
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Config installation completed successfully" -Level "INFO"
                                }
                                
                                # Send verify progress
                                $verifyStepInfo = $Pipeline.StepMapping.ConfigVerify
                                if ($verifyStepInfo) {
                                    $verifyProgress = @{
                                        Type = 'Verify'
                                        Component = 'Config'
                                        State = 'Verifying'
                                        Progress = 0
                                        Message = "Verifying installation..."
                                        StepNumber = $verifyStepInfo.StepNumber
                                        TotalSteps = $verifyStepInfo.TotalSteps
                                        StepName = $verifyStepInfo.StepName
                                    }
                                    [void]$Pipeline.ProgressQueue.Enqueue($verifyProgress)
                                }
                                
                                # Mark complete with Verify type to trigger final status
                                $completeMsg = if ($installResult.RestartRequired) { "Config installed successfully (restart required)" } else { "Config installed successfully" }
                                $completeProgress = @{
                                    Type = 'Verify'
                                    Component = 'Config'
                                    State = 'Completed'
                                    Progress = 100
                                    Message = $completeMsg
                                    InitialVersion = $UpdateInfo.InitialVersion
                                    RestartRequired = [bool]$installResult.RestartRequired
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($completeProgress)
                            } else {
                                throw "Config installation failed with exit code: $($installResult.ExitCode)"
                            }
                        } else {
                            throw "No installer found in extracted Config files"
                        }
                        
                        # Clean up extraction folder
                        if (Test-Path $extractPath) {
                            Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                        }
                        
                    } elseif ($Component -eq 'App') {
                        # App installs directly from EXE
                        $installStepInfo = $Pipeline.StepMapping.AppInstall
                        if ($installStepInfo) {
                            $installProgress = @{
                                Type = 'Install'
                                Component = 'App'
                                State = 'Installing'
                                Progress = 0
                                Message = "Installing..."
                                StepNumber = $installStepInfo.StepNumber
                                TotalSteps = $installStepInfo.TotalSteps
                                StepName = $installStepInfo.StepName
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($installProgress)
                        }
                        
                        # Install App
                        $installResult = Start-LoxoneForWindowsInstaller -InstallerPath $outputPath -InstallMode "SILENT"
                        if ($installResult.Success) {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "App installation completed successfully" -Level "INFO"
                            
                            # Wait for installation to complete before fixing icons
                            Start-Sleep -Seconds 2

                            # Fix shortcut icons (runs silently, no separate progress step)
                            try {
                                $exePath = "${env:LOCALAPPDATA}\Programs\kerberos\Loxone.exe"
                                if (Test-Path $exePath) {
                                    # Fix Start Menu shortcut
                                    $startMenuShortcut = "${env:APPDATA}\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"
                                    if (Test-Path $startMenuShortcut) {
                                        $shell = New-Object -ComObject WScript.Shell
                                        $shortcut = $shell.CreateShortcut($startMenuShortcut)
                                        $shortcut.TargetPath = $exePath
                                        $shortcut.Arguments = "--disable-gpu --disable-software-rasterizer"
                                        $shortcut.IconLocation = "$exePath,0"
                                        $shortcut.Save()
                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Fixed Start Menu shortcut" -Level "INFO"
                                    }
                                    
                                    # Fix desktop shortcut
                                    $desktopShortcut = [System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'Loxone.lnk')
                                    if (Test-Path $desktopShortcut) {
                                        $shell = New-Object -ComObject WScript.Shell
                                        $shortcut = $shell.CreateShortcut($desktopShortcut)
                                        $shortcut.TargetPath = $exePath
                                        $shortcut.Arguments = "--disable-gpu --disable-software-rasterizer"
                                        $shortcut.IconLocation = "$exePath,0"
                                        $shortcut.Save()
                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Fixed desktop shortcut" -Level "INFO"
                                    }
                                }
                            } catch {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Worker" -Message "Failed to fix shortcuts: $_" -Level "WARN"
                            }
                            
                            # Send verify progress
                            $verifyStepInfo = $Pipeline.StepMapping.AppVerify
                            if ($verifyStepInfo) {
                                $verifyProgress = @{
                                    Type = 'Verify'
                                    Component = 'App'
                                    State = 'Verifying'
                                    Progress = 0
                                    Message = "Verifying installation..."
                                    StepNumber = $verifyStepInfo.StepNumber
                                    TotalSteps = $verifyStepInfo.TotalSteps
                                    StepName = $verifyStepInfo.StepName
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($verifyProgress)
                            }
                            
                            # Mark complete with Verify type to trigger final status
                            $completeProgress = @{
                                Type = 'Verify'
                                Component = 'App'
                                State = 'Completed'
                                Progress = 100
                                Message = "App installed successfully"
                                InitialVersion = $UpdateInfo.InitialVersion
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($completeProgress)
                        } else {
                            throw "App installation failed with exit code: $($installResult.ExitCode)"
                        }
                    }
                    
                    # Add download result
                    [void]$Pipeline.Results.Add(@{
                        Type = 'Download'
                        Component = $Component
                        Success = $true
                        FilePath = $outputPath
                    })
                    
                    # Add install result (since ComponentWorker handles both)
                    [void]$Pipeline.Results.Add(@{
                        Type = 'Install'
                        Component = $Component
                        Success = $true
                        Status = 'Completed'
                        Version = $UpdateInfo.TargetVersion
                        InitialVersion = $UpdateInfo.InitialVersion
                        RestartRequired = [bool]$installResult.RestartRequired
                    })
                } else {
                    throw "Download failed for $Component"
                }
            } else {
                # Fallback simulation for testing
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Using simulation mode (Invoke-LoxoneDownload not available)" -Level "WARN"
                
                for ($i = 0; $i -lt 10; $i++) {
                    $downloaded += $chunkSize
                    $percent = [Math]::Round(($downloaded / $totalSize) * 100, 0)
                    
                    $progressUpdate = @{
                        Type = 'Download'
                        Component = $Component
                        State = 'Downloading'
                        Progress = $percent
                        Message = "Downloading $Component... $percent%"
                    }
                    [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                    
                    Start-Sleep -Milliseconds 500
                }
                
                # Create dummy file
                "Dummy $Component content" | Out-File $outputPath
                
                # Queue for installation
                $installTask = @{
                    Type = 'Download'  # Signal that this is a download completion
                    Component = $Component
                    FilePath = $outputPath
                    Version = $UpdateInfo.TargetVersion
                }
                [void]$Pipeline.InstallQueue.Enqueue($installTask)
            }
            
        } catch {
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Error downloading $Component`: $_" -Level "ERROR"
            
            # Send failure progress
            $progressUpdate = @{
                Type = 'Download'
                Component = $Component
                State = 'Failed'
                Progress = 0
                Message = "Failed to download $Component`: $_"
            }
            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
            
            # Add to results
            [void]$Pipeline.Results.Add(@{
                Type = 'Download'
                Component = $Component
                Success = $false
                Error = $_.ToString()
            })
            
            throw
        }
    }
    
    $job = Start-ThreadJob -ThrottleLimit 20 -ScriptBlock $componentScript -ArgumentList @(
        $Pipeline,
        $Component,
        $UpdateInfo,
        $PSScriptRoot,
        $Global:LogFile
    )
    
    if ($job) {
        Add-Member -InputObject $job -MemberType NoteProperty -Name "Name" -Value "${Component}Worker" -Force
    }
    
    return $job
}

function Start-InstallWorker {
    param([hashtable]$Pipeline, [int]$MaxConcurrency, [array]$DownloadWorkers)
    
    Write-Log "[Start-InstallWorker] Creating install worker" -Level "INFO"
    
    # Count expected downloads to track completion
    $expectedDownloads = if ($DownloadWorkers) { $DownloadWorkers.Count } else { 0 }
    
    $installScript = {
        param($Pipeline, $MaxConcurrency, $ModulePath, $LogFile, $ExpectedDownloads)
        
        # Mark this as a parallel worker thread
        $env:LOXONE_PARALLEL_WORKER = "1"
        
        # Set global reference to progress queue for Update-PersistentToast to use
        $Global:WorkerProgressQueue = $Pipeline.ProgressQueue
        
        # Define Write-WorkerLog inline for this worker
        function Write-WorkerLog {
            param(
                [System.Collections.Concurrent.ConcurrentQueue[hashtable]]$LogQueue,
                [string]$WorkerName,
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            if (-not $LogQueue) { return }
            
            $logEntry = @{
                Timestamp = Get-Date
                Worker = $WorkerName
                Message = $Message
                Level = $Level
            }
            
            [void]$LogQueue.Enqueue($logEntry)
        }
        
        try {
            # Import modules and set globals in this thread context
            Import-Module (Join-Path $ModulePath "LoxoneUtils.psd1") -Force
            $Global:LogFile = $LogFile
            
            # Apply TLS settings for consistency
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls13
            } catch {
                try {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                } catch {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                }
            }
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Install worker started" -Level "INFO"
            
            # Monitor install queue
            $noWorkCount = 0
            $maxNoWorkCount = 60  # 30 seconds initial wait for downloads to complete
            $maxNoWorkCountAfterDownloads = 20  # 10 seconds after all downloads complete
            $completedDownloads = 0
            $downloadsCompleted = ($ExpectedDownloads -eq 0)
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Expecting $ExpectedDownloads downloads to complete" -Level "INFO"
            
            # Exit immediately if no downloads are expected
            if ($ExpectedDownloads -eq 0) {
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "No downloads expected, exiting" -Level "INFO"
                return
            }
            
            while ($noWorkCount -lt $maxNoWorkCount) {
                $installTask = $null
                
                # Check for download completion signals in the queue
                # Downloads will signal completion by adding entries to InstallQueue
                
                if ($Pipeline.InstallQueue.TryDequeue([ref]$installTask)) {
                    if ($installTask) {
                        $noWorkCount = 0  # Reset counter
                        
                        # Track completed downloads
                        if ($installTask.Type -eq 'Download') {
                            $completedDownloads++
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Received download completion signal $completedDownloads of $ExpectedDownloads for $($installTask.Component)" -Level "INFO"
                            
                            # Don't skip installation - downloads signal completion AND need installation
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Download complete for $($installTask.Component), proceeding with installation" -Level "INFO"
                            
                            # Continue to process the installation below
                        }
                        
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Installing $($installTask.Component)" -Level "INFO"
                        
                        # Get step info from pipeline mapping
                        $stepInfo = $null
                        if ($Pipeline.StepMapping) {
                            $stepKey = "$($installTask.Component)Install"
                            $stepInfo = $Pipeline.StepMapping[$stepKey]
                            if ($stepInfo) {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Using step info: $($stepInfo.StepNumber)/$($stepInfo.TotalSteps) - $($stepInfo.StepName)" -Level "DEBUG"
                            }
                        }
                        
                        # Send progress update with step info
                        $progressUpdate = @{
                            Type = 'Install'
                            Component = $installTask.Component
                            State = 'Installing'
                            Progress = 0
                            Message = if ($stepInfo) { "$($stepInfo.StepNumber)/$($stepInfo.TotalSteps) $($stepInfo.StepName)" } else { "Installing $($installTask.Component)..." }
                        }
                        if ($stepInfo) {
                            $progressUpdate.StepNumber = $stepInfo.StepNumber
                            $progressUpdate.TotalSteps = $stepInfo.TotalSteps
                            $progressUpdate.StepName = $stepInfo.StepName
                        }
                        [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                        
                        try {
                            # Perform installation based on component type
                            if ($installTask.Component -eq 'Config') {
                                # Send extract progress update
                                $extractStepInfo = $null
                                if ($Pipeline.StepMapping -and $Pipeline.StepMapping.ConfigExtract) {
                                    $extractStepInfo = $Pipeline.StepMapping.ConfigExtract
                                }
                                $extractProgress = @{
                                    Type = 'Extract'
                                    Component = 'Config'
                                    State = 'Extracting'
                                    Progress = 0
                                    Message = if ($extractStepInfo) { "$($extractStepInfo.StepNumber)/$($extractStepInfo.TotalSteps) $($extractStepInfo.StepName)" } else { "Extracting Config..." }
                                }
                                if ($extractStepInfo) {
                                    $extractProgress.StepNumber = $extractStepInfo.StepNumber
                                    $extractProgress.TotalSteps = $extractStepInfo.TotalSteps
                                    $extractProgress.StepName = $extractStepInfo.StepName
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($extractProgress)
                                
                                # Extract and install Config
                                # Extract the ZIP file
                                $extractPath = Join-Path $env:TEMP "LoxoneConfig_Extract_$(Get-Date -Format 'yyyyMMddHHmmss')"
                                try {
                                    # Use built-in Expand-Archive for better compatibility
                                    Expand-Archive -Path $installTask.FilePath -DestinationPath $extractPath
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Extracted $($installTask.Component) to $extractPath" -Level "INFO"
                                    
                                    # Send extract complete progress
                                    $extractProgress.Progress = 100
                                    $extractProgress.Message = if ($extractStepInfo) { "$($extractStepInfo.StepNumber)/$($extractStepInfo.TotalSteps) Extraction complete" } else { "Extraction complete" }
                                    [void]$Pipeline.ProgressQueue.Enqueue($extractProgress)
                                    
                                    # Find installer
                                    $installer = Get-ChildItem -Path $extractPath -Filter "*.exe" -Recurse | Select-Object -First 1
                                    
                                    if ($installer) {
                                        # Send install progress update for Config
                                        $installStepInfo = $null
                                        if ($Pipeline.StepMapping -and $Pipeline.StepMapping.ConfigInstall) {
                                            $installStepInfo = $Pipeline.StepMapping.ConfigInstall
                                        }
                                        $installProgress = @{
                                            Type = 'Install'
                                            Component = 'Config'
                                            State = 'Installing'
                                            Progress = 0
                                            Message = if ($installStepInfo) { "Installing..." } else { "Installing Config..." }
                                        }
                                        if ($installStepInfo) {
                                            $installProgress.StepNumber = $installStepInfo.StepNumber
                                            $installProgress.TotalSteps = $installStepInfo.TotalSteps
                                            $installProgress.StepName = $installStepInfo.StepName
                                        }
                                        [void]$Pipeline.ProgressQueue.Enqueue($installProgress)
                                        
                                        $installResult = Start-LoxoneUpdateInstaller -InstallerPath $installer.FullName -InstallMode "VERYSILENT"
                                        if (-not $installResult.Success) {
                                            throw "Installation failed with exit code: $($installResult.ExitCode)"
                                        }
                                        if ($installResult.RestartRequired) {
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Config installation requires system restart (exit code: $($installResult.ExitCode))" -Level "WARN"
                                        }
                                        
                                        # Send verify progress update for Config
                                        $verifyStepInfo = $null
                                        if ($Pipeline.StepMapping -and $Pipeline.StepMapping.ConfigVerify) {
                                            $verifyStepInfo = $Pipeline.StepMapping.ConfigVerify
                                        }
                                        $verifyProgress = @{
                                            Type = 'Verify'
                                            Component = 'Config'
                                            State = 'Verifying'
                                            Progress = 0
                                            Message = if ($verifyStepInfo) { "Verifying installation..." } else { "Verifying Config..." }
                                        }
                                        if ($verifyStepInfo) {
                                            $verifyProgress.StepNumber = $verifyStepInfo.StepNumber
                                            $verifyProgress.TotalSteps = $verifyStepInfo.TotalSteps
                                            $verifyProgress.StepName = $verifyStepInfo.StepName
                                        }
                                        [void]$Pipeline.ProgressQueue.Enqueue($verifyProgress)
                                    } else {
                                        throw "No installer executable found in extracted files"
                                    }
                                } catch {
                                    throw "Failed to extract Config: $_"
                                } finally {
                                    # Clean up extraction folder
                                    if (Test-Path $extractPath) {
                                        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                                    }
                                }
                            } elseif ($installTask.Component -eq 'App') {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Starting App installation from: $($installTask.FilePath)" -Level "INFO"
                                
                                # Check if file exists
                                if (Test-Path $installTask.FilePath) {
                                    $fileInfo = Get-Item $installTask.FilePath
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Installer file exists: Size=$($fileInfo.Length) bytes, LastWrite=$($fileInfo.LastWriteTime)" -Level "INFO"
                                } else {
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "ERROR: Installer file not found at: $($installTask.FilePath)" -Level "ERROR"
                                }
                                
                                # Install App MSI
                                if (Get-Command Start-LoxoneForWindowsInstaller -ErrorAction SilentlyContinue) {
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Calling Start-LoxoneForWindowsInstaller with InstallMode='SILENT'..." -Level "INFO"
                                    $installResult = Start-LoxoneForWindowsInstaller -InstallerPath $installTask.FilePath -InstallMode "SILENT"
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Start-LoxoneForWindowsInstaller completed. Success: $($installResult.Success), ExitCode: $($installResult.ExitCode), TimedOut: $($installResult.TimedOut)" -Level "INFO"
                                    
                                    if (-not $installResult.Success) {
                                        throw "App installation failed with exit code: $($installResult.ExitCode)"
                                    }
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "App installation completed successfully (Exit code: $($installResult.ExitCode))" -Level "INFO"
                                    
                                    # Wait a moment for installation to complete file operations
                                    Start-Sleep -Seconds 2
                                    
                                    # Fix shortcut icons after successful installation
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Attempting to fix App shortcut icons after 2-second delay..." -Level "INFO"
                                    try {
                                        # Find the Loxone App executable directly
                                        $exePath = $null
                                        
                                        # Check common installation paths (both system and user)
                                        $possiblePaths = @(
                                            # The actual location where the App installs
                                            "${env:LOCALAPPDATA}\Programs\kerberos\Loxone.exe",
                                            # System-wide installations
                                            "C:\Program Files\Loxone\Loxone.exe",
                                            "C:\Program Files (x86)\Loxone\Loxone.exe",
                                            "${env:ProgramFiles}\Loxone\Loxone.exe",
                                            "${env:ProgramFiles(x86)}\Loxone\Loxone.exe",
                                            # User installations (AppData)
                                            "${env:LOCALAPPDATA}\Loxone\Loxone.exe",
                                            "${env:LOCALAPPDATA}\Programs\Loxone\Loxone.exe",
                                            "${env:APPDATA}\Loxone\Loxone.exe",
                                            # User installations (per-user Program Files)
                                            "${env:USERPROFILE}\AppData\Local\Programs\Loxone\Loxone.exe",
                                            "${env:USERPROFILE}\AppData\Local\Loxone\Loxone.exe"
                                        )
                                        
                                        # Log what we're checking
                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Searching for Loxone.exe in $($possiblePaths.Count) common paths..." -Level "INFO"
                                        
                                        foreach ($path in $possiblePaths) {
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Checking: '$path'" -Level "DEBUG"
                                            if (Test-Path $path) {
                                                $exePath = $path
                                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found Loxone executable at: '$exePath'" -Level "INFO"
                                                break
                                            }
                                        }
                                        
                                        # If not found in common paths, try searching Program Files directories
                                        if (-not $exePath) {
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Not found in common paths, searching Program Files..." -Level "DEBUG"
                                            
                                            # Search in Program Files
                                            $searchPaths = @("${env:ProgramFiles}", "${env:ProgramFiles(x86)}")
                                            foreach ($searchPath in $searchPaths) {
                                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Searching in: '$searchPath'" -Level "DEBUG"
                                                if (Test-Path $searchPath) {
                                                    try {
                                                        # First try to find any Loxone folder
                                                        $loxoneFolders = Get-ChildItem -Path $searchPath -Directory -Filter "*Loxone*" -ErrorAction SilentlyContinue
                                                        foreach ($folder in $loxoneFolders) {
                                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found Loxone folder: '$($folder.FullName)'" -Level "DEBUG"
                                                            
                                                            # Check for various possible exe names
                                                            $exeNames = @("Loxone.exe", "LoxoneApp.exe", "Loxone for Windows.exe", "*.exe")
                                                            foreach ($exeName in $exeNames) {
                                                                $exeSearch = Get-ChildItem -Path $folder.FullName -Filter $exeName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                                                                if ($exeSearch) {
                                                                    $exePath = $exeSearch.FullName
                                                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found executable: '$exePath'" -Level "INFO"
                                                                    break
                                                                }
                                                            }
                                                            if ($exePath) { break }
                                                        }
                                                    } catch {
                                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error searching in '$searchPath': $_" -Level "WARN"
                                                    }
                                                }
                                                if ($exePath) { break }
                                            }
                                        }
                                        
                                        # Last resort - check if the installer created any shortcuts and read the target from them
                                        if (-not $exePath) {
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Trying to find executable from shortcuts..." -Level "DEBUG"
                                            
                                            $userProfile = [Environment]::GetFolderPath("UserProfile")
                                            $shortcutPaths = @(
                                                (Join-Path $userProfile "Desktop\Loxone.lnk"),
                                                (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"),
                                                "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"
                                            )
                                            
                                            foreach ($shortcutPath in $shortcutPaths) {
                                                if (Test-Path $shortcutPath) {
                                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found shortcut at: '$shortcutPath'" -Level "DEBUG"
                                                    try {
                                                        $shell = New-Object -ComObject WScript.Shell
                                                        $shortcut = $shell.CreateShortcut($shortcutPath)
                                                        $targetPath = $shortcut.TargetPath
                                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                                                        
                                                        if ($targetPath -and (Test-Path $targetPath)) {
                                                            $exePath = $targetPath
                                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found executable from shortcut target: '$exePath'" -Level "INFO"
                                                            break
                                                        }
                                                    } catch {
                                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error reading shortcut: $_" -Level "WARN"
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if ($exePath) {
                                            # Build shortcut paths - check multiple possible locations
                                            $userProfile = [Environment]::GetFolderPath("UserProfile")
                                            $possibleShortcutPaths = @(
                                                (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"),
                                                (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone\Loxone.lnk"),
                                                "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone.lnk",
                                                "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone\Loxone.lnk"
                                            )
                                            
                                            $fixedStartMenu = $false
                                            foreach ($shortcutPath in $possibleShortcutPaths) {
                                                if (Test-Path $shortcutPath) {
                                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found Start Menu shortcut at: '$shortcutPath'" -Level "INFO"
                                                    try {
                                                        $shell = New-Object -ComObject WScript.Shell
                                                        $shortcut = $shell.CreateShortcut($shortcutPath)
                                                        
                                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Current icon: '$($shortcut.IconLocation)'" -Level "DEBUG"
                                                        
                                                        # Update shortcut properties
                                                        $shortcut.TargetPath = $exePath
                                                        $shortcut.Arguments = "--disable-gpu --disable-software-rasterizer"
                                                        $shortcut.WorkingDirectory = Split-Path $exePath -Parent
                                                        $shortcut.IconLocation = "$exePath,0"
                                                        $shortcut.Description = "Loxone Smart Home App"
                                                        $shortcut.Save()
                                                        
                                                        # Release COM objects
                                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                                                        
                                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Successfully fixed Start Menu shortcut icon" -Level "INFO"
                                                        $fixedStartMenu = $true
                                                        break
                                                    } catch {
                                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error fixing Start Menu shortcut: $_" -Level "WARN"
                                                    }
                                                }
                                            }
                                            
                                            if (-not $fixedStartMenu) {
                                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "No Start Menu shortcut found in checked locations" -Level "WARN"
                                            }
                                            
                                            # Also fix desktop shortcut if it exists
                                            $desktopPath = [Environment]::GetFolderPath("Desktop")
                                            $desktopShortcut = Join-Path $desktopPath "Loxone.lnk"
                                            
                                            if (Test-Path $desktopShortcut) {
                                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Found desktop shortcut" -Level "INFO"
                                                try {
                                                    $shell2 = New-Object -ComObject WScript.Shell
                                                    $desktop = $shell2.CreateShortcut($desktopShortcut)
                                                    
                                                    $desktop.TargetPath = $exePath
                                                    $desktop.Arguments = "--disable-gpu --disable-software-rasterizer"
                                                    $desktop.WorkingDirectory = Split-Path $exePath -Parent
                                                    $desktop.IconLocation = "$exePath,0"
                                                    $desktop.Description = "Loxone Smart Home App"
                                                    $desktop.Save()
                                                    
                                                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($desktop) | Out-Null
                                                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell2) | Out-Null
                                                    
                                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Successfully fixed desktop shortcut icon" -Level "INFO"
                                                } catch {
                                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error fixing desktop shortcut: $_" -Level "WARN"
                                                }
                                            } else {
                                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "No desktop shortcut found" -Level "DEBUG"
                                            }
                                        } else {
                                            # Log detailed information about what was checked
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "WARNING: Could not find Loxone executable after checking:" -Level "WARN"
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "  - $($possiblePaths.Count) common installation paths" -Level "WARN"
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "  - Program Files directories recursively" -Level "WARN"
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "  - Desktop and Start Menu shortcuts" -Level "WARN"
                                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Icon fixing skipped - executable not found" -Level "WARN"
                                        }
                                        
                                        # Send progress update for verification
                                        $verifyStepInfo = $null
                                        if ($Pipeline.StepMapping -and $Pipeline.StepMapping.AppVerify) {
                                            $verifyStepInfo = $Pipeline.StepMapping.AppVerify
                                        }
                                        $verifyProgress = @{
                                            Type = 'Verify'
                                            Component = 'App'
                                            State = 'Verifying'
                                            Progress = 0
                                            Message = if ($verifyStepInfo) { "Verifying installation..." } else { "Verifying..." }
                                        }
                                        if ($verifyStepInfo) {
                                            $verifyProgress.StepNumber = $verifyStepInfo.StepNumber
                                            $verifyProgress.TotalSteps = $verifyStepInfo.TotalSteps
                                            $verifyProgress.StepName = $verifyStepInfo.StepName
                                        }
                                        [void]$Pipeline.ProgressQueue.Enqueue($verifyProgress)
                                    } catch {
                                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error during icon fixing: $_" -Level "WARN"
                                    }
                                } else {
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Start-LoxoneForWindowsInstaller not found - skipping App installation" -Level "WARNING"
                                }
                            }
                            
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Preparing to send completion signal for $($installTask.Component)" -Level "INFO"
                            
                            # Send completion with error handling
                            $progressUpdate = @{
                                Type = 'Install'
                                Component = $installTask.Component
                                State = 'Installed'
                                Progress = 100
                                Message = "$($installTask.Component) installed successfully"
                            }
                            
                            try {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Attempting to enqueue completion progress update for $($installTask.Component)" -Level "INFO"
                                $Pipeline.ProgressQueue.Enqueue($progressUpdate)
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Successfully enqueued completion progress update for $($installTask.Component)" -Level "INFO"
                            } catch {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error enqueueing progress update: $_" -Level "ERROR"
                            }
                            
                            # Add to results with error handling
                            try {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Attempting to add installation result for $($installTask.Component)" -Level "INFO"
                                $Pipeline.Results.Add(@{
                                    Type = 'Install'
                                    Component = $installTask.Component
                                    Success = $true
                                    Status = 'Completed'
                                    Version = $installTask.Version
                                })
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Successfully added installation result for $($installTask.Component), version: $($installTask.Version)" -Level "INFO"
                            } catch {
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error adding result: $_" -Level "ERROR"
                            }
                            
                        } catch {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Failed to install $($installTask.Component): $_" -Level "ERROR"
                            
                            # Send failure
                            $progressUpdate = @{
                                Type = 'Install'
                                Component = $installTask.Component
                                State = 'Failed'
                                Progress = 0
                                Message = "Failed to install $($installTask.Component)"
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            # Add to results
                            [void]$Pipeline.Results.Add(@{
                                Type = 'Install'
                                Component = $installTask.Component
                                Success = $false
                                Status = 'Failed'
                                Error = $_.ToString()
                            })
                        }
                        
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Completed processing $($installTask.Component), continuing to check for more work..." -Level "INFO"
                        
                        # Check if all expected downloads have been processed
                        if ($completedDownloads -ge $ExpectedDownloads) {
                            $downloadsCompleted = $true
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "All $ExpectedDownloads downloads have been installed" -Level "INFO"
                        }
                        
                        # Don't exit yet - there might be more install tasks in the queue
                        # Only exit when queue is empty AND all downloads are complete
                    }
                } else {
                    # No work available
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Install queue empty. Downloads installed: $completedDownloads/$ExpectedDownloads, NoWorkCount: $noWorkCount/$maxNoWorkCount" -Level "DEBUG"
                    
                    if ($downloadsCompleted) {
                        # All downloads are done and queue is empty, we can exit
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "No more work and all downloads installed, exiting" -Level "INFO"
                        break
                    }
                    $noWorkCount++
                    
                    # After downloads complete, use shorter timeout
                    if ($downloadsCompleted -and $noWorkCount -ge $maxNoWorkCountAfterDownloads) {
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Timeout waiting for install tasks after downloads completed" -Level "INFO"
                        break
                    }
                    
                    Start-Sleep -Milliseconds 500
                }
            }
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Install worker completed" -Level "INFO"
            
        } catch {
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Error in install worker: $_" -Level "ERROR"
            throw
        }
    }
    
    $job = Start-ThreadJob -ThrottleLimit 20 -ScriptBlock $installScript -ArgumentList @(
        $Pipeline,
        $MaxConcurrency,
        $PSScriptRoot,
        $Global:LogFile,
        $expectedDownloads
    )
    
    if ($job) {
        Add-Member -InputObject $job -MemberType NoteProperty -Name "Name" -Value "InstallWorker" -Force
    }
    
    return $job
}

function Start-MiniserverWorker {
    param(
        [hashtable]$WorkflowDefinition,
        [hashtable]$Pipeline,
        [int]$MaxConcurrency,
        [array]$MSPreCheckJobs = $null,
        [bool]$MSPreCheckJobsActive = $false
    )
    
    if (-not $WorkflowDefinition.MiniserverUpdates -or $WorkflowDefinition.MiniserverUpdates.Count -eq 0) {
        return $null
    }
    
    Write-Log "[Start-MiniserverWorker] Creating miniserver worker for $($WorkflowDefinition.MiniserverUpdates.Count) miniservers" -Level "INFO"
    
    $msScript = {
        param($Miniservers, $Pipeline, $MaxConcurrency, $ModulePath, $LogFile, $EnforceSSL, $MSPreCheckJobs, $MSPreCheckJobsActive)
        
        # Define Write-WorkerLog inline for this worker
        function Write-WorkerLog {
            param(
                [System.Collections.Concurrent.ConcurrentQueue[hashtable]]$LogQueue,
                [string]$WorkerName,
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            if (-not $LogQueue) { return }
            
            $logEntry = @{
                Timestamp = Get-Date
                Worker = $WorkerName
                Message = $Message
                Level = $Level
            }
            
            [void]$LogQueue.Enqueue($logEntry)
        }
        
        # Function to send updates
        function Send-MSProgress {
            param($Pipeline, $IP, $State, $Progress, $Message, $DNSError = $null)
            
            $update = @{
                Type = 'Miniserver'
                IP = $IP
                State = $State
                Progress = $Progress
                Message = $Message
            }
            
            if ($DNSError) {
                $update.DNSError = $DNSError
            }
            
            [void]$Pipeline.ProgressQueue.Enqueue($update)
        }
        
        try {
            # Import modules and set globals in this thread context
            Import-Module (Join-Path $ModulePath "LoxoneUtils.psd1") -Force
            $Global:LogFile = $LogFile
            $Global:DebugPreference = 'Continue'  # Enable debug logging
            
            # Apply TLS settings for Loxone compatibility (support all versions including old devices)
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls13
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Applied TLS 1.0/1.1/1.2/1.3 for Loxone compatibility" -Level "DEBUG"
            } catch {
                # Fallback without TLS 1.3 if not supported
                try {
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Applied TLS 1.0/1.1/1.2 (without 1.3)" -Level "DEBUG"
                } catch {
                    # Last resort - at least TLS 1.2
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Applied TLS 1.2 only" -Level "DEBUG"
                }
            }
            
            # Don't override Write-Log to avoid depth overflow
            # Instead, just use Write-WorkerLog directly for important messages
            
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Starting miniserver updates for $($Miniservers.Count) miniservers (MaxConcurrency: $MaxConcurrency)" -Level "INFO"

            # Check if MS PreCheck jobs are running (parallel mode dynamic collection)
            if ($MSPreCheckJobsActive -and $MSPreCheckJobs) {
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "[Dynamic Mode] Monitoring MS PreCheck jobs..." -Level "INFO"

                # Track which jobs are still running for progress updates
                $activePreCheckJobs = @{}

                # First pass: Send PreCheck status for all running jobs
                foreach ($job in $MSPreCheckJobs) {
                    $msIP = $job.Name -replace '^MSPreCheck_', ''

                    if ($job.State -eq 'Running') {
                        # Send PreCheck progress update
                        $progressUpdate = @{
                            Type = 'Miniserver'
                            IP = $msIP
                            State = 'PreCheck'
                            Progress = 0
                            Message = "Checking version..."
                        }
                        $Pipeline.ProgressQueue.Enqueue($progressUpdate)
                        $activePreCheckJobs[$msIP] = $job
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "[PreCheck] MS $msIP is being checked..." -Level "DEBUG"
                    }
                }

                # Monitor PreCheck jobs until they complete
                while ($activePreCheckJobs.Count -gt 0) {
                    Start-Sleep -Milliseconds 500

                    $completedIPs = @()
                    foreach ($msIP in $activePreCheckJobs.Keys) {
                        $job = $activePreCheckJobs[$msIP]

                        if ($job.State -eq 'Completed') {
                            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                            $completedIPs += $msIP

                            if ($result -and $result.Success) {
                                $msToAdd = @{
                                    IP = $result.IP
                                    Url = $result.OriginalEntry
                                    CurrentVersion = $result.Version
                                    TargetVersion = "auto"
                                    Credential = $null
                                    UpdateLevel = "auto"
                                }
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "[PreCheck Complete] MS $($result.IP) version: $($result.Version)" -Level "INFO"

                                # Check if update is needed
                                # TODO: Compare with target version

                                # Send completion status
                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $result.IP
                                    State = 'UpToDate'  # Or 'Updating' if update needed
                                    Progress = 100
                                    Message = "Version $($result.Version) - Up to date"
                                }
                                $Pipeline.ProgressQueue.Enqueue($progressUpdate)

                                $Miniservers += $msToAdd
                            } else {
                                # PreCheck failed
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "[PreCheck Failed] MS ${msIP}: $($result.Error)" -Level "WARN"

                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $msIP
                                    State = 'Failed'
                                    Progress = 0
                                    Message = "Check failed: $($result.Error)"
                                }
                                $Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            }
                        }
                    }

                    # Remove completed jobs from tracking
                    foreach ($ip in $completedIPs) {
                        $activePreCheckJobs.Remove($ip)
                    }
                }

                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "[PreCheck] All PreCheck jobs completed" -Level "INFO"
            }

            # Create a queue for miniservers to process
            $msQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
            foreach ($ms in $Miniservers) {
                [void]$msQueue.Enqueue($ms)
            }
            
            # Create parallel jobs for processing miniservers
            $msJobs = @()
            $jobCount = [Math]::Min($MaxConcurrency, $Miniservers.Count)
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Creating $jobCount parallel jobs for miniserver updates" -Level "INFO"
            
            for ($i = 0; $i -lt $jobCount; $i++) {
                $msJob = Start-ThreadJob -ThrottleLimit 20 -ScriptBlock {
                    param($msQueue, $Pipeline, $ModulePath, $LogFile, $EnforceSSL, $WorkerId, $TotalMSCount)
                    
                    # Import modules in this job context
                    Import-Module (Join-Path $ModulePath "LoxoneUtils.psd1") -Force
                    $Global:LogFile = $LogFile
                    
                    # Set parallel mode environment variable for Write-Log
                    $env:LOXONE_PARALLEL_MODE = "1"
                    
                    # Apply TLS settings for Loxone compatibility (support all versions including old devices)
                    try {
                        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls13
                    } catch {
                        # Fallback without TLS 1.3 if not supported
                        try {
                            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                        } catch {
                            # Last resort - at least TLS 1.2
                            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                        }
                    }
                    
                    # Process miniservers from the queue
                    $msProcessedCount = 0
                    while ($msQueue.Count -gt 0) {
                        $ms = $null
                        if (-not $msQueue.TryDequeue([ref]$ms)) {
                            continue
                        }
                        $msProcessedCount++
                        
                        # Determine connection type
                        $isEncrypted = $ms.OriginalEntry -match '^https://'
                        $connectionType = if ($isEncrypted) { "HTTPS (Encrypted)" } else { "HTTP (Unencrypted)" }
                        
                        # Log to central queue
                        $logEntry = @{
                            Timestamp = Get-Date
                            Worker = "MS[$($ms.IP)]"
                            Message = "Processing update for $($ms.IP) - Connection: $connectionType, Credential: $($null -ne $ms.Credential), UpdateLevel: $($ms.UpdateLevel)"
                            Level = "INFO"
                        }
                        [void]$Pipeline.LogQueue.Enqueue($logEntry)
                        
                        try {
                            # Send initial progress
                            $progressUpdate = @{
                                Type = 'Miniserver'
                                IP = $ms.IP
                                State = 'Starting'
                                Progress = 0
                                Message = "Connecting to Miniserver..."
                                TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            # Log debug message
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Testing connectivity to $($ms.IP)"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Skip connectivity check - just try to get the miniserver version directly
                            # This is more reliable than ping/TCP tests and faster
                            
                            # Get current version
                            $progressUpdate = @{
                                Type = 'Miniserver'
                                IP = $ms.IP
                                State = 'Checking'
                                Progress = 20
                                Message = "Checking current version..."
                                TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Getting current version for $($ms.IP)"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Use original entry if available, otherwise build from IP and Credential
                            $msEntry = if ($ms.OriginalEntry) {
                                # Extract just the URL part if this is a cached entry with commas
                                $entryToUse = $ms.OriginalEntry
                                if ($entryToUse -like '*,*') {
                                    $entryToUse = $entryToUse.Split(',')[0].Trim()
                                }
                                $entryToUse
                            } elseif ($ms.Credential) {
                                $username = $ms.Credential.UserName
                                $password = $ms.Credential.GetNetworkCredential().Password
                                $scheme = if ($isEncrypted) { "https" } else { "http" }
                                "${scheme}://${username}:${password}@$($ms.IP)"
                            } else {
                                $scheme = if ($isEncrypted) { "https" } else { "http" }
                                "${scheme}://$($ms.IP)"
                            }
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Calling Get-MiniserverVersion with MSEntry: $($msEntry -replace '(:)[^@]+@', ':****@')"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Connection details: Protocol=$( if ($msEntry -match '^https://') { 'HTTPS (Encrypted)' } else { 'HTTP (Plain text)' }), SkipCertCheck=$(-not $EnforceSSL)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Log what we received from the main thread
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Received MS data - IP: $($ms.IP), CurrentVersion: '$($ms.CurrentVersion)', TargetVersion: '$($ms.TargetVersion)'"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Use pre-checked version if available, otherwise check now (with retry logic)
                            $currentVersion = $ms.CurrentVersion
                            if (-not $currentVersion) {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "No pre-checked version available, checking now..."
                                    Level = "WARN"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                
                                # Add retry logic for version check
                                $maxRetries = 3
                                $retryCount = 0
                                $versionResult = $null
                                
                                while ($retryCount -lt $maxRetries -and -not $currentVersion) {
                                    $retryCount++
                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Version check attempt $retryCount/$maxRetries for $($ms.IP)"
                                        Level = "INFO"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                    
                                    $versionResult = Get-MiniserverVersion -MSEntry $msEntry -SkipCertificateCheck:(-not $EnforceSSL) -TimeoutSec 10
                                    
                                    if ($versionResult.Version) {
                                        $currentVersion = $versionResult.Version
                                        break
                                    } elseif ($retryCount -lt $maxRetries) {
                                        # Wait before retry
                                        Start-Sleep -Seconds 5
                                    }
                                }
                                
                                if (-not $currentVersion) {
                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Version check failed after $maxRetries attempts. Error: $($versionResult.Error)"
                                        Level = "ERROR"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                }
                            } else {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"  
                                    Message = "Using pre-checked version from pre-check phase: $currentVersion"
                                    Level = "INFO"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            }
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Current version for $($ms.IP): $currentVersion"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            if (-not $currentVersion) {
                                $errorDetail = if ($versionResult.Error) { ": $($versionResult.Error)" } else { "" }
                                throw "Failed to get miniserver version$errorDetail"
                            }
                            
                            # Trigger update - step 3/3
                            $progressUpdate = @{
                                Type = 'Miniserver'
                                IP = $ms.IP
                                State = 'Updating'
                                Progress = 40
                                Message = "Triggering update..."
                                TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Triggering update for $($ms.IP) to channel: $($ms.UpdateLevel)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Build update URI 
                            $updateUri = "${msEntry}/dev/sys/autoupdate"
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Update URI: $($updateUri -replace '(:)[^@]+@', ':****@')"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                    
                            # Parse credentials for auth header
                            $usernameForAuth = $null
                            $passwordForAuth = $null
                            
                            # Always log credential status at INFO level for debugging
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Checking credential for $($ms.IP): Credential is null: $($null -eq $ms.Credential), Type: $(if($ms.Credential) { $ms.Credential.GetType().Name } else { 'null' })"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            if ($ms.Credential) {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "Entering credential extraction block. Credential type: $($ms.Credential.GetType().Name), UserName: $($ms.Credential.UserName)"
                                    Level = "INFO"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                
                                $usernameForAuth = $ms.Credential.UserName
                                # PSCredential.Password is a SecureString, need to extract plain text
                                try {
                                    if ($ms.Credential.Password) {
                                        $passwordForAuth = $ms.Credential.GetNetworkCredential().Password
                                        $logEntry = @{
                                            Timestamp = Get-Date
                                            Worker = "MS[$($ms.IP)]"
                                            Message = "Successfully extracted password for user $usernameForAuth (length: $($passwordForAuth.Length))"
                                            Level = "INFO"
                                        }
                                        [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                    } else {
                                        $passwordForAuth = $null
                                        $logEntry = @{
                                            Timestamp = Get-Date
                                            Worker = "MS[$($ms.IP)]"
                                            Message = "Password property is null for credential"
                                            Level = "WARN"
                                        }
                                        [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                    }
                                } catch {
                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Error extracting password: $_"
                                        Level = "ERROR"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                    $passwordForAuth = $null
                                }
                                
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "Using credentials for user: $usernameForAuth"
                                    Level = "DEBUG"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            } else {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "No credentials provided for MS"
                                    Level = "DEBUG"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            }
                            
                            # Get target version - using current version as target for test
                            $targetVersion = if ($ms.TargetVersion) { $ms.TargetVersion } else { "99.99.99.99" }
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Target version: $targetVersion, Current version: $currentVersion"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Check if miniserver is already at target version
                            if ($currentVersion -eq $targetVersion) {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "$($ms.IP) is already at target version $targetVersion. Skipping update."
                                    Level = "INFO"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                
                                # Report as successful (no update needed)
                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    State = 'UpToDate'
                                    Progress = 100
                                    Message = "Already at target version"
                                    TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                                
                                [void]$Pipeline.Results.Add(@{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    Success = $true
                                    OldVersion = $currentVersion
                                    NewVersion = $currentVersion
                                    Status = "AlreadyCurrent"
                                })
                                
                                continue  # Skip to next miniserver
                            }
                            
                            # Create progress reporter for this MS update
                            $progressReporter = New-ProgressReporter -Context 'Parallel' `
                                                                    -Pipeline $Pipeline `
                                                                    -WorkerName "MS[$($ms.IP)]"
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Calling Invoke-MSUpdate..."
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Pass the plain text password directly - Invoke-MSUpdate will handle conversion if needed
                            # Note: Cannot use ConvertTo-SecureString in parallel worker context
                            
                            # Log what we're about to pass to diagnose the issue
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "About to call Invoke-MSUpdate with: URI='$updateUri', Target='$targetVersion', User='$usernameForAuth', PwdLen=$($passwordForAuth.Length), SkipCert=$(-not $EnforceSSL)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Check if the function is available
                            if (-not (Get-Command Invoke-MSUpdate -ErrorAction SilentlyContinue)) {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "ERROR: Invoke-MSUpdate function not found! Module not loaded properly."
                                    Level = "ERROR"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                throw "Invoke-MSUpdate function not found"
                            }
                            
                            # Validate and test queue before use
                            if ($Pipeline.ProgressQueue -and $Pipeline.ProgressQueue.GetType().Name -eq 'ConcurrentQueue`1') {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "ProgressQueue validated: Type=$($Pipeline.ProgressQueue.GetType().Name)"
                                    Level = "DEBUG"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)

                                # Test enqueue to verify queue is working
                                try {
                                    $testUpdate = @{
                                        Type = 'Miniserver'
                                        IP = $ms.IP
                                        State = 'Connecting'
                                        Progress = 5
                                        Message = "Testing queue communication"
                                        TotalMiniservers = $Pipeline.TotalMiniservers
                                        Timestamp = Get-Date
                                    }
                                    [void]$Pipeline.ProgressQueue.Enqueue($testUpdate)

                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Test enqueue successful - queue is working"
                                        Level = "INFO"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                } catch {
                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "ERROR: Test enqueue failed - $_"
                                        Level = "ERROR"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                }
                            } else {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "WARNING: ProgressQueue invalid or wrong type: $($Pipeline.ProgressQueue.GetType().Name)"
                                    Level = "WARN"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            }

                            # Don't pass PSCredential or scriptblock in parallel context - they cause serialization issues
                            # Only pass the plain text username and password
                            $updateSucceeded = $false
                            try {
                                # Call Invoke-MSUpdate WITH ProgressQueue for REAL-TIME status updates
                                # Capture to local variable to avoid scope issues with nested function calls
                                $progressQueueForUpdate = $Pipeline.ProgressQueue

                                if (-not $EnforceSSL) {
                                    $updateResult = Invoke-MSUpdate -MSUri $updateUri -NormalizedDesiredVersion $targetVersion -UsernameForAuthHeader $usernameForAuth -PasswordForAuthHeader $passwordForAuth -SkipCertificateCheck -ProgressQueue $progressQueueForUpdate
                                } else {
                                    $updateResult = Invoke-MSUpdate -MSUri $updateUri -NormalizedDesiredVersion $targetVersion -UsernameForAuthHeader $usernameForAuth -PasswordForAuthHeader $passwordForAuth -ProgressQueue $progressQueueForUpdate
                                }

                                # Debug logging for StatusUpdates
                                if ($updateResult) {
                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Invoke-MSUpdate returned. Has StatusUpdates property: $($null -ne $updateResult.StatusUpdates), Count: $(if ($updateResult.StatusUpdates) { $updateResult.StatusUpdates.Count } else { 0 })"
                                        Level = "DEBUG"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                }
                                
                                # Process returned status updates and enqueue them at THIS level
                                if ($updateResult -and $updateResult.StatusUpdates) {
                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Processing $($updateResult.StatusUpdates.Count) status updates from Invoke-MSUpdate"
                                        Level = "INFO"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)

                                    foreach ($statusUpdate in $updateResult.StatusUpdates) {
                                        # Create progress update with all required fields
                                        $progressUpdate = @{
                                            Type = 'Miniserver'
                                            IP = $ms.IP
                                            State = $statusUpdate.State
                                            Progress = $statusUpdate.Progress
                                            Message = $statusUpdate.Message
                                            TotalMiniservers = $Pipeline.TotalMiniservers
                                            Timestamp = $statusUpdate.Timestamp
                                        }

                                        # Enqueue at THIS ThreadJob level where it works
                                        [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)

                                        # Log successful enqueue
                                        $logEntry = @{
                                            Timestamp = Get-Date
                                            Worker = "MS[$($ms.IP)]"
                                            Message = "Successfully enqueued status: State=$($statusUpdate.State), Progress=$($statusUpdate.Progress)"
                                            Level = "INFO"
                                        }
                                        [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                    }
                                }

                                # Also check CurrentState for backward compatibility
                                if ($updateResult -and $updateResult.CurrentState -and -not $updateResult.StatusUpdates) {
                                    # Fallback for old behavior
                                    $stateToSend = $updateResult.CurrentState
                                    $progressValue = switch ($stateToSend) {
                                        'Installing' { 50 }
                                        'Rebooting' { 60 }
                                        'Verifying' { 80 }
                                        'Updating' { 45 }
                                        default { 40 }
                                    }

                                    $statusMsg = if ($updateResult.LastUpdateStatus) {
                                        $updateResult.LastUpdateStatus
                                    } else {
                                        $stateToSend
                                    }

                                    # Send single progress update
                                    $progressUpdate = @{
                                        Type = 'Miniserver'
                                        IP = $ms.IP
                                        State = $stateToSend
                                        Progress = $progressValue
                                        Message = $statusMsg
                                        TotalMiniservers = $Pipeline.TotalMiniservers
                                    }
                                    [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)

                                    $logEntry = @{
                                        Timestamp = Get-Date
                                        Worker = "MS[$($ms.IP)]"
                                        Message = "Enqueued fallback status: State=$stateToSend, Progress=$progressValue"
                                        Level = "INFO"
                                    }
                                    [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                }
                                
                                # Check if update actually succeeded
                                if ($updateResult -and $updateResult.VerificationSuccess) {
                                    $updateSucceeded = $true
                                    # Send final verification completed state
                                    $progressUpdate = @{
                                        Type = 'Miniserver'
                                        IP = $ms.IP
                                        State = 'Verifying'
                                        Progress = 80
                                        Message = "Version verified"
                                        TotalMiniservers = $Pipeline.TotalMiniservers
                                    }
                                    [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                                }
                            } catch {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "Error calling Invoke-MSUpdate: $_"
                                    Level = "ERROR"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                throw
                            }
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "Update trigger result for $($ms.IP): Success=$($updateResult.VerificationSuccess), Status=$($updateResult.StatusMessage), Version=$($updateResult.ReportedVersion)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            if ($updateResult.VerificationSuccess) {
                                # Update was successful and already verified by Invoke-MSUpdate
                                $newVersion = $updateResult.ReportedVersion
                                
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "Update completed for $($ms.IP): $currentVersion -> $newVersion"
                                    Level = "INFO"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                
                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    State = 'Completed'
                                    Progress = 100
                                    Message = "Updated to $newVersion"
                                    TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                                
                                [void]$Pipeline.Results.Add(@{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    Success = $true
                                    OldVersion = $currentVersion
                                    NewVersion = $newVersion
                                })
                            } else {
                                # Update failed or timed out
                                $errorMsg = "Update failed: $($updateResult.StatusMessage)"
                                
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS[$($ms.IP)]"
                                    Message = "$($ms.IP): $errorMsg"
                                    Level = "ERROR"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                
                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    State = 'Failed'
                                    Progress = 0
                                    Message = $errorMsg
                                    TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                                
                                [void]$Pipeline.Results.Add(@{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    Success = $false
                                    Error = $errorMsg
                                    ErrorOccurred = $updateResult.ErrorOccurredInInvoke
                                    OldVersion = $currentVersion
                                    NewVersion = if ($updateResult.ReportedVersion) { $updateResult.ReportedVersion } else { $currentVersion }
                                    ReportedVersion = $updateResult.ReportedVersion
                                })
                            }
                    
                        } catch {
                            $errorMsg = "Error updating miniserver: $_"
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS[$($ms.IP)]"
                                Message = "$($ms.IP): $errorMsg"
                                Level = "ERROR"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            try {
                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    State = 'Failed'
                                    Progress = 0
                                    Message = $errorMsg
                                    TotalMiniservers = $Pipeline.TotalMiniservers  # Include total MS count
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            } catch {
                                # Progress update failed, just log to results
                            }
                            
                            [void]$Pipeline.Results.Add(@{
                                Type = 'Miniserver'
                                IP = $ms.IP
                                Success = $false
                                Error = $errorMsg
                                OldVersion = if ($currentVersion) { $currentVersion } else { $null }
                                NewVersion = if ($currentVersion) { $currentVersion } else { $null }
                            })
                        }
                    }
                } -ArgumentList $msQueue, $Pipeline, $ModulePath, $LogFile, $EnforceSSL, $i, $Miniservers.Count
                
                $msJobs += $msJob
            }
            
            # Wait for all sub-jobs to complete
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Waiting for $($msJobs.Count) sub-jobs to complete..." -Level "INFO"
            
            $msJobs | Wait-Job | Out-Null
            
            # Clean up sub-jobs
            $msJobs | Remove-Job -Force
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "All miniserver updates completed" -Level "INFO"
            
        } catch {
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "MS Worker" -Message "Error in miniserver worker: $_" -Level "ERROR"
            throw
        }
    }
    
    $job = Start-ThreadJob -ThrottleLimit 20 -ScriptBlock $msScript -ArgumentList @(
        $WorkflowDefinition.MiniserverUpdates,
        $Pipeline,
        $MaxConcurrency,
        $PSScriptRoot,
        $Global:LogFile,
        $WorkflowDefinition.EnforceSSLCertificate,
        $MSPreCheckJobs,
        $MSPreCheckJobsActive
    )
    
    if ($job) {
        Add-Member -InputObject $job -MemberType NoteProperty -Name "Name" -Value "MiniserverWorker" -Force
    }
    
    return $job
}

function Watch-DirectThreadJobs {
    param(
        [array]$WorkerJobs,
        [hashtable]$WorkflowDefinition,
        [hashtable]$Pipeline
    )
    
    if ($WorkerJobs.Count -eq 0) {
        Write-Log "[Watch-DirectThreadJobs] No jobs to monitor, returning immediately" -Level "DEBUG"
        return @{
            Success = $true
            TotalDuration = 0
            Downloads = @{}
            Installations = @{}
            Miniservers = @{}
            Errors = @()
        }
    }
    
    Write-Log "[Watch-DirectThreadJobs] Starting monitoring of $($WorkerJobs.Count) ThreadJobs" -Level "INFO"
    
    $startTime = Get-Date
    # No special handling for progress worker anymore - all jobs monitored equally
    $workerJobsToMonitor = @($WorkerJobs)
    $activeJobs = @() + $workerJobsToMonitor
    $completedJobs = @()
    $maxWaitMinutes = 30
    
    # Initialize MS status tracking
    $msStatusTracker = @{
        Connecting = @()
        Downloading = @()
        Updating = @()     # Add separate Updating state
        Installing = @()
        Rebooting = @()
        Verifying = @()
        UpToDate = @()     # No update needed
        Completed = @()
        Failed = @()
        CompletionList = @()  # Array of @{IP="x.x.x.x"; Status="✓/✗"; Time="00:00"; StartTime=DateTime}
        ProgressByIP = @{}    # Hashtable tracking each MS's progress percentage: @{IP1 = 30; IP2 = 75; IP3 = 100}
        TotalMS = 0           # Total number of Miniservers being updated
    }
    
    # Monitor ThreadJobs
    $logFlushCounter = 0
    $toastCreated = $Global:PersistentToastInitialized -eq $true
    $lastTimerUpdate = Get-Date
    $lastProgressUpdate = Get-Date
    $lastActiveJobsLog = Get-Date
    $activeJobsLogInterval = 15  # Log active jobs every 15 seconds
    while ($activeJobs.Count -gt 0 -and ((Get-Date) - $startTime).TotalMinutes -lt $maxWaitMinutes) {
        # Update timer every second - but don't update StatusText here to avoid conflicts
        $now = Get-Date
        if (($now - $lastTimerUpdate).TotalSeconds -ge 1 -and $toastCreated -and $Global:PersistentToastData) {
            # Just track the time for use in progress updates
            $lastTimerUpdate = $now
            
            # Only update the toast if we haven't had a progress update recently
            # This prevents the timer from overwriting status updates
            if (($now - $lastProgressUpdate).TotalSeconds -ge 2) {
                # Update elapsed time for display
                $elapsed = $now - $startTime
                $elapsedText = "{0:mm}:{0:ss}" -f $elapsed
                
                # Update StatusText with timer only - MS status goes in progress bar
                $statusLine = "Processing updates... [$elapsedText]"
                
                # Only add completion details if ALL MS are done
                # This is handled by the progress update handler
                
                $Global:PersistentToastData.StatusText = $statusLine
                
                # Update toast
                try {
                    if (Get-Command Update-Toast -ErrorAction SilentlyContinue) {
                        Update-Toast
                    }
                } catch {
                    # Silently ignore toast update errors to avoid log spam
                }
            }
        }
        
        # Log active jobs every 15 seconds to help identify stuck workers
        if (($now - $lastActiveJobsLog).TotalSeconds -ge $activeJobsLogInterval) {
            Write-Log "[Watch-DirectThreadJobs] Active jobs status check (every ${activeJobsLogInterval}s):" -Level "INFO"
            foreach ($job in $activeJobs) {
                $jobState = if ($job.State) { $job.State } else { "Unknown" }
                $jobName = if ($job.Name) { $job.Name } else { "Job-$($job.Id)" }
                $jobRuntime = if ($job.PSBeginTime) { 
                    $runtime = (Get-Date) - $job.PSBeginTime
                    " (running for {0:mm}:{0:ss})" -f $runtime
                } else { "" }
                Write-Log "  - ${jobName}: State=${jobState}${jobRuntime}" -Level "INFO"
            }
            $lastActiveJobsLog = $now
        }
        
        # Process any pending log messages from workers (every iteration for better logging)
        if ($Pipeline -and $Pipeline.LogQueue) {
            $logEntry = $null
            $logCount = 0
            while ($Pipeline.LogQueue.TryDequeue([ref]$logEntry)) {
                if ($logEntry) {
                    # Write to main log with worker context
                    $formattedMessage = "[$($logEntry.Worker)] $($logEntry.Message)"
                    Write-Log $formattedMessage -Level $logEntry.Level
                    $logCount++
                }
            }
            if ($logCount -gt 0) {
                Write-Log "[Watch-DirectThreadJobs] Flushed $logCount log entries from workers" -Level "DEBUG"
            }
        }
        
        # Process any pending progress messages (including toast creation requests)
        if (-not $Pipeline) {
            Write-Log "[Watch-DirectThreadJobs] Pipeline is null!" -Level "WARN"
        } elseif (-not $Pipeline.ProgressQueue) {
            Write-Log "[Watch-DirectThreadJobs] Pipeline.ProgressQueue is null!" -Level "WARN"
        } else {
            # Debug: Check queue count
            Write-Log "[Watch-DirectThreadJobs] Checking ProgressQueue for messages" -Level "DEBUG"
            $progressMsg = $null
            $dequeueCount = 0
            while ($Pipeline.ProgressQueue.TryDequeue([ref]$progressMsg)) {
                $dequeueCount++
                Write-Log "[Watch-DirectThreadJobs] Dequeued progress message #$dequeueCount, Type: $($progressMsg.Type), Component: $($progressMsg.Component), Progress: $($progressMsg.Progress), State: $($progressMsg.State), Message: $($progressMsg.Message)" -Level "DEBUG"
                if ($progressMsg) {
                    # Handle Miniserver status updates for tracking
                    if ($progressMsg.Type -eq 'Miniserver' -and $progressMsg.IP) {
                        $msIP = $progressMsg.IP
                        $msState = $progressMsg.State
                        
                        # Remove MS from all status arrays
                        foreach ($status in @('Connecting', 'Downloading', 'Updating', 'Installing', 'Rebooting', 'Verifying', 'UpToDate', 'Completed', 'Failed')) {
                            $msStatusTracker.$status = @($msStatusTracker.$status | Where-Object { $_ -ne $msIP })
                        }

                        # Add MS to appropriate status
                        $statusCategory = switch ($msState) {
                            'Starting' { 'Connecting' }
                            'Checking' { 'Connecting' }
                            'PreCheck' { 'Connecting' }    # Map PreCheck to Connecting (magnifying glass)
                            'Downloading' { 'Downloading' }
                            'Installing' { 'Installing' }
                            'Updating' { 'Updating' }      # Map to separate Updating category
                            'Rebooting' { 'Rebooting' }  # New state we're sending
                            'Verifying' { 'Verifying' }   # New state we're sending
                            'Polling' { 'Rebooting' }      # Legacy state mapping
                            'UpToDate' { 'UpToDate' }      # No update needed
                            'Complete' { 'Completed' }     # Alternative spelling
                            'Completed' { 'Completed' }
                            'Failed' { 'Failed' }
                            default { $null }
                        }
                        
                        if ($statusCategory) {
                            $msStatusTracker.$statusCategory += $msIP

                            # Track individual MS progress for accurate overall progress calculation
                            if ($progressMsg.Progress) {
                                $msStatusTracker.ProgressByIP[$msIP] = [int]$progressMsg.Progress
                            } else {
                                # If no explicit progress provided, estimate based on state
                                $estimatedProgress = switch ($msState) {
                                    'Starting'   { 5 }
                                    'Checking'   { 10 }
                                    'PreCheck'   { 15 }
                                    'Connecting' { 20 }
                                    'Updating'   { 45 }
                                    'Rebooting'  { 70 }
                                    'Verifying'  { 85 }
                                    'Completed'  { 100 }
                                    'Failed'     { 100 }  # Count failed as complete for progress calculation
                                    'UpToDate'   { 100 }  # Already up to date = 100%
                                    default      { 0 }
                                }
                                $msStatusTracker.ProgressByIP[$msIP] = $estimatedProgress
                            }

                            # Update completion list for completed or failed MS
                            if ($msState -eq 'Completed' -or $msState -eq 'Failed') {
                                $existingEntry = $msStatusTracker.CompletionList | Where-Object { $_.IP -eq $msIP }
                                if (-not $existingEntry) {
                                    $elapsed = (Get-Date) - $startTime
                                    $msStatusTracker.CompletionList += @{
                                        IP = $msIP
                                        Status = if ($msState -eq 'Completed') { '✓' } else { '✗' }
                                        Time = "{0:mm}:{0:ss}" -f $elapsed
                                        StartTime = $startTime
                                        EndTime = Get-Date
                                    }
                                }
                            }
                        }
                        
                        # Build COMPACT status string with symbols and counts (as per docs)
                        # Format: "2 🔄 | 1 🚀 | 1 ✓" (only number and symbol, no text)
                        $statusParts = @()
                        $statusDetails = @()  # Detailed list with IPs for logging

                        if ($msStatusTracker.Connecting.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Connecting.Count) 🔍"  # Magnifying glass - checking
                            $statusDetails += "🔍 Checking: $($msStatusTracker.Connecting -join ', ')"
                        }
                        if ($msStatusTracker.Downloading.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Downloading.Count) ⏬"  # Download arrow
                            $statusDetails += "⏬ Downloading: $($msStatusTracker.Downloading -join ', ')"
                        }
                        if ($msStatusTracker.Updating.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Updating.Count) 🔄"  # Update arrows
                            $statusDetails += "🔄 Updating: $($msStatusTracker.Updating -join ', ')"
                        }
                        if ($msStatusTracker.Installing.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Installing.Count) 📦"  # Package - installing
                            $statusDetails += "📦 Installing: $($msStatusTracker.Installing -join ', ')"
                        }
                        if ($msStatusTracker.Rebooting.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Rebooting.Count) 🚀"  # Rocket - reboot
                            $statusDetails += "🚀 Rebooting: $($msStatusTracker.Rebooting -join ', ')"
                        }
                        if ($msStatusTracker.Verifying.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Verifying.Count) ⏳"  # Hourglass - waiting
                            $statusDetails += "⏳ Verifying: $($msStatusTracker.Verifying -join ', ')"
                        }
                        if ($msStatusTracker.UpToDate.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.UpToDate.Count) ✅"   # Green checkmark - no update needed
                            $statusDetails += "✅ UpToDate: $($msStatusTracker.UpToDate -join ', ')"
                        }
                        if ($msStatusTracker.Completed.Count -gt 0) {
                            $statusParts += "$($msStatusTracker.Completed.Count) ✓"   # Checkmark
                            $statusDetails += "✓ Completed: $($msStatusTracker.Completed -join ', ')"
                        }
                        if ($msStatusTracker.Failed.Count -gt 0) {
                            # Include IPs with failed symbol for immediate visibility
                            $failedIPs = $msStatusTracker.Failed -join ", "
                            $statusParts += "$($msStatusTracker.Failed.Count) ✗: $failedIPs"
                            $statusDetails += "✗ Failed: $failedIPs"
                        }
                        
                        # Calculate overall MS progress by averaging all individual MS progress
                        $overallMSProgress = 0.0
                        if ($msStatusTracker.ProgressByIP.Count -gt 0) {
                            $totalProgress = 0
                            foreach ($ip in $msStatusTracker.ProgressByIP.Keys) {
                                $totalProgress += $msStatusTracker.ProgressByIP[$ip]
                            }
                            $overallMSProgress = [Math]::Round(($totalProgress / $msStatusTracker.ProgressByIP.Count) / 100.0, 3)
                            Write-Log "[Watch-DirectThreadJobs] MS Progress Calculation: Total=$totalProgress, Count=$($msStatusTracker.ProgressByIP.Count), Average=$([Math]::Round($overallMSProgress * 100, 1))%" -Level "DEBUG"
                        }

                        # Update toast with MS status
                        if ($Global:PersistentToastData) {
                            $Global:PersistentToastData.MiniserverStatus = $statusParts -join " | "
                            $Global:PersistentToastData.MiniserverProgress = $overallMSProgress

                            # Also log the current MS status for visibility
                            if ($statusParts.Count -gt 0) {
                                $statusSummary = $statusParts -join ' | '
                                $detailedStatus = if ($statusDetails.Count -gt 0) { " [$($statusDetails -join ' | ')]" } else { "" }
                                Write-Log "[Watch-DirectThreadJobs] MS Status Update: $statusSummary$detailedStatus (Overall Progress: $([Math]::Round($overallMSProgress * 100, 1))%)" -Level "INFO"
                            }
                            
                            # Build completion list for display
                            if ($msStatusTracker.CompletionList.Count -gt 0) {
                                $completionLines = @()
                                # Sort failed first, then by end time descending
                                $sorted = $msStatusTracker.CompletionList | Sort-Object -Property @(
                                    @{Expression = {$_.Status -eq '✗'}; Descending = $true},
                                    @{Expression = {$_.EndTime}; Descending = $true}
                                )
                                foreach ($ms in $sorted) {
                                    $completionLines += "$($ms.Status) $($ms.IP) - $($ms.Time)"
                                }
                                # Add currently processing MS
                                $processingMS = @()
                                foreach ($status in @('Connecting', 'Downloading', 'Installing', 'Rebooting', 'Verifying')) {
                                    foreach ($ip in $msStatusTracker.$status) {
                                        $processingMS += "⏳ $ip - $status..."
                                    }
                                }
                                $allLines = $completionLines + $processingMS
                                # Limit to 5 lines to fit in toast
                                if ($allLines.Count -gt 5) {
                                    $allLines = $allLines[0..4]
                                }
                                # Store in a separate field for display
                                $Global:PersistentToastData.MiniserverDetails = $allLines -join "`n"
                            }
                        }
                    }
                    
                    # Handle simple progress updates from workers
                    if (($progressMsg.Type -eq 'Download' -or $progressMsg.Type -eq 'Install' -or $progressMsg.Type -eq 'Extract' -or $progressMsg.Type -eq 'Verify' -or $progressMsg.Type -eq 'Miniserver') -and $toastCreated) {
                        # Include IP address for Miniserver updates
                        $logPrefix = if ($progressMsg.Type -eq 'Miniserver' -and $progressMsg.IP) {
                            "MS[$($progressMsg.IP)]"
                        } elseif ($progressMsg.Component) {
                            $progressMsg.Component
                        } else {
                            ""
                        }
                        Write-Log "[Watch-DirectThreadJobs] Processing progress update for $logPrefix`: $($progressMsg.Message)" -Level "INFO"
                        try {
                            if ($Global:PersistentToastData) {
                                # Update toast data based on component
                                $component = $progressMsg.Component
                                
                                # Try to identify Unknown components from context
                                if ($component -eq 'Unknown') {
                                    if ($progressMsg.Message -match 'Config' -or $progressMsg.Type -eq 'Extract') {
                                        $component = 'Config'
                                        Write-Log "[Watch-DirectThreadJobs] Identified Unknown component as Config from context" -Level "DEBUG"
                                    } elseif ($progressMsg.Message -match 'App') {
                                        $component = 'App'
                                        Write-Log "[Watch-DirectThreadJobs] Identified Unknown component as App from context" -Level "DEBUG"
                                    }
                                }
                                
                                $progress = $progressMsg.Progress
                                $status = $progressMsg.Message
                                
                                # Track step information for display
                                $stepInfo = ""
                                $stepTitle = ""
                                if ($progressMsg.StepNumber -and $progressMsg.TotalSteps) {
                                    $stepInfo = "$($progressMsg.StepNumber)/$($progressMsg.TotalSteps) "
                                    # Create title with step number and action
                                    $action = if ($progressMsg.Type -eq 'Download') { "Downloading" }
                                             elseif ($progressMsg.Type -eq 'Install') { "Installing" }
                                             elseif ($progressMsg.Type -eq 'Extract') { "Extracting" }
                                             elseif ($progressMsg.Type -eq 'Verify') { "Verifying" }
                                             elseif ($progressMsg.Type -eq 'Miniserver') { "Updating" }
                                             else { $progressMsg.Type }
                                    $stepTitle = "${stepInfo}${action}"
                                }
                                
                                if ($component -eq 'Config') {
                                    $Global:PersistentToastData.ConfigProgress = [double]($progress / 100.0)
                                    # Use step title with component prefix
                                    if ($stepTitle) {
                                        $Global:PersistentToastData.ConfigTitle = "Loxone Config: $stepTitle"
                                    }
                                    # Build detailed status - avoid repeating action name
                                    if ($progressMsg.Type -eq 'Download') {
                                        # For downloads, show speed and time info
                                        $statusText = ""
                                        if ($progressMsg.Speed) { $statusText = $progressMsg.Speed }
                                        if ($progressMsg.RemainingTime) { 
                                            $statusText = if ($statusText) { "$statusText - $($progressMsg.RemainingTime)" } else { $progressMsg.RemainingTime }
                                        }
                                        # If no speed/time, use the message from worker (already contains "Downloading...")
                                        if (-not $statusText) { $statusText = $status }
                                    } elseif ($progressMsg.Type -eq 'Install') {
                                        # During installation, just show the installation message
                                        $statusText = $status
                                    } elseif ($progressMsg.Type -eq 'Verify' -and $progressMsg.State -eq 'Verifying') {
                                        # During verification, show verifying status
                                        $statusText = "Verifying installation..."
                                    } elseif ($progressMsg.Type -eq 'Verify' -and $progressMsg.State -eq 'Completed') {
                                        # Only NOW mark as complete with timer
                                        $elapsed = (Get-Date) - $startTime
                                        $Global:PersistentToastData.ConfigDuration = "{0:mm}:{0:ss}" -f $elapsed
                                        # Check if it's a fresh install (no initial version) or an update
                                        $isFreshInstall = -not $progressMsg.InitialVersion -or $progressMsg.InitialVersion -eq "" -or $progressMsg.InitialVersion -eq "0.0.0.0"
                                        $symbol = if ($isFreshInstall) { "🚀" } else { "🔄" }
                                        $Global:PersistentToastData.ConfigSymbol = $symbol  # Save for reuse
                                        $statusText = "Completed $symbol ($($Global:PersistentToastData.ConfigDuration))"
                                    } elseif ($Global:PersistentToastData.ConfigDuration) {
                                        # If we already have a duration, keep showing it with the correct symbol
                                        if (-not $Global:PersistentToastData.ConfigSymbol) {
                                            $Global:PersistentToastData.ConfigSymbol = "✓"  # Default if not set
                                        }
                                        $statusText = "Completed $($Global:PersistentToastData.ConfigSymbol) ($($Global:PersistentToastData.ConfigDuration))"
                                    } else {
                                        # For other operations, show the status message
                                        $statusText = $status
                                    }
                                    $Global:PersistentToastData.ConfigStatus = $statusText
                                    Write-Log "[Watch-DirectThreadJobs] Config update: Progress=$progress%, Title=Loxone Config: $stepTitle, Status=$statusText" -Level "DEBUG"
                                } elseif ($component -eq 'App') {
                                    $Global:PersistentToastData.AppProgress = [double]($progress / 100.0)
                                    # Use step title with component prefix
                                    if ($stepTitle) {
                                        $Global:PersistentToastData.AppTitle = "Loxone App: $stepTitle"
                                    }
                                    # Build detailed status - avoid repeating action name
                                    if ($progressMsg.Type -eq 'Download') {
                                        # For downloads, show speed and time info
                                        $statusText = ""
                                        if ($progressMsg.Speed) { $statusText = $progressMsg.Speed }
                                        if ($progressMsg.RemainingTime) { 
                                            $statusText = if ($statusText) { "$statusText - $($progressMsg.RemainingTime)" } else { $progressMsg.RemainingTime }
                                        }
                                        # If no speed/time, use the message from worker (already contains "Downloading...")
                                        if (-not $statusText) { $statusText = $status }
                                    } elseif ($progressMsg.Type -eq 'Install') {
                                        # During installation, just show the installation message
                                        $statusText = $status
                                    } elseif ($progressMsg.Type -eq 'Verify' -and $progressMsg.State -eq 'Verifying') {
                                        # During verification, show verifying status
                                        $statusText = "Verifying installation..."
                                    } elseif ($progressMsg.Type -eq 'Verify' -and $progressMsg.State -eq 'Completed') {
                                        # Only NOW mark as complete with timer
                                        $elapsed = (Get-Date) - $startTime
                                        $Global:PersistentToastData.AppDuration = "{0:mm}:{0:ss}" -f $elapsed
                                        # Check if it's a fresh install (no initial version) or an update
                                        $isFreshInstall = -not $progressMsg.InitialVersion -or $progressMsg.InitialVersion -eq "" -or $progressMsg.InitialVersion -eq "0.0.0.0"
                                        $symbol = if ($isFreshInstall) { "🚀" } else { "🔄" }
                                        $Global:PersistentToastData.AppSymbol = $symbol  # Save for reuse
                                        $statusText = "Completed $symbol ($($Global:PersistentToastData.AppDuration))"
                                    } elseif ($Global:PersistentToastData.AppDuration) {
                                        # If we already have a duration, keep showing it with the correct symbol
                                        if (-not $Global:PersistentToastData.AppSymbol) {
                                            $Global:PersistentToastData.AppSymbol = "✓"  # Default if not set
                                        }
                                        $statusText = "Completed $($Global:PersistentToastData.AppSymbol) ($($Global:PersistentToastData.AppDuration))"
                                    } else {
                                        # For other operations, show the status message
                                        $statusText = $status
                                    }
                                    $Global:PersistentToastData.AppStatus = $statusText
                                    Write-Log "[Watch-DirectThreadJobs] App update: Progress=$progress%, Title=Loxone App: $stepTitle, Status=$statusText" -Level "DEBUG"
                                } elseif ($progressMsg.Type -eq 'Miniserver') {
                                    # Handle miniserver updates - use IP as component identifier
                                    # NOTE: MiniserverProgress is now calculated dynamically by averaging all MS progress (see above)
                                    # Individual MS progress is tracked in msStatusTracker.ProgressByIP

                                    # Build title with step info and appropriate symbol
                                    $msSymbol = switch ($progressMsg.State) {
                                        'Starting'   { '🔍' }  # Checking/connecting
                                        'Checking'   { '🔍' }  # Checking version
                                        'Updating'   { '🚀' }  # Updating (rocket for actual update)
                                        'Polling'    { '⏳' }  # Waiting for reboot
                                        'Complete'   { '✓' }   # Completed
                                        'Completed'  { '✓' }   # Completed
                                        'Failed'     { '✗' }   # Failed
                                        default      { '🔄' }  # Generic update symbol
                                    }
                                    
                                    # Show MS count and current state
                                    if ($progressMsg.TotalMiniservers -and $progressMsg.TotalMiniservers -gt 0) {
                                        # Show how many MS are being processed with current state
                                        $stateText = switch ($progressMsg.State) {
                                            'Starting'   { 'Connecting' }
                                            'Checking'   { 'Checking' }
                                            'Updating'   { 'Updating' }
                                            'Polling'    { 'Restarting' }
                                            'Complete'   { 'Complete' }
                                            'Completed'  { 'Complete' }
                                            'Failed'     { 'Failed' }
                                            default      { $progressMsg.State }
                                        }
                                        $Global:PersistentToastData.MiniserversTitle = "$msSymbol Miniservers ($($progressMsg.TotalMiniservers) MS) - $stateText"
                                    } else {
                                        # Fallback if count not available
                                        $Global:PersistentToastData.MiniserversTitle = "$msSymbol Miniservers"
                                    }
                                    
                                    # Check if all miniservers are complete to add timer
                                    if ($progressMsg.State -in @('Complete', 'Completed', 'Failed')) {
                                        # Capture duration when miniservers complete
                                        if (-not $Global:PersistentToastData.MiniserverDuration) {
                                            $elapsed = (Get-Date) - $startTime
                                            $Global:PersistentToastData.MiniserverDuration = "{0:mm}:{0:ss}" -f $elapsed
                                            $Global:PersistentToastData.MiniserverSymbol = $msSymbol
                                        }
                                    }
                                    
                                    # DO NOT update MiniserverStatus here - it's handled by msStatusTracker with symbols
                                    # Only log individual MS progress for debugging
                                    $logMessage = if ($progressMsg.IP) { 
                                        "$($progressMsg.Message) [$($progressMsg.IP)]" 
                                    } else { 
                                        $progressMsg.Message 
                                    }
                                    Write-Log "[Watch-DirectThreadJobs] Miniserver update: Progress=$progress%, State=$($progressMsg.State), Message=$logMessage" -Level "DEBUG"
                                } else {
                                    # Unknown component that couldn't be identified
                                    Write-Log "[Watch-DirectThreadJobs] Unhandled component '$component' - Type: $($progressMsg.Type), Message: $($progressMsg.Message), Progress: $($progressMsg.Progress)%" -Level "WARN"
                                }
                                
                                # Update overall status message with step information and timer
                                if ($progressMsg.OverallStatus) {
                                    $Global:PersistentToastData.StatusText = $progressMsg.OverallStatus
                                } else {
                                    # Calculate elapsed time from workflow start
                                    $elapsed = (Get-Date) - $startTime
                                    $elapsedText = "{0:mm}:{0:ss}" -f $elapsed
                                    
                                    # Build status line - keep MS details OUT of main text
                                    # Only show completion info when all MS are done
                                    $statusLine = "Processing updates... [$elapsedText]"
                                    
                                    # Check if all miniservers are complete
                                    if ($component -match 'Miniserver' -and $progressMsg.State -in @('Complete', 'Completed', 'Failed')) {
                                        # Check if ALL miniservers are done
                                        if ($Global:PersistentToastData.MiniserverDetails) {
                                            # Show completion details
                                            $statusLine += "`n" + $Global:PersistentToastData.MiniserverDetails
                                        }
                                    }
                                    
                                    $Global:PersistentToastData.StatusText = $statusLine
                                }
                                
                                # Track when we last updated from a progress message
                                $lastProgressUpdate = Get-Date
                                
                                # Force update toast notification - call every time for smooth updates
                                try {
                                    if (Get-Command Update-Toast -ErrorAction SilentlyContinue) {
                                        Write-Log "[Watch-DirectThreadJobs] Updating toast - Component: $component, Progress: $progress%" -Level "DEBUG"
                                        Update-Toast
                                        Write-Log "[Watch-DirectThreadJobs] Toast updated successfully" -Level "DEBUG"
                                    } else {
                                        Write-Log "[Watch-DirectThreadJobs] Update-Toast command not available" -Level "WARN"
                                    }
                                } catch {
                                    Write-Log "[Watch-DirectThreadJobs] Error updating toast: $_" -Level "ERROR"
                                }
                            }
                        } catch {
                            Write-Log "[Watch-DirectThreadJobs] Failed to update toast: $_" -Level "WARN"
                        }
                    }
                }
            }
            if ($dequeueCount -eq 0) {
                Write-Log "[Watch-DirectThreadJobs] No progress messages in queue" -Level "DEBUG"
            }
        }
        
        # Check job states
        $stillRunning = @()
        
        foreach ($job in $activeJobs) {
            if ($job.State -eq 'Completed' -or $job.State -eq 'Failed' -or $job.State -eq 'Stopped') {
                Write-Log "[Watch-DirectThreadJobs] Job $($job.Name) completed with state: $($job.State)" -Level "DEBUG"
                $completedJobs += $job
                
                # Get output immediately (skip for mock jobs in test mode)
                if ($job.PSJobTypeName -eq 'ThreadJob' -and $job.GetType().Name -ne 'PSCustomObject') {
                    $output = Receive-Job -Job $job -ErrorAction Continue
                    if ($output) {
                        Write-Host "[$($job.Name)] Output:" -ForegroundColor Yellow
                        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                    }
                }
                
                # Remove completed job (skip for mock jobs in test mode)
                if ($job.GetType().Name -ne 'PSCustomObject') {
                    Remove-Job -Job $job -ErrorAction SilentlyContinue
                }
            } else {
                $stillRunning += $job
            }
        }
        
        $activeJobs = $stillRunning
        
        if ($activeJobs.Count -gt 0) {
            # Log status every 10 iterations (20 seconds)
            $logFlushCounter++
            if ($logFlushCounter % 20 -eq 0) {  # Adjusted for more frequent checks
                Write-Log "[Watch-DirectThreadJobs] $($activeJobs.Count) jobs still running..." -Level "DEBUG"
            }
            Start-Sleep -Milliseconds 250  # Check queues 4x per second for better responsiveness
        }
    }
    
    # No progress worker to signal anymore
    
    # Process final log messages
    if ($Pipeline -and $Pipeline.LogQueue) {
        $logEntry = $null
        while ($Pipeline.LogQueue.TryDequeue([ref]$logEntry)) {
            if ($logEntry) {
                $formattedMessage = "[$($logEntry.Worker)] $($logEntry.Message)"
                Write-Log $formattedMessage -Level $logEntry.Level
            }
        }
    }
    
    # Timeout handling
    if ($activeJobs.Count -gt 0) {
        Write-Log "[Watch-DirectThreadJobs] WARNING: $($activeJobs.Count) jobs still running after timeout" -Level "WARN"
        
        foreach ($job in $activeJobs) {
            Write-Log "[Watch-DirectThreadJobs] Stopping job: $($job.Name)" -Level "WARN"
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -ErrorAction SilentlyContinue
        }
    }
    
    # Process results
    $duration = (Get-Date) - $startTime
    $results = @{
        Downloads = @{}
        Installations = @{}
        Miniservers = @{}
        Errors = @()
    }
    
    # Extract results from pipeline
    foreach ($result in $Pipeline.Results) {
        switch ($result.Type) {
            'Download' {
                $results.Downloads[$result.Component + '_Download'] = $result
            }
            'Install' {
                $results.Installations[$result.Component + '_Install'] = $result
            }
            'Miniserver' {
                $results.Miniservers[$result.IP] = $result
            }
        }
        
        if (-not $result.Success -and $result.Error) {
            $results.Errors += $result.Error
        }
    }
    
    $overallSuccess = $results.Errors.Count -eq 0
    
    Write-Log "[Watch-DirectThreadJobs] Workflow completed in $([Math]::Round($duration.TotalSeconds, 2)) seconds. Success: $overallSuccess" -Level "INFO"
    
    return @{
        Success = $overallSuccess
        TotalDuration = $duration.TotalSeconds
        Downloads = $results.Downloads
        Installations = $results.Installations
        Miniservers = $results.Miniservers
        Errors = $results.Errors
    }
}

# Additional helper functions
function Initialize-ProgressTracking {
    param([hashtable]$WorkflowDefinition)
    
    $script:WorkflowState.Progress.Clear()
    
    # Initialize component progress
    if ($WorkflowDefinition.ConfigUpdate) {
        $script:WorkflowState.Progress['Config'] = @{
            Type = 'Component'
            State = 'Pending'
            Progress = 0
            Message = ''
        }
    }
    
    if ($WorkflowDefinition.AppUpdate) {
        $script:WorkflowState.Progress['App'] = @{
            Type = 'Component'
            State = 'Pending'
            Progress = 0
            Message = ''
        }
    }
    
    # Initialize miniserver progress
    if ($WorkflowDefinition.MiniserverUpdates) {
        foreach ($ms in $WorkflowDefinition.MiniserverUpdates) {
            $script:WorkflowState.Progress[$ms.IP] = @{
                Type = 'Miniserver'
                State = 'Pending'
                Progress = 0
                Message = ''
                Name = $ms.Name
            }
        }
    }
}

function Update-MiniserverProgress {
    param(
        [string]$IP,
        [string]$Stage,
        [int]$Progress = -1,
        [string]$Message = '',
        [string]$Error = ''
    )
    
    if ($script:WorkflowState.Progress.ContainsKey($IP)) {
        $msProgress = $script:WorkflowState.Progress[$IP]
        $msProgress.Stage = $Stage
        if ($Progress -ge 0) {
            $msProgress.Progress = $Progress
        }
        if ($Message) {
            $msProgress.Message = $Message
        }
        if ($Error) {
            $msProgress.Error = $Error
        }
        $msProgress.LastUpdate = Get-Date
    }
}

# Export all public functions
Export-ModuleMember -Function @(
    'Start-ParallelWorkflow',
    'Remove-ThreadJobs',
    'Write-WorkerLog',
    'Start-ProgressWorker',
    'Start-ComponentDownloadWorker',
    'Start-InstallWorker',
    'Start-MiniserverWorker',
    'Watch-DirectThreadJobs',
    'Initialize-ProgressTracking',
    'Update-MiniserverProgress'
)