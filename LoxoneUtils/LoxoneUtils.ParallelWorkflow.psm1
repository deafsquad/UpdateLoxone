# LoxoneUtils.ParallelWorkflow.psm1
# Module for parallel execution of Loxone update workflows

# Initialize module-level variables
$script:WorkflowState = @{
    StartTime = $null
    EndTime = $null
    Results = [System.Collections.Concurrent.ConcurrentBag[hashtable]]::new()
    Errors = [System.Collections.Concurrent.ConcurrentBag[hashtable]]::new()
    Progress = [System.Collections.Concurrent.ConcurrentDictionary[string,hashtable]]::new()
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
        [int]$MaxConcurrency = 4,
        
        [Parameter()]
        [int]$MaxMSConcurrency = 3
    )
    
    Write-Log "Starting parallel workflow..." -Level "INFO"
    Write-Host "Starting parallel workflow execution..." -ForegroundColor Cyan
    
    # Initialize workflow pipeline
    $pipeline = @{
        InstallQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
        ProgressQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
        Results = [System.Collections.Concurrent.ConcurrentBag[hashtable]]::new()
        LogQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()  # Add log queue for centralized logging
    }
    
    # Set parallel mode flag
    $env:LOXONE_PARALLEL_MODE = "1"
    
    # Create an array to hold all ThreadJobs
    $allJobs = @()
    
    try {
        # Start progress worker first if there's any work
        $hasWork = $WorkflowDefinition.ConfigUpdate -or $WorkflowDefinition.AppUpdate -or 
                   ($WorkflowDefinition.MiniserverUpdates -and $WorkflowDefinition.MiniserverUpdates.Count -gt 0)
        
        if ($hasWork) {
            Write-Log "Starting progress worker..." -Level "INFO"
            $progressJob = Start-ProgressWorker -Pipeline $pipeline -WorkflowDefinition $WorkflowDefinition
            $allJobs += $progressJob
            
            # Give progress worker time to initialize
            Start-Sleep -Seconds 2
        }
        
        # Start component workers
        $downloadWorkers = @()
        
        if ($WorkflowDefinition.ConfigUpdate) {
            Write-Log "Starting Config download worker..." -Level "INFO"
            $configJob = Start-ComponentDownloadWorker -Pipeline $pipeline -Component 'Config' -DownloadInfo $WorkflowDefinition.ConfigUpdate
            $allJobs += $configJob
            $downloadWorkers += $configJob
        }
        
        if ($WorkflowDefinition.AppUpdate) {
            Write-Log "Starting App download worker..." -Level "INFO"
            $appJob = Start-ComponentDownloadWorker -Pipeline $pipeline -Component 'App' -DownloadInfo $WorkflowDefinition.AppUpdate
            $allJobs += $appJob
            $downloadWorkers += $appJob
        }
        
        # Start install worker if we have downloads
        if ($WorkflowDefinition.ConfigUpdate -or $WorkflowDefinition.AppUpdate) {
            Write-Log "Starting install worker..." -Level "INFO"
            $installJob = Start-InstallWorker -Pipeline $pipeline -MaxConcurrency 1 -DownloadWorkers $downloadWorkers
            $allJobs += $installJob
        }
        
        # Start miniserver worker if needed
        if ($WorkflowDefinition.MiniserverUpdates -and $WorkflowDefinition.MiniserverUpdates.Count -gt 0) {
            Write-Log "Starting miniserver worker..." -Level "INFO"
            $msJob = Start-MiniserverWorker -WorkflowDefinition $WorkflowDefinition -Pipeline $pipeline -MaxConcurrency $MaxMSConcurrency
            $allJobs += $msJob
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

function Start-ProgressWorker {
    param([hashtable]$Pipeline, [hashtable]$WorkflowDefinition)
    
    Write-Log "[Start-ProgressWorker] Creating progress worker" -Level "INFO"
    
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
            
            # Create initial toast notification with data binding template
            if (Get-Command New-BTBinding -ErrorAction SilentlyContinue) {
                # Count actual components for data binding
                $totalComponents = 0
                $msCount = if ($WorkflowDefinition.MiniserverUpdates) { $WorkflowDefinition.MiniserverUpdates.Count } else { 0 }
                
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Initializing toast with $msCount miniservers needing updates" -Level "INFO"
                
                # Build progress bars with data binding placeholders
                $progressBars = @()
                
                if ($WorkflowDefinition.ConfigUpdate) {
                    $progressBars += New-BTProgressBar -Title "Loxone Config" -Status "configStatus" -Value "configProgress"
                    $totalComponents++
                }
                
                if ($WorkflowDefinition.AppUpdate) {
                    $progressBars += New-BTProgressBar -Title "Loxone App" -Status "appStatus" -Value "appProgress"
                    $totalComponents++
                }
                
                if ($msCount -gt 0) {
                    $progressBars += New-BTProgressBar -Title "MiniserversTitle" -Status "msStatus" -Value "msProgress"
                    $totalComponents++
                }
                
                # Create binding with data binding placeholders
                $childElements = @(
                    New-BTText -Text 'UpdateLoxone Progress'
                    New-BTText -Text 'statusMessage'
                )
                # Add progress bars to children
                $childElements += $progressBars
                
                $binding = New-BTBinding -Children $childElements
                
                $visual = New-BTVisual -BindingGeneric $binding
                
                # Use or initialize the global persistent toast data
                # CRITICAL: We must use the SAME global dataframe for all toast operations
                if (-not $Global:PersistentToastData) {
                    # Initialize if not exists (this should normally be done by Toast module)
                    $Global:PersistentToastData = @{
                        statusMessage = 'Starting parallel update process...'
                        configStatus = 'Waiting...'
                        configProgress = 0.0
                        appStatus = 'Waiting...'
                        appProgress = 0.0
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
                    $Global:PersistentToastData.appStatus = 'Waiting...'
                    $Global:PersistentToastData.appProgress = 0.0
                    $Global:PersistentToastData.MiniserversTitle = "Miniservers (0/$msCount)"
                    $Global:PersistentToastData.msCompleted = 0
                    $Global:PersistentToastData.msStatus = 'Waiting...'
                    $Global:PersistentToastData.msProgress = 0.0
                }
                
                # Use the global data for initial binding
                $initialData = $Global:PersistentToastData
                
                # Create content with data binding template
                $content = New-BTContent -Visual $visual
                
                # Submit initial toast with AppId and data binding
                # CRITICAL: Use the same toast ID as the main module
                $toastId = if ($Global:PersistentToastId) { $Global:PersistentToastId } else { 'LoxoneUpdateStatusToast' }
                
                if ($appId) {
                    Submit-BTNotification -Content $content -UniqueIdentifier $toastId -AppId $appId -DataBinding $initialData
                } else {
                    Submit-BTNotification -Content $content -UniqueIdentifier $toastId -DataBinding $initialData
                }
                
                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Initial toast notification created with data binding" -Level "DEBUG"
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
                            'Failed' { "Config: Failed ✗" }
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
                            'Failed' { "App: Failed ✗" }
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
                                'Installed' { 'Completed ✓' }
                                'Completed' { 'Completed ✓' }
                                'Failed' { 'Failed ✗' }
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
                                'Installed' { 'Completed ✓' }
                                'Completed' { 'Completed ✓' }
                                'Failed' { 'Failed ✗' }
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
                                    'Completed' { '✓' }
                                    'Failed' { '✗' }
                                    default { '⏳' }
                                }
                                $statusParts += "$($group.Count) $symbol"
                            }
                            
                            $msStatusText = $statusParts -join ' | '
                            if ($msFailed.Count -gt 0) {
                                $msStatusText += " | Failed: $($msFailed -join ', ')"
                            }
                            
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
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "PersistentToastData not found, creating new" -Level "WARN"
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
                                'Installed' { 'Completed ✓' }
                                'Completed' { 'Completed ✓' }
                                'Failed' { 'Failed ✗' }
                                default { 'Waiting...' }
                            }
                            $updateData.configProgress = $componentStates.Config.Progress / 100.0
                        }
                        
                        if ($componentStates.App) {
                            $updateData.appStatus = switch ($componentStates.App.State) {
                                'Downloading' { "Downloading... $($componentStates.App.Progress)%" }
                                'Downloaded' { "Download complete" }
                                'Installing' { "Installing..." }
                                'Installed' { 'Completed ✓' }
                                'Completed' { 'Completed ✓' }
                                'Failed' { 'Failed ✗' }
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
                                    'Completed' { '✓' }
                                    'Failed' { '✗' }
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
                        
                        # Update notification with the SAME dataframe reference
                        try {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Updating toast notification with existing dataframe" -Level "DEBUG"
                            
                            # CRITICAL: Pass the same dataframe reference that was bound during initialization
                            # Do NOT create a new hashtable or the binding will break
                            # Use the same toast ID as the main module
                            $toastId = if ($Global:PersistentToastId) { $Global:PersistentToastId } else { 'LoxoneUpdateStatusToast' }
                            
                            if ($appId) {
                                Update-BTNotification -UniqueIdentifier $toastId -DataBinding $updateData -AppId $appId
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Toast updated successfully with AppId" -Level "DEBUG"
                            } else {
                                Update-BTNotification -UniqueIdentifier $toastId -DataBinding $updateData
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Toast updated successfully without AppId" -Level "DEBUG"
                            }
                        } catch {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "ProgressWorker" -Message "Failed to update toast notification: $_" -Level "WARN"
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
    
    $job = Start-ThreadJob -ScriptBlock $progressScript -ArgumentList @(
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

function Start-ComponentDownloadWorker {
    param([hashtable]$Pipeline, [string]$Component, [hashtable]$DownloadInfo)
    
    Write-Log "[Start-ComponentDownloadWorker] Creating $Component download worker" -Level "INFO"
    
    $downloadScript = {
        param($Pipeline, $Component, $DownloadInfo, $ModulePath, $LogFile)
        
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
            
            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Starting download of $Component" -Level "INFO"
            
            # Send initial progress
            $progressUpdate = @{
                Type = 'Download'
                Component = $Component
                State = 'Downloading'
                Progress = 0
                Message = "Starting $Component download..."
            }
            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
            
            # Simulate download with progress updates
            $totalSize = $DownloadInfo.FileSize
            if (-not $totalSize) { $totalSize = 100000000 } # 100MB default
            
            $downloaded = 0
            $chunkSize = [Math]::Min(1024 * 1024, $totalSize / 10) # 1MB chunks or 10% of total
            
            # Create output path - use Downloads folder when running from UpdateLoxone directory
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
            $fileExtension = if ($DownloadInfo.Url) {
                $urlFileName = [System.IO.Path]::GetFileName([System.Uri]::new($DownloadInfo.Url).LocalPath)
                if ($urlFileName -match '\.(\w+)$') { $matches[1] } else { 'exe' }
            } else { 'exe' }
            
            # Build output path
            if ($useLocalDownloads) {
                # Use Downloads folder with proper filename from URL
                $fileName = if ($DownloadInfo.Url) {
                    [System.IO.Path]::GetFileName([System.Uri]::new($DownloadInfo.Url).LocalPath)
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
            
            # Perform actual download using Invoke-LoxoneDownload
            if (Get-Command Invoke-LoxoneDownload -ErrorAction SilentlyContinue) {
                # Send download in progress update
                $progressUpdate = @{
                    Type = 'Download'
                    Component = $Component
                    State = 'Downloading'
                    Progress = 50
                    Message = "Downloading $Component..."
                }
                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                
                $downloadResult = Invoke-LoxoneDownload `
                    -Url $DownloadInfo.Url `
                    -DestinationPath $outputPath `
                    -ActivityName "Downloading $Component" `
                    -ExpectedCRC32 $DownloadInfo.ExpectedCRC32 `
                    -ExpectedFilesize $DownloadInfo.FileSize
                
                if ($downloadResult) {
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "$Component download completed successfully" -Level "INFO"
                    
                    # Send completion progress
                    $progressUpdate = @{
                        Type = 'Download'
                        Component = $Component
                        State = 'Downloaded'
                        Progress = 100
                        Message = "$Component download complete"
                    }
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Sending download complete status (100%)" -Level "INFO"
                    try {
                        $Pipeline.ProgressQueue.Enqueue($progressUpdate)
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Successfully sent download complete status" -Level "INFO"
                    } catch {
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Error sending download complete status: $_" -Level "ERROR"
                    }
                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "$Component Download Worker" -Message "Download complete, queuing for installation" -Level "INFO"
                    
                    # Queue for installation
                    $installTask = @{
                        Type = 'Download'  # Signal that this is a download completion
                        Component = $Component
                        FilePath = $outputPath
                        Version = $DownloadInfo.TargetVersion
                    }
                    [void]$Pipeline.InstallQueue.Enqueue($installTask)
                    
                    # Add to results
                    [void]$Pipeline.Results.Add(@{
                        Type = 'Download'
                        Component = $Component
                        Success = $true
                        FilePath = $outputPath
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
                    Version = $DownloadInfo.TargetVersion
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
    
    $job = Start-ThreadJob -ScriptBlock $downloadScript -ArgumentList @(
        $Pipeline,
        $Component,
        $DownloadInfo,
        $PSScriptRoot,
        $Global:LogFile
    )
    
    if ($job) {
        Add-Member -InputObject $job -MemberType NoteProperty -Name "Name" -Value "${Component}DownloadWorker" -Force
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
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Processed download $completedDownloads of $ExpectedDownloads" -Level "INFO"
                            if ($completedDownloads -ge $ExpectedDownloads) {
                                $downloadsCompleted = $true
                                Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "All $ExpectedDownloads downloads completed" -Level "INFO"
                            }
                            
                            # Don't skip installation - downloads signal completion AND need installation
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Download complete for $($installTask.Component), proceeding with installation" -Level "INFO"
                        }
                        
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Installing $($installTask.Component)" -Level "INFO"
                        
                        # Send progress update
                        $progressUpdate = @{
                            Type = 'Install'
                            Component = $installTask.Component
                            State = 'Installing'
                            Progress = 0
                            Message = "Installing $($installTask.Component)..."
                        }
                        [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                        
                        try {
                            # Perform installation based on component type
                            if ($installTask.Component -eq 'Config') {
                                # Extract and install Config
                                # Extract the ZIP file
                                $extractPath = Join-Path $env:TEMP "LoxoneConfig_Extract_$(Get-Date -Format 'yyyyMMddHHmmss')"
                                try {
                                    # Use built-in Expand-Archive for better compatibility
                                    Expand-Archive -Path $installTask.FilePath -DestinationPath $extractPath
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Extracted $($installTask.Component) to $extractPath" -Level "INFO"
                                    
                                    # Find installer
                                    $installer = Get-ChildItem -Path $extractPath -Filter "*.exe" -Recurse | Select-Object -First 1
                                    
                                    if ($installer) {
                                        $installResult = Start-LoxoneUpdateInstaller -InstallerPath $installer.FullName -InstallMode "VERYSILENT"
                                        if (-not $installResult.Success) {
                                            throw "Installation failed with exit code: $($installResult.ExitCode)"
                                        }
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
                                
                                # Install App MSI
                                if (Get-Command Start-LoxoneForWindowsInstaller -ErrorAction SilentlyContinue) {
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Calling Start-LoxoneForWindowsInstaller..." -Level "DEBUG"
                                    $installResult = Start-LoxoneForWindowsInstaller -InstallerPath $installTask.FilePath -InstallMode "SILENT"
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Start-LoxoneForWindowsInstaller returned. Success: $($installResult.Success), ExitCode: $($installResult.ExitCode)" -Level "INFO"
                                    
                                    if (-not $installResult.Success) {
                                        throw "App installation failed with exit code: $($installResult.ExitCode)"
                                    }
                                    Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "App installation completed successfully" -Level "INFO"
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
                                Error = $_.ToString()
                            })
                        }
                        
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "Completed processing $($installTask.Component), continuing to check for more work..." -Level "INFO"
                        
                        # Exit early if all downloads are processed
                        if ($downloadsCompleted) {
                            Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "All downloads processed, exiting" -Level "INFO"
                            break
                        }
                    }
                } else {
                    # No work available
                    if ($downloadsCompleted) {
                        # All downloads are done and queue is empty, we can exit
                        Write-WorkerLog -LogQueue $Pipeline.LogQueue -WorkerName "Install Worker" -Message "No more work and all downloads completed, exiting" -Level "INFO"
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
    
    $job = Start-ThreadJob -ScriptBlock $installScript -ArgumentList @(
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
    param([hashtable]$WorkflowDefinition, [hashtable]$Pipeline, [int]$MaxConcurrency)
    
    if (-not $WorkflowDefinition.MiniserverUpdates -or $WorkflowDefinition.MiniserverUpdates.Count -eq 0) {
        return $null
    }
    
    Write-Log "[Start-MiniserverWorker] Creating miniserver worker for $($WorkflowDefinition.MiniserverUpdates.Count) miniservers" -Level "INFO"
    
    $msScript = {
        param($Miniservers, $Pipeline, $MaxConcurrency, $ModulePath, $LogFile, $EnforceSSL)
        
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
                $msJob = Start-ThreadJob -ScriptBlock {
                    param($msQueue, $Pipeline, $ModulePath, $LogFile, $EnforceSSL, $WorkerId)
                    
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
                    while ($msQueue.Count -gt 0) {
                        $ms = $null
                        if (-not $msQueue.TryDequeue([ref]$ms)) {
                            continue
                        }
                        
                        # Determine connection type
                        $isEncrypted = $ms.OriginalEntry -match '^https://'
                        $connectionType = if ($isEncrypted) { "HTTPS (Encrypted)" } else { "HTTP (Unencrypted)" }
                        
                        # Log to central queue
                        $logEntry = @{
                            Timestamp = Get-Date
                            Worker = "MS Worker[$WorkerId]"
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
                                Message = "Connecting to $($ms.IP)..."
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            # Log debug message
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
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
                                Message = "Checking version..."
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Getting current version for $($ms.IP)"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Use original entry if available, otherwise build from IP and Credential
                            $msEntry = if ($ms.OriginalEntry) {
                                $ms.OriginalEntry
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
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Calling Get-MiniserverVersion with MSEntry: $($msEntry -replace "([Pp]assword=)[^@]+", '$1****')"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Connection details: Protocol=$( if ($msEntry -match '^https://') { 'HTTPS (Encrypted)' } else { 'HTTP (Plain text)' }), SkipCertCheck=$(-not $EnforceSSL)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            $versionResult = Get-MiniserverVersion -MSEntry $msEntry -SkipCertificateCheck:(-not $EnforceSSL) -TimeoutSec 10
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Version result: MSIP=$($versionResult.MSIP), Version=$($versionResult.Version), Error=$($versionResult.Error)"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            $currentVersion = $versionResult.Version
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Current version for $($ms.IP): $currentVersion"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            if (-not $currentVersion) {
                                $errorDetail = if ($versionResult.Error) { ": $($versionResult.Error)" } else { "" }
                                throw "Failed to get miniserver version$errorDetail"
                            }
                            
                            # Trigger update
                            $progressUpdate = @{
                                Type = 'Miniserver'
                                IP = $ms.IP
                                State = 'Updating'
                                Progress = 40
                                Message = "Triggering update..."
                            }
                            [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Triggering update for $($ms.IP) to channel: $($ms.UpdateLevel)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Build update URI 
                            $updateUri = "${msEntry}/dev/sys/autoupdate"
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Update URI: $updateUri"
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                    
                            # Parse credentials for auth header
                            $usernameForAuth = $null
                            $passwordForAuth = $null
                            if ($ms.Credential) {
                                $usernameForAuth = $ms.Credential.UserName
                                $passwordForAuth = $ms.Credential.Password
                                
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS Worker[$WorkerId]"
                                    Message = "Using credentials for user: $usernameForAuth"
                                    Level = "DEBUG"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            } else {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS Worker[$WorkerId]"
                                    Message = "No credentials provided for MS"
                                    Level = "DEBUG"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            }
                            
                            # Get target version - using current version as target for test
                            $targetVersion = if ($ms.TargetVersion) { $ms.TargetVersion } else { "99.99.99.99" }
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Target version: $targetVersion, Current version: $currentVersion"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            # Check if miniserver is already at target version
                            if ($currentVersion -eq $targetVersion) {
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS Worker[$WorkerId]"
                                    Message = "$($ms.IP) is already at target version $targetVersion. Skipping update."
                                    Level = "INFO"
                                }
                                [void]$Pipeline.LogQueue.Enqueue($logEntry)
                                
                                # Report as successful (no update needed)
                                $progressUpdate = @{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    State = 'Complete'
                                    Progress = 100
                                    Message = "Already at target version"
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
                                                                    -WorkerName "MS Worker[$WorkerId]"
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Calling Invoke-MSUpdate..."
                                Level = "DEBUG"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            $updateResult = Invoke-MSUpdate -MSUri $updateUri `
                                                           -NormalizedDesiredVersion $targetVersion `
                                                           -Credential $ms.Credential `
                                                           -UsernameForAuthHeader $usernameForAuth `
                                                           -PasswordForAuthHeader $passwordForAuth `
                                                           -SkipCertificateCheck:(-not $EnforceSSL) `
                                                           -ProgressReporter $progressReporter
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
                                Message = "Update trigger result for $($ms.IP): Success=$($updateResult.VerificationSuccess), Status=$($updateResult.StatusMessage), Version=$($updateResult.ReportedVersion)"
                                Level = "INFO"
                            }
                            [void]$Pipeline.LogQueue.Enqueue($logEntry)
                            
                            if ($updateResult.VerificationSuccess) {
                                # Update was successful and already verified by Invoke-MSUpdate
                                $newVersion = $updateResult.ReportedVersion
                                
                                $logEntry = @{
                                    Timestamp = Get-Date
                                    Worker = "MS Worker[$WorkerId]"
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
                                    Worker = "MS Worker[$WorkerId]"
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
                                }
                                [void]$Pipeline.ProgressQueue.Enqueue($progressUpdate)
                                
                                [void]$Pipeline.Results.Add(@{
                                    Type = 'Miniserver'
                                    IP = $ms.IP
                                    Success = $false
                                    Error = $errorMsg
                                    ErrorOccurred = $updateResult.ErrorOccurredInInvoke
                                })
                            }
                    
                        } catch {
                            $errorMsg = "Error updating miniserver: $_"
                            
                            $logEntry = @{
                                Timestamp = Get-Date
                                Worker = "MS Worker[$WorkerId]"
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
                            })
                        }
                    }
                } -ArgumentList $msQueue, $Pipeline, $ModulePath, $LogFile, $EnforceSSL, $i
                
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
    
    $job = Start-ThreadJob -ScriptBlock $msScript -ArgumentList @(
        $WorkflowDefinition.MiniserverUpdates,
        $Pipeline,
        $MaxConcurrency,
        $PSScriptRoot,
        $Global:LogFile,
        $WorkflowDefinition.EnforceSSLCertificate
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
    
    Write-Log "[Watch-DirectThreadJobs] Starting monitoring of $($WorkerJobs.Count) ThreadJobs" -Level "INFO"
    
    if ($WorkerJobs.Count -eq 0) {
        return @{
            Success = $true
            TotalDuration = 0
            Downloads = @{}
            Installations = @{}
            Miniservers = @{}
            Errors = @()
        }
    }
    
    $startTime = Get-Date
    $progressWorkerJobs = @($WorkerJobs | Where-Object { $_.Name -match 'ProgressWorker' })
    $workerJobsToMonitor = @($WorkerJobs | Where-Object { $_.Name -notmatch 'ProgressWorker' })
    $activeJobs = @() + $workerJobsToMonitor
    $completedJobs = @()
    $maxWaitMinutes = 30
    
    # Monitor ThreadJobs
    while ($activeJobs.Count -gt 0 -and ((Get-Date) - $startTime).TotalMinutes -lt $maxWaitMinutes) {
        # Process any pending log messages from workers
        if ($Pipeline -and $Pipeline.LogQueue) {
            $logEntry = $null
            while ($Pipeline.LogQueue.TryDequeue([ref]$logEntry)) {
                if ($logEntry) {
                    # Write to main log with worker context
                    $formattedMessage = "[$($logEntry.Worker)] $($logEntry.Message)"
                    Write-Log $formattedMessage -Level $logEntry.Level
                }
            }
        }
        
        # Check job states
        $stillRunning = @()
        
        foreach ($job in $activeJobs) {
            if ($job.State -eq 'Completed' -or $job.State -eq 'Failed' -or $job.State -eq 'Stopped') {
                Write-Log "[Watch-DirectThreadJobs] Job $($job.Name) completed with state: $($job.State)" -Level "INFO"
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
            Write-Log "[Watch-DirectThreadJobs] $($activeJobs.Count) jobs still running..." -Level "DEBUG"
            Start-Sleep -Seconds 2
        }
    }
    
    # Signal completion to progress worker
    if ($progressWorkerJobs.Count -gt 0) {
        Write-Log "[Watch-DirectThreadJobs] Signaling completion to progress worker" -Level "INFO"
        [void]$Pipeline.ProgressQueue.Enqueue(@{ Type = 'Complete' })
        
        # Wait for progress worker to finish
        $progressTimeout = 10
        $progressStart = Get-Date
        
        while ($progressWorkerJobs[0].State -eq 'Running' -and ((Get-Date) - $progressStart).TotalSeconds -lt $progressTimeout) {
            Start-Sleep -Milliseconds 500
        }
        
        # Clean up progress worker
        Stop-Job -Job $progressWorkerJobs[0] -ErrorAction SilentlyContinue
        Remove-Job -Job $progressWorkerJobs[0] -ErrorAction SilentlyContinue
    }
    
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