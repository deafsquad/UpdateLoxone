function Get-ProgressBar {
    param(
        [int]$Progress,
        [int]$Width = 30
    )
    
    $completed = [Math]::Floor($Width * ($Progress / 100))
    $remaining = $Width - $completed
    
    $bar = "█" * $completed + "░" * $remaining
    return "[$bar] $Progress%"
}

function Show-ConsoleProgress {
    param(
        [hashtable]$ProgressData,
        [switch]$ClearScreen
    )
    
    if ($ClearScreen) {
        Clear-Host
    }
    
    # Save cursor position
    $origPos = $host.UI.RawUI.CursorPosition
    
    try {
        # Title
        Write-Host "`n=== Loxone Update Progress ===" -ForegroundColor Cyan
        Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')`n" -ForegroundColor Gray
        
        # Config Progress
        if ($ProgressData.ConfigUpdate) {
            $configBar = Get-ProgressBar -Progress $ProgressData.ConfigProgress
            $configStatus = if ($ProgressData.ConfigStatus) { $ProgressData.ConfigStatus } else { "Waiting..." }
            $configTime = if ($ProgressData.ConfigElapsed) { " [$($ProgressData.ConfigElapsed)]" } else { "" }
            
            Write-Host "Config Update$configTime" -ForegroundColor Yellow
            Write-Host "$configBar" -ForegroundColor White
            Write-Host "Status: $configStatus`n" -ForegroundColor Gray
        }
        
        # App Progress
        if ($ProgressData.AppUpdate) {
            $appBar = Get-ProgressBar -Progress $ProgressData.AppProgress
            $appStatus = if ($ProgressData.AppStatus) { $ProgressData.AppStatus } else { "Waiting..." }
            $appTime = if ($ProgressData.AppElapsed) { " [$($ProgressData.AppElapsed)]" } else { "" }
            
            Write-Host "App Update$appTime" -ForegroundColor Yellow
            Write-Host "$appBar" -ForegroundColor White
            Write-Host "Status: $appStatus`n" -ForegroundColor Gray
        }
        
        # Miniserver Progress
        if ($ProgressData.MiniserverCount -gt 0) {
            $msBar = Get-ProgressBar -Progress $ProgressData.MiniserverProgress
            $msStatus = "Processing $($ProgressData.MiniserverCompleted)/$($ProgressData.MiniserverCount) servers"
            $msTime = if ($ProgressData.MiniserverElapsed) { " [$($ProgressData.MiniserverElapsed)]" } else { "" }
            
            Write-Host "Miniserver Updates$msTime" -ForegroundColor Yellow
            Write-Host "$msBar" -ForegroundColor White
            Write-Host "Status: $msStatus" -ForegroundColor Gray
            
            # Show individual miniserver status
            if ($ProgressData.MiniserverDetails) {
                Write-Host "`nServer Status:" -ForegroundColor Gray
                foreach ($server in $ProgressData.MiniserverDetails.GetEnumerator()) {
                    $symbol = switch ($server.Value.Stage) {
                        'Init'     { '🔍' }
                        'Update'   { '🔄' }
                        'Reboot'   { '🚀' }
                        'Wait'     { '⏳' }
                        'Complete' { '✓' }
                        'Failed'   { '✗' }
                        default    { '•' }
                    }
                    Write-Host "  $symbol $($server.Key): $($server.Value.Stage)" -ForegroundColor DarkGray
                }
            }
        }
        
        # Overall Progress
        if ($ProgressData.OverallProgress) {
            Write-Host "`n" -NoNewline
            $overallBar = Get-ProgressBar -Progress $ProgressData.OverallProgress -Width 40
            Write-Host "Overall Progress:" -ForegroundColor Green
            Write-Host "$overallBar" -ForegroundColor Green
        }
        
        # Status Message
        if ($ProgressData.StatusMessage) {
            Write-Host "`nStatus: $($ProgressData.StatusMessage)" -ForegroundColor White
        }
        
        # Press Ctrl+C to cancel
        Write-Host "`nPress Ctrl+C to cancel..." -ForegroundColor DarkGray
        
    }
    catch {
        Write-Warning "Error displaying console progress: $_"
    }
}

function Start-ConsoleProgressMonitor {
    param(
        [System.Collections.Concurrent.ConcurrentQueue[object]]$ProgressQueue,
        [hashtable]$WorkflowDefinition
    )
    
    $progressData = @{
        ConfigUpdate = $WorkflowDefinition.ConfigUpdate -ne $null
        ConfigProgress = 0
        ConfigStatus = "Waiting..."
        ConfigElapsed = ""
        
        AppUpdate = $WorkflowDefinition.AppUpdate -ne $null
        AppProgress = 0
        AppStatus = "Waiting..."
        AppElapsed = ""
        
        MiniserverCount = if ($WorkflowDefinition.MiniserverUpdates) { $WorkflowDefinition.MiniserverUpdates.Count } else { 0 }
        MiniserverCompleted = 0
        MiniserverProgress = 0
        MiniserverElapsed = ""
        MiniserverDetails = @{}
        
        OverallProgress = 0
        StatusMessage = "Initializing..."
    }
    
    # Component timers
    $timers = @{
        Config = $null
        App = $null
        Miniserver = $null
    }
    
    $lastUpdate = Get-Date
    $updateInterval = [TimeSpan]::FromMilliseconds(500)
    
    while ($true) {
        $now = Get-Date
        
        # Process messages from queue
        $message = $null
        while ($ProgressQueue.TryDequeue([ref]$message)) {
            switch ($message.Type) {
                'Component' {
                    switch ($message.Component) {
                        'Config' {
                            if (-not $timers.Config -and $message.Progress -gt 0) {
                                $timers.Config = Get-Date
                            }
                            $progressData.ConfigProgress = $message.Progress
                            $progressData.ConfigStatus = "$($message.Step) - $($message.Status)"
                        }
                        'App' {
                            if (-not $timers.App -and $message.Progress -gt 0) {
                                $timers.App = Get-Date
                            }
                            $progressData.AppProgress = $message.Progress
                            $progressData.AppStatus = "$($message.Step) - $($message.Status)"
                        }
                    }
                }
                
                'MiniserverTotal' {
                    $progressData.MiniserverCount = $message.Total
                }
                
                'MiniserverProgress' {
                    $progressData.MiniserverCompleted = $message.Completed
                    $progressData.MiniserverProgress = $message.Progress
                    if (-not $timers.Miniserver -and $message.Progress -gt 0) {
                        $timers.Miniserver = Get-Date
                    }
                }
                
                'Miniserver' {
                    if ($message.IP -and $message.Stage) {
                        $progressData.MiniserverDetails[$message.IP] = @{
                            Stage = $message.Stage
                        }
                    }
                }
                
                'Status' {
                    $progressData.StatusMessage = $message.Message
                }
                
                'Complete' {
                    $progressData.StatusMessage = "Update process completed!"
                    Show-ConsoleProgress -ProgressData $progressData
                    return
                }
            }
        }
        
        # Update elapsed times
        if ($timers.Config) {
            $elapsed = (Get-Date) - $timers.Config
            $progressData.ConfigElapsed = "{0:mm\:ss}" -f $elapsed
        }
        if ($timers.App) {
            $elapsed = (Get-Date) - $timers.App
            $progressData.AppElapsed = "{0:mm\:ss}" -f $elapsed
        }
        if ($timers.Miniserver) {
            $elapsed = (Get-Date) - $timers.Miniserver
            $progressData.MiniserverElapsed = "{0:mm\:ss}" -f $elapsed
        }
        
        # Calculate overall progress
        $totalProgress = 0
        $componentCount = 0
        
        if ($progressData.ConfigUpdate) {
            $totalProgress += $progressData.ConfigProgress
            $componentCount++
        }
        if ($progressData.AppUpdate) {
            $totalProgress += $progressData.AppProgress
            $componentCount++
        }
        if ($progressData.MiniserverCount -gt 0) {
            $totalProgress += $progressData.MiniserverProgress
            $componentCount++
        }
        
        if ($componentCount -gt 0) {
            $progressData.OverallProgress = [int]($totalProgress / $componentCount)
        }
        
        # Update display if enough time has passed
        if (($now - $lastUpdate) -ge $updateInterval) {
            Show-ConsoleProgress -ProgressData $progressData -ClearScreen
            $lastUpdate = $now
        }
        
        Start-Sleep -Milliseconds 100
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Get-ProgressBar'
    'Show-ConsoleProgress' 
    'Start-ConsoleProgressMonitor'
)