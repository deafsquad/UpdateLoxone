# LoxoneUtils.ProgressReporter.psm1
# Module for unified progress reporting across sequential and parallel operations

<#
.SYNOPSIS
Creates a progress reporter script block for the current execution context

.DESCRIPTION
Returns a script block that can be used to report progress from any operation.
The implementation varies based on the execution context (sequential vs parallel).

.PARAMETER Context
The execution context - either 'Sequential' or 'Parallel'

.PARAMETER Pipeline
For parallel context, the pipeline object containing progress queue

.PARAMETER WorkerName
For parallel context, the name of the worker thread

.PARAMETER ActivityId
For sequential context, the Write-Progress activity ID
#>
function New-ProgressReporter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Sequential', 'Parallel')]
        [string]$Context,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Pipeline,
        
        [Parameter(Mandatory = $false)]
        [string]$WorkerName = "Worker",
        
        [Parameter(Mandatory = $false)]
        [int]$ActivityId = 0,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$ToastParams = @{}
    )
    
    switch ($Context) {
        'Sequential' {
            # Sequential mode - update Write-Progress and toast notifications
            $progressReporter = {
                param(
                    [string]$Operation,
                    [string]$Status,
                    [int]$PercentComplete = -1,
                    [string]$CurrentOperation = "",
                    [hashtable]$Details = @{},
                    [string]$Level = "INFO"
                )
                
                # Write to log
                if ($Status) {
                    Write-Log -Message "$Operation - $Status" -Level $Level
                }
                
                # Update Write-Progress
                if ($PercentComplete -ge 0) {
                    $progressParams = @{
                        Activity = $Operation
                        Status = $Status
                        PercentComplete = $PercentComplete
                    }
                    if ($CurrentOperation) {
                        $progressParams.CurrentOperation = $CurrentOperation
                    }
                    $localActivityId = $ActivityId
                    if ($localActivityId -gt 0) {
                        $progressParams.Id = $localActivityId
                    }
                    Write-Progress @progressParams
                }
                
                # Update toast notification if available
                $localToastParams = $ToastParams
                if ($localToastParams -and $localToastParams.Count -gt 0) {
                    $toastUpdateParams = $localToastParams.Clone()
                    $toastUpdateParams.ToastStatus = $Status
                    if ($PercentComplete -ge 0) {
                        $toastUpdateParams.ProgressValue = $PercentComplete / 100.0
                    }
                    try {
                        Update-PersistentToast @toastUpdateParams -CallingScriptIsInteractive $true
                    } catch {
                        # Toast update failed, continue
                    }
                }
            }.GetNewClosure()
        }
        
        'Parallel' {
            # Parallel mode - send to progress queue
            $progressReporter = {
                param(
                    [string]$Operation,
                    [string]$Status,
                    [int]$PercentComplete = -1,
                    [string]$CurrentOperation = "",
                    [hashtable]$Details = @{},
                    [string]$Level = "INFO"
                )
                
                # Send to worker log queue if available
                $localPipeline = $Pipeline
                $localWorkerName = $WorkerName
                if ($localPipeline -and $localPipeline.LogQueue) {
                    $logMessage = if ($CurrentOperation) {
                        "$Operation - $Status - $CurrentOperation"
                    } else {
                        "$Operation - $Status"
                    }
                    
                    Write-WorkerLog -LogQueue $localPipeline.LogQueue `
                                   -WorkerName $localWorkerName `
                                   -Message $logMessage `
                                   -Level $Level
                }
                
                # Send to progress queue
                if ($localPipeline -and $localPipeline.ProgressQueue) {
                    $progressUpdate = @{
                        Type = 'OperationProgress'
                        Operation = $Operation
                        Status = $Status
                        Progress = $PercentComplete
                        CurrentOperation = $CurrentOperation
                        Details = $Details
                        Timestamp = Get-Date
                        WorkerName = $localWorkerName
                    }
                    
                    [void]$localPipeline.ProgressQueue.Enqueue($progressUpdate)
                }
            }.GetNewClosure()
        }
    }
    
    return $progressReporter
}

<#
.SYNOPSIS
Wraps a long-running operation with progress reporting

.DESCRIPTION
Executes a script block while providing progress reporting capabilities.
Automatically handles setup and cleanup of progress reporting.

.PARAMETER Operation
The name of the operation being performed

.PARAMETER ScriptBlock
The script block to execute

.PARAMETER ProgressReporter
The progress reporter to use (from New-ProgressReporter)

.PARAMETER PassThru
If specified, returns the result of the script block
#>
function Invoke-WithProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProgressReporter,
        
        [switch]$PassThru
    )
    
    try {
        # Report operation start
        & $ProgressReporter -Operation $Operation -Status "Starting" -PercentComplete 0
        
        # Execute the script block with progress reporter available
        $result = & $ScriptBlock -ProgressReporter $ProgressReporter
        
        # Report operation complete
        & $ProgressReporter -Operation $Operation -Status "Completed" -PercentComplete 100
        
        if ($PassThru) {
            return $result
        }
    } catch {
        # Report operation failure
        & $ProgressReporter -Operation $Operation -Status "Failed: $_" -PercentComplete -1 -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
Creates a progress tracker for operations with known item counts

.DESCRIPTION
Helper function to track progress through a list of items, automatically
calculating percentage complete and estimated time remaining.

.PARAMETER TotalItems
The total number of items to process

.PARAMETER ProgressReporter
The progress reporter to use for updates
#>
function New-ProgressTracker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TotalItems,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProgressReporter,
        
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )
    
    $tracker = [PSCustomObject]@{
        TotalItems = $TotalItems
        ProcessedItems = 0
        StartTime = Get-Date
        ProgressReporter = $ProgressReporter
        Operation = $Operation
    }
    
    # Add Update method
    Add-Member -InputObject $tracker -MemberType ScriptMethod -Name Update -Value {
        param(
            [string]$Status,
            [string]$CurrentItem = ""
        )
        
        $this.ProcessedItems++
        $percentComplete = [Math]::Round(($this.ProcessedItems / $this.TotalItems) * 100, 0)
        
        # Calculate ETA
        $elapsed = (Get-Date) - $this.StartTime
        if ($this.ProcessedItems -gt 0) {
            $avgTimePerItem = $elapsed.TotalSeconds / $this.ProcessedItems
            $remainingItems = $this.TotalItems - $this.ProcessedItems
            $remainingSeconds = $avgTimePerItem * $remainingItems
            $eta = (Get-Date).AddSeconds($remainingSeconds)
            $etaString = " (ETA: {0:HH:mm:ss})" -f $eta
        } else {
            $etaString = ""
        }
        
        $fullStatus = "$Status$etaString"
        
        & $this.ProgressReporter -Operation $this.Operation `
                                -Status $fullStatus `
                                -PercentComplete $percentComplete `
                                -CurrentOperation $CurrentItem
    }
    
    return $tracker
}

# Export functions
Export-ModuleMember -Function @(
    'New-ProgressReporter',
    'Invoke-WithProgress',
    'New-ProgressTracker'
)