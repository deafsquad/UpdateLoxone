# Thread-safe workflow state management module

# Create a named mutex for workflow state synchronization
$script:WorkflowStateMutex = $null
$script:WorkflowStateMutexName = "Global\LoxoneUpdateWorkflowStateMutex"

function Initialize-WorkflowStateMutex {
    [CmdletBinding()]
    param()
    
    try {
        # Create or open the named mutex
        $script:WorkflowStateMutex = New-Object System.Threading.Mutex($false, $script:WorkflowStateMutexName)
        Write-Log "Workflow state mutex initialized: $script:WorkflowStateMutexName" -Level "DEBUG"
        return $true
    }
    catch {
        Write-Log "Failed to initialize workflow state mutex: $_" -Level "ERROR"
        return $false
    }
}

function Update-WorkflowState {
    <#
    .SYNOPSIS
    Thread-safe update of workflow state with mutex protection
    
    .DESCRIPTION
    Updates the workflow state in a thread-safe manner using a named mutex.
    This ensures that multiple threads/processes can safely update the shared state.
    
    .PARAMETER State
    The workflow state hashtable to update
    
    .PARAMETER Updates
    Hashtable of updates to apply to the state
    
    .PARAMETER Component
    Optional component name for targeted updates
    
    .PARAMETER Property
    Optional property name for targeted updates
    
    .PARAMETER Value
    The value to set for the specified property
    
    .EXAMPLE
    Update-WorkflowState -State $workflowState -Updates @{ Status = 'Running'; Progress = 50 }
    
    .EXAMPLE
    Update-WorkflowState -State $workflowState -Component 'Config' -Property 'Status' -Value 'Completed'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,
        
        [Parameter(ParameterSetName = 'Bulk')]
        [hashtable]$Updates,
        
        [Parameter(ParameterSetName = 'Targeted')]
        [string]$Component,
        
        [Parameter(ParameterSetName = 'Targeted')]
        [string]$Property,
        
        [Parameter(ParameterSetName = 'Targeted')]
        $Value
    )
    
    # Initialize mutex if not already done
    if (-not $script:WorkflowStateMutex) {
        if (-not (Initialize-WorkflowStateMutex)) {
            Write-Warning "Unable to initialize mutex, performing non-thread-safe update"
            # Fallback to non-thread-safe update
            if ($PSCmdlet.ParameterSetName -eq 'Bulk') {
                foreach ($key in $Updates.Keys) {
                    $State[$key] = $Updates[$key]
                }
            } else {
                if ($Component) {
                    if (-not $State.ContainsKey($Component)) {
                        $State[$Component] = @{}
                    }
                    $State[$Component][$Property] = $Value
                } else {
                    $State[$Property] = $Value
                }
            }
            return
        }
    }
    
    $acquired = $false
    $timeout = [TimeSpan]::FromSeconds(5)
    
    try {
        # Try to acquire the mutex with timeout
        Write-Log "Attempting to acquire workflow state mutex..." -Level "DEBUG"
        $acquired = $script:WorkflowStateMutex.WaitOne($timeout)
        
        if (-not $acquired) {
            Write-Warning "Failed to acquire workflow state mutex within timeout ($($timeout.TotalSeconds)s)"
            throw "Mutex acquisition timeout"
        }
        
        Write-Log "Workflow state mutex acquired" -Level "DEBUG"
        
        # Perform the state update
        if ($PSCmdlet.ParameterSetName -eq 'Bulk') {
            # Bulk update
            foreach ($key in $Updates.Keys) {
                $oldValue = $State[$key]
                $State[$key] = $Updates[$key]
                Write-Log "Updated workflow state: $key = $($Updates[$key]) (was: $oldValue)" -Level "DEBUG"
            }
        } else {
            # Targeted update
            if ($Component) {
                # Component-specific update
                if (-not $State.ContainsKey($Component)) {
                    $State[$Component] = @{}
                    Write-Log "Created new component state: $Component" -Level "DEBUG"
                }
                
                $oldValue = $State[$Component][$Property]
                $State[$Component][$Property] = $Value
                Write-Log "Updated workflow state: $Component.$Property = $Value (was: $oldValue)" -Level "DEBUG"
            } else {
                # Direct property update
                $oldValue = $State[$Property]
                $State[$Property] = $Value
                Write-Log "Updated workflow state: $Property = $Value (was: $oldValue)" -Level "DEBUG"
            }
        }
        
        Write-Log "Workflow state update completed successfully" -Level "DEBUG"
    }
    catch {
        Write-Log "Error updating workflow state: $_" -Level "ERROR"
        throw
    }
    finally {
        if ($acquired) {
            try {
                $script:WorkflowStateMutex.ReleaseMutex()
                Write-Log "Workflow state mutex released" -Level "DEBUG"
            }
            catch {
                Write-Log "Error releasing workflow state mutex: $_" -Level "ERROR"
            }
        }
    }
}

function Get-WorkflowState {
    <#
    .SYNOPSIS
    Thread-safe read of workflow state with mutex protection
    
    .DESCRIPTION
    Reads the workflow state in a thread-safe manner using a named mutex.
    
    .PARAMETER State
    The workflow state hashtable to read from
    
    .PARAMETER Component
    Optional component name to get specific component state
    
    .PARAMETER Property
    Optional property name to get specific property value
    
    .EXAMPLE
    $currentState = Get-WorkflowState -State $workflowState
    
    .EXAMPLE
    $configStatus = Get-WorkflowState -State $workflowState -Component 'Config' -Property 'Status'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,
        
        [string]$Component,
        
        [string]$Property
    )
    
    # Initialize mutex if not already done
    if (-not $script:WorkflowStateMutex) {
        if (-not (Initialize-WorkflowStateMutex)) {
            Write-Warning "Unable to initialize mutex, performing non-thread-safe read"
            # Fallback to non-thread-safe read
            if ($Component) {
                if ($Property) {
                    return $State[$Component][$Property]
                } else {
                    return $State[$Component]
                }
            } elseif ($Property) {
                return $State[$Property]
            } else {
                return $State.Clone()
            }
        }
    }
    
    $acquired = $false
    $timeout = [TimeSpan]::FromSeconds(5)
    $result = $null
    
    try {
        # Try to acquire the mutex with timeout
        $acquired = $script:WorkflowStateMutex.WaitOne($timeout)
        
        if (-not $acquired) {
            Write-Warning "Failed to acquire workflow state mutex for read within timeout"
            throw "Mutex acquisition timeout"
        }
        
        # Read the state
        if ($Component) {
            if ($Property) {
                $result = $State[$Component][$Property]
            } else {
                # Clone the component hashtable
                $result = if ($State[$Component]) { $State[$Component].Clone() } else { $null }
            }
        } elseif ($Property) {
            $result = $State[$Property]
        } else {
            # Clone the entire state
            $result = $State.Clone()
        }
        
        return $result
    }
    catch {
        Write-Log "Error reading workflow state: $_" -Level "ERROR"
        throw
    }
    finally {
        if ($acquired) {
            try {
                $script:WorkflowStateMutex.ReleaseMutex()
            }
            catch {
                Write-Log "Error releasing workflow state mutex: $_" -Level "ERROR"
            }
        }
    }
}

function Remove-WorkflowStateMutex {
    <#
    .SYNOPSIS
    Cleanup workflow state mutex
    
    .DESCRIPTION
    Releases and disposes of the workflow state mutex
    #>
    [CmdletBinding()]
    param()
    
    if ($script:WorkflowStateMutex) {
        try {
            $script:WorkflowStateMutex.Dispose()
            $script:WorkflowStateMutex = $null
            Write-Log "Workflow state mutex disposed" -Level "DEBUG"
        }
        catch {
            Write-Log "Error disposing workflow state mutex: $_" -Level "ERROR"
        }
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-WorkflowStateMutex'
    'Update-WorkflowState'
    'Get-WorkflowState'
    'Remove-WorkflowStateMutex'
)