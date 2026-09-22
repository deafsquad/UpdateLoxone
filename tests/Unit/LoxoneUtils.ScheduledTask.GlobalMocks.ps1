# Global mocks for scheduled task operations to prevent parameter prompts

# Check if running in test mode
if (-not $env:PESTER_TEST_RUN) {
    $env:PESTER_TEST_RUN = "1"
}

# Create global mock functions that override the real cmdlets
if (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue) {
    # Save reference to real cmdlet if needed
    $Global:RealRegisterScheduledTask = Get-Command Register-ScheduledTask
    
    # Override with a function
    function global:Register-ScheduledTask {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskName,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [Microsoft.Management.Infrastructure.CimInstance[]]$Action,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [Microsoft.Management.Infrastructure.CimInstance[]]$Trigger,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [Microsoft.Management.Infrastructure.CimInstance]$Settings,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [Microsoft.Management.Infrastructure.CimInstance]$Principal,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskPath,
            
            [Parameter()]
            [switch]$Force
        )
        
        Write-Verbose "[GLOBAL-MOCK] Register-ScheduledTask called for task: $TaskName"
        
        # Return a mock task object
        return [PSCustomObject]@{
            TaskName = $TaskName
            TaskPath = if ($TaskPath) { $TaskPath } else { '\' }
            State = 'Ready'
            Enabled = $true
            PSTypeName = 'Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_ScheduledTask'
        }
    }
}

if (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue) {
    function global:Unregister-ScheduledTask {
        [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
        param(
            [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$TaskName,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskPath,
            
            [switch]$PassThru
        )
        
        Write-Verbose "[GLOBAL-MOCK] Unregister-ScheduledTask called for task: $TaskName"
        
        if ($PassThru) {
            return $true
        }
    }
}

if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    function global:Get-ScheduledTask {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskName,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskPath
        )
        
        Write-Verbose "[GLOBAL-MOCK] Get-ScheduledTask called for task: $TaskName"
        
        # Return null (no tasks found)
        return $null
    }
}

if (Get-Command Get-ScheduledTaskInfo -ErrorAction SilentlyContinue) {
    function global:Get-ScheduledTaskInfo {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            $InputObject,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskName,
            
            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [string]$TaskPath
        )
        
        Write-Verbose "[GLOBAL-MOCK] Get-ScheduledTaskInfo called"
        
        return [PSCustomObject]@{
            LastRunTime = (Get-Date).AddHours(-1)
            LastTaskResult = 0
            NumberOfMissedRuns = 0
            NextRunTime = (Get-Date).AddHours(1)
            PSTypeName = 'Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_TaskDynamicInfo'
        }
    }
}

Write-Host "Global scheduled task mocks loaded - no real scheduled tasks will be created or modified" -ForegroundColor Green
$Global:ScheduledTaskMocksLoaded = $true