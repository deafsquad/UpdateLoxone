# Mock-ScheduledTasks.ps1
# Provides mock implementations for ScheduledTasks module cmdlets to avoid PowerShell 7 timeout issues

# Mock Get-ScheduledTask globally to avoid timeout issues
if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    function Global:Get-ScheduledTask {
        [CmdletBinding()]
        param(
            [string]$TaskName,
            [string]$TaskPath = "\"
        )
        # Return null by default (task not found)
        return $null
    }
}

# Mock other ScheduledTasks cmdlets if needed
if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
    function Global:Register-ScheduledTask {
        [CmdletBinding()]
        param(
            [string]$TaskName,
            $Action,
            $Trigger,
            $Principal,
            $Settings,
            [string]$Description
        )
        # Return a mock task object
        return [PSCustomObject]@{
            TaskName = $TaskName
            TaskPath = "\"
            State = "Ready"
        }
    }
}

if (-not (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue)) {
    function Global:Unregister-ScheduledTask {
        [CmdletBinding()]
        param(
            [string]$TaskName,
            [switch]$Confirm
        )
        # Do nothing
    }
}

if (-not (Get-Command New-ScheduledTaskAction -ErrorAction SilentlyContinue)) {
    function Global:New-ScheduledTaskAction {
        [CmdletBinding()]
        param(
            [string]$Execute,
            [string]$Argument
        )
        return [PSCustomObject]@{
            Execute = $Execute
            Arguments = $Argument
        }
    }
}

if (-not (Get-Command New-ScheduledTaskTrigger -ErrorAction SilentlyContinue)) {
    function Global:New-ScheduledTaskTrigger {
        [CmdletBinding()]
        param(
            [switch]$Once,
            [datetime]$At,
            [timespan]$RepetitionInterval
        )
        return [PSCustomObject]@{
            Repetition = [PSCustomObject]@{
                Interval = "PT$([int]$RepetitionInterval.TotalMinutes)M"
            }
        }
    }
}

if (-not (Get-Command New-ScheduledTaskPrincipal -ErrorAction SilentlyContinue)) {
    function Global:New-ScheduledTaskPrincipal {
        [CmdletBinding()]
        param(
            [string]$UserId,
            [string]$LogonType,
            [string]$RunLevel
        )
        return [PSCustomObject]@{
            UserId = $UserId
            LogonType = $LogonType
            RunLevel = $RunLevel
        }
    }
}

if (-not (Get-Command New-ScheduledTaskSettingsSet -ErrorAction SilentlyContinue)) {
    function Global:New-ScheduledTaskSettingsSet {
        [CmdletBinding()]
        param()
        
        $settings = [PSCustomObject]@{
            MultipleInstances = 'IgnoreNew'
            StartWhenAvailable = $true
            Hidden = $true
            ExecutionTimeLimit = [System.TimeSpan]::Zero
        }
        
        # Add dynamic properties
        Add-Member -InputObject $settings -MemberType NoteProperty -Name DisallowStartIfOnBatteries -Value $false
        Add-Member -InputObject $settings -MemberType NoteProperty -Name StopIfGoingOnBatteries -Value $false
        Add-Member -InputObject $settings -MemberType NoteProperty -Name AllowHardTerminate -Value $true
        Add-Member -InputObject $settings -MemberType NoteProperty -Name RunOnlyIfNetworkAvailable -Value $false
        Add-Member -InputObject $settings -MemberType NoteProperty -Name Enabled -Value $true
        
        return $settings
    }
}

Write-Host "ScheduledTasks mock functions loaded globally" -ForegroundColor Green