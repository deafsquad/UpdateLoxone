# Mock suite for LoxoneUtils.System module
# This file contains all mocks needed to prevent real system operations during tests
# Note: Module must be imported BEFORE sourcing this file

# Create reusable mock implementations
$mockGetProcessStatus = {
    param($ProcessName, [switch]$StopProcess)
    return @{
        ConfigRunning = $false
        MonitorRunning = $false
        LiveViewRunning = $false
    }
}

$mockRegisterScheduledTaskForScript = {
    param($ScriptPath, $TaskName, $Description, $RunLevel, $Trigger)
    # Return mock task object
    return @{
        TaskName = $TaskName
        State = 'Ready'
        Enabled = $true
        Success = $true
    }
}

$mockStartProcessInteractive = {
    param($FilePath, $ArgumentList, $WorkingDirectory)
    # Return mock process object
    return @{
        Id = Get-Random
        ProcessName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        ExitCode = 0
    }
}

$mockTestLoxoneScheduledTaskExists = {
    param($TaskName)
    # Return false - no scheduled tasks in test environment
    return $false
}

$mockTestScheduledTask = {
    param($TaskName)
    # Return false - no scheduled tasks in test environment
    return $false
}

# Apply mocks both module-scoped and globally
Mock -ModuleName LoxoneUtils.System Get-ProcessStatus $mockGetProcessStatus
Mock Get-ProcessStatus $mockGetProcessStatus

Mock -ModuleName LoxoneUtils.System Register-ScheduledTaskForScript $mockRegisterScheduledTaskForScript
Mock Register-ScheduledTaskForScript $mockRegisterScheduledTaskForScript

Mock -ModuleName LoxoneUtils.System Start-ProcessInteractive $mockStartProcessInteractive
Mock Start-ProcessInteractive $mockStartProcessInteractive

Mock -ModuleName LoxoneUtils.System Test-LoxoneScheduledTaskExists $mockTestLoxoneScheduledTaskExists
Mock Test-LoxoneScheduledTaskExists $mockTestLoxoneScheduledTaskExists

Mock -ModuleName LoxoneUtils.System Test-ScheduledTask $mockTestScheduledTask
Mock Test-ScheduledTask $mockTestScheduledTask

# Mock underlying system cmdlets that are used by the module
$mockGetScheduledTask = {
    param($TaskName, $ErrorAction)
    # Return null - no scheduled tasks in test environment
    return $null
}

$mockRegisterScheduledTask = {
    param($TaskName, $Action, $Trigger, $Settings, $Principal, $Description, $Force)
    # Return mock task object
    return @{
        TaskName = $TaskName
        State = 'Ready'
        Enabled = $true
    }
}

$mockUnregisterScheduledTask = {
    param($TaskName, $Confirm, $ErrorAction)
    # Do nothing - no real task to unregister
}

$mockGetScheduledTaskInfo = {
    param($TaskName, $ErrorAction)
    return @{
        LastRunTime = (Get-Date).AddHours(-1)
        LastTaskResult = 0
        NumberOfMissedRuns = 0
    }
}

$mockGetProcess = {
    param($Name, $ErrorAction)
    # Return empty - no processes running
    return @()
}

$mockStopProcess = {
    param($Name, $Id, $Force, $ErrorAction)
    # Do nothing - don't kill real processes
}

$mockStartProcess = {
    param($FilePath, $ArgumentList, $Wait, $NoNewWindow, $PassThru)
    # Return mock process object
    return @{
        Id = Get-Random
        ProcessName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        ExitCode = 0
    }
}

# Mock Windows cmdlets
Mock -ModuleName LoxoneUtils.System Get-ScheduledTask $mockGetScheduledTask
Mock Get-ScheduledTask $mockGetScheduledTask

Mock -ModuleName LoxoneUtils.System Register-ScheduledTask $mockRegisterScheduledTask
Mock Register-ScheduledTask $mockRegisterScheduledTask

Mock -ModuleName LoxoneUtils.System Unregister-ScheduledTask $mockUnregisterScheduledTask
Mock Unregister-ScheduledTask $mockUnregisterScheduledTask

Mock -ModuleName LoxoneUtils.System Get-ScheduledTaskInfo $mockGetScheduledTaskInfo
Mock Get-ScheduledTaskInfo $mockGetScheduledTaskInfo

Mock -ModuleName LoxoneUtils.System Get-Process $mockGetProcess
Mock Get-Process $mockGetProcess

Mock -ModuleName LoxoneUtils.System Stop-Process $mockStopProcess
Mock Stop-Process $mockStopProcess

Mock -ModuleName LoxoneUtils.System Start-Process $mockStartProcess
Mock Start-Process $mockStartProcess

# Export a flag indicating mocks are loaded
$Global:SystemMocksLoaded = $true

# Suppress mock loading messages in parallel/CI mode to reduce noise
if (-not $env:CI -and -not $env:LOXONE_PARALLEL_MODE) {
    Write-Host "System module mocks loaded - no real system operations will occur" -ForegroundColor Green
}
