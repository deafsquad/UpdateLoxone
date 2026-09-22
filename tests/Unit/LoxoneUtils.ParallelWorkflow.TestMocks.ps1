# Shared mocks for parallel workflow tests - PS7 compatible version
# This file contains all the dangerous operations that must be mocked during tests

# Ensure modules are loaded
$modulePath = Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot)) "LoxoneUtils") "LoxoneUtils.psd1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}

# Create global function overrides that work across runspaces
# These replace the actual functions in the global scope

function global:Start-ProgressWorker {
    param([hashtable]$Pipeline, [hashtable]$WorkflowDefinition)
    
    return [PSCustomObject]@{
        Id = Get-Random
        Name = "Progress-Worker-Mock"
        State = 'Completed'
        HasMoreData = $false
        PSJobTypeName = 'ThreadJob'
    }
}

function global:Start-ComponentDownloadWorker {
    param([hashtable]$Pipeline, [string]$Component, [hashtable]$DownloadInfo)
    
    # Add success result to pipeline
    if ($Pipeline.Results) {
        $Pipeline.Results.Add(@{
            Type = 'Download'
            Component = $Component
            Success = $true
            FilePath = "C:\temp\mock_$Component.zip"
            Duration = 1
        })
    }
    
    # Add to install queue
    if ($Pipeline.InstallQueue) {
        $Pipeline.InstallQueue.Enqueue(@{
            Component = $Component
            FilePath = "C:\temp\mock_$Component.zip"
            TargetVersion = if ($DownloadInfo.TargetVersion) { $DownloadInfo.TargetVersion } else { [version]"14.0.0.0" }
        })
    }
    
    return [PSCustomObject]@{
        Id = Get-Random
        Name = "$Component-Download-Mock"
        State = 'Completed'
        HasMoreData = $false
        PSJobTypeName = 'ThreadJob'
    }
}

function global:Start-InstallWorker {
    param([hashtable]$Pipeline, [int]$MaxConcurrency, [array]$DownloadWorkers)
    
    # Process any items in install queue
    if ($Pipeline.InstallQueue) {
        $item = $null
        while ($Pipeline.InstallQueue.TryDequeue([ref]$item)) {
            if ($Pipeline.Results) {
                $Pipeline.Results.Add(@{
                    Type = 'Install'
                    Component = $item.Component
                    Success = $true
                    Duration = 0.5
                })
            }
        }
    }
    
    return [PSCustomObject]@{
        Id = Get-Random
        Name = "Install-Worker-Mock"
        State = 'Completed'
        HasMoreData = $false
        PSJobTypeName = 'ThreadJob'
    }
}

function global:Start-MiniserverWorker {
    param([hashtable]$WorkflowDefinition, [hashtable]$Pipeline, [int]$MaxConcurrency)
    
    if (-not $WorkflowDefinition.MiniserverUpdates -or $WorkflowDefinition.MiniserverUpdates.Count -eq 0) {
        return $null
    }
    
    # Add mock results for each miniserver
    foreach ($ms in $WorkflowDefinition.MiniserverUpdates) {
        if ($Pipeline.Results) {
            $Pipeline.Results.Add(@{
                Type = 'Miniserver'
                IP = $ms.IP
                Success = $true
                Duration = 1
            })
        }
    }
    
    return [PSCustomObject]@{
        Id = Get-Random
        Name = "Miniserver-Worker-Mock"
        State = 'Completed'
        HasMoreData = $false
        PSJobTypeName = 'ThreadJob'
    }
}

# Use Pester Mock without -ModuleName for better PS7 compatibility
if (Get-Command Mock -ErrorAction SilentlyContinue) {
    # Mock installations to prevent real software being installed
    Mock Start-LoxoneUpdateInstaller {
        param($MSIPath)
        return @{
            Succeeded = $true
            Message = "MOCK: Installation simulated for $MSIPath"
        }
    }

    Mock Start-LoxoneForWindowsInstaller {
        param($MSIPath)
        return @{
            Succeeded = $true
            Message = "MOCK: App installation simulated for $MSIPath"
        }
    }

    # Mock toast notifications to prevent real popups
    Mock Update-PersistentToast {
        param($StepName, $StatusMessage, $ProgressValue)
        # Silently succeed - no real toast
    }

    Mock Show-FinalStatusToast {
        param($StatusMessage, $Success, $LogFileToShow)
        # Silently succeed - no real toast
    }

    Mock New-BurntToastNotification {
        # Silently succeed - no real toast
    }

    # Mock file extraction to prevent real zip operations
    Mock Invoke-ZipFileExtraction {
        param($ZipFilePath, $DestinationPath)
        return @{
            Succeeded = $true
            ExtractedPath = $DestinationPath
        }
    }

    # Mock download operations to prevent real network calls
    Mock Invoke-LoxoneDownload {
        param($Url, $OutFile, $ExpectedSize, $ExpectedCRC32)
        
        # Create a mock file
        if ($OutFile) {
            Set-Content -Path $OutFile -Value "MOCK DOWNLOAD CONTENT"
        }
        
        return @{
            Succeeded = $true
            FilePath = $OutFile
        }
    }

    # Mock process status checking
    Mock Get-ProcessStatus {
        return @{
            ConfigRunning = $false
            MonitorRunning = $false
            LiveViewRunning = $false
        }
    }

    # Mock miniserver updates to prevent real device updates
    Mock Invoke-MSUpdate {
        param($URL, $Credential)
        return @{
            Succeeded = $true
            Message = "MOCK: Update triggered for $URL"
        }
    }

    # Mock miniserver version checking
    Mock Get-MiniserverVersion {
        param($URL, $Credential)
        return [version]"14.0.0.0"
    }

    # Mock scheduled task operations
    Mock Get-ScheduledTask {
        return $null  # No scheduled tasks exist
    }

    Mock Get-ScheduledTaskInfo {
        return $null
    }

    Mock Register-ScheduledTask {
        # Silently succeed - don't create real scheduled tasks
    }

    Mock Unregister-ScheduledTask {
        # Silently succeed
    }

    # Mock job cmdlets
    Mock Wait-Job {
        param($Job, [switch]$Any)
        return $Job
    }

    Mock Receive-Job {
        param($Job, [switch]$Keep, [switch]$Wait)
        return @()
    }

    Mock Remove-Job {
        param($Job, [switch]$Force)
        # Do nothing
    }

    Mock Stop-Job {
        param($Job)
        # Do nothing
    }
} else {
    # When Mock command is not available, create global function overrides
    function global:Start-LoxoneUpdateInstaller {
        param($MSIPath)
        return @{
            Succeeded = $true
            Message = "MOCK: Installation simulated for $MSIPath"
        }
    }

    function global:Start-LoxoneForWindowsInstaller {
        param($MSIPath)
        return @{
            Succeeded = $true
            Message = "MOCK: App installation simulated for $MSIPath"
        }
    }

    function global:Update-PersistentToast {
        param($StepName, $StatusMessage, $ProgressValue)
        # Silently succeed - no real toast
    }

    function global:Show-FinalStatusToast {
        param($StatusMessage, $Success, $LogFileToShow)
        # Silently succeed - no real toast
    }

    function global:Invoke-ZipFileExtraction {
        param($ZipFilePath, $DestinationPath)
        return @{
            Succeeded = $true
            ExtractedPath = $DestinationPath
        }
    }

    function global:Invoke-LoxoneDownload {
        param($Url, $OutFile, $ExpectedSize, $ExpectedCRC32)
        
        # Create a mock file
        if ($OutFile) {
            Set-Content -Path $OutFile -Value "MOCK DOWNLOAD CONTENT"
        }
        
        return @{
            Succeeded = $true
            FilePath = $OutFile
        }
    }

    function global:Get-ProcessStatus {
        return @{
            ConfigRunning = $false
            MonitorRunning = $false
            LiveViewRunning = $false
        }
    }

    function global:Invoke-MSUpdate {
        param($URL, $Credential)
        return @{
            Succeeded = $true
            Message = "MOCK: Update triggered for $URL"
        }
    }

    function global:Get-MiniserverVersion {
        param($URL, $Credential)
        return [version]"14.0.0.0"
    }

    function global:Wait-Job {
        param($Job, [switch]$Any)
        return $Job
    }

    function global:Receive-Job {
        param($Job, [switch]$Keep, [switch]$Wait)
        return @()
    }

    function global:Remove-Job {
        param($Job, [switch]$Force)
        # Do nothing
    }

    function global:Stop-Job {
        param($Job)
        # Do nothing
    }
}

Write-Host "Test safety mocks loaded - PS7 compatible version" -ForegroundColor Green
