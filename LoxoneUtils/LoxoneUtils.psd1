@{
# Script module or binary module file associated with this manifest.
# RootModule is empty because we are using NestedModules
RootModule = 'LoxoneUtils.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# ID used to uniquely identify this module
GUID = '{00000000-0000-0000-0000-000000000001}' # Placeholder GUID - Generate a real one if needed

# Author of this module
Author = 'Refactored by Roo'

# Company or vendor of this module
CompanyName = 'Unknown'

# Copyright statement for this module
Copyright = '(c) 2025. All rights reserved.' # Update year if necessary

# Description of the functionality provided by this module
Description = 'Utility functions for the Loxone Update Script, refactored into multiple modules.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'
# External modules required by this module
# RequiredModules = @('BurntToast') # Temporarily commented out, handled by main script

# Scripts to run when module is imported
ScriptsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# List all script modules (.psm1 files) that are part of this module
NestedModules = @(
'.\LoxoneUtils.Utility.psm1',
    '.\LoxoneUtils.Logging.psm1',
    '.\LoxoneUtils.Toast.psm1',
    '.\LoxoneUtils.Network.psm1',
    '.\LoxoneUtils.ErrorHandling.psm1',
    '.\LoxoneUtils.Installation.psm1',
    '.\LoxoneUtils.CertificateHelper.psm1',
    '.\LoxoneUtils.Miniserver.psm1',
    '.\LoxoneUtils.RunAsUser.psm1',
    '.\LoxoneUtils.System.psm1',
    '.\LoxoneUtils.UpdateCheck.psm1',
    '.\LoxoneUtils.WorkflowSteps.psm1',
    '.\LoxoneUtils.TestCoverage.psm1',
    '.\LoxoneUtils.TestTracking.psm1',
    '.\LoxoneUtils.ParallelWorkflow.psm1',
    '.\LoxoneUtils.ConsoleProgress.psm1',
    '.\LoxoneUtils.ThreadSafe.psm1',
    '.\LoxoneUtils.ProgressReporter.psm1',
    '.\LoxoneUtils.MiniserverCache.psm1',
    '.\LoxoneUtils.NetworkCore.psm1',
    '.\LoxoneUtils.MiniserverHardware.psm1',
    '.\LoxoneUtils.MiniserverGeneration.psm1',
    '.\LoxoneUtils.Monitor.psm1'
)
# Functions to export from this module
    FunctionsToExport = @(
        # LoxoneUtils.ErrorHandling.psm1
        'Invoke-ScriptErrorHandling',
        
        # LoxoneUtils.CertificateHelper.psm1
        'Set-CertificateValidationBypass',
        'Clear-CertificateValidationBypass',
        
        # LoxoneUtils.Installation.psm1
        'Get-InstalledApplicationPath',
        'Get-InstalledVersion',
        'Get-LoxoneExePath',
        'Invoke-ZipFileExtraction',
        'Start-LoxoneForWindowsInstaller',
        'Start-LoxoneUpdateInstaller',
        'Test-ExistingInstaller',
        
        # LoxoneUtils.Logging.psm1
        'Enter-Function',
        'Exit-Function',
        'Invoke-LogFileRotation',
        'Write-Log',
        
        # LoxoneUtils.Miniserver.psm1
        'Get-MiniserverVersion',
        'Invoke-MiniserverWebRequest',
        'Invoke-MSUpdate',
        'Test-LoxoneMiniserverUpdateLevel',
        'Update-MS',
        
        # LoxoneUtils.Network.psm1
        'Format-Bytes',
        'Invoke-LoxoneDownload',
        'Wait-ForPingSuccess',
        'Wait-ForPingTimeout',
        'Test-MiniserverConnectivity',
        
        # LoxoneUtils.RunAsUser.psm1
        'Invoke-AsCurrentUser',
        
        # LoxoneUtils.System.psm1
        'Get-ProcessStatus',
        'Register-ScheduledTaskForScript',
        'Start-ProcessInteractive',
        'Test-LoxoneScheduledTaskExists',
        'Test-ScheduledTask',
        
        # LoxoneUtils.Toast.psm1
        'Get-LoxoneToastAppId',
        'Initialize-LoxoneToastAppId',
        'Show-FinalStatusToast',
        'Update-PersistentToast',
        'Initialize-Toast',
        'Update-Toast',
        
        # LoxoneUtils.UpdateCheck.psm1
        'Get-LoxoneUpdateData',
        'Get-UpdateStatusFromComparison',
        'New-LoxoneComponentStatusObject',
        'Test-LoxoneAppComponent',
        'Test-LoxoneConfigComponent',
        'Test-UpdateNeeded',
        
        # LoxoneUtils.Utility.psm1
        'Convert-VersionString',
        'ConvertTo-Expression',
        'Format-TimeSpanFromSeconds',
        'Get-AppVersionFromRegistry',
        'Get-CRC32',
        'Get-ExecutableSignature',
        'Get-InvocationTrace',
        'Get-RedactedPassword',
        'Initialize-CRC32Type',
        'Test-ExistingFile',
        
        # LoxoneUtils.WorkflowSteps.psm1
        'Get-LoxoneUpdatePrerequisites',
        'Get-StepWeight',
        'Initialize-ScriptWorkflow',
        'Initialize-UpdatePipelineData',
        'Invoke-CheckMiniserverVersions',
        'Invoke-DownloadLoxoneApp',
        'Invoke-DownloadLoxoneConfig',
        'Invoke-ExtractLoxoneConfig',
        'Invoke-InstallLoxoneApp',
        'Invoke-InstallLoxoneConfig',
        'Invoke-UpdateMiniserversInBulk',
        'Test-PipelineStepShouldRun',
        
        # LoxoneUtils.TestCoverage.psm1
        'Get-TestCoverage',
        'Get-TestResults',
        'New-TestCoverageReport',
        'Test-CoverageCompliance',
        'Get-ComplianceViolations',
        'Get-ChangedFunctions',
        'Test-NewCodeCompliance',
        
        # LoxoneUtils.TestTracking.psm1
        'Enable-AssertionTracking',
        'Disable-AssertionTracking',
        'Set-TestContext','Get-TestAssertionResults',
        'Export-TestAssertionResults','Get-CachedAssertionResults',
        'Set-CachedAssertionResults',
        'Import-AssertionResults',
        'Merge-AssertionResults',
        'Find-AssertionMatch',
        'Get-AssertionMatchReport',
        'Get-AssertionPerformanceMetrics',
        'Export-AssertionPerformanceReport',
        
        # LoxoneUtils.ParallelWorkflow.psm1
        'Start-ParallelWorkflow',
        'Remove-ThreadJobs',
        'Write-WorkerLog',
        'Start-ProgressWorker',
        'Start-InstallWorker',
        'Start-MiniserverWorker',
        'Watch-DirectThreadJobs',
        'Initialize-ProgressTracking',
        'Update-MiniserverProgress',
        
        # LoxoneUtils.ConsoleProgress.psm1
        'Get-ProgressBar',
        'Show-ConsoleProgress',
        'Start-ConsoleProgressMonitor',
        
        # LoxoneUtils.ThreadSafe.psm1
        'Initialize-WorkflowStateMutex',
        'Update-WorkflowState',
        'Get-WorkflowState',
        'Remove-WorkflowStateMutex',
        
        # LoxoneUtils.ProgressReporter.psm1
        'New-ProgressReporter',
        'Invoke-WithProgress',
        'New-ProgressTracker',
        
        # LoxoneUtils.MiniserverCache.psm1
        'ConvertFrom-MiniserverListEntry',
        'Test-MiniserverCacheValid',
        'Update-MiniserverListCache',
        'Get-MiniserverListWithCache',
        
        # LoxoneUtils.MiniserverHardware.psm1
        'Get-MiniserverHardwareInfo',
        'Get-MiniserverGeneration',
        'Test-MiniserverRequiresHTTPS',
        
        # LoxoneUtils.MiniserverGeneration.psm1
        'Get-MiniserverGenerationInfo',
        'Update-MiniserverGenerationCache',
        
        # LoxoneUtils.NetworkCore.psm1
        'Initialize-NetworkCore',
        'Invoke-NetworkRequest',
        'Test-NetworkEndpoint',
        'Test-FastNetworkEndpoint',
        'Test-StandardNetworkEndpoint',
        'Clear-NetworkCore',

        # LoxoneUtils.Monitor.psm1
        'Find-LoxoneMonitorExe',
        'Start-LoxoneMonitorProcess',
        'Stop-LoxoneMonitorProcess',
        'Enable-MiniserverLogging',
        'Disable-MiniserverLogging',
        'Get-LocalIPAddress',
        'Find-LxmonFiles',
        'Watch-MonitorLogs',
        'Remove-OldMonitorLogs'
    )
# Cmdlets to export from this module
CmdletsToExport = @() # Explicitly export no cmdlets

# Variables to export from this module
VariablesToExport = @() # Explicitly export no variables

# Aliases to export from this module
AliasesToExport = @() # Explicitly export no aliases

}