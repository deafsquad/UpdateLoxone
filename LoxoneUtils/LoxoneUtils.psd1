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
RequiredModules = @('BurntToast')

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# List all script modules (.psm1 files) that are part of this module
NestedModules = @(
'.\LoxoneUtils.Utility.psm1',
    '.\LoxoneUtils.Logging.psm1',
    '.\LoxoneUtils.Toast.psm1',
    '.\LoxoneUtils.Network.psm1',
    '.\LoxoneUtils.ErrorHandling.psm1',
    '.\LoxoneUtils.Installation.psm1',
    '.\LoxoneUtils.Miniserver.psm1',
    '.\LoxoneUtils.RunAsUser.psm1',
    '.\LoxoneUtils.System.psm1',
    '.\LoxoneUtils.UpdateCheck.psm1',
    '.\LoxoneUtils.WorkflowSteps.psm1'
)
# Functions to export from this module
FunctionsToExport = @(
    # ErrorHandling
    'Invoke-ScriptErrorHandling', # Corrected name
    # Installation
    'Get-InstalledVersion',
    'Get-AppVersionFromRegistry', # Corrected function name
    'Start-LoxoneUpdateInstaller',
    'Start-LoxoneForWindowsInstaller',
    'Get-InstalledApplicationPath',
    'Get-LoxoneExePath',
    'Invoke-ZipFileExtraction',
    'Expand-LoxoneConfigArchive', # Added
    'Install-LoxoneConfig',       # Added
    'Install-LoxoneApp',          # Added
    # Logging
    # Logging
    'Write-Log',                  # Added missing function
    'Enter-Function',             # Keep original name for now, will replace later
    'Exit-Function',              # Keep original name for now, will replace later
    'Invoke-LogFileRotation',
    # Miniserver
    'Update-MS',
    'Get-MiniserverVersion',      # Added missing function (Removed duplicate below)
    'Invoke-MiniserverUpdate',
    'Invoke-MiniserverUpdateStep', # Added
    # Network
    'Invoke-LoxoneDownload', # Corrected name
    'Get-LoxoneUpdateData',       # Added
    'Start-LoxoneConfigDownload', # Added
    'Start-LoxoneAppDownload',    # Added
    'Wait-ForPingTimeout',
    'Wait-ForPingSuccess',
    # RunAsUser
    'Invoke-AsCurrentUser',
    'Invoke-ScriptAsCurrentUserIfSystem', # Added
    'Get-CurrentUserSession',             # Add helper function if it needs to be directly callable (optional)
    'Get-ProcessStatus',                  # Corrected name
    'Test-ScheduledTask', # Added
    'Start-ProcessInteractive', # Added
    'Register-ScheduledTaskForScript', # Added
    # Toast
    'Initialize-LoxoneToastAppId',        # Added
    'Get-LoxoneConfigToastAppId',         # Added (Internal helper, but export for now)
    'Update-PersistentToast',
    'Show-FinalStatusToast',
    'Update-PreCheckToast',       # Added
    # Utility / System (Regrouped for clarity)
    'Complete-UpdateProcess',
    'Get-ExecutableSignature',
    'Format-TimeSpanFromSeconds',
    'Convert-VersionString',
    'Compare-LoxoneVersion',      # Added
    'Get-RedactedPassword',
    'Initialize-CRC32Type',
    'Get-CRC32',
    'ConvertTo-Expression',
    'Get-RegistryValue',          # Added missing utility function
    'Format-StatusLine',          # Added missing utility function for status reporting
    'Get-InvocationTrace',        # Added utility function
    'Test-ExistingFile',          # Added utility function
    # UpdateCheck
    'Test-ExistingInstaller',         # Added
    'Test-UpdateNeeded',
    'Test-LoxoneConfigComponent',     # Added
    'Test-LoxoneAppComponent',        # Added
    'Test-LoxoneMiniserverComponents', # Added
    # Helper functions from UpdateCheck
    'New-LoxoneComponentStatusObject',
    'Get-UpdateStatusFromComparison',
    'Invoke-MiniserverCheckLogic',
    # WorkflowSteps
    'Initialize-ScriptWorkflow',
    'Get-LoxoneUpdatePrerequisites',
    'Get-StepWeight',
    'Invoke-DownloadLoxoneConfig',
    'Invoke-ExtractLoxoneConfig',
    'Invoke-InstallLoxoneConfig',
    'Invoke-DownloadLoxoneApp',
    'Invoke-InstallLoxoneApp',
    'Invoke-CheckMiniserverVersions',
    'Invoke-UpdateMiniserversInBulk',
    'Initialize-UpdatePipelineData'
)
# Cmdlets to export from this module
CmdletsToExport = @() # Explicitly export no cmdlets

# Variables to export from this module
VariablesToExport = @() # Explicitly export no variables

# Aliases to export from this module
AliasesToExport = @() # Explicitly export no aliases

}