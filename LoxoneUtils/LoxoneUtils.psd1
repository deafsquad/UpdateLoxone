@{
# Script module or binary module file associated with this manifest.
# RootModule is empty because we are using NestedModules
RootModule = ''

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
    '.\LoxoneUtils.UpdateCheck.psm1'
)

# Scripts to dot-source on import. Functions/variables are directly added to the module scope.
# ScriptsToProcess = @( # Reverted: Use NestedModules for .psm1 files
#     '.\LoxoneUtils.Utility.psm1',
#     '.\LoxoneUtils.Logging.psm1',
#     '.\LoxoneUtils.Toast.psm1',
#     '.\LoxoneUtils.Network.psm1',
#     '.\LoxoneUtils.ErrorHandling.psm1',
#     '.\LoxoneUtils.Installation.psm1',
#     '.\LoxoneUtils.Miniserver.psm1',
#     '.\LoxoneUtils.RunAsUser.psm1',
#     '.\LoxoneUtils.System.psm1',
#     '.\LoxoneUtils.UpdateCheck.psm1'
# )
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
    'Start-FunctionLog',          # Corrected from Enter-Function
    'Stop-FunctionLog',           # Corrected from Exit-Function
    'Write-Log',
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
    'Get-CurrentUserSession', # Add helper function if it needs to be directly callable (optional)
    'Get-ProcessStatus', # Corrected name
    'Test-ScheduledTask', # Added
    'Start-ProcessInteractive', # Added
    'Register-ScheduledTaskForScript', # Added
    # Toast
    'Set-LoxoneToastAppId',
    'Update-PersistentToast',
    'Show-FinalStatusToast',
    # Utility / System (Regrouped for clarity)
    'Complete-UpdateProcess',
    'Get-ExecutableSignature',
    'Format-TimeSpanFromSeconds',
    'Convert-VersionString',
    'Compare-LoxoneVersion',      # Added
    'Get-RedactedPassword',
    'Register-CRC32Type',         # Corrected from Initialize-CRC32Type
    'Get-CRC32',
    'ConvertTo-Expression',
    'Get-RegistryValue',          # Added missing utility function
    'Format-StatusLine',          # Added missing utility function for status reporting
    # UpdateCheck
    'Test-UpdateNeeded',              # <-- ADD THIS LINE
    'Test-LoxoneConfigComponent',     # Added
    'Test-LoxoneAppComponent',        # Added
    'Test-LoxoneMiniserverComponents', # Added
    # Helper functions from UpdateCheck
    'New-LoxoneComponentStatusObject',
    'Get-UpdateStatusFromComparison',
    'Invoke-MiniserverCheckLogic'
)
# Cmdlets to export from this module
CmdletsToExport = @() # Explicitly export no cmdlets

# Variables to export from this module
VariablesToExport = @() # Explicitly export no variables

# Aliases to export from this module
AliasesToExport = @() # Explicitly export no aliases

# Private data to pass to the module specified in RootModule/ModuleToProcess
PrivateData = @{

    # --- NEW: Context Metadata ---
    ContextMetadata = @{
        NestedModules = @{
            '.\LoxoneUtils.Utility.psm1'      = 'All'    # Core utilities
            '.\LoxoneUtils.Logging.psm1'      = 'All'    # Logging needed everywhere
            '.\LoxoneUtils.Toast.psm1'        = 'User'   # UI/User interaction
            '.\LoxoneUtils.psm1'            = 'All'    # Assuming general purpose if used
            '.\LoxoneUtils.Network.psm1'      = 'All'    # Network operations can be needed by both
            '.\LoxoneUtils.ErrorHandling.psm1'= 'All'    # Error handling needed everywhere
            '.\LoxoneUtils.Installation.psm1' = 'All'    # Contains helpers, actual install runs as User
            '.\LoxoneUtils.Miniserver.psm1'   = 'User'   # Interacts with Config path/creds usually in User context
            '.\LoxoneUtils.RunAsUser.psm1'    = 'System' # Specifically for SYSTEM -> User launch
            '.\LoxoneUtils.System.psm1'       = 'All'    # General system interactions
        }
        Functions = @{
            # ErrorHandling
            'Invoke-ScriptErrorHandling'      = 'All'
            # Installation
            'Get-InstalledVersion'            = 'User'   # Checks user-specific paths/registry
            'Start-LoxoneUpdateInstaller'     = 'User'   # Installation runs in user context (even if elevated)
            'Start-LoxoneForWindowsInstaller' = 'User'   # Installation runs in user context
            'Get-InstalledApplicationPath'    = 'User'   # Checks user-specific paths/registry
            'Get-LoxoneExePath'               = 'User'   # Checks user-specific paths/registry
            'Invoke-ZipFileExtraction'        = 'All'    # File system operation
            # Logging
            'Enter-Function'                  = 'All'
            'Exit-Function'                   = 'All'
            'Write-Log'                       = 'All'
            'Invoke-LogFileRotation'          = 'All'
            # Miniserver
            'Update-MS'                       = 'User'   # Relies on user context Config path/creds
            'Get-MiniserverVersion'           = 'User'   # Network + potentially user creds
            'Invoke-MiniserverUpdate'         = 'User'   # Relies on user context Config path
            # Network
            'Invoke-LoxoneDownload'           = 'All'    # Can run as SYSTEM or User
            'Wait-ForPingTimeout'             = 'All'
            'Wait-ForPingSuccess'             = 'All'
            # RunAsUser
            'Invoke-AsCurrentUser'            = 'System' # Core purpose for SYSTEM context
            'Get-CurrentUserSession'          = 'System' # Helper for Invoke-AsCurrentUser
            'Start-ProcessInteractive'        = 'System' # Helper for Invoke-AsCurrentUser
            # System (Functions potentially from various .psm1 files, grouped logically)
            'Get-ProcessStatus'               = 'All'    # Useful in both contexts
            'Test-ScheduledTask'              = 'User'   # Task interaction usually user (even if elevated)
            'Register-ScheduledTaskForScript' = 'User'   # Task interaction usually user (even if elevated)
            'Get-ExecutableSignature'         = 'All'    # File system/API check
            'Complete-UpdateProcess'          = 'All'     # Finalization step
            'Format-TimeSpanFromSeconds'      = 'All'    # Utility
            'Convert-VersionString'           = 'All'    # Utility
            'Get-RedactedPassword'            = 'All'    # Utility
            'Initialize-CRC32Type'            = 'All'    # Utility
            'Get-CRC32'                       = 'All'    # Utility
            'ConvertTo-Expression'            = 'All'    # Utility
            'Get-AppVersionFromRegistry'      = 'User'   # HKCU registry access
            # Toast
            'Set-LoxoneToastAppId'            = 'User'   # UI related
            'Update-PersistentToast'          = 'User'   # UI related
            'Show-FinalStatusToast'           = 'User'   # UI related
        }
    };
    # --- END: Context Metadata ---

    PSData = @{
        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''
    }; # End of PSData hashtable
} # End of PrivateData hashtable
}