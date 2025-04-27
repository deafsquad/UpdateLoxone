# LoxoneUtils.UpdateCheck.psm1
# Module containing functions to check update status for various Loxone components.

using module '.\LoxoneUtils.Logging.psm1'
using module '.\LoxoneUtils.Utility.psm1'
##Requires -Modules LoxoneUtils.Logging, LoxoneUtils.Utility # Specify dependencies (Commented out for standalone import testing)

#region Private Helper Functions

# Helper to create the standard component status object
function New-LoxoneComponentStatusObject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Config', 'App', 'MS')]
        [string]$ComponentType,

        [Parameter(Mandatory = $true)]
        [string]$Identifier,

        [Parameter(Mandatory = $false)]
        $InitialVersion, # Can be [version] or [string] or $null

        [Parameter(Mandatory = $false)]
        $LatestVersion, # Can be [version] or [string] or $null

        [Parameter(Mandatory = $true)]
        [bool]$UpdateNeeded,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = $null,

        [Parameter(Mandatory = $false)]
        [string]$RawEntry = $null, # Specific to MS

        # Component-specific data objects
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$ConfigData = $null, # Specific to Config

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$AppData = $null # Specific to App (currently unused for extra fields)
    )

    Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (Before Create): Received ComponentType = '$ComponentType'"
    $statusObject = [PSCustomObject]@{
        ComponentType   = $ComponentType
        Identifier      = $Identifier
        InitialVersion  = $InitialVersion
        LatestVersion   = $LatestVersion # Store the raw string/version object passed
        UpdateNeeded    = $UpdateNeeded
        ShouldRun       = $false # Initialize ShouldRun to false
        Status          = $Status
        UpdateAttempted = $false # Initialize status tracking fields
        UpdateSuccess   = $false
        FinalVersion    = $null
        ErrorMessage    = $ErrorMessage
        RawEntry        = $RawEntry
        # Add component-specific fields conditionally
        ZipUrl          = if ($ComponentType -eq 'Config') { $ConfigData?.Path } else { $null }
        ExpectedCRC     = if ($ComponentType -eq 'Config') { $ConfigData?.CRC32 } else { $null }
        ExpectedSize    = if ($ComponentType -eq 'Config') { $ConfigData?.FileSize } else { $null }
        # Add App specific fields here if needed in the future from $AppData
    }
    Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] Created object properties: $(($statusObject | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -join ', ')"
    # Add Debugging AFTER object creation
    Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (After Assignment): statusObject.ZipUrl = '$($statusObject?.ZipUrl)'"
    Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (After Assignment): statusObject.ExpectedCRC = '$($statusObject?.ExpectedCRC)'"
    Write-Log -Level DEBUG -Message "[New-LoxoneComponentStatusObject] DEBUG (After Assignment): statusObject.ExpectedSize = '$($statusObject?.ExpectedSize)'"
            # --- Start Moved Block (Adapted) ---
            # Explicitly set ShouldRun based on Status/UpdateNeeded
            if ($statusObject.Status -eq 'NotFound') {
                Write-Log -Level INFO -Message "[New-LoxoneComponentStatusObject] Component not installed (Status='NotFound'). Setting ShouldRun=True."
                $statusObject.ShouldRun = $true
            } elseif ($statusObject.UpdateNeeded) {
                 Write-Log -Level INFO -Message "[New-LoxoneComponentStatusObject] Update required based on version (UpdateNeeded=True). Setting ShouldRun=True."
                 $statusObject.ShouldRun = $true # Ensure it's true if UpdateNeeded is true but status wasn't 'NotFound'
            } else {
                 # ShouldRun is already initialized to $false, but we can be explicit
                 $statusObject.ShouldRun = $false
            }
            # --- End Moved Block ---

}

# Helper to map Compare-LoxoneVersion result to Status and UpdateNeeded
function Get-UpdateStatusFromComparison {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComparisonResult,

        [Parameter(Mandatory = $true)]
        [string]$ComponentLogPrefix, # e.g., "[Config Check]", "[App Check]", "[MS Check '$msIdentifier']"

        # Pass versions for richer logging
        [Parameter(Mandatory = $false)]
        $InstalledVersionString,

        [Parameter(Mandatory = $false)]
        $TargetVersionString
    )

    $updateNeeded = $false
    $status = "Unknown" # Default

    switch ($ComparisonResult) {
        "NotFound" {
            $status = "NotFound"
            $updateNeeded = $true # Assume update needed if not found
            Write-Log -Message "$ComponentLogPrefix Installation not found." -Level INFO
        }
        "CheckSkipped (No Target)" {
            $status = "CheckSkipped (No Target)"
            $updateNeeded = $false
            Write-Log -Message "$ComponentLogPrefix Initial version found ($InstalledVersionString), but target version ('$TargetVersionString') is missing or invalid. Skipping check." -Level WARN
        }
        "Up-to-date" {
            $status = "Up-to-date" # Explicitly set status
            $updateNeeded = $false
            Write-Log -Message "Is up-to-date ($InstalledVersionString)." -Level INFO
        }
        "Outdated" {
            $status = "Outdated"
            $updateNeeded = $true # Explicitly set update needed
            Write-Log -Message "$ComponentLogPrefix Update required (Installed: $InstalledVersionString, Latest: $TargetVersionString)." -Level INFO
        }
        "ComparisonError" {
            $status = "VersionCheckFailed" # Map comparison error to a check failure
            $updateNeeded = $false # Don't attempt update if comparison failed
            Write-Log -Message "$ComponentLogPrefix Failed to compare versions ($InstalledVersionString vs $TargetVersionString)." -Level WARN
        }
        default {
            $status = "ErrorDeterminingStatus" # Unexpected status from Compare-LoxoneVersion
            $updateNeeded = $false
            Write-Log -Message "$ComponentLogPrefix Unexpected status '$ComparisonResult' received from Compare-LoxoneVersion." -Level ERROR
        }
    }

    return [PSCustomObject]@{
        Status       = $status
        UpdateNeeded = $updateNeeded
    }
}

# Helper to perform the check logic for a single Miniserver
function Invoke-MiniserverCheckLogic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MiniserverEntry,

        [Parameter(Mandatory = $false)] # Target might be null/empty
        [string]$TargetVersionString,

        [Parameter(Mandatory = $false)] # Normalized target might be null
        [string]$NormalizedLatestMSVersionString,

        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )

    # Assuming Get-RedactedPassword is available (from LoxoneUtils.Utility)
    $redactedEntry = Get-RedactedPassword $MiniserverEntry
    $msVersion = $null
    $msIdentifier = "UnknownHost" # Default identifier
    $statusResult = $null
    $errorMessage = $null

    # --- Extract Identifier ---
    try {
        # Regex to capture host from various formats (http://user:pass@host:port, user:pass@host, host:port, host)
        if ($MiniserverEntry -match '^(?:https?://)?(?:[^:]+:[^@]+@)?(?<host>[^/:]+)(?::\d+)?') {
            $msIdentifier = $matches.host
        } else {
             Write-Log -Level WARN -Message "[MS Check Internal] Regex failed to extract host from '$redactedEntry'. Using URI fallback."
             try { $msIdentifier = ([uri]$MiniserverEntry).Host } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($msIdentifier)) { $msIdentifier = "UnknownHost" } # Final fallback
        Write-Log -Level DEBUG -Message "[MS Check Internal] Extracted Identifier '$msIdentifier' for entry '$redactedEntry'."
    } catch {
        Write-Log -Level WARN -Message "[MS Check Internal] Could not parse entry '$redactedEntry' for identifier. Using fallback. Error: $($_.Exception.Message)"
        try { $msIdentifier = $MiniserverEntry.Split('@')[-1].Split('/')[0].Split(':')[0] } catch {} # Original fallback
        if ([string]::IsNullOrWhiteSpace($msIdentifier)) { $msIdentifier = "UnknownHost" } # Final fallback
    }
    # --- End Extract Identifier ---

    $logPrefix = "[MS Check '$msIdentifier']"

    try {
        # Call Get-MiniserverVersion
        $getMSVersionParams = @{
            MiniserverEntry = $MiniserverEntry
            LogFile         = $LogFile
            ErrorAction     = 'Stop'
        }
        if ($DebugMode.IsPresent) { $getMSVersionParams.DebugMode = $true }

        Write-Log -Message "$logPrefix Calling Get-MiniserverVersion..." -Level DEBUG
        # IMPORTANT: Call Get-MiniserverVersion directly as it's exported from the module
        $msVersion = Get-MiniserverVersion @getMSVersionParams

        if ($msVersion) {
            Write-Log -Message "$logPrefix Version retrieved: $msVersion" -Level INFO
            $normalizedCurrentMSVersionString = $null
            try {
                $normalizedCurrentMSVersionString = Convert-VersionString $msVersion # Normalize for logging comparison
            } catch {
                 Write-Log -Message "$logPrefix Failed to normalize current version '$msVersion': $($_.Exception.Message)" -Level WARN
            }


            # Compare versions using Compare-LoxoneVersion (from LoxoneUtils.Utility)
            # IMPORTANT: Call Compare-LoxoneVersion directly as it's exported from the module
            $comparisonStatus = Compare-LoxoneVersion -InstalledVersionString $msVersion -TargetVersionString $TargetVersionString
            Write-Log -Message "$logPrefix Compare-LoxoneVersion returned: '$comparisonStatus'" -Level DEBUG

            # Map comparison status using the other helper
            # IMPORTANT: Call Get-UpdateStatusFromComparison directly as it's now in the same module scope
            $getStatusParams = @{
                ComparisonResult        = $comparisonStatus
                ComponentLogPrefix      = $logPrefix
                InstalledVersionString  = $normalizedCurrentMSVersionString
                TargetVersionString     = $NormalizedLatestMSVersionString
            }
            $statusResult = Get-UpdateStatusFromComparison @getStatusParams

        } else {
            $errorMessage = "Could not retrieve version (Get-MiniserverVersion returned null/empty)."
            Write-Log -Message "$logPrefix $errorMessage" -Level WARN
            $statusResult = [PSCustomObject]@{ Status = "VersionCheckFailed"; UpdateNeeded = $false }
        }
    } catch {
        # Catch errors specifically from Get-MiniserverVersion or other issues in the try block
        $errorMessage = "Error retrieving/processing version: $($_.Exception.Message)."
        Write-Log -Message "$logPrefix $errorMessage" -Level WARN
        $msVersion = $null # Ensure version is null on error
        $statusResult = [PSCustomObject]@{ Status = "VersionCheckFailed"; UpdateNeeded = $false }
    }

    # Return results needed for the status object
    return [PSCustomObject]@{
        Identifier     = $msIdentifier
        InitialVersion = $msVersion # Raw version string or null
        Status         = $statusResult.Status
        UpdateNeeded   = $statusResult.UpdateNeeded
        ErrorMessage   = $errorMessage # Will be null if no error occurred
    }
}

# Helper functions moved back to UpdateLoxone.ps1
#endregion Private Helper Functions


# Function to perform the overall update check
# Refactored Test-UpdateNeeded function content
function Test-UpdateNeeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Test', 'Public')]
        [string]$Channel,

        # Parameters needed for component checks (passed from main script)
        [Parameter(Mandatory = $false)]
        [string]$InstalledVersion, # For Config check (Changed to string to allow empty/null)

        [Parameter(Mandatory = $false)]
        [version]$InstalledAppVersion, # For App check

        [Parameter(Mandatory = $false)]
        [string]$InstalledExePath, # For App check (future use?)

        [Parameter(Mandatory = $true)]
        [bool]$CheckLoxoneApp, # For App check

        [Parameter(Mandatory = $true)]
        [string]$ScriptRoot, # To find MS list and download dir

        [Parameter(Mandatory = $true)]
        [string]$LogFile, # For MS check logging

        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )

    Start-FunctionLog -FunctionName $MyInvocation.MyCommand.Name
    # --- Logic moved to UpdateLoxone.ps1 ---
    Write-Log -Message "[Update Check] Function Test-UpdateNeeded entered but logic is now integrated into UpdateLoxone.ps1. Returning empty list." -Level DEBUG
    Stop-FunctionLog
    return [System.Collections.Generic.List[PSCustomObject]]::new() # Return empty list
}

# Function to check Loxone Config update status
function Test-LoxoneConfigComponent {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)] # Restore Mandatory
            [PSCustomObject]$ConfigData,    # Restore PSCustomObject type
    
            # Keep other existing parameters
            [Parameter(Mandatory = $false)]
            [string]$InstalledVersion, # Changed type from [version] to [string] to allow null/empty
    
            [Parameter(Mandatory = $false)]
            [string]$DownloadDir,
    
            [Parameter(Mandatory = $false)]
            [switch]$DebugMode
        )

    Start-FunctionLog -FunctionName $MyInvocation.MyCommand.Name


        # Extract latest version from ConfigData
        $latestVersion = $null
        if ($null -ne $ConfigData) {
            $latestVersion = $ConfigData.Version
        } else {
            Write-Log -Message "[Config Check] ConfigData parameter was null. Cannot determine latest version." -Level WARN
            # Fall through, logic below handles null target version
        }
    
        # Use Compare-LoxoneVersion to determine status
        # Ensure Compare-LoxoneVersion is available (should be via NestedModules in PSD1 later)
        # Assign properties to local variables FIRST
        # Use Compare-LoxoneVersion to determine status
        # Ensure Compare-LoxoneVersion is available (should be via NestedModules in PSD1 later)
        $comparisonStatus = Compare-LoxoneVersion -InstalledVersionString $InstalledVersion -TargetVersionString $latestVersion
    Write-Log -Message "[Config Check] Compare-LoxoneVersion returned: '$comparisonStatus'" -Level DEBUG
    # NOTE: The problematic 'if ($comparisonStatus -eq 'NotFound')' block is confirmed absent here.

    # Duplicate 'NotFound' block removed.

    # Determine status based on comparison result
    # Call Get-UpdateStatusFromComparison directly (now in same module scope)
    $statusResult = Get-UpdateStatusFromComparison -ComparisonResult $comparisonStatus `
                                                  -ComponentLogPrefix "[Config Check]" `
                                                  -InstalledVersionString $InstalledVersion `
                                                  -TargetVersionString $latestVersion

    # Create Config Status Object using helper
    # Create Config Status Object using helper

    # --- Local variable definitions and related debug logs removed ---

    # Call New-LoxoneComponentStatusObject directly (now in same module scope)
    $configStatusObject = New-LoxoneComponentStatusObject -ComponentType 'Config' `
                                                          -Identifier 'Config' `
                                                          -InitialVersion $InstalledVersion `
                                                          -LatestVersion $latestVersion `
                                                          -UpdateNeeded $statusResult.UpdateNeeded `
                                                          -Status $statusResult.Status `
                                                          -ConfigData $ConfigData # Pass object

   # Explicitly set ShouldRun if component not found, overriding initial value if necessary
   # [ShouldRun logic moved to New-LoxoneComponentStatusObject]

   Write-Log -Message "[Config Check] Status object created: $($configStatusObject | ConvertTo-Json -Depth 1 -Compress)" -Level DEBUG
   Stop-FunctionLog
   Write-Output $configStatusObject
}

# Export the function(s) from this module file
# Function to check Loxone App update status
function Test-LoxoneAppComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] # AppData might be null if XML parsing failed for App node
        [PSCustomObject]$AppData,

        [Parameter(Mandatory = $true)]
        [bool]$CheckEnabled, # Corresponds to $UpdateLoxoneApp parameter

        [Parameter(Mandatory = $false)] # Passed from main script
        [version]$InstalledAppVersion,

        [Parameter(Mandatory = $false)] # Passed from main script
        [string]$LoxoneExePath, # Currently unused, but passed for potential future use

        [Parameter(Mandatory = $false)] # Passed from main script
        [string]$DownloadDir, # Currently unused, but passed for potential future use

        [Parameter(Mandatory = $false)] # Passed from main script
        [switch]$DebugMode
    )

    Start-FunctionLog -FunctionName $MyInvocation.MyCommand.Name

    $latestAppVersion = $null
    if ($null -ne $AppData) {
        $latestAppVersion = $AppData.Version
    } else {
        Write-Log -Message "[App Check] AppData parameter was null. Cannot determine latest version." -Level WARN
        # Fall through, logic below handles null target version
    }

    $appStatusObject = $null # Initialize

    if ($CheckEnabled) {
        Write-Log -Message "[App Check] Check enabled. Proceeding..." -Level DEBUG

        Write-Log -Message "[App Check] Check enabled. Using passed InstalledAppVersion: '$InstalledAppVersion'" -Level DEBUG

        # Use the passed $InstalledAppVersion parameter directly
        # Removed call to Get-AppVersionFromRegistry

        # Use Compare-LoxoneVersion to determine status
        $comparisonStatus = Compare-LoxoneVersion -InstalledVersionString $InstalledAppVersion -TargetVersionString $latestAppVersion
        # Map comparison status using helper
        # Call Get-UpdateStatusFromComparison directly (now in same module scope)
        $statusResult = Get-UpdateStatusFromComparison -ComparisonResult $comparisonStatus `
                                                      -ComponentLogPrefix "[App Check]" `
                                                      -InstalledVersionString $InstalledAppVersion `
                                                      -TargetVersionString $latestAppVersion

        # Create App Status Object using helper (when check is enabled)
        # Call New-LoxoneComponentStatusObject directly (now in same module scope)
        $appStatusObject = New-LoxoneComponentStatusObject -ComponentType 'App' `
                                                          -Identifier 'App' `
                                                          -InitialVersion $InstalledAppVersion `
                                                          -LatestVersion $latestAppVersion `
                                                          -UpdateNeeded $statusResult.UpdateNeeded `
                                                          -Status $statusResult.Status `
                                                          -AppData $AppData # Pass AppData for potential future use

       # [ShouldRun logic moved to New-LoxoneComponentStatusObject]

   } else {
       Write-Log -Message "[App Check] Loxone App update check skipped by parameter." -Level INFO

       # Create Skipped App Status Object using helper
       # Call New-LoxoneComponentStatusObject directly (now in same module scope)
       $appStatusObject = New-LoxoneComponentStatusObject -ComponentType 'App' `
                                                         -Identifier 'App' `
                                                         -InitialVersion $null `
                                                         -LatestVersion $latestAppVersion `
                                                         -UpdateNeeded $false ` # ShouldRun will be initialized to false here
                                                         -Status 'Skipped' `
                                                         -AppData $AppData
       # [ShouldRun logic moved to New-LoxoneComponentStatusObject]
   }

   Write-Log -Message "[App Check] Status object created: $($appStatusObject | ConvertTo-Json -Depth 1 -Compress)" -Level DEBUG

   Stop-FunctionLog        # Stop logging first
   Write-Log -Level DEBUG -Message "[Test-LoxoneAppComponent] Object before Write-Output: $($appStatusObject | ConvertTo-Json -Depth 2 -Compress)" -SkipStackFrame
   Write-Output $appStatusObject # Then output the object
} # Added missing closing brace for Test-LoxoneAppComponent


# Function to check update status for multiple Miniservers
function Test-LoxoneMiniserverComponents {
    # Temporarily commented out for debugging return value issue
    [CmdletBinding()] # Restore CmdletBinding
    param(
        [Parameter(Mandatory = $true)] # Restore Mandatory attribute
        [string[]]$MiniserverEntries, # Array of entries (e.g., user:pass@host)

        [Parameter(Mandatory = $false)] # MSData might be null if XML parsing failed
        [PSCustomObject]$MSData, # Corrected type constraint

        [Parameter(Mandatory = $true)]
        [string]$LogFile, # Pass log file path explicitly

        [Parameter(Mandatory = $false)]
        [switch]$DebugMode # Changed to switch
        # Removed [ref]$ComponentStatusList parameter
    )

    Start-FunctionLog -FunctionName $MyInvocation.MyCommand.Name

    # --- Logic moved to Test-UpdateNeeded ---
    # Keep the function signature but return an empty list immediately.
    # This avoids breaking the module export but bypasses the problematic code.
    Write-Log -Message "[MS Check] Function Test-LoxoneMiniserverComponents entered but logic is now integrated into Test-UpdateNeeded. Returning empty list." -Level DEBUG

    # Initialize empty list
    $msStatusObjects = [System.Collections.Generic.List[PSCustomObject]]::new()

    # No try/catch needed here anymore as the core logic is gone.
    # Minimal finally block just for logging.
    finally {
        # This block ALWAYS executes to ensure logging stops correctly
        Write-Log -Message "[MS Check] Entering finally block for gutted function." -Level DEBUG
        Stop-FunctionLog
    }
    # Log count and return the empty list *after* the finally block
    Write-Log -Message "[MS Check] Function finished. Returning $($msStatusObjects.Count) MS status objects (should be 0)." -Level DEBUG
    return $msStatusObjects
}

# Removed duplicate function definition

# Consolidate exports at the end
Export-ModuleMember -Function Test-UpdateNeeded, Test-LoxoneConfigComponent, Test-LoxoneAppComponent, Test-LoxoneMiniserverComponents, New-LoxoneComponentStatusObject, Get-UpdateStatusFromComparison, Invoke-MiniserverCheckLogic
# Removed duplicate Export-ModuleMember call
# Removed extra closing brace