#Requires -Modules BurntToast

#region Global Variables
# Initialize global variables if they don't exist
if (-not (Test-Path variable:Global:PersistentToastId)) {
    $Global:PersistentToastId = "LoxoneUpdateStatusToast" # Default ID
}
# Initialize PersistentToastInitialized flag
if (-not (Test-Path variable:Global:PersistentToastInitialized)) {
    $Global:PersistentToastInitialized = $false
}
# Initialize with expected keys for data binding
# Unconditionally initialize to ensure fresh state per module load in a session
$Global:PersistentToastData = [ordered]@{
    StatusText            = "Initializing..."
    ProgressBarStatus     = "Download: -"
    ProgressBarValue      = 0.0
    OverallProgressStatus = "Overall: 0%"
    OverallProgressValue  = 0.0
    StepNumber            = 0
    TotalSteps            = 1
    StepName              = "Initializing..."
    DownloadFileName      = ""
    DownloadNumber        = 0
    TotalDownloads        = 0
    CurrentWeight         = 0
    TotalWeight           = 1
    # Keys for multi-line details (can be empty strings)
    DownloadSpeedLine     = ""
    DownloadTimeLine      = ""
    DownloadSizeLine      = ""
}
#endregion Global Variables

#region AppId Handling
function Get-LoxoneConfigToastAppId {
    [CmdletBinding()]
    param(
        [string]$PreFoundPath # Optional: Pass if already found by main script
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level Debug -Message "Attempting to determine Toast AppId for Loxone Config..."

    # Define the known hardcoded AppId structure
    $hardcodedAppIdFormat = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe' # Removed extra single quotes

    # Only search registry/uninstall if path wasn't provided and needed for verification (though we prefer hardcoded)
    $loxonePath = $PreFoundPath
    if (-not $loxonePath) {
        Write-Log -Level Debug -Message "No pre-found path provided. Searching registry..."
        try {
            $loxonePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
            if ($loxonePath) { Write-Log -Level Debug -Message "Found LoxoneConfig.exe path via Get-LoxoneExePath: '$loxonePath'" }
            else { Write-Log -Level Debug -Message "Get-LoxoneExePath did not return a path." }
        } catch { Write-Log -Level Warn -Message "Error calling Get-LoxoneExePath: $($_.Exception.Message)"; $loxonePath = $null }
    } else { Write-Log -Level Debug -Message "Using pre-found path: '$loxonePath'" }

    # Determine AppId based on whether Loxone Config was found
    if (-not [string]::IsNullOrEmpty($loxonePath)) {
        # Loxone Config found, use its hardcoded AppId
        Write-Log -Level Info -Message "Loxone Config path found ('$loxonePath'). Using hardcoded Loxone Config AppId: '$hardcodedAppIdFormat'"
        $appId = $hardcodedAppIdFormat
    } else {
        # Loxone Config not found, do not use a specific AppId (will default to PowerShell)
        Write-Log -Level Info -Message "Loxone Config path not found. No specific AppId will be used for toast notifications."
        $appId = $null # Return null when Loxone Config is not found
    }

    Write-Log -Level Debug -Message ("Get-LoxoneConfigToastAppId: Determined AppId '{0}'." -f ($appId | Out-String).Trim()) # Handle potential $null output
    Exit-Function
    return $appId
}


function Initialize-LoxoneToastAppId {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level Debug -Message "Initializing Loxone Toast AppId..."
    $script:ResolvedToastAppId = Get-LoxoneConfigToastAppId -PreFoundPath $script:InstalledExePath
    Write-Log -Level Debug -Message "Resolved Toast AppId stored as: '$($script:ResolvedToastAppId | Out-String)'"
    Exit-Function
}

#endregion AppId Handling

#region Progress Toast Function (Using New-BurntToastNotification for Create, Update-BTNotification for Update)

function Update-PersistentToast {
    [CmdletBinding()]
    param(
            # Overall Step Info
            [Parameter(Mandatory=$false)][int]$StepNumber,
            [Parameter(Mandatory=$false)][int]$TotalSteps,
            [Parameter(Mandatory=$false)][string]$StepName,
            # Download Specific Info
            [Parameter(Mandatory=$false)][string]$DownloadFileName, # For display
            [Parameter(Mandatory=$false)][int]$DownloadNumber,
            [Parameter(Mandatory=$false)][int]$TotalDownloads,
            [Parameter(Mandatory=$false)][double]$ProgressPercentage, # Current download %
            [Parameter(Mandatory=$false)][string]$DownloadSpeed, # e.g., "11.31 MB/s"
            [Parameter(Mandatory=$false)][string]$DownloadRemainingTime, # e.g., "00:32"
            [Parameter(Mandatory=$false)][string]$DownloadSizeProgress, # e.g., "145/507 MB"
            # Overall Progress Info (Weight-based)
            [Parameter(Mandatory=$false)][double]$CurrentWeight,
            [Parameter(Mandatory=$false)][double]$TotalWeight,
            # Context Parameters (Used for logging/potential future logic)
            [Parameter(Mandatory=$true)][bool]$IsInteractive, # Retaining for logging within this function
            [Parameter(Mandatory=$true)][bool]$ErrorOccurred,
            [Parameter(Mandatory=$true)][bool]$AnyUpdatePerformed = $false,
            # Parameters to pass context from the calling script
            [Parameter(Mandatory=$false)][bool]$CallingScriptIsInteractive = $false,
            [Parameter(Mandatory=$false)][bool]$CallingScriptIsSelfInvoked = $false
        )
    # Add a small delay at the beginning to see if it helps with update visibility
    Start-Sleep -Milliseconds 50 # Reduced sleep duration
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
# Detailed Parameter Logging
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name)) --- Update-PersistentToast: RECEIVED PARAMETER VALUES ---"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   StepNumber: $($PSBoundParameters['StepNumber']) (Bound: $($PSBoundParameters.ContainsKey('StepNumber')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   TotalSteps: $($PSBoundParameters['TotalSteps']) (Bound: $($PSBoundParameters.ContainsKey('TotalSteps')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   StepName: '$($PSBoundParameters['StepName'])' (Bound: $($PSBoundParameters.ContainsKey('StepName')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadFileName: '$($PSBoundParameters['DownloadFileName'])' (Bound: $($PSBoundParameters.ContainsKey('DownloadFileName')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadNumber: $($PSBoundParameters['DownloadNumber']) (Bound: $($PSBoundParameters.ContainsKey('DownloadNumber')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   TotalDownloads: $($PSBoundParameters['TotalDownloads']) (Bound: $($PSBoundParameters.ContainsKey('TotalDownloads')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   ProgressPercentage: $($PSBoundParameters['ProgressPercentage']) (Bound: $($PSBoundParameters.ContainsKey('ProgressPercentage')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadSpeed: '$($PSBoundParameters['DownloadSpeed'])' (Bound: $($PSBoundParameters.ContainsKey('DownloadSpeed')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadRemainingTime: '$($PSBoundParameters['DownloadRemainingTime'])' (Bound: $($PSBoundParameters.ContainsKey('DownloadRemainingTime')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadSizeProgress: '$($PSBoundParameters['DownloadSizeProgress'])' (Bound: $($PSBoundParameters.ContainsKey('DownloadSizeProgress')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   CurrentWeight: $($PSBoundParameters['CurrentWeight']) (Bound: $($PSBoundParameters.ContainsKey('CurrentWeight')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   TotalWeight: $($PSBoundParameters['TotalWeight']) (Bound: $($PSBoundParameters.ContainsKey('TotalWeight')))"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   IsInteractive (param): $($IsInteractive)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   ErrorOccurred (param): $($ErrorOccurred)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   AnyUpdatePerformed (param): $($AnyUpdatePerformed)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   CallingScriptIsInteractive (param): $($CallingScriptIsInteractive)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   CallingScriptIsSelfInvoked (param): $($CallingScriptIsSelfInvoked)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name)) --- Update-PersistentToast: GLOBAL STATE (ON ENTRY) ---"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   Global:PersistentToastInitialized (on entry): $($Global:PersistentToastInitialized)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   Global:PersistentToastId (on entry): '$($Global:PersistentToastId)'"
    Write-Log -Level DEBUG -Message ("($($MyInvocation.MyCommand.Name))   Global:PersistentToastData (on entry, JSON): " + ($Global:PersistentToastData | ConvertTo-Json -Depth 5 -Compress))
# Detailed Parameter Logging
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name)) --- Update-PersistentToast: PARAMETER VALUES ---"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   StepNumber: $($StepNumber)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   TotalSteps: $($TotalSteps)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   StepName: '$($StepName)'"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadFileName: '$($DownloadFileName)'"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadNumber: $($DownloadNumber)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   TotalDownloads: $($TotalDownloads)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   ProgressPercentage: $($ProgressPercentage)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadSpeed: '$($DownloadSpeed)'"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadRemainingTime: '$($DownloadRemainingTime)'"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   DownloadSizeProgress: '$($DownloadSizeProgress)'"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   CurrentWeight: $($CurrentWeight)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   TotalWeight: $($TotalWeight)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   IsInteractive (param): $($IsInteractive)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   ErrorOccurred (param): $($ErrorOccurred)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   AnyUpdatePerformed (param): $($AnyUpdatePerformed)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   CallingScriptIsInteractive (param): $($CallingScriptIsInteractive)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   CallingScriptIsSelfInvoked (param): $($CallingScriptIsSelfInvoked)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name)) --- Update-PersistentToast: GLOBAL STATE (BEFORE UPDATE) ---"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   Global:PersistentToastInitialized: $($Global:PersistentToastInitialized)"
    Write-Log -Level DEBUG -Message "($($MyInvocation.MyCommand.Name))   Global:PersistentToastId: '$($Global:PersistentToastId)'"
    Write-Log -Level DEBUG -Message ("($($MyInvocation.MyCommand.Name))   Global:PersistentToastData (JSON): " + ($Global:PersistentToastData | ConvertTo-Json -Depth 5 -Compress))
    Write-Log -Level DEBUG -Message "Update-PersistentToast CALLED. IsInteractive: $IsInteractive, ErrorOccurred: $ErrorOccurred, AnyUpdatePerformed: $AnyUpdatePerformed, CallingScriptIsInteractive: $CallingScriptIsInteractive, CallingScriptIsSelfInvoked: $CallingScriptIsSelfInvoked"
    Write-Log -Level DEBUG -Message ("Update-PersistentToast PARAMS: " + ($PSBoundParameters | Out-String))
    Write-Log -Level DEBUG -Message ("Update-PersistentToast Initial Global:PersistentToastInitialized: $Global:PersistentToastInitialized")
    Write-Log -Level DEBUG -Message ("Update-PersistentToast Initial Global:PersistentToastData: " + ($Global:PersistentToastData | ConvertTo-Json -Depth 3 -Compress))


    $logMsg = "Updating persistent toast." # Original log message construction can be kept if desired or integrated
    if ($PSBoundParameters.ContainsKey('StepName')) { $logMsg += " Step: '$StepName' ($StepNumber/$TotalSteps)" }
    if ($PSBoundParameters.ContainsKey('DownloadFileName')) { $logMsg += " | Download: '$DownloadFileName' ($DownloadNumber/$TotalDownloads)" }
    if ($PSBoundParameters.ContainsKey('ProgressPercentage')) { $logMsg += " | Download Progress: $ProgressPercentage%" }
    if ($PSBoundParameters.ContainsKey('CurrentWeight')) { $logMsg += " | Overall Weight: $CurrentWeight/$TotalWeight" }
    # Write-Log -Level DEBUG -Message $logMsg # Can log this constructed message too

    try {
        # --- Update Global Data Bindings ---
        Write-Log -Level DEBUG -Message "Update-PersistentToast: Updating global data bindings..."
        $baseStatusText = ""
        if ($PSBoundParameters.ContainsKey('StepNumber') -and $PSBoundParameters.ContainsKey('TotalSteps') -and $PSBoundParameters.ContainsKey('StepName')) {
            $Global:PersistentToastData['StepNumber'] = $StepNumber
            $Global:PersistentToastData['TotalSteps'] = $TotalSteps
            $Global:PersistentToastData['StepName'] = $StepName
            $baseStatusText = "Step ${StepNumber}/${TotalSteps}: ${StepName}"
        } elseif ($Global:PersistentToastData['StatusText']) { $baseStatusText = $Global:PersistentToastData['StatusText'].Split("`n")[0] }

        $detailsParts = @()
        if ($PSBoundParameters.ContainsKey('DownloadSpeed')) { $detailsParts += "Speed: $DownloadSpeed" }
        if ($PSBoundParameters.ContainsKey('DownloadRemainingTime')) { $detailsParts += "Time Rem: $DownloadRemainingTime" }
        if ($PSBoundParameters.ContainsKey('DownloadSizeProgress')) { $detailsParts += "Size: $DownloadSizeProgress" }

        if ($detailsParts.Count -gt 0) {
            $lines = @($baseStatusText) + $detailsParts
            $Global:PersistentToastData['StatusText'] = $lines -join "`n"
            Write-Log -Level Info -Message "Set StatusText (with multi-line details) to '$($Global:PersistentToastData['StatusText'] -replace "`n","\n")'"
        } else {
            $Global:PersistentToastData['StatusText'] = $baseStatusText
             Write-Log -Level Info -Message "Set StatusText (no details) to '$($Global:PersistentToastData['StatusText'])'"
        }

        if ($PSBoundParameters.ContainsKey('DownloadFileName')) {
            $Global:PersistentToastData['DownloadFileName'] = $DownloadFileName
            if ($PSBoundParameters.ContainsKey('DownloadNumber') -and $PSBoundParameters.ContainsKey('TotalDownloads')) {
                 $Global:PersistentToastData['DownloadNumber'] = $DownloadNumber
                 $Global:PersistentToastData['TotalDownloads'] = $TotalDownloads
                 $Global:PersistentToastData['ProgressBarStatus'] = "Download ${DownloadNumber}/${TotalDownloads}: ${DownloadFileName}"
            } else { $Global:PersistentToastData['ProgressBarStatus'] = "Download: $DownloadFileName" }
             Write-Log -Level Debug -Message "Set ProgressBarStatus to '$($Global:PersistentToastData['ProgressBarStatus'])'"
        } elseif ($PSBoundParameters.ContainsKey('StepName') -and $StepName -eq 'Downloads Complete') {
             $Global:PersistentToastData['ProgressBarStatus'] = "Downloads: Done"
             $Global:PersistentToastData['ProgressBarValue'] = 1.0
             Write-Log -Level Debug -Message "Set ProgressBarStatus to 'Downloads: Done' and Value to 1.0"
        }

        if ($PSBoundParameters.ContainsKey('ProgressPercentage')) {
            if ($Global:PersistentToastData['ProgressBarStatus'] -ne "Downloads: Done") {
                $Global:PersistentToastData['ProgressBarValue'] = [Math]::Max(0.0, [Math]::Min(1.0, ($ProgressPercentage / 100)))
                Write-Log -Level Debug -Message "Updated ProgressBarValue to '$($Global:PersistentToastData['ProgressBarValue'])'"
            }
        }

        if ($PSBoundParameters.ContainsKey('CurrentWeight') -and $PSBoundParameters.ContainsKey('TotalWeight')) {
            $Global:PersistentToastData['CurrentWeight'] = $CurrentWeight
            $Global:PersistentToastData['TotalWeight'] = [Math]::Max(1, $TotalWeight)
            $overallProgress = if ($Global:PersistentToastData['TotalWeight'] -gt 0) { [Math]::Max(0.0, [Math]::Min(1.0, ($Global:PersistentToastData['CurrentWeight'] / $Global:PersistentToastData['TotalWeight']))) } else { 0.0 }
            $Global:PersistentToastData['OverallProgressStatus'] = "Overall: {0:P0}" -f $overallProgress
            $Global:PersistentToastData['OverallProgressValue'] = $overallProgress
            Write-Log -Level Debug -Message "Updated OverallProgress to Status '$($Global:PersistentToastData['OverallProgressStatus'])' (Weight: $($Global:PersistentToastData['CurrentWeight'])/$($Global:PersistentToastData['TotalWeight'])) and Value '$($Global:PersistentToastData['OverallProgressValue'])'"
        }

        # --- Always attempt Create or Update ---
        # Defer initial toast creation for non-interactive self-invoked runs until an actual update is confirmed in the main script
        $shouldDeferInitialToast = $false
        # If the calling script identifies itself as a self-invoked (scheduled) run,
        # then this function should defer creating an initial toast if one isn't already initialized.
        # The main script's logic is responsible for the very first initialization if appropriate for that context.
        if ($CallingScriptIsSelfInvoked) {
            $shouldDeferInitialToast = $true # Defer if self-invoked, regardless of $CallingScriptIsInteractive here
            Write-Log -Level Debug -Message "Update-PersistentToast: Potential deferral: CallingScriptIsSelfInvoked is TRUE. shouldDeferInitialToast set to TRUE."
        } else {
            Write-Log -Level Debug -Message "Update-PersistentToast: Potential deferral: CallingScriptIsSelfInvoked is FALSE. shouldDeferInitialToast remains FALSE."
        }

        Write-Log -Level DEBUG -Message "Update-PersistentToast: Before Create/Update decision. Global:PersistentToastInitialized = $Global:PersistentToastInitialized, shouldDeferInitialToast = $shouldDeferInitialToast"

        # Create toast only if not already initialized AND (it's not a deferred scenario OR it is deferred but something else already initialized it)
        # The main condition is: if not initialized AND we are NOT in a scenario that should defer.
        if (-not $Global:PersistentToastInitialized -and -not $shouldDeferInitialToast) {
            # --- Create Toast on First Call using New-BurntToastNotification ---
            Write-Log -Level DEBUG -Message "Persistent toast not initialized AND not deferred. Attempting to CREATE with New-BurntToastNotification."
            try {
                Write-Log -Level DEBUG -Message ("Update-PersistentToast CREATE: Current Global:PersistentToastData before New-BTProgressBar: " + ($Global:PersistentToastData | ConvertTo-Json -Depth 3 -Compress))
                # Define progress bars using the keys from the data binding hashtable
                $localProgressBar = New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "Task Progress" -ErrorAction SilentlyContinue
                $localOverallProgressBar = New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "Overall Progress" -ErrorAction SilentlyContinue
                $AppLogoPath = (Join-Path $PSScriptRoot '..\ms.png')

                # Define parameters for New-BurntToastNotification
                $NewToastParams = @{
                    UniqueIdentifier = $Global:PersistentToastId
                    Text             = "StatusText" # Bind to the key in DataBinding
                    ProgressBar      = @($localProgressBar, $localOverallProgressBar) # Pass bars here
                    DataBinding      = $Global:PersistentToastData
                    AppLogo          = $AppLogoPath
                    SnoozeAndDismiss = $true
                    Silent           = $true
                    ErrorAction      = 'Stop'
                }
                if (-not [string]::IsNullOrEmpty($script:ResolvedToastAppId)) { $NewToastParams['AppId'] = $script:ResolvedToastAppId }

                # Safely log parameters
                $newToastParamsString = $NewToastParams | Format-List | Out-String
                if ($DebugPreference -ne 'SilentlyContinue') { Write-Log -Level Info -Message "NewToastParams BEFORE New-BurntToastNotification call:`n$newToastParamsString" }
                Write-Log -Level DEBUG -Message ("Update-PersistentToast CREATE: Params for New-BurntToastNotification: " + ($NewToastParams | Out-String))
                Write-Log -Level DEBUG -Message "Update-PersistentToast CREATE: State before New-BurntToastNotification: PersistentToastInitialized = $Global:PersistentToastInitialized"
                Write-Log -Level DEBUG -Message ("Update-PersistentToast CREATE: State before New-BurntToastNotification: PersistentToastData (JSON) = " + ($Global:PersistentToastData | ConvertTo-Json -Depth 3 -Compress))
                New-BurntToastNotification @NewToastParams
                $Global:PersistentToastInitialized = $true # Set flag AFTER successful creation
                Write-Log -Level INFO -Message "Persistent toast created successfully via New-BurntToastNotification (AppId used: $(if ($NewToastParams.ContainsKey('AppId')) {$NewToastParams['AppId']} else {'Default'}))."
                Write-Log -Level DEBUG -Message ("Update-PersistentToast CREATE SUCCEEDED. Global:PersistentToastInitialized is now: $Global:PersistentToastInitialized")

            } catch { # Catch ANY error during creation
                Write-Log -Level Error -Message "Error creating persistent toast on first update call: ($($_ | Out-String))"
                $Global:PersistentToastInitialized = $false # Reset flag on failure
                Write-Log -Level DEBUG -Message ("Update-PersistentToast CREATE FAILED. Global:PersistentToastInitialized is now: $Global:PersistentToastInitialized")
            }
        } # <-- Closing brace for 'if (-not $Global:PersistentToastInitialized)'
        else {
            # --- Update Existing Toast using Update-BTNotification (Only if dot-sourced) ---
            # Use $script:IsInteractiveRun from the calling script scope as the reliable indicator - Condition removed for unconditional update
            Write-Log -Level Debug -Message "Persistent toast already initialized or creation deferred. Attempting to UPDATE via Update-BTNotification with DataBinding."
            try {
                $UpdateParams = @{
                    UniqueIdentifier = $Global:PersistentToastId
                    DataBinding      = $Global:PersistentToastData # Pass the *entire* updated hashtable
                    ErrorAction      = 'Stop'
                }
                if (-not [string]::IsNullOrEmpty($script:ResolvedToastAppId)) { $UpdateParams['AppId'] = $script:ResolvedToastAppId }

                # Log parameters before update
                $dataBindingJson = $Global:PersistentToastData | ConvertTo-Json -Depth 5
                Write-Log -Level Debug -Message "DataBinding Hashtable (JSON) BEFORE Update-BTNotification call:`n$dataBindingJson"
                $updateParamsString = $UpdateParams | Format-List | Out-String
                if ($DebugPreference -ne 'SilentlyContinue') { Write-Log -Level Info -Message "UpdateParams BEFORE Update-BTNotification call:`n$updateParamsString" }
                Write-Log -Level DEBUG -Message ("Update-PersistentToast UPDATE: Params for Update-BTNotification: " + ($UpdateParams | Out-String))
                Write-Log -Level DEBUG -Message "Update-PersistentToast UPDATE: State before Update-BTNotification: PersistentToastInitialized = $Global:PersistentToastInitialized"
                # PersistentToastData is already logged as JSON at line 247 before this call, which is sufficient.
                Update-BTNotification @UpdateParams
                Write-Log -Level INFO -Message "Persistent toast updated successfully via Update-BTNotification (AppId used: $(if ($UpdateParams.ContainsKey('AppId')) {$UpdateParams['AppId']} else {'Default'}))."
                Write-Log -Level DEBUG -Message ("Update-PersistentToast UPDATE SUCCEEDED.")
            } catch { # Catch for inner try
                 Write-Log -Level Error -Message "Error updating persistent toast via Update-BTNotification: ($($_ | Out-String))"
                 Write-Log -Level DEBUG -Message ("Update-PersistentToast UPDATE FAILED.")
            }
        } # End else block for if(-not $Global:PersistentToastInitialized)

    } catch { # Catch block for main try
        Write-Log -Level Error -Message "An unexpected error occurred during persistent toast update/creation logic: ($($_ | Out-String))"
        Write-Log -Level DEBUG -Message ("Update-PersistentToast: Main try-catch caught error. Global:PersistentToastInitialized before Exit-Function: $Global:PersistentToastInitialized")
    } finally { # Finally block for main try
        Write-Log -Level DEBUG -Message ("Update-PersistentToast: In finally block. Global:PersistentToastInitialized before Exit-Function: $Global:PersistentToastInitialized")
        Exit-Function
    }
} # Closing brace for the Update-PersistentToast function
#endregion Progress Toast Function

# --- Helper function for Pre-Check Toast Update ---
function Update-PreCheckToast {
    param(
        [string]$CheckName,
        [int]$CurrentCheckNum,
        [int]$TotalChecks,
        # Context Parameters
        [Parameter(Mandatory=$true)][bool]$IsInteractive,
        [Parameter(Mandatory=$true)][bool]$ErrorOccurred,
        [Parameter(Mandatory=$true)][bool]$AnyUpdatePerformed,
        # Weight Parameters (passed through to Update-PersistentToast)
        [Parameter(Mandatory=$false)][double]$CurrentWeight,
        [Parameter(Mandatory=$false)][double]$TotalWeight
    )
    if ($TotalChecks -le 0) { return } # Avoid division by zero
    $progressPercent = ($CurrentCheckNum / $TotalChecks) * 100
    $progressValue = $progressPercent / 100

    # Update the global data binding hashtable for progress bar elements ONLY if interactive (dot-sourced)
    # because Update-BTNotification (which reads these values) will only be called in that case.
    # This prevents log confusion where data appears updated but isn't visually.
    if ($script:IsInteractiveRun) {
        $Global:PersistentToastData['ProgressBarStatus'] = $CheckName # Updates the "Download: -" text
        $Global:PersistentToastData['ProgressBarValue']  = $progressValue # Updates the progress bar
        Write-Log -Level DEBUG -Message "$CheckName ($CurrentCheckNum/$TotalChecks) - Updating Global Toast Data for Progress Bar (Interactive)"
    } else {
         Write-Log -Level DEBUG -Message "$CheckName ($CurrentCheckNum/$TotalChecks) - Skipping Global Toast Data update for Progress Bar (Non-Interactive)"
    }

    # REMOVED: Call Update-PersistentToast to attempt visual update during pre-checks
    # Let the main script loop handle the visual updates at major step boundaries.
    # Update-PersistentToast -IsInteractive $IsInteractive -ErrorOccurred $ErrorOccurred -AnyUpdatePerformed $AnyUpdatePerformed -CurrentWeight $CurrentWeight -TotalWeight $TotalWeight
}
# --- End Helper ---

function Show-FinalStatusToast {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$StatusMessage,
        [Parameter(Mandatory=$true)][bool]$Success,
        [Parameter(Mandatory=$false)][string]$LogFileToShow,
        [Parameter(Mandatory=$false)][string]$TeamsLink,
        [Parameter(Mandatory=$false)][bool]$LoxoneAppInstalled
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber

    try {
        Write-Log -Level Debug -Message "Show-FinalStatusToast called. Success: $Success, LoxoneAppInstalled: $LoxoneAppInstalled, TeamsLink provided: $(!([string]::IsNullOrEmpty($TeamsLink)))"
        Write-Log -Level Debug -Message "Generating final status toast using template structure (Submit-BTNotification)."

        # 1. Determine Variables
        $AppLogoPath = if ($Success) { Join-Path $PSScriptRoot '..\ok.png' } else { Join-Path $PSScriptRoot '..\nok.png' }
        $FinalStatusMessage = $StatusMessage
        $logPathForAction = $null
        if (-not [string]::IsNullOrEmpty($LogFileToShow)) { $logPathForAction = $LogFileToShow } elseif ($script:LogFilePath -and (Test-Path $script:LogFilePath)) { $logPathForAction = $script:LogFilePath }
        $chatScriptPath = Join-Path $PSScriptRoot '..\Send-GoogleChat.ps1' # Assuming relative path works
        # Use the GLOBAL PersistentToastId to REPLACE the progress toast, even for errors.
        # $TimestampSuffix = Get-Date -Format 'yyyyMMddHHmmssfff' # Removed timestamp suffix
        # $ToastGUID = $Global:PersistentToastId + "_Final_" + $TimestampSuffix # Removed suffix logic
        $ToastGUID = $Global:PersistentToastId + "_Final" # Use a different ID for the final toast
        Write-Log -Level Debug -Message "Using ToastGUID: $ToastGUID for final status toast (to replace progress)."

        # 2. Define Content Elements
        $text1 = New-BTText -Content $FinalStatusMessage
        $image1 = if (Test-Path $AppLogoPath) { New-BTImage -Source $AppLogoPath -AppLogoOverride } else { $null }
        $binding1 = if ($image1) { New-BTBinding -Children $text1 -AppLogoOverride $image1 } else { New-BTBinding -Children $text1 }
        $visual1 = New-BTVisual -BindingGeneric $binding1
        $audio = New-BTAudio -Silent

        # 3. Define Buttons (Max 5 total with context items)
        $buttons = [System.Collections.Generic.List[object]]::new()
        $buttons.Add((New-BTButton -Dismiss -Content 'Close'))
        if ($logPathForAction) {
            # Button to just open the log file locally
            $buttons.Add((New-BTButton -Content 'Open Log' -Arguments $logPathForAction))

            # Button to send the log file via Google Chat (only add if not successful)
            if (-not $Success -and $buttons.Count -lt 5) {
                $chatScriptPath = Join-Path $PSScriptRoot '..\Send-GoogleChat.ps1'
                if (Test-Path -LiteralPath $chatScriptPath) {
                    $quotedChatScriptPath = """$chatScriptPath"""
                    $quotedLogPath = """$logPathForAction"""
                    # Construct the command to be executed when the button is clicked
                    $chatButtonCommand = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File $quotedChatScriptPath -LogFilePath $quotedLogPath"
                    Write-Log -Level Debug -Message ("Adding 'Send Log via Chat' button with command: '{0}'" -f $chatButtonCommand)
                    $buttons.Add((New-BTButton -Content 'Send Log via Chat' -Arguments $chatButtonCommand))
                } else {
                    Write-Log -Level Warning -Message "Chat script not found at '$chatScriptPath'. Cannot add 'Send Log via Chat' button."
                }
            }
        }
        if ($LoxoneAppInstalled -and $buttons.Count -lt 5) { $buttons.Add((New-BTButton -Content 'APP' -Arguments 'loxone:/')) }
        if (-not [string]::IsNullOrEmpty($TeamsLink) -and $buttons.Count -lt 5) { $buttons.Add((New-BTButton -Content 'Team' -Arguments $TeamsLink)) }
        # Add Snooze button for persistence with Reminder scenario
        if ($buttons.Count -lt 5) { $buttons.Add((New-BTButton -Snooze)) }

        # 4. Define Context Menu Items (Optional, check limit)
        $contextMenuItems = [System.Collections.Generic.List[object]]::new()
        # Example: Add only if total actions < 5
        # if (($buttons.Count + $contextMenuItems.Count) -lt 5) {
        #     $contextMenuItems.Add((New-BTContextMenuItem -Content 'Some Action' -Arguments 'some:arg'))
        # }

        # 5. Define Actions
        $actions1 = New-BTAction -Buttons $buttons -ContextMenuItems $contextMenuItems

        $actions1 = New-BTAction -Buttons $buttons -ContextMenuItems $contextMenuItems

        # 6. Define Launch Command (REMOVED - Functionality moved to explicit button)
        # $launchCommand = $null
        # ... (Removed launch command definition logic) ...

        # 7. Define Content (with Reminder Scenario)
        $content = New-BTContent -Visual $visual1 -Actions $actions1 -Audio $audio -Scenario ([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Reminder)
        # REMOVED: if ($launchCommand) { $content.Launch = $launchCommand }
        Write-Log -Level Debug -Message "Defined Content. Scenario: Reminder, Launch property is NOT set."

        # 8. Define Submit Parameters
        $SubmitParams = @{
            Content          = $content
            ErrorAction      = 'Stop'
            UniqueIdentifier = $ToastGUID # Use the persistent ID to replace progress toast
        }
        if (-not [string]::IsNullOrEmpty($script:ResolvedToastAppId)) {
            $SubmitParams['AppId'] = $script:ResolvedToastAppId
        }
        # --- End Submit Parameter Definition ---

        # 9. Submit Notification
        Write-Log -Level Info -Message "Submitting final status toast via Submit-BTNotification. Params: $($SubmitParams | Out-String)"
        Submit-BTNotification @SubmitParams
        Write-Log -Level Info -Message "Final status toast submitted successfully via Submit-BTNotification (AppId used: $(if ($SubmitParams.ContainsKey('AppId')) {$SubmitParams['AppId']} else {'Default'}))."

    } catch { # Catch block for the main try starting at line 271
        Write-Log -Level Error -Message "An unexpected error occurred during final status toast generation/submission: ($($_ | Out-String))"
    } finally { # Finally block for the main try starting at line 271
        Exit-Function
    }
} # Closing brace for the Show-FinalStatusToast function