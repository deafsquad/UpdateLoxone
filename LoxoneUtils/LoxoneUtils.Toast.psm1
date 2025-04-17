#Requires -Modules BurntToast

#region Global Variables
# Initialize global variables if they don't exist
if (-not (Test-Path variable:Global:PersistentToastId)) {
    $Global:PersistentToastId = "LoxoneUpdateStatusToast" # Default ID
}
# Removed PersistentToastInitialized - logic changed
if (-not (Test-Path variable:Global:PersistentToastData)) {
    # Initialize with expected keys for data binding
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

    # Always prefer the hardcoded AppId for BurntToast consistency
    Write-Log -Level Info -Message "Using hardcoded Loxone Config AppId: '$hardcodedAppIdFormat'"
    $appId = $hardcodedAppIdFormat

    Write-Log -Level Debug -Message "Get-LoxoneConfigToastAppId: Found Loxone Config AppId '$appId'."
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
            [Parameter(Mandatory=$false)][double]$TotalWeight
        )

    $logMsg = "Updating persistent toast."
    if ($PSBoundParameters.ContainsKey('StepName')) { $logMsg += " Step: '$StepName' ($StepNumber/$TotalSteps)" }
    if ($PSBoundParameters.ContainsKey('DownloadFileName')) { $logMsg += " | Download: '$DownloadFileName' ($DownloadNumber/$TotalDownloads)" }
    if ($PSBoundParameters.ContainsKey('ProgressPercentage')) { $logMsg += " | Download Progress: $ProgressPercentage%" }
    if ($PSBoundParameters.ContainsKey('CurrentWeight')) { $logMsg += " | Overall Weight: $CurrentWeight/$TotalWeight" }
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber

    try {
        # --- Update Global Data Bindings ---
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

        # --- Create or Update ---
        if (-not $Global:PersistentToastInitialized) {
            # --- Create Toast on First Call using New-BurntToastNotification ---
            Write-Log -Level Debug -Message "Persistent toast not initialized. Creating with New-BurntToastNotification."
            try {
                $localProgressBar = New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "Task Progress"
                $localOverallProgressBar = New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "Overall Progress"
                $AppLogoPath = (Join-Path $PSScriptRoot '..\ms.png')
                $NewToastParams = @{
                    UniqueIdentifier = $Global:PersistentToastId
                    Text             = $Global:PersistentToastData['StatusText']
                    ProgressBar      = @($localProgressBar, $localOverallProgressBar)
                    DataBinding      = $Global:PersistentToastData
                    AppLogo          = $AppLogoPath
                    SnoozeAndDismiss = $true
                    Silent           = $true
                    ErrorAction      = 'Stop'
                }
                $appIdToUse = $script:ResolvedToastAppId
                if (-not [string]::IsNullOrEmpty($appIdToUse)) {
                    $NewToastParams['AppId'] = $appIdToUse
                }
                Write-Log -Level Info -Message "DataBinding BEFORE Update-BTNotification call: $($Global:PersistentToastData | Out-String)"
                Write-Log -Level Info -Message "UpdateParams BEFORE Update-BTNotification call: $($UpdateParams | Out-String)"
                New-BurntToastNotification @NewToastParams
                $Global:PersistentToastInitialized = $true # Set flag AFTER successful creation
                Write-Log -Level INFO -Message "Persistent toast created successfully via New-BurntToastNotification (AppId used: $(if ($appIdToUse) {$appIdToUse} else {'Default'}))."
            } catch {
                Write-Log -Level Error -Message "Error creating persistent toast on first update call: ($($_ | Out-String))"
                $Global:PersistentToastInitialized = $false # Reset flag on failure
                return
            }
        } else {
            # --- Submit Update using Update-BTNotification ---
            Write-Log -Level Debug -Message "Persistent toast initialized. Attempting update via Update-BTNotification."
            try {
                $currentToastId = $Global:PersistentToastId
                $currentAppId = $script:ResolvedToastAppId
                if ([string]::IsNullOrEmpty($currentToastId)) {
                    Write-Log -Level Error -Message "CRITICAL: UniqueIdentifier is NULL or EMPTY before Update-BTNotification! Update will fail."
                    return
                }
                $UpdateParams = @{
                    UniqueIdentifier = $currentToastId
                    DataBinding      = $Global:PersistentToastData
                    ErrorAction      = 'Stop'
                }
                if (-not [string]::IsNullOrEmpty($currentAppId)) {
                    $UpdateParams['AppId'] = $currentAppId
                }
                Write-Log -Level Info -Message "DataBinding BEFORE Update-BTNotification call: $($Global:PersistentToastData | Out-String)"
                Write-Log -Level Info -Message "UpdateParams BEFORE Update-BTNotification call: $($UpdateParams | Out-String)"
                [void](Update-BTNotification @UpdateParams)
                Write-Log -Level Debug -Message "Update-BTNotification called successfully (AppId used: $(if ($UpdateParams.ContainsKey('AppId')) {$UpdateParams['AppId']} else {'Default'}))."
            } catch {
                Write-Log -Level Error -Message "Error updating persistent toast directly: ($($_ | Out-String))"
                # Consider if we should try to re-create the toast here if update fails
            }
        }

    } catch { Write-Log -Level Error -Message "An unexpected error occurred during persistent toast update/creation logic: ($($_ | Out-String))" }
    finally { Exit-Function }
}

#endregion Progress Toast Function
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
        # Generate a unique ID for each final toast instance by adding a timestamp
        $TimestampSuffix = Get-Date -Format 'yyyyMMddHHmmssfff'
        $ToastGUID = $Global:PersistentToastId + "_Final_" + $TimestampSuffix
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
        if ($logPathForAction) { $buttons.Add((New-BTButton -Content 'Open Log' -Arguments $logPathForAction)) }
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

        # 6. Define Launch Command
        $launchCommand = $null
        if ($logPathForAction -and (Test-Path -LiteralPath $chatScriptPath)) {
            $quotedChatScriptPath = """$chatScriptPath"""
            $quotedLogPath = """$logPathForAction"""
            $launchCommand = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File $quotedChatScriptPath -LogFilePath $quotedLogPath"
            Write-Log -Level Debug -Message ("Defined Launch Command: '{0}'" -f $launchCommand)
        } elseif (-not (Test-Path -LiteralPath $chatScriptPath)) {
             Write-Log -Level Warning -Message "Cannot define Launch Command: Chat script not found at '$chatScriptPath'."
        } else {
             Write-Log -Level Warning -Message "Cannot define Launch Command: Log path for action is not valid."
        }

        # 7. Define Content (with Reminder Scenario)
        $content = New-BTContent -Visual $visual1 -Actions $actions1 -Audio $audio -Scenario ([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Reminder)
        if ($launchCommand) {
            $content.Launch = $launchCommand # Add Launch property if defined
        }
        Write-Log -Level Debug -Message "Defined Content. Scenario: Reminder, Launch set: $(!([string]::IsNullOrEmpty($content.Launch)))"

        # 8. Define Submit Parameters
        $SubmitParams = @{
            Content = $content
            ErrorAction = 'Stop'
            UniqueIdentifier = $ToastGUID # Use the persistent ID to replace progress toast
        }
        if (-not [string]::IsNullOrEmpty($script:ResolvedToastAppId)) {
            $SubmitParams['AppId'] = $script:ResolvedToastAppId
        }

        # 9. Submit Notification
        Write-Log -Level Info -Message "Submitting final status toast via Submit-BTNotification. Params: $($SubmitParams | Out-String)"
        Submit-BTNotification @SubmitParams
        Write-Log -Level Info -Message "Final status toast submitted successfully via Submit-BTNotification (AppId used: $(if ($SubmitParams.ContainsKey('AppId')) {$SubmitParams['AppId']} else {'Default'}))."

    } catch {
        Write-Log -Level Error -Message "An unexpected error occurred during final status toast generation/submission: ($($_ | Out-String))"
    } finally {
        Exit-Function
    }
}

Export-ModuleMember -Function Initialize-LoxoneToastAppId, Update-PersistentToast, Show-FinalStatusToast