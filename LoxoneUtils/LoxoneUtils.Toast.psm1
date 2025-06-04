# Optimized LoxoneUtils.Toast Module
# Key improvements:
# 1. Reduced redundant logging
# 2. Centralized parameter validation
# 3. Simplified data binding updates
# 4. Better separation of concerns
# 5. Removed duplicate code blocks

#region Module Initialization
$script:IsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem

if (-not $script:IsSystem -and -not (Get-Module -Name BurntToast -ListAvailable)) {
    Write-Warning "BurntToast module not installed. Toast notifications unavailable."
    Write-Warning "Install with: Install-Module -Name BurntToast -Force"
}
#endregion

#region Toast Configuration
class ToastConfiguration {
    [string]$DefaultId = "LoxoneUpdateStatusToast"
    [string]$AppIdFormat = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'
    [hashtable]$DataTemplate = @{
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
        DownloadSpeedLine     = ""
        DownloadTimeLine      = ""
        DownloadSizeLine      = ""
    }
}

# Initialize global state
$script:Config = [ToastConfiguration]::new()
if (-not (Test-Path variable:Global:PersistentToastId)) {
    $Global:PersistentToastId = $script:Config.DefaultId
}
if (-not (Test-Path variable:Global:PersistentToastInitialized)) {
    $Global:PersistentToastInitialized = $false
}
# CRITICAL FIX: Only initialize data binding ONCE per session
# This prevents the toast from dismissing when transitioning between operations
if (-not (Test-Path variable:Global:PersistentToastData)) {
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level Debug -Message "Initializing Global:PersistentToastData for the first time"
    }
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
        DownloadSpeedLine     = ""
        DownloadTimeLine      = ""
        DownloadSizeLine      = ""
    }
} else {
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level Debug -Message "Global:PersistentToastData already exists - preserving existing object"
    }
}
#endregion

#region Helper Functions
function Get-ParameterSummary {
    param([hashtable]$BoundParameters)
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        $summary = @{}
    foreach ($key in $BoundParameters.Keys) {
        $value = $BoundParameters[$key]
        $summary[$key] = if ($value -is [string] -and $value.Length -gt 50) {
            "$($value.Substring(0, 47))..."
        } else { $value }
    }
        return $summary
    }
    finally {
        Exit-Function
    }
}
#endregion

#region AppId Management
function Get-LoxoneToastAppId {
    [CmdletBinding()]
    param([string]$PreFoundPath)
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $loxonePath = $PreFoundPath
        if (-not $loxonePath) {
            Write-Log -Level Debug -Message "No pre-found path provided. Searching registry..."
            try {
                $loxonePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Level Warn -Message "Error calling Get-LoxoneExePath: $($_.Exception.Message)"
            }
        }
        
        if ($loxonePath) {
            Write-Log -Level Info -Message "Using hardcoded Loxone Config AppId"
            return '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'
        }
        
        Write-Log -Level Info -Message "No Loxone Config found. Using default AppId."
        return $null
    }
    finally { Exit-Function }
}

function Initialize-LoxoneToastAppId {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $script:ResolvedToastAppId = Get-LoxoneToastAppId -PreFoundPath $script:InstalledExePath
        Write-Log -Level Debug -Message "Resolved Toast AppId: '$($script:ResolvedToastAppId | Out-String)'"
    }
    finally { Exit-Function }
}
#endregion

#region Data Binding Updates
function Update-ToastDataBinding {
    <#
    .SYNOPSIS
    Safely updates the global toast data binding without recreating the object
    .DESCRIPTION
    CRITICAL: This function only updates individual keys to preserve the data binding.
    Never assign a new hashtable to $Global:PersistentToastData!
    #>
    param(
        [hashtable]$Updates,
        [switch]$PreserveExisting
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        if (-not $Updates) { return }
    
    # Verify we're not accidentally trying to replace the entire object
    if ($Updates -eq $Global:PersistentToastData) {
        Write-Log -Level Error -Message "CRITICAL: Attempted to replace entire PersistentToastData object!"
        throw "Cannot replace PersistentToastData object - use individual key updates only"
    }
    
    foreach ($key in $Updates.Keys) {
        if ($Updates[$key] -ne $null -or -not $PreserveExisting) {
            # CRITICAL: Update individual key, never recreate the hashtable
            $Global:PersistentToastData[$key] = $Updates[$key]
        }
    }
    }
    finally {
        Exit-Function
    }
}

function Build-StatusText {
    param(
        [hashtable]$Params
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        $baseText = if ($Params.StepNumber -and $Params.TotalSteps -and $Params.StepName) {
        "Step $($Params.StepNumber)/$($Params.TotalSteps): $($Params.StepName)"
    } else {
        $Global:PersistentToastData['StatusText'].Split("`n")[0]
    }
    
    $details = @()
    if ($Params.DownloadSpeed) { $details += "Speed: $($Params.DownloadSpeed)" }
    if ($Params.DownloadRemainingTime) { $details += "Time Rem: $($Params.DownloadRemainingTime)" }
    if ($Params.DownloadSizeProgress) { $details += "Size: $($Params.DownloadSizeProgress)" }
    
    if ($details.Count -gt 0) {
        return (@($baseText) + $details) -join "`n"
    }
        return $baseText
    }
    finally {
        Exit-Function
    }
}

function Build-ProgressBarStatus {
    param(
        [hashtable]$Params
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        if ($Params.DownloadFileName) {
        if ($Params.DownloadNumber -and $Params.TotalDownloads) {
            return "Download $($Params.DownloadNumber)/$($Params.TotalDownloads): $($Params.DownloadFileName)"
        }
        return "Download: $($Params.DownloadFileName)"
    }
    elseif ($Params.StepName -eq 'Downloads Complete') {
        return "Downloads: Done"
    }
        return $Global:PersistentToastData['ProgressBarStatus']
    }
    finally {
        Exit-Function
    }
}

function Calculate-ProgressValues {
    param(
        [hashtable]$Params
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        $result = @{}
    
    # Download progress
    if ($Params.ContainsKey('ProgressPercentage') -and 
        $Global:PersistentToastData['ProgressBarStatus'] -ne "Downloads: Done") {
        $result.ProgressBarValue = [Math]::Max(0.0, [Math]::Min(1.0, ($Params.ProgressPercentage / 100)))
    }
    
    # Overall progress
    if ($Params.ContainsKey('CurrentWeight') -and $Params.ContainsKey('TotalWeight')) {
        $totalWeight = [Math]::Max(1, $Params.TotalWeight)
        $progress = [Math]::Max(0.0, [Math]::Min(1.0, ($Params.CurrentWeight / $totalWeight)))
        $result.OverallProgressValue = $progress
        $result.OverallProgressStatus = "Overall: {0:P0}" -f $progress
        $result.CurrentWeight = $Params.CurrentWeight
        $result.TotalWeight = $totalWeight
    }
    
        return $result
    }
    finally {
        Exit-Function
    }
}
#endregion

#region Main Toast Functions
function Update-PersistentToast {
    [CmdletBinding()]
    param(
        # Step Info
        [int]$StepNumber,
        [int]$TotalSteps,
        [string]$StepName,
        # Download Info
        [string]$DownloadFileName,
        [int]$DownloadNumber,
        [int]$TotalDownloads,
        [double]$ProgressPercentage,
        [string]$DownloadSpeed,
        [string]$DownloadRemainingTime,
        [string]$DownloadSizeProgress,
        # Weight Info
        [double]$CurrentWeight,
        [double]$TotalWeight,
        # Context (Required)
        [Parameter(Mandatory)][bool]$IsInteractive,
        [Parameter(Mandatory)][bool]$ErrorOccurred,
        [bool]$AnyUpdatePerformed = $false,
        [bool]$CallingScriptIsInteractive = $false,
        [bool]$CallingScriptIsSelfInvoked = $false
    )
    
    Start-Sleep -Milliseconds 50  # Small delay for visibility
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Verify data binding object still exists (safety check)
        if (-not (Test-Path variable:Global:PersistentToastData)) {
            Write-Log -Level Error -Message "CRITICAL: Global:PersistentToastData was deleted! This should never happen."
            throw "PersistentToastData was deleted - toast binding is broken"
        }
        
        # Log parameter summary (consolidated)
        $paramSummary = Get-ParameterSummary $PSBoundParameters
        Write-Log -Level Debug -Message "Update-PersistentToast called with $($PSBoundParameters.Count) parameters: $($paramSummary | ConvertTo-Json -Compress)"
        
        # Build updates from parameters
        $updates = @{}
        
        # Basic step info
        if ($PSBoundParameters.ContainsKey('StepNumber')) { $updates.StepNumber = $StepNumber }
        if ($PSBoundParameters.ContainsKey('TotalSteps')) { $updates.TotalSteps = $TotalSteps }
        if ($PSBoundParameters.ContainsKey('StepName')) { $updates.StepName = $StepName }
        
        # Download info
        if ($PSBoundParameters.ContainsKey('DownloadFileName')) { $updates.DownloadFileName = $DownloadFileName }
        if ($PSBoundParameters.ContainsKey('DownloadNumber')) { $updates.DownloadNumber = $DownloadNumber }
        if ($PSBoundParameters.ContainsKey('TotalDownloads')) { $updates.TotalDownloads = $TotalDownloads }
        
        # Calculate derived values
        $updates.StatusText = Build-StatusText $PSBoundParameters
        $updates.ProgressBarStatus = Build-ProgressBarStatus $PSBoundParameters
        
        $progressValues = Calculate-ProgressValues $PSBoundParameters
        foreach ($key in $progressValues.Keys) {
            $updates[$key] = $progressValues[$key]
        }
        
        # Special case for completed downloads
        if ($StepName -eq 'Downloads Complete') {
            $updates.ProgressBarValue = 1.0
        }
        
        # Update global data
        Update-ToastDataBinding -Updates $updates
        
        # Determine if we should defer initial creation
        $shouldDefer = $CallingScriptIsSelfInvoked
        
        # Create or update toast
        if (-not $Global:PersistentToastInitialized -and -not $shouldDefer) {
            Initialize-Toast
        }
        elseif ($Global:PersistentToastInitialized) {
            Update-Toast
        }
        else {
            Write-Log -Level Debug -Message "Toast update deferred (self-invoked context)"
        }
    }
    catch {
        Write-Log -Level Error -Message "Error in Update-PersistentToast: $_"
    }
    finally {
        Exit-Function
    }
}

function Initialize-Toast {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level Info -Message "Creating initial toast notification with buttons"
    
    try {
        # Create components
        $text = New-BTText -Content "StatusText"
        $progressBar1 = New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "Task Progress"
        $progressBar2 = New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "Overall Progress"
        $appLogo = Join-Path $PSScriptRoot '..\ms.png'
        
        # Create binding
        $binding = New-BTBinding -Children $text, $progressBar1, $progressBar2
        if (Test-Path $appLogo) {
            $image = New-BTImage -Source $appLogo -AppLogoOverride
            $binding = New-BTBinding -Children $text, $progressBar1, $progressBar2 -AppLogoOverride $image
        }
        
        # Create visual
        $visual = New-BTVisual -BindingGeneric $binding
        
        # Create audio (silent)
        $audio = New-BTAudio -Silent
        
        # Create buttons
        $buttons = @(
            New-BTButton -Dismiss -Content 'Dismiss'
            New-BTButton -Snooze
        )
        $actions = New-BTAction -Buttons $buttons
        
        # Create content with Reminder scenario to prevent auto-dismiss
        $content = New-BTContent -Visual $visual -Audio $audio -Actions $actions `
            -Scenario ([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Reminder) `
            -Duration ([Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long)
        
        # Build parameters
        $params = @{
            Content          = $content
            UniqueIdentifier = $Global:PersistentToastId
            DataBinding      = $Global:PersistentToastData
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        # Submit notification with scenario
        Submit-BTNotification @params
        $Global:PersistentToastInitialized = $true
        
        Write-Log -Level Info -Message "Toast created successfully with Reminder scenario"
    }
    catch {
        $Global:PersistentToastInitialized = $false
        Write-Log -Level Error -Message "Failed to create toast: $_"
        throw
    }
    finally {
        Exit-Function
    }
}

function Update-Toast {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level Debug -Message "Updating existing toast"
    
    try {
        $params = @{
            UniqueIdentifier = $Global:PersistentToastId
            DataBinding      = $Global:PersistentToastData
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        Update-BTNotification @params
        Write-Log -Level Debug -Message "Toast updated successfully"
    }
    catch {
        Write-Log -Level Error -Message "Failed to update toast: $_"
        throw
    }
    finally {
        Exit-Function
    }
}
#endregion

#region Helper Functions
function Update-PreCheckToast {
    param(
        [string]$CheckName,
        [int]$CurrentCheckNum,
        [int]$TotalChecks,
        [Parameter(Mandatory)][bool]$IsInteractive,
        [Parameter(Mandatory)][bool]$ErrorOccurred,
        [Parameter(Mandatory)][bool]$AnyUpdatePerformed,
        [double]$CurrentWeight,
        [double]$TotalWeight
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        if ($TotalChecks -le 0) { return }
    
    # Only update data if interactive
    if ($script:IsInteractiveRun) {
        $progressValue = $CurrentCheckNum / $TotalChecks
        Update-ToastDataBinding -Updates @{
            ProgressBarStatus = $CheckName
            ProgressBarValue  = $progressValue
        }
        Write-Log -Level Debug -Message "$CheckName ($CurrentCheckNum/$TotalChecks)"
    }
    }
    finally {
        Exit-Function
    }
}
#endregion

#region Final Status Toast
function Show-FinalStatusToast {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StatusMessage,
        [Parameter(Mandatory)][bool]$Success,
        [string]$LogFileToShow,
        [string]$TeamsLink,
        [bool]$LoxoneAppInstalled
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        Write-Log -Level Info -Message "Creating final status toast (Success: $Success)"
        
        # Determine resources
        $appLogo = Join-Path $PSScriptRoot "..\" $(if ($Success) { "ok.png" } else { "nok.png" })
        $toastId = "${Global:PersistentToastId}_Final"
        $logPath = if ($LogFileToShow) { $LogFileToShow } else { $script:LogFilePath }
        
        # Build visual
        $text = New-BTText -Content $StatusMessage
        $image = if (Test-Path $appLogo) { New-BTImage -Source $appLogo -AppLogoOverride } else { $null }
        $binding = if ($image) { 
            New-BTBinding -Children $text -AppLogoOverride $image 
        } else { 
            New-BTBinding -Children $text 
        }
        $visual = New-BTVisual -BindingGeneric $binding
        
        # Build buttons
        $buttons = [System.Collections.Generic.List[object]]::new()
        $buttons.Add((New-BTButton -Dismiss -Content 'Close'))
        
        if ($logPath -and (Test-Path $logPath)) {
            $buttons.Add((New-BTButton -Content 'Open Log' -Arguments $logPath))
            
            if (-not $Success) {
                $chatScript = Join-Path $PSScriptRoot '..\Send-GoogleChat.ps1'
                if (Test-Path $chatScript) {
                    $command = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$chatScript`" -LogFilePath `"$logPath`""
                    $buttons.Add((New-BTButton -Content 'Send Log via Chat' -Arguments $command))
                }
            }
        }
        
        if ($LoxoneAppInstalled -and $buttons.Count -lt 5) {
            $buttons.Add((New-BTButton -Content 'APP' -Arguments 'loxone://'))
        }
        
        if ($TeamsLink -and $buttons.Count -lt 5) {
            $buttons.Add((New-BTButton -Content 'Team' -Arguments $TeamsLink))
        }
        
        if ($buttons.Count -lt 5) {
            $buttons.Add((New-BTButton -Snooze))
        }
        
        # Build content
        $actions = New-BTAction -Buttons $buttons
        $audio = New-BTAudio -Silent
        $content = New-BTContent -Visual $visual -Actions $actions -Audio $audio `
            -Scenario ([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Reminder)
        
        # Submit
        $params = @{
            Content          = $content
            UniqueIdentifier = $toastId
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        Submit-BTNotification @params
        Write-Log -Level Info -Message "Final status toast submitted successfully"
    }
    catch {
        Write-Log -Level Error -Message "Failed to show final status toast: $_"
    }
    finally {
        Exit-Function
    }
}
#endregion

# Function to reset toast data without recreating the object
function Reset-ToastDataBinding {
    <#
    .SYNOPSIS
    Resets toast data to initial values WITHOUT recreating the object
    .DESCRIPTION
    This function updates individual keys to preserve the data binding.
    Use this instead of recreating the hashtable.
    #>
    [CmdletBinding()]
    param()
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        Write-Log -Level Debug -Message "Resetting toast data values (preserving object reference)"
    
    # Reset each key individually to preserve the binding
    $Global:PersistentToastData['StatusText'] = "Initializing..."
    $Global:PersistentToastData['ProgressBarStatus'] = "Download: -"
    $Global:PersistentToastData['ProgressBarValue'] = 0.0
    $Global:PersistentToastData['OverallProgressStatus'] = "Overall: 0%"
    $Global:PersistentToastData['OverallProgressValue'] = 0.0
    $Global:PersistentToastData['StepNumber'] = 0
    $Global:PersistentToastData['TotalSteps'] = 1
    $Global:PersistentToastData['StepName'] = "Initializing..."
    $Global:PersistentToastData['DownloadFileName'] = ""
    $Global:PersistentToastData['DownloadNumber'] = 0
    $Global:PersistentToastData['TotalDownloads'] = 0
    $Global:PersistentToastData['CurrentWeight'] = 0
    $Global:PersistentToastData['TotalWeight'] = 1
    $Global:PersistentToastData['DownloadSpeedLine'] = ""
    $Global:PersistentToastData['DownloadTimeLine'] = ""
    $Global:PersistentToastData['DownloadSizeLine'] = ""
    }
    finally {
        Exit-Function
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-LoxoneToastAppId'
    'Update-PersistentToast'
    'Update-PreCheckToast'
    'Show-FinalStatusToast'
    'Reset-ToastDataBinding'  # Export for testing scenarios
)