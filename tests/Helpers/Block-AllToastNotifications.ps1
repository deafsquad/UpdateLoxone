# Block-AllToastNotifications.ps1
# Aggressively blocks ALL toast notification attempts during tests

# Only show message if not already blocked
if (-not $Global:ToastBlockingActive) {
    Write-Host "BLOCKING ALL TOAST NOTIFICATIONS - Loading aggressive mocks..." -ForegroundColor Yellow
    
    # Load Windows API level blocking first
    $apiBlockerPath = Join-Path $PSScriptRoot "Block-WindowsToastAPI.ps1"
    if (Test-Path $apiBlockerPath) {
        . $apiBlockerPath
    }
}

# Track blocked notifications
$Global:BlockedToastCount = 0
$Global:BlockedToastDetails = @()

# Mark that blocking is active
$Global:ToastBlockingActive = $true

# First, unload BurntToast if it's loaded
Get-Module BurntToast | Remove-Module -Force -ErrorAction SilentlyContinue

# Prevent BurntToast from loading
$Global:PreventBurntToastLoad = $true

# Override all BurntToast functions globally
function Global:Submit-BTNotification {
    param($Content, $UniqueIdentifier, $AppId, $DataBinding)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "Submit-BTNotification: $UniqueIdentifier"
    Write-Debug "BLOCKED: Submit-BTNotification - $UniqueIdentifier"
}

function Global:Update-BTNotification {
    param($UniqueIdentifier, $DataBinding, $AppId)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "Update-BTNotification: $UniqueIdentifier"
    Write-Debug "BLOCKED: Update-BTNotification - $UniqueIdentifier"
}

function Global:New-BTProgressBar {
    param($Title, $Status, $Value)
    return @{ Type = 'BlockedProgressBar'; Title = $Title; Status = $Status; Value = $Value }
}

function Global:New-BTButton {
    param([switch]$Dismiss, [switch]$Snooze, $Content, $Arguments)
    return @{ Type = 'BlockedButton'; Dismiss = $Dismiss; Snooze = $Snooze }
}

function Global:New-BTAction {
    param($Buttons)
    return @{ Type = 'BlockedAction'; Buttons = $Buttons }
}

function Global:New-BTText {
    param($Text)
    return @{ Type = 'BlockedText'; Text = $Text }
}

function Global:New-BTVisual {
    param($Text, $Binding, $InlineImage)
    return @{ Type = 'BlockedVisual' }
}

function Global:New-BTContent {
    param($Visual, $Actions, $Audio, $ActivationType, $Scenario, $Duration)
    return @{ Type = 'BlockedContent' }
}

function Global:New-BTAudio {
    param([switch]$Silent)
    return @{ Type = 'BlockedAudio'; Silent = $Silent }
}

function Global:New-BurntToastNotification {
    param($Text, $Header, $AppLogo, [switch]$Silent, [switch]$SnoozeAndDismiss)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "New-BurntToastNotification: $Header"
    Write-Debug "BLOCKED: New-BurntToastNotification - $Header"
}

# Override ALL possible toast-related functions from LoxoneUtils modules
function Global:Show-UpdateLoxoneToast {
    param($StatusText, $ConfigResult, $AppResult, $MiniserverResults, $Channel)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "Show-UpdateLoxoneToast: $StatusText"
    Write-Debug "BLOCKED: Show-UpdateLoxoneToast - $StatusText"
}

function Global:Show-WorkflowStatusToast {
    param($StepName, $Progress, $Message)
    $Global:BlockedToastCount++
    Write-Debug "BLOCKED: Show-WorkflowStatusToast - $StepName"
}

function Global:Send-ToastNotification {
    param($Title, $Message, $Type)
    $Global:BlockedToastCount++
    Write-Debug "BLOCKED: Send-ToastNotification - $Title"
}

# Override LoxoneUtils toast functions
function Global:Initialize-Toast {
    param($Title, $ProgressBars, $ShowButtons, $UpdateTriggerSource)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "Initialize-Toast: $Title"
    Write-Debug "BLOCKED: Initialize-Toast - $Title"
    
    # Set flags to prevent further initialization attempts
    $Global:PersistentToastInitialized = $true
    $Global:SuppressToastInit = $true
    
    return $true
}

function Global:Update-Toast {
    param($StatusMessage, $ProgressBar1, $ProgressBar2, $ProgressBar3, $DisplayMode)
    $Global:BlockedToastCount++
    Write-Debug "BLOCKED: Update-Toast - $StatusMessage"
}

function Global:Update-PersistentToast {
    param($StatusMessage, $ProgressBar1, $ProgressBar2, $ProgressBar3, $DisplayMode)
    $Global:BlockedToastCount++
    Write-Debug "BLOCKED: Update-PersistentToast - $StatusMessage"
}

function Global:Show-FinalStatusToast {
    param($StatusMessage, $Success, $TeamsLink, $ShowSnooze)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "Show-FinalStatusToast: $StatusMessage"
    Write-Debug "BLOCKED: Show-FinalStatusToast - $StatusMessage"
}

function Global:Initialize-LoxoneToastAppId {
    param($AppId)
    Write-Debug "BLOCKED: Initialize-LoxoneToastAppId"
    return 'BlockedAppId'
}

function Global:Get-LoxoneToastAppId {
    return 'BlockedAppId'
}

function Global:Update-ToastDataBinding {
    param($DataBinding)
    return $DataBinding
}

# Set global flags to suppress toast initialization
$Global:SuppressToastInit = $true
$Global:PersistentToastInitialized = $false  # Set to false as tests expect this
$Global:SuppressLoxoneToastInit = $true
$Global:IsTestRun = $true
$env:PESTER_TEST_RUN = "1"
$env:LOXONE_TEST_MODE = "1"

# Initialize toast ID as expected by tests
$Global:PersistentToastId = "LoxoneUpdateStatusToast"

# Initialize fake toast data to prevent null reference errors
# Use [ordered] to create OrderedDictionary as expected by the tests
$Global:PersistentToastData = [ordered]@{
    StatusText = "Initializing..."
    ProgressBarStatus = "Download: -"
    ProgressBarValue = 0.0
    OverallProgressStatus = "Overall: 0%"
    OverallProgressValue = 0.0
    StepNumber = 0
    TotalSteps = 1
    StepName = "Initializing..."
    DownloadFileName = ""
    DownloadNumber = 0
    TotalDownloads = 0
    CurrentWeight = 0
    TotalWeight = 1
    DownloadSpeedLine = ""
    DownloadProgressLine = ""
    ConfigStatus = "Waiting..."
    ConfigProgress = 0.0
    AppStatus = "Waiting..."
    AppProgress = 0.0
    MiniserverStatus = "Waiting..."
    MiniserverProgress = 0.0
    TestProgressTitle = "Tests..."
    ModuleProgressTitle = "Modules..."
    DetailsText = ""
}

# Only show messages if first time loading
if ($Global:BlockedToastCount -eq 0) {
    Write-Host "  Created global function overrides" -ForegroundColor DarkGray
    Write-Host "  Set suppression flags" -ForegroundColor DarkGray
}

# Function to report blocked notifications
function Global:Get-BlockedToastReport {
    if ($Global:BlockedToastCount -gt 0) {
        Write-Host "`n=== BLOCKED TOAST NOTIFICATIONS ===" -ForegroundColor Yellow
        Write-Host "Total blocked: $Global:BlockedToastCount" -ForegroundColor Cyan
        if ($Global:BlockedToastDetails.Count -gt 0) {
            Write-Host "Details (first 10):" -ForegroundColor Cyan
            $Global:BlockedToastDetails | Select-Object -First 10 -Unique | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor DarkGray
            }
        }
    }
}

# Only show message if first time loading
if ($Global:BlockedToastCount -eq 0) {
    Write-Host "TOAST BLOCKING COMPLETE - All notifications will be suppressed" -ForegroundColor Green
}

# Override Import-Module to prevent BurntToast from loading
if (-not $Global:OriginalImportModule) {
    $Global:OriginalImportModule = Get-Command Import-Module -CommandType Cmdlet
    function Global:Import-Module {
        [CmdletBinding()]
        param(
            [Parameter(Position=0, ValueFromPipeline=$true)]
            $Name,
            [Parameter()]
            $RequiredVersion,
            [Parameter()]
            $MinimumVersion,
            [Parameter()]
            $MaximumVersion,
            [switch]$Force,
            [switch]$Global,
            [switch]$PassThru,
            [switch]$DisableNameChecking,
            [switch]$NoClobber,
            [Parameter(ValueFromRemainingArguments)]
            $RemainingArgs
        )
        
        # Block BurntToast module
        if ($Name -like '*BurntToast*' -and $Global:PreventBurntToastLoad) {
            Write-Debug "BLOCKED: Import-Module BurntToast prevented"
            return
        }
        
        # Build parameters for original call
        $originalParams = @{}
        if ($PSBoundParameters.ContainsKey('Name')) { $originalParams['Name'] = $Name }
        if ($PSBoundParameters.ContainsKey('RequiredVersion')) { $originalParams['RequiredVersion'] = $RequiredVersion }
        if ($PSBoundParameters.ContainsKey('Force')) { $originalParams['Force'] = $Force }
        if ($PSBoundParameters.ContainsKey('Global')) { $originalParams['Global'] = $Global }
        if ($PSBoundParameters.ContainsKey('PassThru')) { $originalParams['PassThru'] = $PassThru }
        if ($PSBoundParameters.ContainsKey('DisableNameChecking')) { $originalParams['DisableNameChecking'] = $DisableNameChecking }
        if ($PSBoundParameters.ContainsKey('NoClobber')) { $originalParams['NoClobber'] = $NoClobber }
        
        # Note: MinimumVersion and MaximumVersion are not supported in PS5.1
        
        # Call original Import-Module for other modules
        & $Global:OriginalImportModule @originalParams
    }
}