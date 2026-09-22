# Mock-ToastNotifications.ps1
# Comprehensive toast notification mocks for testing
# This file mocks all toast/notification functions to prevent real notifications during tests

# Load the aggressive blocker first
$blockerPath = Join-Path $PSScriptRoot "Block-AllToastNotifications.ps1"
if (Test-Path $blockerPath) {
    . $blockerPath
} else {
    Write-Host "Toast notification mocks loaded - no real notifications will be shown" -ForegroundColor Green
}

# Track if mocks are loaded
$Global:ToastMocksLoaded = $true
$Global:MockToastNotifications = @()

# Suppress BurntToast module if it's loaded
if (Get-Module BurntToast -ErrorAction SilentlyContinue) {
    Remove-Module BurntToast -Force -ErrorAction SilentlyContinue
}

# Create mock functions for all BurntToast commands
function Global:New-BTProgressBar {
    param($Title, $Status, $Value)
    return @{ Type = 'MockProgressBar'; Title = $Title; Status = $Status; Value = $Value }
}

function Global:New-BTButton {
    param([switch]$Dismiss, [switch]$Snooze, [string]$Content, [string]$Arguments)
    return @{ Type = 'MockButton'; Dismiss = $Dismiss; Snooze = $Snooze; Content = $Content; Arguments = $Arguments }
}

function Global:New-BTAction {
    param($Buttons)
    return @{ Type = 'MockAction'; Buttons = $Buttons }
}

function Global:New-BTText {
    param([string[]]$Text)
    return @{ Type = 'MockText'; Text = $Text }
}

function Global:New-BTVisual {
    param($Text)
    return @{ Type = 'MockVisual'; Text = $Text }
}

function Global:New-BTContent {
    param($Visual, $Actions)
    return @{ Type = 'MockContent'; Visual = $Visual; Actions = $Actions }
}

function Global:Submit-BTNotification {
    param($Content, [string]$UniqueIdentifier, [string]$AppId, $DataBinding)
    $Global:MockToastNotifications += @{
        Type = 'Submit'
        UniqueIdentifier = $UniqueIdentifier
        Timestamp = Get-Date
    }
    Write-Debug "MOCK: Submit-BTNotification blocked - ID: $UniqueIdentifier"
}

function Global:Update-BTNotification {
    param([string]$UniqueIdentifier, $DataBinding, [string]$AppId)
    $Global:MockToastNotifications += @{
        Type = 'Update'
        UniqueIdentifier = $UniqueIdentifier
        Timestamp = Get-Date
    }
    Write-Debug "MOCK: Update-BTNotification blocked - ID: $UniqueIdentifier"
}

function Global:New-BurntToastNotification {
    param([string]$Text, [string]$Header, [string]$AppLogo, [switch]$Silent, [switch]$SnoozeAndDismiss)
    $Global:MockToastNotifications += @{
        Type = 'BurntToast'
        Header = $Header
        Timestamp = Get-Date
    }
    Write-Debug "MOCK: New-BurntToastNotification blocked - Header: $Header"
}

# Mock LoxoneUtils.Toast module functions
$Global:MockInitializeToast = {
    param([string]$Title, [int]$ProgressBars = 0, [bool]$ShowButtons = $false, [string]$UpdateTriggerSource = 'Unknown')
    $Global:MockToastNotifications += @{
        Type = 'Initialize'
        Title = $Title
        Timestamp = Get-Date
    }
    Write-Debug "MOCK: Initialize-Toast blocked - Title: $Title"
    return $true
}

$Global:MockUpdateToast = {
    param([string]$StatusMessage, $ProgressBar1, $ProgressBar2, $ProgressBar3, [string]$DisplayMode)
    Write-Debug "MOCK: Update-Toast blocked - Status: $StatusMessage"
}

$Global:MockUpdatePersistentToast = {
    param([string]$StatusMessage, $ProgressBar1, $ProgressBar2, $ProgressBar3, [string]$DisplayMode)
    Write-Debug "MOCK: Update-PersistentToast blocked - Status: $StatusMessage"
}

$Global:MockShowFinalStatusToast = {
    param([string]$StatusMessage, [bool]$Success = $true, [string]$TeamsLink = '', [bool]$ShowSnooze = $false)
    $Global:MockToastNotifications += @{
        Type = 'FinalStatus'
        StatusMessage = $StatusMessage
        Success = $Success
        Timestamp = Get-Date
    }
    Write-Debug "MOCK: Show-FinalStatusToast blocked - Status: $StatusMessage, Success: $Success"
}

function Global:Initialize-Toast { & $Global:MockInitializeToast @args }
function Global:Update-Toast { & $Global:MockUpdateToast @args }
function Global:Update-PersistentToast { & $Global:MockUpdatePersistentToast @args }
function Global:Show-FinalStatusToast { & $Global:MockShowFinalStatusToast @args }
function Global:Get-LoxoneToastAppId { return 'MockLoxoneUpdateNotifier' }
function Global:Initialize-LoxoneToastAppId { param([string]$AppId); return $true }
function Global:Update-ToastDataBinding { param($DataBinding); return $DataBinding }

Write-Debug "Toast mock functions created globally. All notifications will be suppressed."