# Create-FakeBurntToast.ps1
# Creates a fake BurntToast module that PowerShell will load instead of the real one
# This must be run BEFORE any module tries to import BurntToast

param(
    [switch]$Remove
)

$modulePath = $env:PSModulePath -split ';' | Where-Object { $_ -like "*$env:USERPROFILE*" } | Select-Object -First 1
if (-not $modulePath) {
    $modulePath = Join-Path $env:USERPROFILE "Documents\PowerShell\Modules"
}

$fakeBurntToastPath = Join-Path $modulePath "BurntToast"
$fakeBurntToastModule = Join-Path $fakeBurntToastPath "BurntToast.psm1"
$fakeBurntToastManifest = Join-Path $fakeBurntToastPath "BurntToast.psd1"

if ($Remove) {
    if (Test-Path $fakeBurntToastPath) {
        Remove-Item $fakeBurntToastPath -Recurse -Force
        Write-Host "Removed fake BurntToast module" -ForegroundColor Green
    }
    return
}

# Create fake module directory
if (-not (Test-Path $fakeBurntToastPath)) {
    New-Item -ItemType Directory -Path $fakeBurntToastPath -Force | Out-Null
}

# Create fake module content that does nothing
$fakeModuleContent = @'
# Fake BurntToast Module for Testing
# All functions return silently without creating notifications

$Global:FakeBurntToastActive = $true

function Submit-BTNotification {
    param($Content, $UniqueIdentifier, $AppId, $DataBinding)
    Write-Verbose "FAKE: Submit-BTNotification called with ID: $UniqueIdentifier"
}

function Update-BTNotification {
    param($UniqueIdentifier, $DataBinding, $AppId)
    Write-Verbose "FAKE: Update-BTNotification called with ID: $UniqueIdentifier"
}

function Remove-BTNotification {
    param($AppId, $Tag, $Group)
    Write-Verbose "FAKE: Remove-BTNotification called"
}

function Get-BTHistory {
    param($AppId)
    return @()
}

function New-BTProgressBar {
    param($Title, $Status, $Value, $ValueStringOverride, $IndeterminateState)
    return [PSCustomObject]@{
        Type = 'BTProgressBar'
        Title = $Title
        Status = $Status
        Value = $Value
    }
}

function New-BTButton {
    param(
        [switch]$Dismiss,
        [switch]$Snooze,
        [string]$Content,
        [string]$Arguments,
        [string]$ActivationType,
        [string]$ImageUri,
        [string]$Id
    )
    return [PSCustomObject]@{
        Type = 'BTButton'
        Dismiss = $Dismiss
        Snooze = $Snooze
        Content = $Content
    }
}

function New-BTAction {
    param($Buttons, $ContextMenuItems, $Inputs)
    return [PSCustomObject]@{
        Type = 'BTAction'
        Buttons = $Buttons
    }
}

function New-BTText {
    param([string[]]$Text, [string]$Language, [switch]$Wrap, [int]$MaxLines, [int]$MinLines, [string]$Style, [switch]$Align)
    return [PSCustomObject]@{
        Type = 'BTText'
        Text = $Text
    }
}

function New-BTImage {
    param($Source, $AppLogoOverride, $HeroImage, $AdaptiveImage, $AlternateText, $AddImageQuery, $Crop)
    return [PSCustomObject]@{
        Type = 'BTImage'
        Source = $Source
    }
}

function New-BTVisual {
    param($Text, $Image, $Group, $SubGroup, $AppLogoOverride, $HeroImage, $Attribution, $BaseUri, $AddImageQuery, $Language, $BindingGeneric)
    return [PSCustomObject]@{
        Type = 'BTVisual'
        Text = $Text
    }
}

function New-BTBinding {
    param($Children, $AppLogoOverride, $HeroImage, $BaseUri, $AddImageQuery, $Language)
    return [PSCustomObject]@{
        Type = 'BTBinding'
        Children = $Children
    }
}

function New-BTContent {
    param($Visual, $Audio, $Actions, $ActivationType, $Duration, $Launch, $Scenario, $DisplayTimestamp, $CustomTimestamp, $Header)
    return [PSCustomObject]@{
        Type = 'BTContent'
        Visual = $Visual
        Actions = $Actions
    }
}

function New-BTAudio {
    param([switch]$Silent, $Source, [switch]$Loop)
    return [PSCustomObject]@{
        Type = 'BTAudio'
        Silent = $Silent
    }
}

function New-BTHeader {
    param($Id, $Title, $Arguments, $ActivationType)
    return [PSCustomObject]@{
        Type = 'BTHeader'
        Id = $Id
        Title = $Title
    }
}

function New-BTSelectionBoxItem {
    param($Id, $Content)
    return [PSCustomObject]@{
        Type = 'BTSelectionBoxItem'
        Id = $Id
        Content = $Content
    }
}

function New-BTInput {
    param($Id, $Type, $Title, $PlaceHolderContent, $DefaultInput, $Items)
    return [PSCustomObject]@{
        Type = 'BTInput'
        Id = $Id
        Title = $Title
    }
}

function New-BurntToastNotification {
    param($Text, $AppLogo, $Sound, $Header, [switch]$Silent, [switch]$SnoozeAndDismiss, [switch]$UniqueIdentifier, [switch]$ExpirationTime, $Button, $ProgressBar)
    Write-Verbose "FAKE: New-BurntToastNotification called with Text: $Text"
}

function New-BurntToastShoulderTap {
    param($Image, $Person, $Text)
    Write-Verbose "FAKE: New-BurntToastShoulderTap called"
}

function New-BTDataBinding {
    return [hashtable]@{}
}

function New-BTContextMenuItem {
    param($Content, $Arguments, $ActivationType)
    return [PSCustomObject]@{
        Type = 'BTContextMenuItem'
        Content = $Content
    }
}

# Export all functions
Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *

Write-Verbose "Fake BurntToast module loaded - all notifications will be suppressed"
'@

# Write the fake module
Set-Content -Path $fakeBurntToastModule -Value $fakeModuleContent -Force

# Create a minimal manifest
$manifestContent = @'
@{
    ModuleVersion = '999.999.999'
    GUID = 'fake-burnt-toast-for-testing'
    Author = 'Test Framework'
    Description = 'Fake BurntToast module for testing'
    RootModule = 'BurntToast.psm1'
    FunctionsToExport = '*'
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
}
'@

Set-Content -Path $fakeBurntToastManifest -Value $manifestContent -Force

# Add to the module path at the BEGINNING so it's found first
$currentPath = $env:PSModulePath
if ($currentPath -notlike "*$modulePath*") {
    $env:PSModulePath = "$modulePath;$currentPath"
} else {
    # Make sure our path is FIRST
    $paths = $currentPath -split ';' | Where-Object { $_ -ne $modulePath }
    $env:PSModulePath = "$modulePath;$($paths -join ';')"
}

Write-Host "Created fake BurntToast module at: $fakeBurntToastPath" -ForegroundColor Green
Write-Host "Module will intercept all toast notification attempts" -ForegroundColor Yellow

# Force PowerShell to refresh its module cache
Get-Module BurntToast -ListAvailable -Refresh | Out-Null

return $fakeBurntToastPath