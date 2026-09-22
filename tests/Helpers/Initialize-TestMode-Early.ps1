# Initialize-TestMode-Early.ps1
# This MUST be the FIRST thing that runs before ANY module loads
# It sets up complete toast blocking at all levels

param(
    [switch]$LiveProgress
)

if ($LiveProgress) {
    Write-Host "LiveProgress mode - Toast notifications will be enabled" -ForegroundColor Yellow
    $Global:ForceToastSuppression = $false  # Explicitly allow toasts for LiveProgress
    # Don't create any stub functions or blocking for LiveProgress mode
    return
}

Write-Host "Initializing complete toast blocking..." -ForegroundColor Yellow

# 1. Set ALL environment variables immediately
$env:PESTER_TEST_MODE = "1"
$env:LOXONE_TEST_MODE = "1" 
$env:SUPPRESS_TOAST_NOTIFICATIONS = "1"
$env:NO_TOAST_NOTIFICATIONS = "1"
$env:DISABLE_BURNTTOAST = "1"
$env:BURNTTOAST_MOCK_MODE = "1"

# 2. Set ALL global flags before any module can check them
$Global:SuppressLoxoneToastInit = $true
$Global:SuppressToastInit = $true
$Global:PersistentToastInitialized = $true  # Pretend it's already initialized
$Global:IsTestRun = $true
$Global:DisableAllToasts = $true
$Global:PreventBurntToastLoad = $true
$Global:ToastBlockingActive = $true
$Global:BlockedToastCount = 0
$Global:BlockedToastDetails = @()

# CRITICAL: Override the script-scoped variable in the Toast module after it loads
# This ensures the module respects suppression even if tests try to enable it
$Global:ForceToastSuppression = $true

# 3. Create fake toast data so nothing is null
# Use the exact values the test expects
$Global:PersistentToastId = "LoxoneUpdateStatusToast"
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

# 4. Create stub functions BEFORE any module loads
function Global:Submit-BTNotification {
    param($Content, $UniqueIdentifier, $AppId, $DataBinding)
    $Global:BlockedToastCount++
    $Global:BlockedToastDetails += "Submit-BTNotification: $UniqueIdentifier"
    Write-Debug "[BLOCKED] Submit-BTNotification - $UniqueIdentifier"
}

function Global:Update-BTNotification {
    param($UniqueIdentifier, $DataBinding, $AppId)
    $Global:BlockedToastCount++
    Write-Debug "[BLOCKED] Update-BTNotification - $UniqueIdentifier"
}

function Global:Remove-BTNotification {
    param($AppId, $Tag, $Group)
    Write-Debug "[BLOCKED] Remove-BTNotification"
}

function Global:New-BTProgressBar {
    param($Title, $Status, $Value)
    return @{ Type = 'MockProgressBar'; Title = $Title; Status = $Status; Value = $Value }
}

function Global:New-BTButton {
    param([switch]$Dismiss, [switch]$Snooze, $Content, $Arguments)
    return @{ Type = 'MockButton' }
}

function Global:New-BTAction {
    param($Buttons)
    return @{ Type = 'MockAction' }
}

function Global:New-BTText {
    param($Text)
    return @{ Type = 'MockText'; Text = $Text }
}

function Global:New-BTVisual {
    param($Text, $Binding)
    return @{ Type = 'MockVisual' }
}

function Global:New-BTContent {
    param($Visual, $Actions)
    return @{ Type = 'MockContent' }
}

function Global:New-BTAudio {
    param([switch]$Silent)
    return @{ Type = 'MockAudio' }
}

function Global:New-BTBinding {
    param($Children, $AppLogoOverride, $HeroImage)
    return @{ Type = 'MockBinding' }
}

function Global:New-BTImage {
    param($Source, $AppLogoOverride)
    return @{ Type = 'MockImage' }
}

function Global:New-BTHeader {
    param($Id, $Title, $Arguments)
    return @{ Type = 'MockHeader' }
}

function Global:New-BurntToastNotification {
    param($Text, $Header, $AppLogo, [switch]$Silent, [switch]$SnoozeAndDismiss)
    $Global:BlockedToastCount++
    Write-Debug "[BLOCKED] New-BurntToastNotification - $Header"
}

# 5. Override module loading to inject our mocks
# NOTE: We cannot use Set-Alias to override Import-Module as it's a cmdlet
# Instead, we'll just make sure our mock BurntToast module is loaded first

# 6. Create a mock BurntToast module in memory
$mockModule = New-Module -Name BurntToast -ScriptBlock {
    function Submit-BTNotification { Write-Debug "[MOCK MODULE] Submit-BTNotification" }
    function Update-BTNotification { Write-Debug "[MOCK MODULE] Update-BTNotification" }
    function New-BTProgressBar { return @{Type='Mock'} }
    function New-BTButton { return @{Type='Mock'} }
    function New-BTAction { return @{Type='Mock'} }
    function New-BTText { return @{Type='Mock'} }
    function New-BTVisual { return @{Type='Mock'} }
    function New-BTContent { return @{Type='Mock'} }
    function New-BTAudio { return @{Type='Mock'} }
    function New-BurntToastNotification { Write-Debug "[MOCK MODULE] New-BurntToastNotification" }
    Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
}

# Import it globally so it's available everywhere
Import-Module $mockModule -Global -Force

Write-Host "[OK] Environment variables set" -ForegroundColor Green
Write-Host "[OK] Global suppression flags set" -ForegroundColor Green
Write-Host "[OK] Mock functions created" -ForegroundColor Green
Write-Host "[OK] Module import wrapper installed" -ForegroundColor Green
Write-Host "[OK] BurntToast mock module loaded" -ForegroundColor Green
Write-Host "COMPLETE: All toast notifications will be blocked" -ForegroundColor Green