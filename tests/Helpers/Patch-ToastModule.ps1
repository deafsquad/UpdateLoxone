# Patch-ToastModule.ps1
# Monkey-patches the LoxoneUtils.Toast module to respect test mode
# This must run AFTER the module loads but BEFORE tests run

param(
    [switch]$LiveProgress
)

if ($LiveProgress) {
    Write-Debug "LiveProgress mode - not patching Toast module"
    return
}

Write-Host "Patching Toast module to respect test mode..." -ForegroundColor Yellow

# Override the Initialize-Toast function to check suppression
function Global:Initialize-Toast {
    param(
        [string]$Title = "Loxone Update",
        [int]$ProgressBars = 0,
        [bool]$ShowButtons = $false,
        [string]$UpdateTriggerSource = 'Unknown'
    )
    
    # CHECK SUPPRESSION FLAG FIRST!
    if ($Global:SuppressLoxoneToastInit -or $Global:SuppressToastInit -or $env:LOXONE_TEST_MODE -eq "1") {
        Write-Debug "[PATCHED] Initialize-Toast blocked by test mode"
        $Global:PersistentToastInitialized = $true
        return $true
    }
    
    # This should never execute in test mode
    Write-Warning "[PATCHED] Initialize-Toast called but should be blocked!"
    return $true
}

# Override Update-PersistentToast to check suppression
function Global:Update-PersistentToast {
    param(
        [string]$StatusMessage,
        $ProgressBar1,
        $ProgressBar2,
        $ProgressBar3,
        [string]$DisplayMode
    )
    
    if ($Global:SuppressLoxoneToastInit -or $Global:SuppressToastInit -or $env:LOXONE_TEST_MODE -eq "1") {
        Write-Debug "[PATCHED] Update-PersistentToast blocked by test mode"
        return
    }
    
    Write-Warning "[PATCHED] Update-PersistentToast called but should be blocked!"
}

# Override Show-FinalStatusToast to check suppression
function Global:Show-FinalStatusToast {
    param(
        [string]$StatusMessage,
        [bool]$Success = $true,
        [string]$TeamsLink = '',
        [bool]$ShowSnooze = $false
    )
    
    if ($Global:SuppressLoxoneToastInit -or $Global:SuppressToastInit -or $env:LOXONE_TEST_MODE -eq "1") {
        Write-Debug "[PATCHED] Show-FinalStatusToast blocked by test mode"
        return
    }
    
    Write-Warning "[PATCHED] Show-FinalStatusToast called but should be blocked!"
}

# Override Update-Toast
function Global:Update-Toast {
    param(
        [string]$StatusMessage,
        $ProgressBar1,
        $ProgressBar2,
        $ProgressBar3,
        [string]$DisplayMode
    )
    
    Write-Debug "[PATCHED] Update-Toast blocked"
}

# Also override the actual BurntToast functions if they exist
if (Get-Command Submit-BTNotification -ErrorAction SilentlyContinue) {
    function Global:Submit-BTNotification {
        param($Content, $UniqueIdentifier, $AppId, $DataBinding)
        Write-Debug "[PATCHED] Submit-BTNotification blocked - ID: $UniqueIdentifier"
        $Global:BlockedToastCount++
    }
}

if (Get-Command Update-BTNotification -ErrorAction SilentlyContinue) {
    function Global:Update-BTNotification {
        param($UniqueIdentifier, $DataBinding, $AppId)
        Write-Debug "[PATCHED] Update-BTNotification blocked - ID: $UniqueIdentifier"
        $Global:BlockedToastCount++
    }
}

if (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue) {
    function Global:New-BurntToastNotification {
        param($Text, $Header, $AppLogo, [switch]$Silent, [switch]$SnoozeAndDismiss)
        Write-Debug "[PATCHED] New-BurntToastNotification blocked"
        $Global:BlockedToastCount++
    }
}

Write-Host "[OK] Toast module functions patched" -ForegroundColor Green

# Also ensure the module-level suppression is set
if (Get-Module LoxoneUtils) {
    # Try to set the module-scoped variable
    $toastModule = Get-Module LoxoneUtils
    & $toastModule {
        $script:SuppressToastInit = $true
    } -ErrorAction SilentlyContinue
}

Write-Host "PATCHING COMPLETE: Toast functions will respect test mode" -ForegroundColor Green