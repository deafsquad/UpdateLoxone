# Mock suite for LoxoneUtils.Toast module
# This file contains all mocks needed to prevent real toast notifications during tests
# Note: Module must be imported BEFORE sourcing this file

# Mock all BurntToast functions to prevent real notifications
Mock -ModuleName LoxoneUtils.Toast New-BTText { 
    param($Content) 
    return @{Type='Text'; Content=$Content} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTProgressBar { 
    param($Status, $Value, $Title) 
    return @{Type='ProgressBar'; Status=$Status; Value=$Value; Title=$Title} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTImage { 
    param($Source, [switch]$AppLogoOverride) 
    return @{Type='Image'; Source=$Source; AppLogoOverride=$AppLogoOverride} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTBinding { 
    param($Children, $AppLogoOverride) 
    return @{Type='Binding'; Children=$Children; AppLogoOverride=$AppLogoOverride} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTVisual { 
    param($BindingGeneric) 
    return @{Type='Visual'; Binding=$BindingGeneric} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTAudio { 
    param([switch]$Silent) 
    return @{Type='Audio'; Silent=$Silent} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTButton { 
    param($Content, $Arguments, [switch]$Dismiss, [switch]$Snooze) 
    return @{Type='Button'; Content=$Content; Arguments=$Arguments; Dismiss=$Dismiss; Snooze=$Snooze} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTAction { 
    param($Buttons) 
    return @{Type='Action'; Buttons=$Buttons} 
}

Mock -ModuleName LoxoneUtils.Toast New-BTContent { 
    param($Visual, $Audio, $Actions, $ActivationType, $Scenario, $Duration, $DataBinding) 
    return @{
        Type='Content'
        Visual=$Visual
        Audio=$Audio
        Actions=$Actions
        Scenario=$Scenario
        Duration=$Duration
        DataBinding=$DataBinding
    } 
}

Mock -ModuleName LoxoneUtils.Toast Submit-BTNotification { 
    param($Content, $UniqueIdentifier, $AppId, $DataBinding, $ErrorAction)
    Write-Verbose "[MOCK] Would show toast: $UniqueIdentifier"
    $Global:MockToastShown = $true
    $Global:LastMockToastId = $UniqueIdentifier
    $Global:LastMockToastContent = $Content
    $Global:LastMockToastDataBinding = $DataBinding
}

Mock -ModuleName LoxoneUtils.Toast Update-BTNotification {
    param($UniqueIdentifier, $DataBinding, $AppId, $ErrorAction)
    Write-Verbose "[MOCK] Would update toast: $UniqueIdentifier"
    $Global:MockToastUpdated = $true
    $Global:LastMockToastUpdate = $DataBinding
}

# Mock the main toast functions from the module
Mock -ModuleName LoxoneUtils.Toast Initialize-Toast {
    param($Params)
    Write-Verbose "[MOCK] Would initialize toast"
    $Global:PersistentToastInitialized = $true
    $Global:PersistentToastId = "LoxoneUpdate_MockTest"
    $Global:MockToastParams = $Params
}

Mock -ModuleName LoxoneUtils.Toast Update-Toast {
    param($Updates)
    Write-Verbose "[MOCK] Would update toast"
    $Global:MockToastProgressUpdated = $true
    $Global:LastToastProgressUpdate = $Updates
}

Mock -ModuleName LoxoneUtils.Toast Show-FinalStatusToast {
    param($Status, $Success, $ErrorMessage, $Params)
    Write-Verbose "[MOCK] Would show final status toast: $Status"
    $Global:MockFinalToastShown = $true
    $Global:MockFinalToastStatus = $Status
    $Global:MockFinalToastSuccess = $Success
}

# Mock Invoke-AsCurrentUser to prevent context switching
Mock -ModuleName LoxoneUtils.Toast Invoke-AsCurrentUser {
    param($ScriptBlock, $ArgumentList, $NoWait)
    Write-Verbose "[MOCK] Would invoke as current user"
    
    # Execute the script block directly in current context
    if ($ScriptBlock) {
        if ($ArgumentList) {
            & $ScriptBlock @ArgumentList
        } else {
            & $ScriptBlock
        }
    }
}

# Export a flag indicating mocks are loaded
$Global:ToastMocksLoaded = $true

# Suppress mock loading messages in parallel/CI mode to reduce noise
if (-not $env:CI -and -not $env:LOXONE_PARALLEL_MODE) {
    # Suppress mock loading messages in parallel/CI mode to reduce noise
    Write-Host "Toast module mocks loaded - no real notifications will be shown" -ForegroundColor Green
}
