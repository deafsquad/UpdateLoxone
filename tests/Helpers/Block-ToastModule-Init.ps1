# Block-ToastModule-Init.ps1
# Early module-level toast blocking to prevent any notification initialization
# This should be loaded BEFORE any LoxoneUtils modules

# Set all possible environment variables to suppress notifications
$env:PESTER_TEST_MODE = "1"
$env:LOXONE_TEST_MODE = "1"
$env:SUPPRESS_TOAST_NOTIFICATIONS = "1"
$env:NO_TOAST_NOTIFICATIONS = "1"
$env:DISABLE_BURNTTOAST = "1"

# Set global flags that modules might check
$Global:IsTestRun = $true
$Global:SuppressToastInit = $true
$Global:PersistentToastInitialized = $true
$Global:SuppressLoxoneToastInit = $true
$Global:PreventBurntToastLoad = $true
$Global:ToastBlockingActive = $true
$Global:DisableAllToasts = $true

# Create stub module for BurntToast to prevent real module from loading
if (-not (Get-Module BurntToast)) {
    $mockModule = New-Module -Name BurntToast -ScriptBlock {
        function Submit-BTNotification { 
            param($Content, $UniqueIdentifier, $AppId, $DataBinding)
            Write-Debug "STUB: Submit-BTNotification blocked"
        }
        function Update-BTNotification { 
            param($UniqueIdentifier, $DataBinding, $AppId)
            Write-Debug "STUB: Update-BTNotification blocked"
        }
        function New-BTProgressBar { 
            param($Title, $Status, $Value)
            return @{ Type = 'StubProgressBar' }
        }
        function New-BTButton { 
            param([switch]$Dismiss, [switch]$Snooze, $Content, $Arguments)
            return @{ Type = 'StubButton' }
        }
        function New-BTAction { 
            param($Buttons)
            return @{ Type = 'StubAction' }
        }
        function New-BTText { 
            param($Text)
            return @{ Type = 'StubText' }
        }
        function New-BTVisual { 
            param($Text, $Binding, $InlineImage)
            return @{ Type = 'StubVisual' }
        }
        function New-BTContent { 
            param($Visual, $Actions, $Audio, $ActivationType, $Scenario, $Duration)
            return @{ Type = 'StubContent' }
        }
        function New-BTAudio { 
            param([switch]$Silent)
            return @{ Type = 'StubAudio' }
        }
        function New-BurntToastNotification { 
            param($Text, $Header, $AppLogo, [switch]$Silent, [switch]$SnoozeAndDismiss)
            Write-Debug "STUB: New-BurntToastNotification blocked"
        }
        
        Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
    }
    
    Import-Module $mockModule -Global -Force
}

Write-Debug "Toast module initialization blocked at module level"