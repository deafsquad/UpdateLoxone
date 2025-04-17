# Ensure BurntToast module is available
Import-Module BurntToast -Force

# Define unique identifier and AppId
$ToastId = 'TestProgressToast'
# Using a placeholder AppId for simplicity in testing
$AppId = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'
# Alternatively, use the Loxone AppId if testing specific integration:
# $AppId = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'

# Define initial data binding values
$DataBinding = @{
    StatusText            = "Initializing Test..."
    ProgressBarStatus     = "Task 1: 0%"
    ProgressBarValue      = 0.0
    OverallProgressStatus = "Overall: 0%"
    OverallProgressValue  = 0.0
}

# Create progress bar objects linked to data binding keys
$progressBar1 = New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "Task Progress"
$progressBar2 = New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "Overall Progress"

# Create the initial toast notification
Write-Host "Creating initial toast with ID: $ToastId"
New-BurntToastNotification -UniqueIdentifier $ToastId `
    -Text "StatusText" `
    -ProgressBar @($progressBar1, $progressBar2) `
    -DataBinding $DataBinding `
    -AppId $AppId `
    -SnoozeAndDismiss `
    -Silent

# Wait for a few seconds to observe the initial toast
Write-Host "Waiting 5 seconds before updating..."
Start-Sleep -Seconds 5

# Update the data binding values
Write-Host "Updating data binding values..."
$DataBinding.StatusText = "Processing Step 2/2..."
$DataBinding.ProgressBarStatus = "Task 1: 70%"
$DataBinding.ProgressBarValue = 0.7
$DataBinding.OverallProgressStatus = "Overall: 100%"
$DataBinding.OverallProgressValue = 1.0

# Update the existing toast notification
Write-Host "Sending update for toast ID: $ToastId"
Update-BTNotification -UniqueIdentifier $ToastId `
    -DataBinding $DataBinding `
    -AppId $AppId

Write-Host "Test script complete. Check the toast notification for updates."