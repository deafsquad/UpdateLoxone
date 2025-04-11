# testtoast.ps1 - Test sending toast notification via Invoke-AsCurrentUser

# Import necessary module (assuming runasuser.psm1 is in the same directory or module path)
Import-Module (Join-Path $PSScriptRoot 'runasuser.psd1') -Force

Write-Host "Starting test script for toast notification..."

# Define Toast Details
$Title = "Test Toast Title"
$Message = "This toast was sent via Invoke-AsCurrentUser."
$AppId = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe' # Hardcoded AppID

# Define the script block string with placeholders
$scriptBlockString = @'
Import-Module BurntToast -ErrorAction Stop
$Params = @{
    Text = '$TitlePlaceholder', '$MessagePlaceholder'
    AppId = '$AppIdPlaceholder'
}
New-BurntToastNotification @Params -ErrorAction Stop
Write-Host "(User Session) Minimal toast command successfully executed."
'@

# Replace placeholders
$finalScriptContent = $scriptBlockString -replace '\$TitlePlaceholder', $Title -replace '\$MessagePlaceholder', $Message -replace '\$AppIdPlaceholder', $AppId
$finalScriptBlock = [ScriptBlock]::Create($finalScriptContent)

# Invoke the script block as the current user
Write-Host "Attempting to send toast notification via Invoke-AsCurrentUser..."
try {
    $invokeResult = Invoke-AsCurrentUser -ScriptBlock $finalScriptBlock -CaptureOutput -ErrorAction Stop
    Write-Host "Invoke-AsCurrentUser call completed."
    if ($invokeResult) {
        Write-Host "--- Captured Output ---"
        Write-Host $invokeResult
        Write-Host "--- End Captured Output ---"
    }
} catch {
    Write-Error "Failed to send toast via Invoke-AsCurrentUser: $($_.Exception.Message)"
    # Optionally log error details
}

Write-Host "Test script finished."