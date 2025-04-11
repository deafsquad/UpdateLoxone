# BurntToast import moved back inside script block
# --- Configuration ---
# Timeout is now handled in runasuser.psm1 (set to 3000ms)

# --- Initialization ---
Write-Host "Starting test script..."

try {
    # --- Invoke Loxone Monitor ---
    Write-Host "Attempting to launch Loxone Monitor via Invoke-AsCurrentUser..." # Updated comment

    # Force removal of existing module before re-importing
    # Force removal of existing module before re-importing
    Write-Host "Attempting to remove RunAsUser module..."
    Remove-Module RunAsUser -Force -ErrorAction SilentlyContinue
    Write-Host "Attempting to import RunAsUser module..."
    Import-Module (Join-Path $PSScriptRoot 'runasuser.psd1') -Force # Ensure correct psd1 name

    # Define the path to the executable:
    # $exePath = Join-Path $PSScriptRoot 'Monitor\loxonemonitor.exe' # Original relative path
    $exePath = "C:\Program Files (x86)\Loxone\LoxoneConfig\loxonemonitor.exe" # Use absolute path as per request
    $arguments = "" # No arguments needed

    # Execute the command in the current user's session
    Write-Host "Attempting to launch '$exePath' via Invoke-AsCurrentUser..."
    try {
        # Launch visible but don't wait for it to exit
        Invoke-AsCurrentUser -FilePath $exePath -Arguments $arguments -Visible -NoWait -ErrorAction Stop
        Write-Host "'$exePath' launched."
    } catch {
        Write-Error "Failed to launch '$exePath': $($_.Exception.Message)"
    }
    # Removed the check for $invokeResult as -NoWait doesn't capture output reliably here
} catch {
    # Catch any errors from the main script logic
    Write-Error "An error occurred in the main script: $($_.Exception.Message)"
} finally {
    # --- Cleanup ---
    Write-Host "Performing cleanup..."
    # No specific cleanup needed for this version
    Write-Host "Cleanup finished."
}

Write-Host "Test script finished."
