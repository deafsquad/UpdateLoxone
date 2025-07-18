# Test if UpdateLoxone.ps1 works with emojis
try {
    # Just parse the script to check for syntax errors
    $scriptContent = Get-Content -Path ".\UpdateLoxone.ps1" -Raw
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$tokens, [ref]$errors)
    
    if ($errors.Count -gt 0) {
        Write-Host "Found $($errors.Count) syntax errors:" -ForegroundColor Red
        foreach ($error in $errors) {
            Write-Host "  Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "No syntax errors found! Script is valid." -ForegroundColor Green
        
        # Test that the script can actually run
        Write-Host "`nTesting script execution..." -ForegroundColor Cyan
        $testResult = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command {
            try {
                . .\UpdateLoxone.ps1 -Channel Test -ScriptSaveFolder "." -DebugMode
                Write-Output "SUCCESS"
            } catch {
                Write-Output "ERROR: $_"
            }
        } | Select-Object -Last 1
        
        if ($testResult -eq "SUCCESS") {
            Write-Host "Script executed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Script execution failed: $testResult" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
}