# Test UpdateLoxone.ps1 can be executed without errors
try {
    # Test with the same arguments as the shortcut would use
    & powershell.exe -ExecutionPolicy Bypass -NoProfile -File ".\UpdateLoxone.ps1" -Channel Test -ScriptSaveFolder "." -MaxLogFileSizeMB 1 -DebugMode
    Write-Host "Script executed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Error executing script: $_" -ForegroundColor Red
}