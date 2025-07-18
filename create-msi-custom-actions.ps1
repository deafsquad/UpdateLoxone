# Create custom action scripts for MSI installation

# Success action script
$successScript = @'
param()

# Show success notification
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show(
    "UpdateLoxone has been successfully installed!`n`nYou can find it in your Start Menu.", 
    "Installation Complete", 
    [System.Windows.Forms.MessageBoxButtons]::OK, 
    [System.Windows.Forms.MessageBoxIcon]::Information
)
'@

# Create success script
$successScript | Out-File -FilePath "$PSScriptRoot\msi-success-action.ps1" -Encoding UTF8

Write-Host "Created MSI custom action scripts"
Write-Host "Note: PSMSI doesn't directly support custom actions for UI popups."
Write-Host "Consider using a scheduled task or first-run detection for user notifications."