# Test PSMSI advanced features
Import-Module PSMSI -ErrorAction Stop

# Check New-Installer parameters for display name and cleanup options
Write-Host "New-Installer parameters:" -ForegroundColor Cyan
Get-Help New-Installer -Parameter * | Select-Object Name, Description | Format-Table -AutoSize

Write-Host "`nNew-InstallerCustomAction parameters:" -ForegroundColor Cyan
Get-Help New-InstallerCustomAction -Parameter * | Select-Object Name, Description | Format-Table -AutoSize

Write-Host "`nChecking for cleanup-related functionality:" -ForegroundColor Cyan
Get-Command -Module PSMSI *-Installer* | ForEach-Object {
    $help = Get-Help $_ -Full -ErrorAction SilentlyContinue
    if ($help.description.Text -match 'clean|remove|uninstall') {
        Write-Host "$($_.Name): $($help.description.Text)" -ForegroundColor Yellow
    }
}