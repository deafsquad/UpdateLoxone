# Test PSMSI cleanup capabilities
Import-Module PSMSI -ErrorAction Stop

# Check available commands for cleanup
Write-Host "PSMSI Commands related to cleanup/remove:" -ForegroundColor Cyan
Get-Command -Module PSMSI | Where-Object { $_.Name -match 'Remove|Clean|Delete|Uninstall' } | Format-Table Name, CommandType

Write-Host "`nPSMSI Commands for installer creation:" -ForegroundColor Cyan
Get-Command -Module PSMSI | Where-Object { $_.Name -match 'New-Installer' } | Format-Table Name, CommandType

Write-Host "`nChecking New-InstallerDirectory parameters:" -ForegroundColor Cyan
Get-Help New-InstallerDirectory -Parameter * | Select-Object Name, Description

Write-Host "`nChecking if New-Installer supports cleanup options:" -ForegroundColor Cyan
Get-Help New-Installer -Parameter * | Where-Object { $_.Name -match 'Remove|Clean|Uninstall' } | Select-Object Name, Description