# Check for display name parameters in PSMSI
Import-Module PSMSI -ErrorAction Stop

Write-Host "Checking New-Installer parameters for display name options:" -ForegroundColor Cyan
Get-Help New-Installer -Parameter * | Where-Object { $_.Name -match 'Display|Name|Title' } | Select-Object Name, Description | Format-Table -AutoSize

Write-Host "`nAll New-Installer parameters:" -ForegroundColor Cyan
Get-Help New-Installer -Parameter * | Select-Object Name | Format-Table -AutoSize