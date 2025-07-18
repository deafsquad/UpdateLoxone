# Check installed UpdateLoxone versions
Write-Host "Checking installed UpdateLoxone versions..." -ForegroundColor Cyan

# Check in Uninstall registry
$uninstallPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installed = @()
foreach ($path in $uninstallPaths) {
    if (Test-Path $path) {
        $installed += Get-ItemProperty $path -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -like '*UpdateLoxone*' }
    }
}

if ($installed.Count -gt 0) {
    Write-Host "`nFound $($installed.Count) UpdateLoxone installation(s):" -ForegroundColor Green
    $installed | ForEach-Object {
        Write-Host "`n  DisplayName: $($_.DisplayName)" -ForegroundColor Yellow
        Write-Host "  Version: $($_.DisplayVersion)"
        Write-Host "  Publisher: $($_.Publisher)"
        Write-Host "  InstallLocation: $($_.InstallLocation)"
        Write-Host "  UninstallString: $($_.UninstallString)"
        Write-Host "  ModifyPath: $($_.ModifyPath)"
        Write-Host "  ProductCode: $($_.PSChildName)"
    }
} else {
    Write-Host "No UpdateLoxone installations found in registry." -ForegroundColor Yellow
}

# Also check WMI
Write-Host "`nChecking WMI..." -ForegroundColor Cyan
$wmiProducts = Get-CimInstance -Class Win32_Product | Where-Object { $_.Name -like '*UpdateLoxone*' }
if ($wmiProducts) {
    $wmiProducts | ForEach-Object {
        Write-Host "`nWMI Product:"
        Write-Host "  Name: $($_.Name)"
        Write-Host "  Version: $($_.Version)"
        Write-Host "  IdentifyingNumber: $($_.IdentifyingNumber)"
    }
}