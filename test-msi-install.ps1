# Test MSI installation
param(
    [string]$MsiPath = ".\releases_archive\UpdateLoxone-v0.3.9.msi",
    [switch]$Uninstall
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "This script requires Administrator privileges" -ForegroundColor Red
    exit 1
}

if ($Uninstall) {
    Write-Host "Uninstalling UpdateLoxone..." -ForegroundColor Yellow
    $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq "UpdateLoxone" }
    if ($product) {
        $product.Uninstall() | Out-Null
        Write-Host "Uninstalled successfully" -ForegroundColor Green
    } else {
        Write-Host "UpdateLoxone is not installed" -ForegroundColor Yellow
    }
    return
}

if (-not (Test-Path $MsiPath)) {
    Write-Host "MSI file not found: $MsiPath" -ForegroundColor Red
    exit 1
}

Write-Host "Installing MSI: $MsiPath" -ForegroundColor Cyan

# Install silently with logging
$logFile = Join-Path $env:TEMP "UpdateLoxone_Install.log"
$arguments = @(
    "/i"
    "`"$MsiPath`""
    "/qn"  # Silent install
    "/l*v"
    "`"$logFile`""
)

Write-Host "Running: msiexec $($arguments -join ' ')" -ForegroundColor Gray
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "Installation completed successfully!" -ForegroundColor Green
    
    # Check what was installed
    Write-Host "`nChecking installation..." -ForegroundColor Cyan
    
    # Check Program Files
    $installPath = "${env:ProgramFiles(x86)}\UpdateLoxone"
    if (-not (Test-Path $installPath)) {
        $installPath = "$env:ProgramFiles\UpdateLoxone"
    }
    
    if (Test-Path $installPath) {
        Write-Host "✓ Found installation at: $installPath" -ForegroundColor Green
        Write-Host "  Contents:" -ForegroundColor Gray
        Get-ChildItem $installPath -Recurse | ForEach-Object {
            $indent = "  " * ($_.FullName.Replace($installPath, "").Split('\').Count - 1)
            Write-Host "  $indent- $($_.Name)" -ForegroundColor Gray
        }
    } else {
        Write-Host "✗ Installation directory not found in Program Files" -ForegroundColor Red
    }
    
    # Check Start Menu
    $startMenuPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\UpdateLoxone",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\UpdateLoxone"
    )
    
    $foundStartMenu = $false
    foreach ($path in $startMenuPaths) {
        if (Test-Path $path) {
            Write-Host "✓ Found Start Menu shortcut at: $path" -ForegroundColor Green
            Get-ChildItem $path | ForEach-Object {
                Write-Host "  - $($_.Name)" -ForegroundColor Gray
            }
            $foundStartMenu = $true
            break
        }
    }
    
    if (-not $foundStartMenu) {
        Write-Host "✗ Start Menu shortcut not found" -ForegroundColor Red
    }
    
    # Check registry
    $uninstallKey = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
        Where-Object { $_.DisplayName -eq "UpdateLoxone" }
    
    if ($uninstallKey) {
        Write-Host "✓ Found in Add/Remove Programs:" -ForegroundColor Green
        Write-Host "  DisplayName: $($uninstallKey.DisplayName)" -ForegroundColor Gray
        Write-Host "  Version: $($uninstallKey.DisplayVersion)" -ForegroundColor Gray
        Write-Host "  Publisher: $($uninstallKey.Publisher)" -ForegroundColor Gray
        Write-Host "  InstallLocation: $($uninstallKey.InstallLocation)" -ForegroundColor Gray
    } else {
        Write-Host "✗ Not found in Add/Remove Programs" -ForegroundColor Red
    }
    
} else {
    Write-Host "Installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
    Write-Host "Check log file: $logFile" -ForegroundColor Yellow
}

Write-Host "`nLog file: $logFile" -ForegroundColor Cyan