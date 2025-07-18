# MSI Uninstall Cleanup Script
# This script is called during MSI uninstallation to clean up any remaining files

param(
    [string]$InstallPath = "${env:ProgramFiles}\UpdateLoxone"
)

# Clean up logs directory if it exists
$logsPath = Join-Path $InstallPath "logs"
if (Test-Path $logsPath) {
    try {
        Remove-Item -Path $logsPath -Recurse -Force -ErrorAction Stop
        Write-Host "Removed logs directory: $logsPath"
    } catch {
        # Don't fail the uninstall if cleanup fails
        Write-Warning "Could not remove logs directory: $_"
    }
}

# Clean up any other temporary files
$tempFiles = @(
    "*.tmp",
    "*.log",
    "*.bak"
)

foreach ($pattern in $tempFiles) {
    Get-ChildItem -Path $InstallPath -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Removed: $($_.Name)"
        } catch {
            Write-Warning "Could not remove: $($_.Name)"
        }
    }
}

# Success - return 0
exit 0