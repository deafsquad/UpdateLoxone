# Disable-WindowsNotifications.ps1
# Temporarily disables Windows notifications at the OS level
# WARNING: This affects ALL Windows notifications, not just test notifications

param(
    [switch]$Enable
)

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
$focusAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"

if ($Enable) {
    # Re-enable notifications
    Set-ItemProperty -Path $regPath -Name "ToastEnabled" -Value 1 -ErrorAction SilentlyContinue
    Write-Host "Windows notifications RE-ENABLED" -ForegroundColor Green
} else {
    # Disable toast notifications
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ToastEnabled" -Value 0 -Force
    
    # Also set Focus Assist to Priority Only
    if (-not (Test-Path $focusAssistPath)) {
        New-Item -Path $focusAssistPath -Force | Out-Null
    }
    
    Write-Host "Windows notifications DISABLED for testing" -ForegroundColor Yellow
    Write-Host "Run with -Enable flag to restore notifications" -ForegroundColor Yellow
}