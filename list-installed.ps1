Write-Host "Checking installed UpdateLoxone versions..." -ForegroundColor Cyan
Get-CimInstance -Class Win32_Product | Where-Object { $_.Name -like '*UpdateLoxone*' } | 
    Select-Object Name, Version, IdentifyingNumber | 
    Format-Table -AutoSize