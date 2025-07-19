Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Where-Object { $_.DisplayName -like '*UpdateLoxone*' } | 
    Select-Object DisplayName, DisplayVersion, PSChildName | 
    Format-Table -AutoSize