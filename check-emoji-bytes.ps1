# Check the exact bytes at line 1034 of UpdateLoxone.ps1
$content = Get-Content -Path ".\UpdateLoxone.ps1" -Raw -Encoding UTF8
$lines = $content -split "`r?`n"

# Get line 1034 (0-indexed, so 1033)
$line1034 = $lines[1033]
Write-Host "Line 1034: $line1034"

# Convert to bytes and show hex
$bytes = [System.Text.Encoding]::UTF8.GetBytes($line1034)
Write-Host "Bytes (hex):"
$hexString = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
Write-Host $hexString

# Check specific position where error occurs (around position 29)
Write-Host "`nCharacters around position 29:"
for ($i = 25; $i -lt 35; $i++) {
    if ($i -lt $line1034.Length) {
        $char = $line1034[$i]
        $charCode = [int][char]$char
        Write-Host "Position $i : '$char' (U+{0:X4})" -f $charCode
    }
}