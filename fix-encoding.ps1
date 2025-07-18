# Fix encoding for UpdateLoxone.ps1 by adding UTF-8 BOM

$scriptPath = ".\UpdateLoxone.ps1"

# Read the file content
$content = Get-Content -Path $scriptPath -Raw -Encoding UTF8

# Check if it already has BOM
$bytes = [System.IO.File]::ReadAllBytes($scriptPath)
$hasBOM = ($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)

if ($hasBOM) {
    Write-Host "File already has UTF-8 BOM" -ForegroundColor Green
} else {
    Write-Host "Adding UTF-8 BOM to file..." -ForegroundColor Yellow
    
    # Write with BOM
    $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($scriptPath, $content, $utf8WithBom)
    
    Write-Host "UTF-8 BOM added successfully" -ForegroundColor Green
}

# Verify
$newBytes = [System.IO.File]::ReadAllBytes($scriptPath)
if (($newBytes[0] -eq 0xEF) -and ($newBytes[1] -eq 0xBB) -and ($newBytes[2] -eq 0xBF)) {
    Write-Host "Verification: File now has UTF-8 BOM" -ForegroundColor Green
} else {
    Write-Host "Verification: Failed to add BOM" -ForegroundColor Red
}