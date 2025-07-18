# Replace emojis with safe text alternatives in UpdateLoxone.ps1

$filePath = ".\UpdateLoxone.ps1"

# Read the content
$content = Get-Content -Path $filePath -Raw -Encoding UTF8

# Define replacements using hex codes to avoid encoding issues
$replacements = @(
    @{ Pattern = [char]0xD83D + [char]0xDD04; Replace = "[UPDATE]" }      # 🔄
    @{ Pattern = [char]0xD83D + [char]0xDE80; Replace = "[INSTALL]" }     # 🚀
    @{ Pattern = [char]0x2B07 + [char]0xFE0F; Replace = "[DOWNLOAD]" }    # ⬇️
    @{ Pattern = [char]0xD83D + [char]0xDCE6; Replace = "[EXTRACT]" }     # 📦
    @{ Pattern = [char]0x2713; Replace = "[OK]" }                         # ✓
    @{ Pattern = [char]0xD83D + [char]0xDD0D; Replace = "[NOTFOUND]" }    # 🔍
    @{ Pattern = [char]0x26A0 + [char]0xFE0F; Replace = "[WARNING]" }     # ⚠️
    @{ Pattern = [char]0x2717; Replace = "[FAILED]" }                     # ✗
)

# Also try direct byte pattern matching
$bytePatterns = @(
    @{ Bytes = @(0xF0, 0x9F, 0x94, 0x84); Replace = "[UPDATE]" }     # 🔄
    @{ Bytes = @(0xF0, 0x9F, 0x9A, 0x80); Replace = "[INSTALL]" }    # 🚀
    @{ Bytes = @(0xE2, 0xAC, 0x87, 0xEF, 0xB8, 0x8F); Replace = "[DOWNLOAD]" }  # ⬇️
    @{ Bytes = @(0xF0, 0x9F, 0x93, 0xA6); Replace = "[EXTRACT]" }    # 📦
    @{ Bytes = @(0xE2, 0x9C, 0x93); Replace = "[OK]" }               # ✓
    @{ Bytes = @(0xF0, 0x9F, 0x94, 0x8D); Replace = "[NOTFOUND]" }   # 🔍
    @{ Bytes = @(0xE2, 0x9A, 0xA0, 0xEF, 0xB8, 0x8F); Replace = "[WARNING]" }  # ⚠️
    @{ Bytes = @(0xE2, 0x9C, 0x97); Replace = "[FAILED]" }           # ✗
)

# Convert to UTF8 bytes
$utf8 = [System.Text.Encoding]::UTF8
$bytes = $utf8.GetBytes($content)

# Replace byte patterns
foreach ($pattern in $bytePatterns) {
    $patternBytes = [byte[]]$pattern.Bytes
    $replaceBytes = $utf8.GetBytes($pattern.Replace)
    
    # Find and replace pattern
    for ($i = 0; $i -le $bytes.Length - $patternBytes.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $patternBytes.Length; $j++) {
            if ($bytes[$i + $j] -ne $patternBytes[$j]) {
                $match = $false
                break
            }
        }
        
        if ($match) {
            Write-Host "Found emoji pattern at position $i, replacing with $($pattern.Replace)"
            # Create new byte array with replacement
            $newBytes = New-Object byte[] ($bytes.Length - $patternBytes.Length + $replaceBytes.Length)
            [Array]::Copy($bytes, 0, $newBytes, 0, $i)
            [Array]::Copy($replaceBytes, 0, $newBytes, $i, $replaceBytes.Length)
            [Array]::Copy($bytes, $i + $patternBytes.Length, $newBytes, $i + $replaceBytes.Length, $bytes.Length - $i - $patternBytes.Length)
            $bytes = $newBytes
            $i += $replaceBytes.Length - 1
        }
    }
}

# Convert back to string and write with BOM
$newContent = $utf8.GetString($bytes)
$utf8WithBom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($filePath, $newContent, $utf8WithBom)

Write-Host "Emoji replacement complete!" -ForegroundColor Green