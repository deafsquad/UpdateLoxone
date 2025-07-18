# Restore emoji symbols in UpdateLoxone.ps1

$filePath = ".\UpdateLoxone.ps1"

# Read the content
$content = Get-Content -Path $filePath -Raw -Encoding UTF8

# Replace text alternatives back to emojis
$replacements = @{
    "[UPDATE]"   = "🔄"
    "[INSTALL]"  = "🚀"
    "[DOWNLOAD]" = "⬇️"
    "[EXTRACT]"  = "📦"
    "[OK]"       = "✓"
    "[NOTFOUND]" = "🔍"
    "[WARNING]"  = "⚠️"
    "[FAILED]"   = "✗"
}

foreach ($text in $replacements.Keys) {
    $emoji = $replacements[$text]
    Write-Host "Restoring '$text' to '$emoji'"
    $content = $content -replace [regex]::Escape($text), $emoji
}

# Write back with UTF-8 BOM
$utf8WithBom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($filePath, $content, $utf8WithBom)

Write-Host "Emoji restoration complete!" -ForegroundColor Green