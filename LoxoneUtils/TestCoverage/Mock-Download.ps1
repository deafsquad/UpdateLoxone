# Mock the download function to prevent hanging
function Invoke-LoxoneDownload {
    param(
        [string]$Url,
        [string]$OutputPath,
        [switch]$ShowProgress
    )
    
    # Create a mock file
    "Mock download content" | Out-File $OutputPath -Encoding UTF8
    
    return @{
        Success = $true
        FilePath = $OutputPath
        FileSize = (Get-Item $OutputPath).Length
    }
}
