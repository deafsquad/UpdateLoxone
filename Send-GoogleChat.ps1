param(
    # Parameters are now optional, logic below will decide which to use
    [string]$LogFilePath,
    [string]$Message,

    [string]$Uri = 'https://chat.googleapis.com/v1/spaces/AAAACC1obHI/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=_laQ0zzNJDo60PMKckZY4z-IYz0nLIj4TjJI0qONNyY'
)

# --- Debugging Start ---
# Define log file path FIRST
$scriptErrorLogDir = "C:\temp"
$LogFilePath = "C:\Users\deafs_iutw2w3\UpdateLoxone\UpdateLoxone_deafs_iutw2w3_20250414_004234.log" #Join-Path $scriptErrorLogDir "toast_chat_error.log"
# Ensure directory exists
if (-not (Test-Path $scriptErrorLogDir)) { New-Item -Path $scriptErrorLogDir -ItemType Directory -Force | Out-Null }
# Log received parameters and set name
$debugInfo = @"
Timestamp: $(Get-Date)
PSBoundParameters: $($PSBoundParameters | Out-String)
ParameterSetName: $($PSCmdlet.ParameterSetName)
---
"@
# Add-Content -Path $scriptErrorLogPath -Value $debugInfo # Keep debug logging commented out for now
# --- Debugging End ---

# Define log file for errors from this script itself (path defined above)
#$scriptErrorLogDir = "C:\temp"
#$LogFilePath = Join-Path $scriptErrorLogDir "toast_chat_error.log"

try {
    $messageToSend = ''

    # Determine message based on provided parameters
    if (-not [string]::IsNullOrWhiteSpace($LogFilePath)) {
        # LogFilePath was provided, try to use it
        if (Test-Path -Path $LogFilePath -PathType Leaf) {
            try {
                # Read all bytes from the log file
                $fileBytes = [System.IO.File]::ReadAllBytes($LogFilePath)

                # Compress the bytes using GZip
                $memoryStream = [System.IO.MemoryStream]::new()
                $gzipStream = [System.IO.Compression.GZipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
                $gzipStream.Write($fileBytes, 0, $fileBytes.Length)
                $gzipStream.Close() # Important: Close the GZipStream to flush data
                $compressedBytes = $memoryStream.ToArray()
                $memoryStream.Close()

                # Convert compressed bytes to Base64 string
                $base64String = [System.Convert]::ToBase64String($compressedBytes)
                $messageToSend = "GZIP+Base64:" + $base64String # Prefix to indicate format
            } catch {
                 $messageToSend = "Error reading/compressing log file '$LogFilePath': $($_.Exception.Message)"
            }
        } else {
            $messageToSend = "Error: Log file not found at '$LogFilePath'"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($Message)) {
        # LogFilePath was NOT provided, but Message was
        $messageToSend = $Message
    } else {
        # Neither parameter was provided with a value
        $messageToSend = "Error: No LogFilePath or Message provided to Send-GoogleChat.ps1"
    }

    # Ensure message isn't empty
    if ([string]::IsNullOrWhiteSpace($messageToSend)) {
        $messageToSend = "(Empty log file or message)"
    }

    $body = @{
        text = $messageToSend
    } | ConvertTo-Json -Compress

    # Use -UseBasicParsing to avoid potential IE engine dependency issues
    Invoke-RestMethod -Uri $Uri -Method Post -Body $body -ContentType 'application/json; charset=UTF-8' -UseBasicParsing -ErrorAction Stop

    # Optional success logging
    # if (-not (Test-Path $scriptErrorLogDir)) { New-Item -Path $scriptErrorLogDir -ItemType Directory -Force | Out-Null }
    # Add-Content -Path $scriptErrorLogPath -Value "Successfully sent message at $(Get-Date)"

} catch {
    # Log the error for debugging purposes
    $errorMessage = "Error sending to Google Chat at $(Get-Date): $($_.Exception.ToString())"
    # Ensure the directory exists before writing the log
    if (-not (Test-Path $scriptErrorLogDir)) { New-Item -Path $scriptErrorLogDir -ItemType Directory -Force | Out-Null }
    Add-Content -Path $scriptErrorLogPath -Value $errorMessage
    # throw $_ # Optional: re-throw if needed
}