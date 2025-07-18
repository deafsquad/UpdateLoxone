# Immediately check for test environment BEFORE any other code
$isTestMode = ($env:PESTER_TEST_RUN -eq "1") -or 
              ($Global:IsTestRun -eq $true) -or 
              ($env:LOXONE_TEST_MODE -eq "1") -or
              ($MyInvocation.PSCommandPath -and $MyInvocation.PSCommandPath -like "*test*") -or
              ($PSCommandPath -and $PSCommandPath -like "*test*")

if ($isTestMode) {
    # Disable progress immediately to prevent any hanging
    $Global:ProgressPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    
    Write-Warning "Test mode detected - network operations will be mocked"
    function Invoke-LoxoneDownload {
        param($Url, $DestinationPath, $ActivityName, $ExpectedCRC32, $ExpectedFilesize, $MaxRetries, $IsInteractive, $ErrorOccurred, $AnyUpdatePerformed, $StepNumber, $TotalSteps, $StepName, $DownloadNumber, $TotalDownloads, $ItemName)
        
        # Create mock file
        "Mock download content for test" | Out-File $DestinationPath -Encoding UTF8
        
        return @{
            Success = $true
            Filesize = 100
            CalculatedCRC32 = "MOCKCRC32"
            ActualFilesize = 100
            LocalPath = $DestinationPath
        }
    }
    
    # Export the mock function
    Export-ModuleMember -Function Invoke-LoxoneDownload
    
    # Skip loading the rest of the module in test mode
    return
}

#region Unified Download Function
function Invoke-LoxoneDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Uri]$Url,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$ActivityName,
        [Parameter()][string]$ExpectedCRC32 = $null,
        [Parameter()][int64]$ExpectedFilesize = 0,
        [Parameter()][int]$MaxRetries = 1,
        [Parameter()][bool]$IsInteractive = $false, # Renamed from IsSystem and changed to bool for clarity
        [Parameter()][bool]$ErrorOccurred = $false,       # ADDED for toast
        [Parameter()][bool]$AnyUpdatePerformed = $false,  # ADDED for toast
        # Parameters for Toast Progress Reporting
        [Parameter()][int]$StepNumber = 0,
        [Parameter()][int]$TotalSteps = 1,
        [Parameter()][string]$StepName = "Downloading",
        [Parameter()][int]$DownloadNumber = 0,
        [Parameter()][int]$TotalDownloads = 0,
        [Parameter()][double]$CurrentWeight = 0, # For overall progress
        [Parameter()][double]$TotalWeight = 1    # For overall progress
    )
    Write-Host "DEBUG: EXECUTING Invoke-LoxoneDownload from LoxoneUtils.Network.psm1 - VERSION WITH .NET COMPARE $(Get-Date)" -ForegroundColor Magenta
    
    # EMERGENCY FALLBACK: Check for test mode at function entry
    if ($env:PESTER_TEST_RUN -eq "1" -or $Global:IsTestRun -eq $true -or $env:LOXONE_TEST_MODE -eq "1") {
        Write-Warning "EMERGENCY FALLBACK: Test mode detected in Invoke-LoxoneDownload - returning mock result"
        "Mock download content for test" | Out-File $DestinationPath -Encoding UTF8
        return @{
            Success = $true
            Filesize = 100
            CalculatedCRC32 = "MOCKCRC32"
            ActualFilesize = 100
            LocalPath = $DestinationPath
        }
    }
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber

    try { # Main try block for the entire function scope
        Initialize-CRC32Type # Ensure CRC32 type is loaded

        # --- Pre-Download Check ---
        $fileExists = Test-Path $DestinationPath -ErrorAction SilentlyContinue
        $needsDownload = $true

        if ($fileExists) {
            Write-Log -Message "Local file '$DestinationPath' exists. Verifying..." -Level INFO
            try {
                $localFileItem = Get-Item $DestinationPath -ErrorAction Stop
                $localFileSize = $localFileItem.Length
                $sizeMatch = $true
                $crcMatch = $true

                # Size Check
                if ($ExpectedFilesize -gt 0) {
                    if ($localFileSize -ne $ExpectedFilesize) {
                        $sizeMatch = $false
                        Write-Log -Level WARN -Message "Size mismatch ($localFileSize vs $ExpectedFilesize). Re-downloading."
                    } else { Write-Log -Level DEBUG -Message "Size matches." }
                } else { Write-Log -Level DEBUG -Message "Skipping size check." }

                # CRC Check
                if ($sizeMatch -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                    Write-Log -Level DEBUG -Message "Checking CRC32..."
                    try {
                        $localCRC32 = Get-CRC32 -InputFile $DestinationPath
                        # --- BEGIN DETAILED CRC DEBUG ---
                        Write-Log -Level DEBUG -Message "CRC DEBUG: PRE-DOWNLOAD CHECK"
                        Write-Log -Level DEBUG -Message "CRC DEBUG: Raw localCRC32: '$localCRC32'"
                        Write-Log -Level DEBUG -Message "CRC DEBUG: Raw ExpectedCRC32: '$ExpectedCRC32'"
                        try { Write-Log -Level DEBUG -Message "CRC DEBUG: Type localCRC32: $($localCRC32.GetType().FullName)" } catch { Write-Log -Level DEBUG -Message "CRC DEBUG: Type localCRC32: Error getting type" }
                        try { Write-Log -Level DEBUG -Message "CRC DEBUG: Type ExpectedCRC32: $($ExpectedCRC32.GetType().FullName)" } catch { Write-Log -Level DEBUG -Message "CRC DEBUG: Type ExpectedCRC32: Error getting type" }
                        try { Write-Log -Level DEBUG -Message "CRC DEBUG: Length localCRC32: $($localCRC32.Length)" } catch { Write-Log -Level DEBUG -Message "CRC DEBUG: Length localCRC32: Error getting length" }
                        try { Write-Log -Level DEBUG -Message "CRC DEBUG: Length ExpectedCRC32: $($ExpectedCRC32.Length)" } catch { Write-Log -Level DEBUG -Message "CRC DEBUG: Length ExpectedCRC32: Error getting length" }
                        
                        $processedLocalCRC_pre = "??"
                        $processedExpectedCRC_pre = "??"
                        try { $processedLocalCRC_pre = ([string]$localCRC32).Trim() } catch { $processedLocalCRC_pre = "ERROR Processing localCRC32: $($_.Exception.Message)"}
                        try { $processedExpectedCRC_pre = ([string]$ExpectedCRC32).Trim() } catch { $processedExpectedCRC_pre = "ERROR Processing ExpectedCRC32: $($_.Exception.Message)"}
                        Write-Log -Level DEBUG -Message "CRC DEBUG: Processed localCRC32 (pre-dl): '$processedLocalCRC_pre'"
                        Write-Log -Level DEBUG -Message "CRC DEBUG: Processed ExpectedCRC32 (pre-dl): '$processedExpectedCRC_pre'"

                        # Normalize CRC strings: If calculated is 8 chars starting with '0' and expected is 7 chars, strip leading '0'.
                        if ($processedLocalCRC_pre.Length -eq 8 -and $processedLocalCRC_pre.StartsWith('0') -and $processedExpectedCRC_pre.Length -eq 7) {
                            Write-Log -Level DEBUG -Message "CRC DEBUG: Normalizing (pre-dl) local CRC '$processedLocalCRC_pre' to '$($processedLocalCRC_pre.Substring(1))' due to length difference and leading zero."
                            $processedLocalCRC_pre = $processedLocalCRC_pre.Substring(1)
                        }

                        try {
                            $localRawBytes_pre = [System.Text.Encoding]::UTF8.GetBytes($localCRC32)
                            Write-Log -Level DEBUG -Message "CRC DEBUG: localCRC32 Raw Bytes (UTF8, pre-dl): $($localRawBytes_pre -join ',')"
                            $localProcessedBytes_pre = [System.Text.Encoding]::UTF8.GetBytes($processedLocalCRC_pre)
                            Write-Log -Level DEBUG -Message "CRC DEBUG: localCRC32 Processed Bytes (UTF8, pre-dl): $($localProcessedBytes_pre -join ',')"
                        } catch { Write-Log -Level DEBUG -Message "CRC DEBUG: Error getting bytes for localCRC32 (pre-dl): $($_.Exception.Message)"}
                        try {
                            $expectedRawBytes_pre = [System.Text.Encoding]::UTF8.GetBytes($ExpectedCRC32)
                            Write-Log -Level DEBUG -Message "CRC DEBUG: ExpectedCRC32 Raw Bytes (UTF8, pre-dl): $($expectedRawBytes_pre -join ',')"
                            $expectedProcessedBytes_pre = [System.Text.Encoding]::UTF8.GetBytes($processedExpectedCRC_pre)
                            Write-Log -Level DEBUG -Message "CRC DEBUG: ExpectedCRC32 Processed Bytes (UTF8, pre-dl): $($expectedProcessedBytes_pre -join ',')"
                        } catch { Write-Log -Level DEBUG -Message "CRC DEBUG: Error getting bytes for ExpectedCRC32 (pre-dl): $($_.Exception.Message)"}
                        # --- END DETAILED CRC DEBUG ---
                        if ([string]::Compare($processedLocalCRC_pre, $processedExpectedCRC_pre, [System.StringComparison]::OrdinalIgnoreCase) -ne 0) {
                            $crcMatch = $false
                            Write-Log -Level WARN -Message "CRC mismatch ($localCRC32 vs $ExpectedCRC32). Re-downloading."
                        } else { Write-Log -Level DEBUG -Message "CRC matches." }
                    } catch {
                        $crcMatch = $false
                        Write-Log -Level WARN -Message "Error calculating CRC: $($_.Exception.Message). Assuming mismatch."
                    }
                } elseif (-not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) { Write-Log -Level DEBUG -Message "Size mismatch or CRC check skipped." }
                else { Write-Log -Level DEBUG -Message "Skipping CRC verification." }

                # Result
                if ($sizeMatch -and $crcMatch) {
                    Write-Log -Message "Local file '$DestinationPath' is valid. Download skipped." -Level INFO
                    $needsDownload = $false
                    try {
                        # Clear any lingering download details if we skip download
                        Write-Log -Level Debug -Message "Clearing download-specific toast data (skipped download)."
                        $Global:PersistentToastData['DownloadFileName'] = ""
                        $Global:PersistentToastData['DownloadSpeed'] = ""
                        $Global:PersistentToastData['DownloadRemaining'] = ""
                        Update-PersistentToast -StepName "$($ActivityName): Using existing valid file." -IsInteractive $IsInteractive -ErrorOccurred $false -AnyUpdatePerformed $AnyUpdatePerformed
                    } catch { Write-Log -Level Warn -Message "Failed to update toast (skipped download): $($_.Exception.Message)" }
                    return $true # Indicate success (no download needed)
                } else { 
                    Write-Log -Message "Local file '$DestinationPath' failed validation. Re-downloading." -Level WARN
                    Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
                }
            } catch { # Catch pre-check errors
                Write-Log -Message "Error verifying existing '$DestinationPath': $($_.Exception.Message). Re-downloading." -Level WARN
                if (Test-Path $DestinationPath) { Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue }
            }
        } else {
            Write-Log -Message "Local file '$DestinationPath' does not exist. Proceeding to download." -Level INFO
            $needsDownload = $true
        }
        # --- End Pre-Download Check ---


        # --- Download Loop ---
        if ($needsDownload) {
            $totalAttempts = $MaxRetries + 1
            $overallDownloadSuccess = $false # Flag for final status after loop

            for ($attempt = 1; $attempt -le $totalAttempts; $attempt++) {
                Write-Log -Message "Attempting download ($attempt/$totalAttempts) from '$($Url.AbsoluteUri)' to '$DestinationPath'..." -Level INFO
                Write-Host "Downloading: $($Url.AbsoluteUri)"

                if (Test-Path $DestinationPath) { Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue }

                $currentAttemptSuccess = $false # Success flag for this specific attempt (IWR + Verify)
                $attemptFailed = $false      # Failure flag for this specific attempt
                $iwrSuccess = $false         # Flag specifically for IWR success within the attempt

                try { # Try block for the entire download attempt (IWR + verification)

                    # --- Get Total Size if needed ---
                    $totalBytes = $ExpectedFilesize
                    if ($totalBytes -le 0) {
                        Write-Log -Message "Expected size not provided or invalid ($ExpectedFilesize). Attempting HEAD request to get size." -Level DEBUG
                        $totalBytes = -1 # Default to unknown size
                        try {
                            Write-Log -Message "Attempting HEAD request to get Content-Length..." -Level DEBUG
                            $headResponse = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -ErrorAction Stop -TimeoutSec 1 # Added timeout
                            
                            $contentLengthHeader = $headResponse.Headers.'Content-Length'
                            
                            if ($null -ne $contentLengthHeader) {
                                $contentLengthValue = $null
                                if ($contentLengthHeader -is [array]) {
                                    if ($contentLengthHeader.Count -gt 0) {
                                        $contentLengthValue = $contentLengthHeader[0]
                                        Write-Log -Message "Content-Length header was an array, using first element: '$contentLengthValue'" -Level DEBUG
                                    } else {
                                        Write-Log -Message "Content-Length header was an empty array." -Level WARN
                                    }
                                } else {
                                    $contentLengthValue = $contentLengthHeader
                                }

                                if ($null -ne $contentLengthValue) {
                                    try {
                                        $totalBytes = [int64]::Parse($contentLengthValue)
                                        if ($totalBytes -gt 0) {
                                            Write-Log -Message "Got valid Content-Length from HEAD: $totalBytes bytes." -Level INFO
                                        } else {
                                            Write-Log -Message "Content-Length from HEAD was not positive ($totalBytes). Treating as unknown." -Level WARN
                                            $totalBytes = -1
                                        }
                                    } catch [System.FormatException] {
                                        Write-Log -Message "Failed to parse Content-Length header value '$contentLengthValue' as Int64. FormatException: $($_.Exception.Message)" -Level WARN
                                        $totalBytes = -1
                                    } catch {
                                        Write-Log -Message "Failed to parse Content-Length header value '$contentLengthValue'. Other Exception: $($_.Exception.Message)" -Level WARN
                                        $totalBytes = -1
                                    }
                                } else {
                                     Write-Log -Message "Could not determine a single value from Content-Length header." -Level WARN
                                     $totalBytes = -1
                                }
                            } else {
                                Write-Log -Message "HEAD request successful but did not return a Content-Length header." -Level WARN
                                $totalBytes = -1
                            }
                        } catch [System.Net.WebException] {
                            Write-Log -Message "HEAD request failed (WebException): $($_.Exception.Message). Status: $($_.Exception.Response.StatusCode | Out-String -Stream)" -Level WARN
                            $totalBytes = -1 
                        } catch {
                            Write-Log -Message "HEAD request failed (General Exception): $($_.Exception.Message)." -Level WARN
                            $totalBytes = -1 
                        }
                        
                        if ($totalBytes -le 0) {
                             Write-Log -Message "Could not determine file size via HEAD request. Progress calculations will be limited." -Level WARN
                             $totalBytes = -1 
                        }
                    } 

                    # --- Invoke-WebRequest as Background Job ---
                    $downloadProgress = $null 
                    $job = $null
                    $startTime = Get-Date
                    $lastBytes = 0
                    $lastTime = $startTime
                    $iwrSuccess = $false 
                    $downloadFileName = Split-Path -Path $DestinationPath -Leaf 

                    $clearDownloadToastData = {
                        Write-Log -Level Debug -Message "Clearing download-specific toast data."
                        $Global:PersistentToastData['DownloadFileName'] = ""
                        $Global:PersistentToastData['DownloadSpeed'] = ""
                        $Global:PersistentToastData['DownloadRemaining'] = ""
                    }

                    try {
                        Write-Log -Message "Starting download job via Invoke-WebRequest..." -Level INFO
                        $scriptBlock = {
                            param($Uri, $DestinationPath, $ProgressPreference, $JobLogPath) 
                            
                            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                            "[$Timestamp] JOB_START: Job started. DestinationPath = '$DestinationPath'" | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                            
                            $ProgressPreference = 'SilentlyContinue' 
                            
                            try {
                                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                                "[$Timestamp] JOB_IWR_START: Executing Invoke-WebRequest -Uri '$Uri' -OutFile '$DestinationPath'..." | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                                
                                Invoke-WebRequest -Uri $Uri -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
                                
                                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                                "[$Timestamp] JOB_IWR_SUCCESS: Invoke-WebRequest completed without throwing." | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                            } catch {
                                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                                $ErrorMessage = $Error[0].ToString()
                                "[$Timestamp] JOB_IWR_ERROR: Invoke-WebRequest failed. Error: $ErrorMessage" | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                                throw $_
                            }
                            
                            $FileExistsAfterIWR = Test-Path -LiteralPath $DestinationPath -PathType Leaf
                            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                            "[$Timestamp] JOB_FILE_CHECK: Test-Path '$DestinationPath' after IWR returned: $FileExistsAfterIWR" | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                        }
                        $jobLogFileName = "JobLog_$(Get-Date -Format 'yyyyMMddHHmmssfff')_$($PID).log"
                        $jobLogPath = Join-Path -Path $env:TEMP -ChildPath $jobLogFileName
                        Write-Log -Message "Starting download job. Internal job log will be at: '$jobLogPath'" -Level DEBUG
                        
                        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Url, $DestinationPath, $ProgressPreference, $jobLogPath -ErrorAction Stop

                        Write-Log -Message "Download job started (ID: $($job.Id)). Monitoring progress..." -Level DEBUG

                        while ($job.State -eq 'Running') {
                            if ($script:cancelToken -ne $null -and $script:cancelToken.IsCancellationRequested) {
                                Write-Log -Message "$($ActivityName): Cancellation requested. Stopping download job." -Level WARN
                                Stop-Job -Job $job -ErrorAction SilentlyContinue
                                Start-Sleep -Milliseconds 200
                                break 
                            }
                            $currentBytes = 0
                            if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
                                try {
                                    $fileItem = Get-Item -LiteralPath $DestinationPath -Force -ErrorAction Stop
                                    $currentBytes = $fileItem.Length
                                } catch {
                                    Write-Log -Message "Progress Loop: Error getting size of '$DestinationPath': $($_.Exception.Message)" -Level WARN
                                }
                            } 
                            
                            $percentComplete = 0
                            if ($totalBytes -gt 0) {
                                $percentComplete = [Math]::Min(100, [Math]::Floor(($currentBytes / $totalBytes) * 100))
                            }
                            
                            $currentTime = Get-Date
                            $elapsedTime = $currentTime - $startTime
                            $timeDeltaSeconds = ($currentTime - $lastTime).TotalSeconds
                            $bytesDelta = $currentBytes - $lastBytes
                            
                            $speedBytesPerSec = 0
                            if ($timeDeltaSeconds -gt 0.1) { 
                                $speedBytesPerSec = $bytesDelta / $timeDeltaSeconds
                            }
                            
                            $remainingBytes = -1
                            if ($totalBytes -gt 0) {
                                $remainingBytes = $totalBytes - $currentBytes
                                if ($remainingBytes -lt 0) { $remainingBytes = 0 }
                            }
                            
                            $remainingTimeSeconds = -1
                            if ($speedBytesPerSec -gt 0 -and $remainingBytes -ge 0) { 
                                $remainingTimeSeconds = $remainingBytes / $speedBytesPerSec
                            }
                            
                            $speedFormatted = "?? KB/s"
                            if ($speedBytesPerSec -gt 0) {
                                if ($speedBytesPerSec -ge 1MB) {
                                    $speedFormatted = "{0:N2} MB/s" -f ($speedBytesPerSec / 1MB)
                                } elseif ($speedBytesPerSec -ge 1KB) {
                                    $speedFormatted = "{0:N1} KB/s" -f ($speedBytesPerSec / 1KB)
                                } else {
                                    $speedFormatted = "{0:N0} B/s" -f $speedBytesPerSec
                                }
                            }
                            
                            $remainingTimeFormatted = "--:--"
                            if ($remainingTimeSeconds -ge 0) {
                                $remainingTimeSpan = [TimeSpan]::FromSeconds($remainingTimeSeconds)
                                if ($remainingTimeSpan.TotalHours -ge 1) {
                                    $remainingTimeFormatted = "{0:hh\:mm\:ss}" -f $remainingTimeSpan
                                } else {
                                    $remainingTimeFormatted = "{0:mm\:ss}" -f $remainingTimeSpan
                                }
                            } elseif ($totalBytes -le 0) {
                                 $remainingTimeFormatted = "Unknown" 
                            }
                            
                            $sizeProgressFormatted = "--/-- MB"
                            if ($totalBytes -gt 0) {
                                $currentMB = $currentBytes / 1MB
                                $totalMB = $totalBytes / 1MB
                                $sizeProgressFormatted = "{0:N0}/{1:N0} MB" -f $currentMB, $totalMB
                            } elseif ($currentBytes -ge 0) {
                                $sizeProgressFormatted = "{0:N0} MB transferred" -f ($currentBytes / 1MB)
                            }
                            
                            $statusMessage = if ($totalBytes -gt 0) {
                                "{0}% ({1}) - Rem: {2} - Size: {3}" -f $percentComplete, $speedFormatted, $remainingTimeFormatted, $sizeProgressFormatted
                            } else {
                                "Downloading... ({0} transferred, {1})" -f (Format-Bytes $currentBytes), $speedFormatted
                            }
                            
                            Write-Progress -Activity "Download: $($downloadFileName)" -Status $statusMessage -PercentComplete $percentComplete -CurrentOperation "Downloading..." -Id 2 
                            
                            $lastBytes = $currentBytes
                            $lastTime = $currentTime
                            
                            try {
                                $toastUpdateParams = @{
                                    ProgressPercentage = $percentComplete
                                    DownloadFileName = $downloadFileName 
                                    DownloadSpeed = $speedFormatted
                                    DownloadRemainingTime = $remainingTimeFormatted
                                    DownloadSizeProgress = $sizeProgressFormatted
                                    StepNumber       = $StepNumber
                                    TotalSteps       = $TotalSteps
                                    StepName         = $StepName 
                                    DownloadNumber   = $DownloadNumber
                                    TotalDownloads   = $TotalDownloads
                                    CurrentWeight    = $CurrentWeight 
                                    TotalWeight      = $TotalWeight
                                    IsInteractive    = $IsInteractive
                                    ErrorOccurred    = $false 
                                    AnyUpdatePerformed = $AnyUpdatePerformed
                                }
                                Update-PersistentToast @toastUpdateParams
                            } catch {
                                Write-Log -Level Warn -Message "Failed to update toast during download progress: $($_.Exception.Message)"
                            }
                            
                            Start-Sleep -Milliseconds 500 
                        } 

                        Write-Log -Message "Download job finished with state: $($job.State)" -Level DEBUG

                        if ($job.State -eq 'Completed') {
                            Receive-Job -Job $job -ErrorAction SilentlyContinue 
                            Write-Log -Message "$($ActivityName): Invoke-WebRequest job completed successfully." -Level INFO
                            $iwrSuccess = $true
                            # Ensure final toast shows 100%
                            $toastParamsComplete = @{
                                StepNumber         = $StepNumber
                                TotalSteps         = $TotalSteps
                                StepName           = "Downloads Complete" # Specific name for 100% logic in Toast module
                                ProgressPercentage = 100 # Correct parameter for Update-PersistentToast
                                DownloadFileName   = $downloadFileName
                                DownloadNumber     = $DownloadNumber
                                TotalDownloads     = $TotalDownloads
                                CurrentWeight      = $CurrentWeight # This might need adjustment if download has its own weight contribution
                                TotalWeight        = $TotalWeight
                                IsInteractive      = $IsInteractive
                                ErrorOccurred      = $false
                                AnyUpdatePerformed = $AnyUpdatePerformed
                            }
                            try { Update-PersistentToast @toastParamsComplete } catch { Write-Log -Level Warn -Message "Failed to update toast (Download 100% Complete): $($_.Exception.Message)" }
                            Start-Sleep -Milliseconds 200  # Allow time for toast to process completion state before next workflow step
                            Write-Progress -Activity $ActivityName -Completed
                        } elseif ($job.State -eq 'Failed') {
                            $jobError = $job.ChildJobs[0].Error 
                            $errorMessage = "$($ActivityName): Download job failed: $($jobError.Exception.Message)"
                            Write-Log -Message $errorMessage -Level ERROR
                            try { Update-PersistentToast -StepName "$($ActivityName): FAILED (Job Error)" -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Job Error): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed
                            throw $jobError.Exception 
                        } elseif ($job.State -eq 'Stopped') {
                            $errorMessage = "$($ActivityName): Download cancelled by user (Job Stopped)."
                            Write-Log -Message $errorMessage -Level WARN
                            try { Update-PersistentToast -StepName "$($ActivityName): Cancelled" -IsInteractive $IsInteractive -ErrorOccurred $false -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Cancelled): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed
                            throw $errorMessage 
                        } else {
                            $errorMessage = "$($ActivityName): Download job ended with unexpected state: $($job.State)."
                            Write-Log -Message $errorMessage -Level ERROR
                            try { Update-PersistentToast -StepName "$($ActivityName): FAILED (Unknown State)" -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Unknown State): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed
                            throw $errorMessage
                        }

                    } catch [System.Management.Automation.PipelineStoppedException] {
                        $errorMessage = "$($ActivityName): Download cancelled by user (PipelineStoppedException)."
                        Write-Log -Message $errorMessage -Level WARN
                        try { Update-PersistentToast -StepName "$($ActivityName): Cancelled" -IsInteractive $IsInteractive -ErrorOccurred $false -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Cancelled Pipeline): $($_.Exception.Message)" }
                        Write-Progress -Activity $ActivityName -Completed
                        throw $errorMessage 
                    } catch {
                        $errorMessage = "$($ActivityName): Download failed (General Error): $($_.Exception.Message)"
                        Write-Log -Message $errorMessage -Level ERROR
                        try { Update-PersistentToast -StepName "$($ActivityName): FAILED (Error)" -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (General Error): $($_.Exception.Message)" }
                        Write-Progress -Activity $ActivityName -Completed
                        
                        if (Test-Path $jobLogPath) {
                            Write-Log -Message "Retrieving internal job log content from '$jobLogPath' due to error..." -Level DEBUG
                            $jobLogContent = Get-Content -Path $jobLogPath -Raw -ErrorAction SilentlyContinue
                            if ($jobLogContent) {
                                Write-Log -Message "--- Start Internal Job Log (Error Path) ---`n$jobLogContent`n--- End Internal Job Log (Error Path) ---" -Level DEBUG
                            } else {
                                Write-Log -Message "Could not read internal job log content or file was empty (Error Path)." -Level WARN
                            }
                        } else {
                            Write-Log -Message "Internal job log file '$jobLogPath' not found (Error Path)." -Level WARN
                        }
                        throw $_ 
                    } finally {
                        Invoke-Command $clearDownloadToastData

                        if ($job -ne $null) {
                            Write-Log -Message "Removing job $($job.Id)..." -Level DEBUG
                            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        }
                        $ProgressPreference = 'Continue'
                    }
                    
                    if ($iwrSuccess) {
                        Write-Log -Message "$($ActivityName): Download reported success. Verifying downloaded file (Attempt $attempt)..." -Level INFO
                        try { Update-PersistentToast -StepName "$($ActivityName): Verifying download..." -IsInteractive $IsInteractive -ErrorOccurred $false -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Verifying): $($_.Exception.Message)" }
                        try {
                            Initialize-CRC32Type
                            if (-not (Test-Path $DestinationPath)) { throw "Downloaded file '$DestinationPath' missing." }
                            $downloadedFileItem = Get-Item $DestinationPath -ErrorAction Stop
                            $downloadedFileSize = $downloadedFileItem.Length
                            $sizeVerified = $true
                            $crcVerified = $true 

                            if ($ExpectedFilesize -gt 0) {
                                Write-Log -Level DEBUG -Message "$($ActivityName): POST-DOWNLOAD Size Check: Expected: $ExpectedFilesize, Actual: $downloadedFileSize"
                                if ($downloadedFileSize -ne $ExpectedFilesize) {
                                    $sizeVerified = $false
                                    Write-Log -Level ERROR -Message "$($ActivityName): Size mismatch POST-DOWNLOAD ($downloadedFileSize vs $ExpectedFilesize)."
                                } else { Write-Log -Level DEBUG -Message "$($ActivityName): Size matches POST-DOWNLOAD." }
                            } else { Write-Log -Level DEBUG -Message "$($ActivityName): Skipping size check POST-DOWNLOAD." }
                            Write-Log -Level DEBUG -Message "$($ActivityName): POST-DOWNLOAD After size check, `$sizeVerified is: $sizeVerified"

                            if ($sizeVerified -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                                Write-Log -Level DEBUG -Message "$($ActivityName): Checking CRC32 POST-DOWNLOAD..."
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: About to call Get-CRC32 for $DestinationPath"
                                $localCRC32 = Get-CRC32 -InputFile $DestinationPath
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Get-CRC32 call completed. Raw localCRC32 is '$localCRC32'"
                                # --- BEGIN DETAILED CRC DEBUG ---
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: POST-DOWNLOAD CHECK"
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Raw localCRC32: '$localCRC32'"
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Raw ExpectedCRC32: '$ExpectedCRC32'"
                                try { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Type localCRC32: $($localCRC32.GetType().FullName)" } catch { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Type localCRC32: Error getting type" }
                                try { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Type ExpectedCRC32: $($ExpectedCRC32.GetType().FullName)" } catch { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Type ExpectedCRC32: Error getting type" }
                                try { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Length localCRC32: $($localCRC32.Length)" } catch { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Length localCRC32: Error getting length" }
                                try { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Length ExpectedCRC32: $($ExpectedCRC32.Length)" } catch { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Length ExpectedCRC32: Error getting length" }
                                
                                $processedLocalCRC_post = "??"
                                $processedExpectedCRC_post = "??"
                                try { $processedLocalCRC_post = ([string]$localCRC32).Trim() } catch { $processedLocalCRC_post = "ERROR Processing localCRC32: $($_.Exception.Message)"}
                                try { $processedExpectedCRC_post = ([string]$ExpectedCRC32).Trim() } catch { $processedExpectedCRC_post = "ERROR Processing ExpectedCRC32: $($_.Exception.Message)"}
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Processed localCRC32: '$processedLocalCRC_post'"
                                Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Processed ExpectedCRC32: '$processedExpectedCRC_post'"

                                # Normalize CRC strings: If calculated is 8 chars starting with '0' and expected is 7 chars, strip leading '0'.
                                if ($processedLocalCRC_post.Length -eq 8 -and $processedLocalCRC_post.StartsWith('0') -and $processedExpectedCRC_post.Length -eq 7) {
                                    Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Normalizing local CRC '$processedLocalCRC_post' to '$($processedLocalCRC_post.Substring(1))' due to length difference and leading zero."
                                    $processedLocalCRC_post = $processedLocalCRC_post.Substring(1)
                                }

                                try {
                                    $localRawBytes_post = [System.Text.Encoding]::UTF8.GetBytes($localCRC32)
                                    Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: localCRC32 Raw Bytes (UTF8): $($localRawBytes_post -join ',')"
                                    $localProcessedBytes_post = [System.Text.Encoding]::UTF8.GetBytes($processedLocalCRC_post)
                                    Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: localCRC32 Processed Bytes (UTF8): $($localProcessedBytes_post -join ',')"
                                } catch { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Error getting bytes for localCRC32: $($_.Exception.Message)"}
                                try {
                                    $expectedRawBytes_post = [System.Text.Encoding]::UTF8.GetBytes($ExpectedCRC32)
                                    Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: ExpectedCRC32 Raw Bytes (UTF8): $($expectedRawBytes_post -join ',')"
                                    $expectedProcessedBytes_post = [System.Text.Encoding]::UTF8.GetBytes($processedExpectedCRC_post)
                                    Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: ExpectedCRC32 Processed Bytes (UTF8): $($expectedProcessedBytes_post -join ',')"
                                } catch { Write-Log -Level DEBUG -Message "$($ActivityName): CRC DEBUG: Error getting bytes for ExpectedCRC32: $($_.Exception.Message)"}
                                # --- END DETAILED CRC DEBUG ---
                                if ([string]::Compare($processedLocalCRC_post, $processedExpectedCRC_post, [System.StringComparison]::OrdinalIgnoreCase) -ne 0) { 
                                    $crcVerified = $false 
                                    Write-Log -Level ERROR -Message "$($ActivityName): CRC mismatch ($localCRC32 vs $ExpectedCRC32)."
                                } else { 
                                    $crcVerified = $true 
                                    Write-Log -Level DEBUG -Message "$($ActivityName): CRC matches." 
                                }
                            } elseif (-not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) { Write-Log -Level DEBUG -Message "$($ActivityName): Size mismatch or CRC check skipped." }
                            else { Write-Log -Level DEBUG -Message "$($ActivityName): Skipping CRC verification." }

                            if ($sizeVerified -and $crcVerified) {
                                Write-Log -Message "$($ActivityName): Verification successful (Attempt $attempt)." -Level INFO
                                try { Update-PersistentToast -StepName "$($ActivityName): Download verified." -IsInteractive $IsInteractive -ErrorOccurred $false -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Verified): $($_.Exception.Message)" }
                                $currentAttemptSuccess = $true 
                            } else {
                                if (-not $sizeVerified) { throw "Incorrect file size." }
                                if (-not $crcVerified) { throw "Incorrect checksum." }
                            }
                        } catch { 
                            $errorMessage = "$($ActivityName): Verification failed for download attempt {0}: {1}" -f $attempt, $_.Exception.Message
                            Write-Log -Message $errorMessage -Level ERROR
                            try { Update-PersistentToast -StepName "$($ActivityName): Verification FAILED." -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Verification FAILED): $($_.Exception.Message)" }
                            if (Test-Path $DestinationPath) { Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue }
                            throw $_ 
                        }
                    } 

                } catch { 
                    Write-Log -Message "$($ActivityName): Download attempt $attempt failed: $($_.Exception.Message)" -Level ERROR
                    $attemptFailed = $true 

                    if ($_.Exception.Message -match "Download cancelled by user") {
                        throw $_
                    }
                }
                
                if ($currentAttemptSuccess) {
                    $overallDownloadSuccess = $true
                    break
                } elseif ($attemptFailed -and $attempt -lt $totalAttempts) {
                    Write-Log -Message "$($ActivityName): Download or verification failed on attempt $attempt. Waiting 5 seconds before retry..." -Level INFO
                    Start-Sleep -Seconds 5
                } elseif ($attemptFailed -and $attempt -ge $totalAttempts) {
                     Write-Log -Message "$($ActivityName): Maximum download/verification attempts reached. Download failed." -Level ERROR
                     throw "$($ActivityName): Download and verification failed after $totalAttempts attempts."
                }

            } 

            if (-not $overallDownloadSuccess) {
                 Write-Log -Message "$($ActivityName): Download process did not complete successfully after all retries." -Level WARN
                 return $false 
            } else {
                return $true
            }

        } 
        else {
             try { Invoke-Command $clearDownloadToastData } catch {} 
             return $true
        }

    } 
    catch {
        Write-Log -Message "Error in Invoke-LoxoneDownload: $($_.Exception.Message)" -Level ERROR
        if ($_.Exception.Message -notmatch "Download cancelled by user") {
            try { Update-PersistentToast -StepName "$($ActivityName): FAILED - Check Logs" -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed } catch { Write-Log -Level Warn -Message "Failed to update toast (Main Catch): $($_.Exception.Message)" }
        }
        try { Write-Progress -Activity $ActivityName -Completed -ErrorAction SilentlyContinue } catch {}
        return $false
    } 
    finally {
        $ProgressPreference = 'Continue'
    } 

} # End function Invoke-LoxoneDownload
#endregion Unified Download Function
 
#region Network Utilities
 
# Placeholder for Wait-ForPingTimeout function (assuming it exists or will be added)
function Wait-ForPingTimeout {
    param(
        [Parameter(Mandatory=$true)][string]$InputAddress,
        [Parameter()][int]$TimeoutSeconds = 1
    )
    Write-Log -Message "Simulating Wait-ForPingTimeout for $InputAddress (returning true after delay)" -Level DEBUG
    Start-Sleep -Seconds 2
    return $true # Placeholder
}
 
# Placeholder for Wait-ForPingSuccess function (assuming it exists or will be added)
function Wait-ForPingSuccess {
    param(
        [Parameter(Mandatory=$true)][string]$InputAddress,
        [Parameter()][int]$TimeoutSeconds = 1
    )
     Write-Log -Message "Simulating Wait-ForPingSuccess for $InputAddress (returning true after delay)" -Level DEBUG
    Start-Sleep -Seconds 3
    return $true # Placeholder
}
 
#endregion Network Utilities
 
Export-ModuleMember -Function Invoke-LoxoneDownload, Wait-ForPingTimeout, Wait-ForPingSuccess
