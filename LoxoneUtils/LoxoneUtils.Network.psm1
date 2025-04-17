# BITS download function removed to restore previous Invoke-WebRequest method.

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
        [Parameter()][switch]$IsSystem, # Added to pass context to Toast functions
        # Parameters for Toast Progress Reporting
        [Parameter()][int]$StepNumber = 0,
        [Parameter()][int]$TotalSteps = 1,
        [Parameter()][string]$StepName = "Downloading",
        [Parameter()][int]$DownloadNumber = 0,
        [Parameter()][int]$TotalDownloads = 0,
        [Parameter()][double]$CurrentWeight = 0, # For overall progress
        [Parameter()][double]$TotalWeight = 1    # For overall progress
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    # Ctrl+C handling is managed by the main script's trap handler

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
                        if ($localCRC32 -ne $ExpectedCRC32) {
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
                        Update-PersistentToast -NewStatus "$($ActivityName): Using existing valid file." 
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
                            $headResponse = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -ErrorAction Stop -TimeoutSec 10 # Added timeout
                            
                            $contentLengthHeader = $headResponse.Headers.'Content-Length'
                            
                            if ($null -ne $contentLengthHeader) {
                                $contentLengthValue = $null
                                # Handle potential array value (take the first element)
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

                                # Try converting the determined value
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
                                     # This case handles if the header was an empty array
                                     Write-Log -Message "Could not determine a single value from Content-Length header." -Level WARN
                                     $totalBytes = -1
                                }
                            } else {
                                Write-Log -Message "HEAD request successful but did not return a Content-Length header." -Level WARN
                                $totalBytes = -1
                            }
                        } catch [System.Net.WebException] {
                            Write-Log -Message "HEAD request failed (WebException): $($_.Exception.Message). Status: $($_.Exception.Response.StatusCode | Out-String -Stream)" -Level WARN
                            $totalBytes = -1 # Ensure it's -1 on HEAD failure
                        } catch {
                            Write-Log -Message "HEAD request failed (General Exception): $($_.Exception.Message)." -Level WARN
                            $totalBytes = -1 # Ensure it's -1 on HEAD failure
                        }
                        
                        if ($totalBytes -le 0) {
                             Write-Log -Message "Could not determine file size via HEAD request. Progress calculations will be limited." -Level WARN
                             $totalBytes = -1 # Ensure it's exactly -1 if unknown
                        }
                    } # End of HEAD request block

                    # --- Invoke-WebRequest as Background Job ---
                    $downloadProgress = $null # Ensure variable is clean
                    $job = $null
                    $startTime = Get-Date
                    $lastBytes = 0
                    $lastTime = $startTime
                    $iwrSuccess = $false # Reset flag for this attempt
                    $downloadFileName = Split-Path -Path $DestinationPath -Leaf # Get filename for toast

                    # Helper to clear download data from toast global state
                    $clearDownloadToastData = {
                        Write-Log -Level Debug -Message "Clearing download-specific toast data."
                        $Global:PersistentToastData['DownloadFileName'] = ""
                        $Global:PersistentToastData['DownloadSpeed'] = ""
                        $Global:PersistentToastData['DownloadRemaining'] = ""
                        # Don't trigger an update here, let the calling context do it if needed
                    }

                    try {
                        Write-Log -Message "Starting download job via Invoke-WebRequest..." -Level INFO
                        $scriptBlock = {
                            param($Uri, $DestinationPath, $ProgressPreference, $JobLogPath) # Added JobLogPath parameter
                            
                            # --- Start Job Internal Logging ---
                            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                            # Use Out-File -Append for potentially better flushing
                            "[$Timestamp] JOB_START: Job started. DestinationPath = '$DestinationPath'" | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                            # --- End Job Internal Logging ---

                            # Set preference within the job scope
                            $ProgressPreference = 'SilentlyContinue' # Prevent default IWR progress bar inside job
                            
                            # --- Job Internal IWR Try/Catch ---
                            try {
                                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                                "[$Timestamp] JOB_IWR_START: Executing Invoke-WebRequest -Uri '$Uri' -OutFile '$DestinationPath'..." | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                                
                                # Restore -ProgressAction to enable detailed progress reporting
                                # Remove -ProgressAction as it causes file saving issues in job
                                Invoke-WebRequest -Uri $Uri -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
                                
                                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                                "[$Timestamp] JOB_IWR_SUCCESS: Invoke-WebRequest completed without throwing." | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                            } catch {
                                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                                # Try capturing error using $Error[0]
                                $ErrorMessage = $Error[0].ToString()
                                "[$Timestamp] JOB_IWR_ERROR: Invoke-WebRequest failed. Error: $ErrorMessage" | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                                # Re-throw the error so the job state becomes 'Failed' as expected
                                throw $_
                            }
                            # --- End Job Internal IWR Try/Catch ---

                            # --- Job Internal File Check ---
                            $FileExistsAfterIWR = Test-Path -LiteralPath $DestinationPath -PathType Leaf
                            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                            "[$Timestamp] JOB_FILE_CHECK: Test-Path '$DestinationPath' after IWR returned: $FileExistsAfterIWR" | Out-File -FilePath $JobLogPath -Append -Encoding UTF8 -NoNewline
                            # --- End Job Internal File Check ---
                            
                            # Note: Using $global:downloadProgress relies on the job running in the same process space or having access to it.
                            # A more robust method might involve job messaging, but this is simpler for now.
                        }
                        # Pass ProgressPreference explicitly if needed, otherwise rely on default/inherited
                        # Define unique job log path
                        $jobLogFileName = "JobLog_$(Get-Date -Format 'yyyyMMddHHmmssfff')_$($PID).log"
                        $jobLogPath = Join-Path -Path $env:TEMP -ChildPath $jobLogFileName
                        Write-Log -Message "Starting download job. Internal job log will be at: '$jobLogPath'" -Level DEBUG
                        
                        # Pass the log path to the job
                        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Url, $DestinationPath, $ProgressPreference, $jobLogPath -ErrorAction Stop

                        Write-Log -Message "Download job started (ID: $($job.Id)). Monitoring progress..." -Level DEBUG

                        # --- Progress Monitoring Loop ---
                        while ($job.State -eq 'Running') {
                            # Check for cancellation first
                            if ($script:cancelToken -ne $null -and $script:cancelToken.IsCancellationRequested) {
                                Write-Log -Message "$($ActivityName): Cancellation requested. Stopping download job." -Level WARN
                                Stop-Job -Job $job -ErrorAction SilentlyContinue
                                # Wait briefly for job to enter stopped state
                                Start-Sleep -Milliseconds 200
                                # No need to throw here, the job state check after loop will handle it
                                break # Exit monitoring loop
                            }
# --- Progress Calculation based on File Size ---
$currentBytes = 0
# Check if the destination file exists and get its size
if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
    try {
        # Use -Force to potentially get size even if file is being written to
        $fileItem = Get-Item -LiteralPath $DestinationPath -Force -ErrorAction Stop
        $currentBytes = $fileItem.Length
    } catch {
        # Log error getting file size but continue loop
        Write-Log -Message "Progress Loop: Error getting size of '$DestinationPath': $($_.Exception.Message)" -Level WARN
    }
} # else $currentBytes remains 0

# Use $totalBytes determined earlier (from HEAD or parameter)
$percentComplete = 0
if ($totalBytes -gt 0) {
    $percentComplete = [Math]::Min(100, [Math]::Floor(($currentBytes / $totalBytes) * 100))
}
# Removed fallback using $downloadProgress.TotalBytesToTransfer as $downloadProgress is no longer used

$currentTime = Get-Date
$elapsedTime = $currentTime - $startTime
$timeDeltaSeconds = ($currentTime - $lastTime).TotalSeconds
$bytesDelta = $currentBytes - $lastBytes

$speedBytesPerSec = 0
if ($timeDeltaSeconds -gt 0.1) { # Avoid division by zero or tiny intervals
    $speedBytesPerSec = $bytesDelta / $timeDeltaSeconds
}

$remainingBytes = -1
if ($totalBytes -gt 0) {
    $remainingBytes = $totalBytes - $currentBytes
    # Ensure remaining bytes isn't negative if file size check is slightly ahead
    if ($remainingBytes -lt 0) { $remainingBytes = 0 }
}

$remainingTimeSeconds = -1
if ($speedBytesPerSec -gt 0 -and $remainingBytes -ge 0) { # Check remainingBytes >= 0
    $remainingTimeSeconds = $remainingBytes / $speedBytesPerSec
}

# Formatting
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
     $remainingTimeFormatted = "Unknown" # If total size is unknown
}

# Format Size Progress (e.g., "145/507 MB")
$sizeProgressFormatted = "--/-- MB"
if ($totalBytes -gt 0) {
    $currentMB = $currentBytes / 1MB
    $totalMB = $totalBytes / 1MB
    $sizeProgressFormatted = "{0:N0}/{1:N0} MB" -f $currentMB, $totalMB
} elseif ($currentBytes -ge 0) {
    # Show only current if total is unknown
    $sizeProgressFormatted = "{0:N0} MB transferred" -f ($currentBytes / 1MB)
}

# Construct Status Message for Write-Progress (Console)
$statusMessage = if ($totalBytes -gt 0) {
    "{0}% ({1}) - Rem: {2} - Size: {3}" -f $percentComplete, $speedFormatted, $remainingTimeFormatted, $sizeProgressFormatted
} else {
    # Degraded status when total size is unknown
    "Downloading... ({0} transferred, {1})" -f (Format-Bytes $currentBytes), $speedFormatted
}

# Update Progress Bar (Console)
Write-Progress -Activity "Download: $($downloadFileName)" -Status $statusMessage -PercentComplete $percentComplete -CurrentOperation "Downloading..." -Id 2 # Explicitly set ID 2 and use filename in Activity

# Update for next iteration
$lastBytes = $currentBytes
$lastTime = $currentTime

# --- Update Toast Data ---
try {
    # Prepare parameters for Update-PersistentToast
    $toastUpdateParams = @{
        ProgressPercentage = $percentComplete
        DownloadFileName = $downloadFileName # Used for ProgressBarStatus text
        DownloadSpeed = $speedFormatted
        DownloadRemainingTime = $remainingTimeFormatted
        DownloadSizeProgress = $sizeProgressFormatted
        # Pass through step/download info received by this function
        StepNumber       = $StepNumber
        TotalSteps       = $TotalSteps
        StepName         = $StepName # Use the StepName passed to this function
        DownloadNumber   = $DownloadNumber
        TotalDownloads   = $TotalDownloads
        CurrentWeight    = $CurrentWeight # Pass through overall weight
        TotalWeight      = $TotalWeight
    }
    # Call Update-PersistentToast with detailed download info
    Update-PersistentToast @toastUpdateParams
} catch {
    Write-Log -Level Warn -Message "Failed to update toast during download progress: $($_.Exception.Message)"
}
# --- End Update Toast Data ---
# --- End Progress Calculation ---

Start-Sleep -Milliseconds 500 # Update interval
                        } # End while ($job.State -eq 'Running')

                        # --- Handle Job Completion ---
                        Write-Log -Message "Download job finished with state: $($job.State)" -Level DEBUG

                        if ($job.State -eq 'Completed') {
                            Receive-Job -Job $job -ErrorAction SilentlyContinue # Discard any output, just confirm completion
                            Write-Log -Message "$($ActivityName): Invoke-WebRequest job completed successfully." -Level INFO
                            $iwrSuccess = $true # Mark IWR as successful for verification step
                            try { Update-PersistentToast -NewStatus "$($ActivityName): Download Complete" } catch { Write-Log -Level Warn -Message "Failed to update toast (Download Complete): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed

                        } elseif ($job.State -eq 'Failed') {
                            $jobError = $job.ChildJobs[0].Error # Get the first error record
                            $errorMessage = "$($ActivityName): Download job failed: $($jobError.Exception.Message)"
                            Write-Log -Message $errorMessage -Level ERROR
                            try { Update-PersistentToast -NewStatus "$($ActivityName): FAILED (Job Error)"  } catch { Write-Log -Level Warn -Message "Failed to update toast (Job Error): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed
                            throw $jobError.Exception # Re-throw the underlying exception

                        } elseif ($job.State -eq 'Stopped') {
                            # This state is usually reached due to Stop-Job (likely from cancellation)
                            $errorMessage = "$($ActivityName): Download cancelled by user (Job Stopped)."
                            Write-Log -Message $errorMessage -Level WARN
                            try { Update-PersistentToast -NewStatus "$($ActivityName): Cancelled"  } catch { Write-Log -Level Warn -Message "Failed to update toast (Cancelled): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed
                            throw $errorMessage # Throw cancellation message

                        } else {
                            # Handle other potential states if necessary
                            $errorMessage = "$($ActivityName): Download job ended with unexpected state: $($job.State)."
                            Write-Log -Message $errorMessage -Level ERROR
                            try { Update-PersistentToast -NewStatus "$($ActivityName): FAILED (Unknown State)"  } catch { Write-Log -Level Warn -Message "Failed to update toast (Unknown State): $($_.Exception.Message)" }
                            Write-Progress -Activity $ActivityName -Completed
                            throw $errorMessage
                        }

                    } catch [System.Management.Automation.PipelineStoppedException] {
                        # This might still catch cancellation if it happens *before* the job starts or during job setup
                        $errorMessage = "$($ActivityName): Download cancelled by user (PipelineStoppedException)."
                        Write-Log -Message $errorMessage -Level WARN
                        try { Update-PersistentToast -NewStatus "$($ActivityName): Cancelled"  } catch { Write-Log -Level Warn -Message "Failed to update toast (Cancelled Pipeline): $($_.Exception.Message)" }
                        Write-Progress -Activity $ActivityName -Completed
                        throw $errorMessage # Re-throw cancellation
                    } catch {
                        # Catch any other errors during job start or monitoring setup
                        $errorMessage = "$($ActivityName): Download failed (General Error): $($_.Exception.Message)"
                        Write-Log -Message $errorMessage -Level ERROR
                        try { Update-PersistentToast -NewStatus "$($ActivityName): FAILED (Error)"  } catch { Write-Log -Level Warn -Message "Failed to update toast (General Error): $($_.Exception.Message)" }
                        Write-Progress -Activity $ActivityName -Completed
                        
                        # --- Retrieve Internal Job Log on Error ---
                        # Moved here from finally block to increase chance of capture before script halts
                        if (Test-Path $jobLogPath) {
                            Write-Log -Message "Retrieving internal job log content from '$jobLogPath' due to error..." -Level DEBUG
                            $jobLogContent = Get-Content -Path $jobLogPath -Raw -ErrorAction SilentlyContinue
                            if ($jobLogContent) {
                                Write-Log -Message "--- Start Internal Job Log (Error Path) ---`n$jobLogContent`n--- End Internal Job Log (Error Path) ---" -Level DEBUG
                            } else {
                                Write-Log -Message "Could not read internal job log content or file was empty (Error Path)." -Level WARN
                            }
                            # Optionally remove the temp log file
                            # Remove-Item -Path $jobLogPath -Force -ErrorAction SilentlyContinue
                        } else {
                            Write-Log -Message "Internal job log file '$jobLogPath' not found (Error Path)." -Level WARN
                        }
                        # --- End Retrieve Internal Job Log ---

                        throw $_ # Re-throw other errors
                    } finally {
                        # Ensure job is always removed
                        # Clear download-specific toast data regardless of job outcome
                        Invoke-Command $clearDownloadToastData

                        if ($job -ne $null) {
                            # Log retrieval moved to the catch block above
                            # Remove the job itself
                            Write-Log -Message "Removing job $($job.Id)..." -Level DEBUG
                            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        }
                        # Restore ProgressPreference just in case, although it's set in the job scope now
                        $ProgressPreference = 'Continue'
                    }
                    # --- End Invoke-WebRequest ---

                    # --- Post-Download Verification (only if IWR succeeded) ---
                    if ($iwrSuccess) {
                        Write-Log -Message "$($ActivityName): Download reported success. Verifying downloaded file (Attempt $attempt)..." -Level INFO
                        try { Update-PersistentToast -NewStatus "$($ActivityName): Verifying download..."  } catch { Write-Log -Level Warn -Message "Failed to update toast (Verifying): $($_.Exception.Message)" }
                        try {
                            Initialize-CRC32Type
                            if (-not (Test-Path $DestinationPath)) { throw "Downloaded file '$DestinationPath' missing." }
                            $downloadedFileItem = Get-Item $DestinationPath -ErrorAction Stop
                            $downloadedFileSize = $downloadedFileItem.Length
                            $sizeVerified = $true
                            $crcVerified = $true

                            if ($ExpectedFilesize -gt 0) {
                                if ($downloadedFileSize -ne $ExpectedFilesize) {
                                    $sizeVerified = $false
                                    Write-Log -Level ERROR -Message "$($ActivityName): Size mismatch ($downloadedFileSize vs $ExpectedFilesize)."
                                } else { Write-Log -Level DEBUG -Message "$($ActivityName): Size matches." }
                            } else { Write-Log -Level DEBUG -Message "$($ActivityName): Skipping size check." }

                            if ($sizeVerified -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) {
                                Write-Log -Level DEBUG -Message "$($ActivityName): Checking CRC32..."
                                $localCRC32 = Get-CRC32 -InputFile $DestinationPath
                                if ($localCRC32 -ne $ExpectedCRC32) {
                                    $crcVerified = $false
                                    Write-Log -Level ERROR -Message "$($ActivityName): CRC mismatch ($localCRC32 vs $ExpectedCRC32)."
                                } else { Write-Log -Level DEBUG -Message "$($ActivityName): CRC matches." }
                            } elseif (-not ([string]::IsNullOrWhiteSpace($ExpectedCRC32))) { Write-Log -Level DEBUG -Message "$($ActivityName): Size mismatch or CRC check skipped." }
                            else { Write-Log -Level DEBUG -Message "$($ActivityName): Skipping CRC verification." }

                            if ($sizeVerified -and $crcVerified) {
                                Write-Log -Message "$($ActivityName): Verification successful (Attempt $attempt)." -Level INFO
                                try { Update-PersistentToast -NewStatus "$($ActivityName): Download verified."  } catch { Write-Log -Level Warn -Message "Failed to update toast (Verified): $($_.Exception.Message)" }
                                $currentAttemptSuccess = $true # Mark this attempt as fully successful
                            } else {
                                if (-not $sizeVerified) { throw "Incorrect file size." }
                                if (-not $crcVerified) { throw "Incorrect checksum." }
                            }
                        } catch { # Catch verification errors
                            $errorMessage = "$($ActivityName): Verification failed for download attempt {0}: {1}" -f $attempt, $_.Exception.Message
                            Write-Log -Message $errorMessage -Level ERROR
                            try { Update-PersistentToast -NewStatus "$($ActivityName): Verification FAILED."  } catch { Write-Log -Level Warn -Message "Failed to update toast (Verification FAILED): $($_.Exception.Message)" }
                            if (Test-Path $DestinationPath) { Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue }
                            # Do not set $currentAttemptSuccess = true
                            throw $_ # Re-throw verification error to be caught by the outer attempt's catch block
                        }
                    } # End if ($iwrSuccess) for verification block

                } catch { # Catch block for the entire attempt (outer try)
                    # Log the error from IWR or Verification
                    Write-Log -Message "$($ActivityName): Download attempt $attempt failed: $($_.Exception.Message)" -Level ERROR
                    $attemptFailed = $true # Mark attempt as failed for retry logic

                    # Check if it was a cancellation error - if so, re-throw to exit loop entirely via main catch
                    if ($_.Exception.Message -match "Download cancelled by user") {
                        throw $_
                    }
                    # Otherwise, the error is logged, and the loop will continue to the retry logic below
                }
                # --- End Outer Try/Catch for the attempt ---


                # --- Retry / Success Logic ---
                if ($currentAttemptSuccess) {
                    # If download and verification succeeded, set overall success and exit the loop
                    $overallDownloadSuccess = $true
                    break
                } elseif ($attemptFailed -and $attempt -lt $totalAttempts) {
                    # If download or verification failed, and we haven't reached max attempts, wait and retry
                    Write-Log -Message "$($ActivityName): Download or verification failed on attempt $attempt. Waiting 5 seconds before retry..." -Level INFO
                    Start-Sleep -Seconds 5
                } elseif ($attemptFailed -and $attempt -ge $totalAttempts) {
                     # Max attempts reached after failure, throw final error (caught by main function's catch)
                     Write-Log -Message "$($ActivityName): Maximum download/verification attempts reached. Download failed." -Level ERROR
                     throw "$($ActivityName): Download and verification failed after $totalAttempts attempts."
                }
                # If $currentAttemptSuccess is false but $attemptFailed is also false (e.g., IWR succeeded but verification skipped/failed silently - shouldn't happen), loop continues.

            } # End For loop

            # After loop, check overall status
            if (-not $overallDownloadSuccess) {
                 # This path is taken if loop finished without break (i.e., max retries reached and failed)
                 # The actual error causing failure was already thrown inside the loop.
                 # We might need to return $false here if the throw doesn't exit the function.
                 Write-Log -Message "$($ActivityName): Download process did not complete successfully after all retries." -Level WARN
                 return $false # Explicitly return false if loop completes without success
            } else {
                # Loop was broken due to success
                return $true
            }

        } # End if ($needsDownload)
        else {
             # This case handles when $needsDownload was false initially (file existed and was valid)
             # Ensure download data is cleared if we didn't enter the download loop
             try { Invoke-Command $clearDownloadToastData } catch {} # Use try-catch as $clearDownloadToastData might not be defined if script errored early
             return $true
        }

    } # End main try block for the function
    catch {
        # Catch errors thrown from within the main try block (e.g., cancellation, max retries failed)
        Write-Log -Message "Error in Invoke-LoxoneDownload: $($_.Exception.Message)" -Level ERROR
        # Potentially update toast for final failure state if not already handled (e.g., cancellation)
        if ($_.Exception.Message -notmatch "Download cancelled by user") {
            try { Update-PersistentToast -NewStatus "$($ActivityName): FAILED - Check Logs"  } catch { Write-Log -Level Warn -Message "Failed to update toast (Main Catch): $($_.Exception.Message)" }
        }
        # Ensure progress bar is cleared on any function-level error exit
        try { Write-Progress -Activity $ActivityName -Completed -ErrorAction SilentlyContinue } catch {}
        # Do not re-throw; let the function return $false to indicate failure to the caller
        return $false
    } # End main catch block
    finally {
        # Final cleanup if needed (e.g., restore global settings)
        # Ensure ProgressPreference is restored if somehow an error bypassed the inner finally
        $ProgressPreference = 'Continue'
    } # End main finally block

} # End function Invoke-LoxoneDownload
#endregion Unified Download Function
 
#region Network Utilities
 
# Placeholder for Wait-ForPingTimeout function (assuming it exists or will be added)
function Wait-ForPingTimeout {
    param(
        [Parameter(Mandatory=$true)][string]$InputAddress,
        [Parameter()][int]$TimeoutSeconds = 180
    )
    Write-Log -Message "Simulating Wait-ForPingTimeout for $InputAddress (returning true after delay)" -Level DEBUG
    Start-Sleep -Seconds 2
    return $true # Placeholder
}
 
# Placeholder for Wait-ForPingSuccess function (assuming it exists or will be added)
function Wait-ForPingSuccess {
    param(
        [Parameter(Mandatory=$true)][string]$InputAddress,
        [Parameter()][int]$TimeoutSeconds = 600
    )
     Write-Log -Message "Simulating Wait-ForPingSuccess for $InputAddress (returning true after delay)" -Level DEBUG
    Start-Sleep -Seconds 3
    return $true # Placeholder
}
 
#endregion Network Utilities
 
Export-ModuleMember -Function Invoke-LoxoneDownload, Wait-ForPingTimeout, Wait-ForPingSuccess
