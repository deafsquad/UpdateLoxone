# Module for Loxone Update Script Logging Functions

# Check for test environment and skip initialization if in test mode
if ($env:PESTER_TEST_RUN -eq "1" -or $Global:IsTestRun -eq $true -or $env:LOXONE_TEST_MODE -eq "1") {
    Write-Verbose "Test mode detected - skipping logging initialization"
    # Create dummy variables to avoid errors
    $script:LogMutex = $null
    $script:CallStack = $null
} else {
    # Mutex for Log File Access - PID-based to allow multiple instances
    # Each process gets its own mutex for thread safety within that process
    # File locking will handle inter-process synchronization
    try {
        # Create a mutex unique to this process
        $mutexName = "UpdateLoxoneLogMutex_$PID"
        $script:LogMutex = New-Object System.Threading.Mutex($false, $mutexName)
        Write-Debug "Created process-specific mutex: $mutexName"
    } catch {
        # If named mutex fails, create a local one
        Write-Warning "Could not create named mutex. Using process-local mutex."
        $script:LogMutex = New-Object System.Threading.Mutex($false)
    }
    $script:CallStack = [System.Collections.Generic.Stack[object]]::new() # Corrected type to hold objects
}

#region Function Entry/Exit Logging

function Enter-Function {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FunctionName,
        [Parameter(Mandatory=$false)]
        [string]$FilePath,
        [Parameter(Mandatory=$false)]
        [int]$LineNumber
    )
    # Initialize CallStack if needed (for test scenarios)
    if ($null -eq $script:CallStack) {
        $script:CallStack = [System.Collections.Generic.Stack[object]]::new()
    }
    # Push function details onto the stack
    $stackFrame = @{ Name = $FunctionName; Path = $FilePath; Line = $LineNumber; StartTime = (Get-Date) }
    $script:CallStack.Push($stackFrame)
    # Construct log message
    $relativePath = $FilePath -replace [regex]::Escape($PSScriptRoot + '\'), '' -replace [regex]::Escape($PSScriptRoot + '/'), ''
    # Corrected variable expansion
    $logMessage = "--> Entering Function: $FunctionName (Source: ${relativePath}:${LineNumber})"
    Write-Log -Message $logMessage -Level Debug -SkipStackFrame # Skip stack frame here as we manually constructed it
}

function Exit-Function {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ResultMessage
    )
    # Initialize CallStack if needed (for test scenarios)
    if ($null -eq $script:CallStack) {
        $script:CallStack = [System.Collections.Generic.Stack[object]]::new()
    }
    if ($script:CallStack.Count -eq 0) {
        # Write-Log -Message "Exit-Function called but CallStack is empty." -Level Warn -SkipStackFrame # Avoid logging if Write-Log itself fails
        return
    }
    # Pop the current function details from the stack
    $stackFrame = $script:CallStack.Pop()
    $functionName = $stackFrame.Name
    $startTime = $stackFrame.StartTime
    $duration = (Get-Date) - $startTime
    # Construct log message
    $logMessage = "<-- Exiting Function: $functionName (Duration: $($duration.TotalSeconds.ToString('F3'))s)"
    if (-not [string]::IsNullOrWhiteSpace($ResultMessage)) {
        $logMessage += " | Result: $ResultMessage"
    }
    Write-Log -Message $logMessage -Level Debug -SkipStackFrame # Skip stack frame here
}

#endregion Function Entry/Exit Logging

#region Main Logging Function

# Define valid log levels using ValidateSet
[System.Collections.Generic.List[string]]$ValidLogLevels = @('INFO', 'DEBUG', 'WARN', 'ERROR')

function Write-Log {
    [CmdletBinding(SupportsShouldProcess=$false, PositionalBinding=$false)] # Add PositionalBinding=$false
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Message,

        [Parameter(Mandatory=$false, Position=1)]
        [ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')] # Enforce valid levels
        [string]$Level = 'INFO',

        [Parameter(Mandatory=$false)]
        [switch]$SkipStackFrame, # Switch to skip adding stack frame info

        [Parameter(ValueFromRemainingArguments=$true)]
        [object[]]$RemainingArguments # Catchall for any unbound parameters
    )

    # --- Input Validation ---
    if ([string]::IsNullOrWhiteSpace($Message)) {
        Write-Warning "Write-Log: Message parameter cannot be empty." # Use Write-Warning for internal issues
        return
    }
    if (-not $ValidLogLevels.Contains($Level.ToUpper())) {
         Write-Warning "Write-Log: Invalid log level '$Level'. Defaulting to INFO."
         $Level = 'INFO'
    }

    # --- Debug Mode Check ---
    # Use $Global:DebugPreference set by -Debug switch or script default
    if ($Level -eq 'DEBUG' -and $Global:DebugPreference -ne 'Continue') {
        return # Skip DEBUG messages if not in debug mode
    }

    # --- Construct Log Entry ---
    $timestamp = Get-Date -Format 'yyMMdd HH:mm:ss.fff'
    $processId = $PID
    $userName = $env:USERNAME
    $computerName = $env:COMPUTERNAME
    $execContext = "[${processId}:${userName}:${computerName}]"

    # --- Get Caller Information (Optional) ---
    $callerInfo = ""
    if (-not $SkipStackFrame.IsPresent) {
        try {
            # Get the call stack, skip Write-Log itself (index 1), and potentially the Enter/Exit function (index 2)
            # Get the call stack
            $callStack = Get-PSCallStack
            $caller = $null
            $callerIndex = 1 # Start by checking the immediate caller

            # Try caller at index 1
            if ($callStack.Count -gt $callerIndex) {
                $potentialCaller = $callStack[$callerIndex]
                # Check if this frame has script location info
                if ($potentialCaller -and -not ([string]::IsNullOrWhiteSpace($potentialCaller.ScriptName))) {
                    $caller = $potentialCaller
                }
            }

            # If caller at index 1 lacked location, try index 2 (might be the case in catch blocks)
            if (-not $caller) {
                $callerIndex = 2
                if ($callStack.Count -gt $callerIndex) {
                    $potentialCaller = $callStack[$callerIndex]
                    if ($potentialCaller -and -not ([string]::IsNullOrWhiteSpace($potentialCaller.ScriptName))) {
                        $caller = $potentialCaller
                    }
                }
            }

            # Format caller info if found
            if ($caller) {
                $callerScriptName = $caller.ScriptName # Keep full path initially
                $callerLineNumber = $caller.ScriptLineNumber
                $callerFunctionName = $caller.FunctionName

                # Try to get relative path if possible
                $relativePath = $callerScriptName
                try {
                    # Ensure $PSScriptRoot is available in this scope (it should be for a module)
                    if ($PSScriptRoot -and $relativePath.StartsWith($PSScriptRoot)) {
                         $relativePath = $relativePath.Substring($PSScriptRoot.Length).TrimStart('\/')
                    } elseif ($PSScriptRoot) {
                        # If not starting with PSScriptRoot, just use the leaf name
                        $relativePath = Split-Path -Path $callerScriptName -Leaf
                    } else {
                         # Fallback if PSScriptRoot isn't defined
                         $relativePath = Split-Path -Path $callerScriptName -Leaf
                    }
                } catch { $relativePath = Split-Path -Path $callerScriptName -Leaf } # Fallback on error

                $callerInfo = "[${relativePath}:${callerLineNumber}"
                # Add function name if it's not the top-level script or a simple block
                if ($callerFunctionName -and $callerFunctionName -ne '<ScriptBlock>' -and $callerFunctionName -ne $MyInvocation.MyCommand.Name) {
                     $callerInfo += " $callerFunctionName"
                }
                 $callerInfo += "]"
            } else {
                $callerInfo = "[Unknown Location]" # Fallback if no suitable caller found
            }
        } catch { # Catch for the outer try block (started line 101)
            $callerInfo = "[Error getting caller info]"
        }
    }

    # --- Format Final Message ---
    $logEntry = "[$timestamp] $execContext [$Level] $callerInfo $Message" # Use $execContext

    # --- Write to Console Streams (for redirection) ---
    # Write all levels if in debug mode, otherwise only WARN/ERROR
    # Write DEBUG, WARN, ERROR to their respective streams.
    # Write INFO directly to host ONLY if not in debug mode, otherwise suppress it
    # (as it will be written to the file anyway).
    switch ($Level.ToUpper()) {
        'DEBUG' { Write-Debug $logEntry } # Only shows if $DebugPreference = 'Continue'
        'WARN'  { Write-Warning $logEntry } # Shows unless $WarningPreference = 'SilentlyContinue'
        'ERROR' { Write-Error $logEntry -ErrorAction Continue } # Shows unless $ErrorActionPreference = 'SilentlyContinue'
        'INFO'  {
            # Force INFO to console only when NOT debugging, otherwise it's just noise.
            if ($Global:DebugPreference -ne 'Continue') {
                Write-Host $logEntry
            }
            # INFO messages are always written to the file regardless of console visibility.
        }
        # No default needed as levels are validated
    }
    # --- Write to File (with Mutex) ---
    if (-not $Global:LogFile) {
        Write-Warning "Global:LogFile variable not set. Cannot write to log file."
        return
    }

    $mutexAcquired = $false
    $retryCount = 0
    $maxRetries = 3
    
    try {
        while ($retryCount -lt $maxRetries -and -not $mutexAcquired) {
            try {
                # Try to acquire mutex with shorter timeout
                $mutexAcquired = $script:LogMutex.WaitOne(1000) # 1 second timeout
                if ($mutexAcquired) {
                    # Use file locking for inter-process synchronization
                    $fileWritten = $false
                    $fileRetries = 0
                    while (-not $fileWritten -and $fileRetries -lt 3) {
                        try {
                            # Open file with exclusive lock for append
                            $fileStream = [System.IO.FileStream]::new($Global:LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                            $writer = [System.IO.StreamWriter]::new($fileStream, [System.Text.Encoding]::UTF8)
                            $writer.WriteLine($logEntry)
                            $writer.Flush()
                            $writer.Close()
                            $fileStream.Close()
                            $fileWritten = $true
                        } catch [System.IO.IOException] {
                            # File is locked by another process
                            $fileRetries++
                            if ($fileRetries -lt 3) {
                                Start-Sleep -Milliseconds 50
                            }
                        } catch {
                            # Other errors
                            throw
                        }
                    }
                    if (-not $fileWritten) {
                        # Fall back to Out-File if file locking fails
                        $logEntry | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Append -ErrorAction Stop
                    }
                    break
                } else {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        # Brief pause before retry
                        Start-Sleep -Milliseconds 100
                    }
                }
            } catch [System.Threading.AbandonedMutexException] {
                # This shouldn't happen with PID-based mutex, but handle it anyway
                $mutexAcquired = $true
                try {
                    # Use the same file locking approach
                    $fileStream = [System.IO.FileStream]::new($Global:LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                    $writer = [System.IO.StreamWriter]::new($fileStream, [System.Text.Encoding]::UTF8)
                    $writer.WriteLine($logEntry)
                    $writer.Flush()
                    $writer.Close()
                    $fileStream.Close()
                } catch {
                    # Fall back to Out-File
                    $logEntry | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Append -ErrorAction Stop
                }
                Write-Warning "Write-Log: Recovered from abandoned mutex."
                break
            }
        }
        
        if (-not $mutexAcquired) {
            Write-Warning "Write-Log: Timed out waiting for log file mutex after $maxRetries retries. Log entry skipped: $logEntry"
        }
    } catch {
        # Avoid calling Write-Log within catch of Write-Log to prevent recursion on error
        Write-Warning "Write-Log: Error writing to log file '$Global:LogFile'. Error: $($_.Exception.Message). Log entry skipped: $logEntry"
    } finally {
        if ($mutexAcquired) {
            $script:LogMutex.ReleaseMutex()
        }
    }
}

#endregion Main Logging Function

#region Log File Rotation

function Invoke-LogFileRotation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogFilePath,

        [Parameter(Mandatory=$false)]
        [int]$MaxArchiveCount = 10, # Default number of archives to keep

        [Parameter(Mandatory=$false)]
        [long]$MaxSizeKB = 10240, # Default max size 10MB before rotation
        
        [Parameter(Mandatory=$false)]
        [int]$MaxAgeDays = 7 # Default to keep logs for 7 days
    )
    # Do not call Enter-Function here to avoid recursive logging if Write-Log fails

    $logFileName = Split-Path -Path $LogFilePath -Leaf
    $logDir = Split-Path -Path $LogFilePath -Parent
    Write-Log -Level INFO -Message "Starting log rotation check for '$logFileName'."

    $mutexAcquired = $false
    try {
        # Acquire Mutex at the beginning
        $mutexAcquired = $script:LogMutex.WaitOne(10000) # Wait longer for rotation
        if (-not $mutexAcquired) {
            Write-Log -Level WARN -Message "Invoke-LogFileRotation: Could not acquire mutex. Skipping rotation for '$logFileName'."
            return $null # Return null if mutex fails
        }

        # Perform all file operations within the mutex lock
        if (-not (Test-Path -LiteralPath $LogFilePath -PathType Leaf)) {
            Write-Log -Level DEBUG -Message "Log file '$logFileName' does not exist. No rotation needed."
            return $null # Return null if log file doesn't exist
        }

        # Rotation logic - if file already has timestamp, just move it; otherwise add timestamp
        Write-Log -Level INFO -Message "Log file '$logFileName' exists. Rotating..."
        
        $baseLogFileName = [System.IO.Path]::GetFileNameWithoutExtension($logFileName)
        $logExtension = [System.IO.Path]::GetExtension($logFileName)
        
        # Check if the file already has a timestamp
        if ($baseLogFileName -match '_\d{8}_\d{6}$') {
            # File already has timestamp, use it as-is for the archive
            $archiveName = $logFileName
            Write-Log -Level DEBUG -Message "Log file already has timestamp, keeping original name for archive: '$archiveName'"
        } else {
            # No timestamp, add one for the archive
            $rotationTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $archiveName = "${baseLogFileName}_${rotationTimestamp}${logExtension}"
            Write-Log -Level DEBUG -Message "Adding timestamp to archive: '$archiveName'"
        }
        
        $archivePath = Join-Path -Path $logDir -ChildPath $archiveName

        $renameSuccess = $false # Initialize rename success flag

        # Pre-check for existing recent archive to handle rapid re-execution
        if (Test-Path -LiteralPath $archivePath) {
            $existingArchive = Get-Item -LiteralPath $archivePath -ErrorAction SilentlyContinue
            if ($existingArchive) {
                $timeSinceCreation = (Get-Date) - $existingArchive.CreationTime
                $timeSinceWrite = (Get-Date) - $existingArchive.LastWriteTime
                
                if ($timeSinceCreation.TotalSeconds -lt 5 -or $timeSinceWrite.TotalSeconds -lt 5) {
                    Write-Log -Level INFO -Message "Target archive '$archiveName' already exists and was modified recently (Created: $($existingArchive.CreationTime), Written: $($existingArchive.LastWriteTime)). Assuming rotation for '$logFileName' already completed."
                    $renameSuccess = $true
                } else {
                    Write-Log -Level INFO -Message "Target archive '$archiveName' already exists but is older (Created: $($existingArchive.CreationTime), Written: $($existingArchive.LastWriteTime)). Normal rename attempt for '$logFileName' will proceed."
                }
            }
        }

        if (-not $renameSuccess) {
            $retryCount = 0
            $maxRetries = 3
            while ($retryCount -lt $maxRetries -and -not $renameSuccess) {
                $retryCount++
                Write-Log -Level INFO -Message "Attempt ${retryCount}: Renaming '$logFileName' to '$archiveName'"
                try {
                    Rename-Item -LiteralPath $LogFilePath -NewName $archiveName -ErrorAction Stop
                    Write-Log -Level INFO -Message "Attempt ${retryCount}: Successfully renamed log file '$logFileName' to '$archiveName'."
                    $renameSuccess = $true
                } catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log -Level WARN -Message "Invoke-LogFileRotation: Attempt ${retryCount}: Failed to rename log file '$logFileName'. Error: $errorMessage"
                    if ($errorMessage -match "Cannot create a file when that file already exists") {
                        Write-Log -Level WARN -Message "Rename of '$logFileName' failed because target '$archiveName' now exists. This might be due to concurrent rotation."
                    }
                    if ($retryCount -lt $maxRetries) {
                        Write-Log -Level INFO -Message "Retrying rename of '$logFileName' in 1 second..."
                        Start-Sleep -Seconds 1
                    }
                }
            }
        }

        if (-not $renameSuccess) {
             Write-Log -Level ERROR -Message "Invoke-LogFileRotation: Failed to rotate log file '$logFileName' to '$archiveName' after $maxRetries attempts."
             if (-not (Test-Path -LiteralPath $LogFilePath) -and (Test-Path -LiteralPath $archivePath)) {
                 Write-Log -Level INFO -Message "Original log '$LogFilePath' is gone and archive '$archivePath' exists. Rotation for '$logFileName' likely succeeded despite earlier errors."
             } else {
                Write-Log -Level ERROR -Message "Rotation of '$LogFilePath' to '$archivePath' definitively failed."
             }
             return $null
        }
        
        # --- Cleanup Old Archives ---
        Write-Log -Level INFO -Message "Starting cleanup of old archives in '$logDir' for series related to '$logFileName' (Max kept: $MaxArchiveCount)."
        try {
            # Extract the prefix (everything before the timestamp) for grouping
            $seriesPrefixForCleanup = ""
            if ($logFileName -match '^(.+?)(_\d{8}_\d{6}.*)?\.(log|txt)$') {
                # Get everything before the first timestamp (or the whole name if no timestamp)
                $seriesPrefixForCleanup = $matches[1]
                if (-not $seriesPrefixForCleanup.EndsWith("_")) { 
                    $seriesPrefixForCleanup += "_" 
                }
                Write-Log -Level DEBUG -Message "Determined series prefix: '$seriesPrefixForCleanup'"
            } else {
                # Fallback for unusual filenames
                $seriesPrefixForCleanup = ($logFileName.Split('_')[0])
                if (-not $seriesPrefixForCleanup.EndsWith("_")) { 
                    $seriesPrefixForCleanup += "_" 
                }
                Write-Log -Level WARN -Message "Could not parse log filename '$logFileName', using fallback prefix: '$seriesPrefixForCleanup'"
            }

            # Simple pattern: match any file that starts with our prefix and has a timestamp
            $escapedSeriesPrefix = [regex]::Escape($seriesPrefixForCleanup)
            $escapedLogExtension = [regex]::Escape($logExtension)
            # This will match both old double-timestamp files and new single-timestamp files
            $archivePatternRegex = "^${escapedSeriesPrefix}.*\d{8}_\d{6}.*${escapedLogExtension}$"

            Write-Log -Level DEBUG -Message "Cleanup: seriesPrefixForCleanup='$seriesPrefixForCleanup', archivePatternRegex='$archivePatternRegex', logExtension='$logExtension'"

            $allPotentialArchives = Get-ChildItem -Path $logDir -Filter "${seriesPrefixForCleanup}*${logExtension}" -File -ErrorAction SilentlyContinue
            Write-Log -Level DEBUG -Message "Found $($allPotentialArchives.Count) potential archives with filter '${seriesPrefixForCleanup}*${logExtension}'."

            $archivesToDelete = $allPotentialArchives |
                                Where-Object { $_.Name -match $archivePatternRegex } |
                                Sort-Object CreationTime |
                                Select-Object -SkipLast $MaxArchiveCount
            
            Write-Log -Level DEBUG -Message "After regex filter and sorting, $($archivesToDelete.Count) archives selected for deletion."
            
            # Also check for age-based cleanup
            if ($MaxAgeDays -gt 0) {
                $cutoffDate = (Get-Date).AddDays(-$MaxAgeDays)
                $oldArchives = $allPotentialArchives |
                               Where-Object { $_.Name -match $archivePatternRegex -and $_.LastWriteTime -lt $cutoffDate }
                
                if ($oldArchives.Count -gt 0) {
                    Write-Log -Level INFO -Message "Found $($oldArchives.Count) archives older than $MaxAgeDays days for deletion."
                    $archivesToDelete = @($archivesToDelete) + @($oldArchives) | Select-Object -Unique
                }
            }

            $deletedCount = 0
            foreach ($archive in $archivesToDelete) {
                Write-Log -Level DEBUG -Message "Deleting old archive: $($archive.FullName)"
                try {
                    Remove-Item -LiteralPath $archive.FullName -Force -ErrorAction Stop
                    $deletedCount++
                } catch {
                    Write-Log -Level WARN -Message "Invoke-LogFileRotation: Error deleting archive '$($archive.FullName)': $($_.Exception.Message)"
                }
            }
            Write-Log -Level INFO -Message "Log rotation and cleanup finished for series related to '$logFileName'. $deletedCount archive(s) deleted."
        } catch {
             Write-Log -Level WARN -Message "Invoke-LogFileRotation: Error during archive cleanup for '$logFileName': $($_.Exception.Message)"
        }
        # --- End Cleanup ---
        
        Write-Log -Level DEBUG -Message "Invoke-LogFileRotation for '$logFileName' returning archive path: $archivePath"
        return $archivePath

    } catch {
        Write-Log -Level ERROR -Message "Invoke-LogFileRotation: An unhandled error occurred during log rotation for '$LogFilePath': $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Full error record for Invoke-LogFileRotation: ($($_ | Out-String))"
    } finally {
        if ($mutexAcquired) {
            $script:LogMutex.ReleaseMutex()
            Write-Log -Level DEBUG -Message "Log rotation mutex released for '$logFileName'."
        }
    }
}

#endregion Log File Rotation

#region Module Cleanup

# Cleanup function to properly release mutex
function Clear-LoggingResources {
    [CmdletBinding()]
    param()
    
    if ($script:LogMutex) {
        try {
            # Try to release if we own it
            $script:LogMutex.ReleaseMutex()
        } catch {
            # Ignore errors - we might not own it
        }
        try {
            $script:LogMutex.Dispose()
        } catch {
            # Ignore disposal errors
        }
        $script:LogMutex = $null
    }
}

# Register cleanup on module removal
$ExecutionContext.SessionState.Module.OnRemove = {
    Clear-LoggingResources
}

#endregion Module Cleanup

# Ensure functions are available
Export-ModuleMember -Function Write-Log, Enter-Function, Exit-Function, Invoke-LogFileRotation, Clear-LoggingResources