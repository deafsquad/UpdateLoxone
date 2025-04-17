# Module for Loxone Update Script Logging Functions

# Mutex for Log File Access (Local only now)
$script:LogMutex = New-Object System.Threading.Mutex($false, 'UpdateLoxoneLogMutex')
$script:CallStack = [System.Collections.Generic.Stack[object]]::new() # Corrected type to hold objects

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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')] # Enforce valid levels
        [string]$Level = 'INFO',

        [Parameter(Mandatory=$false)]
        [switch]$SkipStackFrame # Switch to skip adding stack frame info
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
    try {
        # Wait up to 5 seconds for the mutex
        $mutexAcquired = $script:LogMutex.WaitOne(5000)
        if ($mutexAcquired) {
            # Use Out-File -Append which might be more robust with file locking
            $logEntry | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Append -ErrorAction Stop
        } else {
            Write-Warning "Write-Log: Timed out waiting for log file mutex. Log entry skipped: $logEntry"
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
        [long]$MaxSizeKB = 10240 # Default max size 10MB before rotation
    )
    # Do not call Enter-Function here to avoid recursive logging if Write-Log fails

    $logFileName = Split-Path -Path $LogFilePath -Leaf
    $logDir = Split-Path -Path $LogFilePath -Parent
    # Use Write-Host for initial message to avoid log lock issues during rotation start
    Write-Host "INFO: Starting log rotation check for '$logFileName'." -ForegroundColor Cyan

    $mutexAcquired = $false
    try {
        # Acquire Mutex at the beginning
        $mutexAcquired = $script:LogMutex.WaitOne(10000) # Wait longer for rotation
        if (-not $mutexAcquired) {
            Write-Warning "Invoke-LogFileRotation: Could not acquire mutex. Skipping rotation."
            return $null # Return null if mutex fails
        }

        # Perform all file operations within the mutex lock
        if (-not (Test-Path -LiteralPath $LogFilePath -PathType Leaf)) {
            Write-Log -Level DEBUG -Message "Log file '$logFileName' does not exist. No rotation needed."
            return $null # Return null if log file doesn't exist
        }

        # Rotation logic moved outside the size check - runs every time if file exists
        Write-Host "INFO: Log file exists. Rotating..." -ForegroundColor Cyan
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $archiveName = "$($logFileName -replace '\.[^.]+$','_')_$timestamp$([System.IO.Path]::GetExtension($logFileName))" # Insert timestamp before extension
        $archivePath = Join-Path -Path $logDir -ChildPath $archiveName

        $retryCount = 0
        $maxRetries = 3
        $renameSuccess = $false
        while ($retryCount -lt $maxRetries -and -not $renameSuccess) {
            $retryCount++
            # Corrected variable expansion
            Write-Host "INFO: Attempt ${retryCount}: Renaming $logFileName > $archiveName" -ForegroundColor Cyan
            try {
                # Ensure file is closed before renaming - Add-Content/Out-File should do this, but maybe explicitly?
                # No direct way to close Add-Content/Out-File handle easily. Relying on OS.
                Rename-Item -LiteralPath $LogFilePath -NewName $archiveName -ErrorAction Stop
                # Corrected variable expansion
                Write-Host "INFO: Attempt ${retryCount}: Successfully renamed log file to '$archiveName'." -ForegroundColor Cyan
                $renameSuccess = $true
            } catch {
                # Corrected variable expansion
                Write-Warning "Invoke-LogFileRotation: Attempt ${retryCount}: Failed to rename log file. Error: $($_.Exception.Message). Retrying in 1 second..."
                Start-Sleep -Seconds 1
            }
        }

        if (-not $renameSuccess) {
             Write-Warning "Invoke-LogFileRotation: Failed to rotate log file '$logFileName' after $maxRetries attempts."
             return $null # Return null if rename fails
        }

        # --- Cleanup Old Archives ---
        Write-Host "INFO: Starting cleanup of old archives in '$logDir' (Max: $MaxArchiveCount)." -ForegroundColor Cyan
        try {
            $baseName = $logFileName -replace '\.[^.]+$','_' # Base name for archive matching
            $extension = [System.IO.Path]::GetExtension($logFileName)
            # Get archives, sort by creation time (oldest first), skip the newest $MaxArchiveCount
            $archivesToDelete = Get-ChildItem -Path $logDir -Filter "$baseName*$extension" |
                                Where-Object { $_.Name -match "$baseName\d{8}_\d{6}$extension" } | # Ensure it matches the timestamp pattern
                                Sort-Object CreationTime |
                                Select-Object -SkipLast $MaxArchiveCount

            $deletedCount = 0
            foreach ($archive in $archivesToDelete) {
                Write-Log -Level DEBUG -Message "Deleting old archive: $($archive.Name)"
                try {
                    Remove-Item -LiteralPath $archive.FullName -Force -ErrorAction Stop
                    $deletedCount++
                } catch {
                    Write-Warning "Invoke-LogFileRotation: Error deleting archive '$($archive.Name)': $($_.Exception.Message)"
                }
            }
            Write-Host "INFO: Log rotation and cleanup finished for '$logFileName'." -ForegroundColor Cyan
            if ($deletedCount -gt 0) {
                Write-Host "INFO: $deletedCount deleted [$($archivesToDelete.Name -join ';')]" -ForegroundColor Cyan
            }
        } catch {
             Write-Warning "Invoke-LogFileRotation: Error during archive cleanup: $($_.Exception.Message)"
        }
        # --- End Cleanup ---
        # Removed the 'else' block for size check

        # Return the path of the created archive
        Write-Log -Level DEBUG -Message "Invoke-LogFileRotation returning archive path: $archivePath"
        return $archivePath

    } catch {
        # Use Write-Host/Warning here as Write-Log might be the source of the problem
        Write-Warning "Invoke-LogFileRotation: An error occurred during log rotation: $($_.Exception.Message)"
    } finally {
        # Release Mutex at the very end
        if ($mutexAcquired) {
            $script:LogMutex.ReleaseMutex()
            Write-Log -Level DEBUG -Message "Log rotation mutex released."
        }
        # Do not call Exit-Function here
    }
}

#endregion Log File Rotation

# Ensure functions are available
Export-ModuleMember -Function Write-Log, Enter-Function, Exit-Function, Invoke-LogFileRotation