# Module for Loxone Update Script System/Process/Task Functions

#region Process and Task Helpers
function Get-ProcessStatus {
    param(
        # The name of the process to check (without .exe).
        [Parameter(Mandatory = $true)] [string]$ProcessName,
        # If specified, attempt to stop the process if found.
        [switch]$StopProcess
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try { # Outer try
        try { # Inner try (Original logic)
            $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
            if ($processes) {
                Write-Log -Message "Process '${ProcessName}' is running." -Level INFO
                if ($StopProcess) {
                    foreach ($proc in $processes) {
                        try { # Innermost try (Original logic)
                            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                            Write-Log -Message "Process '${ProcessName}' (PID: $($proc.Id)) stopped." -Level INFO
                        }
                        catch { # Innermost catch (Modified)
                            # Log the error but don't re-throw, allowing the loop to continue
                            Write-Log -Message "Error attempting to stop process '${ProcessName}' (PID: $($proc.Id)): ${($_.Exception.Message)}. It might have already exited." -Level WARN
                        }
                    }
                }
                return $true
            }
            else {
                Write-Log -Message "Process '${ProcessName}' is not running." -Level INFO
                return $false
            }
        } # End of Inner try
        catch { # Catch for Inner try (Original logic)
            Write-Log -Message "Error checking process '${ProcessName}': ${($_.Exception.Message)}" -Level ERROR
            throw $_
        } # End of Inner catch
    } finally { # End of Outer try # Finally for Outer try
        Exit-Function
    } # End of Outer finally
}

function Test-ScheduledTask {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Executing Test-ScheduledTask function from module." -Level DEBUG # Adjusted log message
    # Removed outer try/catch, inner try/catch removed to allow errors to propagate
    try {
        # Performance optimization: Use Get-Process instead of Get-CimInstance for speed
        try {
            $currentProcess = Get-Process -Id $PID -ErrorAction Stop
            $parentProcessId = $currentProcess.Parent.Id
            $parentProcess = Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue
            $parentProcessName = if ($parentProcess) { $parentProcess.Name } else { "Unknown" }
            Write-Log -Message "Parent process for PID $PID is ${parentProcessName} (PID: ${parentProcessId})" -Level DEBUG
            if ($parentProcessName.Trim() -ieq "taskeng" -or $parentProcessName.Trim() -ieq "svchost") { return $true } else { return $false }
        } catch {
            # Fallback to slower CIM query only if Get-Process fails
            Write-Log -Message "Get-Process failed, falling back to CIM query: $($_.Exception.Message)" -Level DEBUG
            $parentProcessId = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId
            $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId"
            $parentProcessName = $parentProcess.Name
            Write-Log -Message "Parent process (CIM) for PID $PID is ${parentProcessName} (PID: ${parentProcessId})" -Level DEBUG
            if ($parentProcessName.Trim() -ieq "taskeng.exe" -or $parentProcessName.Trim() -ieq "svchost.exe") { return $true } else { return $false }
        }
    } finally {
        Exit-Function
    }
}

#region Test-LoxoneScheduledTaskExists Function
function Test-LoxoneScheduledTaskExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Checking existence for task '$TaskName'..." -Level DEBUG
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        $exists = ($null -ne $task)
        if ($exists) {
            Write-Log -Message "Task '$TaskName' found." -Level DEBUG
        } else {
            Write-Log -Message "Task '$TaskName' not found." -Level DEBUG
        }
        return $exists
    } catch {
        Write-Log -Message "Error checking scheduled task '$TaskName': $($_.Exception.Message)" -Level ERROR
        # In case of error (e.g., permissions), assume it doesn't exist or is inaccessible
        Write-Log -Message "Assuming task '$TaskName' does not exist due to error." -Level WARN
        return $false
    } finally {
        Exit-Function
    }
}
#endregion Test-LoxoneScheduledTaskExists Function


function Start-ProcessInteractive {
    param(
        # The path to the executable to start.
        [Parameter(Mandatory = $true)][string]$FilePath,
        # Optional arguments to pass to the executable.
        [string]$Arguments = ""
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $shell = New-Object -ComObject "Shell.Application"
        # ShellExecute returns void, not a process object
        $shell.ShellExecute($FilePath, $Arguments, "", "open", 1)
        # Note: We cannot wait for the process since ShellExecute doesn't return a process ID
        Write-Log -Message "Launched process interactively: $FilePath $Arguments" -Level INFO
    }
    catch {
        throw "Failed to launch process interactively: ${($_.Exception.Message)}"
    } finally {
        Exit-Function
    }
}

#endregion Process and Task Helpers

#region Register-ScheduledTaskForScript Function
function Register-ScheduledTaskForScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$ScriptPath,
        [Parameter(Mandatory = $true)] [string]$TaskName,
        [Parameter()] [int]$ScheduledTaskIntervalMinutes = 10,
        [Parameter()] [string]$Channel = "Test",
        [Parameter()] [bool]$DebugMode = $false,
        [Parameter()] [bool]$EnableCRC = $true,
        [Parameter()] [string]$InstallMode = "verysilent",
        [Parameter()] [bool]$CloseApplications = $false,
        [Parameter()] [string]$ScriptSaveFolder = "$env:USERPROFILE\Scripts",
        [Parameter()] [int]$MaxLogFileSizeMB = 1,
        [Parameter()] [bool]$SkipUpdateIfAnyProcessIsRunning = $false
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Register-ScheduledTaskForScript called. Received -DebugMode parameter value: $DebugMode" -Level DEBUG
    try {
        # Check if task exists using the dedicated function
Write-Log -Message "DEBUG (Elevated): Checking task existence using Test-LoxoneScheduledTaskExists for '$TaskName'." -Level DEBUG
$taskActuallyExists = Test-LoxoneScheduledTaskExists -TaskName $TaskName
Write-Log -Message "DEBUG (Elevated): Test-LoxoneScheduledTaskExists returned: $taskActuallyExists" -Level DEBUG

# Check if task exists and if its configuration matches the desired state.
$needsUpdate = $true # Assume update is needed unless proven otherwise
if ($taskActuallyExists) {
    # Retrieve the task object *only if* it exists, for configuration check
    $taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue # Keep this to get the object for config check
    Write-Log -Message "Scheduled task '${TaskName}' found (elevated check). Checking configuration..." -Level INFO
        Write-Log -Message "Scheduled task '${TaskName}' found (elevated check). Checking configuration..." -Level INFO
        try {
            $existingAction = $taskExists.Actions | Where-Object { $_.Execute -match 'powershell.exe' } | Select-Object -First 1
            $existingTrigger = $taskExists.Triggers | Where-Object { $_.Repetition.Interval -ne $null } | Select-Object -First 1

            if ($existingAction -and $existingTrigger) {
                # Extract existing script path from arguments
                $existingArgs = $existingAction.Arguments
                $existingPath = $null
                if ($existingArgs -match '-File\s+"([^"]+)"') { # Match quoted path
                    $existingPath = $matches[1]
                } elseif ($existingArgs -match '-File\s+([^\s]+)') { # Match unquoted path
                    $existingPath = $matches[1]
                }

                # Extract existing interval in minutes
                $existingIntervalMinutes = $null
                try {
                    $intervalTimeSpan = [System.Xml.XmlConvert]::ToTimeSpan($existingTrigger.Repetition.Interval)
                    $existingIntervalMinutes = [int]$intervalTimeSpan.TotalMinutes
                } catch {
                    Write-Log -Message "Could not parse existing trigger interval '$($existingTrigger.Repetition.Interval)': $($_.Exception.Message)" -Level WARN
                }

                # --- Detailed Logging for Comparison ---
                Write-Log -Message "Comparing Task Config:" -Level DEBUG
                Write-Log -Message "  -> Existing Path: '$existingPath'" -Level DEBUG
                Write-Log -Message "  -> Expected Path: '$ScriptPath'" -Level DEBUG
                Write-Log -Message "  -> Existing Interval (min): '$existingIntervalMinutes'" -Level DEBUG
                Write-Log -Message "  -> Expected Interval (min): '$ScheduledTaskIntervalMinutes'" -Level DEBUG
                # --- End Detailed Logging ---

                # Perform comparison (Case-insensitive path, integer interval)
                if ($existingPath -ne $null -and $existingIntervalMinutes -ne $null -and
                    $existingPath -eq $ScriptPath -and # Case-insensitive by default
                    $existingIntervalMinutes -eq $ScheduledTaskIntervalMinutes) {
                    Write-Log -Message "Existing task '$TaskName' configuration matches. No update needed." -Level INFO
                    $needsUpdate = $false
                } else {
                    Write-Log -Message "Existing task '$TaskName' configuration mismatch detected. Task will be updated." -Level WARN
                    # Log specific mismatches
                    if ($existingPath -ne $ScriptPath) { Write-Log -Message "  - Path mismatch: '$existingPath' vs '$ScriptPath'" -Level DEBUG }
                    if ($existingIntervalMinutes -ne $ScheduledTaskIntervalMinutes) { Write-Log -Message "  - Interval mismatch: '$existingIntervalMinutes' vs '$ScheduledTaskIntervalMinutes'" -Level DEBUG }
                }
            } else {
                Write-Log -Message "Could not retrieve valid action or trigger from existing task '$TaskName'. Task will be updated." -Level WARN
            }
        } catch {
            Write-Log -Message "Error checking existing task '$TaskName' configuration: $($_.Exception.Message). Assuming update is needed." -Level WARN
        }

        # Unregister only if update is needed
        if ($needsUpdate) {
            Write-Log -Message "Unregistering existing task '$TaskName' before update." -Level INFO
            try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
            catch { Write-Log -Message "Failed to unregister existing task '$TaskName': $($_.Exception.Message). Update might fail or use old settings." -Level WARN }
        }
    } else {
        Write-Log -Message "Scheduled task '${TaskName}' does not exist. Registration required." -Level INFO
        $needsUpdate = $true # Task doesn't exist, so it needs to be created
    }

    # Proceed with registration only if needed
    if ($needsUpdate) {
        Write-Log -Message "Proceeding with registration/update for task '${TaskName}'." -Level INFO
    # Build action arguments - ONLY include necessary PowerShell execution parameters
    # Ensure ActionArguments contains ONLY the required PowerShell parameters
    # Build the arguments for the scheduled task action
    $TaskActionArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$ScriptPath`"", # Quote the script path
        "-ScriptSaveFolder", "`"$ScriptSaveFolder`"" # Quote path
        # Add switches only if they were true when Register-ScheduledTaskForScript was called
        # Note: $DebugMode is intentionally excluded from the scheduled task arguments
    )
    if ($CloseApplications) { $TaskActionArgs += "-CloseApplications" }
    if ($SkipUpdateIfAnyProcessIsRunning) { $TaskActionArgs += "-SkipUpdateIfAnyProcessIsRunning" }

    $ActionArguments = $TaskActionArgs -join " "
    Write-Log -Message "[DEBUG] Constructed Scheduled Task Action Arguments: '$ActionArguments'" -Level DEBUG # Logging the final value

    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $ActionArguments
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $ScheduledTaskIntervalMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest # Run as SYSTEM

    # Simplified settings for compatibility
    $settingsParams = @{
        MultipleInstances = 'IgnoreNew'
        StartWhenAvailable = $true
        Hidden = $true
        ExecutionTimeLimit = ([System.TimeSpan]::Zero) # No time limit
        # Add other basic, known compatible parameters if needed
    }
    Write-Log -Message "Attempting to create task settings with parameters: $($settingsParams | Out-String)" -Level DEBUG
    $settings = New-ScheduledTaskSettingsSet @settingsParams -ErrorAction SilentlyContinue

    if (-not $settings) {
         Write-Log -Message "Failed to create ScheduledTaskSettingsSet object. Task registration cannot proceed." -Level ERROR
         throw "Failed to create ScheduledTaskSettingsSet."
    }
    Write-Log -Message "Successfully created basic ScheduledTaskSettingsSet object." -Level DEBUG

    try {
        # --- START DEBUG: Log parameters before Register-ScheduledTask ---
        Write-Log -Message "DEBUG: Parameters for Register-ScheduledTask:" -Level DEBUG
        Write-Log -Message "  - TaskName: '$TaskName'" -Level DEBUG
        Write-Log -Message "  - Action:" -Level DEBUG
        Write-Log -Message ($action | Format-List | Out-String) -Level DEBUG
        Write-Log -Message "  - Trigger:" -Level DEBUG
        Write-Log -Message ($trigger | Format-List | Out-String) -Level DEBUG
        Write-Log -Message "  - Principal:" -Level DEBUG
        Write-Log -Message ($principal | Format-List | Out-String) -Level DEBUG
        Write-Log -Message "  - Settings:" -Level DEBUG
        Write-Log -Message ($settings | Format-List | Out-String) -Level DEBUG
        Write-Log -Message "  - Description: 'Automatic Loxone Config Update'" -Level DEBUG
        # --- END DEBUG ---
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Automatic Loxone Config Update" -ErrorAction Stop
        Write-Log -Message "Scheduled task '${TaskName}' registered/updated successfully." -Level INFO

        # Attempt to set other settings separately (might fail on older systems)
        try {
            $task = Get-ScheduledTask -TaskName $TaskName
            $task.Settings.DisallowStartIfOnBatteries = $false
            $task.Settings.StopIfGoingOnBatteries = $false
            $task.Settings.AllowHardTerminate = $true
            $task.Settings.RunOnlyIfNetworkAvailable = $false
            $task.Settings.Enabled = $true
            Set-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
            Write-Log -Message "Attempted to apply additional settings to task '$TaskName'." -Level DEBUG
        } catch {
            Write-Log -Message "Could not apply additional settings to task '$TaskName' using Set-ScheduledTask: $($_.Exception.Message)" -Level WARN
        }

    } catch { # This catch corresponds to the try block starting at line 218
        # --- START DEBUG: Enhanced Error Logging ---
        $fullError = $_.Exception.ToString()
        Write-Log -Message "CRITICAL ERROR during scheduled task registration/update for '$TaskName'. Full Exception: $fullError" -Level ERROR
        # --- END DEBUG ---
        # If running non-elevated, this is expected. If elevated, it's a real error.
        # ASSUMPTION: $script:IsAdminRun is set globally by the calling script/environment
        if ($script:IsAdminRun) {
             throw $_ # Re-throw if running as admin, as it shouldn't fail
        } else {
             Write-Log -Level DEBUG -Message "Task registration correctly failed with error (not Admin): $($_.Exception.Message)"
             # Do not throw if not admin, the calling script handles this.
        }
    }
} # End of the 'if ($needsUpdate)' block starting at line 172

} finally { # Corresponds to the main function's try block starting around line 100
    Exit-Function
}
}
# End of function Register-ScheduledTaskForScript
#endregion Register-ScheduledTaskForScript Function

# Ensure functions are available (though NestedModules in PSD1 is the primary mechanism)
Export-ModuleMember -Function Get-ProcessStatus, Test-ScheduledTask, Test-LoxoneScheduledTaskExists, Start-ProcessInteractive, Register-ScheduledTaskForScript
# NOTE: Explicit Export-ModuleMember is required for the manifest to re-export with FunctionsToExport = '*'.
