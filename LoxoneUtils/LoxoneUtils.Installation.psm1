# Module for Loxone Update Script Installation Functions

# Global cache for expensive path lookups (performance optimization)
$script:LoxonePathCache = @{}
$script:LoxoneAppIdCache = $null

#region Installation Helpers
function Get-InstalledVersion {
    param(
        # The path to the executable file or its installation directory.
        [string]$ExePath
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    if (-not $ExePath.EndsWith(".exe")) {
        $ExePath = Join-Path -Path $ExePath -ChildPath "LoxoneConfig.exe"
    }
    if (Test-Path $ExePath) {
        try {
            $version = (Get-Item $ExePath).VersionInfo.FileVersion
            $version = $version.Trim()
            Write-Log -Message "Found version of '${ExePath}': ${version}" -Level INFO
            return $version
        } catch {
            Write-Log -Message "Error retrieving version from '${ExePath}': ${($_.Exception.Message)}" -Level WARN
		   Return $null
        }
    }
    else {
        Write-Log -Message "Installed application not found at '${ExePath}'." -Level WARN
		Return $null
    } finally {
        Exit-Function
    }
}
function Start-LoxoneUpdateInstaller {
    param(
        # The full path to the Loxone installer executable.
        [string]$InstallerPath,
        # The installation mode ('silent' or 'verysilent').
        [string]$InstallMode,
        # The script's save folder (used for potential logging by the installer, though not directly used here).
        [string]$ScriptSaveFolder
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Starting update installer: ${InstallerPath} with install mode ${InstallMode}." -Level INFO
    try {
        Write-Log -Message "Executing Start-Process: '$InstallerPath' /${InstallMode}" -Level DEBUG
        
        # Start the process without -Wait to allow periodic toast updates
        $process = Start-Process -FilePath $InstallerPath -ArgumentList "/${InstallMode}", "/NORESTART" -PassThru -ErrorAction Stop
        Write-Log -Message "Installer process started with PID: $($process.Id)" -Level DEBUG
        
        # Wait with timeout (5 minutes max for config installer)
        $timeout = 300  # seconds
        $waited = 0
        while (-not $process.HasExited -and $waited -lt $timeout) {
            Start-Sleep -Seconds 1
            $waited++
            
            # Update toast every 2 seconds to prevent auto-dismissal
            if ($waited % 2 -eq 0) {
                # Check if we can update the toast
                if ($Global:PersistentToastInitialized -and (Get-Command Update-PersistentToast -ErrorAction SilentlyContinue)) {
                    try {
                        # Create a pulsing dots animation to show activity
                        $dots = '.' * (($waited / 2) % 4)
                        $statusText = "Installing Loxone Config$dots"
                        
                        # Update the toast data directly if available
                        if ($Global:PersistentToastData) {
                            if ($Global:PersistentToastData.ContainsKey('ConfigStatus')) {
                                $Global:PersistentToastData['ConfigStatus'] = $statusText
                            }
                            if ($Global:PersistentToastData.ContainsKey('StatusText')) {
                                $Global:PersistentToastData['StatusText'] = $statusText
                            }
                            
                            # Call Update-PersistentToast to refresh the notification
                            Update-PersistentToast -StepNumber 0 -StepName "Config Installation" -UpdateText $statusText
                        }
                    } catch {
                        # Silently ignore toast update errors during installation
                        Write-Log -Message "Could not update toast during installation: $_" -Level DEBUG
                    }
                }
            }
            
            if ($waited % 30 -eq 0) {
                Write-Log -Message "Still waiting for installer (PID: $($process.Id))... ($waited seconds elapsed)" -Level DEBUG
            }
        }
        
        if (-not $process.HasExited) {
            Write-Log -Message "Installation timeout after $timeout seconds" -Level WARNING
            # Try to get exit code anyway
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                $exitCode = -1
            } catch {
                $exitCode = -1
            }
        } else {
            $exitCode = $process.ExitCode
        }
        
        Write-Log -Message "Start-Process completed. PID: $($process.Id), ExitCode: $exitCode" -Level DEBUG

        # Exit codes 3010 (ERROR_SUCCESS_REBOOT_REQUIRED) and 1641 (ERROR_SUCCESS_REBOOT_INITIATED)
        # indicate successful installation that requires a system restart (e.g. VC++ Redistributable)
        $restartRequired = ($exitCode -eq 3010 -or $exitCode -eq 1641)
        $installSuccess = ($exitCode -eq 0 -or $restartRequired)

        if ($restartRequired) {
            Write-Log -Message "Installer completed successfully but requires system restart (exit code: $exitCode)." -Level WARN
        } elseif ($exitCode -ne 0) {
            Write-Log -Message "Installer process exited with non-zero code: $exitCode." -Level WARN
        }
        Write-Log -Message "Update installer process finished waiting." -Level INFO

        # Return result object before Exit-Function
        $result = @{
            Success = $installSuccess
            ExitCode = $exitCode
            RestartRequired = $restartRequired
            Error = if (-not $installSuccess) { "Installer exited with code $exitCode" } else { $null }
        }
        
        Exit-Function
        return $result
    }
    catch {
        Write-Log -Message "Error executing update installer: $($_.Exception.Message)" -Level ERROR
        $errorResult = @{
            Success = $false
            ExitCode = -1
            Error = $_.Exception.Message
        }
        Exit-Function
        return $errorResult
    }
}

function Start-LoxoneForWindowsInstaller {
    param(
        # The full path to the Loxone for Windows installer executable.
        [string]$InstallerPath,
        # The installation mode ('silent' or 'verysilent').
        [string]$InstallMode,
        # The script's save folder (used for potential logging by the installer).
        [string]$ScriptSaveFolder
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    
    # Kill any running Loxone app processes before installation
    $maxAttempts = 5
    $attempt = 0
    while ($attempt -lt $maxAttempts) {
        $loxoneProcesses = @(Get-Process -Name "Loxone" -ErrorAction SilentlyContinue)
        if ($loxoneProcesses.Count -eq 0) {
            if ($attempt -eq 0) {
                Write-Log -Message "No running Loxone processes found" -Level DEBUG
            } else {
                Write-Log -Message "All Loxone processes successfully terminated after $attempt attempt(s)" -Level INFO
            }
            break
        }
        
        $attempt++
        Write-Log -Message "Attempt $attempt of $maxAttempts - Found $($loxoneProcesses.Count) running Loxone process(es). Terminating..." -Level INFO
        foreach ($proc in $loxoneProcesses) {
            try {
                $proc | Stop-Process -Force -ErrorAction Stop
                Write-Log -Message "Terminated Loxone process (PID: $($proc.Id))" -Level DEBUG
            } catch {
                Write-Log -Message "Failed to terminate Loxone process (PID: $($proc.Id)): $_" -Level WARN
            }
        }
        
        if ($attempt -lt $maxAttempts) {
            # Brief pause before rechecking (100ms)
            Start-Sleep -Milliseconds 100
        }
    }
    
    # Final check
    $remainingProcesses = @(Get-Process -Name "Loxone" -ErrorAction SilentlyContinue)
    if ($remainingProcesses.Count -gt 0) {
        Write-Log -Message "WARNING: $($remainingProcesses.Count) Loxone process(es) still running after $maxAttempts attempts" -Level WARN
    }
    
    Write-Log -Message "Starting Loxone for Windows installer: ${InstallerPath} with install mode ${InstallMode}." -Level INFO
    try {
        # Assuming the same silent switches work. This might need adjustment based on the actual installer.
        # Use /S based on the provided XML example's likely installer type (InnoSetup often uses /VERYSILENT or /SILENT, but /S is common too)
        # We'll use the $InstallMode parameter passed in, assuming it's correctly set ('silent' or 'verysilent')
        $arguments = if ($InstallMode) { "/${InstallMode}" } else { "/SILENT" }
        Write-Log -Message "Executing: '$InstallerPath' $arguments" -Level DEBUG
        
        # Start the process without -Wait initially to avoid blocking
        $process = Start-Process -FilePath $InstallerPath -ArgumentList $arguments -PassThru -ErrorAction Stop
        Write-Log -Message "Installer process started with PID: $($process.Id)" -Level DEBUG
        
        # Wait with timeout (5 minutes max for app installer)
        $timeout = 300  # seconds
        $waited = 0
        while (-not $process.HasExited -and $waited -lt $timeout) {
            Start-Sleep -Seconds 1
            $waited++
            
            # Update toast every 2 seconds to prevent auto-dismissal
            if ($waited % 2 -eq 0) {
                # Check if we can update the toast
                if ($Global:PersistentToastInitialized -and (Get-Command Update-PersistentToast -ErrorAction SilentlyContinue)) {
                    try {
                        # Create a pulsing dots animation to show activity
                        $dots = '.' * (($waited / 2) % 4)
                        $statusText = "Installing Loxone App$dots"
                        
                        # Update the toast data directly if available
                        if ($Global:PersistentToastData) {
                            if ($Global:PersistentToastData.ContainsKey('AppStatus')) {
                                $Global:PersistentToastData['AppStatus'] = $statusText
                            }
                            if ($Global:PersistentToastData.ContainsKey('StatusText')) {
                                $Global:PersistentToastData['StatusText'] = $statusText
                            }
                            
                            # Call Update-PersistentToast to refresh the notification
                            Update-PersistentToast -StepNumber 0 -StepName "App Installation" -UpdateText $statusText
                        }
                    } catch {
                        # Silently ignore toast update errors during installation
                        Write-Log -Message "Could not update toast during installation: $_" -Level DEBUG
                    }
                }
            }
            
            if ($waited % 30 -eq 0) {
                Write-Log -Message "Still waiting for installer (PID: $($process.Id))... ($waited seconds elapsed)" -Level DEBUG
            }
        }
        
        if (-not $process.HasExited) {
            Write-Log -Message "WARNING: Installer (PID: $($process.Id)) did not complete within $timeout seconds" -Level WARNING
            Write-Log -Message "Checking if installation succeeded anyway..." -Level INFO
            
            # Check if the app was installed successfully despite timeout
            $appInstalled = $false
            try {
                # Try to find the installed app
                $appPath = Get-InstalledApplicationPath -DisplayName "Loxone" -ErrorAction SilentlyContinue
                if ($appPath) {
                    Write-Log -Message "App appears to be installed at: $appPath (despite timeout)" -Level INFO
                    $appInstalled = $true
                }
            } catch {
                Write-Log -Message "Could not verify app installation: $_" -Level DEBUG
            }
            
            if ($appInstalled) {
                return @{
                    ExitCode = 0
                    Success = $true
                    TimedOut = $true
                }
            } else {
                return @{
                    ExitCode = -1
                    Success = $false
                    TimedOut = $true
                }
            }
        } else {
            $exitCode = $process.ExitCode
            Write-Log -Message "Loxone for Windows installer completed. Exit code: $exitCode (after $waited seconds)" -Level INFO
            
            # NOTE: Shortcut icon fix code commented out - Loxone has fixed the bug in their installer (2024-11)
            # If the bug resurfaces, uncomment the block below
            <#
            # Fix shortcut icons if installation was successful
            if ($exitCode -eq 0) {
                Write-Log -Message "Installation successful, attempting to fix shortcut icons..." -Level INFO
                try {
                    # Find the Loxone App executable directly
                    $exePath = $null

                    # Check common installation paths
                    $possiblePaths = @(
                        # The actual location where the App installs
                        "${env:LOCALAPPDATA}\Programs\kerberos\Loxone.exe",
                        # Other common paths
                        "C:\Program Files\Loxone\Loxone.exe",
                        "C:\Program Files (x86)\Loxone\Loxone.exe",
                        "${env:ProgramFiles}\Loxone\Loxone.exe",
                        "${env:ProgramFiles(x86)}\Loxone\Loxone.exe",
                        "${env:LOCALAPPDATA}\Loxone\Loxone.exe",
                        "${env:APPDATA}\Loxone\Loxone.exe"
                    )

                    Write-Log -Message "Searching for Loxone.exe in common paths..." -Level DEBUG
                    foreach ($path in $possiblePaths) {
                        Write-Log -Message "Checking: '$path'" -Level DEBUG
                        if (Test-Path $path) {
                            $exePath = $path
                            Write-Log -Message "Found Loxone executable at: '$exePath'" -Level INFO
                            break
                        }
                    }

                    # If not found in common paths, try searching user AppData directories
                    if (-not $exePath) {
                        Write-Log -Message "Not found in common paths, searching AppData directories..." -Level DEBUG

                        # Search in user AppData (where per-user apps install)
                        $searchPaths = @(
                            "${env:LOCALAPPDATA}\Programs",
                            "${env:LOCALAPPDATA}",
                            "${env:APPDATA}"
                        )
                        foreach ($searchPath in $searchPaths) {
                            if (Test-Path $searchPath) {
                                Write-Log -Message "Searching in: $searchPath" -Level DEBUG
                                # Look for Loxone.exe but exclude LoxoneConfig folder
                                $found = Get-ChildItem -Path $searchPath -Filter "Loxone.exe" -Recurse -ErrorAction SilentlyContinue |
                                         Where-Object { $_.FullName -notmatch "LoxoneConfig" } |
                                         Select-Object -First 1
                                if ($found) {
                                    $exePath = $found.FullName
                                    Write-Log -Message "Found Loxone App executable at: '$exePath'" -Level INFO
                                    break
                                }
                            }
                        }
                    }

                    if ($exePath) {

                        # Build shortcut paths - check multiple possible locations
                        $userProfile = [Environment]::GetFolderPath("UserProfile")
                        $possibleShortcutPaths = @(
                            (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"),
                            (Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone\Loxone.lnk"),
                            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone.lnk",
                            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Loxone\Loxone.lnk"
                        )

                        $fixedStartMenu = $false
                        foreach ($shortcutPath in $possibleShortcutPaths) {
                            if (Test-Path $shortcutPath) {
                                Write-Log -Message "Found Start Menu shortcut at: '$shortcutPath'" -Level DEBUG
                                try {
                                    $shell = New-Object -ComObject WScript.Shell
                                    $shortcut = $shell.CreateShortcut($shortcutPath)

                                    # Log current properties
                                    Write-Log -Message "Current TargetPath: '$($shortcut.TargetPath)', IconLocation: '$($shortcut.IconLocation)'" -Level DEBUG

                                    # Update shortcut properties
                                    $shortcut.TargetPath = $exePath
                                    $shortcut.Arguments = ""
                                    $shortcut.WorkingDirectory = Split-Path $exePath -Parent
                                    $shortcut.IconLocation = "$exePath,0"
                                    $shortcut.Description = "Loxone Smart Home App"
                                    $shortcut.Save()

                                    # Release COM objects
                                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null

                                    Write-Log -Message "Successfully fixed Start Menu shortcut icon at: $shortcutPath" -Level INFO
                                    $fixedStartMenu = $true
                                    break  # Only fix the first found shortcut
                                } catch {
                                    Write-Log -Message "Error fixing Start Menu shortcut: $_" -Level WARN
                                }
                            }
                        }

                        if (-not $fixedStartMenu) {
                            Write-Log -Message "No Start Menu shortcut found in any of the checked locations" -Level WARN
                        }

                        # Also fix desktop shortcut if it exists
                        $desktopPath = [Environment]::GetFolderPath("Desktop")
                        $desktopShortcut = Join-Path $desktopPath "Loxone.lnk"

                        if (Test-Path $desktopShortcut) {
                            Write-Log -Message "Found desktop shortcut, attempting to fix..." -Level DEBUG
                            try {
                                $shell2 = New-Object -ComObject WScript.Shell
                                $desktop = $shell2.CreateShortcut($desktopShortcut)

                                $desktop.TargetPath = $exePath
                                $desktop.Arguments = ""
                                $desktop.WorkingDirectory = Split-Path $exePath -Parent
                                $desktop.IconLocation = "$exePath,0"
                                $desktop.Description = "Loxone Smart Home App"
                                $desktop.Save()

                                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($desktop) | Out-Null
                                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell2) | Out-Null

                                Write-Log -Message "Successfully fixed desktop shortcut icon" -Level INFO
                            } catch {
                                Write-Log -Message "Error fixing desktop shortcut: $_" -Level WARN
                            }
                        } else {
                            Write-Log -Message "No desktop shortcut found" -Level DEBUG
                        }
                    } else {
                        Write-Log -Message "Could not find Loxone executable in common installation paths" -Level WARN
                    }
                } catch {
                    Write-Log -Message "Error during icon fixing process: $_" -Level WARN
                    # Non-critical error, continue
                }
            }
            #>
            
            return @{
                ExitCode = $exitCode
                Success = ($exitCode -eq 0)
                TimedOut = $false
            }
        }
    }
    catch {
        Write-Log -Message "Error executing Loxone for Windows installer: ${($_.Exception.Message)}" -Level ERROR
        throw $_
    } finally {
        Exit-Function
    }
}


#endregion Installation Helpers

#region Installation Helpers (Continued)
function Get-InstalledApplicationPath {
    [CmdletBinding()]
    param(
        # The display name of the application to search for in the registry.
        [Parameter(Mandatory=$false)] # Make optional, default below
        [string]$AppName = "Loxone Config"
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    
    # Check cache first (performance optimization)
    if ($script:LoxonePathCache.ContainsKey($AppName)) {
        Write-Log -Message "[CACHE HIT] Returning cached path for '$AppName': $($script:LoxonePathCache[$AppName])" -Level DEBUG
        Exit-Function
        return $script:LoxonePathCache[$AppName]
    }
    
    Write-Log -Message "[CACHE MISS] Performing registry lookup for '$AppName'..." -Level DEBUG
    try {
        $registryPaths = @(
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        # AppName is now a parameter

    Write-Log -Message "Searching registry for '$AppName' installation path..." -Level DEBUG # Use parameter

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Write-Log -Message "Checking registry path: $path" -Level DEBUG
            
            # Performance optimization: Use direct registry access instead of Get-ChildItem
            try {
                # Extract the registry hive and path
                if ($path -like "HKLM:*") {
                    $registryPath = $path.Replace("HKLM:\", "")
                    $hive = [Microsoft.Win32.Registry]::LocalMachine
                } elseif ($path -like "HKCU:*") {
                    $registryPath = $path.Replace("HKCU:\", "")
                    $hive = [Microsoft.Win32.Registry]::CurrentUser
                } else {
                    throw "Unsupported registry path format: $path"
                }
                
                $regKey = $hive.OpenSubKey($registryPath, $false)
                if (-not $regKey) {
                    Write-Log -Message "Could not open registry key: $path" -Level DEBUG
                    continue
                }
                
                $subKeyNames = $regKey.GetSubKeyNames()
                Write-Log -Message "Found $($subKeyNames.Count) subkeys under '$path' (optimized enumeration)." -Level DEBUG
                
                foreach ($subKeyName in $subKeyNames) {
                    $subKey = $null
                    try {
                        $subKey = $regKey.OpenSubKey($subKeyName, $false)
                        if (-not $subKey) { continue }
                        
                        $displayName = $subKey.GetValue("DisplayName") -as [string]
                        
                        # Early exit optimization: Only check InstallLocation if DisplayName matches
                        if ($displayName -eq $AppName) {
                            Write-Log -Message "MATCH FOUND: Key '$subKeyName' has DisplayName '$AppName'." -Level DEBUG
                            $installLocation = $subKey.GetValue("InstallLocation") -as [string]
                            
                            if ($installLocation) {
                                Write-Log -Message "InstallLocation value found: '$installLocation'. Checking path validity..." -Level DEBUG
                                if (Test-Path $installLocation -PathType Container) {
                                    Write-Log -Message "SUCCESS: Found valid '$AppName' installation directory: '$installLocation'" -Level INFO
                                    # Cache the successful result for future calls
                                    $script:LoxonePathCache[$AppName] = $installLocation
                                    Write-Log -Message "[CACHE STORE] Cached path for '$AppName': '$installLocation'" -Level DEBUG
                                    
                                    # Cleanup and return immediately
                                    $subKey.Close()
                                    $regKey.Close()
                                    return $installLocation
                                } else {
                                    Write-Log -Message "InstallLocation '$installLocation' for '$AppName' exists but is NOT a valid directory. Continuing search..." -Level WARN
                                }
                            } else {
                                Write-Log -Message "Found '$AppName' registry entry in key '$subKeyName', but InstallLocation value is missing or empty. Continuing search..." -Level WARN
                            }
                        }
                    } catch {
                        Write-Log -Message "Error reading subkey '$subKeyName' under '$path': $($_.Exception.Message)" -Level DEBUG
                    } finally {
                        if ($subKey) { $subKey.Close() }
                    }
                }
                
                $regKey.Close()
            } catch {
                Write-Log -Message "Error with optimized registry access for '$path': $($_.Exception.Message). Falling back to Get-ChildItem." -Level DEBUG
                
                # Fallback to original method for this path
                $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                if (-not $keys) {
                    Write-Log -Message "No subkeys found under '$path' (fallback method)." -Level DEBUG
                    continue
                }
                
                foreach ($key in $keys) {
                    $keyName = $key.PSChildName
                    try {
                        $displayName = $key.GetValue("DisplayName") -as [string]
                        if ($displayName -eq $AppName) {
                            $installLocation = $key.GetValue("InstallLocation") -as [string]
                            if ($installLocation -and (Test-Path $installLocation -PathType Container)) {
                                Write-Log -Message "SUCCESS: Found valid '$AppName' installation directory: '$installLocation' (fallback)" -Level INFO
                                $script:LoxonePathCache[$AppName] = $installLocation
                                return $installLocation
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        } else {
             Write-Log -Message "Registry path not found or inaccessible: $path" -Level DEBUG
        }
    } # End foreach ($path in $registryPaths)

    Write-Log -Message "'$AppName' installation path not found after checking all registry locations." -Level INFO # Use parameter
    # Cache the negative result to avoid repeated expensive lookups
    $script:LoxonePathCache[$AppName] = $null
    Write-Log -Message "[CACHE STORE] Cached negative result for '$AppName'" -Level DEBUG
    return $null # Explicitly return null if not found after checking all paths
    } finally {
        Exit-Function # Corrected function call
    } # Closing brace for the finally block
}

function Get-LoxoneExePath { # Renamed function
    [CmdletBinding()]
    param(
        # The display name of the application to find.
        [Parameter(Mandatory=$false)]
        [string]$AppName = "Loxone Config",

        # The name of the executable file within the installation directory.
        [Parameter(Mandatory=$false)]
        [string]$ExeName = "LoxoneConfig.exe"
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    
    # Create cache key for exe path (includes both AppName and ExeName)
    $exeCacheKey = "$AppName|$ExeName"
    
    # Check cache first for exe path
    if ($script:LoxonePathCache.ContainsKey($exeCacheKey)) {
        Write-Log -Message "[CACHE HIT] Returning cached exe path for '$AppName\$ExeName': $($script:LoxonePathCache[$exeCacheKey])" -Level DEBUG
        Exit-Function
        return $script:LoxonePathCache[$exeCacheKey]
    }
    
    Write-Log -Message "[CACHE MISS] Performing exe path lookup for '$AppName\$ExeName'..." -Level DEBUG
    
    try {
        Write-Log -Message "Calling Get-InstalledApplicationPath for AppName '$AppName'..." -Level DEBUG
        $installDir = Get-InstalledApplicationPath -AppName $AppName # Pass AppName
        Write-Log -Message "GetInstalledApplicationPath returned: '$installDir'" -Level DEBUG

        if ($installDir) {
            $exePath = Join-Path -Path $installDir -ChildPath $ExeName # Use ExeName parameter
            Write-Log -Message "Checking for executable at combined path: '$exePath'" -Level DEBUG
            if (Test-Path $exePath -PathType Leaf) {
                Write-Log -Message "SUCCESS: Found executable '$ExeName' for '$AppName' at: '$exePath'" -Level INFO # Use parameters
                # Cache the successful exe path result
                $script:LoxonePathCache[$exeCacheKey] = $exePath
                Write-Log -Message "[CACHE STORE] Cached exe path for '$AppName\$ExeName': '$exePath'" -Level DEBUG
                return $exePath
            } else {
                Write-Log -Message "Executable '$ExeName' NOT found at path '$exePath' (derived from InstallLocation '$installDir')." -Level WARN # Use parameters
                # Cache the negative result
                $script:LoxonePathCache[$exeCacheKey] = $null
                Write-Log -Message "[CACHE STORE] Cached negative exe result for '$AppName\$ExeName'" -Level DEBUG
                return $null
            }
        } else {
            Write-Log -Message "'$AppName' installation directory was not found by GetInstalledApplicationPath. Cannot determine '$ExeName' path." -Level INFO # Use parameters
            # Cache the negative result (no install directory found)
            $script:LoxonePathCache[$exeCacheKey] = $null
            Write-Log -Message "[CACHE STORE] Cached negative exe result for '$AppName\$ExeName' (no install dir)" -Level DEBUG
            return $null
        }
    } finally {
        Exit-Function # Corrected function call
    }
}
#endregion Installation Helpers (Continued)
function Test-ExistingInstaller {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath,

        [Parameter(Mandatory=$true)]
        [string]$TargetVersion, # Expecting normalized version

        [Parameter(Mandatory=$false)]
        [string]$ComponentName = "Installer" # For logging purposes (e.g., "Config", "App")
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber

    $result = @{
        IsValid        = $false
        Reason         = "Not found"
        SkipDownload   = $false
        SkipExtraction = $false # Primarily for Config, but included for consistency
    }

    try {
        if (-not (Test-Path -Path $InstallerPath -PathType Leaf)) {
            Write-Log -Message "[$ComponentName] Existing installer not found at '$InstallerPath'." -Level INFO
            return $result # Return default (invalid, not found)
        }

        Write-Log -Message "[$ComponentName] Existing installer found at '$InstallerPath'. Validating..." -Level INFO

        # 1. Check Version
        $existingVersionRaw = $null
        $normalizedExisting = $null
        $versionMatch = $false
        try {
            $fileItem = Get-Item -Path $InstallerPath -ErrorAction Stop
            $existingVersionRaw = $fileItem.VersionInfo.FileVersion
            
            # Log more details about the file
            Write-Log -Message "[$ComponentName] File details: Size=$($fileItem.Length) bytes, LastWrite=$($fileItem.LastWriteTime)" -Level DEBUG
            Write-Log -Message "[$ComponentName] VersionInfo.FileVersion='$existingVersionRaw', ProductVersion='$($fileItem.VersionInfo.ProductVersion)'" -Level DEBUG
            
            # Handle case where FileVersion might be null or empty for some installers
            if ([string]::IsNullOrWhiteSpace($existingVersionRaw)) {
                Write-Log -Message "[$ComponentName] Installer has no FileVersion info. Checking by filename and size..." -Level WARN
                
                # For App installer, if file exists with reasonable size, consider it valid
                if ($ComponentName -eq "App" -and $fileItem.Length -gt 10000000) { # > 10MB
                    Write-Log -Message "[$ComponentName] App installer exists with size $($fileItem.Length) bytes. Considering it valid based on size." -Level INFO
                    $result.IsValid = $true
                    $result.SkipDownload = $true
                    $result.Reason = "File exists with reasonable size"
                    return $result
                } else {
                    $result.Reason = "No version info available"
                    return $result
                }
            }
            
            $normalizedExisting = Convert-VersionString $existingVersionRaw -ErrorAction Stop
            Write-Log -Message "[$ComponentName] Existing installer version: $normalizedExisting (Raw: '$existingVersionRaw'). Target version: $TargetVersion." -Level DEBUG
            if ($normalizedExisting -eq $TargetVersion) {
                $versionMatch = $true
                Write-Log -Message "[$ComponentName] Existing installer version matches target." -Level INFO
            } else {
                Write-Log -Message "[$ComponentName] Existing installer version ($normalizedExisting) does NOT match target ($TargetVersion)." -Level WARN
                $result.Reason = "Version mismatch (Found: $normalizedExisting, Expected: $TargetVersion)"
                # Remove invalid file here? Or let the caller handle it? Let caller handle removal.
                return $result
            }
        } catch {
            Write-Log -Message "[$ComponentName] Could not determine or normalize version for existing installer '$InstallerPath': $($_.Exception.Message)" -Level WARN
            $result.Reason = "Version check failed"
            return $result
        }

        # 2. Check Signature (only if version matches)
        Write-Log -Message "[$ComponentName] Version matches. Checking signature of existing installer '$InstallerPath'..." -Level DEBUG
        $existingSignatureValid = $false
        try {
            # Assuming Get-ExecutableSignature is available in the scope
            $sigCheckResult = Get-ExecutableSignature -ExePath $InstallerPath -ErrorAction Stop
            if ($sigCheckResult -and $sigCheckResult.Status -eq 'Valid') {
                $existingSignatureValid = $true
                Write-Log -Message "[$ComponentName] Existing installer signature is valid." -Level INFO
            } else {
                $sigStatus = if ($sigCheckResult) { $sigCheckResult.Status } else { "Error checking" }
                Write-Log -Message "[$ComponentName] Existing installer signature is NOT valid (Status: $sigStatus)." -Level WARN
                $result.Reason = "Invalid signature (Status: $sigStatus)"
                # Remove invalid file here? Or let the caller handle it? Let caller handle removal.
                return $result
            }
        } catch {
             Write-Log -Message "[$ComponentName] Error checking signature for existing installer '$InstallerPath': $($_.Exception.Message)" -Level WARN
             $result.Reason = "Signature check failed"
             return $result
        }

        # 3. If both checks passed
        Write-Log -Message "[$ComponentName] Existing installer '$InstallerPath' is valid (Version & Signature)." -Level INFO
        $result.IsValid = $true
        $result.Reason = "Valid existing installer found"
        $result.SkipDownload = $true
        # Set SkipExtraction to true only if it's the Config component, as App doesn't have an extraction step
        if ($ComponentName -eq "Config") {
            $result.SkipExtraction = $true
        }

        return $result

    } catch {
        # Catch unexpected errors within the function itself
        Write-Log -Message "[$ComponentName] Unexpected error during existing installer check for '$InstallerPath': $($_.Exception.Message)" -Level ERROR
        $result.Reason = "Unexpected error during check"
        return $result
    } finally {
        Exit-Function
    }
}

#region Zip Extraction
function Invoke-ZipFileExtraction {
    [CmdletBinding()]
    param(
        # Full path to the ZIP archive.
        [Parameter(Mandatory=$true)][string]$ZipPath,
        # Full path to the destination directory where files should be extracted.
        [Parameter(Mandatory=$true)][string]$DestinationPath
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    
    Write-Log -Message "Extracting '$ZipPath' to '$DestinationPath'..." -Level INFO
    try {
        if (-not (Test-Path $ZipPath -PathType Leaf)) {
            throw "Source ZIP file not found: '$ZipPath'"
        }
        if (-not (Test-Path $DestinationPath -PathType Container)) {
            Write-Log -Message "Destination directory '$DestinationPath' does not exist. Creating..." -Level INFO
            New-Item -Path $DestinationPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force -ErrorAction Stop
        Write-Log -Message "Successfully extracted '$ZipPath' to '$DestinationPath'." -Level INFO
    } catch {
        Write-Log -Message "Error during ZIP extraction from '$ZipPath' to '$DestinationPath': $($_.Exception.Message)" -Level ERROR
        throw $_ # Re-throw the error
    } finally {
        Exit-Function
    }
}
#endregion Zip Extraction

# Ensure functions are available (though NestedModules in PSD1 is the primary mechanism)
Export-ModuleMember -Function Get-InstalledVersion, Start-LoxoneUpdateInstaller, Start-LoxoneForWindowsInstaller, Get-InstalledApplicationPath, Get-LoxoneExePath, Invoke-ZipFileExtraction, Test-ExistingInstaller
# NOTE: Explicit Export-ModuleMember is required for the manifest to re-export with FunctionsToExport = '*'.
