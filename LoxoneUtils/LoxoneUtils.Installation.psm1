# Module for Loxone Update Script Installation Functions

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
    try {
        Write-Log -Message "Executing Start-Process: '$InstallerPath' /${InstallMode} -Wait" -Level DEBUG
        $process = Start-Process -FilePath $InstallerPath -ArgumentList "/${InstallMode}" -Wait -PassThru -ErrorAction Stop
        Write-Log -Message "Start-Process completed. PID: $($process.Id), ExitCode: $($process.ExitCode)" -Level DEBUG
        if ($process.ExitCode -ne 0) {
            Write-Log -Message "Installer process exited with non-zero code: $($process.ExitCode)." -Level WARN
            # Optionally throw an error here if a non-zero exit code should be treated as failure
            # throw "Installer failed with exit code $($process.ExitCode)."
        }
        Write-Log -Message "Update installer process finished waiting." -Level INFO # Changed message slightly
    }
    catch {
        Write-Log -Message "Error executing update installer: ${($_.Exception.Message)}" -Level ERROR
        throw $_
    }
    } finally {
        Exit-Function
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
    Write-Log -Message "Starting Loxone for Windows installer: ${InstallerPath} with install mode ${InstallMode}." -Level INFO
    try {
        # Assuming the same silent switches work. This might need adjustment based on the actual installer.
        # Use /S based on the provided XML example's likely installer type (InnoSetup often uses /VERYSILENT or /SILENT, but /S is common too)
        # We'll use the $InstallMode parameter passed in, assuming it's correctly set ('silent' or 'verysilent')
        $arguments = "/${InstallMode}"
        Write-Log -Message "Executing: '$InstallerPath' $arguments" -Level DEBUG
        Start-Process -FilePath $InstallerPath -ArgumentList $arguments -Wait -ErrorAction Stop
        Write-Log -Message "Loxone for Windows installer executed successfully." -Level INFO
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
            $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            if (-not $keys) {
                Write-Log -Message "No subkeys found under '$path'." -Level DEBUG
                continue # Skip to next registry path
            }
            Write-Log -Message "Found $($keys.Count) subkeys under '$path'." -Level DEBUG
            foreach ($key in $keys) {
                $keyName = $key.PSChildName # Get the actual key name for logging
                $displayName = $null
                $installLocation = $null
                try {
                    $displayName = $key.GetValue("DisplayName") -as [string]
                    $installLocation = $key.GetValue("InstallLocation") -as [string]
                } catch {
                    Write-Log -Message "Error reading values from key '$keyName' under '$path': $($_.Exception.Message)" -Level DEBUG
                    continue # Skip this key
                }

                # Log details even if it's not the target app
                # Write-Log -Message "Key: '$keyName', DisplayName: '$displayName', InstallLocation: '$installLocation'" -Level DEBUG

                if ($displayName -eq $AppName) { # Use parameter
                    Write-Log -Message "MATCH FOUND: Key '$keyName' has DisplayName '$AppName'." -Level DEBUG
                    if ($installLocation) {
                        Write-Log -Message "InstallLocation value found: '$installLocation'. Checking path validity..." -Level DEBUG
                        if (Test-Path $installLocation -PathType Container) { # Check if it's a valid directory
                            Write-Log -Message "SUCCESS: Found valid '$AppName' installation directory: '$installLocation'" -Level INFO # Use parameter
                            return $installLocation
                        } else {
                            Write-Log -Message "InstallLocation '$installLocation' for '$AppName' exists but is NOT a valid directory. Continuing search..." -Level WARN # Use parameter
                        }
                    } else {
                         Write-Log -Message "Found '$AppName' registry entry in key '$keyName', but InstallLocation value is missing or empty. Continuing search..." -Level WARN # Use parameter
                    }
                }
            } # End foreach ($key in $keys)
        } else {
             Write-Log -Message "Registry path not found or inaccessible: $path" -Level DEBUG
        } # End if (Test-Path $path)
    } # End foreach ($path in $registryPaths)

    Write-Log -Message "'$AppName' installation path not found after checking all registry locations." -Level INFO # Use parameter
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
    try {
        Write-Log -Message "Calling Get-InstalledApplicationPath for AppName '$AppName'..." -Level DEBUG
        $installDir = Get-InstalledApplicationPath -AppName $AppName # Pass AppName
        Write-Log -Message "GetInstalledApplicationPath returned: '$installDir'" -Level DEBUG

        if ($installDir) {
            $exePath = Join-Path -Path $installDir -ChildPath $ExeName # Use ExeName parameter
            Write-Log -Message "Checking for executable at combined path: '$exePath'" -Level DEBUG
            if (Test-Path $exePath -PathType Leaf) {
                Write-Log -Message "SUCCESS: Found executable '$ExeName' for '$AppName' at: '$exePath'" -Level INFO # Use parameters
                return $exePath
            } else {
                Write-Log -Message "Executable '$ExeName' NOT found at path '$exePath' (derived from InstallLocation '$installDir')." -Level WARN # Use parameters
                return $null
            }
        } else {
            Write-Log -Message "'$AppName' installation directory was not found by GetInstalledApplicationPath. Cannot determine '$ExeName' path." -Level INFO # Use parameters
            return $null
        }
    } finally {
        Exit-Function # Corrected function call
    }
}
#endregion Installation Helpers (Continued)

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
Export-ModuleMember -Function Get-InstalledVersion, Start-LoxoneUpdateInstaller, Start-LoxoneForWindowsInstaller, Get-InstalledApplicationPath, Get-LoxoneExePath, Invoke-ZipFileExtraction
# NOTE: Explicit Export-ModuleMember is required for the manifest to re-export with FunctionsToExport = '*'.