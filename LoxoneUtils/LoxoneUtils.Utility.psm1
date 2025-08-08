# --- Original Utility Module Content Starts Below ---
# Module for Loxone Update Script Utility Functions

#region Utility Helpers
function Get-ScriptSaveFolder {
    [CmdletBinding()]
    param(
        # The $MyInvocation automatic variable (contains info about the caller). Use [object] for easier testing/mocking.
        [Parameter(Mandatory=$true)]
        [object]$InvocationInfo,

        # The $PSBoundParameters automatic variable (a dictionary of parameters passed to the caller).
        [Parameter(Mandatory=$true)]
        [hashtable]$BoundParameters,

        # The path to the user's profile directory (defaults to $env:USERPROFILE). Used as a fallback.
        [string]$UserProfilePath = $env:USERPROFILE
    )

    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Get-ScriptSaveFolder: Invocation Command Definition = '$($InvocationInfo.MyCommand.Definition)'" -Level DEBUG
    try {
    Write-Log -Message "Get-ScriptSaveFolder: BoundParameters contains ScriptSaveFolder = $($BoundParameters.ContainsKey('ScriptSaveFolder'))" -Level DEBUG
    if ($BoundParameters.ContainsKey('ScriptSaveFolder')) {
        Write-Log -Message "Get-ScriptSaveFolder: ScriptSaveFolder Parameter Value = '$($BoundParameters['ScriptSaveFolder'])'" -Level DEBUG
    }

    $determinedSaveFolder = $null

    # 1. Check if ScriptSaveFolder parameter was explicitly provided
    if ($BoundParameters.ContainsKey('ScriptSaveFolder')) {
        $determinedSaveFolder = $BoundParameters['ScriptSaveFolder']
        Write-Log -Message "Get-ScriptSaveFolder: Using provided parameter value: '$determinedSaveFolder'" -Level DEBUG
    }
    # 2. If not provided, determine from InvocationInfo
    else {
        try {
            $scriptDir = Split-Path -Parent $InvocationInfo.MyCommand.Definition -ErrorAction Stop
            if (-not ([string]::IsNullOrWhiteSpace($scriptDir))) {
                $determinedSaveFolder = $scriptDir
                Write-Log -Message "Get-ScriptSaveFolder: Determined from script path: '$determinedSaveFolder'" -Level DEBUG
            } else {
                 Write-Log -Message "Get-ScriptSaveFolder: Split-Path returned empty/whitespace." -Level DEBUG
            }
        } catch {
            Write-Log -Message "Get-ScriptSaveFolder: Error splitting path from InvocationInfo: $($_.Exception.Message)" -Level WARN
            # Continue to fallback
        }
    }

    # 3. Fallback if still not determined (e.g., empty path from Split-Path, or parameter was provided but empty)
    if ([string]::IsNullOrWhiteSpace($determinedSaveFolder)) {
        Write-Log -Message "Get-ScriptSaveFolder: Could not determine path from parameter or invocation. Falling back to UserProfile path." -Level WARN
        $determinedSaveFolder = Join-Path -Path $UserProfilePath -ChildPath "UpdateLoxone" # Use parameter for fallback
        Write-Log -Message "Get-ScriptSaveFolder: Using fallback path: '$determinedSaveFolder'" -Level DEBUG
    }

    Write-Log -Message "Get-ScriptSaveFolder: Final determined path: '$determinedSaveFolder'" -Level INFO
    return $determinedSaveFolder
    } finally {
        Exit-Function # No change needed here, function name is correct
    }
}

function Get-ExecutableSignature { # Renamed from TestExecutableSignature
    [CmdletBinding()]
    param(
        # The path to the executable file to validate.
        [string]$ExePath
    )

    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Validating signature for '$ExePath'..." -Level INFO # Removed expected signature from log
    try {

    $result = [PSCustomObject]@{
        Status     = 'UnknownError' # Default status
        Thumbprint = $null
    }

    if (-not (Test-Path -Path $ExePath -PathType Leaf)) {
        Write-Log -Message "Executable file not found at '$ExePath'. Cannot validate signature." -Level WARN
        $result.Status = 'FileNotFound'
        return $result
    }

    try {
        $signatureInfo = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction Stop
        $result.Status = $signatureInfo.Status.ToString() # Store the status string

        if ($result.Status -eq 'Valid') {
            Write-Log -Message "Signature VALID: Authenticode status for '$ExePath' is 'Valid'." -Level INFO
            # Extract Thumbprint only if valid
            if ($null -ne $signatureInfo.SignerCertificate) {
                $result.Thumbprint = $signatureInfo.SignerCertificate.Thumbprint
                Write-Log -Message "Thumbprint: $($result.Thumbprint)" -Level DEBUG
            } else {
                Write-Log -Message "Signature status is Valid, but SignerCertificate object is null. Cannot retrieve thumbprint." -Level WARN
                $result.Status = 'ValidButNoCert' # Indicate a specific issue
            }
        } else {
            Write-Log -Message "Signature INVALID/OTHER: Authenticode status for '$ExePath' is '$($result.Status)'." -Level WARN
            # Thumbprint remains $null
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Log -Message "Signature check failed: File not found at '$ExePath'." -Level WARN
        $result.Status = 'FileNotFound' # Update status
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Message "Signature check failed for '$ExePath': $errorMessage" -Level WARN
        if ($errorMessage -like '*file is not digitally signed*') {
             Write-Log -Message "(File '$ExePath' is not digitally signed.)" -Level INFO
             $result.Status = 'NotSigned' # Specific status for not signed
        } else {
             $result.Status = 'CheckError' # General error during check
        }
    }

    # Return the result object containing Status and Thumbprint (or null)
    return $result
    # Removed misplaced closing brace for the outer try block
    } finally {
        Exit-Function
    }
}

# Helper function to format seconds into HH:mm:ss
function Format-TimeSpanFromSeconds {
    param(
        # The total number of seconds to format.
        [double]$TotalSeconds
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    try {
    # More robust check: Handle double Infinity, NaN, negative, AND the string "Infinity"
    if (($TotalSeconds -is [double] -and ([double]::IsInfinity($TotalSeconds) -or [double]::IsNaN($TotalSeconds) -or $TotalSeconds -lt 0)) `
        -or ($TotalSeconds -is [string] -and $TotalSeconds -eq 'Infinity')) {
        Write-Log -Message "Format-TimeSpanFromSeconds received invalid input: $TotalSeconds. Returning '--:--:--'." -Level DEBUG # Corrected function call
        return "--:--:--"
    }
    $ts = [System.TimeSpan]::FromSeconds($TotalSeconds)
    return "{0:00}:{1:00}:{2:00}" -f $ts.Hours, $ts.Minutes, $ts.Seconds
    } finally {
        Exit-Function # Corrected function call
    }
}

function Get-RedactedPassword {
    param(
        # The input string potentially containing "user:password@host".
        [Parameter(Mandatory=$true)][string]$InputString
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
        # Updated Regex: Handles optional user:pass@ part, ensures '@' is not in password
        $pattern = "^(?<scheme>http[s]?://)?(?:(?<user>[^:']+)(?::(?<pass>[^@/]*))?@)?(?<rest>.*)$" # Corrected Line: Removed invalid trailing text

        if ($InputString -match $pattern) {
            $userPart = $matches['user']
            $passPart = $matches['pass']
            $schemePart = $matches['scheme']
            $restPart = $matches['rest']

            if (-not ([string]::IsNullOrEmpty($passPart))) {
                $redactedPassword = "****" # Fixed redaction as per test requirement
                $redactedUrl = "${schemePart}${userPart}:${redactedPassword}@${restPart}"
                Write-Log -Message "GetRedactedPassword - Redacted URL: $redactedUrl" -Level DEBUG # Corrected function name in log
                return $redactedUrl
            } else {
                Write-Log -Message "Get-RedactedPassword - No password part found or password empty, returning original URL: $InputString" -Level DEBUG
                return $InputString
            }
        } else {
            Write-Log -Message "Get-RedactedPassword - Regex did not match, returning original URL: $InputString" -Level DEBUG
            return $InputString
        }
    } finally {
        Exit-Function
    }
} # Closing brace for GetRedactedPassword

# Helper function to convert a hashtable to a PowerShell expression string
# Needed for passing complex data to Invoke-AsCurrentUser script blocks
function ConvertTo-Expression {
    param($Object)
    if ($Object -is [hashtable]) {
        $items = @()
        foreach ($key in $Object.Keys) {
            $valueExpression = ConvertTo-Expression $Object[$key]
            $items += "'$key' = $valueExpression"
        }
        return "@{" + ($items -join '; ') + "}"
    } elseif ($Object -is [array]) {
        $items = @()
        foreach ($item in $Object) {
            $items += ConvertTo-Expression $item
        }
        return "@(" + ($items -join ', ') + ")"
    } elseif ($Object -is [string]) {
        # Escape single quotes within the string
        $escapedString = $Object -replace "'", "''"
        return "'$escapedString'"
    } elseif ($Object -is [bool]) {
        return "`$$($Object.ToString())" # $true or $false
    } elseif ($Object -is [int] -or $Object -is [double] -or $Object -is [float] -or $Object -is [decimal]) {
        return $Object.ToString() # Numbers don't need quotes
    } elseif ($null -eq $Object) {
        return "`$null"
    } else {
        # Fallback for other types - might need adjustment
        Write-Log -Message "ConvertTo-Expression: Unhandled type $($Object.GetType().FullName). Returning as string." -Level WARN
        $escapedString = $Object.ToString() -replace "'", "''"
        return "'$escapedString'"
    }
}

#endregion Utility Helpers

#region Version Helpers
function Convert-VersionString {
    param(
        # The version string to normalize (e.g., "14.0.3.28").
        [string]$VersionString
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber # Corrected function call
    try {
    if ([string]::IsNullOrWhiteSpace($VersionString)) {
        Write-Log -Message "Convert-VersionString: Input is null or empty, returning empty." -Level DEBUG
        return ""
    }
    # Regex to extract up to 4 numeric parts, allowing for leading zeros but treating them as decimal.
    # It also handles cases where versions might have fewer than 4 parts.
    if ($VersionString -match '^(\d{1,4})(?:\.(\d{1,4}))?(?:\.(\d{1,4}))?(?:\.(\d{1,4}))?.*$') {
        $major = if ($matches[1]) { [int]$matches[1] } else { 0 }
        $minor = if ($matches[2]) { [int]$matches[2] } else { 0 }
        $build = if ($matches[3]) { [int]$matches[3] } else { 0 }
        $revision = if ($matches[4]) { [int]$matches[4] } else { 0 }
        
        # Return in a consistent format, e.g., "15.6.5.13"
        # If a part was not present in the original string, it defaults to 0 here.
        # This creates a System.Version compatible string if all parts are present.
        $normalizedString = "$major.$minor.$build.$revision"
        Write-Log -Message ("Convert-VersionString: Input '{0}' normalized to '{1}'" -f $VersionString, $normalizedString) -Level DEBUG
        return $normalizedString
    }
    Write-Log -Message "Convert-VersionString: Input '{0}' did not match expected version pattern. Returning original." -Level WARN
    return $VersionString # Return original if no match
    } finally {
        Exit-Function # Corrected function call
    }
} # Closing brace for ConvertVersionString
#endregion Version Helpers

#region Application Info Helpers
function Get-AppVersionFromRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RegistryPath,

        [string]$AppNameValueName = 'shortcutname',
        [string]$InstallPathValueName = 'InstallLocation'
    )

    $ErrorActionPreference = 'Stop' # Ensure errors are caught by try/catch
    $output = @{
        ShortcutName    = $null
        InstallLocation = $null
        FileVersion     = $null # Revert: Only need FileVersion
        Error           = $null
    }

    try {
        Write-Verbose "Attempting to read registry key: $RegistryPath"
        # Check if the key exists first to provide a clearer error if not
        if (-not (Test-Path -Path $RegistryPath)) {
             $output.Error = "Registry key not found: $RegistryPath"
             Write-Warning $output.Error
             return $output
        }

        # Key exists, try to get properties
        $regProperties = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue # Use SilentlyContinue here in case specific values are missing but key exists

        # Check for specific values
        # Check for specific values using parameters
        if ($null -ne $regProperties -and $regProperties.PSObject.Properties.Name -contains $AppNameValueName) {
            $output.ShortcutName = $regProperties.$AppNameValueName # Use parameter variable for property access
            Write-Verbose "Found ${AppNameValueName}: $($output.ShortcutName)"
        } else {
            Write-Warning "Registry value '$AppNameValueName' not found at $RegistryPath."
            # Continue, but ShortcutName remains $null
        }
        if ($null -ne $regProperties -and $regProperties.PSObject.Properties.Name -contains $InstallPathValueName) {
            $output.InstallLocation = $regProperties.$InstallPathValueName # Use parameter variable for property access
            Write-Verbose "Found ${InstallPathValueName}: $($output.InstallLocation)"
        } else {
            $output.Error = "Required registry value '$InstallPathValueName' not found at $RegistryPath."
            Write-Warning $output.Error
            return $output # Cannot proceed without install location
        }

        # Validate InstallLocation path and get FileVersion
        if (-not ([string]::IsNullOrWhiteSpace($output.InstallLocation))) {
            # Check if the path is a directory first
            if (Test-Path -Path $output.InstallLocation -PathType Container) {
                Write-Verbose "InstallLocation '$($output.InstallLocation)' is a directory. Checking for executable..."
                # Check if ShortcutName is available to construct the executable name
                if (-not ([string]::IsNullOrWhiteSpace($output.ShortcutName))) {
                    # Use the value retrieved via AppNameValueName to construct the potential exe name
                    $potentialExeName = "$($output.ShortcutName).exe" # Assuming ShortcutName holds the base name
                    $potentialExePath = Join-Path -Path $output.InstallLocation -ChildPath $potentialExeName
                    Write-Verbose "Constructed potential executable path based on '$AppNameValueName': $potentialExePath"

                    # Check if the constructed executable path exists and is a file
                    if (Test-Path -Path $potentialExePath -PathType Leaf) {
                        Write-Verbose "Executable '$potentialExeName' found at '$potentialExePath'. Using this path."
                        # Update InstallLocation to the actual executable path for clarity and use
                        $output.InstallLocation = $potentialExePath
                        # Now, proceed to get the file version using the updated path
                        try {
                            Write-Verbose "Attempting to get file version for: $($output.InstallLocation)"
                            $fileItem = Get-Item -Path $output.InstallLocation -ErrorAction Stop # Re-add ErrorAction Stop
                            Start-Sleep -Millis 100 # Small delay before accessing properties
                            if ($null -ne $fileItem -and $null -ne $fileItem.VersionInfo) {
                                if (-not ([string]::IsNullOrWhiteSpace($fileItem.VersionInfo.FileVersion))) {
                                     $output.FileVersion = $fileItem.VersionInfo.FileVersion
                                     # Add build date from file's LastWriteTime
                                     if ($fileItem.LastWriteTime) {
                                         $buildDate = $fileItem.LastWriteTime.ToString("yyyy-MM-dd")
                                         $output.FileVersion = "$($output.FileVersion) (Build $buildDate)"
                                     }
                                     Write-Verbose "Found FileVersion: $($output.FileVersion)"
                                } else {
                                     $output.Error = "FileVersion property is null or empty for '$($output.InstallLocation)'."
                                     Write-Warning $output.Error
                                     # Log available VersionInfo properties for debugging
                                     Write-Log -Level WARN -Message "[App Version Check Debug] FileVersion null/empty. Available VersionInfo properties: $($fileItem.VersionInfo | Out-String)"
                                }
                            } else {
                                $output.Error = "Could not retrieve valid FileItem or VersionInfo property from '$($output.InstallLocation)'."
                                Write-Warning $output.Error
                            }
                        } catch {
                            $output.Error = "Failed to get file item or version info for '$($output.InstallLocation)': $($_.Exception.Message)"
                            Write-Warning $output.Error
                        }
                    } else {
                        # Executable (derived from AppNameValueName) not found in the directory
                        $output.Error = "Executable '$potentialExeName' (derived from '$AppNameValueName') not found in directory '$($output.InstallLocation)'."
                        Write-Warning $output.Error
                    }
                } else {
                    # AppNameValueName is missing, cannot construct executable path
                    $output.Error = "InstallLocation '$($output.InstallLocation)' is a directory, but '$AppNameValueName' is missing from registry, cannot determine executable name."
                    Write-Warning $output.Error
                }
            } elseif (Test-Path -Path $output.InstallLocation -PathType Leaf) {
                # Original path is a file, proceed as before
                Write-Verbose "InstallLocation '$($output.InstallLocation)' is a file. Proceeding to get version."
                try {
                    Write-Verbose "Attempting to get file version for: $($output.InstallLocation)"
                    $fileItem = Get-Item -Path $output.InstallLocation -ErrorAction Stop # Re-add ErrorAction Stop
                    Start-Sleep -Millis 100 # Small delay before accessing properties
                    if ($null -ne $fileItem -and $null -ne $fileItem.VersionInfo) {
                        if (-not ([string]::IsNullOrWhiteSpace($fileItem.VersionInfo.FileVersion))) {
                             $output.FileVersion = $fileItem.VersionInfo.FileVersion
                             # Add build date from file's LastWriteTime
                             if ($fileItem.LastWriteTime) {
                                 $buildDate = $fileItem.LastWriteTime.ToString("yyyy-MM-dd")
                                 $output.FileVersion = "$($output.FileVersion) (Build $buildDate)"
                             }
                             Write-Verbose "Found FileVersion: $($output.FileVersion)"
                        } else {
                             $output.Error = "FileVersion property is null or empty for '$($output.InstallLocation)'."
                             Write-Warning $output.Error
                             # Log available VersionInfo properties for debugging
                             Write-Log -Level WARN -Message "[App Version Check Debug] FileVersion null/empty. Available VersionInfo properties: $($fileItem.VersionInfo | Out-String)"
                        }
                    } else {
                        $output.Error = "Could not retrieve valid FileItem or VersionInfo property from '$($output.InstallLocation)'."
                        Write-Warning $output.Error
                    }
                } catch {
                    $output.Error = "Failed to get file item or version info for '$($output.InstallLocation)': $($_.Exception.Message)"
                    Write-Warning $output.Error
                }
            } else {
                # Path is neither a valid directory (containing the exe derived from AppNameValueName) nor a valid file
                $output.Error = "Path specified in registry via '$InstallPathValueName' ('$($output.InstallLocation)') is not a valid file or a directory containing the expected executable (derived from '$AppNameValueName')."
                Write-Warning $output.Error
            }
        } else {
             $output.Error = "Registry value '$InstallPathValueName' is empty or whitespace."
             Write-Warning $output.Error
        }

    } catch {
        # Catch errors from Get-ItemProperty if it failed unexpectedly, or other issues
        $output.Error = "An unexpected error occurred: $($_.Exception.Message)"
        Write-Warning $output.Error
    } finally {
        $ErrorActionPreference = 'Continue' # Reset error preference to default
    }

    return $output
}
#endregion Application Info Helpers


#region CRC32 Logic
# --- Initialize CRC32 Class ---
function Initialize-CRC32Type {
    [CmdletBinding()]
    param()

    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
        # Check if type already exists before defining source and adding
        if (([System.Management.Automation.PSTypeName]'CRC32').Type) {
            Write-Log -Message "CRC32 type already exists. Initialization skipped." -Level DEBUG
            return
        }

        Write-Log -Message "CRC32 type not found. Defining and adding..." -Level DEBUG
        $Source = @"
using System;
using System.IO;

public static class CRC32
{
    private static readonly uint[] table = GenerateTable();
    private const uint Poly = 0xEDB88320; // Standard CRC32 polynomial (reversed)

    private static uint[] GenerateTable()
    {
        uint[] createTable = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) == 1)
                    c = (c >> 1) ^ Poly;
                else
                    c = c >> 1;
            }
            createTable[i] = c;
        }
        return createTable;
    }

    public static uint Compute(byte[] bytes)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in bytes)
        {
            crc = (crc >> 8) ^ table[(crc & 0xFF) ^ b];
        }
        return ~crc; // Final XOR
    }
}
"@
        try {
            Write-Log -Message "Attempting Add-Type for CRC32..." -Level DEBUG
            Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
            Write-Log -Message "Add-Type for CRC32 completed successfully." -Level DEBUG
            # Verify type exists immediately after adding
            if (([System.Management.Automation.PSTypeName]'CRC32').Type) {
                Write-Log -Message "Verified CRC32 type exists immediately after Add-Type." -Level DEBUG
            } else {
                Write-Log -Message "CRITICAL: CRC32 type DOES NOT exist immediately after Add-Type call succeeded!" -Level ERROR
            }
        } catch {
            Write-Error "Error adding CRC32 type: $($_.Exception.Message)"
            throw "Failed to add necessary CRC32 type." # Re-throw critical error
        }
    } finally {
        Exit-Function
    }
}


function Get-CRC32 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($InputFile)
        Write-Log -Message "Read $($fileBytes.Length) bytes from file '$InputFile'." -Level DEBUG
        # Check if CRC32 type exists right before using it

#region XML Signature Verification (Removed - Complex and causing module load issues)
#endregion XML Signature Verification

        if (([System.Management.Automation.PSTypeName]'CRC32').Type) {
            Write-Log -Message "CRC32 type exists just before calling Compute." -Level DEBUG
        } else {
            Write-Log -Message "ERROR: CRC32 type DOES NOT exist just before calling Compute for file '$InputFile'." -Level ERROR
            # Optionally throw here if this is unexpected, or let the next line fail naturally
            # throw "CRC32 type not found when needed in Get-CRC32 function."

            # Export is handled by the main module manifest (LoxoneUtils.psd1)
        }
        $crc = [CRC32]::Compute($fileBytes)
        $crcString = $crc.ToString("X8")
        Write-Log -Message "Calculated CRC32 for '$InputFile': ${crcString}" -Level DEBUG
        return $crcString
    } catch {
        Write-Log -Message "Error calculating CRC32 for ${InputFile}: $($_.Exception.Message)" -Level ERROR
        throw $_
    } finally {
        Exit-Function
    }
}
#endregion CRC32 Logic
#endregion CRC32 Logic

function Get-InvocationTrace {
    [CmdletBinding()]
    param()
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $stack   = Get-PSCallStack         # always safe
        
        # Performance optimization: Use Get-Process instead of Get-CimInstance for speed
        $self = $null
        $parent = $null
        $parentProcessId = $null
        
        try {
            $self = Get-Process -Id $PID -ErrorAction Stop
            $parentProcessId = if ($self.Parent) { $self.Parent.Id } else { $null }
            $parent = if ($parentProcessId) { Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue } else { $null }
            
            # Note: Get-Process doesn't expose CommandLine, so we need to use alternative method
            $thisProcessCLI = if ($self) { "Process: $($self.Name) (PID: $PID)" } else { "PID $PID not found" }
            $parentProcessCLI = if ($parent) { "Parent: $($parent.Name) (PID: $parentProcessId)" } elseif ($parentProcessId) { "Parent PID $parentProcessId found but process unavailable" } else { "Parent process ID not available"}
        } catch {
            # Fallback to slower CIM query only if Get-Process fails or we need CommandLine
            Write-Log -Message "Get-Process failed for invocation trace, falling back to CIM query: $($_.Exception.Message)" -Level DEBUG
            $self    = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue
            $parentProcessId = if ($self) { $self.ParentProcessId } else { $null }
            $parent  = if ($parentProcessId) { Get-CimInstance Win32_Process -Filter "ProcessId=$parentProcessId" -ErrorAction SilentlyContinue } else { $null }
            
            $thisProcessCLI = if ($self) { $self.CommandLine } else { "PID $PID not found or CommandLine unavailable" }
            $parentProcessCLI = if ($parent) { $parent.CommandLine } elseif ($parentProcessId) { "Parent PID $parentProcessId not found or CommandLine unavailable" } else { "Parent process ID not available"}
        }

        [pscustomobject]@{
            CallStack       = $stack.Command
            ThisProcessCLI  = $thisProcessCLI
            ParentProcessCLI= $parentProcessCLI
        }
    }
    catch {
        Write-Log -Message "While collecting invocation info: $($_.Exception.Message)" -Level WARN
        # Return an object with empty/error values so the calling code doesn't break
        [pscustomobject]@{
            CallStack       = @("Error collecting call stack: $($_.Exception.Message)")
            ThisProcessCLI  = "Error collecting this process CLI: $($_.Exception.Message)"
            ParentProcessCLI= "Error collecting parent process CLI: $($_.Exception.Message)"
        }
    } finally {
        Exit-Function
    }
}

function Test-ExistingFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [string]$ExpectedCRC,

        [Parameter(Mandatory=$false)]
        [long]$ExpectedSize, # Changed to long to match file sizes

        [Parameter(Mandatory=$false)]
        [bool]$EnableCRC = $true # Default to true as per original script logic
    )

    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Message "Test-ExistingFile: Validating '$FilePath'. EnableCRC: $EnableCRC, ExpectedSize: $ExpectedSize, ExpectedCRC: $ExpectedCRC" -Level DEBUG

    try {
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            Write-Log -Message "Test-ExistingFile: File not found at '$FilePath'." -Level INFO
            return $false
        }

        $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop

        # Size Check (always perform if ExpectedSize is provided and greater than 0)
        if ($PSBoundParameters.ContainsKey('ExpectedSize') -and $ExpectedSize -gt 0) {
            if ($fileInfo.Length -ne $ExpectedSize) {
                Write-Log -Message "Test-ExistingFile: Size mismatch for '$FilePath'. Expected: $ExpectedSize, Actual: $($fileInfo.Length)." -Level WARN
                return $false
            }
            Write-Log -Message "Test-ExistingFile: Size check PASSED for '$FilePath'." -Level DEBUG
        } else {
            Write-Log -Message "Test-ExistingFile: Skipping size check (ExpectedSize not provided or not positive)." -Level DEBUG
        }

        # CRC Check (only if EnableCRC is true and ExpectedCRC is provided)
        if ($EnableCRC -and $PSBoundParameters.ContainsKey('ExpectedCRC') -and -not ([string]::IsNullOrWhiteSpace($ExpectedCRC))) {
            Write-Log -Message "Test-ExistingFile: Performing CRC check for '$FilePath'." -Level DEBUG
            Initialize-CRC32Type # Ensure CRC32 type is loaded
            $actualCRC = Get-CRC32 -InputFile $FilePath -ErrorAction SilentlyContinue
            if ($null -eq $actualCRC) {
                Write-Log -Message "Test-ExistingFile: Get-CRC32 returned null for '$FilePath'. CRC check failed." -Level WARN
                return $false
            }
            if ($actualCRC.Trim().ToUpperInvariant() -ne $ExpectedCRC.Trim().ToUpperInvariant()) {
                Write-Log -Message "Test-ExistingFile: CRC mismatch for '$FilePath'. Expected: '$ExpectedCRC', Actual: '$actualCRC'." -Level WARN
                return $false
            }
            Write-Log -Message "Test-ExistingFile: CRC check PASSED for '$FilePath'." -Level DEBUG
        } else {
            Write-Log -Message "Test-ExistingFile: Skipping CRC check (EnableCRC is false or ExpectedCRC not provided)." -Level DEBUG
        }

        Write-Log -Message "Test-ExistingFile: All checks passed for '$FilePath'." -Level INFO
        return $true

    } catch {
        Write-Log -Message "Test-ExistingFile: Error during validation of '$FilePath': $($_.Exception.Message)" -Level ERROR
        return $false
    } finally {
        Exit-Function
    }
}

# Ensure functions are available (though NestedModules in PSD1 is the primary mechanism)
Export-ModuleMember -Function Get-ScriptSaveFolder, Get-ExecutableSignature, Format-TimeSpanFromSeconds, Convert-VersionString, Get-RedactedPassword, Initialize-CRC32Type, Get-CRC32, ConvertTo-Expression, Get-AppVersionFromRegistry, Get-InvocationTrace, Test-ExistingFile # Added Get-AppVersionFromRegistry and Test-ExistingFile
# NOTE: Explicit Export-ModuleMember is now enabled to ensure functions are available for the manifest to re-export.