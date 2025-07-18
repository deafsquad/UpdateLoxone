# Module for Loxone Update Script MS Interaction Functions

#region Internal Helper Functions

# Wrapper function for Invoke-WebRequest to enable mocking in tests
# Exported to allow mocking from test files
function Invoke-MiniserverWebRequest {
    [CmdletBinding()]
    param(
        [hashtable]$Parameters
    )
    
    # Check for test environment first
    if ($env:PESTER_TEST_RUN -eq "1" -or $Global:IsTestRun -eq $true -or $env:LOXONE_TEST_MODE -eq "1") {
        Write-Verbose "Test mode detected - returning mock web response"
        
        # Check what type of request this is based on the URI
        if ($Parameters.Uri -match '/dev/cfg/version|/dev/cfg/api|/dev/cfg/updatelevel') {
            # Version/API request - return XML format expected by version check
            return @{
                StatusCode = 200
                Content = '<LL control="test" value="14.0.0.0" Code="200"/>'
                Headers = @{}
            }
        } elseif ($Parameters.Uri -match '/dev/sys/autoupdate') {
            # Update trigger request
            return @{
                StatusCode = 200
                Content = '<LL control="test" value="1" Code="200"/>'
                Headers = @{}
            }
        } else {
            # Other requests - return generic response
            return @{
                StatusCode = 200
                Content = '{"status":"ok"}'
                Headers = @{}
            }
        }
    }
    
    # This wrapper allows mocking in tests while maintaining the same functionality
    # PowerShell 6+ requires explicit TLS for HTTPS
    if ($PSVersionTable.PSVersion.Major -ge 6 -and $Parameters.Uri -like "https://*") {
        # Add TLS 1.2 for PS Core if not already specified
        if (-not $Parameters.ContainsKey('SslProtocol')) {
            Invoke-WebRequest @Parameters -SslProtocol Tls12
        } else {
            Invoke-WebRequest @Parameters
        }
    } else {
        # PS 5.1 or HTTP requests
        Invoke-WebRequest @Parameters
    }
}

#endregion

#region MS Update Logic

function Get-MiniserverVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MSEntry,

        [Parameter()]
        [switch]$SkipCertificateCheck,

        [Parameter()]
        [int]$TimeoutSec = 1 # Default timeout
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    Enter-Function -FunctionName $FunctionName -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level DEBUG -Message "Entering function '$($FunctionName)'."
    Write-Log -Level DEBUG -Message "Parameters for '$($FunctionName)':"
    Write-Log -Level DEBUG -Message ("  MSEntry (original): '{0}'" -f ($MSEntry -replace "([Pp]assword=)[^;]+", '$1********'))
    Write-Log -Level DEBUG -Message ("  SkipCertificateCheck: {0}" -f $SkipCertificateCheck.IsPresent)
    Write-Log -Level DEBUG -Message ("  TimeoutSec: {0}" -f $TimeoutSec)

    $result = [PSCustomObject]@{
        MSIP       = "Unknown"
        RawVersion = $null
        Version    = $null
        Error      = $null
    }

    $msIP = $null; $versionUri = $null; $credential = $null
    $originalCallback = $null; $callbackChanged = $false
    $oldProgressPreference = $ProgressPreference

    try {
        $ProgressPreference = 'SilentlyContinue'

        $entryToParse = $MSEntry
        if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
        if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
        
        # Use UriBuilder for scheme, host, and constructing the final version check URI
        $uriBuilderForHostAndPath = [System.UriBuilder]$entryToParse # This parses the whole string initially
        $result.MSIP = $uriBuilderForHostAndPath.Host
        $msIP = $result.MSIP
        # $parsedScheme = $uriBuilderForHostAndPath.Scheme # Scheme will be determined later based on HTTP/HTTPS attempts

        # Manually parse username and password from the original $entryToParse to avoid URL-decoding issues with UriBuilder.Password
        # These will be used specifically for constructing the Basic Auth header.
        $usernameForAuthHeader = $null
        $passwordForAuthHeader = $null
        if ($entryToParse -match '^(?<scheme>[^:]+)://(?<credentials>[^@]+)@(?<hostinfo>.+)$') {
            $credPartFromFile = $Matches.credentials
            if ($credPartFromFile -match '^(?<user>[^:]+):(?<pass>.+)$') {
                $usernameForAuthHeader = $Matches.user
                $passwordForAuthHeader = $Matches.pass # This is the literal password string from the input
                Write-Log -Level DEBUG -Message ("$($FunctionName): Manually parsed Username for Auth Header: '{0}'" -f $usernameForAuthHeader)
                Write-Log -Level DEBUG -Message ("$($FunctionName): Manually parsed Password for Auth Header (length): {0}" -f $passwordForAuthHeader.Length)
            } else {
                Write-Log -Level WARN -Message ("$($FunctionName): Could not manually parse user:pass from credentials part: '$credPartFromFile'")
            }
        } else {
            Write-Log -Level DEBUG -Message ("$($FunctionName): MSEntry '$($entryToParse -replace "([Pp]assword=)[^;]+", '$1********')' does not seem to contain user:pass@host format for direct manual parsing for Auth Header.")
        }

        # Create $credential object using UriBuilder's properties.
        # This $credential object might be used by Invoke-WebRequest for other auth mechanisms (e.g. NTLM on HTTPS)
        # or if our manual parsing for the Auth Header fails.
        # Note: $uriBuilderForHostAndPath.Password IS URL-decoded.
        if (-not ([string]::IsNullOrWhiteSpace($uriBuilderForHostAndPath.UserName))) {
            $securePasswordFromUriBuilder = $uriBuilderForHostAndPath.Password | ConvertTo-SecureString -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($uriBuilderForHostAndPath.UserName, $securePasswordFromUriBuilder)
            Write-Log -Level DEBUG -Message ("$($FunctionName): UriBuilder.UserName (for general \$credential obj): '{0}'" -f $uriBuilderForHostAndPath.UserName)
            Write-Log -Level DEBUG -Message ("$($FunctionName): UriBuilder.Password (for general \$credential obj, URL-decoded, length): {0}" -f $uriBuilderForHostAndPath.Password.Length)
            Write-Log -Level DEBUG -Message ("$($FunctionName): General \$credential object created for user: '{0}'" -f $credential.UserName)
        } else {
            Write-Log -Level DEBUG -Message ("$($FunctionName): UriBuilder.UserName is NULL/Whitespace. No general \$credential object created from UriBuilder properties.")
        }
        
        # If $usernameForAuthHeader is still null (manual parsing failed or not applicable) AND $credential exists,
        # populate $usernameForAuthHeader from $credential.UserName.
        # $passwordForAuthHeader should ideally remain the manually parsed one for Basic Auth.
        if ([string]::IsNullOrEmpty($usernameForAuthHeader) -and $credential) {
            $usernameForAuthHeader = $credential.UserName
            Write-Log -Level DEBUG -Message ("$($FunctionName): Populated \$usernameForAuthHeader from \$credential.UserName ('$usernameForAuthHeader') as manual parse was empty/not applicable.")
            # If $passwordForAuthHeader is also empty here, the Basic Auth header might rely on $credential.GetNetworkCredential().Password which is URL-decoded.
        }

        # Construct the $versionUri (e.g., http://e1lox/dev/cfg/version or https://e1lox/dev/cfg/version)
        # The scheme for $versionUri will be determined by the HTTPS/HTTP logic later.
        # For now, build it based on the original scheme and host, then clear userinfo for this specific URI.
        $tempUriBuilderForVersionPath = [System.UriBuilder]$entryToParse
        $tempUriBuilderForVersionPath.Path = "/dev/cfg/version"
        $tempUriBuilderForVersionPath.Password = $null
        $tempUriBuilderForVersionPath.UserName = $null
        $versionUri = $tempUriBuilderForVersionPath.Uri.AbsoluteUri # This will be the base, scheme might change

        Write-Log -Message ("$($FunctionName): Checking MS version for '{0}' (parsed host)." -f $msIP) -Level DEBUG
        Write-Log -Level DEBUG -Message ("$($FunctionName): Base URI for version check (scheme may change): {0}" -f $versionUri)
        
        if (-not [string]::IsNullOrEmpty($usernameForAuthHeader) -and -not [string]::IsNullOrEmpty($passwordForAuthHeader)) {
            Write-Log -Level DEBUG -Message ("$($FunctionName): Credentials intended FOR BASIC AUTH HEADER - User: '{0}', Password (literal from input) Length: {1}" -f $usernameForAuthHeader, $passwordForAuthHeader.Length)
        } elseif ($credential) {
             Write-Log -Level DEBUG -Message ("$($FunctionName): General \$credential object exists (user: '{0}'). Manual parsing for Auth header might have been incomplete or not applicable." -f $credential.UserName)
        } else {
            Write-Log -Level DEBUG -Message ("$($FunctionName): No credentials available from manual parsing or UriBuilder for Authorization.")
        }
        if ($SkipCertificateCheck.IsPresent) {
            $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $callbackChanged = $true
            Write-Log -Message ("Get-MiniserverVersion: SSL certificate check temporarily disabled for {0}." -f $msIP) -Level DEBUG
        }

        $responseObject = $null
        $iwrParams = @{ Uri = $versionUri; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop'; Method = 'Get' }
        if ($credential) { $iwrParams.Credential = $credential }

        try { # Main try for Invoke-WebRequest logic
            # Determine the scheme from the original $entryToParse via $uriBuilderForHostAndPath
            $originalScheme = $uriBuilderForHostAndPath.Scheme
            Write-Log -Level DEBUG -Message ("$($FunctionName): Original scheme parsed from MSEntry: '$originalScheme'")

            if ($originalScheme -eq 'http') {
                # Original entry is HTTP, go straight to HTTP with manual auth
                Write-Log -Level DEBUG -Message ("$($FunctionName): Original scheme is HTTP. Proceeding directly with HTTP call.")
                $iwrParams.Uri = $versionUri # $versionUri is already http://.../dev/cfg/version
                
                # Ensure $iwrParams.Uri is explicitly HTTP
                if (($iwrParams.Uri -is [string]) -and $iwrParams.Uri.StartsWith('https://')) {
                    $iwrParams.Uri = $iwrParams.Uri -replace '^https://', 'http://'
                } elseif (($iwrParams.Uri -is [System.Uri]) -and $iwrParams.Uri.Scheme -eq 'https') {
                     $httpDirectUriBuilder = [System.UriBuilder]$iwrParams.Uri
                     $httpDirectUriBuilder.Scheme = 'http'; $httpDirectUriBuilder.Port = -1
                     $iwrParams.Uri = $httpDirectUriBuilder.Uri.AbsoluteUri
                }
                Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Direct: Final URI for Invoke-WebRequest: $($iwrParams.Uri)")

                if (-not [string]::IsNullOrEmpty($usernameForAuthHeader) -and -not [string]::IsNullOrEmpty($passwordForAuthHeader)) {
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Direct: Constructing Authorization header using MANUALLY PARSED User: '{0}' and Password (length: {1})." -f $usernameForAuthHeader, $passwordForAuthHeader.Length)
                    $Pair = "${usernameForAuthHeader}:${passwordForAuthHeader}"
                    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Pair)
                    $Base64Auth = [System.Convert]::ToBase64String($Bytes)
                    $iwrParams.Headers = @{ Authorization = "Basic $Base64Auth" }
                    $iwrParams.Remove('Credential'); $iwrParams.Credential = $null
                    $iwrParams.Remove('AllowUnencryptedAuthentication')
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Direct: Using manual Authorization header. Ensured -Credential is nulled and -AllowUnencryptedAuthentication removed.")
                } else { # Should not happen if credentials are in MSEntry, but as a safeguard
                    Write-Log -Level WARN -Message ("$($FunctionName): HTTP Direct: Manually parsed credentials for Auth Header are missing. If \$credential object exists, IWR might use it, but this could lead to AllowUnencryptedAuthentication prompt if not handled by manual header.")
                    # If $credential exists, IWR might try to use it. If not, it's an unauthenticated request.
                    # We prefer the manual header, so this path indicates an issue with parsing or input.
                    # To be safe, if we have no manual header, remove any existing $iwrParams.Headers to avoid sending a stale one.
                    $iwrParams.Remove('Headers')
                    if ($credential) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Direct: \$credential object exists. IWR might attempt to use it. Adding AllowUnencryptedAuthentication as a precaution if PSVersion >= 6.")
                        if ($PSVersionTable.PSVersion.Major -ge 6) { $iwrParams.AllowUnencryptedAuthentication = $true }
                    } else {
                         $iwrParams.Remove('Credential'); $iwrParams.Credential = $null
                         $iwrParams.Remove('AllowUnencryptedAuthentication')
                    }
                }
                $iwrParams.UseBasicParsing = $true
                Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Direct: iwrParams before invoke: $($iwrParams | Out-String)")
                $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParams
                Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Direct: Invoke-MiniserverWebRequest successful. StatusCode: {0}" -f $responseObject.StatusCode)

            } elseif ($originalScheme -eq 'https') {
                # Original entry is HTTPS, try HTTPS first (using $credential object if present)
                Write-Log -Level DEBUG -Message ("$($FunctionName): Original scheme is HTTPS. Attempting HTTPS connection first.")
                $iwrParams.Uri = $versionUri # $versionUri is already https://.../dev/cfg/version
                # $iwrParams.Credential would have been set earlier if $credential was created.
                # For HTTPS, using $credential object is standard.
                Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS Attempt: iwrParams before invoke: $($iwrParams | Out-String)")
                try {
                    # Use wrapper function which handles PS version differences
                    $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParams
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS Attempt: Invoke-MiniserverWebRequest successful. StatusCode: {0}" -f $responseObject.StatusCode)
                } catch { # Catch for primary HTTPS attempt
                    $CaughtPrimaryHttpsError = $_
                    Write-Log -Level WARN -Message ("$($FunctionName): Primary HTTPS connection to '{0}' failed ('{1}')." -f $iwrParams.Uri, $CaughtPrimaryHttpsError.Exception.Message.Split([Environment]::NewLine)[0])
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Full Exception for primary HTTPS failure: $($CaughtPrimaryHttpsError.Exception.ToString())")
                    # No automatic HTTP fallback here if original was HTTPS, let it error out or be handled by outer catch.
                    # If a specific fallback to HTTP for an originally HTTPS entry is desired, it would be added here.
                    # For now, if HTTPS fails, the error from this catch will propagate.
                    throw $CaughtPrimaryHttpsError
                }
            } else {
                throw ("$($FunctionName): Unknown original scheme '$originalScheme' from MSEntry '$($entryToParse -replace "([Pp]assword=)[^;]+", '$1********')'")
            }

            # Process response if any was successful
            if ($responseObject) {
                $xmlResponse = [xml]$responseObject.Content
                $result.RawVersion = $xmlResponse.LL.value
                if ([string]::IsNullOrEmpty($result.RawVersion)) {
                    Write-Log -Level WARN -Message ("$($FunctionName): Could not parse version from MS '{0}' (LL.value empty in response: '$($responseObject.Content | Select-String -Pattern '^.{0,200}' | ForEach-Object {$_.Matches[0].Value})')." -f $msIP)
                    throw ("Could not parse version from MS '{0}' (LL.value empty)." -f $msIP)
                }
                $result.Version = Convert-VersionString $result.RawVersion
                Write-Log -Level DEBUG -Message ("$($FunctionName): Extracted Version: '{0}', RawVersion from XML: '{1}' for MS: '{2}'" -f $result.Version, $result.RawVersion, $msIP)
            } else {
                Write-Log -Level WARN -Message ("$($FunctionName): Failed to get a valid response object for version check of MS '{0}' after all attempts." -f $msIP)
                throw ("Failed to get a valid response for version check of MS '{0}' after all attempts." -f $msIP)
            }
        } catch {
            $CaughtIwrError = $_
            $result.Error = ("Error during Invoke-WebRequest for '{0}': {1}" -f $msIP, $CaughtIwrError.Exception.Message.Split([Environment]::NewLine)[0])
            Write-Log -Level WARN -Message $result.Error
            Write-Log -Level DEBUG -Message ("$($FunctionName): Full Invoke-WebRequest error details for MS '{0}': {1}" -f $msIP, $CaughtIwrError.Exception.ToString())
            if ($CaughtIwrError.Exception -is [System.Net.WebException] -and $null -ne $CaughtIwrError.Exception.Response) {
                 Write-Log -Level DEBUG -Message ("$($FunctionName): WebException Details - Status: {0}, Description: {1}" -f $CaughtIwrError.Exception.Response.StatusCode, $CaughtIwrError.Exception.Response.StatusDescription)
            }
        }
    } catch {
        $OuterCaughtError = $_
        $result.Error = ("Outer error in Get-MiniserverVersion for '{0}': {1}" -f $msIP, $OuterCaughtError.Exception.Message.Split([Environment]::NewLine)[0])
        Write-Log -Level WARN -Message $result.Error
        Write-Log -Level DEBUG -Message ("$($FunctionName): Full outer error details for MS '{0}': {1}" -f $msIP, $OuterCaughtError.Exception.ToString())
    } finally {
        $ProgressPreference = $oldProgressPreference
        if ($callbackChanged) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
            Write-Log -Message ("$($FunctionName): Restored SSL certificate validation callback for {0}." -f $msIP) -Level DEBUG
        }
        Write-Log -Level DEBUG -Message ("$($FunctionName): Exiting. Final version for MS '{0}': '{1}', Error: '{2}'" -f $result.MSIP, $result.Version, $result.Error)
        Exit-Function
    }
    return $result
return $result
}

function Test-LoxoneMiniserverUpdateLevel {
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MSEntry,

    [Parameter(Mandatory = $true)]
    [string]$ConfiguredUpdateChannel, # e.g., "Release", "Beta", "Test"

    [Parameter()]
    [switch]$SkipCertificateCheck,

    [Parameter()]
    [int]$TimeoutSec = 1 # Default timeout
)
$FunctionName = $MyInvocation.MyCommand.Name
Enter-Function -FunctionName $FunctionName -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
Write-Log -Level DEBUG -Message "Entering function '$($FunctionName)'."
Write-Log -Level DEBUG -Message "Parameters for '$($FunctionName)':"
Write-Log -Level DEBUG -Message ("  MSEntry (original): '{0}'" -f ($MSEntry -replace "([Pp]assword=)[^;]+", '$1********'))
Write-Log -Level DEBUG -Message ("  ConfiguredUpdateChannel: {0}" -f $ConfiguredUpdateChannel)
Write-Log -Level DEBUG -Message ("  SkipCertificateCheck: {0}" -f $SkipCertificateCheck.IsPresent)
Write-Log -Level DEBUG -Message ("  TimeoutSec: {0}" -f $TimeoutSec)

$msIP = "Unknown"; $credential = $null; $usernameForAuthHeader = $null; $passwordForAuthHeader = $null
$originalCallback = $null; $callbackChanged = $false
$oldProgressPreference = $ProgressPreference

try {
    $ProgressPreference = 'SilentlyContinue'

    $entryToParse = $MSEntry
    if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
    
    $uriBuilderForHostAndPath = [System.UriBuilder]$entryToParse
    $msIP = $uriBuilderForHostAndPath.Host
    
    # Manually parse username and password for Basic Auth header
    if ($entryToParse -match '^(?<scheme>[^:]+)://(?<credentials>[^@]+)@(?<hostinfo>.+)$') {
        $credPartFromFile = $Matches.credentials
        if ($credPartFromFile -match '^(?<user>[^:]+):(?<pass>.+)$') {
            $usernameForAuthHeader = $Matches.user
            $passwordForAuthHeader = $Matches.pass
        }
    }

    # Fallback to UriBuilder's properties if manual parsing failed, for $credential object
    if (-not ([string]::IsNullOrWhiteSpace($uriBuilderForHostAndPath.UserName))) {
        $securePasswordFromUriBuilder = $uriBuilderForHostAndPath.Password | ConvertTo-SecureString -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($uriBuilderForHostAndPath.UserName, $securePasswordFromUriBuilder)
        if ([string]::IsNullOrEmpty($usernameForAuthHeader)) { $usernameForAuthHeader = $credential.UserName } # Populate if manual parse was empty
    }

    # Determine the target update level string for comparison
    $expectedUpdateLevelValue = $ConfiguredUpdateChannel
    if ($ConfiguredUpdateChannel -eq "Test") {
        $expectedUpdateLevelValue = "Alpha"
        Write-Log -Level DEBUG -Message ("$($FunctionName): Translated ConfiguredUpdateChannel 'Test' to 'Alpha' for comparison.")
    }

    # Construct URI for /dev/cfg/updatelevel
    $updateLevelUriBuilder = [System.UriBuilder]$entryToParse # Start with the full entry
    $updateLevelUriBuilder.Path = "/dev/cfg/updatelevel"
    $updateLevelUriBuilder.Password = $null # Clear userinfo for the request URI itself
    $updateLevelUriBuilder.UserName = $null
    
    # The scheme (http/https) will be handled by the request logic below
    $baseUpdateLevelUri = $updateLevelUriBuilder.Uri.AbsoluteUri

    Write-Log -Message ("$($FunctionName): Checking MS updatelevel for '{0}' (parsed host)." -f $msIP) -Level DEBUG
    
    if ($SkipCertificateCheck.IsPresent) {
        $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $callbackChanged = $true
    }

    $responseObject = $null
    $iwrParams = @{ TimeoutSec = $TimeoutSec; ErrorAction = 'Stop'; Method = 'Get' }
    # Auth header construction logic (similar to Get-MiniserverVersion)
    # Will try HTTPS first, then HTTP if original scheme was HTTP, or stick to HTTPS if original was HTTPS

    $originalScheme = $uriBuilderForHostAndPath.Scheme
    Write-Log -Level DEBUG -Message ("$($FunctionName): Original scheme parsed from MSEntry: '$originalScheme'")

    $schemesToTry = @()
    if ($originalScheme -eq 'http') {
        $schemesToTry = 'https', 'http' # Try HTTPS first even if original is HTTP
    } elseif ($originalScheme -eq 'https') {
        $schemesToTry = 'https'
    } else {
        throw ("$($FunctionName): Unknown original scheme '$originalScheme' from MSEntry.")
    }

    $lastException = $null
    foreach ($scheme in $schemesToTry) {
        $currentUriBuilder = [System.UriBuilder]$baseUpdateLevelUri
        $currentUriBuilder.Scheme = $scheme
        if ($scheme -eq 'http') { $currentUriBuilder.Port = if ($uriBuilderForHostAndPath.Port -ne -1 -and $uriBuilderForHostAndPath.Scheme -eq 'http') { $uriBuilderForHostAndPath.Port } else { -1 } } # Use original port for http if specified, else default
        elseif ($scheme -eq 'https') { $currentUriBuilder.Port = if ($uriBuilderForHostAndPath.Port -ne -1 -and $uriBuilderForHostAndPath.Scheme -eq 'https') { $uriBuilderForHostAndPath.Port } else { -1 } } # Use original port for https if specified, else default
        
        $iwrParams.Uri = $currentUriBuilder.Uri.AbsoluteUri
        Write-Log -Level DEBUG -Message ("$($FunctionName): Attempting $scheme connection to $($iwrParams.Uri)")

        # Clear previous auth settings for this attempt
        $iwrParams.Remove('Headers')
        $iwrParams.Remove('Credential')
        $iwrParams.Credential = $null
        $iwrParams.Remove('AllowUnencryptedAuthentication')
        $iwrParams.Remove('SslProtocol') # Remove SslProtocol for HTTP attempts
        $iwrParams.Remove('UseBasicParsing')


        if (-not [string]::IsNullOrEmpty($usernameForAuthHeader) -and -not [string]::IsNullOrEmpty($passwordForAuthHeader)) {
            $Pair = "${usernameForAuthHeader}:${passwordForAuthHeader}"
            $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Pair)
            $Base64Auth = [System.Convert]::ToBase64String($Bytes)
            $iwrParams.Headers = @{ Authorization = "Basic $Base64Auth" }
            if ($scheme -eq 'http') {
                # For HTTP with manual header, ensure AllowUnencryptedAuthentication is not needed by PS Core
                # and UseBasicParsing is set.
                $iwrParams.UseBasicParsing = $true
            }
             Write-Log -Level DEBUG -Message ("$($FunctionName): Using manual Authorization header for $scheme.")
        } elseif ($credential) { # Fallback to $credential object if manual parsing failed
            $iwrParams.Credential = $credential
            if ($scheme -eq 'http' -and $PSVersionTable.PSVersion.Major -ge 6) { $iwrParams.AllowUnencryptedAuthentication = $true }
            if ($scheme -eq 'http') { $iwrParams.UseBasicParsing = $true }
            Write-Log -Level DEBUG -Message ("$($FunctionName): Using \$credential object for $scheme.")
        } else {
             if ($scheme -eq 'http') { $iwrParams.UseBasicParsing = $true }
             Write-Log -Level DEBUG -Message ("$($FunctionName): No credentials for $scheme.")
        }
        
        if ($scheme -eq 'https') {
             if ($PSVersionTable.PSVersion.Major -ge 6) { $iwrParams.SslProtocol = [System.Net.SecurityProtocolType]::Tls12 }
        }

        try {
            Write-Log -Level DEBUG -Message ("$($FunctionName): iwrParams for ${scheme}: $($iwrParams | Out-String)")
            $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParams
            Write-Log -Level DEBUG -Message ("$($FunctionName): $scheme connection successful. StatusCode: $($responseObject.StatusCode)")
            $lastException = $null # Clear last exception on success
            break # Success, exit loop
        } catch {
            $lastException = $_
            Write-Log -Level WARN -Message ("$($FunctionName): $scheme connection to '$($iwrParams.Uri)' failed: $($_.Exception.Message.Split([Environment]::NewLine)[0])")
        }
    }

    if ($lastException -and -not $responseObject) { # If all attempts failed
        throw $lastException # Re-throw the last encountered exception
    }
    
    if ($responseObject) {
        $xmlResponse = [xml]$responseObject.Content
        $currentUpdateLevel = $xmlResponse.LL.value
        $responseCode = $xmlResponse.LL.Code
        Write-Log -Level INFO -Message ("$($FunctionName): MS '{0}' current updatelevel: '{1}' (Code: {2}). Expected: '{3}' (from channel '{4}')" -f $msIP, $currentUpdateLevel, $responseCode, $expectedUpdateLevelValue, $ConfiguredUpdateChannel)

        if ($currentUpdateLevel -ne $expectedUpdateLevelValue) {
            # Construct the URI for the error message
            # We need the original user:pass and ip/hostname. $entryToParse has this.
            # Scheme needs to be determined. If original was HTTP, suggest HTTP. If HTTPS, suggest HTTPS.
            # For Gen1, always suggest HTTP. We don't have Gen1 info here directly.
            # Let's provide both if unsure, or stick to original scheme.
            
            $setErrorUriHttp = "http://"
            $setErrorUriHttps = "https://"
            
            if ($entryToParse -match '^(?<scheme>[^:]+)://(?<userpass>[^@]+@)?(?<hostandport>[^/]+)') {
                $userPassPart = $Matches.userpass # Includes '@' if present
                $hostAndPortPart = $Matches.hostandport
                $setErrorUriHttp += $userPassPart + $hostAndPortPart + "/dev/cfg/updatelevel/" + $ConfiguredUpdateChannel # Use original channel name for setting
                $setErrorUriHttps += $userPassPart + $hostAndPortPart + "/dev/cfg/updatelevel/" + $ConfiguredUpdateChannel
            } else { # Fallback if regex fails (should not happen with validated MSEntry)
                 $setErrorUriHttp += $msIP + "/dev/cfg/updatelevel/" + $ConfiguredUpdateChannel
                 $setErrorUriHttps += $msIP + "/dev/cfg/updatelevel/" + $ConfiguredUpdateChannel
            }

            $errorMessage = @"
Miniserver '$msIP' is on updatelevel '$currentUpdateLevel', but the configured update channel is '$ConfiguredUpdateChannel' (expects '$expectedUpdateLevelValue').
Please set the correct updatelevel on the Miniserver using an account with administrator rights.
You can typically do this by navigating to one of the following URLs in a web browser:
$setErrorUriHttps
(For older Miniservers, try HTTP: $setErrorUriHttp)
Then, re-run this script.
"@
            Write-Log -Level ERROR -Message $errorMessage
            throw $errorMessage # This will be caught by Update-MS
        } else {
            Write-Log -Level INFO -Message ("$($FunctionName): MS '{0}' updatelevel ('{1}') matches configured channel ('{2}' -> '{3}')." -f $msIP, $currentUpdateLevel, $ConfiguredUpdateChannel, $expectedUpdateLevelValue)
        }
    } else {
        throw ("$($FunctionName): Failed to get a valid response for updatelevel check of MS '{0}' after all attempts." -f $msIP)
    }

} catch {
    $CaughtError = $_
    $errorMessageToLog = ("Error in Test-LoxoneMiniserverUpdateLevel for '{0}': {1}" -f $msIP, $CaughtError.Exception.Message.Split([Environment]::NewLine)[0])
    Write-Log -Level ERROR -Message $errorMessageToLog
    Write-Log -Level DEBUG -Message ("$($FunctionName): Full error details for MS '{0}': {1}" -f $msIP, $CaughtError.Exception.ToString())
    # Re-throw the original exception object to preserve its type and details for the caller (Update-MS)
    throw $CaughtError
} finally {
    $ProgressPreference = $oldProgressPreference
    if ($callbackChanged) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
    Write-Log -Level DEBUG -Message "$($FunctionName): Exiting."
    Exit-Function
}
}

function Update-MS {
[CmdletBinding()]
param(
[Parameter(Mandatory = $true)] [string]$DesiredVersion,
[Parameter(Mandatory = $true)] [string]$ConfiguredUpdateChannel, # Added parameter
[Parameter(Mandatory = $true)] [string]$MSListPath,
[Parameter(Mandatory = $true)] [string]$LogFile,
[Parameter(Mandatory = $true)] [int]$MaxLogFileSizeMB,
[Parameter()][switch]$DebugMode,
[Parameter(Mandatory = $true)] [string]$ScriptSaveFolder,
[Parameter(Mandatory = $false)][int]$StepNumber = 1,
[Parameter(Mandatory = $false)][int]$TotalSteps = 1,
[Parameter()][switch]$SkipCertificateCheck,
[Parameter()][bool]$IsInteractive = $false
)
Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
$script:ErrorOccurredInUpdateMS = $false
$allMSResults = @()

try { # Main function try
    $global:LogFile = $LogFile
    Write-Log -Message "Starting MS update process. Desired version: $DesiredVersion" -Level "INFO"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    if (-not (Test-Path $MSListPath)) {
        Write-Log -Message ("MS list file not found at '{0}'. Skipping MS updates." -f $MSListPath) -Level "WARN"
        return $allMSResults
    }

    $MSs = Get-Content $MSListPath | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
    Write-Log -Message ("Loaded MS list with {0} entries." -f $MSs.Count) -Level "INFO"

    if ($MSs.Count -eq 0) {
        Write-Log -Message "MS list is empty. Skipping MS updates." -Level "INFO"
        return $allMSResults
        return $allMSResults
    }

    $msCounter = 0
    foreach ($msEntry in $MSs) {
        $msCounter++
        $redactedEntryForLog = Get-RedactedPassword $msEntry
        Write-Log -Message ("Processing MS entry ($msCounter/$($MSs.Count)): {0}" -f $redactedEntryForLog) -Level INFO

        $msIP = $null; $versionUriForCheck = $null; $credential = $null
        $msStatusObject = [PSCustomObject]@{
            MSEntry             = $msEntry # Store the original entry for matching
            MSIP                = "Unknown"
            InitialVersion      = "Unknown"
            AttemptedUpdate     = $false
            UpdateSucceeded     = $false
            VersionAfterUpdate  = "Unknown"
            StatusMessage       = "NotProcessed"
            ErrorDuringProcessing = $false
        }
        try { # Per-MS processing
            $entryToParse = $msEntry
            if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
            $uriBuilder = [System.UriBuilder]$entryToParse
            $msIP = $uriBuilder.Host
            $msStatusObject.MSIP = $msIP

            if (-not ([string]::IsNullOrWhiteSpace($uriBuilder.UserName))) {
                $securePassword = $uriBuilder.Password | ConvertTo-SecureString -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential($uriBuilder.UserName, $securePassword)
            }
            
            $uriBuilder.Path = "/dev/cfg/version"
            $uriBuilder.Password = $null; $uriBuilder.UserName = $null
            $versionUriForCheck = $uriBuilder.Uri.AbsoluteUri

            # Manually parse username and password from $entryToParse for Auth Header in Update-MS InitialCheck
            $usernameForAuthHeaderUpdateMS = $null
            $passwordForAuthHeaderUpdateMS = $null
            # $entryToParse already has scheme, e.g., http://user:pass@host
            if ($entryToParse -match '^(?<scheme>[^:]+)://(?<credentials>[^@]+)@(?<hostinfo>.+)$') {
                $credPartFromEntry = $Matches.credentials
                if ($credPartFromEntry -match '^(?<user>[^:]+):(?<pass>.+)$') {
                    $usernameForAuthHeaderUpdateMS = $Matches.user
                    $passwordForAuthHeaderUpdateMS = $Matches.pass
                    Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: Manually parsed Username for Auth Header: '{0}'" -f $usernameForAuthHeaderUpdateMS)
                    Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: Manually parsed Password for Auth Header (length): {0}" -f $passwordForAuthHeaderUpdateMS.Length)
                } else {
                    Write-Log -Level WARN -Message ("Update-MS InitialCheck: Could not manually parse user:pass from credentials part: '$credPartFromEntry'")
                }
            } else {
                Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: Entry '$($entryToParse -replace "([Pp]assword=)[^;]+", '$1********')' does not seem to contain user:pass@host format for direct manual parsing for Auth Header.")
            }
            
            Write-Log -Message ("Checking current MS version for '{0}'..." -f $msIP) -Level "INFO"
            $responseObject = $null; $initialVersionCheckSuccess = $false; $currentNormalizedVersion = $null
            $originalCallbackCheck = $null; $callbackChangedCheck = $false
            $oldProgressPreferenceCheck = $ProgressPreference
            
            try { # For SSL callback and ProgressPreference restoration
                $ProgressPreference = 'SilentlyContinue'
                if ($SkipCertificateCheck.IsPresent) {
                    $originalCallbackCheck = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; $callbackChangedCheck = $true
                }
    
                try { # For IWR calls
                    $iwrParamsInitialCheck = @{ TimeoutSec = 1; ErrorAction = 'Stop'; Method = 'Get' }
                    # $credential (with URL-decoded password) is NOT set here by default anymore.
                    # We will explicitly build headers if $usernameForAuthHeaderUpdateMS is available.

                    if ($uriBuilder.Scheme -eq 'http') {
                        # Original entry is HTTP. Try HTTPS first as a failsafe, then HTTP.
                        Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: Original scheme is HTTP. Attempting HTTPS first (with manual AuthN if available).")
                        $httpsUriBuilderCheck = [System.UriBuilder]$versionUriForCheck # $versionUriForCheck is http://host/dev/cfg/version
                        $httpsUriBuilderCheck.Scheme = 'https'; $httpsUriBuilderCheck.Port = -1 # Use default HTTPS port
                        $iwrParamsInitialCheck.Uri = $httpsUriBuilderCheck.Uri.AbsoluteUri

                        # Configure Auth for HTTPS attempt
                        if (-not [string]::IsNullOrEmpty($usernameForAuthHeaderUpdateMS) -and -not [string]::IsNullOrEmpty($passwordForAuthHeaderUpdateMS)) {
                            $PairHttps = "${usernameForAuthHeaderUpdateMS}:${passwordForAuthHeaderUpdateMS}"
                            $BytesHttps = [System.Text.Encoding]::ASCII.GetBytes($PairHttps)
                            $Base64AuthHttps = [System.Convert]::ToBase64String($BytesHttps)
                            $iwrParamsInitialCheck.Headers = @{ Authorization = "Basic $Base64AuthHttps" }
                            $iwrParamsInitialCheck.Remove('Credential'); $iwrParamsInitialCheck.Credential = $null
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTPS Attempt): Using manual Authorization header.")
                        } elseif ($credential) { # Fallback to $credential ONLY if manual parsing failed
                            $iwrParamsInitialCheck.Credential = $credential
                            $iwrParamsInitialCheck.Remove('Headers')
                            Write-Log -Level WARN -Message ("Update-MS InitialCheck (HTTPS Attempt): Manual creds not parsed, using \$credential (URL-decoded password).")
                        } else { # No credentials
                            $iwrParamsInitialCheck.Remove('Credential'); $iwrParamsInitialCheck.Credential = $null
                            $iwrParamsInitialCheck.Remove('Headers')
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTPS Attempt): No credentials available.")
                        }
                        if ($PSVersionTable.PSVersion.Major -ge 6) { $iwrParamsInitialCheck.SslProtocol = [System.Net.SecurityProtocolType]::Tls12 }
                        Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTPS Attempt): iwrParams before invoke: $($iwrParamsInitialCheck | Out-String)")
                        try {
                            $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParamsInitialCheck
                            $initialVersionCheckSuccess = $true
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: HTTPS attempt successful for $msIP.")
                        } catch {
                            $CaughtErrorHttpsAttempt = $_
                            Write-Log -Message ("Update-MS InitialCheck for {0}: Initial HTTPS attempt failed ({1}). Falling back to HTTP." -f $msIP, $CaughtErrorHttpsAttempt.Exception.Message.Split([Environment]::NewLine)[0]) -Level DEBUG

                            # HTTP Fallback
                            $iwrParamsInitialCheck.Uri = $versionUriForCheck # Revert to original HTTP URI from $uriBuilder (e.g. http://host/dev/cfg/version)
                            $iwrParamsInitialCheck.Remove('SslProtocol') # Not applicable for HTTP

                            if (-not [string]::IsNullOrEmpty($usernameForAuthHeaderUpdateMS) -and -not [string]::IsNullOrEmpty($passwordForAuthHeaderUpdateMS)) {
                                $PairHttpFallback = "${usernameForAuthHeaderUpdateMS}:${passwordForAuthHeaderUpdateMS}"
                                $BytesHttpFallback = [System.Text.Encoding]::ASCII.GetBytes($PairHttpFallback)
                                $Base64AuthHttpFallback = [System.Convert]::ToBase64String($BytesHttpFallback)
                                $iwrParamsInitialCheck.Headers = @{ Authorization = "Basic $Base64AuthHttpFallback" }
                                $iwrParamsInitialCheck.Remove('Credential'); $iwrParamsInitialCheck.Credential = $null
                                Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTP Fallback): Using manual Authorization header.")
                            } elseif ($credential) { # Fallback to $credential ONLY if manual parsing failed
                                $iwrParamsInitialCheck.Credential = $credential
                                $iwrParamsInitialCheck.Remove('Headers')
                                if ($PSVersionTable.PSVersion.Major -ge 6) { $iwrParamsInitialCheck.AllowUnencryptedAuthentication = $true }
                                Write-Log -Level WARN -Message ("Update-MS InitialCheck (HTTP Fallback): Manual creds not parsed, using \$credential (URL-decoded password).")
                            } else { # No credentials
                                $iwrParamsInitialCheck.Remove('Credential'); $iwrParamsInitialCheck.Credential = $null
                                $iwrParamsInitialCheck.Remove('Headers')
                                Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTP Fallback): No credentials available.")
                            }
                            $iwrParamsInitialCheck.UseBasicParsing = $true
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTP Fallback): iwrParams before invoke: $($iwrParamsInitialCheck | Out-String)")
                            $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParamsInitialCheck # This will throw to the outer IWR catch if it fails
                            $initialVersionCheckSuccess = $true
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: HTTP fallback attempt successful for $msIP.")
                        }
                    } else { # Original Scheme was HTTPS
                        Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: Original scheme is HTTPS. Attempting HTTPS (with manual AuthN if available).")
                        $iwrParamsInitialCheck.Uri = $versionUriForCheck # URI is already HTTPS

                        if (-not [string]::IsNullOrEmpty($usernameForAuthHeaderUpdateMS) -and -not [string]::IsNullOrEmpty($passwordForAuthHeaderUpdateMS)) {
                            $PairHttpsDirect = "${usernameForAuthHeaderUpdateMS}:${passwordForAuthHeaderUpdateMS}"
                            $BytesHttpsDirect = [System.Text.Encoding]::ASCII.GetBytes($PairHttpsDirect)
                            $Base64AuthHttpsDirect = [System.Convert]::ToBase64String($BytesHttpsDirect)
                            $iwrParamsInitialCheck.Headers = @{ Authorization = "Basic $Base64AuthHttpsDirect" }
                            $iwrParamsInitialCheck.Remove('Credential'); $iwrParamsInitialCheck.Credential = $null
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTPS Direct): Using manual Authorization header.")
                        } elseif ($credential) { # Fallback to $credential ONLY if manual parsing failed
                            $iwrParamsInitialCheck.Credential = $credential
                            $iwrParamsInitialCheck.Remove('Headers')
                            Write-Log -Level WARN -Message ("Update-MS InitialCheck (HTTPS Direct): Manual creds not parsed, using \$credential (URL-decoded password).")
                        } else { # No credentials
                            $iwrParamsInitialCheck.Remove('Credential'); $iwrParamsInitialCheck.Credential = $null
                            $iwrParamsInitialCheck.Remove('Headers')
                            Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTPS Direct): No credentials available.")
                        }
                        if ($PSVersionTable.PSVersion.Major -ge 6) { $iwrParamsInitialCheck.SslProtocol = [System.Net.SecurityProtocolType]::Tls12 }
                        Write-Log -Level DEBUG -Message ("Update-MS InitialCheck (HTTPS Direct): iwrParams before invoke: $($iwrParamsInitialCheck | Out-String)")
                        $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParamsInitialCheck
                        $initialVersionCheckSuccess = $true
                        Write-Log -Level DEBUG -Message ("Update-MS InitialCheck: HTTPS direct attempt successful for $msIP.")
                    }
    
                    if ($initialVersionCheckSuccess -and $responseObject) {
                        $xmlResponse = [xml]$responseObject.Content
                        $initialVersionRaw = $xmlResponse.LL.value
                        if ([string]::IsNullOrEmpty($initialVersionRaw)) { throw ("Could not parse initial version from MS '{0}' (LL.value empty)." -f $msIP) }
                        $currentNormalizedVersion = Convert-VersionString $initialVersionRaw
                        $msStatusObject.InitialVersion = $currentNormalizedVersion
                        Write-Log -Message ("MS '{0}' initial version: {1} (Raw: {2})" -f $msIP, $currentNormalizedVersion, $initialVersionRaw) -Level INFO
                    } else {
                        # This else should ideally not be hit if ErrorAction='Stop' works as expected in all IWR calls.
                        throw ("Failed to get a valid response for initial version check of MS '{0}'." -f $msIP)
                    }
                } catch { # Catch for IWR calls
                    $CaughtErrorIWR = $_
                    Write-Log -Message ("Error during initial version WebRequest/parsing for {0}: {1}" -f $msIP, $CaughtErrorIWR.Exception.Message.Split([Environment]::NewLine)[0]) -Level ERROR; throw # Re-throw to be caught by Per-MS processing catch
                }
            } finally {
                $ProgressPreference = $oldProgressPreferenceCheck
                if ($callbackChangedCheck) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallbackCheck }
            }
            
            if ($currentNormalizedVersion -eq $DesiredVersion) {
                Write-Log -Message ("MS '{0}' is current (version '{1}')" -f $msIP, $DesiredVersion) -Level INFO
                $msStatusObject.StatusMessage = "Current"; $msStatusObject.VersionAfterUpdate = $currentNormalizedVersion; $msStatusObject.UpdateSucceeded = $true
            } else {
                # Check UpdateLevel before proceeding with update
                Write-Log -Message ("MS '{0}' needs update. Checking updatelevel before proceeding..." -f $msIP) -Level INFO
                Test-LoxoneMiniserverUpdateLevel -MSEntry $msEntry -ConfiguredUpdateChannel $ConfiguredUpdateChannel -SkipCertificateCheck:$SkipCertificateCheck.IsPresent
                # If Test-LoxoneMiniserverUpdateLevel throws an error, it will be caught by the per-MS catch block below,
                # setting ErrorDuringProcessing and StatusMessage appropriately.

                Write-Log -Message ("Proceeding with update trigger for MS '{0}'..." -f $msIP) -Level INFO
                $msStatusObject.AttemptedUpdate = $true
                # Use the passed StepNumber and TotalSteps for the toast
                $stepNameString = "Step $($StepNumber)/$($TotalSteps): Updating MS $($msCounter)/$($MSs.Count) - Starting for $($msIP)..."
                Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName $stepNameString -IsInteractive $IsInteractive -ErrorOccurred $script:ErrorOccurredInUpdateMS -AnyUpdatePerformed ($allMSResults.UpdateSucceeded -contains $true)
                
                $autoupdateUriBuilder = [System.UriBuilder]$entryToParse; $autoupdateUriBuilder.Path = "/dev/sys/autoupdate"
                $uriForUpdateTrigger = $autoupdateUriBuilder.Uri.AbsoluteUri
                
                $invokeParams = @{
                    MSUri                  = $uriForUpdateTrigger
                    NormalizedDesiredVersion = $DesiredVersion
                    Credential             = $credential # Still pass for potential non-Basic Auth or fallback
                    UsernameForAuthHeader  = $usernameForAuthHeaderUpdateMS # Pass manually parsed creds
                    PasswordForAuthHeader  = if (-not [string]::IsNullOrEmpty($passwordForAuthHeaderUpdateMS)) { $passwordForAuthHeaderUpdateMS | ConvertTo-SecureString -AsPlainText -Force } else { $null } # Convert to SecureString
                    StepNumber             = $StepNumber
                    TotalSteps             = $TotalSteps
                    IsInteractive          = $IsInteractive
                    ErrorOccurred          = $script:ErrorOccurredInUpdateMS
                    AnyUpdatePerformed     = ($allMSResults.UpdateSucceeded -contains $true)
                    SkipCertificateCheck   = $SkipCertificateCheck.IsPresent
                    MSCounter              = $msCounter
                    TotalMS                = $MSs.Count
                }
                $updateResultObject = Invoke-MSUpdate @invokeParams
    
                if ($updateResultObject.VerificationSuccess) {
                    $msStatusObject.UpdateSucceeded = $true; $msStatusObject.VersionAfterUpdate = $updateResultObject.ReportedVersion; $msStatusObject.StatusMessage = "UpdateSuccessful"
                } else {
                    $msStatusObject.UpdateSucceeded = $false; $msStatusObject.VersionAfterUpdate = if ($updateResultObject.ReportedVersion) { $updateResultObject.ReportedVersion } else { $currentNormalizedVersion }
                    $msStatusObject.StatusMessage = $updateResultObject.StatusMessage
                    if ($updateResultObject.ErrorOccurredInInvoke) { $msStatusObject.ErrorDuringProcessing = $true; $script:ErrorOccurredInUpdateMS = $true }
                }
            }
    
        } catch {
            $CaughtError = $_
            Write-Log -Level ERROR -Message ("Update-MS: Error processing MS '$($msIP)' or '$($redactedEntryForLog)': $($CaughtError.Exception.Message)")
            $msStatusObject.MSIP = if ($msIP) { $msIP } else { $redactedEntryForLog }
            $msStatusObject.StatusMessage = "Error_Processing_MS_Entry"
            $msStatusObject.ErrorDuringProcessing = $true
            $script:ErrorOccurredInUpdateMS = $true
        } finally {
            $allMSResults += $msStatusObject
        }
    } # End foreach
    Write-Log -Message "Finished processing all MSs." -Level "INFO"
} catch {
    $CaughtError = $_ # Capture current error to avoid issues with $_ context in Write-Log
    Write-Log -Message ("Unexpected error in Update-MS: {0}" -f $CaughtError.Exception.Message) -Level ERROR
    $script:ErrorOccurredInUpdateMS = $true
} finally {
    Write-Log -Message ("Update-MS returning {0} results. Overall Error: {1}" -f $allMSResults.Count, $script:ErrorOccurredInUpdateMS) -Level INFO
}

Exit-Function
return $allMSResults
}

function Invoke-MSUpdate {
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MSUri,
    [Parameter(Mandatory=$true)][string]$NormalizedDesiredVersion,
    [Parameter()][System.Management.Automation.PSCredential]$Credential = $null, # Original credential object
    [Parameter()][string]$UsernameForAuthHeader = $null, # Manually parsed username
    [Parameter()][SecureString]$PasswordForAuthHeader = $null, # Manually parsed (raw) password
    [Parameter(Mandatory = $false)][int]$StepNumber = 1,
    [Parameter(Mandatory = $false)][int]$TotalSteps = 1,
    [Parameter()][bool]$IsInteractive = $false,
    [Parameter()][bool]$ErrorOccurred = $false,
    [Parameter()][bool]$AnyUpdatePerformed = $false,
    [Parameter()][switch]$SkipCertificateCheck,
    [Parameter(Mandatory = $false)][int]$MSCounter = 1,
    [Parameter(Mandatory = $false)][int]$TotalMS = 1
)
Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
Write-Log -Level DEBUG -Message ("Invoke-MSUpdate: UsernameForAuthHeader is null/empty: $([string]::IsNullOrEmpty($UsernameForAuthHeader)), PasswordForAuthHeader is null/empty: $(($null -eq $PasswordForAuthHeader -or $PasswordForAuthHeader.Length -eq 0))")

$invokeResult = [PSCustomObject]@{ VerificationSuccess = $false; ReportedVersion = $null; ErrorOccurredInInvoke = $false; StatusMessage = "NotStarted" }
$originalCallback = $null; $callbackChanged = $false
$oldProgressPreference = $ProgressPreference

try { # Main try for ProgressPreference and SSL Callback restoration
    $ProgressPreference = 'SilentlyContinue'
    
    $uriObjectForInvoke = [System.Uri]$MSUri
    $hostForPingInInvoke = $uriObjectForInvoke.Host
    $schemeInInvoke = $uriObjectForInvoke.Scheme
    $verificationUriBuilder = [System.UriBuilder]$MSUri; $verificationUriBuilder.Path = "/dev/cfg/version"
    $verificationUriForPolling = $verificationUriBuilder.Uri.AbsoluteUri

    $invokeResult.StatusMessage = "TriggeringUpdate"
    Write-Log -Message ("Attempting to trigger update for MS '{0}'..." -f $hostForPingInInvoke) -Level INFO

    if ($SkipCertificateCheck.IsPresent) {
        $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; $callbackChanged = $true
    }

    try { # For IWR - Trigger
            $triggerParams = @{ Uri = $MSUri; Method = 'Get'; TimeoutSec = 1; ErrorAction = 'Stop' }
            
            if (-not [string]::IsNullOrEmpty($UsernameForAuthHeader) -and ($PasswordForAuthHeader -ne $null -and $PasswordForAuthHeader.Length -gt 0)) {
                Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Trigger): Using manually parsed credentials for Authorization header."
                $plainPasswordForAuthHeader = $null
                $bstr = $null
                try {
                    # Convert SecureString to plain text for the Authorization header
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordForAuthHeader)
                    $plainPasswordForAuthHeader = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                }
                finally {
                    if ($null -ne $bstr) {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }
                }
                $PairTrigger = "${UsernameForAuthHeader}:${plainPasswordForAuthHeader}"
                # Clear the plain text password variable as its content is now in PairTrigger
                if ($null -ne $plainPasswordForAuthHeader) { Clear-Variable plainPasswordForAuthHeader -ErrorAction SilentlyContinue }
                $BytesTrigger = [System.Text.Encoding]::ASCII.GetBytes($PairTrigger)
                $Base64AuthTrigger = [System.Convert]::ToBase64String($BytesTrigger)
                $triggerParams.Headers = @{ Authorization = "Basic $Base64AuthTrigger" }
                # $triggerParams.Credential = $null # Ensure $Credential object is not used if manual header is set
            } elseif ($Credential) { # Fallback to $Credential object if manual ones aren't available
                Write-Log -Level WARN -Message "Invoke-MSUpdate (Trigger): Manually parsed credentials not available, falling back to \$Credential object (may use URL-decoded password)."
                if ($schemeInInvoke -eq 'http' -and $PSVersionTable.PSVersion.Major -ge 6) {
                    $triggerParams.Credential = $Credential; $triggerParams.AllowUnencryptedAuthentication = $true
                } elseif ($schemeInInvoke -eq 'http') {
                    # This path for PS5 HTTP with $Credential might still use URL-decoded password from $Credential.GetNetworkCredential().Password
                    # Ideally, if $UsernameForAuthHeader/$PasswordForAuthHeader were always populated from Update-MS, this branch wouldn't be hit for Basic Auth.
                    $UsernameDecoded = $Credential.UserName; $PasswordDecoded = $Credential.GetNetworkCredential().Password
                    Write-Log -Level WARN -Message "Invoke-MSUpdate (Trigger): PS5 HTTP with \$Credential. Password used will be URL-decoded from \$Credential object."
                    $EncodedCredentialsDecoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${UsernameDecoded}:${PasswordDecoded}"))
                    $triggerParams.Headers = @{ Authorization = "Basic $EncodedCredentialsDecoded" }
                } else { # HTTPS
                    $triggerParams.Credential = $Credential
                }
            } else {
                Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Trigger): No credentials provided."
            }
            if ($schemeInInvoke -eq 'http') { $triggerParams.UseBasicParsing = $true }
    
            Write-Log -Level DEBUG -Message ("Invoke-MSUpdate (Trigger): triggerParams before invoke: $($triggerParams | Out-String)")
            Invoke-MiniserverWebRequest -Parameters $triggerParams | Out-Null
            Write-Log -Message ("Update trigger sent to '{0}'." -f $hostForPingInInvoke) -Level INFO
            $invokeResult.StatusMessage = "UpdateTriggered_WaitingForReboot"
        } catch {
        $invokeResult.ErrorOccurredInInvoke = $true; $invokeResult.StatusMessage = ("Error_TriggeringUpdate: {0}" -f $CaughtError.Exception.Message.Split([Environment]::NewLine)[0])
        Write-Log -Message ("Error triggering update for '{0}': {1}" -f $hostForPingInInvoke, $CaughtError.Exception.Message) -Level ERROR
    }

    if (-not $invokeResult.ErrorOccurredInInvoke) {
        Write-Log -Message ("Waiting for MS {0} to reboot/update..." -f $hostForPingInInvoke) -Level INFO
        $toastStepNameWait = "Step $($StepNumber)/$($TotalSteps): Updating MS $($MSCounter)/$($TotalMS) - Waiting for $($hostForPingInInvoke)..."
        Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName $toastStepNameWait -IsInteractive $IsInteractive -ErrorOccurred $ErrorOccurred -AnyUpdatePerformed $AnyUpdatePerformed
        
        $startTime = Get-Date; $timeout = New-TimeSpan -Minutes 15; $msResponsive = $false; $loggedUpdatingStatus = $false
        $verifyParams = @{ Uri = $verificationUriForPolling; UseBasicParsing = $true; TimeoutSec = 1; ErrorAction = 'Stop' }

        if (-not [string]::IsNullOrEmpty($UsernameForAuthHeader) -and ($PasswordForAuthHeader -ne $null -and $PasswordForAuthHeader.Length -gt 0)) {
            Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Polling): Using manually parsed credentials for Authorization header."
            $plainPasswordForVerifyHeader = $null
            $bstrVerify = $null
            try {
                # Convert SecureString to plain text for the Authorization header
                $bstrVerify = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordForAuthHeader)
                $plainPasswordForVerifyHeader = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrVerify)
            }
            finally {
                If ($null -ne $bstrVerify) {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrVerify)
                }
            }
            $PairVerify = "${UsernameForAuthHeader}:${plainPasswordForVerifyHeader}"
            # Clear the plain text password variable
            if ($null -ne $plainPasswordForVerifyHeader) { Clear-Variable plainPasswordForVerifyHeader -ErrorAction SilentlyContinue }
            $BytesVerify = [System.Text.Encoding]::ASCII.GetBytes($PairVerify)
            $Base64AuthVerify = [System.Convert]::ToBase64String($BytesVerify)
            $verifyParams.Headers = @{ Authorization = "Basic $Base64AuthVerify" }
            # $verifyParams.Credential = $null
        } elseif ($Credential) { # Fallback to $Credential object
            Write-Log -Level WARN -Message "Invoke-MSUpdate (Polling): Manually parsed credentials not available, falling back to \$Credential object (may use URL-decoded password)."
            if ($schemeInInvoke -eq 'http' -and $PSVersionTable.PSVersion.Major -ge 6) {
                $verifyParams.Credential = $Credential; $verifyParams.AllowUnencryptedAuthentication = $true
            } elseif ($schemeInInvoke -eq 'http') {
                $UsernameDecodedPoll = $Credential.UserName; $PasswordDecodedPoll = $Credential.GetNetworkCredential().Password
                Write-Log -Level WARN -Message "Invoke-MSUpdate (Polling): PS5 HTTP with \$Credential. Password used will be URL-decoded from \$Credential object."
                $EncodedCredentialsDecodedPoll = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${UsernameDecodedPoll}:${PasswordDecodedPoll}"))
                $verifyParams.Headers = @{ Authorization = "Basic $EncodedCredentialsDecodedPoll" }
            } else { # HTTPS
                $verifyParams.Credential = $Credential
            }
        } else {
            Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Polling): No credentials provided."
        }
        # UseBasicParsing is already in $verifyParams base definition for polling.
        Write-Log -Level DEBUG -Message ("Invoke-MSUpdate (Polling): verifyParams before invoke: $($verifyParams | Out-String)")

        $Attempts = 0; $MaxAttempts = [Math]::Floor($timeout.TotalSeconds / 10)
        $LastPollStatusMessage = "Initiating..."
        while (((Get-Date) - $startTime) -lt $timeout) {
            $Attempts++; Write-Host -NoNewline ("`rPolling MS $hostForPingInInvoke (Attempt $Attempts/$MaxAttempts): $LastPollStatusMessage".PadRight(120)); Start-Sleep -Seconds 10
            try {
                $lastResponse = Invoke-MiniserverWebRequest -Parameters $verifyParams
                $msResponsive = $true; $xmlCurrent = [xml]$lastResponse.Content; $versionCurrentPoll = $xmlCurrent.LL.value
                if ([string]::IsNullOrEmpty($versionCurrentPoll)) { throw "LL.value empty in poll response." }
                $normalizedVersionCurrentPoll = Convert-VersionString $versionCurrentPoll; $invokeResult.ReportedVersion = $normalizedVersionCurrentPoll
                if ($normalizedVersionCurrentPoll -eq $NormalizedDesiredVersion) {
                    $invokeResult.VerificationSuccess = $true; $invokeResult.StatusMessage = "UpdateSuccessful_VersionVerified"; $LastPollStatusMessage = ("OK - Version {0}" -f $NormalizedDesiredVersion); break
                } else { $invokeResult.StatusMessage = ("Polling_VersionMismatch_Current_{0}" -f $normalizedVersionCurrentPoll); $LastPollStatusMessage = ("OK - Version {0} (Expected {1})" -f $normalizedVersionCurrentPoll, $NormalizedDesiredVersion) }
            } catch [System.Net.WebException] {
                $CaughtWebError = $_
                $statusCode = if ($CaughtWebError.Exception.Response) { [int]$CaughtWebError.Exception.Response.StatusCode } else { $null }
                if ($statusCode -eq 503) {
                    $invokeResult.StatusMessage = "Polling_MS_Updating_503"; $errorDetail = 'Updating...'
                    if ($CaughtWebError.Exception.Response) { try { $responseStream = $CaughtWebError.Exception.Response.GetResponseStream(); $streamReader = New-Object System.IO.StreamReader($responseStream); $errorDetail = ($streamReader.ReadToEnd() -match '<errordetail>(.*?)</errordetail>') | Out-Null; if($matches[1]){$errorDetail = $matches[1].Trim()}; $streamReader.Close(); $responseStream.Close() } catch {} }
                    $LastPollStatusMessage = ("Updating ({0})" -f $errorDetail); if (-not $loggedUpdatingStatus) { Write-Log -Level INFO -Message ("MS {0} status: {1}" -f $hostForPingInInvoke, $errorDetail); $loggedUpdatingStatus = $true }
                } else { $invokeResult.StatusMessage = ("Polling_WebException_StatusCode_{0}" -f $statusCode); $LastPollStatusMessage = ("Error ({0})" -f $statusCode) }
                Write-Log -Message ("MS {0} WebException during poll ({1}): {2}" -f $hostForPingInInvoke, $LastPollStatusMessage, $CaughtWebError.Exception.Message.Split([Environment]::NewLine)[0]) -Level WARN
        } catch {
            $CaughtCatchError = $_
            $invokeResult.StatusMessage = ("Polling_Unreachable_Or_ParseError: {0}" -f $CaughtCatchError.Exception.Message.Split([Environment]::NewLine)[0]); $LastPollStatusMessage = "Unreachable/ParseError"; Write-Log -Message ("MS {0} unreachable/parse error: {1}" -f $hostForPingInInvoke, $CaughtCatchError.Exception.Message) -Level WARN
        }
    } # End while
    Write-Host ""
    if (-not $invokeResult.VerificationSuccess) {
        if ($msResponsive) { $invokeResult.StatusMessage = ("VerificationFailed_Timeout_VersionMismatch_FinalReported_{0}" -f $invokeResult.ReportedVersion) }
        else { $invokeResult.StatusMessage = "VerificationFailed_Timeout_NoResponse" }
        Write-Log -Message ("FAILURE: MS {0} - {1}" -f $hostForPingInInvoke, $invokeResult.StatusMessage) -Level ERROR
        $toastStepNameFail = "Step $($StepNumber)/$($TotalSteps): Updating MS $($MSCounter)/$($TotalMS) - FAILED for $($hostForPingInInvoke) ($($invokeResult.StatusMessage))"
        Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName $toastStepNameFail -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed
    }
}
} catch { # Catch for the main try in Invoke-MSUpdate
$CaughtOuterError = $_
$invokeResult.ErrorOccurredInInvoke = $true
$invokeResult.StatusMessage = ("Error_InvokeMSUpdate_OuterTry: {0}" -f $CaughtOuterError.Exception.Message.Split([Environment]::NewLine)[0])
Write-Log -Message ("Outer error in Invoke-MSUpdate for '{0}': {1}" -f $hostForPingInInvoke, $CaughtOuterError.Exception.Message) -Level ERROR
$toastStepNameOuterFail = "Step $($StepNumber)/$($TotalSteps): Updating MS $($MSCounter)/$($TotalMS) - ERROR for $($hostForPingInInvoke)"
Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName $toastStepNameOuterFail -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed
} finally {
$ProgressPreference = $oldProgressPreference
if ($callbackChanged) {
    Write-Log -Message "Restoring original SSL/TLS certificate validation callback in Invoke-MSUpdate." -Level DEBUG
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
}
}
return $invokeResult
}